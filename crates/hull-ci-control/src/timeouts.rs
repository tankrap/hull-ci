//! Timeouts — design D§10.2.
//!
//! Spec §10 says Hull never times a job out: "the verdict is whatever your callback eventually
//! says." So a job we lose track of does not fail, it *hangs* — the tree stays unverified and a
//! human has to notice. Every clock below exists to turn that silence into a verdict.
//!
//! | Scope | Default | On expiry |
//! |---|---|---|
//! | Step wall clock | 20 min (pipeline-overridable) | step `errored` → job `errored`, `reason: timeout` |
//! | Job wall clock | 60 min | cancel everything, `errored` |
//! | Queue wait | 30 min | `errored`, `reason: capacity` |
//! | Fetch | 5 min | `errored`, `reason: infra` |
//!
//! All of them report **`errored`, never `red`**: the code did not fail, we did. Reporting red here
//! would be memoized by Hull (spec §7) and would block a merge on our own outage.

use std::time::{Duration, Instant};

use hull_ci_proto::{Reason, Verdict};

use crate::model::{Step, StepId, StepState};

/// The four clocks. Defaults are design D§10.2's table.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub step: Duration,
    pub job: Duration,
    pub queue_wait: Duration,
    pub fetch: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            step: Duration::from_secs(20 * 60),
            job: Duration::from_secs(60 * 60),
            queue_wait: Duration::from_secs(30 * 60),
            fetch: Duration::from_secs(5 * 60),
        }
    }
}

/// Which clock fired. The mapping to [`Reason`] is the point of the type: it is the one place that
/// decides what a user is told about *why* we could not answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    Step,
    Job,
    /// Over the tenant's plan quota for longer than we are willing to hold the work (design D§4.5).
    QueueWait,
    Fetch,
}

impl Expiry {
    pub fn reason(self) -> Reason {
        match self {
            // A wall clock is a timeout, whoever's fault it was.
            Expiry::Step | Expiry::Job => Reason::Timeout,
            // Not a timeout to the user: the job sat in a queue because the plan ran out. Design
            // D§4.5 is explicit that this is `capacity`, so the message can say "buy more" instead
            // of "your tests are slow".
            Expiry::QueueWait => Reason::Capacity,
            // Design D§10.2 classes a fetch expiry as `infra` rather than `timeout`: the source
            // never arrived, which from Hull's side is indistinguishable from us being broken.
            Expiry::Fetch => Reason::Infra,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Expiry::Step => "step wall clock",
            Expiry::Job => "job wall clock",
            Expiry::QueueWait => "queue wait",
            Expiry::Fetch => "source fetch",
        }
    }
}

/// The verdict for a clock that fired outside the step model (fetch and job level).
///
/// Built from fixed text and a duration — no job bytes are involved, so there is nothing to
/// sanitize and nothing a job can influence.
pub fn expiry_verdict(expiry: Expiry, limit: Duration) -> Verdict {
    Verdict::errored(
        expiry.reason(),
        format!("{} exceeded {} — no verdict produced", expiry.as_str(), human(limit)),
    )
}

/// Expire whatever is overdue, marking each step `errored` with the right [`Reason`].
///
/// The step wall clock is armed **at lease time**, not at the node's "running" signal: the moment
/// the work leaves our hands is the last moment we can be sure of, and a node that dies between
/// lease and start would otherwise never trip a clock at all.
pub fn sweep(steps: &mut [Step], t: &Timeouts, now: Instant) -> Vec<(StepId, Expiry)> {
    let mut fired = Vec::new();
    for s in steps.iter_mut() {
        let Some((deadline, expiry)) = step_deadline(s, t) else { continue };
        if now < deadline {
            continue;
        }
        // `errored`, never `failed` — see the module docs.
        if s.transition(StepState::Errored).is_ok() {
            s.error_reason = Some(expiry.reason());
            s.finished_at = Some(now);
            s.detail = format!("{} exceeded {}", expiry.as_str(), human(match expiry {
                Expiry::QueueWait => t.queue_wait,
                _ => s.spec.timeout.unwrap_or(t.step),
            }));
            fired.push((s.id.clone(), expiry));
        }
    }
    fired
}

/// The soonest moment the sweep could have something to do, so the driver can sleep exactly that
/// long instead of polling.
pub fn next_step_deadline(steps: &[Step], t: &Timeouts) -> Option<Instant> {
    steps.iter().filter_map(|s| step_deadline(s, t).map(|(d, _)| d)).min()
}

fn step_deadline(s: &Step, t: &Timeouts) -> Option<(Instant, Expiry)> {
    match s.state {
        // Waiting for capacity — the queue-wait clock, from the moment it became schedulable.
        StepState::Pending | StepState::Ready => s.ready_at.map(|at| (at + t.queue_wait, Expiry::QueueWait)),
        // In someone else's hands — the step wall clock.
        StepState::Leased | StepState::Running => {
            s.started_at.map(|at| (at + s.spec.timeout.unwrap_or(t.step), Expiry::Step))
        }
        _ => None,
    }
}

fn human(d: Duration) -> String {
    let secs = d.as_secs();
    let (mins, rem) = (secs / 60, secs % 60);
    if mins > 0 && rem == 0 {
        format!("{mins}m")
    } else {
        format!("{secs}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::StepSpec;

    fn leased(id: &str, at: Instant) -> Step {
        let mut s = Step::new(id.into(), StepSpec::new("test", vec!["t".into()], "img"));
        s.state = StepState::Leased;
        s.started_at = Some(at);
        s
    }

    #[test]
    fn every_clock_maps_to_errored_with_the_designed_reason() {
        // The regression this guards: a timeout that reports `red` gets memoized by Hull and blocks
        // a merge on our outage (spec §7).
        assert_eq!(Expiry::Step.reason(), Reason::Timeout);
        assert_eq!(Expiry::Job.reason(), Reason::Timeout);
        assert_eq!(Expiry::QueueWait.reason(), Reason::Capacity);
        assert_eq!(Expiry::Fetch.reason(), Reason::Infra);
        for e in [Expiry::Step, Expiry::Job, Expiry::QueueWait, Expiry::Fetch] {
            let v = expiry_verdict(e, Duration::from_secs(300));
            assert_eq!(v.status, hull_ci_proto::Status::Errored, "{e:?} must never be red");
            assert_eq!(v.reason, Some(e.reason()));
        }
    }

    #[test]
    fn a_leased_step_past_its_wall_clock_errors_with_timeout() {
        let t = Timeouts::default();
        let start = Instant::now();
        let mut steps = vec![leased("a", start)];
        assert!(sweep(&mut steps, &t, start + Duration::from_secs(60)).is_empty(), "not yet due");

        let fired = sweep(&mut steps, &t, start + t.step + Duration::from_secs(1));
        assert_eq!(fired, vec![("a".to_string(), Expiry::Step)]);
        assert_eq!(steps[0].state, StepState::Errored);
        assert_eq!(steps[0].error_reason, Some(Reason::Timeout));
    }

    #[test]
    fn a_step_stuck_behind_plan_quota_errors_with_capacity() {
        let t = Timeouts::default();
        let start = Instant::now();
        let mut s = Step::new("q".into(), StepSpec::new("test", vec!["t".into()], "img"));
        s.state = StepState::Ready;
        s.ready_at = Some(start);
        let mut steps = vec![s];

        let fired = sweep(&mut steps, &t, start + t.queue_wait + Duration::from_secs(1));
        assert_eq!(fired, vec![("q".to_string(), Expiry::QueueWait)]);
        assert_eq!(steps[0].error_reason, Some(Reason::Capacity), "a plan limit is not a test failure");
    }

    #[test]
    fn a_pipeline_step_timeout_overrides_the_default() {
        let t = Timeouts::default();
        let start = Instant::now();
        let mut s = leased("a", start);
        s.spec.timeout = Some(Duration::from_secs(30));
        let mut steps = vec![s];
        assert_eq!(sweep(&mut steps, &t, start + Duration::from_secs(31)).len(), 1);
    }

    #[test]
    fn terminal_steps_have_no_deadline() {
        let t = Timeouts::default();
        let mut s = leased("a", Instant::now());
        s.state = StepState::Passed;
        assert!(step_deadline(&s, &t).is_none());
    }
}
