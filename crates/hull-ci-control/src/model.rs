//! The job and step model — design D§4.3.
//!
//! ```text
//! job  : queued → fetching → planning → running → {green | red | errored} → reported
//! step : pending → ready → leased → running → {passed | failed | errored | cached | skipped}
//! ```
//!
//! `reported` is deliberately **not** part of the verdict. The verdict is what the job decided; the
//! report state is whether Hull has heard about it. Keeping them apart is what lets the callback
//! sender retry for an hour (design D§10.1) without the job pretending to still be running, and what
//! lets a duplicate dispatch (spec §9) re-report a finished job without re-running a single step.
//!
//! The transition tables are exhaustive rather than permissive: an illegal transition is a bug we
//! want to fail loudly on in a test, not silently absorb into a wrong verdict.

use std::time::{Duration, Instant};

use hull_ci_proto::{AuthorClass, Dispatch, Reason, Status, Verdict};

pub type JobId = String;
pub type StepId = String;

/// Where a job is in its life. `Green`/`Red`/`Errored` mirror [`Status`]; the two report states are
/// the delivery half (design D§10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Queued,
    Fetching,
    Planning,
    Running,
    Green,
    Red,
    Errored,
    /// The verdict reached Hull.
    Reported,
    /// Retries exhausted. Parked and alerted — never silently dropped (design D§10.1).
    ReportFailed,
}

impl JobState {
    pub fn from_status(status: Status) -> JobState {
        match status {
            Status::Green => JobState::Green,
            Status::Red => JobState::Red,
            Status::Errored => JobState::Errored,
        }
    }

    /// A job that has decided. It may still owe Hull a callback.
    pub fn has_verdict(self) -> bool {
        matches!(
            self,
            JobState::Green
                | JobState::Red
                | JobState::Errored
                | JobState::Reported
                | JobState::ReportFailed
        )
    }

    /// A job that will never run another step. Duplicate dispatch re-reports these (spec §9).
    pub fn is_finished(self) -> bool {
        self.has_verdict()
    }

    pub fn as_str(self) -> &'static str {
        match self {
            JobState::Queued => "queued",
            JobState::Fetching => "fetching",
            JobState::Planning => "planning",
            JobState::Running => "running",
            JobState::Green => "green",
            JobState::Red => "red",
            JobState::Errored => "errored",
            JobState::Reported => "reported",
            JobState::ReportFailed => "report_failed",
        }
    }

    /// The legal edges of design D§4.3, plus two the prose implies:
    /// * any pre-verdict state may jump straight to `errored` — the job wall clock (D§10.2) and a
    ///   fetch failure both fire before `running` exists;
    /// * `report_failed` may return to `reported`, because an operator-driven redelivery of a parked
    ///   job is a heal, not a new job.
    pub fn can_transition_to(self, next: JobState) -> bool {
        use JobState::*;
        match (self, next) {
            (Queued, Fetching) => true,
            (Fetching, Planning) => true,
            (Planning, Running) => true,
            (Running, Green | Red | Errored) => true,
            // Planning may decide the verdict without ever running: "nothing detectable to run"
            // is `errored` with `reason: no_tests` (design D§4.4).
            (Queued | Fetching | Planning, Errored) => true,
            (Green | Red | Errored, Reported | ReportFailed) => true,
            (ReportFailed, Reported) => true,
            _ => false,
        }
    }
}

/// Where one step is. `Cached` is a memo hit (design D§6.1) and `Skipped` is a sibling cancelled by
/// fail-fast (design D§6.6); both are terminal and neither is a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepState {
    Pending,
    Ready,
    Leased,
    Running,
    Passed,
    Failed,
    Errored,
    Cached,
    Skipped,
}

impl StepState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            StepState::Passed
                | StepState::Failed
                | StepState::Errored
                | StepState::Cached
                | StepState::Skipped
        )
    }

    /// Still occupying capacity somewhere — a candidate for fail-fast cancellation.
    pub fn is_in_flight(self) -> bool {
        !self.is_terminal()
    }

    pub fn as_str(self) -> &'static str {
        match self {
            StepState::Pending => "pending",
            StepState::Ready => "ready",
            StepState::Leased => "leased",
            StepState::Running => "running",
            StepState::Passed => "passed",
            StepState::Failed => "failed",
            StepState::Errored => "errored",
            StepState::Cached => "cached",
            StepState::Skipped => "skipped",
        }
    }

    pub fn can_transition_to(self, next: StepState) -> bool {
        use StepState::*;
        match (self, next) {
            (Pending, Ready) => true,
            (Ready, Leased) => true,
            (Leased, Running) => true,
            (Leased | Running, Passed | Failed | Errored) => true,
            // A lease that expires puts the step back on the queue (design D§5.3).
            (Leased | Running, Ready) => true,
            // A memo hit resolves a step before it is ever scheduled (design D§6.1).
            (Pending | Ready, Cached) => true,
            // Fail-fast cancels anything not yet terminal (design D§6.6).
            (Pending | Ready | Leased | Running, Skipped) => true,
            // Queue-wait / step wall clock expiry (design D§10.2).
            (Pending | Ready, Errored) => true,
            _ => false,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StateError {
    #[error("illegal job transition {from} → {to}")]
    Job { from: &'static str, to: &'static str },
    #[error("illegal step transition {from} → {to}")]
    Step { from: &'static str, to: &'static str },
}

/// What the planner emitted for one step. `argv` is opaque data that is executed **inside the
/// sandbox only** (design D§4.4) — the control plane never runs it, never shells it out, and never
/// interpolates it into anything.
#[derive(Debug, Clone)]
pub struct StepSpec {
    pub name: String,
    pub argv: Vec<String>,
    pub image: String,
    /// Pipeline override for the step wall clock; `None` takes the default (design D§10.2).
    pub timeout: Option<Duration>,
    /// A failure here does not decide the job red (design D§6.6).
    pub continue_on_error: bool,
}

impl StepSpec {
    pub fn new(name: impl Into<String>, argv: Vec<String>, image: impl Into<String>) -> Self {
        StepSpec {
            name: name.into(),
            argv,
            image: image.into(),
            timeout: None,
            continue_on_error: false,
        }
    }

    pub fn continue_on_error(mut self) -> Self {
        self.continue_on_error = true;
        self
    }
}

#[derive(Debug, Clone)]
pub struct Step {
    pub id: StepId,
    pub spec: StepSpec,
    pub state: StepState,
    pub attempt: u32,
    /// The node holding the lease. Verdict integrity (design D§10.4) is exactly this field: a result
    /// from anyone else is dropped.
    pub node_id: Option<String>,
    pub lease_expires_at: Option<Instant>,
    /// When the step became schedulable — the clock the queue-wait timeout runs against.
    pub ready_at: Option<Instant>,
    /// When a node actually started it — the clock the step wall clock runs against.
    pub started_at: Option<Instant>,
    pub finished_at: Option<Instant>,
    pub exit_code: Option<i32>,
    pub log_key: Option<String>,
    /// Node-supplied detail. **Untrusted** (spec §14.5): sanitize on every use.
    pub detail: String,
    /// Set only when `state == Errored`, so the aggregator can name a [`Reason`] instead of guessing.
    pub error_reason: Option<Reason>,
}

impl Step {
    pub fn new(id: StepId, spec: StepSpec) -> Self {
        Step {
            id,
            spec,
            state: StepState::Pending,
            attempt: 0,
            node_id: None,
            lease_expires_at: None,
            ready_at: None,
            started_at: None,
            finished_at: None,
            exit_code: None,
            log_key: None,
            detail: String::new(),
            error_reason: None,
        }
    }

    pub fn transition(&mut self, next: StepState) -> Result<(), StateError> {
        if !self.state.can_transition_to(next) {
            return Err(StateError::Step { from: self.state.as_str(), to: next.as_str() });
        }
        self.state = next;
        Ok(())
    }

    /// A failure that does not decide the verdict (design D§6.6) still counts as "we ran it".
    pub fn failed_fatally(&self) -> bool {
        self.state == StepState::Failed && !self.spec.continue_on_error
    }
}

#[derive(Debug, Clone)]
pub struct Job {
    pub id: JobId,
    /// The dispatch verbatim. `callback_url` and `source_url` are **opaque** (spec §5) and are only
    /// ever used as received.
    pub dispatch: Dispatch,
    /// Derived from the actor, never assertable by a pipeline (design D§1).
    pub author_class: AuthorClass,
    pub state: JobState,
    pub steps: Vec<Step>,
    pub verdict: Option<Verdict>,
    pub created_at: Instant,
    /// The job wall clock (design D§10.2, default 60 min).
    pub deadline_at: Instant,
    pub report_attempts: u32,
    /// Every distinct `callback_url` that has asked about this tree, in arrival order, starting with
    /// the dispatch that created the job.
    ///
    /// **Work is deduplicated by `(repo, tree_id)`; delivery is not.** Two different changes can share
    /// one tree — that is the entire premise of tree-keyed memoization (a rebase, a cherry-pick, a
    /// revert of a revert) — and each arrives with its *own* `callback_url`. Spec §9 says Hull's
    /// in-flight de-dup is best-effort and in-memory, so a second dispatch for a tree we already know
    /// is expected: after a Hull restart, across replicas, or with `{"force": true}`. Reporting only
    /// to the first URL would leave that second change unverified forever, waiting on an answer that
    /// was delivered somewhere else. §9's own wording is the hint — be idempotent "per `(tree_id)`
    /// **or** per `callback_url`": the tree keys the *work*, the callback keys the *answer*.
    pub callback_urls: Vec<String>,
}

impl Job {
    /// Record a `callback_url` that must receive this job's verdict. Returns whether it was new.
    ///
    /// De-duplicated, because an ordinary retry of the *same* dispatch must not make us deliver the
    /// same verdict twice to the same place.
    pub fn add_callback_url(&mut self, url: &str) -> bool {
        if self.callback_urls.iter().any(|u| u == url) {
            return false;
        }
        self.callback_urls.push(url.to_string());
        true
    }
}

impl Job {
    pub fn new(
        id: JobId,
        dispatch: Dispatch,
        author_class: AuthorClass,
        now: Instant,
        job_timeout: Duration,
    ) -> Self {
        let callback_urls = vec![dispatch.callback_url.clone()];
        Job {
            id,
            dispatch,
            author_class,
            state: JobState::Queued,
            steps: Vec::new(),
            verdict: None,
            created_at: now,
            deadline_at: now + job_timeout,
            report_attempts: 0,
            callback_urls,
        }
    }

    /// The idempotency key of spec §9 / design D§4.1: `(repo, tree_id)`.
    pub fn key(&self) -> (String, String) {
        (self.dispatch.repo.clone(), self.dispatch.tree_id.clone())
    }

    pub fn transition(&mut self, next: JobState) -> Result<(), StateError> {
        if !self.state.can_transition_to(next) {
            return Err(StateError::Job { from: self.state.as_str(), to: next.as_str() });
        }
        self.state = next;
        Ok(())
    }

    pub fn step_mut(&mut self, step_id: &str) -> Option<&mut Step> {
        self.steps.iter_mut().find(|s| s.id == step_id)
    }

    pub fn step(&self, step_id: &str) -> Option<&Step> {
        self.steps.iter().find(|s| s.id == step_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_walks_the_designed_path_and_refuses_shortcuts() {
        use JobState::*;
        for (a, b) in [
            (Queued, Fetching),
            (Fetching, Planning),
            (Planning, Running),
            (Running, Green),
            (Green, Reported),
        ] {
            assert!(a.can_transition_to(b), "{a:?} → {b:?} is on the D§4.3 path");
        }
        assert!(!Queued.can_transition_to(Running), "a job cannot skip fetch and plan");
        assert!(!Reported.can_transition_to(Green), "a reported job is done");
        assert!(!Green.can_transition_to(Red), "one verdict, ever (D§6.6)");
    }

    #[test]
    fn a_job_may_error_before_it_ever_runs() {
        // Fetch timeout and "nothing detectable to run" both decide the job with no steps at all.
        assert!(JobState::Queued.can_transition_to(JobState::Errored));
        assert!(JobState::Fetching.can_transition_to(JobState::Errored));
        assert!(JobState::Planning.can_transition_to(JobState::Errored));
    }

    #[test]
    fn a_lost_lease_returns_a_step_to_the_queue_not_to_failure() {
        // Design D§5.3: a missed renewal is our problem, so the step is retried, not marked red.
        assert!(StepState::Leased.can_transition_to(StepState::Ready));
        assert!(StepState::Running.can_transition_to(StepState::Ready));
        assert!(!StepState::Passed.can_transition_to(StepState::Failed));
    }

    #[test]
    fn continue_on_error_failure_is_not_a_fatal_failure() {
        let mut s = Step::new("s1".into(), StepSpec::new("lint", vec!["x".into()], "img").continue_on_error());
        s.state = StepState::Failed;
        assert!(!s.failed_fatally());
    }
}
