//! The dependency graph — design D§4.3's `edge (job_id, from_step, to_step)`, scheduled per D§6.5.
//!
//! A plan is a DAG, not a list. The scheduling rule is one sentence: **a step becomes `ready` when
//! every step it `needs` has finished without blocking it**, and *everything* that is ready goes out
//! at once. The "at once" is the whole point of design D§6.5 — "a 4-step pipeline with one dependency
//! edge is 2 steps deep in wall clock, not 4" — so this module never picks a single step to run next.
//! It answers, for every pending step, whether the graph still holds it, and the caller schedules
//! whatever came free in one pass.
//!
//! Three things a naive `needs` check gets wrong, and this one does not:
//!
//! * **A blocked step must *finish*, not wait.** If a dependency failed, errored, or was itself
//!   skipped, its dependents can never run — so they become `skipped`, which is terminal. A step left
//!   `pending` forever is a job that never folds to a verdict, and spec §10 is explicit that Hull will
//!   not time it out for us: the tree would simply stay unverified until a human noticed.
//! * **A tolerated failure is not a block.** `continue_on_error` means the pipeline already said this
//!   failure does not decide the job (design D§6.6), so it must not silently decide the *sub-graph*
//!   underneath it either. Its dependents run.
//! * **A graph we cannot satisfy must not hang.** The planner guarantees the DAG is acyclic and that
//!   every `needs` target was already declared (design D§4.4), so a cycle or a dangling edge here is a
//!   planner bug rather than user error. We still refuse to wait an hour for the job wall clock to
//!   notice: the affected steps are `errored` with `reason: infra` immediately — never `red`, because
//!   nothing about the code has been learned (spec §7).

use std::time::Instant;

use hull_ci_proto::{sanitize_summary, Reason};

use crate::model::{Step, StepId, StepState};

/// How much of a `needs` label we echo back. Design D§4.4 caps a step name at 64 chars, so this
/// truncates nothing legitimate — it bounds what a hostile pipeline can spend our summary budget on.
const NEEDS_NAME_CAP: usize = 64;

/// What the graph did to one step that was waiting on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Advance {
    /// Every dependency finished without blocking it: schedulable now.
    Ready,
    /// A dependency failed fatally, errored, or was itself skipped. Terminal, and neither a pass nor
    /// a failure — see [`crate::aggregate::fold`].
    Skipped,
    /// The plan asked for something no walk of the graph can deliver. `errored`/`infra`.
    Broken,
}

/// Move every step the graph has just unblocked, and refuse to leave one waiting forever.
///
/// Idempotent and cheap: the caller runs it on every pass of the driver loop, because the only thing
/// that changes a step's gate is another step reaching a terminal state, which happens
/// asynchronously.
pub fn advance(steps: &mut [Step], now: Instant) -> Vec<(StepId, Advance)> {
    let mut moved = Vec::new();

    // Runs to a fixpoint rather than making one pass: a skip *cascades*, because skipping a step
    // blocks its own dependents, which blocks theirs. Promotion never cascades (a step becoming
    // `ready` unblocks nobody), so this converges in one extra pass for an already-settled graph, and
    // terminates regardless because every pass that continues moved at least one step out of
    // `pending` and no step ever returns to it.
    loop {
        let snapshot: Vec<(&str, StepState, bool)> = steps
            .iter()
            .map(|s| (s.spec.name.as_str(), s.state, s.spec.continue_on_error))
            .collect();
        // The snapshot borrows `steps`; the gate decisions are computed against it first so the
        // mutation below sees a consistent view of the graph rather than a half-updated one.
        let decisions: Vec<Gate> = steps
            .iter()
            .map(|s| {
                if s.state == StepState::Pending {
                    gate(&s.spec.needs, &snapshot)
                } else {
                    Gate::Wait
                }
            })
            .collect();

        let mut changed = false;
        for (step, decision) in steps.iter_mut().zip(decisions) {
            let advance = match decision {
                Gate::Wait => continue,
                Gate::Ready => {
                    if step.transition(StepState::Ready).is_err() {
                        continue;
                    }
                    // The queue-wait clock (design D§10.2) starts *here*, not when the job started:
                    // time spent waiting on a dependency is not time spent waiting for capacity, and
                    // billing it to the queue would error healthy long pipelines with `capacity`.
                    step.ready_at = Some(now);
                    Advance::Ready
                }
                Gate::Skip => {
                    if step.transition(StepState::Skipped).is_err() {
                        continue;
                    }
                    step.finished_at = Some(now);
                    Advance::Skipped
                }
                Gate::Undeclared(name) => {
                    let name = quoted(name);
                    if !error_infra(step, now, format!("needs {name}, which the plan does not declare"))
                    {
                        continue;
                    }
                    Advance::Broken
                }
            };
            moved.push((step.id.clone(), advance));
            changed = true;
        }
        if !changed {
            break;
        }
    }

    // Nothing ready, nothing in flight, and something still pending: every remaining step is waiting
    // on a step that is itself waiting, which is a cycle. Left alone it would sit silent until the
    // job wall clock (design D§10.2) — an hour to say something we can say now, and with a worse
    // message. A planner bug, so `errored`/`infra`; the fold still lets a genuine failure elsewhere
    // outrank it.
    let live = steps
        .iter()
        .any(|s| matches!(s.state, StepState::Ready | StepState::Leased | StepState::Running));
    if !live {
        for step in steps.iter_mut().filter(|s| s.state == StepState::Pending) {
            let detail = "waiting on a dependency that can never start (cycle in the plan's needs edges)";
            if error_infra(step, now, detail.to_string()) {
                moved.push((step.id.clone(), Advance::Broken));
            }
        }
    }

    moved
}

/// What one step's `needs` list says about it.
enum Gate {
    /// Schedulable.
    Ready,
    /// A dependency will never let it run.
    Skip,
    /// A dependency has not finished yet.
    Wait,
    /// A dependency that is not in this plan at all.
    Undeclared(String),
}

fn gate(needs: &[String], snapshot: &[(&str, StepState, bool)]) -> Gate {
    let mut blocked = false;
    let mut waiting = false;
    for name in needs {
        match dep_status(name, snapshot) {
            // Returned immediately, and ahead of `blocked`: a dangling edge means the graph we were
            // handed is not the graph the pipeline described, which is worth saying out loud even
            // when another dependency also failed. If something genuinely failed, `fold`'s fail-fast
            // rule still makes the *job* red — rule 1 outranks rule 3 — so surfacing this costs no
            // accuracy in the verdict, only precision in this one step's detail.
            DepStatus::Unknown => return Gate::Undeclared(name.clone()),
            DepStatus::Blocked => blocked = true,
            DepStatus::Waiting => waiting = true,
            DepStatus::Satisfied => {}
        }
    }
    match (blocked, waiting) {
        (true, _) => Gate::Skip,
        (false, true) => Gate::Wait,
        (false, false) => Gate::Ready,
    }
}

enum DepStatus {
    Satisfied,
    Blocked,
    Waiting,
    Unknown,
}

fn dep_status(name: &str, snapshot: &[(&str, StepState, bool)]) -> DepStatus {
    let Some((_, state, continue_on_error)) = snapshot.iter().find(|(n, _, _)| *n == name) else {
        return DepStatus::Unknown;
    };
    match state {
        // A memo hit is as finished as a run (design D§6.1) — the dependent must not care which.
        StepState::Passed | StepState::Cached => DepStatus::Satisfied,
        // Design D§6.6: the pipeline said this failure does not decide the job, so it must not
        // decide the sub-graph under it either.
        StepState::Failed if *continue_on_error => DepStatus::Satisfied,
        StepState::Failed | StepState::Errored | StepState::Skipped => DepStatus::Blocked,
        _ => DepStatus::Waiting,
    }
}

/// Mark a step `errored` for a reason that is ours, not the code's (spec §7). Returns whether the
/// transition was legal — a step that has already moved on is left alone.
fn error_infra(step: &mut Step, now: Instant, detail: String) -> bool {
    if step.transition(StepState::Errored).is_err() {
        return false;
    }
    step.error_reason = Some(Reason::Infra);
    step.detail = detail;
    step.finished_at = Some(now);
    true
}

/// Quote a pipeline-supplied label so it reads as data, having stripped anything that could escape
/// the quotes' intent (spec §14.5). The same treatment `aggregate` gives a step name, applied here
/// because this detail is composed before it reaches the summary template.
fn quoted(raw: String) -> String {
    let clean = sanitize_summary(&raw, NEEDS_NAME_CAP).replace('`', "'");
    format!("`{clean}`")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::StepSpec;

    /// `(name, needs)` in declaration order, all `pending` — the state `phase_run` builds.
    fn plan(edges: &[(&str, &[&str])]) -> Vec<Step> {
        edges
            .iter()
            .enumerate()
            .map(|(i, (name, needs))| {
                let spec = StepSpec::new(*name, vec!["true".into()], "img")
                    .needs(needs.iter().map(|n| n.to_string()).collect());
                Step::new(format!("s{i}"), spec)
            })
            .collect()
    }

    fn state(steps: &[Step], name: &str) -> StepState {
        steps.iter().find(|s| s.spec.name == name).expect("named step").state
    }

    fn set(steps: &mut [Step], name: &str, to: StepState) {
        steps.iter_mut().find(|s| s.spec.name == name).expect("named step").state = to;
    }

    #[test]
    fn independent_steps_are_all_ready_at_once() {
        // Design D§6.5: the branches of a diamond are 1 level deep, not 2 — a scheduler that
        // promoted one step per pass would serialize a pipeline that was written to fan out.
        let mut steps = plan(&[("a", &[]), ("b", &["a"]), ("c", &["a"]), ("d", &["b", "c"])]);
        let now = Instant::now();

        advance(&mut steps, now);
        assert_eq!(state(&steps, "a"), StepState::Ready);
        assert_eq!(state(&steps, "b"), StepState::Pending, "b waits on a");
        assert_eq!(state(&steps, "d"), StepState::Pending);

        set(&mut steps, "a", StepState::Passed);
        advance(&mut steps, now);
        assert_eq!(state(&steps, "b"), StepState::Ready);
        assert_eq!(state(&steps, "c"), StepState::Ready, "both branches, one pass");
        assert_eq!(state(&steps, "d"), StepState::Pending, "d needs both");

        set(&mut steps, "b", StepState::Passed);
        advance(&mut steps, now);
        assert_eq!(state(&steps, "d"), StepState::Pending, "one of two is not enough");

        set(&mut steps, "c", StepState::Cached);
        advance(&mut steps, now);
        assert_eq!(state(&steps, "d"), StepState::Ready, "a memo hit satisfies an edge (D§6.1)");
    }

    #[test]
    fn a_failure_skips_everything_downstream_of_it_in_one_pass() {
        // The cascade is why this runs to a fixpoint: c is blocked by b, which does not exist as a
        // blocker until b is skipped in this same call.
        let mut steps = plan(&[("a", &[]), ("b", &["a"]), ("c", &["b"]), ("d", &["c"])]);
        let now = Instant::now();
        advance(&mut steps, now);
        set(&mut steps, "a", StepState::Failed);

        advance(&mut steps, now);
        for name in ["b", "c", "d"] {
            assert_eq!(state(&steps, name), StepState::Skipped, "{name} can never run");
            assert!(state(&steps, name).is_terminal(), "a blocked step must finish, not wait");
        }
    }

    #[test]
    fn an_errored_dependency_blocks_just_like_a_failed_one() {
        // A step we could not run tells us nothing about whether its dependent would have passed.
        let mut steps = plan(&[("a", &[]), ("b", &["a"])]);
        let now = Instant::now();
        advance(&mut steps, now);
        set(&mut steps, "a", StepState::Errored);
        advance(&mut steps, now);
        assert_eq!(state(&steps, "b"), StepState::Skipped);
    }

    #[test]
    fn a_tolerated_failure_does_not_block_its_dependents() {
        // Design D§6.6: `continue_on_error` already said this failure does not decide the job, so it
        // must not quietly decide the sub-graph underneath it.
        let mut steps = vec![
            Step::new(
                "s0".into(),
                StepSpec::new("lint", vec!["x".into()], "img").continue_on_error(),
            ),
            Step::new(
                "s1".into(),
                StepSpec::new("test", vec!["x".into()], "img").needs(vec!["lint".into()]),
            ),
        ];
        let now = Instant::now();
        advance(&mut steps, now);
        set(&mut steps, "lint", StepState::Failed);
        advance(&mut steps, now);
        assert_eq!(state(&steps, "test"), StepState::Ready);
    }

    #[test]
    fn a_dependency_still_in_flight_holds_its_dependent_pending() {
        let mut steps = plan(&[("a", &[]), ("b", &["a"])]);
        let now = Instant::now();
        advance(&mut steps, now);
        for busy in [StepState::Ready, StepState::Leased, StepState::Running] {
            set(&mut steps, "a", busy);
            advance(&mut steps, now);
            assert_eq!(state(&steps, "b"), StepState::Pending, "a is {busy:?}");
        }
    }

    #[test]
    fn a_dangling_edge_errors_the_step_instead_of_hanging_the_job() {
        // Spec §10: Hull never times a job out, so "wait for a step that does not exist" is not a
        // slow job, it is a change that is never verified.
        let mut steps = plan(&[("a", &[]), ("b", &["nope"])]);
        let now = Instant::now();
        advance(&mut steps, now);
        let b = steps.iter().find(|s| s.spec.name == "b").unwrap();
        assert_eq!(b.state, StepState::Errored);
        assert_eq!(b.error_reason, Some(Reason::Infra), "our bug, not the code's — never red");
        assert!(b.detail.contains("does not declare"));
    }

    #[test]
    fn a_cycle_errors_rather_than_waiting_for_the_job_wall_clock() {
        let mut steps = plan(&[("a", &["b"]), ("b", &["a"])]);
        let now = Instant::now();
        let moved = advance(&mut steps, now);
        assert_eq!(moved.len(), 2);
        for s in &steps {
            assert_eq!(s.state, StepState::Errored);
            assert_eq!(s.error_reason, Some(Reason::Infra));
            assert!(s.detail.contains("cycle"));
        }
    }

    #[test]
    fn a_cycle_behind_a_healthy_root_is_only_detected_once_the_root_is_done() {
        // The stall guard must not fire while real work is in flight, or a slow first step would
        // error the steps queued behind it.
        let mut steps = plan(&[("a", &[]), ("b", &["a", "c"]), ("c", &["b"])]);
        let now = Instant::now();
        advance(&mut steps, now);
        assert_eq!(state(&steps, "b"), StepState::Pending, "not errored while a is schedulable");
        assert_eq!(state(&steps, "c"), StepState::Pending);

        set(&mut steps, "a", StepState::Passed);
        advance(&mut steps, now);
        assert_eq!(state(&steps, "b"), StepState::Errored);
        assert_eq!(state(&steps, "c"), StepState::Errored);
    }

    #[test]
    fn a_hostile_step_name_cannot_escape_the_detail_it_is_quoted_into() {
        let mut steps = plan(&[("a", &["\u{1b}[31m`x`\nnope"])]);
        advance(&mut steps, Instant::now());
        let detail = &steps[0].detail;
        assert!(!detail.contains('\u{1b}'));
        assert!(!detail.contains('\n'));
        assert_eq!(detail.matches('`').count(), 2, "only the quotes we placed");
    }

    #[test]
    fn advancing_a_settled_graph_moves_nothing() {
        let mut steps = plan(&[("a", &[]), ("b", &["a"])]);
        let now = Instant::now();
        advance(&mut steps, now);
        set(&mut steps, "a", StepState::Passed);
        advance(&mut steps, now);
        assert!(advance(&mut steps, now).is_empty(), "the driver calls this on every pass");
    }
}
