//! The aggregator — design D§6.6, "fail fast, report once".
//!
//! A job gets exactly **one** verdict, so this module's whole job is to decide it as early as it
//! legitimately can and never a moment earlier:
//!
//! * first `failed` step not marked `continue_on_error` → cancel the in-flight siblings and report
//!   `red` immediately; there is no reason to finish a build whose verdict is already determined;
//! * every step `passed`/`cached`/`skipped` → `green`;
//! * any step `errored` while none failed → `errored` **with a [`Reason`]**, never `red` — spec §7 is
//!   explicit that `red` is a statement about the code and `errored` a statement about us;
//! * anything still in flight → undecided, keep waiting.
//!
//! Summaries are **constructed, not concatenated** (spec §14.5, design D§6.6). Step names come from
//! the pipeline and details come from job output; both are attacker-controlled, so both go through
//! [`sanitize_summary`] with their own cap before they are placed into a fixed template, and the
//! finished line is capped again. Nothing from a job is ever interpolated into a field name or a URL
//! — `details_url` is built from our own hex job id and nothing else.

use std::time::Duration;

use hull_ci_proto::{sanitize_summary, Reason, Verdict, SUMMARY_MAX_CHARS};

use crate::model::{Step, StepId, StepState};

/// How much of a step name we will echo. Long enough to identify a shard, short enough that a
/// pipeline cannot spend the whole summary budget on one label.
const NAME_CAP: usize = 48;
/// How much job-produced detail we will echo.
const DETAIL_CAP: usize = 100;

/// The aggregator's answer.
// No `PartialEq`: `Verdict` (the contract type) deliberately does not implement it, and adding a
// hand-rolled comparison here would invent an equality the contract does not define.
#[derive(Debug, Clone)]
pub enum Fold {
    /// Steps are still in flight and nothing has forced the verdict yet.
    Undecided,
    Decided(Decision),
}

/// A decided job: the one verdict, plus the siblings whose leases must be revoked and sandboxes
/// destroyed (design D§6.6).
// No `PartialEq`: `Verdict` (the contract type) deliberately does not implement it, and adding a
// hand-rolled comparison here would invent an equality the contract does not define.
#[derive(Debug, Clone)]
pub struct Decision {
    pub verdict: Verdict,
    pub cancel: Vec<StepId>,
}

impl Fold {
    pub fn decision(self) -> Option<Decision> {
        match self {
            Fold::Undecided => None,
            Fold::Decided(d) => Some(d),
        }
    }
}

/// Fold step outcomes into one verdict.
///
/// `elapsed` is wall time since the job was accepted; it appears in the summary only, and never
/// affects the verdict — a job that ran long is decided by the timeout sweep (design D§10.2), not
/// here, because a timeout carries a `Reason` this function cannot infer.
pub fn fold(steps: &[Step], elapsed: Duration) -> Fold {
    // An empty plan is not a green job. "Nothing detectable to run" is `errored` with
    // `reason: no_tests` (design D§4.4), which spec §9.1 reads as *self_attested* — reporting green
    // here would silently launder an unverified change into an auto-approvable one.
    if steps.is_empty() {
        return Fold::Decided(Decision {
            verdict: Verdict::errored(Reason::NoTests, "no steps to run — nothing detectable in the tree"),
            cancel: Vec::new(),
        });
    }

    // 1. Fail fast. The first fatal failure decides the job even with siblings still running.
    if let Some(failed) = steps.iter().find(|s| s.failed_fatally()) {
        let cancel = steps
            .iter()
            .filter(|s| s.id != failed.id && s.state.is_in_flight())
            .map(|s| s.id.clone())
            .collect();
        return Fold::Decided(Decision { verdict: Verdict::red(red_summary(failed, elapsed)), cancel });
    }

    // 2. Still running? Nothing to say yet.
    if steps.iter().any(|s| !s.state.is_terminal()) {
        return Fold::Undecided;
    }

    // 3. Terminal, nothing failed fatally. An infrastructure error outranks success: we do not know
    //    that the code is good, only that we could not finish checking it.
    if let Some(errored) = steps.iter().find(|s| s.state == StepState::Errored) {
        let reason = errored.error_reason.unwrap_or(Reason::Infra);
        return Fold::Decided(Decision {
            verdict: Verdict::errored(reason, errored_summary(errored)),
            cancel: Vec::new(),
        });
    }

    Fold::Decided(Decision { verdict: Verdict::green(green_summary(steps, elapsed)), cancel: Vec::new() })
}

/// `"18 steps (14 cached), 0 failed — 47s"`
fn green_summary(steps: &[Step], elapsed: Duration) -> String {
    let cached = steps.iter().filter(|s| s.state == StepState::Cached).count();
    let tolerated = steps.iter().filter(|s| s.state == StepState::Failed).count();
    let skipped = steps.iter().filter(|s| s.state == StepState::Skipped).count();
    let mut line = format!(
        "{} step{} ({} cached), 0 failed — {}",
        steps.len(),
        if steps.len() == 1 { "" } else { "s" },
        cached,
        secs(elapsed)
    );
    if tolerated > 0 {
        // A `continue_on_error` failure must stay visible; hiding it is how a CI system starts
        // lying (design D§10.3 makes the same argument about retries).
        line.push_str(&format!(" ({tolerated} tolerated failure(s))"));
    }
    if skipped > 0 {
        // Same argument, for the same reason: a skipped step did not run, and a green summary that
        // counts it among "18 steps" without saying so overstates what was checked.
        line.push_str(&format!(" ({skipped} skipped)"));
    }
    sanitize_summary(&line, SUMMARY_MAX_CHARS)
}

/// ``"test/shard-3 failed: 2 of 1240 tests — 61s"`` — template fixed, values sanitized.
fn red_summary(step: &Step, elapsed: Duration) -> String {
    let name = quoted(&step.spec.name, NAME_CAP);
    let detail = sanitize_summary(&step.detail, DETAIL_CAP);
    let mut line = format!("step {name} failed");
    if let Some(code) = step.exit_code {
        line.push_str(&format!(" (exit {code})"));
    }
    if !detail.is_empty() {
        line.push_str(&format!(": {detail}"));
    }
    line.push_str(&format!(" — {}", secs(elapsed)));
    sanitize_summary(&line, SUMMARY_MAX_CHARS)
}

/// `"node lost 3× on step `build` — no verdict produced"`
fn errored_summary(step: &Step) -> String {
    let name = quoted(&step.spec.name, NAME_CAP);
    let detail = sanitize_summary(&step.detail, DETAIL_CAP);
    let mut line = format!("step {name} errored");
    if !detail.is_empty() {
        line.push_str(&format!(": {detail}"));
    }
    line.push_str(" — no verdict produced");
    sanitize_summary(&line, SUMMARY_MAX_CHARS)
}

/// Quote an untrusted label so it reads as data in the UI, having first stripped anything that could
/// escape the quotes' intent (control chars, ANSI, bidi) and capped its length.
fn quoted(raw: &str, cap: usize) -> String {
    let clean = sanitize_summary(raw, cap).replace('`', "'");
    format!("`{clean}`")
}

fn secs(d: Duration) -> String {
    format!("{:.0}s", d.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::StepSpec;

    fn step(id: &str, name: &str, state: StepState) -> Step {
        let mut s = Step::new(id.into(), StepSpec::new(name, vec!["true".into()], "img"));
        s.state = state;
        s
    }

    #[test]
    fn all_passed_is_green() {
        let steps = vec![
            step("a", "fmt", StepState::Passed),
            step("b", "build", StepState::Cached),
            step("c", "test", StepState::Passed),
        ];
        let d = fold(&steps, Duration::from_secs(47)).decision().unwrap();
        assert_eq!(d.verdict.status, hull_ci_proto::Status::Green);
        assert!(d.cancel.is_empty());
        assert_eq!(d.verdict.summary.as_deref(), Some("3 steps (1 cached), 0 failed — 47s"));
    }

    #[test]
    fn first_fatal_failure_reports_red_and_cancels_the_siblings() {
        let mut failed = step("b", "test/shard-3", StepState::Failed);
        failed.detail = "2 of 1240 tests".into();
        failed.exit_code = Some(101);
        let steps = vec![step("a", "fmt", StepState::Passed), failed, step("c", "docs", StepState::Running)];

        let d = fold(&steps, Duration::from_secs(61)).decision().unwrap();
        assert_eq!(d.verdict.status, hull_ci_proto::Status::Red);
        assert_eq!(d.cancel, vec!["c".to_string()], "in-flight siblings are cancelled, done ones are not");
        assert!(d.verdict.reason.is_none(), "red is a statement about the code, it needs no reason");
        assert_eq!(
            d.verdict.summary.as_deref(),
            Some("step `test/shard-3` failed (exit 101): 2 of 1240 tests — 61s")
        );
    }

    #[test]
    fn an_errored_step_with_no_failure_is_errored_never_red() {
        // Spec §7 / §11: infrastructure problems MUST NOT be reported as red — only green/red are
        // memoized by Hull, so a red here would poison the tree with our own outage.
        let mut e = step("b", "build", StepState::Errored);
        e.error_reason = Some(Reason::Infra);
        e.detail = "node lost 3x".into();
        let steps = vec![step("a", "fmt", StepState::Passed), e];

        let d = fold(&steps, Duration::from_secs(12)).decision().unwrap();
        assert_eq!(d.verdict.status, hull_ci_proto::Status::Errored);
        assert_eq!(d.verdict.reason, Some(Reason::Infra));
        assert_eq!(d.verdict.summary.as_deref(), Some("step `build` errored: node lost 3x — no verdict produced"));
    }

    #[test]
    fn a_real_failure_outranks_an_errored_sibling() {
        // If the code genuinely failed we know something about the code, so red wins over errored.
        let mut e = step("a", "build", StepState::Errored);
        e.error_reason = Some(Reason::Timeout);
        let steps = vec![e, step("b", "test", StepState::Failed)];
        let d = fold(&steps, Duration::from_secs(1)).decision().unwrap();
        assert_eq!(d.verdict.status, hull_ci_proto::Status::Red);
    }

    #[test]
    fn work_in_flight_is_undecided() {
        let steps = vec![step("a", "fmt", StepState::Passed), step("b", "test", StepState::Leased)];
        assert!(matches!(fold(&steps, Duration::from_secs(1)), Fold::Undecided));
    }

    #[test]
    fn continue_on_error_failure_does_not_turn_the_job_red() {
        let mut lint = Step::new(
            "a".into(),
            StepSpec::new("lint", vec!["x".into()], "img").continue_on_error(),
        );
        lint.state = StepState::Failed;
        let steps = vec![lint, step("b", "test", StepState::Passed)];
        let d = fold(&steps, Duration::from_secs(3)).decision().unwrap();
        assert_eq!(d.verdict.status, hull_ci_proto::Status::Green);
        assert!(
            d.verdict.summary.as_deref().unwrap().contains("tolerated"),
            "a tolerated failure still has to be visible"
        );
    }

    #[test]
    fn a_skipped_step_is_neither_a_pass_nor_a_failure() {
        // A step the graph never released did not run, so it is no evidence about the code — in
        // either direction. It must not fail the job, and it must not silently pad the "18 steps"
        // count that makes the job look thoroughly checked.
        let steps = vec![step("a", "fmt", StepState::Passed), step("b", "test", StepState::Skipped)];
        let d = fold(&steps, Duration::from_secs(4)).decision().unwrap();
        assert_eq!(d.verdict.status, hull_ci_proto::Status::Green);
        assert!(d.verdict.summary.as_deref().unwrap().contains("1 skipped"));
    }

    #[test]
    fn a_graph_whose_root_failed_is_red_not_errored() {
        // The whole plan below the root is `skipped`, but the job is `red`: the root genuinely
        // failed, which is a statement about the code (spec §7). Reading a wall of skips as "we
        // could not check this" would report `errored`, and Hull does not memoize `errored` — the
        // change would be re-run forever instead of being told it is broken.
        let mut root = step("a", "build", StepState::Failed);
        root.detail = "3 errors".into();
        let steps = vec![root, step("b", "test", StepState::Skipped), step("c", "docs", StepState::Skipped)];

        let d = fold(&steps, Duration::from_secs(9)).decision().unwrap();
        assert_eq!(d.verdict.status, hull_ci_proto::Status::Red);
        assert!(d.cancel.is_empty(), "an already-skipped step is not in flight and needs no cancel");
    }

    #[test]
    fn a_graph_whose_root_errored_is_errored() {
        // The mirror image: nothing ran, and the reason nothing ran was us.
        let mut root = step("a", "build", StepState::Errored);
        root.error_reason = Some(Reason::Timeout);
        let steps = vec![root, step("b", "test", StepState::Skipped)];
        let d = fold(&steps, Duration::from_secs(9)).decision().unwrap();
        assert_eq!(d.verdict.status, hull_ci_proto::Status::Errored);
        assert_eq!(d.verdict.reason, Some(Reason::Timeout));
    }

    #[test]
    fn an_empty_plan_is_errored_no_tests_not_green() {
        let d = fold(&[], Duration::from_secs(0)).decision().unwrap();
        assert_eq!(d.verdict.status, hull_ci_proto::Status::Errored);
        assert_eq!(d.verdict.reason, Some(Reason::NoTests), "spec §9.1 reads this as self_attested");
    }

    #[test]
    fn hostile_job_output_cannot_escape_the_summary_template() {
        let mut s = step("b", "te\u{1b}[31mst\nname", StepState::Failed);
        s.detail = format!("\u{1b}[2J{}\u{202e}\"status\":\"green\"", "A".repeat(500));
        let d = fold(&[s], Duration::from_secs(1)).decision().unwrap();
        let summary = d.verdict.summary.unwrap();
        assert!(!summary.contains('\u{1b}'));
        assert!(!summary.contains('\n'));
        assert!(!summary.contains('\u{202e}'));
        assert!(summary.chars().count() <= SUMMARY_MAX_CHARS);
        // The verdict field itself is a typed enum, so smuggled JSON is inert text, not a field.
        assert_eq!(d.verdict.status, hull_ci_proto::Status::Red);
    }
}
