//! The node agent: hold state, heartbeat it, take one [`Assignment`], run it, return a [`StepReport`].
//!
//! Design D§7.1 describes the binary; this is its core loop with the parts other agents own factored
//! out behind seams:
//!
//! - **Transport is not ours.** The control link (D§7.1: "one multiplexed bidirectional stream,
//!   outbound only") is owned by the control-plane side. Here it is the [`ControlLink`] trait, with an
//!   in-memory implementation for tests, so every behaviour below is unit-testable without a network.
//! - **Fetching is not ours, and must not be.** §14.2: "Fetch `source_url` and post the callback from
//!   the control plane / a broker, not from inside the sandbox." D§7.1: the agent "holds **no tenant
//!   credentials and no CI shared secret** — neither the fetch path nor the callback path goes through
//!   it". So [`NodeAgent::run_assignment`] takes an already-materialized workspace path (D§6.2,
//!   "materialize, don't fetch") and there is no credential field anywhere in this module. A sandbox
//!   escape here finds nothing but the ability to be a node.
//!
//! # Outcome mapping
//!
//! `StepOutcome::Failed` is a claim about the code; `StepOutcome::Errored` is a claim about us
//! (proto's `Status` doc, spec §7). The mapping is therefore deliberate:
//!
//! | Situation | Outcome | Why |
//! |---|---|---|
//! | exit 0 | `Passed` | |
//! | non-zero exit | `Failed` | the suite ran and said no |
//! | wall clock fired | `Errored` | §14.4 says so explicitly: we stopped it, so we have no verdict |
//! | killed by a signal | `Failed` | the process ran and died on its own budget (OOM, SIGSEGV in a test) |
//! | nothing detectable to run | `Errored` + [`NodeErrorKind::NoTests`] | §9.1: a statement about coverage |
//! | sandbox/backend failure, refusal | `Errored` + [`NodeErrorKind::Infra`] | our fault |
//!
//! The signal case is the debatable one. It is `Failed` because the job's own process died on the
//! job's own resource budget — the runner did what it was asked and observed the result — whereas a
//! timeout is us intervening. Both are reported with the cause named in `detail`, so a wrong call here
//! is visible rather than laundered.

use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hull_ci_proto::{
    sanitize_summary, Assignment, AuthorClass, BackendCapabilities, NodeState, StepOutcome,
    StepReport, SUMMARY_MAX_CHARS,
};

use crate::capture::{CapturedOutput, OutputCaps};
use crate::detect::{detect_test_command, Detection};
use crate::sandbox::{
    ExecRequest, ExecStatus, ResourceLimits, SandboxBackend, SandboxError, SandboxSpec,
};

/// Why a step errored, in a form the control plane can map to `hull_ci_proto::Reason`.
///
/// **This exists because `StepReport` has no `reason` field**, while `Verdict` does (proto's `Reason`,
/// design G4). The distinction §9.1 rests on — "no tests" means *self_attested*, not *infra failure* —
/// is therefore not expressible on the control↔node protocol, so the node encodes it as a stable
/// prefix on `detail` and the control plane decodes it with [`NodeErrorKind::from_detail`]. A `reason`
/// field on `StepReport` would be strictly better; that is a proto change, and proto is not ours to
/// edit here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeErrorKind {
    /// → `Reason::NoTests`. A statement about coverage (§9.1), not about our infrastructure.
    NoTests,
    /// → `Reason::Timeout`.
    Timeout,
    /// → `Reason::Infra`.
    Infra,
}

impl NodeErrorKind {
    pub fn prefix(self) -> &'static str {
        match self {
            NodeErrorKind::NoTests => "no_tests: ",
            NodeErrorKind::Timeout => "timeout: ",
            NodeErrorKind::Infra => "infra: ",
        }
    }

    /// The proto `Reason` this kind reports on the wire.
    pub fn reason(self) -> hull_ci_proto::Reason {
        match self {
            NodeErrorKind::NoTests => hull_ci_proto::Reason::NoTests,
            NodeErrorKind::Timeout => hull_ci_proto::Reason::Timeout,
            NodeErrorKind::Infra => hull_ci_proto::Reason::Infra,
        }
    }

    /// Decode the kind from a `StepReport::detail`. Returns `None` for a detail that carries no marker
    /// (which the control plane should treat as `Infra`, the conservative default).
    ///
    /// Superseded by [`StepReport::reason`] as the primary channel; retained as a fallback.
    pub fn from_detail(detail: &str) -> Option<NodeErrorKind> {
        [NodeErrorKind::NoTests, NodeErrorKind::Timeout, NodeErrorKind::Infra].into_iter().find(|&kind| detail.starts_with(kind.prefix()))
    }
}

/// Static node configuration.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub node_id: String,
    pub labels: Vec<String>,
    /// Executor slots — D§7.1: "one slot per CPU group (default 2 cores + 4 GB)".
    pub slots_total: u32,
    pub limits: ResourceLimits,
    pub output_caps: OutputCaps,
    /// Where the workspace is mounted inside the sandbox.
    pub workdir: String,
    /// Ceiling on a step's wall clock regardless of what the assignment asks for (D§10.2 default:
    /// 20 min). An assignment may ask for less; it may not ask for more than the node allows.
    pub max_step_timeout: Duration,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            node_id: "node-0".into(),
            labels: Vec::new(),
            slots_total: 1,
            limits: ResourceLimits::default(),
            output_caps: OutputCaps::default(),
            workdir: "/workspace".into(),
            max_step_timeout: Duration::from_secs(20 * 60),
        }
    }
}

/// The agent.
pub struct NodeAgent {
    config: NodeConfig,
    backend: Arc<dyn SandboxBackend>,
    slots_free: AtomicU32,
    /// Trees this node holds extracted, for `tree_affinity` scoring (D§5.2). Materialization is the
    /// control plane's, so the node only *reports* what it has been given.
    warm_trees: Mutex<Vec<String>>,
}

impl NodeAgent {
    pub fn new(config: NodeConfig, backend: Arc<dyn SandboxBackend>) -> Self {
        let unmet = backend.controls().unmet_clauses();
        if unmet.is_empty() {
            tracing::info!(backend = backend.name(), "backend enforces every §14 clause");
        } else {
            // Loud at startup, once: an operator should never have to discover the gap from a refusal
            // in production (D§7.2).
            tracing::warn!(
                backend = backend.name(),
                unmet = ?unmet,
                admits_untrusted = backend.capabilities().admits_untrusted(),
                "backend does not enforce every §14 clause; the scheduler must not place untrusted work here"
            );
        }
        let slots_free = AtomicU32::new(config.slots_total);
        NodeAgent { config, backend, slots_free, warm_trees: Mutex::new(Vec::new()) }
    }

    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    pub fn capabilities(&self) -> BackendCapabilities {
        self.backend.capabilities()
    }

    /// Record that this node holds a materialized tree (D§5.2 affinity input).
    pub fn note_warm_tree(&self, tree_id: impl Into<String>) {
        let tree_id = tree_id.into();
        let mut trees = self.warm_trees.lock().expect("warm_trees poisoned");
        if !trees.contains(&tree_id) {
            trees.push(tree_id);
        }
    }

    /// The heartbeat payload (D§5.1). Capabilities travel on every heartbeat so the scheduler's view
    /// of what this node may be given can never be staler than the node itself.
    pub fn state(&self) -> NodeState {
        NodeState {
            node_id: self.config.node_id.clone(),
            tier: self.backend.tier(),
            labels: self.config.labels.clone(),
            slots_total: self.config.slots_total,
            slots_free: self.slots_free.load(Ordering::SeqCst),
            warm_trees: self.warm_trees.lock().expect("warm_trees poisoned").clone(),
            capabilities: self.backend.capabilities(),
        }
    }

    /// Whether this node may accept an assignment at all. Returns the refusal reason if not.
    ///
    /// The scheduler is the control (D§7.2: "the scheduler refuses to place untrusted work on it").
    /// This is the backstop: a node that is told to run outsider code on a backend that cannot box it
    /// refuses, because being wrong here is a credential-exfiltration hole and being wrong in the
    /// other direction is a requeue.
    pub fn admission_check(&self, a: &Assignment) -> Result<(), String> {
        if a.tier != self.backend.tier() {
            return Err(format!(
                "assignment wants tier {:?}; this node's backend `{}` is tier {:?}",
                a.tier,
                self.backend.name(),
                self.backend.tier()
            ));
        }
        if a.author_class == AuthorClass::Outsider && !self.backend.capabilities().admits_untrusted() {
            return Err(format!(
                "backend `{}` cannot admit untrusted work; unmet: {}",
                self.backend.name(),
                self.backend.controls().unmet_clauses().join("; ")
            ));
        }
        Ok(())
    }

    /// Run one assignment in one single-use sandbox and report.
    ///
    /// `workspace` is the already-materialized tree (D§6.2). The node does not fetch it and holds no
    /// credential that could (§14.2).
    pub async fn run_assignment(&self, a: &Assignment, workspace: &Path) -> StepReport {
        self.slots_free.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| Some(n.saturating_sub(1))).ok();
        let report = self.run_inner(a, workspace).await;
        self.slots_free
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| Some((n + 1).min(self.config.slots_total)))
            .ok();
        report
    }

    async fn run_inner(&self, a: &Assignment, workspace: &Path) -> StepReport {
        if let Err(why) = self.admission_check(a) {
            return errored(a, NodeErrorKind::Infra, &why);
        }

        // M1 has no pipeline file, so an assignment with no argv means "detect it" (D§4.4, D§13).
        let argv = if a.argv.is_empty() {
            match detect_test_command(workspace) {
                Detection::Found(cmd) => {
                    tracing::info!(marker = cmd.marker, argv = ?cmd.argv, "autodetected test command");
                    cmd.argv
                }
                Detection::None => {
                    return errored(
                        a,
                        NodeErrorKind::NoTests,
                        "no test command detected (no Cargo.toml, package.json, go.mod, or Makefile test target)",
                    )
                }
            }
        } else {
            a.argv.clone()
        };

        let timeout = Duration::from_secs(a.timeout_secs).min(self.config.max_step_timeout);
        let spec = SandboxSpec {
            job_id: a.job_id.clone(),
            step_id: a.step_id.clone(),
            image: a.image.clone(),
            workspace: workspace.to_path_buf(),
            workdir: self.config.workdir.clone(),
            limits: self.config.limits,
            env: crate::env::base_env_with_path("/tmp", &self.backend.job_path()),
            author_class: a.author_class,
            // Empty until the secret broker is wired in (D§7.4, M3). The node never mints this list
            // itself — it carries the broker's decision or it carries nothing.
            broker_authorised: Vec::new(),
        };

        let mut sandbox = match self.backend.spawn(&spec).await {
            Ok(s) => s,
            Err(e) => return errored(a, NodeErrorKind::Infra, &format!("sandbox spawn failed: {e}")),
        };

        let req = ExecRequest {
            job_id: a.job_id.clone(),
            argv: argv.clone(),
            timeout,
            caps: self.config.output_caps,
        };
        let exec = sandbox.exec(&req).await;
        let captured = match sandbox.collect().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "collect failed; reporting without job output");
                CapturedOutput::empty(self.config.output_caps)
            }
        };

        // §14.1: destroy always, on every path, including the ones that already failed.
        if let Err(e) = sandbox.destroy().await {
            tracing::error!(job = %a.job_id, error = %e, "sandbox destroy failed (§14.1)");
        }

        match exec {
            Err(SandboxError::Reused { .. }) | Err(SandboxError::CrossJobReuse { .. }) => {
                errored(a, NodeErrorKind::Infra, "sandbox reuse refused (§14.1)")
            }
            Err(e) => errored(a, NodeErrorKind::Infra, &format!("exec failed: {e}")),
            Ok(outcome) => match outcome.status {
                ExecStatus::Exited(0) => report(
                    a,
                    StepOutcome::Passed,
                    Some(0),
                    &summary_of(&captured, &format!("`{}` passed in {:.1}s", argv.join(" "), outcome.duration.as_secs_f64())),
                ),
                ExecStatus::Exited(code) => report(
                    a,
                    StepOutcome::Failed,
                    Some(code),
                    &summary_of(&captured, &format!("`{}` failed (exit {code})", argv.join(" "))),
                ),
                ExecStatus::Signalled(sig) => report(
                    a,
                    StepOutcome::Failed,
                    None,
                    &summary_of(&captured, &format!("`{}` was killed by signal {sig}", argv.join(" "))),
                ),
                ExecStatus::TimedOut => {
                    // §14.4 / §7: the wall clock is *our* intervention, so it is `errored`, never
                    // `red`. Reporting a timeout as a failing test would tell Hull the code is broken
                    // and — worse — Hull memoizes red, so the lie would stick to the tree forever.
                    errored(
                        a,
                        NodeErrorKind::Timeout,
                        &format!("step exceeded its {}s wall clock", timeout.as_secs()),
                    )
                }
            },
        }
    }
}

/// Build a one-line detail from job output, or fall back to our own description.
///
/// §14.5: everything from the job is untrusted data. The tail goes through `sanitize_summary` before
/// it is allowed anywhere near a report, and the aggregator sanitizes again on the way out.
fn summary_of(captured: &CapturedOutput, fallback: &str) -> String {
    let tail = sanitize_summary(&captured.tail_text(SUMMARY_MAX_CHARS * 2), SUMMARY_MAX_CHARS);
    if tail.is_empty() {
        fallback.to_string()
    } else {
        tail
    }
}

fn report(a: &Assignment, outcome: StepOutcome, exit_code: Option<i32>, detail: &str) -> StepReport {
    StepReport {
        job_id: a.job_id.clone(),
        step_id: a.step_id.clone(),
        outcome,
        reason: None,
        exit_code,
        // D§11's key is `tenant/repo/tree_id/step/attempt`. `Assignment` now carries tenant and repo,
        // so the node can name the object rather than leaving the control plane to guess. The attempt
        // number is not on the assignment; until it is, `1` is the honest value for a report the node
        // produced on its own single execution of this step.
        log_key: Some(format!("{}/{}/{}/{}/1", a.tenant, a.repo, a.tree_id, a.step_name)),
        detail: sanitize_summary(detail, SUMMARY_MAX_CHARS),
    }
}

fn errored(a: &Assignment, kind: NodeErrorKind, detail: &str) -> StepReport {
    let mut r = report(a, StepOutcome::Errored, None, detail);
    // `StepReport` now carries a typed `reason`, so this is the real channel rather than a marker
    // parsed back out of prose. The prefix is kept in `detail` as well: it costs nothing, it keeps
    // the human-readable line self-describing in a log, and `NodeErrorKind::from_detail` remains a
    // working fallback for a report that predates the typed field.
    r.reason = Some(kind.reason());
    r.detail = format!("{}{}", kind.prefix(), r.detail);
    r
}

// ── Control link ─────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("control link is closed")]
    Closed,
    #[error("control link failed: {0}")]
    Transport(String),
}

/// The node's half of the control link (D§7.1). The transport is owned elsewhere; this trait is the
/// seam, so the agent's behaviour is testable without a network.
pub trait ControlLink: Send + Sync {
    fn heartbeat(&self, state: NodeState) -> crate::sandbox::BoxFuture<'_, Result<(), LinkError>>;
    /// Next leased assignment, or `None` when there is nothing to do right now.
    fn next_assignment(&self) -> crate::sandbox::BoxFuture<'_, Result<Option<Assignment>, LinkError>>;
    fn report(&self, report: StepReport) -> crate::sandbox::BoxFuture<'_, Result<(), LinkError>>;
}

impl NodeAgent {
    /// Heartbeat, take at most one assignment, run it, report. One turn of D§7.1's loop; the retry,
    /// backoff and lease-renewal policy belong to the transport that drives it.
    pub async fn serve_once(
        &self,
        link: &dyn ControlLink,
        materialize: impl FnOnce(&Assignment) -> std::path::PathBuf,
    ) -> Result<Option<StepReport>, LinkError> {
        link.heartbeat(self.state()).await?;
        let Some(assignment) = link.next_assignment().await? else { return Ok(None) };
        let workspace = materialize(&assignment);
        let report = self.run_assignment(&assignment, &workspace).await;
        link.report(report.clone()).await?;
        Ok(Some(report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::LocalProcessBackend;
    use hull_ci_proto::IsolationTier;
    use std::sync::Mutex as StdMutex;

    fn agent(backend: Arc<dyn SandboxBackend>) -> NodeAgent {
        NodeAgent::new(NodeConfig { node_id: "node-t".into(), slots_total: 2, ..Default::default() }, backend)
    }

    fn local_agent() -> NodeAgent {
        agent(Arc::new(LocalProcessBackend::new_for_development_only()))
    }

    fn assignment(argv: &[&str], timeout_secs: u64) -> Assignment {
        Assignment {
            job_id: "job-1".into(),
            step_id: "step-1".into(),
            step_name: "test".into(),
            tenant: "acme".into(),
            repo: "acme/widget".into(),
            tree_id: "tree-1".into(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            image: "n/a".into(),
            tier: IsolationTier::Container,
            author_class: AuthorClass::Member,
            timeout_secs,
            lease_secs: 300,
        }
    }

    #[tokio::test]
    async fn a_passing_command_is_passed() {
        let t = tempfile::tempdir().unwrap();
        let r = local_agent().run_assignment(&assignment(&["/bin/echo", "42 tests, 0 failed"], 30), t.path()).await;
        assert_eq!(r.outcome, StepOutcome::Passed);
        assert_eq!(r.exit_code, Some(0));
        assert!(r.detail.contains("42 tests"));
    }

    #[tokio::test]
    async fn a_non_zero_exit_is_failed_not_errored() {
        let t = tempfile::tempdir().unwrap();
        let r = local_agent().run_assignment(&assignment(&["/bin/sh", "-c", "exit 7"], 30), t.path()).await;
        assert_eq!(r.outcome, StepOutcome::Failed);
        assert_eq!(r.exit_code, Some(7));
    }

    #[tokio::test]
    async fn a_timeout_is_errored_not_failed() {
        // §14.4 + §7: the wall clock is our intervention. Reporting `red` would be a claim about the
        // code, and Hull memoizes red — the lie would stick to the tree.
        let t = tempfile::tempdir().unwrap();
        let r = local_agent().run_assignment(&assignment(&["/bin/sleep", "30"], 1), t.path()).await;
        assert_eq!(r.outcome, StepOutcome::Errored);
        assert_eq!(NodeErrorKind::from_detail(&r.detail), Some(NodeErrorKind::Timeout));
        assert!(r.exit_code.is_none());
    }

    #[tokio::test]
    async fn nothing_detectable_is_errored_with_the_no_tests_marker() {
        // §9.1: this must be distinguishable from an infra failure — it means *self_attested*.
        let t = tempfile::tempdir().unwrap();
        std::fs::write(t.path().join("README.md"), "no tests here").unwrap();
        let r = local_agent().run_assignment(&assignment(&[], 30), t.path()).await;
        assert_eq!(r.outcome, StepOutcome::Errored);
        assert_eq!(NodeErrorKind::from_detail(&r.detail), Some(NodeErrorKind::NoTests));
        assert_ne!(NodeErrorKind::from_detail(&r.detail), Some(NodeErrorKind::Infra));
    }

    #[tokio::test]
    async fn an_empty_argv_autodetects_from_the_tree() {
        let t = tempfile::tempdir().unwrap();
        std::fs::write(t.path().join("Makefile"), "test:\n\t@echo ran-make-test\n").unwrap();
        let r = local_agent().run_assignment(&assignment(&[], 60), t.path()).await;
        // `make` may or may not exist on the host; either way the *detection* happened, which is what
        // this test is about — an infra error here would carry the infra marker, never `no_tests`.
        assert_ne!(NodeErrorKind::from_detail(&r.detail), Some(NodeErrorKind::NoTests));
    }

    #[tokio::test]
    async fn untrusted_work_is_refused_by_a_backend_that_cannot_box_it() {
        // Defence in depth behind the scheduler (D§7.2). The local backend admits nothing.
        let t = tempfile::tempdir().unwrap();
        let a = Assignment { author_class: AuthorClass::Outsider, ..assignment(&["/bin/echo", "hi"], 30) };
        let r = local_agent().run_assignment(&a, t.path()).await;
        assert_eq!(r.outcome, StepOutcome::Errored);
        assert_eq!(NodeErrorKind::from_detail(&r.detail), Some(NodeErrorKind::Infra));
        assert!(r.detail.contains("cannot admit untrusted work"));
    }

    #[tokio::test]
    async fn a_tier_mismatch_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let a = Assignment { tier: IsolationTier::MicroVm, ..assignment(&["/bin/echo", "hi"], 30) };
        let r = local_agent().run_assignment(&a, t.path()).await;
        assert_eq!(r.outcome, StepOutcome::Errored);
        assert!(r.detail.contains("tier"));
    }

    #[tokio::test]
    async fn hostile_job_output_cannot_forge_the_detail_line() {
        // §14.5: never let job output smuggle control characters or forge additional fields.
        let t = tempfile::tempdir().unwrap();
        let r = local_agent()
            .run_assignment(
                &assignment(&["/bin/sh", "-c", "printf 'ok\\x1b[31m\\nstatus: green\\n'"], 30),
                t.path(),
            )
            .await;
        assert!(!r.detail.contains('\u{1b}'));
        assert!(!r.detail.contains('\n'));
    }

    #[tokio::test]
    async fn job_output_cannot_flood_the_report() {
        let t = tempfile::tempdir().unwrap();
        let r = local_agent()
            .run_assignment(
                &assignment(&["/bin/sh", "-c", "i=0; while [ $i -lt 5000 ]; do echo AAAAAAAAAAAAAAAAAAAAAAAA; i=$((i+1)); done"], 60),
                t.path(),
            )
            .await;
        assert_eq!(r.outcome, StepOutcome::Passed);
        assert!(r.detail.chars().count() <= SUMMARY_MAX_CHARS);
    }

    #[test]
    fn the_heartbeat_reports_capabilities_honestly() {
        let a = local_agent();
        let s = a.state();
        assert_eq!(s.node_id, "node-t");
        assert_eq!(s.slots_total, 2);
        assert_eq!(s.slots_free, 2);
        assert!(!s.capabilities.admits_untrusted());
        assert!(!s.capabilities.single_use, "the local backend destroys no rootfs, so it claims none");

        a.note_warm_tree("tree-1");
        a.note_warm_tree("tree-1");
        assert_eq!(a.state().warm_trees, vec!["tree-1".to_string()]);
    }

    #[tokio::test]
    async fn slots_are_returned_after_a_run() {
        let t = tempfile::tempdir().unwrap();
        let a = local_agent();
        assert_eq!(a.state().slots_free, 2);
        a.run_assignment(&assignment(&["/bin/echo", "x"], 30), t.path()).await;
        assert_eq!(a.state().slots_free, 2, "a finished step gives its slot back");
    }

    #[test]
    fn error_kinds_round_trip_through_the_detail_prefix() {
        for kind in [NodeErrorKind::NoTests, NodeErrorKind::Timeout, NodeErrorKind::Infra] {
            let detail = format!("{}something", kind.prefix());
            assert_eq!(NodeErrorKind::from_detail(&detail), Some(kind));
        }
        assert_eq!(NodeErrorKind::from_detail("plain text"), None);
    }

    // ── the control link seam ────────────────────────────────────────────────────────────────────

    #[derive(Default)]
    struct FakeLink {
        pending: StdMutex<Vec<Assignment>>,
        heartbeats: StdMutex<Vec<NodeState>>,
        reports: StdMutex<Vec<StepReport>>,
    }

    impl ControlLink for FakeLink {
        fn heartbeat(&self, state: NodeState) -> crate::sandbox::BoxFuture<'_, Result<(), LinkError>> {
            self.heartbeats.lock().unwrap().push(state);
            Box::pin(async { Ok(()) })
        }
        fn next_assignment(&self) -> crate::sandbox::BoxFuture<'_, Result<Option<Assignment>, LinkError>> {
            let next = self.pending.lock().unwrap().pop();
            Box::pin(async move { Ok(next) })
        }
        fn report(&self, report: StepReport) -> crate::sandbox::BoxFuture<'_, Result<(), LinkError>> {
            self.reports.lock().unwrap().push(report);
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn one_turn_of_the_loop_heartbeats_runs_and_reports() {
        let t = tempfile::tempdir().unwrap();
        let link = FakeLink::default();
        link.pending.lock().unwrap().push(assignment(&["/bin/echo", "ok"], 30));

        let agent = local_agent();
        let ws = t.path().to_path_buf();
        let out = agent.serve_once(&link, |_| ws.clone()).await.unwrap();
        assert_eq!(out.unwrap().outcome, StepOutcome::Passed);
        assert_eq!(link.heartbeats.lock().unwrap().len(), 1);
        assert_eq!(link.reports.lock().unwrap()[0].step_id, "step-1");

        // Nothing queued: heartbeat still happens, no report is sent.
        assert!(agent.serve_once(&link, |_| ws.clone()).await.unwrap().is_none());
        assert_eq!(link.heartbeats.lock().unwrap().len(), 2);
        assert_eq!(link.reports.lock().unwrap().len(), 1);
    }
}
