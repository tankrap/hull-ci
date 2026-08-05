//! Fakes for the three seams, so every decision in this crate can be tested without a sandbox, a
//! broker, or a network — and, more importantly, so the *failure* paths (a node that rejects, a Hull
//! that 503s, a fetch that hangs past its clock) are exercised rather than assumed.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use hull_ci_proto::{Assignment, AuthorClass, Dispatch, StepOutcome, StepReport};

use crate::callback::{BoxFuture, CallbackRequest, CallbackResponse, CallbackTransport, TransportError};
use crate::control::{Control, ControlConfig, Deps};
use crate::model::StepSpec;
use crate::seams::{
    FetchError, FetchRequest, Fetcher, Membership, NodeError, NodeSink, PlanError, Planner,
    VerifiedTree,
};

/// A dispatch with the shape spec §5 documents.
pub fn dispatch(repo: &str, tree_id: &str) -> Dispatch {
    Dispatch {
        repo: repo.into(),
        change: "21ea2242186c99ff".into(),
        tree_id: tree_id.into(),
        intent: "fixes #6 pagination off-by-one".into(),
        author: "justin".into(),
        source_url: format!("https://hull.example/api/repos/{repo}/tree/{tree_id}/tar"),
        callback_url: "https://hull.example/api/repos/t/r/change/21ea/ci-result".into(),
        fetch_token: None,
    }
}

// ── Callback transport ───────────────────────────────────────────────────────────────────────────

enum Script {
    /// Fail `n` times with a transport error, then succeed.
    FailingThenOk(u32),
    AlwaysFailing,
    AlwaysStatus(u16),
}

pub struct ScriptedTransport {
    script: Script,
    attempts: AtomicU32,
    seen: Mutex<Vec<CallbackRequest>>,
}

impl ScriptedTransport {
    pub fn failing_then_ok(n: u32) -> Self {
        ScriptedTransport { script: Script::FailingThenOk(n), attempts: AtomicU32::new(0), seen: Mutex::new(Vec::new()) }
    }
    pub fn always_failing() -> Self {
        ScriptedTransport { script: Script::AlwaysFailing, attempts: AtomicU32::new(0), seen: Mutex::new(Vec::new()) }
    }
    pub fn always_status(status: u16) -> Self {
        ScriptedTransport { script: Script::AlwaysStatus(status), attempts: AtomicU32::new(0), seen: Mutex::new(Vec::new()) }
    }
    pub fn ok() -> Self {
        Self::failing_then_ok(0)
    }
    pub fn attempts(&self) -> u32 {
        self.attempts.load(Ordering::SeqCst)
    }
    pub fn seen(&self) -> Vec<CallbackRequest> {
        self.seen.lock().unwrap().clone()
    }
}

impl CallbackTransport for ScriptedTransport {
    fn post<'a>(&'a self, req: &'a CallbackRequest) -> BoxFuture<'a, Result<CallbackResponse, TransportError>> {
        Box::pin(async move {
            let n = self.attempts.fetch_add(1, Ordering::SeqCst) + 1;
            self.seen.lock().unwrap().push(req.clone());
            match self.script {
                Script::FailingThenOk(fail_for) if n > fail_for => Ok(CallbackResponse { status: 200 }),
                Script::FailingThenOk(_) | Script::AlwaysFailing => {
                    Err(TransportError::Send("connection refused".into()))
                }
                Script::AlwaysStatus(s) => Ok(CallbackResponse { status: s }),
            }
        })
    }
}

// ── Fetcher ──────────────────────────────────────────────────────────────────────────────────────

/// Reports the tree materialized at a path nothing in this crate opens.
///
/// The control plane never reads the workspace — that is the planner's and the node's business, both
/// of which are fakes here — so a path that does not exist is the honest fixture: if a test ever
/// starts failing because this directory is missing, the control plane has grown a filesystem
/// dependency it is not supposed to have (§14.1).
pub struct OkFetcher;
impl Fetcher for OkFetcher {
    fn fetch<'a>(&'a self, req: &'a FetchRequest) -> BoxFuture<'a, Result<VerifiedTree, FetchError>> {
        Box::pin(async move {
            Ok(VerifiedTree {
                tree_id: req.tree_id.clone(),
                path: std::path::PathBuf::from("/nonexistent/control-plane-never-opens-this"),
                cached: false,
            })
        })
    }
}

pub struct FailingFetcher;
impl Fetcher for FailingFetcher {
    fn fetch<'a>(&'a self, _req: &'a FetchRequest) -> BoxFuture<'a, Result<VerifiedTree, FetchError>> {
        Box::pin(async { Err(FetchError::TreeMismatch) })
    }
}

/// Never returns — the only way to test the fetch clock.
pub struct HangingFetcher;
impl Fetcher for HangingFetcher {
    fn fetch<'a>(&'a self, req: &'a FetchRequest) -> BoxFuture<'a, Result<VerifiedTree, FetchError>> {
        Box::pin(async move {
            futures_forever().await;
            Ok(VerifiedTree {
                tree_id: req.tree_id.clone(),
                path: std::path::PathBuf::from("/nonexistent/control-plane-never-opens-this"),
                cached: false,
            })
        })
    }
}

/// Answers with a tree id that is not the one dispatched — the "wrong tree" guard in `phase_fetch`.
pub struct WrongTreeFetcher;
impl Fetcher for WrongTreeFetcher {
    fn fetch<'a>(&'a self, _req: &'a FetchRequest) -> BoxFuture<'a, Result<VerifiedTree, FetchError>> {
        Box::pin(async {
            Ok(VerifiedTree {
                tree_id: "some-other-tree".into(),
                path: std::path::PathBuf::from("/nonexistent/control-plane-never-opens-this"),
                cached: true,
            })
        })
    }
}

async fn futures_forever() {
    // A very long sleep rather than `pending()`, so a stuck test fails instead of hanging.
    tokio::time::sleep(Duration::from_secs(3600)).await;
}

// ── Planner ──────────────────────────────────────────────────────────────────────────────────────

pub struct StaticPlanner(pub Vec<StepSpec>);

impl StaticPlanner {
    /// `n` independent steps — a plan with no edges at all, still the common shape.
    pub fn steps(n: usize) -> Self {
        StaticPlanner(
            (0..n)
                .map(|i| StepSpec::new(format!("step{i}"), vec!["cargo".into(), "test".into()], "rust:1.83"))
                .collect(),
        )
    }

    /// A DAG, as `(name, needs)` in declaration order — the shape design D§4.4's `step(…, needs=[…])`
    /// emits. Declaration order matters: a `needs` target must already have been declared, which is
    /// what makes the graph acyclic by construction.
    pub fn graph(edges: &[(&str, &[&str])]) -> Self {
        StaticPlanner(edges.iter().map(|(name, needs)| spec(name, needs)).collect())
    }
}

/// One planner step, named so other steps' `needs` can reference it.
pub fn spec(name: &str, needs: &[&str]) -> StepSpec {
    StepSpec::new(name, vec!["cargo".into(), "test".into()], "rust:1.83")
        .needs(needs.iter().map(|n| (*n).to_string()).collect())
}

impl Planner for StaticPlanner {
    fn plan<'a>(&'a self, _tree: &'a VerifiedTree) -> BoxFuture<'a, Result<Vec<StepSpec>, PlanError>> {
        Box::pin(async move { Ok(self.0.clone()) })
    }
}

// ── Node fleet ───────────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NodeMode {
    Accept,
    /// Over quota: a wait, not a failure (design D§4.5).
    NoCapacity,
    Reject,
}

pub struct RecordingNode {
    pub node_id: String,
    pub mode: NodeMode,
    assigned: Mutex<Vec<(Assignment, VerifiedTree)>>,
    cancelled: Mutex<Vec<(String, String)>>,
}

impl RecordingNode {
    pub fn new(mode: NodeMode) -> Self {
        RecordingNode {
            node_id: "node-test".into(),
            mode,
            assigned: Mutex::new(Vec::new()),
            cancelled: Mutex::new(Vec::new()),
        }
    }
    pub fn assigned(&self) -> Vec<Assignment> {
        self.assigned.lock().unwrap().iter().map(|(a, _)| a.clone()).collect()
    }
    /// What the fleet was told about the materialized tree — the broker's answer, unaltered.
    pub fn trees(&self) -> Vec<VerifiedTree> {
        self.assigned.lock().unwrap().iter().map(|(_, t)| t.clone()).collect()
    }
    pub fn cancelled(&self) -> Vec<(String, String)> {
        self.cancelled.lock().unwrap().clone()
    }
}

impl NodeSink for RecordingNode {
    fn assign(&self, assignment: &Assignment, tree: &VerifiedTree) -> Result<String, NodeError> {
        self.assigned.lock().unwrap().push((assignment.clone(), tree.clone()));
        match self.mode {
            NodeMode::Accept => Ok(self.node_id.clone()),
            NodeMode::NoCapacity => Err(NodeError::NoCapacity),
            NodeMode::Reject => Err(NodeError::Rejected("no such image".into())),
        }
    }
    fn cancel(&self, job_id: &str, step_id: &str) {
        self.cancelled.lock().unwrap().push((job_id.to_string(), step_id.to_string()));
    }
}

// ── Membership ───────────────────────────────────────────────────────────────────────────────────

pub struct AlwaysMember;
impl Membership for AlwaysMember {
    fn classify(&self, _repo: &str, _author: &str) -> AuthorClass {
        AuthorClass::Member
    }
}

// ── Wiring helpers ───────────────────────────────────────────────────────────────────────────────

/// A config whose retry schedule costs no wall-clock time. Same code path, no sleeping.
pub fn fast_config() -> ControlConfig {
    ControlConfig {
        secret: Some("s3cret".into()),
        retry: crate::callback::RetryPolicy {
            base: Duration::ZERO,
            max_delay: Duration::ZERO,
            max_attempts: 3,
        },
        ..ControlConfig::default()
    }
}

pub struct Harness {
    pub control: std::sync::Arc<Control>,
    pub transport: std::sync::Arc<ScriptedTransport>,
    pub node: std::sync::Arc<RecordingNode>,
}

/// Wire a control plane out of fakes.
pub fn harness(config: ControlConfig, fetcher: std::sync::Arc<dyn Fetcher>, planner: std::sync::Arc<dyn Planner>, node_mode: NodeMode) -> Harness {
    let transport = std::sync::Arc::new(ScriptedTransport::ok());
    let node = std::sync::Arc::new(RecordingNode::new(node_mode));
    let deps = Deps {
        fetcher,
        planner,
        node: node.clone(),
        transport: transport.clone(),
        membership: std::sync::Arc::new(AlwaysMember),
    };
    Harness { control: Control::new(config, deps), transport, node }
}

/// A terminal report from the node that holds the lease.
pub fn step_report(job_id: &str, step_id: &str, outcome: StepOutcome, detail: &str) -> StepReport {
    StepReport {
        job_id: job_id.into(),
        step_id: step_id.into(),
        outcome,
        // A node that errors always names a reason; `Infra` is the conservative default a report
        // without one is read as, so the fixture models the same convention.
        reason: (outcome == StepOutcome::Errored).then_some(hull_ci_proto::Reason::Infra),
        exit_code: Some(if outcome == StepOutcome::Passed { 0 } else { 1 }),
        log_key: None,
        detail: detail.into(),
    }
}

/// Poll until `pred` holds. Tests assert on state that a spawned driver reaches asynchronously;
/// a bounded poll keeps a broken assertion a failure rather than a hang.
pub async fn wait_until(mut pred: impl FnMut() -> bool) -> bool {
    for _ in 0..1000 {
        if pred() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    false
}

/// Poll for a short bounded window and answer whether `pred` stayed false throughout.
///
/// The counterpart to [`wait_until`], and what a DAG assertion needs: "the join step has *not* been
/// scheduled yet" is an absence, and an absence can only ever be tested for a finite time. Kept
/// short because every call spends it — and worth spending, because the alternative is asserting
/// nothing about the one bug this scheduler can have, which is running a step before its edge
/// cleared.
pub async fn stays_false(mut pred: impl FnMut() -> bool) -> bool {
    for _ in 0..25 {
        if pred() {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    true
}
