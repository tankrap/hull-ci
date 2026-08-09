//! Fakes for the three seams, so every decision in this crate can be tested without a sandbox, a
//! broker, or a network — and, more importantly, so the *failure* paths (a node that rejects, a Hull
//! that 503s, a fetch that hangs past its clock) are exercised rather than assumed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use hull_ci_proto::{Assignment, AuthorClass, Dispatch, StepOutcome, StepReport};

use crate::callback::{BoxFuture, CallbackRequest, CallbackResponse, CallbackTransport, TransportError};
use crate::control::{Control, ControlConfig, Deps};
use crate::fairshare::{Prioritizer, Priority};
use crate::memo::{DigestError, InputDigest, MemoConfig, SubtreeDigest};
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
    /// Fail `fail_fast` times immediately, then **hold** every later attempt for `hold` without ever
    /// answering — a Hull that has stopped talking rather than one that refuses.
    ///
    /// The only way to observe a delivery *while it is in flight*: every other script answers within
    /// the same poll, so "a delivery is running right now" is a state a test could otherwise never
    /// catch, and the guard against starting a second one for the same job would be asserted against
    /// a window that never opens.
    FailingThenStalling { fail_fast: u32, hold: Duration },
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
    /// Fail `n` times fast — enough to spend a short retry budget — then stop answering altogether.
    pub fn failing_then_stalling(n: u32, hold: Duration) -> Self {
        ScriptedTransport {
            script: Script::FailingThenStalling { fail_fast: n, hold },
            attempts: AtomicU32::new(0),
            seen: Mutex::new(Vec::new()),
        }
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
                Script::FailingThenStalling { fail_fast, hold } => {
                    // Counted and recorded *before* the hold, so a test can see the attempt begin —
                    // which is the whole point of this script.
                    if n > fail_fast {
                        tokio::time::sleep(hold).await;
                    }
                    Err(TransportError::Send("connection refused".into()))
                }
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
                cached: false, keep_alive: None
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
                cached: false, keep_alive: None
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
                cached: true, keep_alive: None
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

/// How many independent steps each `tree_id` plans to, so one control plane can serve two tenants
/// with wildly different amounts of work — which is the only shape a fairness test can be written in.
pub struct PerTreePlanner(HashMap<String, usize>);

impl PerTreePlanner {
    pub fn new(steps_per_tree: &[(&str, usize)]) -> Self {
        PerTreePlanner(steps_per_tree.iter().map(|(t, n)| ((*t).to_string(), *n)).collect())
    }
}

impl Planner for PerTreePlanner {
    fn plan<'a>(&'a self, tree: &'a VerifiedTree) -> BoxFuture<'a, Result<Vec<StepSpec>, PlanError>> {
        let n = self.0.get(&tree.tree_id).copied().unwrap_or(1);
        Box::pin(async move {
            Ok((0..n)
                .map(|i| StepSpec::new(format!("step{i}"), vec!["cargo".into(), "test".into()], "rust:1.83"))
                .collect())
        })
    }
}

// ── Step memoization (design D§6.1) ──────────────────────────────────────────────────────────────

/// A fetcher backed by **real directories on disk**, keyed by `tree_id`.
///
/// The other fetchers here answer with a path nothing opens, which is the right fixture for a
/// control plane that touches no filesystem. Layer 2 is the one place that legitimately needs a real
/// tree behind the seam — the digest is a claim about actual bytes, and a fake that agreed with a
/// broken key derivation would prove nothing.
pub struct DirFetcher(HashMap<String, std::path::PathBuf>);

impl DirFetcher {
    pub fn new(trees: &[(&str, &std::path::Path)]) -> Self {
        DirFetcher(trees.iter().map(|(id, p)| ((*id).to_string(), p.to_path_buf())).collect())
    }
}

impl Fetcher for DirFetcher {
    fn fetch<'a>(&'a self, req: &'a FetchRequest) -> BoxFuture<'a, Result<VerifiedTree, FetchError>> {
        Box::pin(async move {
            let path = self
                .0
                .get(&req.tree_id)
                .ok_or_else(|| FetchError::Failed(format!("no such tree {}", req.tree_id)))?;
            Ok(VerifiedTree { tree_id: req.tree_id.clone(), path: path.clone(), cached: false, keep_alive: None })
        })
    }
}

/// The [`SubtreeDigest`] seam, backed by the real `hull-ci-fetch` digester.
///
/// Ten lines, and deliberately so: this is the whole adapter a composition root needs to turn layer
/// 2 on, and it is the same shape as `hull-ci-server`'s `BrokerFetcher`. Everything that makes the
/// digest sound — keel's encoding, the O(depth) prefix descent, the `(tenant, tree, glob)` memo —
/// lives in the broker crate.
#[derive(Default)]
pub struct FetchDigester(hull_ci_fetch::TreeDigester);

impl SubtreeDigest for FetchDigester {
    fn digest(&self, tenant: &str, tree: &VerifiedTree, glob: &str) -> Result<InputDigest, DigestError> {
        self.0
            .digest(tenant, &tree.tree_id, &tree.path, glob)
            .map(|d| InputDigest { digest: d.digest, selected: d.selected })
            .map_err(|e| DigestError::Failed { glob: glob.into(), detail: e.to_string() })
    }
}

/// A planner whose steps declare `inputs`, so they are actually cacheable.
pub struct MemoPlanner(pub Vec<StepSpec>);

impl Planner for MemoPlanner {
    fn plan<'a>(&'a self, _tree: &'a VerifiedTree) -> BoxFuture<'a, Result<Vec<StepSpec>, PlanError>> {
        Box::pin(async move { Ok(self.0.clone()) })
    }
}

/// One step declaring what it reads (design D§6.1).
pub fn memo_spec(name: &str, inputs: &[&str], needs: &[&str]) -> StepSpec {
    StepSpec::new(name, vec!["cargo".into(), "test".into()], "rust:1.83")
        .inputs(inputs.iter().map(|g| (*g).to_string()).collect())
        .needs(needs.iter().map(|n| (*n).to_string()).collect())
}

/// [`fast_config`] with layer 2 wired to the real digester and a shared memo store.
pub fn memo_config(store: std::sync::Arc<dyn crate::memo::StepMemo>) -> ControlConfig {
    ControlConfig {
        memo: MemoConfig {
            digest: std::sync::Arc::new(FetchDigester::default()),
            store,
            pipeline_version: "test/1".into(),
        },
        ..fast_config()
    }
}

// ── Priority ─────────────────────────────────────────────────────────────────────────────────────

/// Files one named repo's work as `background` and everything else as `interactive` — a stand-in for
/// Hull telling us "this came from the nightly sweep, not from someone clicking check".
pub struct BackgroundRepo(pub &'static str);

impl Prioritizer for BackgroundRepo {
    fn priority(&self, dispatch: &Dispatch) -> Priority {
        if dispatch.repo_name() == self.0 {
            Priority::Background
        } else {
            Priority::Interactive
        }
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

// ── Journal (design D§4.1's durable outbox) ──────────────────────────────────────────────────────

/// A journal whose `record` always fails, so the "we did not ack a job we could lose" path is
/// exercised rather than assumed.
///
/// `forget` and `outstanding` still behave, because the failure this models is a full or read-only
/// disk at write time, not a store that has stopped existing — and a fake that broke everything at
/// once would let a test pass for the wrong reason.
pub struct RefusingJournal;

impl crate::journal::Journal for RefusingJournal {
    fn record(&self, intent: &crate::journal::JobIntent) -> Result<(), crate::journal::JournalError> {
        Err(crate::journal::JournalError::Write {
            job_id: intent.job_id.clone(),
            detail: "no space left on device".into(),
        })
    }
    fn forget(&self, _job_id: &str) {}
    fn outstanding(&self) -> Result<Vec<crate::journal::JobIntent>, crate::journal::JournalError> {
        Ok(Vec::new())
    }
}

pub struct Harness {
    pub control: std::sync::Arc<Control>,
    pub transport: std::sync::Arc<ScriptedTransport>,
    pub node: std::sync::Arc<RecordingNode>,
}

/// Wire a control plane out of fakes.
/// [`harness`] with a caller-chosen transport, for tests about what happens when Hull does not answer.
pub fn harness_with(
    config: ControlConfig,
    fetcher: std::sync::Arc<dyn Fetcher>,
    planner: std::sync::Arc<dyn Planner>,
    node_mode: NodeMode,
    transport: std::sync::Arc<ScriptedTransport>,
) -> Harness {
    harness_full(config, fetcher, planner, node_mode, transport, std::sync::Arc::new(crate::journal::NoJournal))
}

pub fn harness(config: ControlConfig, fetcher: std::sync::Arc<dyn Fetcher>, planner: std::sync::Arc<dyn Planner>, node_mode: NodeMode) -> Harness {
    harness_full(
        config,
        fetcher,
        planner,
        node_mode,
        std::sync::Arc::new(ScriptedTransport::ok()),
        std::sync::Arc::new(crate::journal::NoJournal),
    )
}

/// [`harness`] with both the transport and the journal chosen by the caller.
///
/// The journal is a parameter rather than a field the harness owns because the restart tests need the
/// *same* journal behind two different [`Control`]s — that shared `Arc` is what stands in for a
/// process boundary, and it is the only way to test the thing the journal exists for.
pub fn harness_full(
    config: ControlConfig,
    fetcher: std::sync::Arc<dyn Fetcher>,
    planner: std::sync::Arc<dyn Planner>,
    node_mode: NodeMode,
    transport: std::sync::Arc<ScriptedTransport>,
    journal: std::sync::Arc<dyn crate::journal::Journal>,
) -> Harness {
    let node = std::sync::Arc::new(RecordingNode::new(node_mode));
    let deps = Deps {
        fetcher,
        planner,
        node: node.clone(),
        transport: transport.clone(),
        membership: std::sync::Arc::new(AlwaysMember),
        journal,
        // The process-local index, which is what every one of these tests was already exercising when
        // it lived inside the job store.
        claims: std::sync::Arc::new(crate::claims::LocalClaims::new()),
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
