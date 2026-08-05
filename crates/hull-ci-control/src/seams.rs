//! The three things the control plane asks *someone else* to do, expressed as traits it owns.
//!
//! The control plane **never executes job code and never clones a repo** (spec §14.1: a runner that
//! executes a job on the control-plane host is a full RCE and credential-exfiltration hole). It
//! parses JSON, keeps state, and decides. Everything that touches attacker-controlled bytes lives
//! behind one of these seams:
//!
//! * [`Fetcher`] — the fetch broker (`hull-ci-fetch`): GET `source_url`, verify the archive re-hashes
//!   to `tree_id`, hardened tar extraction (design D§4.2).
//! * [`Planner`] — reads the pipeline out of the *already verified* tree and emits a DAG (design
//!   D§4.4). M2's Starlark evaluator plugs in here.
//! * [`NodeSink`] — hands a leased [`Assignment`] to a node agent (`hull-ci-node`), which runs it in
//!   a single-use sandbox (design D§5.3, §7).
//!
//! They are traits rather than direct dependencies for two reasons: the aggregator and the callback
//! sender are then unit-testable with no sandbox and no network, and the components are owned by
//! separate crates that must be able to evolve without a compile-time cycle through this one.
//!
//! The default implementations are deliberately **unwired** — they fail loudly rather than pretending
//! to succeed. A control plane with no fetcher that reported `green` would be the worst possible
//! failure mode; `errored` is not memoized by Hull (spec §7), so failing this way costs a re-check
//! and nothing more.
//!
//! ## What the broker hands forward
//!
//! All three seams are joined by one value, [`VerifiedTree`]: *where the broker put the tree*. The
//! planner has to read the pipeline (or, in M1, autodetect) out of the **already verified** tree
//! (design D§4.4) and the node has to materialize a workspace from it (D§6.2), so both need a path
//! that only the broker can name. It travels as a return value from [`Fetcher::fetch`] into
//! [`Planner::plan`] and [`NodeSink::assign`] rather than being re-derived downstream, because the
//! store's layout — tenant-scoped, hashed, staged-then-renamed (`hull-ci-fetch`'s `ContentStore`) —
//! is the broker's alone. A consumer that rebuilt the path from a convention would be a second
//! source of truth for it, and the first thing that convention would do is drift.

use std::path::PathBuf;

use hull_ci_proto::{Assignment, AuthorClass};

use crate::callback::{BoxFuture, CallbackRequest, CallbackResponse, CallbackTransport, TransportError};
use crate::model::StepSpec;

/// What the broker needs to materialize a tree. `source_url` is **opaque** (spec §5) and the token,
/// if present, is consumed by the broker only and MUST NOT enter a sandbox (spec §14.2).
#[derive(Debug, Clone)]
pub struct FetchRequest {
    pub tenant: String,
    pub tree_id: String,
    pub source_url: String,
    pub fetch_token: Option<String>,
}

/// A tree the broker has fetched, re-hashed against `tree_id`, and published in its content store.
///
/// The existence of this value is the claim "these bytes really are that tree" (design D§4.2), which
/// is why nothing downstream may construct one: it is only ever produced by a [`Fetcher`].
///
/// `path` is **read-only** as far as everything downstream is concerned. It names the store's copy,
/// shared by every step of every job that referenced this `tree_id`, so a node materializes its own
/// writable workspace from it rather than running in it (D§6.2). A job that wrote here would mutate
/// content at its own content address, and the next job to take a store hit would run code that no
/// longer matches the address it was verified against — the one guarantee the whole fetch path exists
/// to provide.
#[derive(Debug, Clone)]
pub struct VerifiedTree {
    /// Normalized `tree_id`, as the store keys it.
    pub tree_id: String,
    /// Directory holding the extracted tree, on the control plane's filesystem.
    pub path: PathBuf,
    /// True when the tree was already in the store, so no fetch, extract or verify happened now.
    /// Informational: a hit is as verified as a miss, because the address is what was verified.
    pub cached: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("no fetch broker is wired into this control plane")]
    Unwired,
    #[error("fetch failed: {0}")]
    Failed(String),
    /// The archive did not re-hash to `tree_id` (spec §6, design D§4.2). Never a `red` verdict — we
    /// did not test anything, so we have nothing to say about the code.
    #[error("archive did not verify against tree_id")]
    TreeMismatch,
}

pub trait Fetcher: Send + Sync + 'static {
    /// Make the tree present and verified, and say where it landed.
    fn fetch<'a>(&'a self, req: &'a FetchRequest) -> BoxFuture<'a, Result<VerifiedTree, FetchError>>;
}

#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    #[error("no planner is wired into this control plane")]
    Unwired,
    #[error("pipeline is invalid: {0}")]
    Invalid(String),
}

pub trait Planner: Send + Sync + 'static {
    /// Returns the steps for a verified tree. An **empty** plan is not an error here — it means
    /// "nothing detectable to run", which the aggregator turns into `errored`/`no_tests` (design
    /// D§4.4), the state spec §9.1 reads as *self_attested*.
    ///
    /// Takes the whole [`VerifiedTree`] rather than a `tree_id` because planning is defined as
    /// reading the pipeline *out of the tree* (D§4.4) — `.hull/ci.star` in M2, marker-file
    /// autodetection in M1 — and an id alone cannot be opened. It may read those bytes; it may never
    /// execute them (§14.1).
    fn plan<'a>(&'a self, tree: &'a VerifiedTree) -> BoxFuture<'a, Result<Vec<StepSpec>, PlanError>>;
}

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("no node fleet is wired into this control plane")]
    Unwired,
    /// Not a failure: the step stays queued and keeps its position, and only the queue-wait timeout
    /// can turn a wait into a verdict (design D§4.5).
    #[error("no capacity")]
    NoCapacity,
    #[error("node rejected the assignment: {0}")]
    Rejected(String),
}

pub trait NodeSink: Send + Sync + 'static {
    /// Lease the step to a node, returning the `node_id` that took it. That id is what verdict
    /// integrity (design D§10.4) is checked against.
    ///
    /// `tree` is passed alongside the [`Assignment`] rather than inside it, and that split is
    /// deliberate. [`Assignment`] is the control↔node **wire** type: a host path on it would be
    /// meaningless the moment the node is a different machine (M3), and would invite a node to read a
    /// path the control plane named. What the wire carries is `tree_id`; what this seam carries is
    /// the control-plane-side location that a fleet implementation turns into a workspace — directly
    /// for M1's in-process node, by a LAN pull from the content store for M3's (design D§6.2, §3's
    /// architecture diagram).
    fn assign(&self, assignment: &Assignment, tree: &VerifiedTree) -> Result<String, NodeError>;

    /// Revoke the lease and destroy the sandbox — fail-fast cancellation (design D§6.6) and job
    /// timeout. Best effort by nature: a node that has already gone away cannot be told anything,
    /// and the lease expiry covers that case.
    fn cancel(&self, job_id: &str, step_id: &str);
}

/// Author class is a **fact about the actor**, derived from the dispatch's `author` and repo
/// membership — never anything a pipeline can assert (design D§1).
pub trait Membership: Send + Sync + 'static {
    fn classify(&self, repo: &str, author: &str) -> AuthorClass;
}

/// The default: everyone is an outsider.
///
/// Least privilege, on purpose. An outsider's job reads the shared cache, writes only a throwaway
/// layer, and receives no secrets. Being wrong in this direction costs a cache miss; being wrong in
/// the other direction hands a fork PR the tenant's secrets.
pub struct LeastPrivilege;

impl Membership for LeastPrivilege {
    fn classify(&self, _repo: &str, _author: &str) -> AuthorClass {
        AuthorClass::Outsider
    }
}

/// Placeholder fetcher: refuses rather than silently claiming an empty workspace is a verified tree.
pub struct UnwiredFetcher;

impl Fetcher for UnwiredFetcher {
    fn fetch<'a>(&'a self, _req: &'a FetchRequest) -> BoxFuture<'a, Result<VerifiedTree, FetchError>> {
        Box::pin(async { Err(FetchError::Unwired) })
    }
}

/// Placeholder planner: refuses rather than reporting a green job that ran nothing.
pub struct UnwiredPlanner;

impl Planner for UnwiredPlanner {
    fn plan<'a>(&'a self, _tree: &'a VerifiedTree) -> BoxFuture<'a, Result<Vec<StepSpec>, PlanError>> {
        Box::pin(async { Err(PlanError::Unwired) })
    }
}

/// Placeholder node fleet.
pub struct UnwiredNodes;

impl NodeSink for UnwiredNodes {
    fn assign(&self, _assignment: &Assignment, _tree: &VerifiedTree) -> Result<String, NodeError> {
        Err(NodeError::Unwired)
    }
    fn cancel(&self, _job_id: &str, _step_id: &str) {}
}

/// Fallback transport for the case where the HTTP client itself could not be built.
///
/// It errors on every attempt, which walks the retry schedule and then parks the job with the
/// alert of design D§10.1 — visible, rather than a verdict that quietly evaporates.
pub struct UnwiredTransport;

impl CallbackTransport for UnwiredTransport {
    fn post<'a>(
        &'a self,
        _req: &'a CallbackRequest,
    ) -> BoxFuture<'a, Result<CallbackResponse, TransportError>> {
        Box::pin(async { Err(TransportError::Send("no callback transport is wired".into())) })
    }
}
