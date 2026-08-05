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
    fn fetch<'a>(&'a self, req: &'a FetchRequest) -> BoxFuture<'a, Result<(), FetchError>>;
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
    fn plan<'a>(&'a self, tree_id: &'a str) -> BoxFuture<'a, Result<Vec<StepSpec>, PlanError>>;
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
    fn assign(&self, assignment: &Assignment) -> Result<String, NodeError>;

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
    fn fetch<'a>(&'a self, _req: &'a FetchRequest) -> BoxFuture<'a, Result<(), FetchError>> {
        Box::pin(async { Err(FetchError::Unwired) })
    }
}

/// Placeholder planner: refuses rather than reporting a green job that ran nothing.
pub struct UnwiredPlanner;

impl Planner for UnwiredPlanner {
    fn plan<'a>(&'a self, _tree_id: &'a str) -> BoxFuture<'a, Result<Vec<StepSpec>, PlanError>> {
        Box::pin(async { Err(PlanError::Unwired) })
    }
}

/// Placeholder node fleet.
pub struct UnwiredNodes;

impl NodeSink for UnwiredNodes {
    fn assign(&self, _assignment: &Assignment) -> Result<String, NodeError> {
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
