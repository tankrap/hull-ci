//! **hull-ci-control** — the control plane: ingest, the job/step model, aggregation, and idempotent
//! verdict delivery.
//!
//! It is the half of the system that talks to Hull, and the half that **never runs job code**. Spec
//! §14.1 is categorical: "the runner MUST NEVER execute job code on the control-plane host or on any
//! host with access to Hull's secrets, the CI shared secret, or cloud-provider credentials." This
//! process holds the CI shared secret, so it parses JSON and nothing else — no tar extraction, no
//! git, no `sh -c`, no repository on disk. Everything that touches attacker-controlled bytes lives
//! behind a seam in [`seams`] and runs in another crate.
//!
//! ## The shape of a job
//!
//! ```text
//! Hull ──POST /hull──▶ [ingest]  auth → version → parse → record (repo, tree_id)
//!                          │                                   └─ 202 {"accepted":true,…}
//!                          ▼
//!                      [driver]  fetching → planning → running
//!                          │        (fetch broker)   (planner)   (node fleet)
//!                          ▼
//!                    [aggregate]  one verdict: green | red | errored+reason
//!                          ▼
//!                     [callback]  POST callback_url verbatim, retried, or parked + alerted
//! ```
//!
//! ## What M1 is, and is not
//!
//! The job **record** is in memory, and stays there: it is written by exactly one replica, through
//! ~39 read-modify-write call sites in [`control`] that a remote store could not serve without every
//! one of them first becoming a committable operation (see [`store`]). What is *not* in memory any
//! more is the `(repo, tree_id)` index and the step claims — the two decisions two replicas genuinely
//! contend over — which moved behind the [`claims`] seam and are decided by an atomic
//! insert-or-attach. The default implementation is still process-local, so a single-replica
//! deployment behaves exactly as it did.
//!
//! What must **not** be only in memory is the promise that every accepted dispatch is answered — spec
//! §10 leaves both the timeout and the recovery to us, and an unanswered job wedges its tree — so that
//! promise has a durable record of its own behind the [`journal`] seam. Steps are scheduled as a DAG ([`graph`],
//! design D§6.5); which of the ready ones actually goes out, and in what order, is the multi-tenant
//! scheduler's answer ([`fairshare`], design D§4.5). There is still no step memo.
//!
//! ## Conformance (spec §11)
//!
//! | Clause | Where |
//! |---|---|
//! | Accepts `POST`, returns 2xx on receipt | [`ingest`] |
//! | Verifies `X-Hull-CI-Secret` | [`auth`] — constant-time |
//! | Fetches `source_url`, no git | [`seams::Fetcher`] (broker crate) |
//! | POSTs to the exact `callback_url`, echoing the secret | [`callback`] |
//! | `errored`, not `red`, for infrastructure failures | [`aggregate`], [`timeouts`] |
//! | Ignores unknown dispatch fields | `hull_ci_proto::Dispatch` |
//! | Safe under duplicate dispatch and duplicate callback | [`claims`], [`callback`] |
//! | Enforces its own job timeout and answers every accepted dispatch (§10) | [`timeouts`], [`journal`] |

pub mod aggregate;
pub mod auth;
pub mod callback;
pub mod claims;
pub mod control;
pub mod fairshare;
pub mod graph;
pub mod ids;
pub mod ingest;
pub mod journal;
pub mod memo;
pub mod model;
pub mod seams;
pub mod snapshot;
pub mod store;
pub mod timeouts;

#[cfg(test)]
mod testing;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub use claims::{Admitted, ClaimError, DriveLease, JobClaims, LocalClaims, StepClaim, TreeKey};
pub use control::{Accepted, AcceptError, Control, ControlConfig, Deps, ReportRejected};
pub use fairshare::{Admission, Depth, FairShare, Prioritizer, Priority, TenantPlan};
pub use journal::{JobIntent, Journal, JournalError, NoJournal};
pub use memo::{
    InMemoryStepMemo, InputDigest, JobKeyContext, MemoConfig, MemoOutcome, MemoPolicy, StepKey,
    StepMemo, SubtreeDigest,
};
pub use snapshot::{JobSnapshot, StepSnapshot, TenantSnapshot, VerdictSnapshot};
pub use timeouts::Timeouts;

use callback::{CallbackTransport, HttpCallback};
use seams::{LeastPrivilege, UnwiredFetcher, UnwiredNodes, UnwiredPlanner, UnwiredTransport};

impl Default for Deps {
    /// Everything unwired except the callback transport, which is the one collaborator this crate
    /// legitimately owns end to end.
    ///
    /// The unwired defaults **fail** rather than no-op. A control plane with no fetcher that
    /// reported `green` would have Hull memoize a passing verdict for a tree nobody ever built
    /// (spec §7); `errored` is not memoized, so failing loudly costs a re-check and nothing else.
    fn default() -> Self {
        let transport: Arc<dyn CallbackTransport> = match HttpCallback::new(Duration::from_secs(30)) {
            Ok(http) => Arc::new(http),
            Err(e) => {
                tracing::error!(error = %e, "could not build the HTTP callback client");
                Arc::new(UnwiredTransport)
            }
        };
        Deps {
            fetcher: Arc::new(UnwiredFetcher),
            planner: Arc::new(UnwiredPlanner),
            node: Arc::new(UnwiredNodes),
            transport,
            membership: Arc::new(LeastPrivilege),
            // The one unwired default that is *not* a loud failure, because remembering nothing is
            // what this system already did. Refusing every dispatch on a deployment that never asked
            // for a journal would be an outage introduced by a feature nobody enabled — see
            // [`journal::NoJournal`].
            journal: Arc::new(journal::NoJournal),
            // The other default that is not a loud failure, and for a stronger reason than the
            // journal's: this *is* the behaviour, not a stand-in for it. The process-local claim
            // store is the `(repo, tree_id)` index the job store used to own, moved out so it has one
            // owner. A single-replica deployment that never configures a shared one is not degraded —
            // it is exactly where it was (see [`claims::LocalClaims`]).
            claims: Arc::new(claims::LocalClaims::new()),
        }
    }
}

/// How to start the control plane.
pub struct Opts {
    /// Where to listen. Loopback by default: this endpoint holds the CI shared secret, so exposing
    /// it is a deliberate act rather than a default.
    pub addr: SocketAddr,
    pub config: ControlConfig,
    pub deps: Deps,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
            config: ControlConfig::default(),
            deps: Deps::default(),
        }
    }
}

impl Opts {
    pub fn new(addr: SocketAddr) -> Self {
        Opts { addr, ..Opts::default() }
    }

    /// The shared secret (spec §8). Configuring one is a SHOULD in the spec and a MUST in practice —
    /// without it, anyone who can reach this port can queue work on the fleet.
    pub fn with_secret(mut self, secret: impl Into<String>) -> Self {
        self.config.secret = Some(secret.into());
        self
    }

    pub fn with_deps(mut self, deps: Deps) -> Self {
        self.deps = deps;
        self
    }
}

/// Bind and serve until the process ends.
pub async fn run(opts: Opts) -> std::io::Result<()> {
    let addr = opts.addr;
    if opts.config.secret.is_none() {
        tracing::warn!("no shared secret configured — every dispatch will be accepted (spec §8)");
    }
    let control = Control::new(opts.config, opts.deps);
    let app = ingest::router(Arc::clone(&control));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "hull-ci control plane listening on POST /hull");
    axum::serve(listener, app).await
}
