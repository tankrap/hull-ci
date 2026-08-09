//! The two decisions a second replica cannot be trusted to make on its own — design D§4.5, spec §9.
//!
//! M5 is scale-out: more than one control plane over one shared state. The README says what stops it
//! today — "state is still in memory … the fair-share clocks and the job store are process-local" —
//! and the obvious first move is to put [`JobStore`](crate::store::JobStore) behind a trait and
//! reimplement it against Postgres.
//!
//! **That move is wrong, and this module is the narrower thing instead.** The reasoning is worth
//! writing down because it is the whole shape of this phase.
//!
//! # Why the job store is not the seam
//!
//! `Control` mutates a job through `with_job_mut`, at ~39 call sites, and every one of them is a
//! read-modify-write under a local mutex: read the `Job`, change some fields, drop the guard. Under
//! one process that is atomic, because the guard *is* the transaction. Across a network it is not:
//!
//! * a trait that hands out `&mut Job` cannot express "and commit this", so two replicas each doing
//!   read-modify-write on the same row is a lost update — the second write wins and the first
//!   silently disappears;
//! * and a trait that could express it would have to name every one of those 39 mutations as a
//!   committable operation before a single one of them was safe. Half-done, it is worse than not
//!   started: the seam compiles, the wiring looks right, and the store is a remote database that
//!   still loses writes.
//!
//! So the job **record** stays local, exactly as it is, and this module shares only what genuinely
//! cannot be local. Two things qualify:
//!
//! 1. **The idempotency claim.** Spec §9 keys work by `(repo, tree_id)`. One tree, one job — and with
//!    two replicas the winner of that race is decided by `INSERT … ON CONFLICT`, not by a mutex
//!    neither of them shares.
//! 2. **The step claim.** Design D§5.3 leases a step to a node. Two replicas that both hand the same
//!    step to the fleet run the same code twice, bill it twice, and race two reports at one lease.
//!
//! Everything else a job is — its steps' states, its verdict, its delivery bookkeeping — is written
//! by exactly one replica, because of (1) and (2). That is not a coincidence; it is the point. The
//! claim is what *makes* the local record single-writer, which is what lets the other 39 call sites
//! stay as they are.
//!
//! # The lost update, made unrepresentable
//!
//! Nothing in this trait returns a `&mut` anything, and nothing returns a value the caller mutates
//! and hands back. Every operation is named, complete, and committed by the implementation:
//! [`admit`](JobClaims::admit) either creates or attaches, [`claim_step`](JobClaims::claim_step)
//! either grants or refuses. There is no shape here that means "here is the state, write it back
//! later", so there is no window for a second replica to write in between.
//!
//! The other half is **fencing**. A [`DriveLease`] carries a `fence` that the store increments every
//! time a claim changes hands, and every mutating operation presents it. A replica that was declared
//! dead and then wakes up still holds fence 1 while the world has moved to fence 2, and the store
//! refuses it — see [`StepClaim::Fenced`]. The token is not the guarantee (a caller could construct
//! one); the store's `WHERE fence = $n` is. The token exists so the *correct* call is the easy one
//! to write, and so a caller cannot claim a step for a job it never admitted.
//!
//! # What this does not do
//!
//! * **No fair-share state is shared.** The scheduler's clocks are still per replica (design D§4.5),
//!   so two replicas are fair *each*, not fair *together*. That is the next phase, not this one.
//! * **No dead replica's work is resumed.** A claim whose lease expired is *released* — the tree
//!   becomes dispatchable again — but nothing re-runs it, because the shared claim deliberately
//!   carries no `source_url` and no `fetch_token` (spec §14.2, and see
//!   [`JobIntent`](crate::journal::JobIntent) for the same rule one level up). Recovery of the debt
//!   itself is still the journal's job, on the dead replica's own next start.
//! * **No sweeper.** Expiry is evaluated when a dispatch arrives, in the same amortized spirit as
//!   retention eviction and redelivery in [`Control::accept`](crate::control::Control::accept) —
//!   there is no background task to own, supervise, and shut down.
//!
//! # Clocks
//!
//! Every operation takes the caller's wall clock as `now_ms`, epoch milliseconds. Wall clock rather
//! than the `Instant` the rest of the control plane runs on, for the reason
//! [`journal::now_unix`](crate::journal::now_unix) already gives: a monotonic clock is meaningless to
//! another process, and this is the one piece of state two processes compare. Supplied by the caller
//! rather than read from the database so that a lease expiry is testable by passing a number instead
//! of by sleeping — this repository does not assert on wall-clock timing.
//!
//! The cost is stated plainly: **lease expiry assumes the replicas' clocks agree to within much less
//! than the lease TTL.** Skew larger than the TTL lets one replica declare another dead while it is
//! still working. That costs a duplicate job for one tree — safe by spec §9, which makes a duplicate
//! callback a re-affirmation — and never a step run twice, because the fence stops the old owner
//! dispatching anything the moment it is superseded.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hull_ci_proto::Verdict;

use crate::model::JobId;

/// Epoch milliseconds, saturating at zero for a clock behind the epoch.
///
/// Saturating rather than erroring, like [`journal::now_unix`](crate::journal::now_unix): a
/// nonsensical system clock must not be able to refuse a dispatch.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

/// The idempotency key of spec §9 / design D§4.1.
///
/// `(repo, tree_id)`, never `tree_id` alone: two tenants with an identical tree are two jobs with two
/// `callback_url`s, and collapsing them would deliver one tenant's verdict to the other — design
/// D§1's log/summary bleed row.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TreeKey {
    pub repo: String,
    pub tree_id: String,
}

impl TreeKey {
    pub fn new(repo: impl Into<String>, tree_id: impl Into<String>) -> Self {
        TreeKey { repo: repo.into(), tree_id: tree_id.into() }
    }
}

/// Proof that this replica is the current driver of a job, and the fence it must present to act.
///
/// Held by [`Control`](crate::control::Control) for as long as it drives the job and dropped in
/// `retire`. Cloneable because the driver, the scheduler pass, and the heartbeat all need it; it is
/// a token, not a resource.
///
/// # The constructor is not the guarantee
///
/// [`DriveLease::issued`] is public because implementations live in other crates (the real one is in
/// the composition root, next to its connection string — the same reason
/// [`Journal`](crate::journal::Journal) is a seam). A caller could therefore fabricate one. That does
/// not matter: every operation that takes a lease re-checks `fence` **in the store**, so a fabricated
/// or stale token buys nothing but a [`StepClaim::Fenced`]. The type's job is to make the wrong call
/// hard to write, not to make it impossible to construct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveLease {
    job_id: JobId,
    owner: String,
    fence: u64,
}

impl DriveLease {
    /// Only a [`JobClaims`] implementation should call this — see the type's docs.
    pub fn issued(job_id: impl Into<String>, owner: impl Into<String>, fence: u64) -> Self {
        DriveLease { job_id: job_id.into(), owner: owner.into(), fence }
    }

    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Incremented by the store every time this job's claim changes hands. Presented on every
    /// mutation; a stale one is refused.
    pub fn fence(&self) -> u64 {
        self.fence
    }
}

/// What admitting a dispatch did — the shared-state form of spec §9's "a duplicate MUST be safe".
///
/// Deliberately only two variants, where the old process-local `Admit` had three. "Live" and
/// "finished" were both *attached*; the difference between them is whether a verdict exists, and with
/// two replicas that is a question about the claim rather than about a local record which the
/// answering replica may not even hold.
#[derive(Debug, Clone)]
pub enum Admitted {
    /// First time anyone has seen `(repo, tree_id)`, or the previous claimant's lease had expired.
    /// **This replica drives it**, and holds the only lease.
    Created { lease: DriveLease },
    /// A claim already exists. The `callback_url` has been recorded against it, so whoever is
    /// driving will deliver there too.
    ///
    /// `owner` is informational — for the log line that answers "which replica has it". The question
    /// the caller actually acts on is whether *it* holds the job record, which it answers by looking
    /// in its own store.
    Attached {
        job_id: JobId,
        owner: String,
        /// `Some` when the job already reached a verdict, so the caller can re-report it without
        /// re-running a single step (spec §9: a duplicate "simply re-affirms the same verdict") —
        /// **even on a replica that never ran the job.**
        verdict: Option<Box<Verdict>>,
    },
}

impl Admitted {
    pub fn job_id(&self) -> &str {
        match self {
            Admitted::Created { lease } => lease.job_id(),
            Admitted::Attached { job_id, .. } => job_id,
        }
    }

    pub fn is_duplicate(&self) -> bool {
        matches!(self, Admitted::Attached { .. })
    }
}

/// The answer to "may I hand this step to the fleet?".
///
/// Three answers, not two, because "no" has two meanings that must not be confused. A step someone
/// else already took is a step that is *running*; a fenced lease means **this whole replica is no
/// longer the driver** and must stop dispatching anything for this job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepClaim {
    /// Nobody else can dispatch this step. Go.
    Granted,
    /// Already claimed — by another replica, or by an earlier pass of this one. Do not dispatch.
    Taken { by: String },
    /// Our drive lease is stale: this job's claim was taken over while we held it. Nothing about this
    /// job may be dispatched from here again.
    Fenced { held_by: String },
}

/// The store could not answer. **Never** "the answer was no".
///
/// Separate from [`StepClaim`] on purpose: a refusal is a decision and is safe to act on, while a
/// backend failure is an absence of one. The caller must fail *closed* on this — a step whose claim
/// is unknown is a step that may already be running somewhere else.
#[derive(Debug, thiserror::Error)]
pub enum ClaimError {
    #[error("the claim store is unavailable: {0}")]
    Unavailable(String),
}

/// The shared claims two replicas contend over. Everything else stays process-local.
///
/// Implementations: [`LocalClaims`] (the default, one process) and `hull_ci_server::claims::PgClaims`
/// behind the `postgres` feature. The real one lives in the composition root for the same reason
/// [`Journal`](crate::journal::Journal)'s does — this crate opens no file and holds no connection
/// string (spec §14.1) — and so that a build without a database is still a complete runner.
pub trait JobClaims: Send + Sync + 'static {
    /// This replica's identity, as it appears in a claim. Stable for the life of the process.
    fn owner(&self) -> &str;

    /// Whether a lease held here can be taken away by someone else, which is the only reason to run a
    /// heartbeat.
    ///
    /// `false` for [`LocalClaims`], and that is not an optimization: a single-process deployment must
    /// not grow a background renewal task per job for a lease nothing can contend. The default build
    /// keeps exactly the task graph it had.
    fn needs_renewal(&self) -> bool {
        false
    }

    /// Insert-or-attach on `(repo, tree_id)`, atomically across replicas.
    ///
    /// `proposed_job_id` is used **only if we win**; a loser is told the winner's id. The
    /// `callback_url` is recorded against the claim either way, in the same commit — that is what
    /// makes "two dispatchers, one job, both answered" true rather than hopeful, because delivery is
    /// not deduplicated even though work is (see [`Job::callback_urls`](crate::model::Job)).
    ///
    /// `lease_ms` is how long the winner's drive lease is good for. An existing claim that has **no
    /// verdict** and whose lease expired before `now_ms` is taken over: a replica that died holding a
    /// tree must not hold it forever, or a forced re-check comes back as a duplicate of a job nobody
    /// is running (spec §10 — that tree stays wedged until a human intervenes twice).
    ///
    /// `settled_retention_ms` drops claims that reached a verdict longer ago than that, mirroring
    /// [`JobStore::evict`](crate::store::JobStore::evict)'s retention so the shared index and the
    /// local one forget on the same schedule. Losing a settled claim costs a re-run, never a wrong
    /// answer.
    fn admit(
        &self,
        key: &TreeKey,
        proposed_job_id: &str,
        callback_url: &str,
        now_ms: i64,
        lease_ms: i64,
        settled_retention_ms: i64,
    ) -> Result<Admitted, ClaimError>;

    /// Push the drive lease's expiry out. `Ok(false)` means we have been fenced — another replica
    /// holds this job now and this one must stop driving it.
    fn renew(&self, lease: &DriveLease, now_ms: i64, lease_ms: i64) -> Result<bool, ClaimError>;

    /// Take the exclusive right to hand one step to the fleet.
    ///
    /// Called immediately before [`NodeSink::assign`](crate::seams::NodeSink::assign) and released by
    /// [`release_step`](JobClaims::release_step) if the fleet had no capacity. That ordering is the
    /// whole guarantee: the claim is held across the only call that can start work.
    fn claim_step(
        &self,
        lease: &DriveLease,
        step_id: &str,
        now_ms: i64,
    ) -> Result<StepClaim, ClaimError>;

    /// Give a step claim back **because it was never dispatched** — the fleet was full, so the step
    /// goes back on the queue and must be claimable again next pass.
    ///
    /// Never called after a successful assign: a step that reached a node keeps its claim forever, so
    /// nothing can dispatch it a second time.
    fn release_step(&self, lease: &DriveLease, step_id: &str) -> Result<(), ClaimError>;

    /// Publish the one verdict onto the claim, so a duplicate dispatch arriving at **any** replica
    /// re-reports it instead of re-running the work.
    fn settle(&self, lease: &DriveLease, verdict: &Verdict, now_ms: i64) -> Result<(), ClaimError>;

    /// Every `callback_url` recorded against this job's claim, including ones attached by another
    /// replica after we started delivering.
    ///
    /// Re-read on every delivery pass rather than snapshotted, for the reason
    /// [`Control::report`](crate::control::Control) already re-reads its local set: a dispatch that
    /// attaches a URL a moment too late must not wait forever on an answer delivered somewhere else.
    fn destinations(&self, job_id: &str) -> Result<Vec<String>, ClaimError>;

    /// Drop a claim: this replica is done with the job, or it was evicted.
    ///
    /// Infallible for the same reason [`Journal::forget`](crate::journal::Journal::forget) is — it
    /// runs after the decision it belongs to is already made, and a failure costs at most a re-run of
    /// a tree, which spec §9 makes safe. An implementation must refuse to drop a claim that is
    /// neither settled nor its own; forgetting someone else's *running* job would hand its tree to a
    /// second dispatcher while the first was still driving it.
    fn forget(&self, job_id: &str);
}

/// The default: claims in this process's memory, contended by nobody.
///
/// Not a stub, and not a test double. It is the exact behaviour the job store had before this module
/// existed — the `(repo, tree_id) → job_id` index that used to live in
/// [`JobStore`](crate::store::JobStore), moved out so that it has one owner rather than two. A
/// single-process deployment therefore behaves identically: `needs_renewal` is false so no heartbeat
/// is spawned, `claim_step` never refuses a step the local state machine would have dispatched, and
/// expiry never fires because nothing else can hold a claim.
#[derive(Default)]
pub struct LocalClaims {
    state: std::sync::Mutex<LocalState>,
}

#[derive(Default)]
struct LocalState {
    by_key: std::collections::HashMap<TreeKey, JobId>,
    claims: std::collections::HashMap<JobId, LocalClaim>,
}

struct LocalClaim {
    key: TreeKey,
    callback_urls: Vec<String>,
    verdict: Option<Box<Verdict>>,
    settled_at_ms: Option<i64>,
    steps: std::collections::HashSet<String>,
}

impl LocalClaims {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LocalState> {
        // Same policy as the job store's lock: a panic in one job's bookkeeping must not poison the
        // whole runner's state.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The owner string of the process-local store.
///
/// A constant rather than a hostname, because with one process there is nobody to distinguish it
/// from, and a value that varied per run would make the log line noisier without answering anything.
const LOCAL_OWNER: &str = "local";

/// What a [`StepClaim::Fenced`] names when there is no claim to be fenced *by*.
///
/// A separate constant rather than a bare string, because both implementations have to say the same
/// thing: an operator reading it should not have to work out which store produced the line.
pub const NO_CLAIM: &str = "(no claim)";

impl JobClaims for LocalClaims {
    fn owner(&self) -> &str {
        LOCAL_OWNER
    }

    fn admit(
        &self,
        key: &TreeKey,
        proposed_job_id: &str,
        callback_url: &str,
        now_ms: i64,
        _lease_ms: i64,
        settled_retention_ms: i64,
    ) -> Result<Admitted, ClaimError> {
        let mut st = self.lock();

        // Retention, mirroring the Postgres implementation so the two forget on the same schedule.
        // Only settled claims, and only this key's: a scan of every claim on every dispatch would be
        // the store's own eviction sweep duplicated, and the local job store already runs that.
        let stale = st
            .by_key
            .get(key)
            .and_then(|id| st.claims.get(id))
            .and_then(|c| c.settled_at_ms)
            .is_some_and(|t| now_ms.saturating_sub(t) >= settled_retention_ms);
        if stale {
            if let Some(id) = st.by_key.remove(key) {
                st.claims.remove(&id);
            }
        }

        if let Some(existing) = st.by_key.get(key).cloned() {
            if let Some(claim) = st.claims.get_mut(&existing) {
                if !claim.callback_urls.iter().any(|u| u == callback_url) {
                    claim.callback_urls.push(callback_url.to_string());
                }
                return Ok(Admitted::Attached {
                    job_id: existing,
                    owner: LOCAL_OWNER.to_string(),
                    verdict: claim.verdict.clone(),
                });
            }
            // An index entry with no claim behind it cannot happen through this type's own API; heal
            // by falling through to a fresh insert rather than handing back a job id nothing knows.
            st.by_key.remove(key);
        }

        let job_id = proposed_job_id.to_string();
        st.by_key.insert(key.clone(), job_id.clone());
        st.claims.insert(
            job_id.clone(),
            LocalClaim {
                key: key.clone(),
                callback_urls: vec![callback_url.to_string()],
                verdict: None,
                settled_at_ms: None,
                steps: std::collections::HashSet::new(),
            },
        );
        // Fence 0 forever: a claim in this process's memory never changes hands, so there is nothing
        // to fence against. A non-zero value would imply a takeover that cannot happen here.
        Ok(Admitted::Created { lease: DriveLease::issued(job_id, LOCAL_OWNER, 0) })
    }

    fn renew(&self, lease: &DriveLease, _now_ms: i64, _lease_ms: i64) -> Result<bool, ClaimError> {
        Ok(self.lock().claims.contains_key(lease.job_id()))
    }

    fn claim_step(
        &self,
        lease: &DriveLease,
        step_id: &str,
        _now_ms: i64,
    ) -> Result<StepClaim, ClaimError> {
        let mut st = self.lock();
        let Some(claim) = st.claims.get_mut(lease.job_id()) else {
            // No claim behind this lease. Refusing is right, and [`StepClaim::Fenced`] is the honest
            // answer: from the caller's side "the claim was forgotten" and "someone superseded it"
            // are the same fact — this job is not ours to drive — and a shared store cannot tell them
            // apart either, so both implementations answer the same way rather than one of them
            // being subtly nicer than the other.
            return Ok(StepClaim::Fenced { held_by: NO_CLAIM.to_string() });
        };
        if claim.steps.insert(step_id.to_string()) {
            Ok(StepClaim::Granted)
        } else {
            Ok(StepClaim::Taken { by: LOCAL_OWNER.to_string() })
        }
    }

    fn release_step(&self, lease: &DriveLease, step_id: &str) -> Result<(), ClaimError> {
        if let Some(claim) = self.lock().claims.get_mut(lease.job_id()) {
            claim.steps.remove(step_id);
        }
        Ok(())
    }

    fn settle(&self, lease: &DriveLease, verdict: &Verdict, now_ms: i64) -> Result<(), ClaimError> {
        if let Some(claim) = self.lock().claims.get_mut(lease.job_id()) {
            claim.verdict = Some(Box::new(verdict.clone()));
            claim.settled_at_ms = Some(now_ms);
        }
        Ok(())
    }

    fn destinations(&self, job_id: &str) -> Result<Vec<String>, ClaimError> {
        Ok(self
            .lock()
            .claims
            .get(job_id)
            .map(|c| c.callback_urls.clone())
            .unwrap_or_default())
    }

    fn forget(&self, job_id: &str) {
        let mut st = self.lock();
        if let Some(claim) = st.claims.remove(job_id) {
            // Only clear the index if it still points at *this* job. A later job for the same
            // (repo, tree_id) — which exists precisely because an earlier one was evicted — must not
            // have its index entry removed by its predecessor's cleanup.
            if st.by_key.get(&claim.key).is_some_and(|id| id == job_id) {
                st.by_key.remove(&claim.key);
            }
        }
    }
}

/// How long a drive lease is good for by default, and the fraction of it a heartbeat renews at.
///
/// Exposed so the composition root and the control plane cannot disagree about them.
pub const DEFAULT_LEASE: Duration = Duration::from_secs(60);

/// Renew at a third of the TTL: two consecutive renewals may be lost before a live replica is
/// declared dead, which is the usual bound for a lease this cheap to refresh.
pub fn renew_every(lease: Duration) -> Duration {
    // At least a second, so a pathologically small TTL cannot become a busy loop against the store.
    (lease / 3).max(Duration::from_secs(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> LocalClaims {
        LocalClaims::new()
    }

    const HOUR_MS: i64 = 60 * 60 * 1000;

    fn admit(c: &LocalClaims, repo: &str, tree: &str, id: &str, url: &str) -> Admitted {
        c.admit(&TreeKey::new(repo, tree), id, url, 0, 60_000, HOUR_MS).unwrap()
    }

    #[test]
    fn a_duplicate_dispatch_for_a_live_tree_attaches_instead_of_starting_a_second_job() {
        // Spec §9's headline, now decided by the claim rather than by the job store.
        let c = claims();
        let a = admit(&c, "t/r", "tree1", "job_a", "https://hull/cb");
        let b = admit(&c, "t/r", "tree1", "job_b", "https://hull/cb");

        assert!(matches!(a, Admitted::Created { .. }));
        assert!(matches!(b, Admitted::Attached { .. }), "got {b:?}");
        assert_eq!(b.job_id(), "job_a", "the loser is told the winner's id, not its own proposal");
    }

    #[test]
    fn the_key_is_repo_and_tree_not_tree_alone() {
        // Two tenants with an identical tree are two jobs with two callback_urls. Collapsing them
        // would send one tenant's verdict to the other (design D§1: log/summary bleed).
        let c = claims();
        let a = admit(&c, "acme/api", "same", "job_a", "https://a/cb");
        let b = admit(&c, "other/api", "same", "job_b", "https://b/cb");
        assert_eq!(a.job_id(), "job_a");
        assert_eq!(b.job_id(), "job_b");
    }

    #[test]
    fn every_dispatchers_callback_url_is_recorded_against_the_one_claim() {
        // Work is deduplicated by (repo, tree_id); delivery is not. The URL has to be attached in the
        // *admitting* commit, because the replica that will deliver may not be the one that took it.
        let c = claims();
        admit(&c, "t/r", "tree1", "job_a", "https://one/cb");
        admit(&c, "t/r", "tree1", "job_b", "https://two/cb");
        admit(&c, "t/r", "tree1", "job_c", "https://one/cb");

        let dests = c.destinations("job_a").unwrap();
        assert_eq!(dests, vec!["https://one/cb".to_string(), "https://two/cb".to_string()]);
    }

    #[test]
    fn a_settled_claim_hands_back_the_verdict_to_re_report() {
        let c = claims();
        let Admitted::Created { lease } = admit(&c, "t/r", "tree1", "job_a", "https://one/cb") else {
            panic!("first admit must create");
        };
        c.settle(&lease, &Verdict::green("42 tests, 0 failed"), 0).unwrap();

        match admit(&c, "t/r", "tree1", "job_b", "https://two/cb") {
            Admitted::Attached { job_id, verdict: Some(v), .. } => {
                assert_eq!(job_id, "job_a");
                assert_eq!(v.summary.as_deref(), Some("42 tests, 0 failed"));
            }
            other => panic!("expected an attached claim carrying the verdict, got {other:?}"),
        }
    }

    #[test]
    fn a_settled_claim_is_forgotten_once_it_is_past_retention() {
        // The shared index has to forget on the same schedule as the local store, or the two disagree
        // about whether an old tree is new work. Costs a re-run, never a wrong answer (spec §9).
        let c = claims();
        let Admitted::Created { lease } = admit(&c, "t/r", "tree1", "job_a", "https://one/cb") else {
            panic!("first admit must create");
        };
        c.settle(&lease, &Verdict::green("ok"), 0).unwrap();

        let later = c
            .admit(&TreeKey::new("t/r", "tree1"), "job_b", "https://two/cb", 2 * HOUR_MS, 60_000, HOUR_MS)
            .unwrap();
        assert!(matches!(later, Admitted::Created { .. }), "got {later:?}");
        assert_eq!(later.job_id(), "job_b");
    }

    #[test]
    fn a_step_is_claimable_once_and_dispatchable_again_only_if_it_never_went_out() {
        // The two halves of the step claim. Granted once, because a step handed to the fleet must
        // never be handed to it again; releasable while the fleet was full, because a step that was
        // never dispatched has to be claimable on the next pass or it would never run at all.
        let c = claims();
        let Admitted::Created { lease } = admit(&c, "t/r", "tree1", "job_a", "https://one/cb") else {
            panic!("first admit must create");
        };

        assert_eq!(c.claim_step(&lease, "step_00", 0).unwrap(), StepClaim::Granted);
        assert!(matches!(c.claim_step(&lease, "step_00", 0).unwrap(), StepClaim::Taken { .. }));

        c.release_step(&lease, "step_00").unwrap();
        assert_eq!(c.claim_step(&lease, "step_00", 0).unwrap(), StepClaim::Granted);
    }

    #[test]
    fn a_forgotten_claim_frees_the_tree_and_refuses_further_steps() {
        let c = claims();
        let Admitted::Created { lease } = admit(&c, "t/r", "tree1", "job_a", "https://one/cb") else {
            panic!("first admit must create");
        };
        c.forget("job_a");

        assert!(matches!(c.claim_step(&lease, "step_00", 0).unwrap(), StepClaim::Fenced { .. }));
        let again = admit(&c, "t/r", "tree1", "job_b", "https://two/cb");
        assert!(matches!(again, Admitted::Created { .. }), "the tree is new work again");
    }

    #[test]
    fn forgetting_a_job_does_not_take_its_successors_index_entry() {
        let c = claims();
        admit(&c, "t/r", "tree1", "job_a", "https://one/cb");
        c.forget("job_a");
        admit(&c, "t/r", "tree1", "job_b", "https://two/cb");
        // The predecessor's cleanup, arriving late, must not unhook the job that replaced it.
        c.forget("job_a");
        let third = admit(&c, "t/r", "tree1", "job_c", "https://three/cb");
        assert_eq!(third.job_id(), "job_b", "the live claim survived its predecessor's cleanup");
    }

    #[test]
    fn the_local_store_never_asks_for_a_heartbeat() {
        // The single-process deployment must keep exactly the task graph it had: nothing can take a
        // claim held in this process's memory, so there is nothing to renew.
        assert!(!claims().needs_renewal());
    }
}
