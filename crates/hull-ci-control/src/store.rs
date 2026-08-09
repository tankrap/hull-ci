//! Job storage — the **record** of a job, held by the one replica driving it.
//!
//! ## What used to be here, and where it went
//!
//! This module used to own two maps: the job records, and the `(repo, tree_id) → job_id` index that
//! makes spec §9's duplicate dispatch safe. The index has moved to [`crate::claims`], and that split
//! is the whole of M5 phase 1. The short version, with the long one in that module:
//!
//! * the **index** is contended by every replica — one tree, one job, and with two processes that
//!   race is arbitrated by an atomic insert-or-attach, not by a mutex neither of them shares;
//! * the **record** is written by exactly one replica, *because* of the index, so it can stay where
//!   it is: a `HashMap` behind a `Mutex`, mutated by ~39 read-modify-write call sites in
//!   [`crate::control`] which would every one have to become a committable operation before a remote
//!   store could serve them correctly.
//!
//! Splitting them rather than putting this type behind a trait is what keeps those 39 call sites
//! honest. A trait that handed out `&mut Job` across a network would be a lost update wearing a
//! seam's clothes.
//!
//! What remains here is storage and **retention**: hold the record while a duplicate might still be
//! answered from it, and bound the process so a long-lived runner does not grow until it dies holding
//! every verdict it ever computed.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use hull_ci_proto::{AuthorClass, Dispatch};

use crate::model::{Job, JobId};

#[derive(Default)]
pub struct JobStore {
    by_id: HashMap<JobId, Job>,
}

impl JobStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a job whose claim this replica has already won.
    ///
    /// Deliberately *not* an insert-or-attach: whether this `(repo, tree_id)` is new work is
    /// [`JobClaims::admit`](crate::claims::JobClaims::admit)'s decision, because it is the only one
    /// that can be made atomically across replicas. By the time this is called the answer is already
    /// "yes, and this process drives it", and `job_id` is the id the claim issued — never one minted
    /// here, or the shared index and the local record would disagree about what the winning job is
    /// called.
    ///
    /// Idempotent on `job_id`, so a re-record cannot silently discard a job that already has steps.
    pub fn insert(
        &mut self,
        job_id: JobId,
        dispatch: Dispatch,
        author_class: AuthorClass,
        now: Instant,
        job_timeout: Duration,
    ) -> &mut Job {
        self.by_id
            .entry(job_id.clone())
            .or_insert_with(|| Job::new(job_id, dispatch, author_class, now, job_timeout))
    }

    pub fn get(&self, job_id: &str) -> Option<&Job> {
        self.by_id.get(job_id)
    }

    pub fn get_mut(&mut self, job_id: &str) -> Option<&mut Job> {
        self.by_id.get_mut(job_id)
    }

    /// Every job still held, in no particular order.
    ///
    /// Crate-internal on purpose. Its one caller is [`crate::snapshot`], which copies out a redacted
    /// view; handing a `&Job` across a crate boundary would hand out `dispatch`, and `dispatch`
    /// carries `source_url`, `callback_url` and `fetch_token` — the fields spec §14.2 keeps away
    /// from everything that is not the broker.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Job> {
        self.by_id.values()
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Drop settled jobs that are older than `retention`, then, if still over `max_jobs`, the oldest
    /// settled ones until the cap is met. Returns the ids removed.
    ///
    /// The ids rather than a count, because forgetting a job now has a second half: its
    /// [claim](crate::claims) holds the `(repo, tree_id)` index, and a record dropped here while its
    /// claim stood would leave the tree pointing at a job this process no longer has — a duplicate
    /// dispatch would be told "already running" about work nobody is doing. The caller
    /// ([`Control::accept`](crate::control::Control::accept)) closes that with `claims.forget`.
    ///
    /// **A live job is never evicted**, at any pressure. That is enforced structurally rather than by
    /// a check: eviction candidates are those with a `settled_at`, and only a terminal transition
    /// sets one. If every job in the store is live we go over the cap and say so — refusing to evict
    /// is the correct failure, because dropping a running job would strand its driver, lose its
    /// verdict, and leave Hull waiting on a callback that can no longer be sent.
    ///
    /// What eviction costs, stated plainly: the `(repo, tree_id)` index goes with the job, so a
    /// duplicate dispatch arriving after eviction re-runs the work instead of re-reporting the
    /// recorded verdict. That is a wasted run, not a wrong answer — spec §9 puts memoization in Hull
    /// and describes our re-report as a convenience that heals a lost callback. Trading it for a
    /// bounded process is the right way round; the alternative is a store that grows until the
    /// process dies, which loses every verdict rather than one.
    ///
    /// # A settled job is not necessarily a paid one
    ///
    /// `ReportFailed` is settled — the work is over — but Hull never heard the verdict, so its tree is
    /// as wedged as one that never ran (spec §10: Hull does not poll us, and clears its in-flight set
    /// only in the callback handler). Those jobs are exactly the ones `Control::drain_undelivered`
    /// exists to retry while this process is alive, and eviction is the one thing that can put them
    /// out of its reach: after eviction only the journal entry remains, and that is drained on the
    /// *next start*, so a long-lived runner would never answer them at all.
    ///
    /// So the sweep runs in two passes, and the difference between them is the whole point:
    ///
    /// 1. **Paid** jobs — [`Reported`](crate::model::JobState::Reported), Hull has the verdict — are
    ///    evicted by the retention clock or by cap pressure, oldest first, exactly as before.
    /// 2. **Owed** jobs — settled but still [owing a verdict](crate::model::JobState::owes_a_verdict)
    ///    — are *never* dropped by the retention clock. Time passing is not evidence that a debt was paid,
    ///    and an hour of silence is the case the outbox was built for.
    ///
    /// A debt is dropped only as the last thing standing between this process and its hard `max_jobs`
    /// ceiling, after every paid job has already gone — and then **loudly**, at alert level, naming
    /// the job. The invariant that buys is "a job whose verdict was never delivered is not *silently*
    /// forgotten", not "is never forgotten": the residual failure mode is real and worth stating
    /// plainly. Under sustained cap pressure with an unreachable Hull, the oldest debts leave memory
    /// and no dispatch will retry them again in this process. Their journal entries survive on disk,
    /// so a restart still answers them; nothing else will. The alternative — exempting them
    /// absolutely — turns a Hull that refuses every callback while continuing to dispatch (a wrong
    /// secret, a 404 route) into an unbounded store and eventually a runner that dies holding every
    /// verdict it ever computed, which is strictly worse than losing the oldest few.
    pub fn evict(&mut self, now: Instant, retention: Duration, max_jobs: usize) -> Vec<JobId> {
        // The two classes, each oldest-first so both passes below take from the same end.
        let paid = self.settled_oldest_first(false);
        let owed = self.settled_oldest_first(true);

        let mut evicted: Vec<JobId> = Vec::new();
        for (settled_at, id) in &paid {
            let too_old = now.duration_since(*settled_at) >= retention;
            let over_cap = self.by_id.len() - evicted.len() > max_jobs;
            if !too_old && !over_cap {
                break;
            }
            self.remove(id);
            evicted.push(id.clone());
        }

        // Debts, and only under the hard cap. No retention clause: see the note above.
        for (_, id) in &owed {
            if self.by_id.len() - evicted.len() <= max_jobs {
                break;
            }
            // Alert level, because this is the one path in the system that gives up on answering a
            // dispatch we acked. Not silent, and not the end of the story either — the journal entry
            // is still on disk and the next start drains it (`hull_ci_server::journal::recover`).
            tracing::error!(
                alert = true,
                job_id = %id,
                max_jobs,
                "dropping a job whose verdict Hull never received — the store is at its cap with \
                 nothing paid left to evict; nothing in this process will retry it again, and only a \
                 restart will answer it from the journal"
            );
            self.remove(id);
            evicted.push(id.clone());
        }

        if self.by_id.len() > max_jobs {
            tracing::warn!(
                jobs = self.by_id.len(),
                max_jobs,
                "job store is over its cap with nothing settled to evict — every job is still live"
            );
        }
        evicted
    }

    /// Settled jobs that do (or do not) still owe Hull an answer, oldest settlement first.
    ///
    /// A live job is in neither list: it has no `settled_at`, which is what makes "a running job is
    /// never evicted" structural rather than a check somebody has to remember to write.
    fn settled_oldest_first(&self, owing: bool) -> Vec<(Instant, JobId)> {
        let mut out: Vec<(Instant, JobId)> = self
            .by_id
            .values()
            .filter(|j| j.state.owes_a_verdict() == owing)
            .filter_map(|j| j.settled_at.map(|t| (t, j.id.clone())))
            .collect();
        out.sort_by_key(|(t, _)| *t);
        out
    }

    /// Forget one job's record.
    ///
    /// Crate-internal because there is exactly one legitimate caller outside eviction: the rollback in
    /// [`Control::accept`] when the write-ahead journal refuses a freshly created job. That job has no
    /// driver, no steps and no verdict, and leaving it would hold the `(repo, tree_id)` claim against
    /// work nobody will ever do — so the dispatcher's retry would come back attached to a job that is
    /// not running, and get acked for it.
    ///
    /// **The record only.** Releasing the `(repo, tree_id)` claim is
    /// [`JobClaims::forget`](crate::claims::JobClaims::forget)'s, and both callers do both — see
    /// [`JobStore::evict`]'s note on why the ids come back.
    ///
    /// [`Control::accept`]: crate::control::Control::accept
    pub(crate) fn remove(&mut self, job_id: &str) {
        self.by_id.remove(job_id);
    }
}

// The idempotency tests that used to live here are in [`crate::claims`], with the index they were
// testing. What is left is retention, which is this type's remaining job.

#[cfg(test)]
mod retention_tests {
    use super::*;
    use crate::ids::new_job_id;
    use crate::model::JobState;
    use crate::testing::dispatch;

    /// A job recorded the way [`Control`](crate::control::Control) records one: with an id its claim
    /// already issued.
    fn record(store: &mut JobStore, repo: &str, tree: &str, at: Instant) -> JobId {
        let id = new_job_id();
        store.insert(id.clone(), dispatch(repo, tree), AuthorClass::Member, at, Duration::from_secs(60));
        id
    }

    fn settled_job(store: &mut JobStore, repo: &str, tree: &str, at: Instant) -> JobId {
        let id = record(store, repo, tree, at);
        let job = store.get_mut(&id).unwrap();
        for s in [JobState::Fetching, JobState::Planning, JobState::Running, JobState::Green, JobState::Reported] {
            job.transition_at(s, at).unwrap();
        }
        id
    }

    #[test]
    fn a_live_job_is_never_evicted_however_much_pressure_there_is() {
        // The invariant that matters. Dropping a running job strands its driver, loses its verdict,
        // and leaves Hull waiting on a callback that can never be sent — worse than being over the
        // cap. It holds structurally: only a terminal transition sets `settled_at`, and only jobs
        // with one are candidates.
        let mut store = JobStore::new();
        let t0 = Instant::now();
        for i in 0..5 {
            record(&mut store, "t/r", &format!("tree{i}"), t0);
        }
        let removed = store.evict(t0 + Duration::from_secs(86_400), Duration::from_secs(1), 1);
        assert_eq!(removed.len(), 0, "no live job may be evicted");
        assert_eq!(store.len(), 5, "and the store stays over its cap rather than losing work");
    }

    #[test]
    fn settled_jobs_older_than_retention_are_dropped() {
        let mut store = JobStore::new();
        let t0 = Instant::now();
        settled_job(&mut store, "t/r", "old", t0);
        settled_job(&mut store, "t/r", "new", t0 + Duration::from_secs(50));

        let removed = store.evict(t0 + Duration::from_secs(60), Duration::from_secs(30), usize::MAX);
        assert_eq!(removed.len(), 1, "only the one past retention");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn the_cap_evicts_oldest_first_even_inside_retention() {
        let mut store = JobStore::new();
        let t0 = Instant::now();
        let oldest = settled_job(&mut store, "t/r", "a", t0);
        settled_job(&mut store, "t/r", "b", t0 + Duration::from_secs(1));
        settled_job(&mut store, "t/r", "c", t0 + Duration::from_secs(2));

        let removed = store.evict(t0 + Duration::from_secs(3), Duration::from_secs(3600), 2);
        assert_eq!(removed.len(), 1);
        assert!(store.get(&oldest).is_none(), "the oldest settled job goes first");
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn eviction_names_what_it_dropped_so_the_claim_can_be_released_too() {
        // The cost of eviction, asserted rather than assumed: the tree becomes new work again, which
        // means a re-run instead of a re-report. A wasted run, not a wrong answer — Hull owns the real
        // memo (spec §9). What must NOT happen is the *claim* outliving the record: the tree would
        // then point at a job this process no longer has, and the next dispatch would be told
        // "already running" about work nobody is doing. So `evict` names its casualties and
        // `Control::accept` forgets their claims.
        let mut store = JobStore::new();
        let t0 = Instant::now();
        let id = settled_job(&mut store, "t/r", "tree1", t0);
        let removed = store.evict(t0 + Duration::from_secs(7200), Duration::from_secs(3600), usize::MAX);

        assert_eq!(removed, vec![id.clone()]);
        assert!(store.get(&id).is_none());
    }

    /// A job parked in `report_failed`: settled, but Hull never heard the verdict.
    fn undelivered_job(store: &mut JobStore, repo: &str, tree: &str, at: Instant) -> JobId {
        let id = record(store, repo, tree, at);
        let job = store.get_mut(&id).unwrap();
        for s in [JobState::Fetching, JobState::Planning, JobState::Running, JobState::Green, JobState::ReportFailed] {
            job.transition_at(s, at).unwrap();
        }
        id
    }

    #[test]
    fn a_verdict_hull_never_received_outlives_the_retention_clock() {
        // The interaction that makes the in-process drain worth having. `report_failed` is settled —
        // the work is over — so the retention sweep used to take it like any other finished job, and
        // once it left memory nothing in this process could retry it: only the journal entry remained,
        // and that is drained at the next start. A long-lived runner would therefore never answer it,
        // and spec §10 leaves the tree wedged until a human forces a rerun.
        //
        // Time passing is not evidence that a debt was paid. An hour of silence is precisely the case
        // the outbox was built for.
        let mut store = JobStore::new();
        let t0 = Instant::now();
        let paid = settled_job(&mut store, "t/r", "delivered", t0);
        let owed = undelivered_job(&mut store, "t/r", "undelivered", t0);

        let removed = store.evict(t0 + Duration::from_secs(7200), Duration::from_secs(3600), usize::MAX);
        assert_eq!(removed.len(), 1, "only the job Hull has already heard about");
        assert!(store.get(&paid).is_none());
        assert!(store.get(&owed).is_some(), "an undelivered verdict must still be retryable");
    }

    #[test]
    fn the_cap_takes_delivered_jobs_first_and_a_debt_only_as_a_last_resort() {
        // The other half, and the honest one: `max_jobs` stays a real ceiling. A Hull that refuses
        // every callback while continuing to dispatch — a wrong secret, a 404 route — would otherwise
        // grow the store without bound and eventually take the runner down holding every verdict it
        // ever computed, which is worse than losing the oldest few.
        //
        // So debts are evicted last, after every delivered job has gone, and never on age alone. The
        // oldest job here is a debt and it still outlives two newer delivered ones.
        let mut store = JobStore::new();
        let t0 = Instant::now();
        let owed = undelivered_job(&mut store, "t/r", "undelivered", t0);
        let newer_paid = settled_job(&mut store, "t/r", "b", t0 + Duration::from_secs(1));
        settled_job(&mut store, "t/r", "c", t0 + Duration::from_secs(2));

        let removed = store.evict(t0 + Duration::from_secs(3), Duration::from_secs(3600), 2);
        assert_eq!(removed.len(), 1);
        assert!(store.get(&newer_paid).is_none(), "the oldest *delivered* job goes first");
        assert!(store.get(&owed).is_some(), "even though the debt is older still");

        // Pressed again, the last delivered job goes and the debt still does not.
        assert_eq!(store.evict(t0 + Duration::from_secs(4), Duration::from_secs(3600), 1).len(), 1);
        assert!(store.get(&owed).is_some(), "a debt is the last thing in the store to be given up");

        // Only when it is the sole thing between this process and its ceiling. That drop is logged at
        // alert level, because it is the one path in the system that gives up on answering a dispatch
        // we acked — and its journal entry survives, so a restart still answers it. Nothing else will.
        assert_eq!(store.evict(t0 + Duration::from_secs(5), Duration::from_secs(3600), 0).len(), 1);
        assert!(store.get(&owed).is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn a_delivery_retry_does_not_renew_a_jobs_lease_on_memory() {
        // ReportFailed → Reported is a recovery path. If it restamped `settled_at`, a job whose
        // delivery keeps failing and retrying would keep postponing its own eviction — exactly the
        // job least worth holding on to.
        let mut store = JobStore::new();
        let t0 = Instant::now();
        let id = record(&mut store, "t/r", "tree1", t0);
        let job = store.get_mut(&id).unwrap();
        for s in [JobState::Fetching, JobState::Planning, JobState::Running, JobState::Green] {
            job.transition_at(s, t0).unwrap();
        }
        job.transition_at(JobState::ReportFailed, t0).unwrap();
        let first = job.settled_at.unwrap();
        job.transition_at(JobState::Reported, t0 + Duration::from_secs(600)).unwrap();
        assert_eq!(job.settled_at.unwrap(), first, "the retention clock starts once");
    }
}
