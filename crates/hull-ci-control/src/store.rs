//! Job storage and the idempotency rule — design D§4.1 step 3, spec §9.
//!
//! Spec §9 is blunt about whose problem duplicate dispatch is: Hull's in-flight de-dup is
//! "best-effort (in-memory)", so **our** system "SHOULD itself be idempotent per `(tree_id)`", and a
//! duplicate dispatch "MUST be safe to run". The key is `(repo, tree_id)`: `tree_id` alone would
//! collide two tenants' identical trees into one job — which is both a correctness bug (one
//! callback_url wins) and a cross-tenant channel (design D§1's threat table).
//!
//! Two duplicate cases, both cheap:
//!
//! * a duplicate for a **live** job attaches to it — same job id, no second pipeline, one verdict;
//! * a duplicate for a **finished** job re-sends the recorded verdict, which is how a lost callback
//!   heals itself without re-running a single step.
//!
//! Storage is in-memory for M1 (single-replica bring-up). The design's `INSERT … ON CONFLICT DO
//! NOTHING` lands with Postgres; the shape here — one atomic admit that either creates or reports a
//! duplicate — is the same shape, so the swap does not move the decision anywhere.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use hull_ci_proto::{AuthorClass, Dispatch, Verdict};

use crate::ids::new_job_id;
use crate::model::{Job, JobId};

/// What admitting a dispatch did.
#[derive(Debug, Clone)]
pub enum Admit {
    /// First time we have seen `(repo, tree_id)`. The caller starts the pipeline.
    Created { job_id: JobId },
    /// A job for this tree is already in flight. Attach; the one verdict will serve both dispatches.
    Live { job_id: JobId },
    /// Already decided. The caller re-sends `verdict` (spec §9: a duplicate "simply re-affirms the
    /// same verdict") without re-running anything.
    Finished { job_id: JobId, verdict: Box<Verdict> },
}

impl Admit {
    pub fn job_id(&self) -> &str {
        match self {
            Admit::Created { job_id } | Admit::Live { job_id } => job_id,
            Admit::Finished { job_id, .. } => job_id,
        }
    }

    pub fn is_duplicate(&self) -> bool {
        !matches!(self, Admit::Created { .. })
    }
}

#[derive(Default)]
pub struct JobStore {
    by_id: HashMap<JobId, Job>,
    /// The idempotency index: `(repo, tree_id) → job_id`.
    by_key: HashMap<(String, String), JobId>,
}

impl JobStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert-or-attach, atomically with respect to this store's lock.
    pub fn admit(
        &mut self,
        dispatch: Dispatch,
        author_class: AuthorClass,
        now: Instant,
        job_timeout: Duration,
    ) -> Admit {
        let key = (dispatch.repo.clone(), dispatch.tree_id.clone());

        if let Some(existing_id) = self.by_key.get(&key).cloned() {
            if let Some(job) = self.by_id.get_mut(&existing_id) {
                // The work is a duplicate; the *destination* may not be. A second change sharing this
                // tree carries its own `callback_url`, and dropping it would leave that change waiting
                // forever on an answer delivered elsewhere (see `Job::callback_urls`).
                job.add_callback_url(&dispatch.callback_url);
                return match (job.state.is_finished(), job.verdict.clone()) {
                    (true, Some(v)) => Admit::Finished { job_id: job.id.clone(), verdict: Box::new(v) },
                    // Finished-but-verdictless cannot happen through the driver; treat it as live
                    // rather than inventing a verdict for it.
                    _ => Admit::Live { job_id: job.id.clone() },
                };
            }
            // Index entry with no job behind it: heal by falling through to a fresh insert.
        }

        let id = new_job_id();
        let job = Job::new(id.clone(), dispatch, author_class, now, job_timeout);
        self.by_key.insert(key, id.clone());
        self.by_id.insert(id.clone(), job);
        Admit::Created { job_id: id }
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
    /// settled ones until the cap is met. Returns how many were removed.
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
    pub fn evict(&mut self, now: Instant, retention: Duration, max_jobs: usize) -> usize {
        let mut settled: Vec<(Instant, JobId)> = self
            .by_id
            .values()
            .filter_map(|j| j.settled_at.map(|t| (t, j.id.clone())))
            .collect();
        // Oldest first, so both passes below take from the same end.
        settled.sort_by_key(|(t, _)| *t);

        let mut removed = 0;
        let mut i = 0;
        while i < settled.len() {
            let (settled_at, id) = &settled[i];
            let too_old = now.duration_since(*settled_at) >= retention;
            let over_cap = self.by_id.len() - removed > max_jobs;
            if !too_old && !over_cap {
                break;
            }
            self.remove(id);
            removed += 1;
            i += 1;
        }

        if self.by_id.len() > max_jobs {
            tracing::warn!(
                jobs = self.by_id.len(),
                max_jobs,
                "job store is over its cap with nothing settled to evict — every job is still live"
            );
        }
        removed
    }

    fn remove(&mut self, job_id: &str) {
        if let Some(job) = self.by_id.remove(job_id) {
            // Only clear the index if it still points at *this* job. A later job for the same
            // (repo, tree_id) — which exists precisely because an earlier one was evicted — must not
            // have its index entry removed by its predecessor's cleanup.
            let key = job.key();
            if self.by_key.get(&key).map(|id| id == job_id).unwrap_or(false) {
                self.by_key.remove(&key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::JobState;
    use crate::testing::dispatch;

    fn store() -> JobStore {
        JobStore::new()
    }

    #[test]
    fn a_duplicate_dispatch_for_a_live_tree_attaches_instead_of_starting_a_second_job() {
        let mut s = store();
        let now = Instant::now();
        let a = s.admit(dispatch("t/r", "tree1"), AuthorClass::Outsider, now, Duration::from_secs(60));
        let b = s.admit(dispatch("t/r", "tree1"), AuthorClass::Outsider, now, Duration::from_secs(60));

        assert!(matches!(a, Admit::Created { .. }));
        assert!(matches!(b, Admit::Live { .. }));
        assert_eq!(a.job_id(), b.job_id(), "one tree, one job");
        assert_eq!(s.len(), 1, "a duplicate must not double the work (spec §9)");
    }

    #[test]
    fn a_duplicate_for_a_finished_job_returns_the_recorded_verdict_to_re_report() {
        let mut s = store();
        let now = Instant::now();
        let id = s
            .admit(dispatch("t/r", "tree1"), AuthorClass::Outsider, now, Duration::from_secs(60))
            .job_id()
            .to_string();
        {
            let job = s.get_mut(&id).unwrap();
            job.state = JobState::Green;
            job.verdict = Some(Verdict::green("42 tests, 0 failed"));
        }

        match s.admit(dispatch("t/r", "tree1"), AuthorClass::Outsider, now, Duration::from_secs(60)) {
            Admit::Finished { job_id, verdict } => {
                assert_eq!(job_id, id);
                assert_eq!(verdict.summary.as_deref(), Some("42 tests, 0 failed"));
            }
            other => panic!("expected Finished, got {other:?}"),
        }
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn the_key_is_repo_and_tree_not_tree_alone() {
        // Two tenants with an identical tree are two jobs with two callback_urls. Collapsing them
        // would send one tenant's verdict to the other (design D§1: log/summary bleed).
        let mut s = store();
        let now = Instant::now();
        let a = s.admit(dispatch("acme/api", "same"), AuthorClass::Outsider, now, Duration::from_secs(60));
        let b = s.admit(dispatch("other/api", "same"), AuthorClass::Outsider, now, Duration::from_secs(60));
        assert_ne!(a.job_id(), b.job_id());
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn a_different_change_over_the_same_tree_is_the_same_work() {
        // Spec §1.2: "the change is the unit of work, the tree is the identity."
        let mut s = store();
        let now = Instant::now();
        let mut d2 = dispatch("t/r", "tree1");
        d2.change = "a-different-change".into();
        let a = s.admit(dispatch("t/r", "tree1"), AuthorClass::Outsider, now, Duration::from_secs(60));
        let b = s.admit(d2, AuthorClass::Outsider, now, Duration::from_secs(60));
        assert_eq!(a.job_id(), b.job_id());
    }
}

#[cfg(test)]
mod retention_tests {
    use super::*;
    use crate::model::JobState;
    use crate::testing::dispatch;

    fn settled_job(store: &mut JobStore, repo: &str, tree: &str, at: Instant) -> JobId {
        let admit = store.admit(dispatch(repo, tree), AuthorClass::Member, at, Duration::from_secs(60));
        let id = admit.job_id().to_string();
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
            store.admit(dispatch("t/r", &format!("tree{i}")), AuthorClass::Member, t0, Duration::from_secs(60));
        }
        let removed = store.evict(t0 + Duration::from_secs(86_400), Duration::from_secs(1), 1);
        assert_eq!(removed, 0, "no live job may be evicted");
        assert_eq!(store.len(), 5, "and the store stays over its cap rather than losing work");
    }

    #[test]
    fn settled_jobs_older_than_retention_are_dropped() {
        let mut store = JobStore::new();
        let t0 = Instant::now();
        settled_job(&mut store, "t/r", "old", t0);
        settled_job(&mut store, "t/r", "new", t0 + Duration::from_secs(50));

        let removed = store.evict(t0 + Duration::from_secs(60), Duration::from_secs(30), usize::MAX);
        assert_eq!(removed, 1, "only the one past retention");
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
        assert_eq!(removed, 1);
        assert!(store.get(&oldest).is_none(), "the oldest settled job goes first");
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn an_evicted_tree_dispatched_again_is_new_work_not_a_half_found_duplicate() {
        // The cost of eviction, asserted rather than assumed: the index goes with the job, so this
        // re-runs instead of re-reporting. A wasted run, not a wrong answer — Hull owns the real memo
        // (spec §9). What must NOT happen is `Admit::Finished` pointing at a job that no longer
        // exists, which is why `remove` clears both maps together.
        let mut store = JobStore::new();
        let t0 = Instant::now();
        settled_job(&mut store, "t/r", "tree1", t0);
        store.evict(t0 + Duration::from_secs(7200), Duration::from_secs(3600), usize::MAX);

        let again = store.admit(dispatch("t/r", "tree1"), AuthorClass::Member, t0, Duration::from_secs(60));
        assert!(matches!(again, Admit::Created { .. }), "got {again:?}");
        assert!(store.get(again.job_id()).is_some(), "and the new job is really there");
    }

    #[test]
    fn a_delivery_retry_does_not_renew_a_jobs_lease_on_memory() {
        // ReportFailed → Reported is a recovery path. If it restamped `settled_at`, a job whose
        // delivery keeps failing and retrying would keep postponing its own eviction — exactly the
        // job least worth holding on to.
        let mut store = JobStore::new();
        let t0 = Instant::now();
        let admit = store.admit(dispatch("t/r", "tree1"), AuthorClass::Member, t0, Duration::from_secs(60));
        let id = admit.job_id().to_string();
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
