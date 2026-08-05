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

        if let Some(existing_id) = self.by_key.get(&key) {
            if let Some(job) = self.by_id.get(existing_id) {
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

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
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
