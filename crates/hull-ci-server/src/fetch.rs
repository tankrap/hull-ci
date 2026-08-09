//! The [`Fetcher`] seam, backed by `hull-ci-fetch`'s broker.
//!
//! This is a thin adapter and is meant to stay one. Everything that makes the fetch safe — the byte
//! and entry caps, the hardened tar reader, the mandatory re-hash against `tree_id`, the tenant-scoped
//! store, the sensitive handling of `fetch_token` — lives in the broker (design D§4.2, spec §6/§14.2).
//! What this file adds is the translation between the control plane's vocabulary and the broker's, and
//! the mapping of a broker failure onto a control-plane failure.
//!
//! Note what is *not* here: no retry. A fetch failure is `errored`, Hull does not memoize `errored`
//! (spec §7), and a re-check re-dispatches — so a failed fetch costs one re-check, while a retry loop
//! inside the fetch phase would eat the fetch clock and turn a fast, honest `errored` into a slow one.

use std::sync::Arc;

use hull_ci_control::callback::BoxFuture;
use hull_ci_control::seams::{FetchError, FetchRequest, Fetcher, VerifiedTree};
use hull_ci_fetch::{FetchBroker, FetchError as BrokerError, ReclaimConfig, VerifyError};

use crate::config::Config;

/// The content store's reclamation policy for this deployment, announced.
///
/// Announced rather than merely applied, for the reason the journal and the memo announce
/// themselves: what an operator has to be able to tell apart is *"the sweep ran and everything is
/// still referenced"* from *"nothing has ever swept"*, and from the outside — a disk that is not
/// shrinking — those are the same picture. The startup line is the first half of that (this runner
/// will sweep, this often, keeping this long); `FetchBroker`'s per-sweep `info` line is the second.
///
/// The **cooldown is not an operator setting** and is left at [`ReclaimConfig`]'s default. It is a
/// rate limit on our own housekeeping rather than a policy about anyone's data: an operator whose
/// store is too large wants a shorter retention, and one whose runner is too busy does not want a
/// reaper walking more often. Exposing it would offer a dial whose only useful setting is the one
/// already chosen.
pub fn reclaim(config: &Config) -> ReclaimConfig {
    let default = ReclaimConfig::default();
    if !config.reclaim {
        tracing::warn!(
            "content store reclamation is OFF (HULL_CI_RECLAIM=off): every tree this runner fetches \
             is kept forever. Nothing else here bounds the store, and a full disk fails every job on \
             this host, not just the one that filled it."
        );
        return ReclaimConfig { enabled: false, ..default };
    }

    let reclaim = ReclaimConfig { enabled: true, tree_retention: config.reclaim_retention, ..default };
    tracing::info!(
        retention_days = reclaim.tree_retention.as_secs() / (24 * 60 * 60),
        cooldown_secs = reclaim.cooldown.as_secs(),
        "content store reclamation on: a tree unused for the retention is removed, and then any blob \
         no tree names. Swept when a commit grows the store, at most once per tenant per cooldown. A \
         reclaimed tree is re-fetched on the next dispatch that wants it (spec §6) — the cost of \
         reclaiming too much is a cache miss."
    );
    reclaim
}

/// Adapts [`FetchBroker`] to the control plane's [`Fetcher`] seam.
pub struct BrokerFetcher {
    broker: FetchBroker,
}

impl BrokerFetcher {
    pub fn new(broker: FetchBroker) -> Self {
        BrokerFetcher { broker }
    }

    pub fn broker(&self) -> &FetchBroker {
        &self.broker
    }
}

impl Fetcher for BrokerFetcher {
    fn fetch<'a>(&'a self, req: &'a FetchRequest) -> BoxFuture<'a, Result<VerifiedTree, FetchError>> {
        Box::pin(async move {
            let stored = self
                .broker
                .ensure_tree(&req.tenant, &req.tree_id, &req.source_url, req.fetch_token.as_deref())
                .await
                .map_err(to_seam_error)?;
            tracing::info!(
                tenant = %req.tenant,
                tree_id = %stored.tree_id,
                cached = stored.cached,
                "tree ready"
            );
            // The store's pin travels onward as the seam's opaque keep-alive.
            //
            // This is the line that makes `ContentStore::reclaim` safe to switch on at all. Without
            // it the pin dies here, at the seam, and the tree is unprotected for exactly the window
            // that matters: a job is admitted at the fetch and materializes at its *steps*, which
            // can be a full queue wait later. A sweep in between deletes the tree out from under a
            // job that was already accepted, and the failure surfaces as a materialize error on a
            // path the fetch reported as `cached: true` minutes earlier.
            //
            // `hull-ci-control` never looks inside it and could not — it must not name a
            // `hull-ci-fetch` type, which is the entire reason the seams are traits (see
            // `seams::VerifiedTree::keep_alive`). Its contract is to keep the value alive, which
            // `Control` does by holding the `VerifiedTree` in its per-job map until `retire`.
            Ok(VerifiedTree {
                tree_id: stored.tree_id,
                path: stored.path,
                cached: stored.cached,
                keep_alive: Some(Arc::new(stored.pin)),
            })
        })
    }
}

/// Map a broker failure onto the seam's error.
///
/// The mismatch case is called out separately because it is the one failure that is *about the
/// archive* rather than about the transfer: the source served bytes that are not the tree it named.
/// It is still not `red` — we never ran anything, so we have no statement about the code — but an
/// operator reading `errored` needs to be able to tell "Hull sent us the wrong bytes" apart from
/// "the connection dropped", and the seam has a variant for exactly that.
fn to_seam_error(e: BrokerError) -> FetchError {
    match e {
        BrokerError::Verify(VerifyError::Mismatch { .. }) => FetchError::TreeMismatch,
        other => FetchError::Failed(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mismatched_archive_is_its_own_failure_not_a_generic_one() {
        let mismatch = BrokerError::Verify(VerifyError::Mismatch {
            expected: "a".repeat(64),
            actual: "b".repeat(64),
        });
        assert!(matches!(to_seam_error(mismatch), FetchError::TreeMismatch));

        let http = BrokerError::Http { status: 502, url: "https://hull.example/tar".into() };
        match to_seam_error(http) {
            FetchError::Failed(detail) => assert!(detail.contains("502")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────────────────────
    // The keep-alive, end to end.
    //
    // `ContentStore::reclaim` is only safe to switch on if a tree a job is *already using* survives
    // it. The store's half of that is an RAII pin; this crate's half is carrying the pin across the
    // seam, and the control plane's half is holding the `VerifiedTree` for the whole life of the
    // job. None of the three is worth anything alone, and the join between them is not something a
    // unit test of any one of them can see — so this drives a real `Control`, over a real
    // `ContentStore`, with a node that leases a step and then goes quiet, which is precisely the
    // "admitted, queued, not finished" state a sweep must not touch.
    // ─────────────────────────────────────────────────────────────────────────────────────────────

    #[cfg(test)]
    mod keep_alive {
        use super::*;
        use hull_ci_control::callback::{
            BoxFuture as CbFuture, CallbackRequest, CallbackResponse, CallbackTransport, TransportError,
        };
        use hull_ci_control::model::StepSpec;
        use hull_ci_control::seams::{Membership, NodeError, NodeSink, PlanError, Planner};
        use hull_ci_control::{Control, ControlConfig, Deps};
        use hull_ci_fetch::{ContentStore, ReclaimPolicy};
        use hull_ci_proto::{Assignment, AuthorClass, Dispatch, StepOutcome, StepReport};
        use std::time::{Duration, SystemTime};

        const TENANT: &str = "acme";
        /// A syntactically valid keel address. Its value is irrelevant — the store files a tree where
        /// it is told; what is under test is how long that tree lives.
        const TREE: &str = "abababababababababababababababababababababababababababababababab";

        /// Everything past the fetch is a stub: this test is about the tree's lifetime, and a real
        /// planner or sandbox would only add ways for it to fail for another reason.
        struct OneStep;
        impl Planner for OneStep {
            fn plan<'a>(&'a self, _t: &'a VerifiedTree) -> BoxFuture<'a, Result<Vec<StepSpec>, PlanError>> {
                Box::pin(async { Ok(vec![StepSpec::new("test", vec!["/bin/true".into()], "img")]) })
            }
        }

        /// Leases the step and then says nothing at all, so the job parks in `running` with a
        /// `leased` step — a job that has been admitted, has its tree, and is not finished. That is
        /// the state the whole feature exists for, and a node that reported immediately would close
        /// the window before a sweep could be aimed at it.
        #[derive(Default)]
        struct LeaseAndGoQuiet {
            /// Every tree the fleet was handed, kept — a real fleet holds one for as long as its
            /// step is running, and a stub that dropped it would quietly stand in for a fleet that
            /// cannot protect the tree it is materializing from.
            handed: std::sync::Mutex<Vec<VerifiedTree>>,
        }
        impl LeaseAndGoQuiet {
            fn handed(&self) -> Vec<VerifiedTree> {
                self.handed.lock().unwrap().clone()
            }
            fn release(&self) {
                self.handed.lock().unwrap().clear();
            }
        }
        impl NodeSink for LeaseAndGoQuiet {
            fn assign(&self, _a: &Assignment, t: &VerifiedTree) -> Result<String, NodeError> {
                self.handed.lock().unwrap().push(t.clone());
                Ok("node-test".into())
            }
            fn cancel(&self, _job_id: &str, _step_id: &str) {}
        }

        struct SilentTransport;
        impl CallbackTransport for SilentTransport {
            fn post<'a>(&'a self, _r: &'a CallbackRequest) -> CbFuture<'a, Result<CallbackResponse, TransportError>> {
                Box::pin(async { Ok(CallbackResponse { status: 200 }) })
            }
        }

        struct Everyone;
        impl Membership for Everyone {
            fn classify(&self, _repo: &str, _author: &str) -> AuthorClass {
                AuthorClass::Member
            }
        }

        fn dispatch(tree_id: &str) -> Dispatch {
            Dispatch {
                repo: format!("{TENANT}/widget"),
                change: "c0ffee".into(),
                tree_id: tree_id.into(),
                intent: "a change".into(),
                author: "someone".into(),
                // Nowhere. The tree is already in the store, so reaching for this would be the
                // failure — every fetch in this test is a hit.
                source_url: "http://127.0.0.1:1/never-dialed".into(),
                callback_url: "http://127.0.0.1:1/cb".into(),
                fetch_token: None,
            }
        }

        async fn wait_until(mut f: impl FnMut() -> bool) -> bool {
            for _ in 0..400 {
                if f() {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            false
        }

        /// Reclaim everything this tenant has not used in the last instant.
        fn sweep(store: &ContentStore) -> hull_ci_fetch::ReclaimReport {
            store
                .reclaim(TENANT, &ReclaimPolicy { tree_retention: Duration::ZERO, now: SystemTime::now() })
                .unwrap()
        }

        #[tokio::test]
        async fn a_tree_a_live_job_is_using_survives_a_sweep_and_is_reclaimable_once_the_job_is_done() {
            let dir = tempfile::tempdir().unwrap();
            let store = ContentStore::new(dir.path());
            let broker = FetchBroker::new(store.clone()).unwrap();

            // One tree in the store, and nothing holding it: the sweep below would take it.
            let staged = store.stage(TENANT).unwrap();
            std::fs::write(staged.path().join("Makefile"), b"test:\n\ttrue\n").unwrap();
            store.commit(TENANT, TREE, staged).unwrap();
            assert!(store.has(TENANT, TREE));

            let node = Arc::new(LeaseAndGoQuiet::default());
            let control = Control::new(
                ControlConfig::default(),
                Deps {
                    fetcher: Arc::new(BrokerFetcher::new(broker)),
                    planner: Arc::new(OneStep),
                    node: node.clone(),
                    transport: Arc::new(SilentTransport),
                    membership: Arc::new(Everyone),
                    claims: Arc::new(hull_ci_control::LocalClaims::new()),
                    journal: Arc::new(hull_ci_control::NoJournal),
                },
            );

            let job_id = control.accept(dispatch(TREE)).unwrap().job_id;
            let live = |c: &Arc<Control>| {
                c.snapshot_jobs()
                    .into_iter()
                    .find(|j| j.job_id == job_id)
                    .map(|j| j.state == hull_ci_control::model::JobState::Running)
                    .unwrap_or(false)
            };
            assert!(wait_until(|| live(&control)).await, "the job never reached `running`");

            // The sweep, aimed at a tree a job is in the middle of using. Retention is zero, so
            // nothing but the pin can save it — and the pin has to have travelled from
            // `ContentStore::open`, through `BrokerFetcher`, across the seam as an opaque
            // keep-alive, into `Control`'s per-job map. Any one of those links missing and this
            // tree is deleted here.
            let report = sweep(&store);
            assert_eq!(
                report.trees_pinned, 1,
                "the tree of a running job is not pinned: the keep-alive is not reaching the \
                 control plane, and a sweep would delete a queued job's tree"
            );
            assert_eq!(report.trees_removed, 0);
            assert!(store.has(TENANT, TREE), "and it is still on disk");
            assert_eq!(
                std::fs::read_to_string(store.tree_path(TENANT, TREE).join("Makefile")).unwrap(),
                "test:\n\ttrue\n",
                "intact, not merely present — a step is about to materialize from it"
            );
            // The blob is untouched too: the tree still holds its link, so there is nothing
            // unreferenced for the second half of the sweep to take.
            assert_eq!(report.blobs_removed, 0);

            // The keep-alive reached the *fleet*, not just the control plane's bookkeeping. This is
            // the hop that matters for a step already in flight: the value `NodeSink::assign` is
            // handed is the only thing a node run can hold, and a control plane that stored the tree
            // without its guard would place work on a tree it had stopped protecting.
            {
                // Scoped, because a `VerifiedTree` left lying about in this function is itself a
                // holder — which is the whole point of the type and would silently defeat the
                // release assertions below.
                let handed = node.handed();
                assert_eq!(handed.len(), 1, "the fleet was given exactly this job's step");
                assert!(
                    handed[0].keep_alive.is_some(),
                    "the fleet was handed a tree with no keep-alive: a node materializing from it \
                     has nothing holding the path it is about to read"
                );
            }

            // Now let the job finish. The driver settles it and `retire` drops the control plane's
            // copy; the fleet's copy is released just below, and only then is the tree unheld.
            let step_id = control
                .snapshot_jobs()
                .into_iter()
                .find(|j| j.job_id == job_id)
                .and_then(|j| j.steps.first().map(|s| s.step_id.clone()))
                .expect("the job has a step");
            control
                .record_step_report(
                    &StepReport {
                        job_id: job_id.clone(),
                        step_id,
                        outcome: StepOutcome::Passed,
                        reason: None,
                        exit_code: Some(0),
                        log_key: None,
                        detail: String::new(),
                    },
                    "node-test",
                )
                .expect("the lease holder may report");
            assert!(
                wait_until(|| control
                    .snapshot_jobs()
                    .into_iter()
                    .find(|j| j.job_id == job_id)
                    .map(|j| j.state.is_finished())
                    .unwrap_or(false))
                .await,
                "the job never settled"
            );

            // The fleet is done with it too. Until this line the tree is still held — by the copy
            // the node was given — which is the property a running step depends on.
            assert_eq!(sweep(&store).trees_pinned, 1, "the fleet's copy alone still protects the tree");
            assert!(store.has(TENANT, TREE));
            node.release();

            // The other half, and the one that catches a keep-alive that is never released: a pin
            // that outlives its job is a store that can never be reclaimed, which is the same
            // outcome as no reclamation at all, arrived at from the opposite direction. Retried
            // because `retire` runs on the driver's task, not on this one.
            assert!(
                wait_until(|| sweep(&store).trees_removed == 1).await,
                "the tree of a finished job is still pinned: nothing will ever reclaim it"
            );
            assert!(!store.has(TENANT, TREE));
            assert_eq!(sweep(&store), Default::default(), "and nothing is left to sweep");
        }
    }
}
