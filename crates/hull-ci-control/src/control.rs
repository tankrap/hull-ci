//! The control plane itself: accept, drive, decide, report.
//!
//! One [`Control`] owns the job store, the seams to the broker/planner/fleet, and the callback
//! sender. It runs one asynchronous **driver** per job:
//!
//! ```text
//! accept ──202──▶ queued → fetching → planning → running ─┬─▶ green/red/errored ─▶ reported
//!                                                          └─ (timeout sweep, fail-fast cancel)
//! ```
//!
//! The ack is returned before any of that starts (design D§4.1: "the ack means *durably ours*.
//! Everything after is asynchronous"), which is also what spec §5 means by "*accepted*, not *done*".
//!
//! Nothing here runs job code. `argv` is copied from the plan into an [`Assignment`] and handed to a
//! node; it is never a string this process interpolates, splits, or executes (spec §14.1).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hull_ci_proto::{
    sanitize_summary, Assignment, Dispatch, IsolationTier, Reason, StepOutcome, StepReport, Verdict,
    SUMMARY_MAX_CHARS,
};
use tokio::sync::Notify;

use crate::aggregate::{fold, Decision, Fold};
use crate::callback::{deliver, CallbackRequest, CallbackTransport, Delivery, RetryPolicy};
use crate::ids::new_step_id;
use crate::model::{Job, JobId, JobState, Step, StepId, StepSpec, StepState};
use crate::seams::{
    Fetcher, FetchRequest, Membership, NodeError, NodeSink, Planner, VerifiedTree,
};
use crate::store::{Admit, JobStore};
use crate::timeouts::{expiry_verdict, next_step_deadline, sweep, Expiry, Timeouts};

/// Everything the control plane is configured with, minus the listen address.
#[derive(Clone)]
pub struct ControlConfig {
    /// The shared secret (spec §8). `None` means an endpoint with no secret configured.
    pub secret: Option<String>,
    pub timeouts: Timeouts,
    pub retry: RetryPolicy,
    /// The isolation tier this deployment places work in. M1 is [`IsolationTier::Container`] — a
    /// bring-up scaffold, single-tenant only (design D§13).
    pub tier: IsolationTier,
    /// Lease TTL handed to a node (design D§5.3).
    pub lease_ttl: Duration,
    /// Base for `details_url` (design G4). Only our own hex job id is ever appended — never a byte
    /// that came from a dispatch or from job output (spec §14.5).
    pub details_base_url: Option<String>,
}

impl Default for ControlConfig {
    fn default() -> Self {
        ControlConfig {
            secret: None,
            timeouts: Timeouts::default(),
            retry: RetryPolicy::default(),
            tier: IsolationTier::Container,
            lease_ttl: Duration::from_secs(30),
            details_base_url: None,
        }
    }
}

/// The wired-in collaborators. Swappable so the decision logic is testable without a sandbox.
#[derive(Clone)]
pub struct Deps {
    pub fetcher: Arc<dyn Fetcher>,
    pub planner: Arc<dyn Planner>,
    pub node: Arc<dyn NodeSink>,
    pub transport: Arc<dyn CallbackTransport>,
    pub membership: Arc<dyn Membership>,
}

/// What the ingest handler answers with.
#[derive(Debug, Clone)]
pub struct Accepted {
    pub job_id: JobId,
    /// True when `(repo, tree_id)` was already known — attached to a live job, or re-reported from a
    /// finished one (spec §9).
    pub duplicate: bool,
}

/// Why a step report was refused. Verdict integrity, design D§10.4: "a step result is accepted only
/// from the node currently holding its lease; a late result from an expired lease is dropped."
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReportRejected {
    #[error("unknown job")]
    UnknownJob,
    #[error("unknown step")]
    UnknownStep,
    #[error("reporting node does not hold the lease")]
    NotLeaseHolder,
    #[error("step is not in flight")]
    NotInFlight,
    #[error("lease expired before the report arrived")]
    LeaseExpired,
}

pub struct Control {
    config: ControlConfig,
    deps: Deps,
    jobs: Mutex<JobStore>,
    /// One waker per live job, so a step report wakes its driver instead of the driver polling.
    wakers: Mutex<HashMap<JobId, Arc<Notify>>>,
}

impl Control {
    pub fn new(config: ControlConfig, deps: Deps) -> Arc<Self> {
        Arc::new(Control {
            config,
            deps,
            jobs: Mutex::new(JobStore::new()),
            wakers: Mutex::new(HashMap::new()),
        })
    }

    pub fn config(&self) -> &ControlConfig {
        &self.config
    }

    pub fn secret(&self) -> Option<&str> {
        self.config.secret.as_deref()
    }

    // ── Ingest ───────────────────────────────────────────────────────────────────────────────────

    /// Record the job and start (or re-report) it. Returns as soon as the job is recorded — design
    /// D§4.1: ack fast, and only after the record exists.
    ///
    /// Must be called from a tokio context; the pipeline runs on a spawned task so the ack is not
    /// behind any work.
    pub fn accept(self: &Arc<Self>, dispatch: Dispatch) -> Accepted {
        let author_class = self.deps.membership.classify(&dispatch.repo, &dispatch.author);
        let repo = dispatch.repo.clone();
        let tree_id = dispatch.tree_id.clone();

        let admit = {
            let mut jobs = self.lock_jobs();
            jobs.admit(dispatch, author_class, Instant::now(), self.config.timeouts.job)
        };

        let job_id = admit.job_id().to_string();
        match &admit {
            Admit::Created { .. } => {
                self.wakers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(job_id.clone(), Arc::new(Notify::new()));
                tracing::info!(%job_id, %repo, %tree_id, ?author_class, "dispatch accepted");
                let ctrl = Arc::clone(self);
                let id = job_id.clone();
                tokio::spawn(async move { drive(ctrl, id).await });
            }
            Admit::Live { .. } => {
                tracing::info!(%job_id, %repo, %tree_id, "duplicate dispatch attached to live job");
            }
            Admit::Finished { .. } => {
                // Cheap, and it heals a lost callback (design D§4.1).
                tracing::info!(%job_id, %repo, %tree_id, "duplicate dispatch for a finished job — re-reporting");
                let ctrl = Arc::clone(self);
                let id = job_id.clone();
                tokio::spawn(async move { ctrl.report(&id).await });
            }
        }

        Accepted { job_id, duplicate: admit.is_duplicate() }
    }

    // ── The node-facing side (design D§5.3, D§10.4) ──────────────────────────────────────────────

    /// Apply a node's terminal report for one step.
    ///
    /// `from_node` is the authenticated identity of the reporting node, not a field the report can
    /// claim. Only the lease holder is believed, which is what makes "a step may run twice"
    /// harmless: it may run twice, but exactly one run is ever counted.
    pub fn record_step_report(
        &self,
        report: &StepReport,
        from_node: &str,
    ) -> Result<(), ReportRejected> {
        let now = Instant::now();
        {
            let mut jobs = self.lock_jobs();
            let job = jobs.get_mut(&report.job_id).ok_or(ReportRejected::UnknownJob)?;
            let step = job.step_mut(&report.step_id).ok_or(ReportRejected::UnknownStep)?;

            if !matches!(step.state, StepState::Leased | StepState::Running) {
                return Err(ReportRejected::NotInFlight);
            }
            if step.node_id.as_deref() != Some(from_node) {
                return Err(ReportRejected::NotLeaseHolder);
            }
            if step.lease_expires_at.is_some_and(|exp| now > exp) {
                return Err(ReportRejected::LeaseExpired);
            }

            let next = match report.outcome {
                StepOutcome::Passed => StepState::Passed,
                StepOutcome::Failed => StepState::Failed,
                StepOutcome::Errored => StepState::Errored,
            };
            step.transition(next).map_err(|_| ReportRejected::NotInFlight)?;
            step.exit_code = report.exit_code;
            step.log_key = report.log_key.clone();
            // Sanitized again on the way out (aggregate.rs); this is the defence-in-depth pass the
            // proto crate's `StepReport::detail` doc calls for.
            step.detail = sanitize_summary(&report.detail, SUMMARY_MAX_CHARS);
            step.finished_at = Some(now);
            if next == StepState::Errored {
                step.error_reason = Some(Reason::Infra);
            }
        }
        self.wake(&report.job_id);
        Ok(())
    }

    /// Extend a lease (design D§5.3: the node renews every 10 s while running).
    pub fn renew_lease(&self, job_id: &str, step_id: &str, from_node: &str) -> Result<(), ReportRejected> {
        let mut jobs = self.lock_jobs();
        let job = jobs.get_mut(job_id).ok_or(ReportRejected::UnknownJob)?;
        let ttl = self.config.lease_ttl;
        let step = job.step_mut(step_id).ok_or(ReportRejected::UnknownStep)?;
        if step.node_id.as_deref() != Some(from_node) {
            return Err(ReportRejected::NotLeaseHolder);
        }
        if !matches!(step.state, StepState::Leased | StepState::Running) {
            return Err(ReportRejected::NotInFlight);
        }
        step.lease_expires_at = Some(Instant::now() + ttl);
        if step.state == StepState::Leased {
            let _ = step.transition(StepState::Running);
        }
        Ok(())
    }

    // ── Introspection (used by tests and, later, the operator dashboard) ─────────────────────────

    pub fn job_state(&self, job_id: &str) -> Option<JobState> {
        self.with_job(job_id, |j| j.state)
    }

    pub fn verdict(&self, job_id: &str) -> Option<Verdict> {
        self.with_job(job_id, |j| j.verdict.clone()).flatten()
    }

    pub fn with_job<R>(&self, job_id: &str, f: impl FnOnce(&Job) -> R) -> Option<R> {
        self.lock_jobs().get(job_id).map(f)
    }

    fn with_job_mut<R>(&self, job_id: &str, f: impl FnOnce(&mut Job) -> R) -> Option<R> {
        self.lock_jobs().get_mut(job_id).map(f)
    }

    fn lock_jobs(&self) -> std::sync::MutexGuard<'_, JobStore> {
        // A panic in one job's bookkeeping must not take the whole runner's state down with it.
        self.jobs.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn waker(&self, job_id: &str) -> Arc<Notify> {
        let mut w = self.wakers.lock().unwrap_or_else(|e| e.into_inner());
        Arc::clone(w.entry(job_id.to_string()).or_insert_with(|| Arc::new(Notify::new())))
    }

    fn wake(&self, job_id: &str) {
        // `notify_one` stores a permit, so a report that lands between the driver's fold and its
        // await is not lost. Looked up rather than created: a job whose driver has finished has no
        // waker, and re-inserting one would leak an entry per late report.
        let waker = self
            .wakers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(job_id)
            .map(Arc::clone);
        if let Some(w) = waker {
            w.notify_one();
        }
    }

    // ── Phases ───────────────────────────────────────────────────────────────────────────────────

    /// Materialize the dispatched tree, and answer with *where the broker put it* — the value every
    /// later phase needs and only this one can produce (see [`VerifiedTree`]).
    async fn phase_fetch(&self, job_id: &str, dispatch: &Dispatch) -> Result<VerifiedTree, Verdict> {
        self.set_state(job_id, JobState::Fetching);
        let req = FetchRequest {
            tenant: dispatch.tenant().to_string(),
            tree_id: dispatch.tree_id.clone(),
            source_url: dispatch.source_url.clone(),
            fetch_token: dispatch.fetch_token.clone(),
        };
        let tree = match tokio::time::timeout(self.config.timeouts.fetch, self.deps.fetcher.fetch(&req)).await {
            Err(_elapsed) => return Err(expiry_verdict(Expiry::Fetch, self.config.timeouts.fetch)),
            // The source never arrived, so we know nothing about the code: `errored`, not `red`.
            Ok(Err(e)) => {
                return Err(Verdict::errored(
                    Reason::Infra,
                    sanitize_summary(&format!("could not fetch the source tree: {e}"), SUMMARY_MAX_CHARS),
                ))
            }
            Ok(Ok(tree)) => tree,
        };

        // A broker that answered with a *different* tree than the one dispatched would send every
        // downstream decision — the plan, the steps, Hull's memo keyed by `tree_id` — off the tree
        // under test. Cheap to check here, and the only place both ids are in hand.
        if !tree.tree_id.eq_ignore_ascii_case(dispatch.tree_id.trim()) {
            tracing::error!(job_id, dispatched = %dispatch.tree_id, materialized = %tree.tree_id, "broker returned a different tree");
            return Err(Verdict::errored(
                Reason::Infra,
                "the fetch broker materialized a different tree than the one dispatched",
            ));
        }
        Ok(tree)
    }

    async fn phase_plan(&self, job_id: &str, tree: &VerifiedTree) -> Result<Vec<StepSpec>, Verdict> {
        self.set_state(job_id, JobState::Planning);
        match self.deps.planner.plan(tree).await {
            Ok(specs) if specs.is_empty() => {
                // "Nothing detectable to run" — design D§4.4. `fold` owns the wording so there is
                // one no_tests message in the system.
                Err(fold(&[], Duration::ZERO).decision().expect("empty fold decides").verdict)
            }
            Ok(specs) => Ok(specs),
            Err(e) => Err(Verdict::errored(
                Reason::Infra,
                sanitize_summary(&format!("could not plan the job: {e}"), SUMMARY_MAX_CHARS),
            )),
        }
    }

    async fn phase_run(
        &self,
        job_id: &str,
        dispatch: &Dispatch,
        tree: &VerifiedTree,
        specs: Vec<StepSpec>,
    ) {
        let now = Instant::now();
        self.with_job_mut(job_id, |job| {
            let _ = job.transition(JobState::Running);
            for (i, spec) in specs.into_iter().enumerate() {
                let mut step = Step::new(new_step_id(i), spec);
                // M1 has no DAG: every step is schedulable at once. `needs` edges arrive with the
                // planner in M2 and become the `pending → ready` gate.
                step.state = StepState::Ready;
                step.ready_at = Some(now);
                job.steps.push(step);
            }
        });

        self.schedule_ready(job_id, dispatch, tree);
        let notify = self.waker(job_id);

        enum Next {
            Decided(Box<Decision>),
            JobTimeout,
            Wait(Option<Instant>),
        }

        loop {
            let next = {
                let mut jobs = self.lock_jobs();
                let Some(job) = jobs.get_mut(job_id) else { return };
                let now = Instant::now();

                // Timeouts first: an expired step becomes `errored`, and the fold below then turns
                // that into an `errored` job with a reason (design D§10.2).
                for (step_id, expiry) in sweep(&mut job.steps, &self.config.timeouts, now) {
                    tracing::warn!(%job_id, %step_id, expiry = expiry.as_str(), "step timed out");
                }

                if now >= job.deadline_at {
                    Next::JobTimeout
                } else {
                    match fold(&job.steps, now.saturating_duration_since(job.created_at)) {
                        Fold::Decided(d) => Next::Decided(Box::new(d)),
                        Fold::Undecided => {
                            let step_deadline = next_step_deadline(&job.steps, &self.config.timeouts);
                            Next::Wait(Some(
                                step_deadline.map_or(job.deadline_at, |d| d.min(job.deadline_at)),
                            ))
                        }
                    }
                }
            };

            match next {
                Next::Decided(d) => {
                    self.cancel_steps(job_id, &d.cancel);
                    self.finish(job_id, d.verdict).await;
                    return;
                }
                Next::JobTimeout => {
                    let in_flight = self
                        .with_job(job_id, |j| {
                            j.steps.iter().filter(|s| s.state.is_in_flight()).map(|s| s.id.clone()).collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    self.cancel_steps(job_id, &in_flight);
                    self.finish(job_id, expiry_verdict(Expiry::Job, self.config.timeouts.job)).await;
                    return;
                }
                Next::Wait(deadline) => {
                    let dur = deadline
                        .map(|d| d.saturating_duration_since(Instant::now()))
                        .unwrap_or(Duration::from_secs(1));
                    tokio::select! {
                        _ = notify.notified() => {}
                        _ = tokio::time::sleep(dur) => {}
                    }
                    // Capacity may have freed up while we waited.
                    self.schedule_ready(job_id, dispatch, tree);
                }
            }
        }
    }

    /// Hand every schedulable step to the fleet.
    ///
    /// `NoCapacity` is **not** a failure — the step keeps its queue position and only the queue-wait
    /// clock can turn the wait into a verdict (design D§4.5: "over cap is a wait, not a failure").
    fn schedule_ready(&self, job_id: &str, dispatch: &Dispatch, tree: &VerifiedTree) {
        let assignments: Vec<(StepId, Assignment)> = self
            .with_job(job_id, |job| {
                job.steps
                    .iter()
                    .filter(|s| s.state == StepState::Ready)
                    .map(|s| {
                        (
                            s.id.clone(),
                            Assignment {
                                job_id: job.id.clone(),
                                step_id: s.id.clone(),
                                step_name: s.spec.name.clone(),
                                // Tenancy travels with the work. The node needs it to scope the
                                // workspace, the cache namespace, and the log key (D§1, D§11) —
                                // derived here once, from the dispatch, rather than re-parsed
                                // `tenant/repo` at each use on the far side.
                                tenant: dispatch.tenant().to_string(),
                                repo: dispatch.repo.clone(),
                                tree_id: dispatch.tree_id.clone(),
                                argv: s.spec.argv.clone(),
                                image: s.spec.image.clone(),
                                tier: self.config.tier,
                                author_class: job.author_class,
                                timeout_secs: s
                                    .spec
                                    .timeout
                                    .unwrap_or(self.config.timeouts.step)
                                    .as_secs(),
                                lease_secs: self.config.lease_ttl.as_secs(),
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();

        for (step_id, assignment) in assignments {
            // Outside the store lock: the fleet is somebody else's process, and blocking every
            // job's bookkeeping on it would be a self-inflicted outage.
            let result = self.deps.node.assign(&assignment, tree);
            let now = Instant::now();
            self.with_job_mut(job_id, |job| {
                let ttl = self.config.lease_ttl;
                let Some(step) = job.step_mut(&step_id) else { return };
                match result {
                    Ok(node_id) => {
                        if step.transition(StepState::Leased).is_ok() {
                            step.node_id = Some(node_id);
                            step.attempt += 1;
                            // The step wall clock is armed here, not at the node's "running"
                            // signal — see timeouts::sweep.
                            step.started_at = Some(now);
                            step.lease_expires_at = Some(now + ttl.max(self.config.timeouts.step));
                        }
                    }
                    Err(NodeError::NoCapacity) => {}
                    Err(e) => {
                        if step.transition(StepState::Errored).is_ok() {
                            step.error_reason = Some(Reason::Infra);
                            step.detail = sanitize_summary(&e.to_string(), SUMMARY_MAX_CHARS);
                            step.finished_at = Some(now);
                        }
                    }
                }
            });
        }
        // No wake here on purpose: the driver calls this and then folds immediately, so notifying
        // itself would hand back a permit and spin the loop instead of sleeping on the deadline.
    }

    fn cancel_steps(&self, job_id: &str, step_ids: &[StepId]) {
        for step_id in step_ids {
            // Revoke the lease and destroy the sandbox (design D§6.6).
            self.deps.node.cancel(job_id, step_id);
            self.with_job_mut(job_id, |job| {
                if let Some(step) = job.step_mut(step_id) {
                    let _ = step.transition(StepState::Skipped);
                }
            });
        }
    }

    fn set_state(&self, job_id: &str, next: JobState) {
        self.with_job_mut(job_id, |job| {
            if let Err(e) = job.transition(next) {
                tracing::error!(%job_id, error = %e, "illegal job transition");
            }
        });
    }

    /// Record the one verdict and hand it to the callback sender.
    async fn finish(&self, job_id: &str, verdict: Verdict) {
        let details_url = self.config.details_base_url.as_ref().map(|base| {
            // Only our own hex job id is appended — nothing from the dispatch, nothing from a job.
            format!("{}/jobs/{}", base.trim_end_matches('/'), job_id)
        });

        let recorded = self
            .with_job_mut(job_id, |job| {
                if job.state.has_verdict() {
                    // One verdict, ever (design D§6.6). A late timeout racing a real result must
                    // not overwrite it.
                    return false;
                }
                let mut v = verdict;
                if let Some(url) = details_url {
                    v = v.with_details_url(url);
                }
                let _ = job.transition(JobState::from_status(v.status));
                tracing::info!(%job_id, status = v.status.as_str(), summary = ?v.summary, "job decided");
                job.verdict = Some(v);
                true
            })
            .unwrap_or(false);

        if recorded {
            self.report(job_id).await;
        }
    }

    /// Deliver (or re-deliver) the recorded verdict. Safe to call more than once — spec §9 makes a
    /// duplicate callback explicitly a re-affirmation.
    async fn report(&self, job_id: &str) {
        // One verdict, but possibly several places that asked for it: work is deduplicated by
        // (repo, tree_id), delivery is not (see `Job::callback_urls`).
        let Some(Some(reqs)) = self.with_job(job_id, |job| {
            job.verdict.clone().map(|verdict| {
                job.callback_urls
                    .iter()
                    .map(|url| CallbackRequest {
                        // Verbatim (spec §5).
                        url: url.clone(),
                        secret: self.config.secret.clone(),
                        verdict: verdict.clone(),
                        job_id: job.id.clone(),
                    })
                    .collect::<Vec<_>>()
            })
        }) else {
            return;
        };

        // Every destination is attempted, and one unreachable Hull must not suppress the others; the
        // job counts as reported if *any* delivery landed, and parked only if they all failed.
        let mut attempts_total = 0;
        let mut any_delivered = false;
        for req in &reqs {
            let outcome = deliver(&*self.deps.transport, req, &self.config.retry).await;
            attempts_total += match &outcome {
                Delivery::Delivered { attempts, .. } | Delivery::Parked { attempts, .. } => *attempts,
            };
            any_delivered |= outcome.is_delivered();
        }
        let outcome_delivered = any_delivered;
        self.with_job_mut(job_id, |job| {
            job.report_attempts += attempts_total;
            let _ = job.transition(if outcome_delivered {
                JobState::Reported
            } else {
                JobState::ReportFailed
            });
        });

        if outcome_delivered {
            // The driver is done with this job; drop its waker so a long-lived process does not
            // accumulate one per job it has ever seen.
            self.wakers.lock().unwrap_or_else(|e| e.into_inner()).remove(job_id);
        }
    }
}

/// One job's pipeline, start to finish. Spawned by [`Control::accept`] so the ack never waits on it.
async fn drive(ctrl: Arc<Control>, job_id: JobId) {
    let Some(dispatch) = ctrl.with_job(&job_id, |j| j.dispatch.clone()) else { return };

    // The broker's answer is the thread the rest of the pipeline hangs from: the planner reads the
    // tree at this path and the fleet materializes a workspace from it (design D§4.4, D§6.2).
    let tree = match ctrl.phase_fetch(&job_id, &dispatch).await {
        Ok(tree) => tree,
        Err(verdict) => {
            ctrl.finish(&job_id, verdict).await;
            return;
        }
    };
    let specs = match ctrl.phase_plan(&job_id, &tree).await {
        Ok(specs) => specs,
        Err(verdict) => {
            ctrl.finish(&job_id, verdict).await;
            return;
        }
    };
    ctrl.phase_run(&job_id, &dispatch, &tree, specs).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{
        dispatch, fast_config, harness, step_report, wait_until, FailingFetcher, HangingFetcher,
        NodeMode, OkFetcher, StaticPlanner, WrongTreeFetcher,
    };
    use hull_ci_proto::{Status, StepOutcome};

    struct Live {
        ctrl: Arc<Control>,
        job_id: JobId,
        node: Arc<crate::testing::RecordingNode>,
        transport: Arc<crate::testing::ScriptedTransport>,
    }

    /// Accept one dispatch against a fake fleet.
    fn start(
        config: ControlConfig,
        fetcher: Arc<dyn Fetcher>,
        planner: Arc<dyn Planner>,
        node_mode: NodeMode,
    ) -> Live {
        let h = harness(config, fetcher, planner, node_mode);
        let accepted = h.control.accept(dispatch("t/r", "tree1"));
        Live { ctrl: h.control, job_id: accepted.job_id, node: h.node, transport: h.transport }
    }

    impl Live {
        async fn steps_leased(&self) -> Vec<StepId> {
            let ok = {
                let ctrl = Arc::clone(&self.ctrl);
                let id = self.job_id.clone();
                wait_until(move || {
                    ctrl.with_job(&id, |j| {
                        !j.steps.is_empty() && j.steps.iter().all(|s| s.state == StepState::Leased)
                    })
                    .unwrap_or(false)
                })
                .await
            };
            assert!(ok, "steps never reached the fleet");
            self.ctrl
                .with_job(&self.job_id, |j| j.steps.iter().map(|s| s.id.clone()).collect())
                .unwrap_or_default()
        }

        async fn settled(&self) -> Verdict {
            let ctrl = Arc::clone(&self.ctrl);
            let id = self.job_id.clone();
            let ok = wait_until(move || {
                matches!(ctrl.job_state(&id), Some(JobState::Reported) | Some(JobState::ReportFailed))
            })
            .await;
            assert!(ok, "job never reported: state {:?}", self.ctrl.job_state(&self.job_id));
            self.ctrl.verdict(&self.job_id).expect("a reported job has a verdict")
        }
    }

    #[tokio::test]
    async fn a_job_whose_steps_all_pass_reports_green_to_the_exact_callback_url() {
        let live = start(fast_config(), Arc::new(OkFetcher), Arc::new(StaticPlanner::steps(2)), NodeMode::Accept);
        let steps = live.steps_leased().await;
        for id in &steps {
            live.ctrl
                .record_step_report(&step_report(&live.job_id, id, StepOutcome::Passed, "ok"), "node-test")
                .expect("the lease holder is believed");
        }

        let verdict = live.settled().await;
        assert_eq!(verdict.status, Status::Green);
        assert_eq!(live.ctrl.job_state(&live.job_id), Some(JobState::Reported));
        let sent = live.transport.seen();
        assert_eq!(sent.len(), 1, "one verdict, delivered once");
        assert_eq!(
            sent[0].url, "https://hull.example/api/repos/t/r/change/21ea/ci-result",
            "spec §5: callback_url verbatim"
        );
        assert_eq!(sent[0].secret.as_deref(), Some("s3cret"), "spec §8: echo the secret");
    }

    #[tokio::test]
    async fn a_failing_step_reports_red_immediately_and_cancels_its_siblings() {
        let live = start(fast_config(), Arc::new(OkFetcher), Arc::new(StaticPlanner::steps(3)), NodeMode::Accept);
        let steps = live.steps_leased().await;
        live.ctrl
            .record_step_report(
                &step_report(&live.job_id, &steps[1], StepOutcome::Failed, "2 of 1240 tests"),
                "node-test",
            )
            .unwrap();

        let verdict = live.settled().await;
        assert_eq!(verdict.status, Status::Red);
        // Design D§6.6: no reason to finish a build whose verdict is determined.
        let cancelled: Vec<String> = live.node.cancelled().into_iter().map(|(_, s)| s).collect();
        assert_eq!(cancelled.len(), 2);
        assert!(cancelled.contains(&steps[0]) && cancelled.contains(&steps[2]));
        assert!(!cancelled.contains(&steps[1]), "the step that decided the job is not cancelled");
    }

    #[tokio::test]
    async fn a_step_that_errors_makes_the_job_errored_not_red() {
        let live = start(fast_config(), Arc::new(OkFetcher), Arc::new(StaticPlanner::steps(1)), NodeMode::Accept);
        let steps = live.steps_leased().await;
        live.ctrl
            .record_step_report(&step_report(&live.job_id, &steps[0], StepOutcome::Errored, "sandbox died"), "node-test")
            .unwrap();

        let verdict = live.settled().await;
        assert_eq!(verdict.status, Status::Errored, "spec §7: infra failures are never red");
        assert_eq!(verdict.reason, Some(Reason::Infra));
    }

    #[tokio::test]
    async fn a_fetch_failure_errors_the_job_before_a_single_step_exists() {
        let live = start(fast_config(), Arc::new(FailingFetcher), Arc::new(StaticPlanner::steps(1)), NodeMode::Accept);
        let verdict = live.settled().await;
        assert_eq!(verdict.status, Status::Errored);
        assert_eq!(verdict.reason, Some(Reason::Infra));
        assert!(live.node.assigned().is_empty(), "nothing may run against an unverified tree");
    }

    #[tokio::test]
    async fn a_fetch_that_never_returns_trips_the_fetch_clock() {
        let mut config = fast_config();
        config.timeouts.fetch = Duration::from_millis(20);
        let live = start(config, Arc::new(HangingFetcher), Arc::new(StaticPlanner::steps(1)), NodeMode::Accept);

        let verdict = live.settled().await;
        assert_eq!(verdict.status, Status::Errored);
        // Design D§10.2's table classes a fetch expiry as `infra`, not `timeout`.
        assert_eq!(verdict.reason, Some(Reason::Infra));
    }

    #[tokio::test]
    async fn the_job_wall_clock_ends_a_job_no_node_ever_answers() {
        // Spec §10: Hull never times a job out, so a job we lose track of hangs forever unless we
        // end it ourselves.
        let mut config = fast_config();
        config.timeouts.job = Duration::from_millis(30);
        let live = start(config, Arc::new(OkFetcher), Arc::new(StaticPlanner::steps(1)), NodeMode::Accept);

        let verdict = live.settled().await;
        assert_eq!(verdict.status, Status::Errored);
        assert_eq!(verdict.reason, Some(Reason::Timeout));
        assert_eq!(live.node.cancelled().len(), 1, "the in-flight step is cancelled, not left running");
    }

    #[tokio::test]
    async fn an_unwired_control_plane_errors_rather_than_claiming_green() {
        let live = start(
            fast_config(),
            Arc::new(crate::seams::UnwiredFetcher),
            Arc::new(StaticPlanner::steps(1)),
            NodeMode::Accept,
        );
        let verdict = live.settled().await;
        assert_eq!(verdict.status, Status::Errored, "errored is not memoized; green would be");
    }

    #[tokio::test]
    async fn a_plan_with_nothing_to_run_is_errored_no_tests() {
        // Design D§4.4 → spec §9.1 reads `no_tests` as *self_attested*, which escalates to a human
        // reviewer instead of auto-approving.
        let live = start(fast_config(), Arc::new(OkFetcher), Arc::new(StaticPlanner::steps(0)), NodeMode::Accept);
        let verdict = live.settled().await;
        assert_eq!(verdict.status, Status::Errored);
        assert_eq!(verdict.reason, Some(Reason::NoTests));
    }

    #[tokio::test]
    async fn the_fleet_is_told_where_the_broker_put_the_tree() {
        // The workspace path is produced by the broker and threaded to the fleet unaltered: nothing
        // downstream re-derives it from the store's layout (seams::VerifiedTree).
        let live = start(fast_config(), Arc::new(OkFetcher), Arc::new(StaticPlanner::steps(1)), NodeMode::Accept);
        live.steps_leased().await;
        let trees = live.node.trees();
        assert_eq!(trees.len(), 1);
        assert_eq!(trees[0].tree_id, "tree1");
        assert_eq!(trees[0].path, std::path::PathBuf::from("/nonexistent/control-plane-never-opens-this"));
    }

    #[tokio::test]
    async fn a_broker_that_materializes_a_different_tree_errors_the_job() {
        // Every downstream decision — the plan, the steps, Hull's memo — is keyed to the dispatched
        // tree. Running a different one would attach a verdict to bytes nobody asked about.
        let live = start(fast_config(), Arc::new(WrongTreeFetcher), Arc::new(StaticPlanner::steps(1)), NodeMode::Accept);
        let verdict = live.settled().await;
        assert_eq!(verdict.status, Status::Errored);
        assert_eq!(verdict.reason, Some(Reason::Infra));
        assert!(live.node.assigned().is_empty(), "nothing runs against a tree we did not ask for");
    }

    #[tokio::test]
    async fn only_the_lease_holder_can_report_a_step() {
        // Design D§10.4: this is what makes "a step may run twice" harmless.
        let live = start(fast_config(), Arc::new(OkFetcher), Arc::new(StaticPlanner::steps(1)), NodeMode::Accept);
        let steps = live.steps_leased().await;
        let report = step_report(&live.job_id, &steps[0], StepOutcome::Passed, "ok");

        assert_eq!(
            live.ctrl.record_step_report(&report, "some-other-node"),
            Err(ReportRejected::NotLeaseHolder)
        );
        assert_eq!(
            live.ctrl.record_step_report(&step_report(&live.job_id, "no-such-step", StepOutcome::Passed, ""), "node-test"),
            Err(ReportRejected::UnknownStep)
        );

        live.ctrl.record_step_report(&report, "node-test").unwrap();
        // A second report for a settled step is dropped rather than overwriting the first.
        assert_eq!(
            live.ctrl.record_step_report(
                &step_report(&live.job_id, &steps[0], StepOutcome::Failed, "late"),
                "node-test"
            ),
            Err(ReportRejected::NotInFlight)
        );
        assert_eq!(live.settled().await.status, Status::Green);
    }

    #[tokio::test]
    async fn a_duplicate_dispatch_for_a_finished_job_re_sends_the_same_verdict() {
        // Spec §9: "a duplicate callback for an already-recorded tree simply re-affirms the same
        // verdict" — and it is how a lost callback heals.
        let live = start(fast_config(), Arc::new(OkFetcher), Arc::new(StaticPlanner::steps(1)), NodeMode::Accept);
        let steps = live.steps_leased().await;
        live.ctrl
            .record_step_report(&step_report(&live.job_id, &steps[0], StepOutcome::Passed, "ok"), "node-test")
            .unwrap();
        let first = live.settled().await;

        let again = live.ctrl.accept(dispatch("t/r", "tree1"));
        assert_eq!(again.job_id, live.job_id);
        assert!(again.duplicate);

        let transport = Arc::clone(&live.transport);
        assert!(wait_until(move || transport.seen().len() == 2).await, "the verdict is re-sent");
        let sent = live.transport.seen();
        assert_eq!(sent[1].url, sent[0].url);
        assert_eq!(sent[1].verdict.status, first.status);
        assert_eq!(live.node.assigned().len(), 1, "a duplicate must not re-run a single step");
    }

    #[tokio::test]
    async fn a_second_change_sharing_a_tree_gets_the_verdict_at_its_own_callback_url() {
        // The premise of tree-keyed memoization is that two changes can share a tree — a rebase, a
        // cherry-pick, a revert of a revert. Each arrives with its OWN callback_url, and spec §9 says
        // Hull's in-flight de-dup is best-effort and in-memory, so a second dispatch for a tree we
        // already know is expected (after a Hull restart, across replicas, or with force).
        //
        // Deduplicating the WORK is right; deduplicating the DELIVERY is not. Reporting only to the
        // first URL leaves the second change unverified forever, waiting on an answer that was
        // delivered somewhere else — and because that change never gets a verdict, nothing about it
        // ever looks broken enough to investigate.
        let live = start(fast_config(), Arc::new(OkFetcher), Arc::new(StaticPlanner::steps(1)), NodeMode::Accept);
        let steps = live.steps_leased().await;
        live.ctrl
            .record_step_report(&step_report(&live.job_id, &steps[0], StepOutcome::Passed, "ok"), "node-test")
            .unwrap();
        live.settled().await;

        // Same repo, same tree, DIFFERENT change — so a different callback_url.
        let mut second = dispatch("t/r", "tree1");
        second.change = "b2b2b2b2b2b2".into();
        second.callback_url = "https://hull.example/api/repos/t/r/change/b2b2/ci-result".into();
        let again = live.ctrl.accept(second.clone());
        assert_eq!(again.job_id, live.job_id, "the work is still deduplicated");

        let transport = Arc::clone(&live.transport);
        assert!(wait_until(move || transport.seen().len() >= 2).await);
        let urls: Vec<String> = live.transport.seen().iter().map(|r| r.url.clone()).collect();
        assert!(
            urls.contains(&second.callback_url),
            "the second change must receive the verdict at its own callback_url; got {urls:?}"
        );
        assert_eq!(live.node.assigned().len(), 1, "and still only one execution");
    }

    #[tokio::test]
    async fn re_dispatching_the_identical_callback_url_does_not_double_deliver() {
        // The counterpart to the above: an ordinary retry of the *same* dispatch must not make us
        // post the same verdict twice to the same place. Delivery is per distinct URL, not per
        // dispatch received.
        let live = start(fast_config(), Arc::new(OkFetcher), Arc::new(StaticPlanner::steps(1)), NodeMode::Accept);
        let steps = live.steps_leased().await;
        live.ctrl
            .record_step_report(&step_report(&live.job_id, &steps[0], StepOutcome::Passed, "ok"), "node-test")
            .unwrap();
        live.settled().await;

        live.ctrl.accept(dispatch("t/r", "tree1"));
        let transport = Arc::clone(&live.transport);
        assert!(wait_until(move || transport.seen().len() == 2).await);
        let urls: Vec<String> = live.transport.seen().iter().map(|r| r.url.clone()).collect();
        assert_eq!(urls[0], urls[1], "the re-report goes to the one known URL, not to a second one");
    }

    #[tokio::test]
    async fn a_step_the_fleet_rejects_errors_the_job_but_no_capacity_only_waits() {
        // Design D§4.5: "over cap is a wait, not a failure."
        let mut config = fast_config();
        config.timeouts.queue_wait = Duration::from_millis(30);
        let live = start(config, Arc::new(OkFetcher), Arc::new(StaticPlanner::steps(1)), NodeMode::NoCapacity);
        let verdict = live.settled().await;
        assert_eq!(verdict.status, Status::Errored);
        assert_eq!(verdict.reason, Some(Reason::Capacity), "a plan limit is not a test failure");

        let live = start(fast_config(), Arc::new(OkFetcher), Arc::new(StaticPlanner::steps(1)), NodeMode::Reject);
        let verdict = live.settled().await;
        assert_eq!(verdict.status, Status::Errored);
        assert_eq!(verdict.reason, Some(Reason::Infra));
    }
}
