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
//!
//! ## One driver per job, one queue for the fleet
//!
//! The drivers are per job, but the fleet is shared, so *which* ready step goes out next cannot be a
//! per-job decision — that is how one tenant's flood takes the whole fleet (design D§4.5). Every
//! driver pass therefore ends in [`Control::pump`]: it reconciles the calling job's steps into the
//! one [`FairQueue`], asks the queue to choose across **all** tenants, and hands the winners to the
//! fleet — including steps belonging to other jobs, whose drivers it then wakes.
//!
//! That is deliberate. A driver that could only dispatch its own steps would leave a granted step
//! sitting until its own job happened to wake, which is precisely the latency the fairness SLO
//! measures. Whichever driver is awake serves the queue; the queue decides whose turn it is.

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
use crate::fairshare::{Depth, FairQueue, FairShare, Grant, JobView, StepView};
use crate::graph;
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
    /// How long a settled job stays in the store so a duplicate dispatch can be re-reported from it
    /// (design D§4.1) before it is evicted.
    ///
    /// This is the only thing bounding the store's size over time. Longer means more duplicates
    /// answered without re-running; shorter means less memory. It is not a correctness knob — after
    /// eviction a duplicate simply re-runs, and Hull owns the real memo (spec §9).
    pub job_retention: Duration,
    /// Hard ceiling on jobs held in memory. Settled jobs are evicted oldest-first to meet it; live
    /// jobs never are, so this can be exceeded by a burst of concurrent work rather than by history.
    pub max_jobs: usize,
    /// How the fleet is divided between tenants: weights, plan quotas, and priority classes
    /// (design D§4.5). See [`crate::fairshare`].
    pub fair_share: FairShare,
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
            // An hour comfortably outlaps the callback retry budget, so a job cannot be evicted while
            // its own delivery is still being attempted.
            job_retention: Duration::from_secs(60 * 60),
            max_jobs: 10_000,
            fair_share: FairShare::default(),
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
    /// The one multi-tenant scheduler (design D§4.5). Shared by every driver, because a per-job
    /// queue cannot be fair about a shared fleet.
    ///
    /// **Lock order is always `jobs` then `queue`.** The scheduler's accounting is derived from the
    /// job store, so it is always the inner lock; nothing may take it first and then reach for a job.
    queue: Mutex<FairQueue>,
    /// Where the broker put each running job's tree, so any driver can build an [`Assignment`] for a
    /// step the scheduler granted — including one belonging to a job it is not itself driving.
    trees: Mutex<HashMap<JobId, VerifiedTree>>,
    /// One waker per live job, so a step report wakes its driver instead of the driver polling.
    wakers: Mutex<HashMap<JobId, Arc<Notify>>>,
}

impl Control {
    pub fn new(config: ControlConfig, deps: Deps) -> Arc<Self> {
        let queue = FairQueue::new(config.fair_share.clone());
        Arc::new(Control {
            config,
            deps,
            jobs: Mutex::new(JobStore::new()),
            queue: Mutex::new(queue),
            trees: Mutex::new(HashMap::new()),
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
            let now = Instant::now();
            let mut jobs = self.lock_jobs();
            // Amortized retention: eviction pressure is applied where new work arrives, so the store
            // is bounded without a background task to own, supervise, and shut down. Cheap — it is a
            // scan of settled jobs under a lock we are already holding — and it runs before `admit`
            // so a duplicate of a just-evicted tree is treated as new rather than half-found.
            let evicted = jobs.evict(now, self.config.job_retention, self.config.max_jobs);
            if evicted > 0 {
                tracing::debug!(evicted, remaining = jobs.len(), "evicted settled jobs");
            }
            jobs.admit(dispatch, author_class, now, self.config.timeouts.job)
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

    async fn phase_run(&self, job_id: &str, tree: &VerifiedTree, specs: Vec<StepSpec>) {
        // Published before the first step is even `pending`, because the scheduler may hand this
        // job's work to a node from *another* job's driver, and that driver needs to know where the
        // broker put this tree (see [`Control::pump`]).
        self.trees
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(job_id.to_string(), tree.clone());

        self.with_job_mut(job_id, |job| {
            let _ = job.transition(JobState::Running);
            for (i, spec) in specs.into_iter().enumerate() {
                // Every step enters `pending`. Which of them are schedulable *now* and which are
                // waiting on an edge is the graph's answer, not this loop's (design D§4.3), and the
                // driver below asks it on every pass — including the first, so a plan with no `needs`
                // at all is promoted wholesale before anything else happens.
                job.steps.push(Step::new(new_step_id(i), spec));
            }
        });

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

                // Then the graph: a step that just finished may have unblocked its dependents, or —
                // if it failed or errored — made them unrunnable. Both answers have to be in the
                // steps *before* the fold, or a partly-skipped job would never reach a verdict
                // (design D§6.5).
                for (step_id, advance) in graph::advance(&mut job.steps, now) {
                    tracing::debug!(%job_id, %step_id, ?advance, "step advanced by the graph");
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
                    // Whatever the graph just unblocked goes out **now**, before we sleep. Waiting
                    // for the next report to schedule it would turn every dependency edge into a
                    // round trip and serialize a pipeline that was written to fan out (D§6.5). This
                    // is also the retry for a step the fleet had no capacity for last pass, and the
                    // pass on which another tenant's freed capacity is handed on.
                    if self.pump(Some(job_id)) {
                        // Steps changed hands, so the deadline computed above is stale — re-fold
                        // instead of sleeping on it. Bounded: a pass only reports a change when it
                        // moved a step out of `ready`, and no step returns there on its own.
                        continue;
                    }
                    let dur = deadline
                        .map(|d| d.saturating_duration_since(Instant::now()))
                        .unwrap_or(Duration::from_secs(1));
                    tokio::select! {
                        _ = notify.notified() => {}
                        _ = tokio::time::sleep(dur) => {}
                    }
                }
            }
        }
    }

    // ── The multi-tenant scheduler (design D§4.5) ────────────────────────────────────────────────

    /// One pass of the scheduler: reconcile, choose, dispatch.
    ///
    /// `on_behalf_of` is the job whose driver is calling, and the only job whose steps are read back
    /// into the queue on this pass — every other job's state changes are reconciled by its own
    /// driver, which its own events wake. What is *not* per job is the choosing: [`FairQueue`] picks
    /// across every tenant, so this may dispatch — and then wake — jobs the caller has never heard
    /// of. That is the point of a shared fleet (see the module docs).
    ///
    /// Independent DAG steps still go out together (design D§6.5) whenever the plan quotas allow;
    /// what the scheduler adds is that a *neighbour's* first step is not behind all of them.
    ///
    /// `NoCapacity` is **not** a failure: the step goes back on the queue and only the queue-wait
    /// clock can turn the wait into a verdict (design D§4.5, "over cap is a wait, not a failure").
    ///
    /// Returns whether a step of `on_behalf_of` left `ready`, which tells the caller its deadline is
    /// stale and it should fold again rather than sleep.
    fn pump(&self, on_behalf_of: Option<&str>) -> bool {
        let now = Instant::now();
        let grants = {
            let jobs = self.lock_jobs();
            let mut queue = self.lock_queue();
            if let Some(job_id) = on_behalf_of {
                if let Some(job) = jobs.get(job_id) {
                    queue.reconcile(&job_view(job, &self.config.fair_share), now);
                }
            }
            queue.select(now)
        };

        let mut moved_here = false;
        let mut woken: Vec<JobId> = Vec::new();
        for grant in grants {
            let Some((assignment, tree)) = self.assignment_for(&grant) else {
                // The job settled, or was evicted, between the grant and now. Hand its slot back
                // rather than leaving the tenant paying for work that will never run.
                self.lock_queue().release(&grant.job_id, &grant.step_id, now);
                continue;
            };
            // Outside the store lock: the fleet is somebody else's process, and blocking every
            // job's bookkeeping on it would be a self-inflicted outage.
            let result = self.deps.node.assign(&assignment, &tree);
            let moved = self.settle_assignment(&grant, &assignment, result);
            if !moved {
                continue;
            }
            if on_behalf_of == Some(grant.job_id.as_str()) {
                moved_here = true;
            } else if !woken.contains(&grant.job_id) {
                woken.push(grant.job_id.clone());
            }
        }

        // Someone else's driver may be asleep on a deadline while we hand its step to a node; it has
        // to fold. No wake for the caller on purpose — it folds immediately after this returns, so
        // notifying itself would hand back a permit and spin the loop instead of sleeping.
        for job_id in woken {
            self.wake(&job_id);
        }
        moved_here
    }

    /// Apply what the fleet said about one granted step. Returns whether the step left `ready`.
    fn settle_assignment(
        &self,
        grant: &Grant,
        assignment: &Assignment,
        result: Result<String, NodeError>,
    ) -> bool {
        let now = Instant::now();
        if matches!(result, Err(NodeError::NoCapacity)) {
            // The fleet is full. Back on the queue at the tail of its class, still holding the
            // tenant's place — a plan limit and a full fleet are both waits, not failures.
            self.lock_queue().requeue(&grant.job_id, &grant.step_id, &assignment.step_name, now);
            return false;
        }
        let rejected = result.is_err();

        let moved = self
            .with_job_mut(&grant.job_id, |job| {
                let ttl = self.config.lease_ttl;
                let Some(step) = job.step_mut(&grant.step_id) else { return false };
                match result {
                    Ok(node_id) => {
                        if step.transition(StepState::Leased).is_err() {
                            return false;
                        }
                        step.node_id = Some(node_id);
                        step.attempt += 1;
                        // The step wall clock is armed here, not at the node's "running" signal —
                        // see timeouts::sweep.
                        step.started_at = Some(now);
                        step.lease_expires_at = Some(now + ttl.max(self.config.timeouts.step));
                        true
                    }
                    Err(e) => {
                        if step.transition(StepState::Errored).is_err() {
                            return false;
                        }
                        step.error_reason = Some(Reason::Infra);
                        step.detail = sanitize_summary(&e.to_string(), SUMMARY_MAX_CHARS);
                        step.finished_at = Some(now);
                        true
                    }
                }
            })
            .unwrap_or(false);

        // A rejection ends the step here, and a step that would not move was cancelled or timed out
        // while we were talking to the fleet. Either way the scheduler stops accounting for it, and
        // its tenant gets the slot back.
        if rejected || !moved {
            self.lock_queue().release(&grant.job_id, &grant.step_id, now);
        }
        moved
    }

    /// What the fleet needs to run one granted step, or `None` if the job is no longer runnable.
    fn assignment_for(&self, grant: &Grant) -> Option<(Assignment, VerifiedTree)> {
        let tree = self.trees.lock().unwrap_or_else(|e| e.into_inner()).get(&grant.job_id).cloned()?;
        let assignment = self.with_job(&grant.job_id, |job| {
            let step = job.step(&grant.step_id)?;
            Some(Assignment {
                job_id: job.id.clone(),
                step_id: step.id.clone(),
                step_name: step.spec.name.clone(),
                // Tenancy travels with the work. The node needs it to scope the workspace, the
                // cache namespace, and the log key (D§1, D§11) — derived here once, from the
                // dispatch, rather than re-parsed out of `tenant/repo` at each use on the far side.
                tenant: job.dispatch.tenant().to_string(),
                repo: job.dispatch.repo.clone(),
                tree_id: job.dispatch.tree_id.clone(),
                argv: step.spec.argv.clone(),
                image: step.spec.image.clone(),
                tier: self.config.tier,
                author_class: job.author_class,
                timeout_secs: step.spec.timeout.unwrap_or(self.config.timeouts.step).as_secs(),
                lease_secs: self.config.lease_ttl.as_secs(),
            })
        })??;
        Some((assignment, tree))
    }

    /// Give back everything a finished job was holding, and offer the freed capacity to whoever is
    /// next in the fair order.
    ///
    /// Called once the driver is done rather than left to the retention sweep: a tenant's quota is
    /// the scarcest thing in the system under load, and holding a settled job's slots until its
    /// record is evicted an hour later would quietly shrink every plan.
    fn retire(&self, job_id: &str) {
        let now = Instant::now();
        self.trees.lock().unwrap_or_else(|e| e.into_inner()).remove(job_id);
        self.lock_queue().forget_job(job_id, now);
        self.pump(None);
    }

    /// How much work one tenant has queued and running. Only ever its own — design D§1's
    /// scheduler-side-channel row (see [`FairQueue::depth`]).
    pub fn queue_depth(&self, tenant: &str) -> Depth {
        self.lock_queue().depth(tenant)
    }

    fn lock_queue(&self) -> std::sync::MutexGuard<'_, FairQueue> {
        self.queue.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn cancel_steps(&self, job_id: &str, step_ids: &[StepId]) {
        for step_id in step_ids {
            // Only tell the fleet about steps it was actually given. A `Pending` step behind a
            // cancelled branch has no lease and no sandbox, so a cancel for it is a message about
            // work the node has never heard of — harmless, but it makes `cancelled()` mean "we sent
            // a cancel" rather than "a sandbox was destroyed", and that is the sort of imprecision
            // that later gets read as a metric.
            let in_flight = self
                .with_job(job_id, |job| {
                    job.step(step_id)
                        .map(|s| matches!(s.state, StepState::Leased | StepState::Running))
                        .unwrap_or(false)
                })
                .unwrap_or(false);
            if in_flight {
                // Revoke the lease and destroy the sandbox (design D§6.6).
                self.deps.node.cancel(job_id, step_id);
            }
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
    ctrl.phase_run(&job_id, &tree, specs).await;
    // However the run ended — verdict, timeout, or a job that vanished under us — the quota it was
    // holding belongs to its tenant again, and to whoever the fair order says is next.
    ctrl.retire(&job_id);
}

/// One job's steps as the scheduler needs to see them (design D§4.5).
///
/// The priority class is derived here, on every pass, rather than stamped on the job at admission:
/// it is policy, and a control plane that re-read its policy only at accept time would keep
/// scheduling a re-classified tenant's work under the old rule for as long as the job lived.
fn job_view(job: &Job, cfg: &FairShare) -> JobView {
    JobView {
        job_id: job.id.clone(),
        // The tenant half of `repo`, which is the isolation boundary (design D§1) and the unit every
        // quota and every virtual clock below is kept per.
        tenant: job.dispatch.tenant().to_string(),
        priority: cfg.prioritizer.priority(&job.dispatch),
        steps: job
            .steps
            .iter()
            .map(|s| StepView {
                step_id: s.id.clone(),
                name: s.spec.name.clone(),
                state: s.state,
                started_at: s.started_at,
                finished_at: s.finished_at,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fairshare::TenantPlan;
    use crate::testing::{
        dispatch, fast_config, harness, spec, stays_false, step_report, wait_until, BackgroundRepo,
        FailingFetcher, HangingFetcher, NodeMode, OkFetcher, PerTreePlanner, StaticPlanner,
        WrongTreeFetcher,
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

        // ── DAG helpers. Steps are addressed by pipeline name, the way `needs` addresses them. ──

        fn step_id(&self, name: &str) -> StepId {
            self.ctrl
                .with_job(&self.job_id, |j| {
                    j.steps.iter().find(|s| s.spec.name == name).map(|s| s.id.clone())
                })
                .flatten()
                .unwrap_or_else(|| panic!("no step named {name}"))
        }

        /// `None` until the driver has fetched, planned, and built the steps — which every poll
        /// below has to tolerate, because that all happens on a spawned task.
        fn maybe_state(&self, name: &str) -> Option<StepState> {
            self.ctrl
                .with_job(&self.job_id, |j| {
                    j.steps.iter().find(|s| s.spec.name == name).map(|s| s.state)
                })
                .flatten()
        }

        fn state_of(&self, name: &str) -> StepState {
            self.maybe_state(name).unwrap_or_else(|| panic!("no step named {name}"))
        }

        /// What the fleet was handed, in the order it was handed over.
        fn assigned_names(&self) -> Vec<String> {
            self.node.assigned().into_iter().map(|a| a.step_name).collect()
        }

        async fn wait_leased(&self, name: &str) -> bool {
            wait_until(|| self.maybe_state(name) == Some(StepState::Leased)).await
        }

        fn report(&self, name: &str, outcome: StepOutcome) {
            let id = self.step_id(name);
            self.ctrl
                .record_step_report(&step_report(&self.job_id, &id, outcome, "ok"), "node-test")
                .expect("the lease holder is believed");
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
    async fn only_steps_the_fleet_actually_holds_are_cancelled() {
        // `a → b`, and `a` fails. `b` was never assigned — it was still Pending behind the edge — so
        // there is no lease to revoke and no sandbox to destroy. Sending a cancel for it would make
        // `cancelled()` mean "we sent a message" rather than "a sandbox died", which is the kind of
        // imprecision that later gets read as a metric.
        let plan = StaticPlanner::graph(&[("a", &[]), ("b", &["a"])]);
        let live = start(fast_config(), Arc::new(OkFetcher), Arc::new(plan), NodeMode::Accept);
        assert!(live.wait_leased("a").await, "the root should reach the fleet");
        assert_eq!(live.state_of("b"), StepState::Pending, "`b` waits behind the edge");

        live.report("a", StepOutcome::Failed);
        live.settled().await;

        assert!(
            live.node.cancelled().is_empty(),
            "nothing was in flight to cancel; got {:?}",
            live.node.cancelled()
        );
        assert_eq!(live.assigned_names(), ["a"], "and `b` never ran");
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

    // ── The DAG (design D§6.5) ───────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_diamond_runs_both_branches_at_once_and_joins_only_when_both_are_in() {
        // The claim design D§6.5 makes is about wall clock: "a 4-step pipeline with one dependency
        // edge is 2 steps deep, not 4." A scheduler that respected `needs` but released one step at a
        // time would satisfy every ordering assertion below and still be wrong, so the load-bearing
        // assertion is that b and c are leased *simultaneously*.
        let live = start(
            fast_config(),
            Arc::new(OkFetcher),
            Arc::new(StaticPlanner::graph(&[("a", &[]), ("b", &["a"]), ("c", &["a"]), ("d", &["b", "c"])])),
            NodeMode::Accept,
        );

        assert!(live.wait_leased("a").await);
        assert_eq!(live.assigned_names(), vec!["a"], "nothing downstream may start before its edge");
        live.report("a", StepOutcome::Passed);

        assert!(live.wait_leased("b").await);
        assert!(live.wait_leased("c").await);
        assert_eq!(live.state_of("b"), StepState::Leased, "both branches are in flight together");
        assert_eq!(live.state_of("c"), StepState::Leased);
        assert_eq!(live.state_of("d"), StepState::Pending, "the join has not been reached");

        live.report("b", StepOutcome::Passed);
        assert!(
            stays_false(|| live.assigned_names().iter().any(|n| n == "d")).await,
            "a join waits for every edge, not for the first one to arrive"
        );

        live.report("c", StepOutcome::Passed);
        assert!(live.wait_leased("d").await);
        live.report("d", StepOutcome::Passed);
        assert_eq!(live.settled().await.status, Status::Green);
    }

    #[tokio::test]
    async fn a_failed_root_skips_everything_behind_it_and_the_job_is_red() {
        // Two things at once, because they are the same bug: a dependent that stayed `pending` would
        // never run *and* would keep the job from ever folding (spec §10 — Hull will not time it out
        // for us). And the verdict is `red`: the root genuinely failed, which is a fact about the
        // code, not about us.
        let live = start(
            fast_config(),
            Arc::new(OkFetcher),
            Arc::new(StaticPlanner::graph(&[("a", &[]), ("b", &["a"]), ("c", &["b"])])),
            NodeMode::Accept,
        );
        assert!(live.wait_leased("a").await);
        live.report("a", StepOutcome::Failed);

        let verdict = live.settled().await;
        assert_eq!(verdict.status, Status::Red, "a real failure, not an infrastructure one");
        assert_eq!(live.state_of("b"), StepState::Skipped, "a blocked step finishes, it does not wait");
        assert_eq!(live.state_of("c"), StepState::Skipped, "and the skip cascades down the chain");
        assert_eq!(live.assigned_names(), vec!["a"], "nothing behind a failure is ever handed to a node");
    }

    #[tokio::test]
    async fn a_tolerated_failure_still_releases_the_steps_behind_it() {
        // Design D§6.6: `continue_on_error` says this failure does not decide the job. It must not
        // decide the sub-graph underneath it either — a lint step that is allowed to fail and yet
        // silently cancels the test suite would be far worse than no `continue_on_error` at all.
        let live = start(
            fast_config(),
            Arc::new(OkFetcher),
            Arc::new(StaticPlanner(vec![spec("lint", &[]).continue_on_error(), spec("test", &["lint"])])),
            NodeMode::Accept,
        );
        assert!(live.wait_leased("lint").await);
        live.report("lint", StepOutcome::Failed);

        assert!(live.wait_leased("test").await, "the dependent runs despite the tolerated failure");
        live.report("test", StepOutcome::Passed);

        let verdict = live.settled().await;
        assert_eq!(verdict.status, Status::Green);
        assert!(
            verdict.summary.as_deref().unwrap_or_default().contains("tolerated"),
            "tolerated is not invisible"
        );
    }

    #[tokio::test]
    async fn fail_fast_cancels_the_other_branch_without_waiting_for_it_to_answer() {
        // Design D§6.6: no reason to finish a build whose verdict is determined. `b` never reports at
        // all here — if the driver waited for the graph to drain, this test would hang until the job
        // wall clock rather than assert.
        let live = start(
            fast_config(),
            Arc::new(OkFetcher),
            Arc::new(StaticPlanner::graph(&[("a", &[]), ("b", &[]), ("a2", &["a"]), ("b2", &["b"])])),
            NodeMode::Accept,
        );
        assert!(live.wait_leased("a").await);
        assert!(live.wait_leased("b").await);
        live.report("a", StepOutcome::Failed);

        let verdict = live.settled().await;
        assert_eq!(verdict.status, Status::Red);
        let cancelled: Vec<String> = live.node.cancelled().into_iter().map(|(_, s)| s).collect();
        assert!(cancelled.contains(&live.step_id("b")), "the in-flight sibling's sandbox is destroyed");
        assert_eq!(live.state_of("b"), StepState::Skipped);
        assert_eq!(live.state_of("a2"), StepState::Skipped, "and the work behind the failure is dropped");
        assert_eq!(live.state_of("b2"), StepState::Skipped, "as is the work behind the cancelled branch");
        assert_eq!(live.transport.seen().len(), 1, "one verdict, reported once");
    }

    #[tokio::test]
    async fn a_late_report_from_a_cancelled_step_cannot_flip_a_decided_verdict() {
        // Design D§10.4 in the direction that matters most: a `passed` arriving after we gave up
        // would turn an `errored` job green, and Hull memoizes green (spec §7) — an outage would
        // launder itself into a permanent pass for that tree. The existing lease/in-flight guard is
        // what stops it, and cancellation is exactly the case that takes a step out of flight while a
        // node is still working on it.
        let mut config = fast_config();
        config.timeouts.job = Duration::from_millis(30);
        let live = start(
            config,
            Arc::new(OkFetcher),
            Arc::new(StaticPlanner::graph(&[("a", &[]), ("b", &["a"])])),
            NodeMode::Accept,
        );

        let verdict = live.settled().await;
        assert_eq!(verdict.status, Status::Errored);
        assert_eq!(verdict.reason, Some(Reason::Timeout));

        let late = step_report(&live.job_id, &live.step_id("a"), StepOutcome::Passed, "finished late");
        assert_eq!(live.ctrl.record_step_report(&late, "node-test"), Err(ReportRejected::NotInFlight));
        assert_eq!(
            live.ctrl.verdict(&live.job_id).map(|v| v.status),
            Some(Status::Errored),
            "the one verdict stands"
        );
        assert_eq!(live.transport.seen().len(), 1, "and it is not re-decided or re-sent");
    }

    #[tokio::test]
    async fn a_chain_never_runs_ahead_of_itself() {
        let names = ["a", "b", "c", "d", "e"];
        let edges: Vec<(&str, &[&str])> = vec![
            ("a", &[]),
            ("b", &["a"]),
            ("c", &["b"]),
            ("d", &["c"]),
            ("e", &["d"]),
        ];
        let live = start(
            fast_config(),
            Arc::new(OkFetcher),
            Arc::new(StaticPlanner::graph(&edges)),
            NodeMode::Accept,
        );

        for (i, name) in names.iter().enumerate() {
            assert!(live.wait_leased(name).await, "{name} never reached the fleet");
            assert_eq!(live.assigned_names(), names[..=i], "the chain is strictly ordered");
            live.report(name, StepOutcome::Passed);
        }
        assert_eq!(live.settled().await.status, Status::Green);
    }

    #[tokio::test]
    async fn a_plan_whose_edges_cannot_be_satisfied_errors_instead_of_hanging() {
        // The planner promises an acyclic graph with no dangling edges (design D§4.4), so this is a
        // guard against *our* bug, not a user's. It earns its place because the failure mode without
        // it is silence: spec §10 says Hull never times a job out, so the change would sit
        // unverified until a human noticed.
        let live = start(
            fast_config(),
            Arc::new(OkFetcher),
            Arc::new(StaticPlanner::graph(&[("a", &["ghost"])])),
            NodeMode::Accept,
        );
        let verdict = live.settled().await;
        assert_eq!(verdict.status, Status::Errored, "never red — we learned nothing about the code");
        assert_eq!(verdict.reason, Some(Reason::Infra));
        assert!(live.node.assigned().is_empty());
    }

    // ── Fair share and admission (design D§4.5) ──────────────────────────────────────────────────

    /// The step one job currently holds a lease on.
    fn leased_step(ctrl: &Control, job_id: &str) -> Option<StepId> {
        ctrl.with_job(job_id, |j| {
            j.steps.iter().find(|s| s.state == StepState::Leased).map(|s| s.id.clone())
        })
        .flatten()
    }

    #[tokio::test]
    async fn a_flooding_tenant_does_not_delay_a_neighbours_step() {
        // The §1 fairness SLO, in the only form a test can hold it: p99 is not measurable here, but
        // the *ordering* that produces it is. `flood` has six steps queued against a fleet with one
        // slot; `solo` arrives afterwards with one. A first-come scheduler hands `solo` the seventh
        // slot it ever frees. The fair queue hands it the second, because `flood` only ever advances
        // its own virtual clock (design D§4.5).
        let mut config = fast_config();
        config.fair_share.fleet_slots = Some(1);
        let h = harness(
            config,
            Arc::new(OkFetcher),
            Arc::new(PerTreePlanner::new(&[("flood", 6), ("solo", 1)])),
            NodeMode::Accept,
        );

        let flood = h.control.accept(dispatch("flood/api", "flood"));
        let node = Arc::clone(&h.node);
        assert!(wait_until(move || node.assigned().len() == 1).await, "the flood takes the one slot");

        // Wait for the neighbour's step to actually be *in* the queue, so this is a test about the
        // scheduler's choice and not about which driver happened to wake first.
        h.control.accept(dispatch("solo/api", "solo"));
        let ctrl = Arc::clone(&h.control);
        assert!(wait_until(move || ctrl.queue_depth("solo").queued == 1).await, "solo is waiting");
        assert_eq!(h.control.queue_depth("flood").queued, 5, "and so are five of the flood's");
        let node = Arc::clone(&h.node);
        assert!(
            stays_false(move || node.assigned().len() > 1).await,
            "nothing more goes out while the fleet is full"
        );

        // One slot comes free. It is the neighbour's turn, not the flood's second step.
        let running = leased_step(&h.control, &flood.job_id).expect("a leased step");
        h.control
            .record_step_report(&step_report(&flood.job_id, &running, StepOutcome::Passed, "ok"), "node-test")
            .unwrap();

        let node = Arc::clone(&h.node);
        assert!(wait_until(move || node.assigned().len() == 2).await, "the freed slot is used");
        assert_eq!(
            h.node.assigned()[1].tenant,
            "solo",
            "the neighbour goes second, not behind five more of the flood's steps"
        );
    }

    #[tokio::test]
    async fn steps_over_a_tenants_concurrency_cap_stay_queued_rather_than_failing() {
        // Design D§4.5: "a step is admitted to running only if both [caps] are under cap; otherwise
        // it stays queued." The failure this guards against is the tempting one — treating a plan
        // limit as a rejection — which would turn "you are on the small plan" into a red build.
        let mut config = fast_config();
        config.fair_share.default_plan =
            TenantPlan { max_running_steps: 1, ..TenantPlan::default() };
        let live = start(config, Arc::new(OkFetcher), Arc::new(StaticPlanner::steps(3)), NodeMode::Accept);

        assert!(live.wait_leased("step0").await);
        let node = Arc::clone(&live.node);
        assert!(stays_false(move || node.assigned().len() > 1).await, "one at a time, by plan");
        assert_eq!(live.state_of("step1"), StepState::Ready, "queued, not errored");
        assert_eq!(live.state_of("step2"), StepState::Ready);
        assert_eq!(live.ctrl.queue_depth("t"), crate::fairshare::Depth { queued: 2, running: 1 });

        // And the cap is a queue, not a ceiling on the job: each step goes as the last one lands.
        for name in ["step0", "step1", "step2"] {
            assert!(live.wait_leased(name).await, "{name} never got its turn");
            live.report(name, StepOutcome::Passed);
        }
        assert_eq!(live.settled().await.status, Status::Green);
        assert_eq!(live.assigned_names(), ["step0", "step1", "step2"]);
    }

    #[tokio::test]
    async fn a_plan_limit_becomes_a_verdict_only_when_the_queue_wait_clock_fires() {
        // The other half of "a wait, not a failure": the wait is not infinite either. A tenant with
        // no node-minutes left never gets admitted, and after the queue-wait clock (design D§10.2)
        // the step is `errored` with `reason: capacity` — never `red`, because the code did not
        // fail, the tenant ran out of plan.
        let mut config = fast_config();
        config.timeouts.queue_wait = Duration::from_millis(40);
        config.fair_share.default_plan =
            TenantPlan { node_minutes_per_hour: 0.0, ..TenantPlan::default() };
        let live = start(config, Arc::new(OkFetcher), Arc::new(StaticPlanner::steps(1)), NodeMode::Accept);

        let verdict = live.settled().await;
        assert_eq!(verdict.status, Status::Errored);
        assert_eq!(verdict.reason, Some(Reason::Capacity), "a plan limit is not a test failure");
        assert!(live.node.assigned().is_empty(), "and the fleet was never asked to run it");
    }

    #[tokio::test]
    async fn an_interactive_step_preempts_its_own_tenants_background_work() {
        // Design D§4.5's within-tenant order, end to end through the [`Prioritizer`] seam. The
        // nightly job is queued first and has work left; the human's click still goes next. Both
        // jobs are the *same tenant*, which is the only place priority is allowed to matter.
        let mut config = fast_config();
        config.fair_share.fleet_slots = Some(1);
        config.fair_share.prioritizer = Arc::new(BackgroundRepo("nightly"));
        let h = harness(
            config,
            Arc::new(OkFetcher),
            Arc::new(PerTreePlanner::new(&[("nightly", 3), ("click", 1)])),
            NodeMode::Accept,
        );

        let nightly = h.control.accept(dispatch("acme/nightly", "nightly"));
        let node = Arc::clone(&h.node);
        assert!(wait_until(move || node.assigned().len() == 1).await);

        h.control.accept(dispatch("acme/api", "click"));
        let ctrl = Arc::clone(&h.control);
        assert!(wait_until(move || ctrl.queue_depth("acme").queued == 3).await, "2 nightly + 1 click");

        let running = leased_step(&h.control, &nightly.job_id).expect("a leased step");
        h.control
            .record_step_report(&step_report(&nightly.job_id, &running, StepOutcome::Passed, "ok"), "node-test")
            .unwrap();

        let node = Arc::clone(&h.node);
        assert!(wait_until(move || node.assigned().len() == 2).await);
        assert_eq!(
            h.node.assigned()[1].repo, "acme/api",
            "someone is watching a spinner; the nightly's remaining steps wait"
        );
    }
}
