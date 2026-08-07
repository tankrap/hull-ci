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
use crate::callback::{
    deliver_reporting, CallbackRequest, CallbackTransport, Delivery, DeliveryProgress, RetryPolicy,
};
use crate::fairshare::{Admission, Depth, FairQueue, FairShare, Grant, JobView, StepView};
use crate::graph;
use crate::ids::new_step_id;
use crate::journal::{now_unix, JobIntent, Journal, JournalError};
use crate::memo::{plan_step_keys, JobKeyContext, MemoConfig, MemoOutcome, StepKey};
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
    /// How many parked verdicts one [`accept`](Control::accept) may hand back to the callback sender
    /// (see `Control::drain_undelivered`).
    ///
    /// A ceiling on the *burst*, not on the rate: a thousand jobs parked against a Hull that is still
    /// down must not become a thousand simultaneous POSTs the moment one dispatch arrives. The
    /// per-job [`redeliver_interval`](Self::redeliver_interval) is what bounds the sustained rate.
    pub redeliver_max_per_accept: usize,
    /// The shortest gap between two redelivery runs **for the same job**.
    ///
    /// Dispatches arrive at machine rates; without this, one busy repo would turn every parked
    /// verdict into a retry per dispatch. Measured from the end of the previous run
    /// ([`Job::last_delivery_at`](crate::model::Job::last_delivery_at)), so a run that spends its
    /// whole retry budget is followed by a real pause rather than an immediate re-run.
    pub redeliver_interval: Duration,
    /// How the fleet is divided between tenants: weights, plan quotas, and priority classes
    /// (design D§4.5). See [`crate::fairshare`].
    pub fair_share: FairShare,
    /// Step-level memoization — design D§6.1, layer 2. See [`crate::memo`].
    ///
    /// **Disabled by default**, because its default digester refuses every glob. A deployment that
    /// has not wired one behaves exactly as it did before layer 2 existed: every step runs.
    pub memo: MemoConfig,
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
            // Two, not one: after Hull comes back the parked set has to *shrink*, and a drain of one
            // per dispatch can only keep pace with the dispatch rate rather than eat into a backlog.
            // Two, not twenty: each one is a full retry run against a Hull that may still be down.
            redeliver_max_per_accept: 2,
            // A minute. Long enough that a burst of dispatches cannot become a burst of retries
            // against an unwell Hull, and far shorter than the alternative it replaces — which was a
            // process restart. Comfortably under the default retry budget too, so the pause between
            // runs is never the thing that dominates recovery time.
            redeliver_interval: Duration::from_secs(60),
            fair_share: FairShare::default(),
            memo: MemoConfig::default(),
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
    /// The durable outbox of dispatches we owe an answer for ([`crate::journal`]).
    ///
    /// A seam like the others, and for the same reason: this crate opens no file (spec §14.1). The
    /// default is [`NoJournal`](crate::journal::NoJournal), which is the behaviour every deployment
    /// had before the journal existed — a restart strands in-flight jobs — so wiring a real one is an
    /// operator's decision rather than a new failure mode nobody asked for.
    pub journal: Arc<dyn Journal>,
}

/// What the ingest handler answers with.
#[derive(Debug, Clone)]
pub struct Accepted {
    pub job_id: JobId,
    /// True when `(repo, tree_id)` was already known — attached to a live job, or re-reported from a
    /// finished one (spec §9).
    pub duplicate: bool,
}

/// Why a dispatch was **not** accepted.
///
/// One variant, and it is the only one that can exist here: everything else a dispatch can be wrong
/// about is decided in [`crate::ingest`] before this point. This is the failure of our own storage,
/// which is why it becomes a 503 (try us again) rather than a 4xx (you are wrong).
#[derive(Debug, thiserror::Error)]
pub enum AcceptError {
    /// The write-ahead journal refused the entry, so this job would not survive a restart.
    ///
    /// **We do not ack.** Spec §5 makes a 2xx mean *accepted* — Hull tells the user "dispatched" and
    /// stops caring, and spec §10 makes clear it never polls us and never times the job out. So an ack
    /// for a job we can lose does not degrade to "slow"; it degrades to a tree Hull marks in-flight
    /// and never clears, recoverable only by a human clicking force-rerun. A visible failed dispatch
    /// is strictly better: the dispatcher sees the 503, and the tree is never wedged in the first
    /// place.
    #[error("the dispatch could not be recorded durably: {0}")]
    NotDurable(#[from] JournalError),
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

/// What layer 2 decided about one step before it was ever scheduled (design D§6.1).
///
/// The default — no key, no hit — is the safe one: a step with no key is never looked up *and* never
/// recorded, so a refusal to cache holds in both directions without a second check to keep in sync.
#[derive(Debug, Clone, Default)]
struct MemoDecision {
    key: Option<StepKey>,
    hit: Option<MemoOutcome>,
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
    /// "Recorded" now means recorded *durably*: the write-ahead journal entry is written before this
    /// returns, and a journal that refuses is a refused dispatch (see [`AcceptError::NotDurable`]).
    /// Everything after the ack is still asynchronous.
    ///
    /// Must be called from a tokio context; the pipeline runs on a spawned task so the ack is not
    /// behind any work.
    pub fn accept(self: &Arc<Self>, dispatch: Dispatch) -> Result<Accepted, AcceptError> {
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

        // ── The durable record, before the ack and before the driver (design D§4.1) ───────────────
        //
        // Written for `Created` *and* for `Live`. `Live` is the case that is easy to skip and wrong to
        // skip: it attached a second `callback_url` to a job we already know about, and an entry that
        // still carried only the first URL would, after a restart, answer one dispatcher and leave the
        // other waiting forever on a verdict delivered somewhere else. The journal has to carry the
        // full current URL set, so the second dispatch rewrites the entry.
        //
        // `Finished` needs no entry: it re-reports a verdict that is already in memory, and either the
        // job's own entry is still outstanding (delivery has not been confirmed, so the debt is
        // already recorded) or it was forgotten because the verdict reached Hull. Recording a fresh
        // one would resurrect a paid debt as an unpaid one.
        if !matches!(admit, Admit::Finished { .. }) {
            if let Err(e) = self.journal_record(&job_id, None) {
                // Not acked. See `AcceptError::NotDurable`: an ack Hull believes for a job we can lose
                // wedges the tree until a human forces a rerun, which is strictly worse than a visible
                // failed dispatch the dispatcher can retry.
                tracing::error!(
                    %job_id, %repo, %tree_id, error = %e,
                    "refusing a dispatch we could not record durably — not acking"
                );
                if matches!(admit, Admit::Created { .. }) {
                    // Undo the admission. The driver was never spawned, so nothing is running; leaving
                    // the record would hold the `(repo, tree_id)` index against a job nobody will ever
                    // answer, and the dispatcher's retry would come back as `Admit::Live` on it — an
                    // ack for work that is not happening, which is the exact outcome the refusal
                    // exists to prevent.
                    //
                    // An `Admit::Live` failure is deliberately *not* rolled back: that job belongs to
                    // an earlier dispatch that was recorded and is running, and tearing it down
                    // because a later duplicate could not be journaled would turn one unacked dispatch
                    // into two lost ones.
                    self.lock_jobs().remove(&job_id);
                }
                return Err(AcceptError::NotDurable(e));
            }
        }

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
                //
                // Behind the claim like every other sender. Losing it means a delivery for this job
                // is already in flight, which is not a reason to start a second one: the URL this
                // dispatch just attached is picked up by the run that is already going, because
                // `report` re-reads the destination set before it finishes.
                if self.claim_delivery(&job_id, Instant::now()) {
                    tracing::info!(%job_id, %repo, %tree_id, "duplicate dispatch for a finished job — re-reporting");
                    let ctrl = Arc::clone(self);
                    let id = job_id.clone();
                    tokio::spawn(async move { ctrl.report(&id).await });
                } else {
                    tracing::info!(
                        %job_id, %repo, %tree_id,
                        "duplicate dispatch for a finished job — a delivery is already in flight and will carry it"
                    );
                }
            }
        }

        // **Amortized redelivery**, in the same spirit as the eviction pressure above and for the
        // same reason: a dispatch arriving is cheap, honest evidence that this process is alive and
        // that time has passed, so it is where parked verdicts get another go — no background task to
        // own, supervise and shut down. Spawns; never waits (see `drain_undelivered`).
        self.drain_undelivered(&job_id);

        Ok(Accepted { job_id, duplicate: admit.is_duplicate() })
    }

    /// Hand a few verdicts Hull never received back to the callback sender.
    ///
    /// The gap this closes. Delivery retries on a [`RetryPolicy`] and then gives up, parking the job
    /// in [`JobState::ReportFailed`] with its journal entry deliberately retained — and until now that
    /// entry was retried *only at the next process start*
    /// (`hull_ci_server::journal::recover`). So the one failure the outbox was built for — Hull
    /// unreachable for longer than the retry budget — was the one it could not fix on its own: Hull
    /// comes back, this runner is still up, still healthy, still holding the computed verdict, and
    /// never tries again. Spec §10 means the tree stays wedged for as long as that lasts, because Hull
    /// neither polls us nor times the job out, and an ordinary re-check comes back `Pending`.
    ///
    /// Four properties, each pinned by a test:
    ///
    /// * **Only parked jobs.** [`Job::awaits_redelivery`] is the whole predicate, and it is re-checked
    ///   under the lock that takes the claim rather than trusted from the scan above it.
    /// * **One sender per job.** The claim is the thing that makes that true; the scan is only a
    ///   suggestion, and a job someone else claimed in between is skipped.
    /// * **Bounded and rate-limited**, by `redeliver_max_per_accept` and `redeliver_interval`. A burst
    ///   of dispatches during an outage must not become a burst of retries against a Hull that is
    ///   still down.
    /// * **Never on the ack path.** Each retry is spawned, exactly as `accept` spawns `drive` and the
    ///   `Admit::Finished` re-report. Spec §5 makes the ack mean *accepted*, and it has to stay fast.
    ///
    /// The job this dispatch was *about* is excluded: `accept`'s own branches above already own it,
    /// and driving it from here as well would be the double-send one level up from the claim.
    ///
    /// Oldest debt first, so a steady trickle of dispatches works through a backlog instead of
    /// re-serving whichever job the hash map happened to yield first.
    fn drain_undelivered(self: &Arc<Self>, just_admitted: &str) {
        let now = Instant::now();
        let interval = self.config.redeliver_interval;
        let mut due: Vec<(Instant, JobId)> = self.with_jobs(|jobs| {
            jobs.filter(|job| job.id != just_admitted && job.awaits_redelivery(now, interval))
                .map(|job| (job.last_delivery_at.unwrap_or(job.created_at), job.id.clone()))
                .collect()
        });
        due.sort_by_key(|(last, _)| *last);

        for (_, job_id) in due.into_iter().take(self.config.redeliver_max_per_accept) {
            // The scan ran under a lock this call has since dropped, so everything it decided is
            // re-decided here, atomically, before a task exists.
            if !self.claim_delivery_if_parked(&job_id, now) {
                continue;
            }
            tracing::info!(
                %job_id,
                "retrying a verdict Hull never received (spec §10: silence wedges the tree)"
            );
            let ctrl = Arc::clone(self);
            tokio::spawn(async move { ctrl.report(&job_id).await });
        }
    }

    /// Take the exclusive right to deliver this job's verdict, or answer `false` if a delivery
    /// already holds it.
    ///
    /// Check and take in one step, under the store lock, because a claim with a gap in it is not a
    /// claim: `accept` and the drain both start their senders from an arriving dispatch, so the gap
    /// would be sampled by the very thing it is meant to exclude. [`Control::report`] releases it on
    /// every exit path.
    ///
    /// A missing job answers `false`: it was evicted or rolled back, and there is nothing to deliver.
    ///
    /// The residual, stated plainly: a claim is released by the task that took it, so a delivery task
    /// that is dropped without running — a runtime shutting down mid-spawn — leaks the claim, and that
    /// job gets no further retries *in this process*. Its journal entry is untouched, so the next
    /// start still answers it. Nothing worse than the behaviour that existed before this drain.
    fn claim_delivery(&self, job_id: &str, now: Instant) -> bool {
        self.with_job_mut(job_id, |job| {
            if job.delivering {
                return false;
            }
            job.delivering = true;
            job.last_delivery_at = Some(now);
            true
        })
        .unwrap_or(false)
    }

    /// [`Control::claim_delivery`], but only for a job that is genuinely parked and off its cooldown.
    ///
    /// Separate from the unconditional claim because the callers differ in kind: `finish` and the
    /// `Admit::Finished` re-report own a verdict outright and are *entitled* to send it, while the
    /// drain is speculative and must not touch a job that is mid-delivery, already answered, or
    /// retried a moment ago. Sharing [`Job::awaits_redelivery`] with the scan keeps the two readings
    /// of "parked" from drifting.
    fn claim_delivery_if_parked(&self, job_id: &str, now: Instant) -> bool {
        let interval = self.config.redeliver_interval;
        self.with_job_mut(job_id, |job| {
            if !job.awaits_redelivery(now, interval) {
                return false;
            }
            job.delivering = true;
            job.last_delivery_at = Some(now);
            true
        })
        .unwrap_or(false)
    }

    /// Give the claim back, and start the cooldown from *now* rather than from when delivery began.
    fn release_delivery(&self, job_id: &str) {
        let now = Instant::now();
        self.with_job_mut(job_id, |job| {
            job.delivering = false;
            job.last_delivery_at = Some(now);
        });
    }

    /// Write the journal entry for `job_id` from the job record as it stands right now.
    ///
    /// One function for both call sites — accept and verdict — because the entry is a *snapshot of
    /// the whole intent*, not a delta ([`Journal::record`] is an upsert). Two hand-rolled builders
    /// would be two chances for one of them to forget a `callback_url` that arrived between them, and
    /// a dropped URL is a change that hangs unverified.
    ///
    /// A job that is no longer in the store is not an error: it was evicted or rolled back, which
    /// means nobody is waiting on this write.
    fn journal_record(&self, job_id: &str, verdict: Option<Verdict>) -> Result<(), JournalError> {
        let Some(intent) = self.with_job(job_id, |job| JobIntent {
            job_id: job.id.clone(),
            repo: job.dispatch.repo.clone(),
            tree_id: job.dispatch.tree_id.clone(),
            // The full current set, never `dispatch.callback_url` alone — see `JobIntent`.
            callback_urls: job.callback_urls.clone(),
            accepted_at_unix: now_unix(),
            verdict,
        }) else {
            return Ok(());
        };
        self.deps.journal.record(&intent)
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
        let mut to_memoize: Option<(String, StepKey, MemoOutcome)> = None;
        {
            let mut jobs = self.lock_jobs();
            let job = jobs.get_mut(&report.job_id).ok_or(ReportRejected::UnknownJob)?;
            let tenant = job.dispatch.tenant().to_string();
            // The prefix this job's logs are allowed to occupy — D§11's `tenant/repo/tree_id/…`,
            // built from the job record rather than from anything the report says. See
            // `accepted_log_key`.
            let log_prefix =
                format!("{}/{}/{}/", tenant, job.dispatch.repo, job.dispatch.tree_id);
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
            step.log_key = accepted_log_key(
                report.log_key.as_deref(),
                &log_prefix,
                &report.job_id,
                &report.step_id,
            );
            // Sanitized again on the way out (aggregate.rs); this is the defence-in-depth pass the
            // proto crate's `StepReport::detail` doc calls for.
            step.detail = sanitize_summary(&report.detail, SUMMARY_MAX_CHARS);
            step.finished_at = Some(now);
            if next == StepState::Errored {
                step.error_reason = Some(Reason::Infra);
            }

            // Layer 2's write side (design D§6.1). Two gates, and both are structural rather than
            // remembered: the step must have a key at all (so every refusal in `memo` covers writes
            // as well as reads), and the outcome must be representable as a [`MemoOutcome`] — which
            // has no `errored` variant, so an outage cannot be written down. Mirrors spec §7 one
            // level below Hull's own memo.
            if let (Some(key), Some(outcome)) = (step.memo_key.clone(), MemoOutcome::from_state(next)) {
                to_memoize = Some((tenant, key, outcome));
            }
        }
        // Outside the store lock: the memo is somebody else's mutex, and the lock order in this file
        // is only ever `jobs` → `queue`.
        if let Some((tenant, key, outcome)) = to_memoize {
            tracing::debug!(job_id = %report.job_id, step_id = %report.step_id, outcome = outcome.as_str(), "recording step memo");
            self.config.memo.store.record(&tenant, &key, outcome, now);
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

    // ── Introspection (used by tests and by the operator dashboard, design D§11) ─────────────────
    //
    // The operator-facing half of this lives in [`crate::snapshot`], which returns owned, redacted
    // copies. What is here is the raw access it is built from, deliberately not public: a `&Job`
    // carries the dispatch, and the dispatch carries `source_url`, `callback_url` and `fetch_token`.

    pub fn job_state(&self, job_id: &str) -> Option<JobState> {
        self.with_job(job_id, |j| j.state)
    }

    pub fn verdict(&self, job_id: &str) -> Option<Verdict> {
        self.with_job(job_id, |j| j.verdict.clone()).flatten()
    }

    pub fn with_job<R>(&self, job_id: &str, f: impl FnOnce(&Job) -> R) -> Option<R> {
        self.lock_jobs().get(job_id).map(f)
    }

    /// Read every held job under one lock acquisition. The public way in is
    /// [`Control::snapshot_jobs`].
    pub(crate) fn with_jobs<R>(&self, f: impl FnOnce(&mut dyn Iterator<Item = &Job>) -> R) -> R {
        let jobs = self.lock_jobs();
        let mut iter = jobs.iter();
        f(&mut iter)
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

    /// Layer 2, applied — design D§6.1.
    ///
    /// Every step's key is computed before a single one is scheduled, because a key depends only on
    /// *definitions* (its own, its inputs' content, and its dependencies' keys) and never on an
    /// outcome. That is what makes the fully-cached case sub-second: the whole plan is resolved
    /// against the memo in one pass, and if every step hits, the job folds to a verdict without the
    /// fleet ever being asked for capacity.
    ///
    /// Returns one decision per spec, in order.
    async fn phase_memo(
        &self,
        job_id: &str,
        ctx: JobKeyContext,
        tree: &VerifiedTree,
        specs: &[StepSpec],
    ) -> Vec<MemoDecision> {
        if !self.config.memo.enabled() {
            return vec![MemoDecision::default(); specs.len()];
        }

        // Resolving a glob reads the extracted tree, which is filesystem work — off the executor,
        // because a first-time index of a large repo is milliseconds-to-seconds and every other
        // job's driver shares this thread pool.
        let memo = self.config.memo.clone();
        let tree_owned = tree.clone();
        let specs_owned = specs.to_vec();
        let ctx_owned = ctx.clone();
        let keys = tokio::task::spawn_blocking(move || {
            plan_step_keys(&memo, &ctx_owned, &tree_owned, &specs_owned)
        })
        .await
        .unwrap_or_else(|e| {
            // A panic in key derivation must cost cache hits, never correctness: with no keys,
            // every step runs.
            tracing::error!(%job_id, error = %e, "step key derivation failed; running every step");
            Vec::new()
        });

        let now = Instant::now();
        let mut decisions = Vec::with_capacity(specs.len());
        let (mut hits, mut uncacheable) = (0usize, 0usize);
        for (spec, key) in specs.iter().zip(keys.into_iter().chain(std::iter::repeat_with(|| {
            Err(crate::memo::NotCacheable::NoInputs)
        }))) {
            let decision = match key {
                Ok(key) => {
                    let hit = self.config.memo.store.lookup(&ctx.tenant, &key, now);
                    if let Some(outcome) = hit {
                        hits += 1;
                        tracing::debug!(
                            %job_id, step = %spec.name, outcome = outcome.as_str(), key = %key,
                            "step memo hit — not dispatching"
                        );
                    }
                    MemoDecision { key: Some(key), hit }
                }
                Err(why) => {
                    uncacheable += 1;
                    tracing::debug!(%job_id, step = %spec.name, why = %why, "step is not cacheable");
                    MemoDecision::default()
                }
            };
            decisions.push(decision);
        }
        if hits > 0 || uncacheable > 0 {
            tracing::info!(%job_id, hits, uncacheable, total = specs.len(), "step memo resolved");
        }
        decisions
    }

    async fn phase_run(&self, job_id: &str, tree: &VerifiedTree, specs: Vec<StepSpec>) {
        // Published before the first step is even `pending`, because the scheduler may hand this
        // job's work to a node from *another* job's driver, and that driver needs to know where the
        // broker put this tree (see [`Control::pump`]).
        self.trees
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(job_id.to_string(), tree.clone());

        let Some(ctx) = self.with_job(job_id, |job| JobKeyContext {
            tenant: job.dispatch.tenant().to_string(),
            tier: self.config.tier,
            author_class: job.author_class,
        }) else {
            return;
        };
        let decisions = self.phase_memo(job_id, ctx, tree, &specs).await;

        let now = Instant::now();
        self.with_job_mut(job_id, |job| {
            let _ = job.transition(JobState::Running);
            for (i, (spec, decision)) in specs.into_iter().zip(decisions).enumerate() {
                // Every step enters `pending`. Which of them are schedulable *now* and which are
                // waiting on an edge is the graph's answer, not this loop's (design D§4.3), and the
                // driver below asks it on every pass — including the first, so a plan with no `needs`
                // at all is promoted wholesale before anything else happens.
                let mut step = Step::new(new_step_id(i), spec);
                step.memo_key = decision.key;
                match decision.hit {
                    // Design D§6.1: "a step whose `step_key` has a recorded `passed` result is
                    // marked `cached` and never dispatched." It never becomes `ready`, so the
                    // scheduler never sees it and the fleet is never asked.
                    Some(MemoOutcome::Passed) => {
                        let _ = step.transition(StepState::Cached);
                        step.finished_at = Some(now);
                    }
                    // A remembered failure is served as `failed`, not `cached` — `cached` folds
                    // green. The detail says where it came from, because a red verdict nobody can
                    // trace to a run is worse than a slow one.
                    Some(MemoOutcome::Failed) => {
                        let _ = step.transition(StepState::Failed);
                        step.detail = "identical inputs failed recently (step memo)".into();
                        step.finished_at = Some(now);
                    }
                    None => {}
                }
                job.steps.push(step);
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
                // Names, verbatim from the plan (D§7.4). The control plane does not adjudicate them
                // and could not resolve one if it wanted to — it holds no key material. It carries
                // them to the placement site, which mints against the job's author class.
                secrets: step.spec.secrets.clone(),
                image: step.spec.image.clone(),
                tier: self.config.tier,
                author_class: job.author_class,
                // Clamped, not merely defaulted: this is the number that arms the sandbox's own
                // wall clock (§14.4), so it has to be the same one `timeouts::sweep` will use.
                timeout_secs: self.config.timeouts.step_timeout(step.spec.timeout).as_secs(),
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

    /// Which plan caps one tenant is currently over — why its queued steps are being skipped
    /// (design D§4.5). Per tenant, like [`Control::queue_depth`], and for the same reason.
    pub fn queue_admission(&self, tenant: &str, now: Instant) -> Admission {
        self.lock_queue().admission(tenant, now)
    }

    /// Node-seconds one tenant has consumed in the rolling hour, against its plan's ceiling.
    pub fn queue_node_seconds(&self, tenant: &str, now: Instant) -> f64 {
        self.lock_queue().node_seconds_used(tenant, now)
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
            // Move the journal entry from "accepted, no answer" to "answered, delivery unconfirmed",
            // **before** a single delivery attempt is made. That ordering is the whole point: a crash
            // between the verdict and its delivery is the window this feature exists for, and an entry
            // still saying `verdict: None` would make the next start report `errored` for a job that
            // had genuinely gone green — a wrong answer, and one spec §7 has Hull memoize by `tree_id`
            // permanently. Reporting a stale `errored` is not memoized and merely costs a re-check;
            // reporting a *fabricated* one is not recoverable, so the write goes first.
            //
            // A failure here is logged and not fatal. The verdict exists and is about to be delivered;
            // refusing to deliver it because we could not update a file would guarantee the wedge the
            // file exists to prevent. The worst case is the entry keeps `verdict: None` and a restart
            // sends `errored` for a job that had a real verdict — bad, but strictly better than
            // sending nothing at all.
            let decided = self.with_job(job_id, |job| job.verdict.clone()).flatten();
            if let Err(e) = self.journal_record(job_id, decided) {
                tracing::error!(
                    %job_id, error = %e,
                    "could not journal the verdict; a restart before delivery would report `errored` for it"
                );
            }

            // **Release the tenant's quota at the verdict, not at delivery.**
            //
            // `report` below retries for up to the full budget — with the default schedule, roughly
            // an hour against an unreachable Hull. Retiring only afterwards meant a job held its
            // tenant's concurrency for that entire window, long after its work had finished and its
            // sandbox was gone, so a single unreachable Hull could wedge a tenant's whole allocation.
            // A liveness bug, and a quiet one: the fleet sits idle, the steps sit `ready`, and
            // nothing in the logs says why.
            //
            // Design D§10.1 had already drawn this line — `reported` is a state separate from the
            // verdict precisely "so the callback sender can retry independently of job completion" —
            // and the implementation simply had not honoured it. The work is finished when the
            // verdict exists. Delivery is bookkeeping about telling someone, and bookkeeping must
            // never hold a slot.
            self.retire(job_id);
            // Behind the claim like every other sender. It cannot normally be refused — the drain
            // only ever claims a `ReportFailed` job and this one has just decided — but a duplicate
            // dispatch that raced this verdict may already have taken it, in which case that sender
            // delivers exactly the same thing and a second run would be pure duplicate traffic.
            if self.claim_delivery(job_id, Instant::now()) {
                self.report(job_id).await;
            } else {
                tracing::debug!(%job_id, "a delivery for this verdict is already in flight");
            }
        }
    }

    /// Deliver (or re-deliver) the recorded verdict. Safe to call more than once — spec §9 makes a
    /// duplicate callback explicitly a re-affirmation.
    ///
    /// **The caller must hold the delivery claim** ([`Control::claim_delivery`]); this releases it on
    /// every exit path. The claim is taken by the caller rather than here because every caller starts
    /// this on a spawned task, and a claim taken inside the task would be taken one scheduling gap
    /// too late — which is exactly when the next dispatch, and with it the next drain, arrives.
    async fn report(&self, job_id: &str) {
        // Every destination is attempted, and one unreachable Hull must not suppress the others; the
        // job counts as reported if *any* delivery landed, and parked only if they all failed.
        let mut attempted: Vec<String> = Vec::new();
        let mut attempts_total = 0;
        let mut any_delivered = false;

        // One verdict, but possibly several places that asked for it: work is deduplicated by
        // (repo, tree_id), delivery is not (see `Job::callback_urls`).
        //
        // Re-read between passes rather than snapshotted once, because a duplicate dispatch attaches
        // its `callback_url` to a job that may already be mid-delivery, and that dispatch is acked on
        // the strength of the delivery in flight (see the `Admit::Finished` branch of `accept`). A
        // single snapshot would leave a URL that arrived a moment too late waiting forever on an
        // answer delivered somewhere else — a change that hangs unverified, which is the same wedge
        // one level down. Terminates: the URL set is finite and de-duplicated.
        loop {
            let Some(Some(reqs)) = self.with_job(job_id, |job| {
                job.verdict.clone().map(|verdict| {
                    job.callback_urls
                        .iter()
                        .filter(|url| !attempted.iter().any(|done| done == *url))
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
                break;
            };
            if reqs.is_empty() {
                break;
            }

            for req in &reqs {
                attempted.push(req.url.clone());
                // Publish each attempt into the job record as it happens, so a stuck delivery is
                // visible while it is stuck rather than only in the post-mortem (D§11.1).
                let jobs = &self.jobs;
                let id = job_id.to_string();
                let sink = move |p: DeliveryProgress| {
                    if let Ok(mut store) = jobs.lock() {
                        if let Some(job) = store.get_mut(&id) {
                            job.delivery = Some(p);
                        }
                    }
                };
                let outcome =
                    deliver_reporting(&*self.deps.transport, req, &self.config.retry, &sink).await;
                attempts_total += match &outcome {
                    Delivery::Delivered { attempts, .. } | Delivery::Parked { attempts, .. } => {
                        *attempts
                    }
                };
                any_delivered |= outcome.is_delivered();
            }
        }

        if attempted.is_empty() {
            // The job was evicted or rolled back under us, or never had a verdict. Nothing was sent,
            // so nothing about its state is ours to change — but the claim is still ours to give back.
            self.release_delivery(job_id);
            return;
        }

        // Delivery is over, one way or the other; `report_attempts` below is the settled record.
        self.with_job_mut(job_id, |job| job.delivery = None);
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
            // **The debt is paid, and only now.** Hull has the verdict, so this job can no longer
            // wedge a tree and there is nothing for a restart to re-send.
            //
            // The `ReportFailed` branch deliberately keeps the entry, and that asymmetry is what makes
            // this an outbox rather than a crash log. A verdict that was computed but never delivered
            // leaves Hull exactly as wedged as one that was never computed — its in-flight set is only
            // cleared by the callback handler (spec §10: "Hull does not poll you") — so the entry has
            // to outlive the failed delivery. Forgetting here on both outcomes would mean the journal
            // only survived crashes and quietly dropped every job that exhausted its retry budget
            // against an unreachable Hull, which is the *likelier* failure.
            //
            // What retries the kept entry: `Control::drain_undelivered`, on the next dispatch, for as
            // long as this process lives; and `hull_ci_server::journal::recover` at the next start,
            // for a debt this process no longer remembers.
            self.deps.journal.forget(job_id);
            // The driver is done with this job; drop its waker so a long-lived process does not
            // accumulate one per job it has ever seen.
            self.wakers.lock().unwrap_or_else(|e| e.into_inner()).remove(job_id);
        }

        // **Last**, after the state above has settled. Releasing first would expose a job that is
        // about to become `Reported` while it still reads `ReportFailed`, and the next dispatch's
        // drain would claim and re-send a verdict Hull already has.
        self.release_delivery(job_id);
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

/// The `log_key` we are willing to remember for a step, from the one a node reported.
///
/// **A node names where it put a log; it does not choose where a log may go.** The key is built on
/// the node as `{tenant}/{repo}/{tree_id}/{step_name}/{attempt}` (D§11) out of strings that all
/// started somewhere else — `repo` arrived on a dispatch, `step_name` arrived in a pipeline, and
/// `hull_ci_plan`'s step-name grammar permits `/`. So a pipeline can put extra path segments into
/// what will become an object-store key, and the only thing that was stopping `../` was that the
/// same grammar has no `.` in its charset. That is a property of a table somebody may widen, not a
/// control, and this is the control:
///
/// * [`check_log_key`] says the key is a sequence of names — no empty segment, no `.`/`..`, no `\`,
///   nothing invisible — so it cannot address anything but what it spells;
/// * the prefix says the key is *this job's*, under this job's tenant, repo and tree. Only the
///   control plane knows those three, which is why the check lives here and not in the proto crate.
///
/// A key that fails is **dropped, not fatal**. The log key is auxiliary — nothing has ever been read
/// back by it — and erroring the step would turn a naming problem into a red build on a spec §7
/// verdict Hull memoizes. It is dropped loudly: the warning names the job and the step, with the
/// offending key sanitized (spec §14.5) because it is exactly the bytes we refused.
fn accepted_log_key(
    reported: Option<&str>,
    expected_prefix: &str,
    job_id: &str,
    step_id: &str,
) -> Option<String> {
    let key = reported?;
    if let Err(e) = hull_ci_proto::check_log_key(key) {
        tracing::warn!(%job_id, %step_id, error = %e, key = %sanitize_summary(key, 120), "dropped a malformed log key");
        return None;
    }
    if !key.starts_with(expected_prefix) {
        tracing::warn!(
            %job_id, %step_id, key = %sanitize_summary(key, 120), expected = %expected_prefix,
            "dropped a log key outside this job's own prefix"
        );
        return None;
    }
    Some(key.to_string())
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
        dispatch, fast_config, harness, memo_config, memo_spec, spec, stays_false, step_report,
        wait_until, BackgroundRepo, DirFetcher, FailingFetcher, HangingFetcher, MemoPlanner,
        NodeMode, OkFetcher, PerTreePlanner, StaticPlanner, WrongTreeFetcher,
    };
    use crate::memo::{InMemoryStepMemo, MemoPolicy, StepMemo};
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
        let accepted = h.control.accept(dispatch("t/r", "tree1")).unwrap();
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
    async fn a_nodes_log_key_is_kept_only_where_it_names_this_jobs_own_prefix() {
        // Design D§11's key is `tenant/repo/tree_id/step/attempt`, and every component of it is a
        // string that started somewhere else — so it was being stored verbatim from a node with no
        // check at all. Nothing writes objects by it *yet*, which is the reason to fix it now: the
        // first writer inherits whatever is in the field.
        let live = start(fast_config(), Arc::new(OkFetcher), Arc::new(StaticPlanner::steps(4)), NodeMode::Accept);
        let steps = live.steps_leased().await;

        let log_key_of = |step_id: &str| {
            live.ctrl
                .with_job(&live.job_id, |j| j.step(step_id).and_then(|s| s.log_key.clone()))
                .flatten()
        };
        let report_with_key = |i: usize, key: &str| {
            let mut r = step_report(&live.job_id, &steps[i], StepOutcome::Passed, "ok");
            r.log_key = Some(key.to_string());
            live.ctrl.record_step_report(&r, "node-test").expect("the lease holder is believed");
        };

        // The dispatch is `t/r` at `tree1`, so this job owns exactly `t/t/r/tree1/…`.
        //
        // 1. Traversal out of the prefix — what a step named `a/../../b` produces.
        report_with_key(0, "t/t/r/tree1/../../../globex/secrets/1");
        // 2. Well-formed, and somebody else's.
        report_with_key(1, "globex/globex/r/tree1/test/1");
        // 3. An absolute key: an empty first segment is a root, not a tenant.
        report_with_key(2, "/t/t/r/tree1/test/1");
        // 4. What a node legitimately reports, including the `/` D§4.4 allows in a step name.
        report_with_key(3, "t/t/r/tree1/test/unit/1");

        for (i, step_id) in steps.iter().take(3).enumerate() {
            assert_eq!(log_key_of(step_id).as_deref(), None, "case {i} was stored");
        }
        assert_eq!(
            log_key_of(&steps[3]).as_deref(),
            Some("t/t/r/tree1/test/unit/1"),
            "a real key must survive — dropping every log is not a control, it is an outage"
        );

        // A dropped key is the only thing dropped: the step's own result still counts, because a
        // naming problem must not become a `red` verdict Hull memoizes (spec §7).
        assert_eq!(live.settled().await.status, Status::Green);
    }

    #[tokio::test]
    async fn the_clock_a_pipeline_asks_for_is_clamped_before_it_arms_a_sandbox() {
        // The half of the step ceiling that leaves this process. `Assignment::timeout_secs` arms the
        // sandbox's own wall clock (§14.4), and it was `spec.timeout.unwrap_or(config.step)` — the
        // same unbounded expression the sweep used. Two ceilings that disagree are worse than one,
        // so both readers go through `Timeouts::step_timeout`.
        let mut config = fast_config();
        config.timeouts.max_step = Duration::from_secs(90);
        let mut greedy = spec("marathon", &[]);
        greedy.timeout = Some(Duration::from_secs(6 * 60 * 60));
        let mut modest = spec("quick", &[]);
        modest.timeout = Some(Duration::from_secs(30));
        let live = start(
            config,
            Arc::new(OkFetcher),
            Arc::new(StaticPlanner(vec![greedy, modest])),
            NodeMode::Accept,
        );
        live.steps_leased().await;

        let handed: Vec<(String, u64)> =
            live.node.assigned().into_iter().map(|a| (a.step_name, a.timeout_secs)).collect();
        assert!(handed.contains(&("marathon".into(), 90)), "the fleet was told {handed:?}");
        assert!(
            handed.contains(&("quick".into(), 30)),
            "and a step under the ceiling keeps its own clock: {handed:?}"
        );
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

        let again = live.ctrl.accept(dispatch("t/r", "tree1")).unwrap();
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
    async fn an_undeliverable_verdict_does_not_hold_its_tenants_quota() {
        // The liveness bug this guards. `finish` used to await `report` before retiring, so a job
        // whose Hull was unreachable held its tenant's concurrency for the whole retry budget —
        // about an hour by default — with its work long finished and its sandbox long gone. One
        // unreachable Hull could therefore wedge a tenant's entire allocation, and quietly: the
        // fleet idles, the next steps sit `ready`, and nothing says why.
        //
        // Caught by clamping the default plan to the fleet size, which turned "needs 16 leaks to
        // notice" into "needs one".
        let mut cfg = fast_config();
        cfg.fair_share.default_plan.max_running_steps = 1;
        cfg.fair_share.fleet_slots = Some(1);
        // Delivery must be genuinely slow, or there is no window to observe and the test passes
        // whether or not the bug is present — which is exactly what the first version of it did.
        // These numbers stand in for the default schedule's ~1 hour.
        cfg.retry = crate::callback::RetryPolicy {
            base: Duration::from_secs(30),
            max_delay: Duration::from_secs(60),
            max_attempts: 12,
        };

        let h = crate::testing::harness_with(
            cfg,
            Arc::new(OkFetcher),
            Arc::new(StaticPlanner::steps(1)),
            NodeMode::Accept,
            // A Hull that never answers: delivery will retry to exhaustion.
            Arc::new(crate::testing::ScriptedTransport::always_failing()),
        );
        let accepted = h.control.accept(dispatch("t/r", "tree1")).unwrap();
        let live = Live {
            ctrl: Arc::clone(&h.control),
            job_id: accepted.job_id.clone(),
            node: Arc::clone(&h.node),
            transport: Arc::clone(&h.transport),
        };

        let steps = live.steps_leased().await;
        live.ctrl
            .record_step_report(&step_report(&live.job_id, &steps[0], StepOutcome::Passed, "ok"), "node-test")
            .unwrap();

        // The quota must come back as soon as the verdict exists — while delivery is still retrying,
        // not after it gives up.
        let ctrl = Arc::clone(&live.ctrl);
        let freed = wait_until(move || ctrl.queue_depth("t").running == 0).await;
        assert!(
            freed,
            "the tenant's slot must be released at the verdict, not at delivery; depth was {:?}",
            live.ctrl.queue_depth("t")
        );
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
        let again = live.ctrl.accept(second.clone()).unwrap();
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

        live.ctrl.accept(dispatch("t/r", "tree1")).unwrap();
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

        let flood = h.control.accept(dispatch("flood/api", "flood")).unwrap();
        let node = Arc::clone(&h.node);
        assert!(wait_until(move || node.assigned().len() == 1).await, "the flood takes the one slot");

        // Wait for the neighbour's step to actually be *in* the queue, so this is a test about the
        // scheduler's choice and not about which driver happened to wake first.
        h.control.accept(dispatch("solo/api", "solo")).unwrap();
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
        assert_eq!(live.ctrl.queue_depth("t"), Depth { queued: 2, running: 1 });

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

        let nightly = h.control.accept(dispatch("acme/nightly", "nightly")).unwrap();
        let node = Arc::clone(&h.node);
        assert!(wait_until(move || node.assigned().len() == 1).await);

        h.control.accept(dispatch("acme/api", "click")).unwrap();
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

    // ── Step memoization, end to end (design D§6.1, layer 2) ─────────────────────────────────────
    //
    // These run against the **real** digester (`hull-ci-fetch`, keel's own tree walk) over real
    // directories, not a fake. A fake digest would agree with a broken key derivation, which is
    // exactly the bug class this layer can have: a cache that is confidently wrong.

    /// A small repo whose code, docs and tests can be varied independently.
    fn write_tree(root: &std::path::Path, code: &str, docs: &str, tests: &str) {
        std::fs::create_dir_all(root.join("crates/a/src")).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::create_dir_all(root.join("tests")).unwrap();
        std::fs::write(root.join("crates/a/src/lib.rs"), code).unwrap();
        std::fs::write(root.join("docs/guide.md"), docs).unwrap();
        std::fs::write(root.join("tests/it.rs"), tests).unwrap();
    }

    /// Three trees that differ in exactly one place each: `base`, a **doc-only** edit of it, and a
    /// **code** edit of it. The doc-only tree is the D§8 shape — a new `tree_id` Hull has never seen
    /// whose declared `inputs` are byte-identical.
    struct Trees {
        _dir: tempfile::TempDir,
        base: std::path::PathBuf,
        doc_only: std::path::PathBuf,
        code_changed: std::path::PathBuf,
        test_changed: std::path::PathBuf,
    }

    fn trees() -> Trees {
        let dir = tempfile::TempDir::new().unwrap();
        let (base, doc_only, code_changed, test_changed) = (
            dir.path().join("base"),
            dir.path().join("doc"),
            dir.path().join("code"),
            dir.path().join("test"),
        );
        write_tree(&base, "pub fn a() {}\n", "guide v1\n", "#[test] fn t() {}\n");
        write_tree(&doc_only, "pub fn a() {}\n", "guide v2\n", "#[test] fn t() {}\n");
        write_tree(&code_changed, "pub fn a() { todo!() }\n", "guide v1\n", "#[test] fn t() {}\n");
        write_tree(&test_changed, "pub fn a() {}\n", "guide v1\n", "#[test] fn t2() {}\n");
        Trees { _dir: dir, base, doc_only, code_changed, test_changed }
    }

    fn memo_fetcher(t: &Trees) -> Arc<DirFetcher> {
        Arc::new(DirFetcher::new(&[
            ("base", &t.base),
            ("doc", &t.doc_only),
            ("code", &t.code_changed),
            ("test", &t.test_changed),
        ]))
    }

    fn state_of_step(ctrl: &Control, job_id: &str, name: &str) -> Option<StepState> {
        ctrl.with_job(job_id, |j| j.steps.iter().find(|s| s.spec.name == name).map(|s| s.state))
            .flatten()
    }

    /// Report `outcome` for every step of `job_id` the fleet currently holds. Returns how many.
    fn report_leased(ctrl: &Control, job_id: &str, outcome: StepOutcome) -> usize {
        let leased: Vec<StepId> = ctrl
            .with_job(job_id, |j| {
                j.steps
                    .iter()
                    .filter(|s| matches!(s.state, StepState::Leased | StepState::Running))
                    .map(|s| s.id.clone())
                    .collect()
            })
            .unwrap_or_default();
        for id in &leased {
            ctrl.record_step_report(&step_report(job_id, id, outcome, "ok"), "node-test").unwrap();
        }
        leased.len()
    }

    async fn settled_verdict(ctrl: &Arc<Control>, job_id: &str) -> Verdict {
        let c = Arc::clone(ctrl);
        let id = job_id.to_string();
        let ok = wait_until(move || {
            matches!(c.job_state(&id), Some(JobState::Reported) | Some(JobState::ReportFailed))
        })
        .await;
        assert!(ok, "job {job_id} never reported: {:?}", ctrl.job_state(job_id));
        ctrl.verdict(job_id).expect("a reported job has a verdict")
    }

    /// Run one job to green, passing every step the fleet is handed — however deep the DAG.
    async fn run_to_green(h: &crate::testing::Harness, repo: &str, tree: &str) -> JobId {
        let job = h.control.accept(dispatch(repo, tree)).unwrap().job_id;
        let ctrl = Arc::clone(&h.control);
        let id = job.clone();
        let done = wait_until(move || {
            // Report whatever is in flight on every poll, so a chain drains one edge at a time.
            report_leased(&ctrl, &id, StepOutcome::Passed);
            matches!(ctrl.job_state(&id), Some(JobState::Reported) | Some(JobState::ReportFailed))
        })
        .await;
        assert!(done, "job {job} never reported: {:?}", h.control.job_state(&job));
        assert_eq!(h.control.verdict(&job).expect("a verdict").status, Status::Green);
        job
    }

    #[tokio::test]
    async fn a_doc_only_edit_hits_the_memo_and_a_code_edit_misses() {
        // Layer 2's whole claim, in one test. Three *different* trees — so Hull's own `tree_id` memo
        // (layer 1) offers nothing — and the middle one skips the step entirely because its declared
        // `inputs` are byte-identical (design D§6.1, D§8).
        let t = trees();
        let store = Arc::new(InMemoryStepMemo::default());
        let h = harness(
            memo_config(store.clone()),
            memo_fetcher(&t),
            Arc::new(MemoPlanner(vec![memo_spec("test", &["crates/**"], &[])])),
            NodeMode::Accept,
        );

        run_to_green(&h, "acme/api", "base").await;
        assert_eq!(h.node.assigned().len(), 1, "the first tree runs");

        // Doc-only: a new tree Hull has never seen, whose `crates/**` is unchanged.
        let doc = h.control.accept(dispatch("acme/api", "doc")).unwrap().job_id;
        assert_eq!(settled_verdict(&h.control, &doc).await.status, Status::Green);
        assert_eq!(state_of_step(&h.control, &doc, "test"), Some(StepState::Cached));
        assert_eq!(h.node.assigned().len(), 1, "a memo hit is never dispatched");

        // Code change inside the glob: a miss, and the step runs.
        let code = h.control.accept(dispatch("acme/api", "code")).unwrap().job_id;
        let ctrl = Arc::clone(&h.control);
        let id = code.clone();
        assert!(wait_until(move || state_of_step(&ctrl, &id, "test") == Some(StepState::Leased)).await);
        assert_eq!(h.node.assigned().len(), 2, "a change inside the declared inputs must miss");
    }

    #[tokio::test]
    async fn a_fully_cached_job_reaches_a_verdict_without_any_node_assignment() {
        // The sub-second verdict D§6.1 exists for: "if every step is cached, the job resolves
        // without touching a node and the callback goes out in milliseconds."
        let t = trees();
        let store = Arc::new(InMemoryStepMemo::default());
        let plan = vec![
            memo_spec("build", &["crates/**"], &[]),
            memo_spec("test", &["tests/**"], &["build"]),
            // `crates/**` again, not `docs/**`: the second tree edits the docs, so a step that
            // declared them would rightly miss. Which is the point — every step here declares
            // inputs the doc-only edit does not touch.
            memo_spec("lint", &["crates/**"], &[]),
        ];
        let h = harness(
            memo_config(store.clone()),
            memo_fetcher(&t),
            Arc::new(MemoPlanner(plan)),
            NodeMode::Accept,
        );

        run_to_green(&h, "acme/api", "base").await;
        let ran = h.node.assigned().len();
        assert_eq!(ran, 3);

        // A tree that differs only where nothing declares an input… every step is a hit.
        let mut second = dispatch("acme/api", "doc");
        second.callback_url = "https://hull.example/api/repos/acme/api/change/doc/ci-result".into();
        let job = h.control.accept(second).unwrap().job_id;
        let verdict = settled_verdict(&h.control, &job).await;

        assert_eq!(verdict.status, Status::Green);
        assert_eq!(h.node.assigned().len(), ran, "not one step reached the fleet");
        for name in ["build", "test", "lint"] {
            assert_eq!(state_of_step(&h.control, &job, name), Some(StepState::Cached), "{name}");
        }
        assert!(
            verdict.summary.as_deref().unwrap_or_default().contains("3 cached"),
            "the summary must say what was actually checked; got {:?}",
            verdict.summary
        );
        assert_eq!(h.control.queue_depth("acme"), Depth { queued: 0, running: 0 });
    }

    #[tokio::test]
    async fn a_changed_dependency_invalidates_its_dependents() {
        // `test` reads only `tests/**`, which is identical across these two trees — so on its own
        // inputs it is a hit. Its *dependency* `build` changed, and D§6.1 folds a dependency's key
        // into its dependents', so `test` must run anyway. Without that fold, a rebuilt library
        // would be paired with a test result from the old one.
        let t = trees();
        let store = Arc::new(InMemoryStepMemo::default());
        let plan = vec![
            memo_spec("build", &["crates/**"], &[]),
            memo_spec("test", &["tests/**"], &["build"]),
        ];
        let h = harness(
            memo_config(store.clone()),
            memo_fetcher(&t),
            Arc::new(MemoPlanner(plan)),
            NodeMode::Accept,
        );

        run_to_green(&h, "acme/api", "base").await;
        assert_eq!(h.node.assigned().len(), 2);

        let job = h.control.accept(dispatch("acme/api", "code")).unwrap().job_id;
        let ctrl = Arc::clone(&h.control);
        let id = job.clone();
        assert!(wait_until(move || state_of_step(&ctrl, &id, "build") == Some(StepState::Leased)).await);
        assert_eq!(state_of_step(&h.control, &job, "test"), Some(StepState::Pending), "not cached, waiting");
        report_leased(&h.control, &job, StepOutcome::Passed);

        let ctrl = Arc::clone(&h.control);
        let id = job.clone();
        assert!(
            wait_until(move || state_of_step(&ctrl, &id, "test") == Some(StepState::Leased)).await,
            "the dependent must run: its dependency's key moved"
        );
        assert_eq!(h.node.assigned().len(), 4);
    }

    #[tokio::test]
    async fn a_dependents_own_inputs_still_matter() {
        // The mirror image, so the previous test is not passing for the wrong reason: `build` is a
        // hit and `test`'s own inputs moved, so exactly one step runs.
        let t = trees();
        let store = Arc::new(InMemoryStepMemo::default());
        let plan = vec![
            memo_spec("build", &["crates/**"], &[]),
            memo_spec("test", &["tests/**"], &["build"]),
        ];
        let h = harness(memo_config(store), memo_fetcher(&t), Arc::new(MemoPlanner(plan)), NodeMode::Accept);

        run_to_green(&h, "acme/api", "base").await;
        let job = h.control.accept(dispatch("acme/api", "test")).unwrap().job_id;

        let ctrl = Arc::clone(&h.control);
        let id = job.clone();
        assert!(wait_until(move || state_of_step(&ctrl, &id, "test") == Some(StepState::Leased)).await);
        assert_eq!(state_of_step(&h.control, &job, "build"), Some(StepState::Cached));
        assert_eq!(h.node.assigned().len(), 3, "only the test step re-ran");
    }

    #[tokio::test]
    async fn two_tenants_with_identical_trees_never_see_each_others_results() {
        // Design D§1's timing/existence-oracle row: "every cache/memo/affinity key is tenant-scoped,
        // so a cross-tenant hit is structurally impossible — there is nothing to time." Byte-identical
        // trees, byte-identical steps, and `other` still runs its own build.
        let t = trees();
        let store = Arc::new(InMemoryStepMemo::default());
        let h = harness(
            memo_config(store.clone()),
            memo_fetcher(&t),
            Arc::new(MemoPlanner(vec![memo_spec("test", &["crates/**"], &[])])),
            NodeMode::Accept,
        );

        run_to_green(&h, "acme/api", "base").await;
        assert_eq!(h.node.assigned().len(), 1);

        // A different tenant, the same tree id, the same content, the same step definition.
        let other = h.control.accept(dispatch("other/api", "base")).unwrap().job_id;
        let ctrl = Arc::clone(&h.control);
        let id = other.clone();
        assert!(
            wait_until(move || state_of_step(&ctrl, &id, "test") == Some(StepState::Leased)).await,
            "the second tenant must run the work itself"
        );
        assert_eq!(h.node.assigned().len(), 2);
        assert_eq!(h.node.assigned()[1].tenant, "other");

        // And `acme`'s own repeat is still a hit, so the miss above is tenancy and nothing else.
        let again = h.control.accept(dispatch("acme/api", "doc")).unwrap().job_id;
        assert_eq!(settled_verdict(&h.control, &again).await.status, Status::Green);
        assert_eq!(state_of_step(&h.control, &again, "test"), Some(StepState::Cached));
        assert_eq!(h.node.assigned().len(), 2);
    }

    #[tokio::test]
    async fn two_repos_of_the_same_tenant_do_share_the_memo() {
        // The deliberate *other* side of the boundary, pinned so it stays a decision rather than an
        // accident. D§1: "the tenant is the hard boundary"; D§6.1 keys the memo by tenant, not by
        // repo. Two repos of one org with an identical step definition over identical input content
        // are the same work, and the tenant already vouches for both — so the hit is correct, and it
        // is what makes a shared library's steps cheap across an org.
        let t = trees();
        let store = Arc::new(InMemoryStepMemo::default());
        let h = harness(
            memo_config(store),
            memo_fetcher(&t),
            Arc::new(MemoPlanner(vec![memo_spec("test", &["crates/**"], &[])])),
            NodeMode::Accept,
        );

        run_to_green(&h, "acme/api", "base").await;
        let sibling = h.control.accept(dispatch("acme/web", "doc")).unwrap().job_id;
        assert_eq!(settled_verdict(&h.control, &sibling).await.status, Status::Green);
        assert_eq!(state_of_step(&h.control, &sibling, "test"), Some(StepState::Cached));
        assert_eq!(h.node.assigned().len(), 1, "a sibling repo of the same tenant is a hit");
    }

    #[tokio::test]
    async fn an_errored_step_is_never_written_to_the_memo() {
        // Spec §7's discipline one level down (D§6.1): an outage must not poison anything. A cached
        // `errored` would attach our own five-minute outage to a tree for as long as the entry lived.
        let t = trees();
        let store = Arc::new(InMemoryStepMemo::default());
        let h = harness(
            memo_config(store.clone()),
            memo_fetcher(&t),
            Arc::new(MemoPlanner(vec![memo_spec("test", &["crates/**"], &[])])),
            NodeMode::Accept,
        );

        let job = h.control.accept(dispatch("acme/api", "base")).unwrap().job_id;
        let ctrl = Arc::clone(&h.control);
        let id = job.clone();
        assert!(wait_until(move || state_of_step(&ctrl, &id, "test") == Some(StepState::Leased)).await);
        report_leased(&h.control, &job, StepOutcome::Errored);
        assert_eq!(settled_verdict(&h.control, &job).await.status, Status::Errored);
        assert!(store.is_empty(), "nothing may be recorded for an errored step");

        // The next tree with identical inputs must therefore run, not be served the outage.
        let next = h.control.accept(dispatch("acme/api", "doc")).unwrap().job_id;
        let ctrl = Arc::clone(&h.control);
        let id = next.clone();
        assert!(wait_until(move || state_of_step(&ctrl, &id, "test") == Some(StepState::Leased)).await);
        assert_eq!(h.node.assigned().len(), 2);
    }

    #[tokio::test]
    async fn a_remembered_failure_decides_red_without_a_node_and_then_expires() {
        // D§6.1 caches `failed` **briefly**: it is real signal about the code on exactly these
        // inputs, so a repeat should not rerun the world — but it is also the thing an author is
        // actively trying to change, so it must expire.
        let t = trees();
        let store = Arc::new(InMemoryStepMemo::default());
        let h = harness(
            memo_config(store.clone()),
            memo_fetcher(&t),
            Arc::new(MemoPlanner(vec![memo_spec("test", &["crates/**"], &[])])),
            NodeMode::Accept,
        );

        let job = h.control.accept(dispatch("acme/api", "base")).unwrap().job_id;
        let ctrl = Arc::clone(&h.control);
        let id = job.clone();
        assert!(wait_until(move || state_of_step(&ctrl, &id, "test") == Some(StepState::Leased)).await);
        report_leased(&h.control, &job, StepOutcome::Failed);
        assert_eq!(settled_verdict(&h.control, &job).await.status, Status::Red);

        // Served — as `failed`, never as `cached`, because `cached` folds green.
        let repeat = h.control.accept(dispatch("acme/api", "doc")).unwrap().job_id;
        let verdict = settled_verdict(&h.control, &repeat).await;
        assert_eq!(verdict.status, Status::Red, "a remembered failure is still red");
        assert_eq!(state_of_step(&h.control, &repeat, "test"), Some(StepState::Failed));
        assert_eq!(h.node.assigned().len(), 1, "and it cost no node time");
    }

    #[tokio::test]
    async fn a_failure_that_has_expired_is_re_run() {
        // The other half: `failed_ttl` elapsed, so the step goes back to the fleet rather than
        // reporting a stale red forever.
        let t = trees();
        let store: Arc<dyn StepMemo> = Arc::new(InMemoryStepMemo::new(MemoPolicy {
            failed_ttl: Duration::ZERO,
            ..MemoPolicy::default()
        }));
        let h = harness(
            memo_config(store),
            memo_fetcher(&t),
            Arc::new(MemoPlanner(vec![memo_spec("test", &["crates/**"], &[])])),
            NodeMode::Accept,
        );

        let job = h.control.accept(dispatch("acme/api", "base")).unwrap().job_id;
        let ctrl = Arc::clone(&h.control);
        let id = job.clone();
        assert!(wait_until(move || state_of_step(&ctrl, &id, "test") == Some(StepState::Leased)).await);
        report_leased(&h.control, &job, StepOutcome::Failed);
        settled_verdict(&h.control, &job).await;

        let repeat = h.control.accept(dispatch("acme/api", "doc")).unwrap().job_id;
        let ctrl = Arc::clone(&h.control);
        let id = repeat.clone();
        assert!(
            wait_until(move || state_of_step(&ctrl, &id, "test") == Some(StepState::Leased)).await,
            "an expired failure must be re-run, not re-reported"
        );
        assert_eq!(h.node.assigned().len(), 2);
    }

    #[tokio::test]
    async fn a_step_with_no_declared_inputs_is_never_cached() {
        // The refusal of D§6.1 that keeps a stale green out of the system: with no inputs the key
        // would not mention the tree at all, so the first `passed` would answer every future run of
        // this step — forever, for any code.
        let t = trees();
        let store = Arc::new(InMemoryStepMemo::default());
        let h = harness(
            memo_config(store.clone()),
            memo_fetcher(&t),
            // Same shape as the cacheable plans above, minus `inputs`.
            Arc::new(MemoPlanner(vec![StepSpec::new("test", vec!["cargo".into()], "rust:1.83")])),
            NodeMode::Accept,
        );

        run_to_green(&h, "acme/api", "base").await;
        assert!(store.is_empty(), "an uncacheable step is never recorded either");

        let repeat = h.control.accept(dispatch("acme/api", "doc")).unwrap().job_id;
        let ctrl = Arc::clone(&h.control);
        let id = repeat.clone();
        assert!(wait_until(move || state_of_step(&ctrl, &id, "test") == Some(StepState::Leased)).await);
        assert_eq!(h.node.assigned().len(), 2, "every run of an input-less step must run");
    }

    #[tokio::test]
    async fn inputs_that_name_nothing_are_the_same_refusal() {
        // A plausible-looking declaration that selects nothing folds an empty set — the same digest
        // on every tree in existence — so it must be refused exactly like no inputs at all.
        let t = trees();
        let store = Arc::new(InMemoryStepMemo::default());
        let h = harness(
            memo_config(store.clone()),
            memo_fetcher(&t),
            Arc::new(MemoPlanner(vec![memo_spec("test", &["no-such-dir/**"], &[])])),
            NodeMode::Accept,
        );

        run_to_green(&h, "acme/api", "base").await;
        assert!(store.is_empty());

        let repeat = h.control.accept(dispatch("acme/api", "doc")).unwrap().job_id;
        let ctrl = Arc::clone(&h.control);
        let id = repeat.clone();
        assert!(wait_until(move || state_of_step(&ctrl, &id, "test") == Some(StepState::Leased)).await);
        assert_eq!(h.node.assigned().len(), 2);
    }

    #[tokio::test]
    async fn a_control_plane_with_no_digester_behaves_exactly_as_it_did_before_layer_2() {
        // Unwired means off, not open. The default `MemoConfig` refuses every glob, so a deployment
        // that has not wired a digester runs every step — the M2 behaviour, unchanged.
        let t = trees();
        let h = harness(
            fast_config(),
            memo_fetcher(&t),
            Arc::new(MemoPlanner(vec![memo_spec("test", &["crates/**"], &[])])),
            NodeMode::Accept,
        );
        run_to_green(&h, "acme/api", "base").await;
        let repeat = h.control.accept(dispatch("acme/api", "doc")).unwrap().job_id;
        let ctrl = Arc::clone(&h.control);
        let id = repeat.clone();
        assert!(wait_until(move || state_of_step(&ctrl, &id, "test") == Some(StepState::Leased)).await);
        assert_eq!(h.node.assigned().len(), 2);
    }
}

/// The write-ahead journal, from the control plane's side (design D§4.1, [`crate::journal`]).
///
/// Everything here serves one sentence: **every accepted dispatch is eventually answered, across a
/// restart.** Spec §10 leaves both halves of that to us — "Hull does not time out a dispatched job"
/// and "Hull does not poll you" — and Hull's in-flight set is cleared only by our callback, so a job
/// we accept and never answer is a tree wedged until a human forces a rerun. These tests pin the
/// three moments where that promise is made or broken: the ack, the verdict, and the delivery.
#[cfg(test)]
mod journal_tests {
    use super::*;
    use crate::journal::{JobIntent, Journal, MemJournal};
    use crate::testing::{
        dispatch, fast_config, harness_full, step_report, wait_until, Harness, NodeMode, OkFetcher,
        RefusingJournal, ScriptedTransport, StaticPlanner,
    };
    use hull_ci_proto::{Status, StepOutcome};

    /// A harness over a caller-supplied journal, so a *second* `Control` can be built over the same
    /// one — which is how a restart is simulated without a process boundary.
    fn over(journal: Arc<dyn Journal>, transport: Arc<ScriptedTransport>) -> Harness {
        harness_full(
            fast_config(),
            Arc::new(OkFetcher),
            Arc::new(StaticPlanner::steps(1)),
            NodeMode::Accept,
            transport,
            journal,
        )
    }

    fn only(journal: &MemJournal) -> JobIntent {
        let mut out = journal.outstanding().unwrap();
        assert_eq!(out.len(), 1, "expected exactly one outstanding entry, got {out:#?}");
        out.remove(0)
    }

    /// Drive the one planned step to `outcome` and wait for the job to settle either way.
    async fn settle(h: &Harness, job_id: &str, outcome: StepOutcome) {
        let ctrl = Arc::clone(&h.control);
        let id = job_id.to_string();
        assert!(
            wait_until(move || ctrl.with_job(&id, |j| j.steps.len() == 1).unwrap_or(false)).await,
            "the step never reached the fleet"
        );
        let step = h.control.with_job(job_id, |j| j.steps[0].id.clone()).unwrap();
        h.control
            .record_step_report(&step_report(job_id, &step, outcome, "ok"), "node-test")
            .expect("the lease holder is believed");
        let ctrl = Arc::clone(&h.control);
        let id = job_id.to_string();
        assert!(
            wait_until(move || matches!(
                ctrl.job_state(&id),
                Some(JobState::Reported) | Some(JobState::ReportFailed)
            ))
            .await,
            "the job never settled"
        );
    }

    #[tokio::test]
    async fn an_accepted_job_is_outstanding_until_its_verdict_is_delivered() {
        // The whole lifecycle in one test, because what matters is the *transitions* rather than any
        // single state: accepted → owed, delivered → paid.
        let journal = Arc::new(MemJournal::default());
        let h = over(Arc::clone(&journal) as Arc<dyn Journal>, Arc::new(ScriptedTransport::ok()));

        let accepted = h.control.accept(dispatch("t/r", "tree1")).unwrap();
        let entry = only(&journal);
        assert_eq!(entry.job_id, accepted.job_id);
        assert_eq!(entry.repo, "t/r");
        assert_eq!(entry.tree_id, "tree1");
        assert_eq!(entry.callback_urls, ["https://hull.example/api/repos/t/r/change/21ea/ci-result"]);
        assert!(entry.verdict.is_none(), "nothing has been decided yet");

        settle(&h, &accepted.job_id, StepOutcome::Passed).await;
        assert_eq!(h.control.job_state(&accepted.job_id), Some(JobState::Reported));
        assert!(journal.outstanding().unwrap().is_empty(), "Hull has the verdict, so nothing is owed");
    }

    #[tokio::test]
    async fn a_verdict_whose_delivery_failed_stays_outstanding_carrying_that_verdict() {
        // **This is what makes it an outbox rather than a crash log.** A `report_failed` job has a
        // real verdict Hull never received, so its tree is exactly as wedged as one that never ran —
        // and unlike a crash this is the *likely* failure: a full retry budget spent against an
        // unreachable Hull. Forgetting the entry on any settled outcome would drop precisely these.
        //
        // The verdict has to survive with it. Re-sending `errored` for a job that genuinely went
        // green would be a wrong answer rather than a late one.
        let journal = Arc::new(MemJournal::default());
        // A Hull that never answers.
        let h = over(Arc::clone(&journal) as Arc<dyn Journal>, Arc::new(ScriptedTransport::always_failing()));

        let accepted = h.control.accept(dispatch("t/r", "tree1")).unwrap();
        settle(&h, &accepted.job_id, StepOutcome::Passed).await;
        assert_eq!(h.control.job_state(&accepted.job_id), Some(JobState::ReportFailed));

        let entry = only(&journal);
        assert_eq!(entry.job_id, accepted.job_id);
        assert_eq!(
            entry.verdict.as_ref().map(|v| v.status),
            Some(Status::Green),
            "the entry carries the true answer, not a placeholder"
        );
    }

    #[tokio::test]
    async fn a_second_dispatch_for_a_live_tree_leaves_one_entry_carrying_both_urls() {
        // `Admit::Live`. Work is deduplicated by `(repo, tree_id)`; delivery is not. An entry still
        // carrying only the first `callback_url` would, after a restart, answer one dispatcher and
        // leave the other waiting forever on a verdict delivered somewhere else — the same wedge, one
        // level down and much harder to notice.
        let journal = Arc::new(MemJournal::default());
        let h = over(Arc::clone(&journal) as Arc<dyn Journal>, Arc::new(ScriptedTransport::ok()));

        let first = h.control.accept(dispatch("t/r", "tree1")).unwrap();
        let mut second = dispatch("t/r", "tree1");
        second.change = "b2b2b2b2b2b2".into();
        second.callback_url = "https://hull.example/api/repos/t/r/change/b2b2/ci-result".into();
        let again = h.control.accept(second.clone()).unwrap();
        assert_eq!(again.job_id, first.job_id, "one tree, one job");
        assert!(again.duplicate);

        let entry = only(&journal);
        assert_eq!(
            entry.callback_urls,
            [
                "https://hull.example/api/repos/t/r/change/21ea/ci-result".to_string(),
                second.callback_url.clone(),
            ],
            "one entry, both destinations, in arrival order"
        );
    }

    #[tokio::test]
    async fn a_dispatch_whose_journal_write_fails_is_refused_and_leaves_no_job() {
        // Spec §5 makes a 2xx mean *accepted*: Hull tells the user "dispatched" and stops caring, and
        // §10 says it neither polls us nor times the job out. So an ack for a job we can lose is not
        // "slow", it is a tree wedged until a human forces a rerun. The store must also be left as if
        // the dispatch never arrived — otherwise the dispatcher's retry comes back `Admit::Live` and
        // gets acked for work that is not running, which is the same failure wearing a duplicate's
        // clothes.
        let refusing = harness_full(
            fast_config(),
            Arc::new(OkFetcher),
            Arc::new(StaticPlanner::steps(1)),
            NodeMode::Accept,
            Arc::new(ScriptedTransport::ok()),
            Arc::new(RefusingJournal),
        );

        let refused = refusing.control.accept(dispatch("t/r", "tree1"));
        assert!(matches!(refused, Err(AcceptError::NotDurable(_))), "got {refused:?}");
        assert!(refusing.control.snapshot_jobs().is_empty(), "no job was created");
        assert_eq!(refusing.node.assigned().len(), 0, "and nothing was scheduled");

        // A dispatch that *can* be recorded is still ordinary new work, not a duplicate of a phantom.
        let ok = over(Arc::new(MemJournal::default()), Arc::new(ScriptedTransport::ok()));
        assert!(!ok.control.accept(dispatch("t/r", "tree1")).unwrap().duplicate);
    }

    #[tokio::test]
    async fn a_restart_can_still_answer_a_job_the_previous_process_never_finished() {
        // **The test that would have caught the real bug.** All state was in memory, so a runner that
        // died mid-job left Hull holding an in-flight tree no re-check would dislodge: no callback, no
        // `errored`, and nothing anywhere that knew a callback was owed.
        //
        // The process boundary here is the shared journal. One `Control` accepts a job and is dropped
        // while it is genuinely in flight; a second is built over the same journal with an empty job
        // store, and the debt is still legible to it — the job id, the repo, the tree, and every
        // `callback_url` that has to hear an answer.
        let journal = Arc::new(MemJournal::default());

        let first = over(Arc::clone(&journal) as Arc<dyn Journal>, Arc::new(ScriptedTransport::ok()));
        let accepted = first.control.accept(dispatch("t/r", "tree1")).unwrap();
        let ctrl = Arc::clone(&first.control);
        let id = accepted.job_id.clone();
        assert!(
            wait_until(move || ctrl.with_job(&id, |j| j.steps.len() == 1).unwrap_or(false)).await,
            "the job should be genuinely in flight when the process dies"
        );

        // The crash: everything in memory goes, and only the journal survives.
        drop(first);

        let restarted = over(Arc::clone(&journal) as Arc<dyn Journal>, Arc::new(ScriptedTransport::ok()));
        assert!(restarted.control.snapshot_jobs().is_empty(), "a fresh process knows no jobs");

        let owed = journal.outstanding().unwrap();
        assert_eq!(owed.len(), 1, "the debt outlived the process");
        assert_eq!(owed[0].job_id, accepted.job_id);
        assert_eq!(owed[0].tree_id, "tree1");
        assert!(owed[0].verdict.is_none(), "it never reached a verdict, and the entry says so");
        assert_eq!(
            owed[0].callback_urls,
            ["https://hull.example/api/repos/t/r/change/21ea/ci-result"],
            "and it knows where the answer has to go"
        );

        // Paying it is what unwedges the tree. The delivery itself belongs to the composition root —
        // `hull_ci_server::journal::recover`, tested there against the real filesystem journal and a
        // second live `Control` — and what this asserts is the half the control plane owns: a
        // restarted process can still see the debt, and settling it clears the record for good.
        journal.forget(&owed[0].job_id);
        assert!(journal.outstanding().unwrap().is_empty());
        drop(restarted);
    }
}

/// **The in-process drain**: verdicts Hull never received get another go while this process is alive.
///
/// The gap these pin, stated once. Delivery retries on a [`RetryPolicy`] and then parks the job in
/// [`JobState::ReportFailed`], keeping its journal entry — but that entry used to be retried *only at
/// the next process start*. So the likeliest failure of all, Hull unreachable for longer than the
/// retry budget, was the one the outbox could not fix by itself: Hull comes back, this runner is still
/// up and still holding the computed verdict, and never tries again. Spec §10 leaves the tree wedged
/// for the duration, because Hull neither polls us nor times the job out and an ordinary re-check
/// answers `Pending`.
#[cfg(test)]
mod redelivery_tests {
    use super::*;
    use crate::journal::{Journal, MemJournal};
    use crate::testing::{
        dispatch, fast_config, harness_full, stays_false, step_report, wait_until, Harness, NodeMode,
        OkFetcher, ScriptedTransport, StaticPlanner,
    };
    use hull_ci_proto::{Status, StepOutcome};

    /// A control plane whose fleet accepts, over a caller-chosen transport and journal.
    fn over(
        config: ControlConfig,
        transport: Arc<ScriptedTransport>,
        journal: Arc<dyn Journal>,
    ) -> Harness {
        harness_full(
            config,
            Arc::new(OkFetcher),
            Arc::new(StaticPlanner::steps(1)),
            NodeMode::Accept,
            transport,
            journal,
        )
    }

    /// [`over`] with a journal nobody inspects.
    fn plain(config: ControlConfig, transport: Arc<ScriptedTransport>) -> Harness {
        over(config, transport, Arc::new(MemJournal::default()))
    }

    /// Accept `tree`, pass its one step, and wait for the delivery to fail — a job parked in
    /// `report_failed` holding a real verdict Hull never got. The state everything below starts from.
    async fn park(h: &Harness, tree: &str) -> JobId {
        let accepted = h.control.accept(dispatch("t/r", tree)).unwrap();
        let job_id = accepted.job_id;

        let ctrl = Arc::clone(&h.control);
        let id = job_id.clone();
        assert!(
            wait_until(move || ctrl.with_job(&id, |j| j.steps.len() == 1).unwrap_or(false)).await,
            "the step never reached the fleet"
        );
        let step = h.control.with_job(&job_id, |j| j.steps[0].id.clone()).unwrap();
        h.control
            .record_step_report(&step_report(&job_id, &step, StepOutcome::Passed, "ok"), "node-test")
            .expect("the lease holder is believed");

        let ctrl = Arc::clone(&h.control);
        let id = job_id.clone();
        assert!(
            wait_until(move || ctrl.job_state(&id) == Some(JobState::ReportFailed)).await,
            "the job should be parked with an undelivered verdict"
        );
        job_id
    }

    /// Accept work that never finishes, so a dispatch can be used purely as the *signal* the drain
    /// runs on without its own job producing a verdict — and therefore any callback traffic — of its
    /// own.
    fn dispatch_only(h: &Harness, tree: &str) {
        h.control.accept(dispatch("t/r", tree)).unwrap();
    }

    /// Make a minute pass for one job, which no test can do by waiting.
    ///
    /// The cooldown is deliberately long enough (a minute by default) that a test cannot sleep
    /// through it, so the clock is moved instead of the test. Reaching into the record is the point:
    /// the *only* thing altered is when the last delivery happened.
    fn age_out_cooldown(ctrl: &Control, job_id: &str) {
        let then = Instant::now()
            .checked_sub(ctrl.config().redeliver_interval + Duration::from_secs(1))
            .expect("the machine has been up for longer than one cooldown");
        ctrl.with_job_mut(job_id, |job| job.last_delivery_at = Some(then))
            .expect("the job is still held");
    }

    /// How many times the transport was handed this job's verdict.
    fn sent_for(h: &Harness, job_id: &str) -> usize {
        h.transport.seen().into_iter().filter(|r| r.job_id == job_id).count()
    }

    #[tokio::test]
    async fn a_parked_verdict_is_retried_by_the_next_dispatch_and_lands_once_hull_returns() {
        // The whole feature in one test. `fast_config`'s budget is three attempts, so the first three
        // posts are the initial delivery failing; the fourth is the drain's, and it is the one that
        // unwedges the tree.
        let journal = Arc::new(MemJournal::default());
        let transport = Arc::new(ScriptedTransport::failing_then_ok(3));
        let h = over(fast_config(), Arc::clone(&transport), Arc::clone(&journal) as Arc<dyn Journal>);

        let parked = park(&h, "tree1").await;
        assert_eq!(transport.attempts(), 3, "the whole budget was spent, and Hull got nothing");
        assert!(
            journal.outstanding().unwrap().iter().any(|e| e.job_id == parked),
            "the debt is recorded: an undelivered verdict is still owed"
        );

        // Time passes; a dispatch for unrelated work arrives. That is the entire trigger.
        age_out_cooldown(&h.control, &parked);
        dispatch_only(&h, "tree2");

        let ctrl = Arc::clone(&h.control);
        let id = parked.clone();
        assert!(
            wait_until(move || ctrl.job_state(&id) == Some(JobState::Reported)).await,
            "the parked verdict was never retried — only a restart would have answered it"
        );

        let landed = h.transport.seen().pop().expect("something was sent");
        assert_eq!(landed.job_id, parked, "and it was the parked job's own verdict");
        assert_eq!(landed.verdict.status, Status::Green, "the verdict it computed, not an error");
        assert_eq!(
            landed.url, "https://hull.example/api/repos/t/r/change/21ea/ci-result",
            "spec §5: the callback_url verbatim, on a retry as on the first attempt"
        );
        assert!(
            !journal.outstanding().unwrap().iter().any(|e| e.job_id == parked),
            "the debt is paid, so nothing is left for the next start to re-send"
        );
    }

        /// The claim itself, exercised directly — the race the filter cannot cover.
    ///
    /// `a_job_that_is_already_delivering_is_not_sent_a_second_time` proves the drain *scan* skips a
    /// job that is delivering, and that is the common path. It is not this one: the scan and the
    /// spawn are separate steps, and between them `finish`, an `Admit::Finished` re-report, or a
    /// drain running on another accept can start delivering the same job. Only the claim closes
    /// that window, because only the claim tests and sets under one hold of the store lock.
    ///
    /// Verified: deleting the `if job.delivering { return false }` from `claim_delivery` leaves
    /// every other test in this crate passing, so without this the atomic half of the guard is
    /// unpinned and a future tidy-up would take it for redundant with the filter.
    #[tokio::test]
    async fn only_one_claimant_can_hold_a_delivery_at_a_time() {
        let transport = Arc::new(ScriptedTransport::failing_then_stalling(3, Duration::from_secs(3600)));
        let h = plain(fast_config(), Arc::clone(&transport));
        let parked = park(&h, "tree1").await;
        age_out_cooldown(&h.control, &parked);

        let now = Instant::now();
        assert!(h.control.claim_delivery(&parked, now), "an unclaimed job is claimable");
        assert!(!h.control.claim_delivery(&parked, now), "a second claimant must lose");
        // The parked variant guards the same field, so it must lose to a held claim too — otherwise
        // a drain could start a sender for a job `finish` is already delivering.
        assert!(
            !h.control.claim_delivery_if_parked(&parked, now),
            "the drain's claim must also lose to a claim already held"
        );

        h.control.release_delivery(&parked);
        age_out_cooldown(&h.control, &parked);
        assert!(
            h.control.claim_delivery_if_parked(&parked, Instant::now()),
            "and releasing it makes the job claimable again, or a failed delivery would park forever"
        );
    }

#[tokio::test]
    async fn a_job_that_is_already_delivering_is_not_sent_a_second_time() {
        // A redelivery leaves the job in `report_failed` for its whole duration — that is the state
        // it retries *from* — so the state check alone does not exclude it and the claim is what
        // does. The cooldown is stepped out of the way on purpose: with it left in place this test
        // would pass whether or not the claim existed.
        let transport = Arc::new(ScriptedTransport::failing_then_stalling(3, Duration::from_secs(3600)));
        let h = plain(fast_config(), Arc::clone(&transport));

        let parked = park(&h, "tree1").await;
        age_out_cooldown(&h.control, &parked);
        dispatch_only(&h, "tree2");

        let t = Arc::clone(&transport);
        assert!(
            wait_until(move || t.attempts() == 4).await,
            "the drain should have started a retry, which is now stuck in the transport"
        );
        assert!(
            h.control.with_job(&parked, |j| j.delivering).unwrap(),
            "and the job is claimed while that retry is in flight"
        );

        // Even with the cooldown expired *again*, a second dispatch must not start a second sender.
        age_out_cooldown(&h.control, &parked);
        dispatch_only(&h, "tree3");

        let t = Arc::clone(&transport);
        assert!(
            stays_false(move || t.attempts() > 4).await,
            "a second delivery was started for a job that was already delivering"
        );
    }

    #[tokio::test]
    async fn a_delivered_verdict_is_never_re_sent_by_the_drain() {
        // `Reported` means Hull has it. Re-sending would be traffic nobody needs, against the one
        // endpoint whose availability the whole system depends on — and it would do it on every
        // dispatch, forever, because a delivered job never leaves that state.
        let h = plain(fast_config(), Arc::new(ScriptedTransport::ok()));

        let accepted = h.control.accept(dispatch("t/r", "tree1")).unwrap();
        let ctrl = Arc::clone(&h.control);
        let id = accepted.job_id.clone();
        assert!(wait_until(move || ctrl.with_job(&id, |j| j.steps.len() == 1).unwrap_or(false)).await);
        let step = h.control.with_job(&accepted.job_id, |j| j.steps[0].id.clone()).unwrap();
        h.control
            .record_step_report(
                &step_report(&accepted.job_id, &step, StepOutcome::Passed, "ok"),
                "node-test",
            )
            .unwrap();
        let ctrl = Arc::clone(&h.control);
        let id = accepted.job_id.clone();
        assert!(wait_until(move || ctrl.job_state(&id) == Some(JobState::Reported)).await);
        assert_eq!(sent_for(&h, &accepted.job_id), 1);

        age_out_cooldown(&h.control, &accepted.job_id);
        dispatch_only(&h, "tree2");
        dispatch_only(&h, "tree3");

        let t = Arc::clone(&h.transport);
        let id = accepted.job_id.clone();
        assert!(
            stays_false(move || t.seen().iter().filter(|r| r.job_id == id).count() > 1).await,
            "a job Hull has already heard about was re-sent"
        );
        assert_eq!(sent_for(&h, &accepted.job_id), 1);
    }

    #[tokio::test]
    async fn a_burst_of_dispatches_is_not_a_burst_of_retries_for_the_same_job() {
        // The rate limit, in both directions. Dispatches arrive at machine rates; without a cooldown
        // every one of them would be another retry against a Hull that is, by hypothesis, still down.
        let transport = Arc::new(ScriptedTransport::always_failing());
        let h = plain(fast_config(), Arc::clone(&transport));

        let parked = park(&h, "tree1").await;
        assert_eq!(transport.attempts(), 3, "the initial delivery spent the budget");

        // Five dispatches, back to back, immediately after the delivery gave up.
        for tree in ["tree2", "tree3", "tree4", "tree5", "tree6"] {
            dispatch_only(&h, tree);
        }
        let t = Arc::clone(&transport);
        assert!(
            stays_false(move || t.attempts() > 3).await,
            "a job retried a moment ago was retried again by every dispatch in the burst"
        );

        // And the cooldown expires rather than parking the job forever: one more dispatch, one more
        // run of the budget, and no more than one however many dispatches follow it.
        age_out_cooldown(&h.control, &parked);
        for tree in ["tree7", "tree8", "tree9"] {
            dispatch_only(&h, tree);
        }
        let t = Arc::clone(&transport);
        assert!(wait_until(move || t.attempts() == 6).await, "the cooldown never expired");
        let t = Arc::clone(&transport);
        assert!(stays_false(move || t.attempts() > 6).await, "one run, not three");
    }

    #[tokio::test]
    async fn one_dispatch_retries_at_most_the_configured_number_of_jobs() {
        // The burst cap. A thousand jobs parked against a Hull that is still down must not become a
        // thousand simultaneous POSTs the moment one dispatch arrives.
        let transport = Arc::new(ScriptedTransport::always_failing());
        let h = plain(fast_config(), Arc::clone(&transport));
        assert_eq!(h.control.config().redeliver_max_per_accept, 2, "the cap this test is written to");

        let parked: Vec<JobId> = {
            let mut ids = Vec::new();
            for tree in ["tree1", "tree2", "tree3"] {
                ids.push(park(&h, tree).await);
            }
            ids
        };
        assert_eq!(transport.attempts(), 9, "three jobs, three attempts each, nothing retried yet");
        for id in &parked {
            age_out_cooldown(&h.control, id);
        }

        // One dispatch. Three jobs are due; two may go.
        dispatch_only(&h, "tree4");
        let t = Arc::clone(&transport);
        assert!(wait_until(move || t.attempts() >= 15).await, "two runs of the budget should follow");
        let t = Arc::clone(&transport);
        assert!(stays_false(move || t.attempts() > 15).await, "and no more than two");

        let retried = parked.iter().filter(|id| sent_for(&h, id) > 3).count();
        assert_eq!(retried, 2, "exactly two distinct jobs were retried, not three");
        // The third is not forgotten, only deferred: it is still parked, still owed, and first in
        // line the next time a dispatch arrives.
        let waiting = parked.iter().find(|id| sent_for(&h, id) == 3).unwrap();
        assert_eq!(h.control.job_state(waiting), Some(JobState::ReportFailed));
    }

    #[tokio::test]
    async fn the_ack_never_waits_on_a_redelivery() {
        // Spec §5 makes a 2xx mean *accepted*, and design D§4.1 makes the ack fast on purpose: Hull
        // tells the user "dispatched" on the strength of it. A drain that delivered inline would put
        // a whole retry budget — up to an hour against an unreachable Hull — in front of every
        // dispatch that happened to arrive while a job was parked.
        let transport = Arc::new(ScriptedTransport::failing_then_stalling(3, Duration::from_secs(3600)));
        let h = plain(fast_config(), Arc::clone(&transport));

        let parked = park(&h, "tree1").await;
        age_out_cooldown(&h.control, &parked);

        let started = Instant::now();
        h.control.accept(dispatch("t/r", "tree2")).unwrap();
        let took = started.elapsed();

        // The retry this dispatch started is genuinely stuck — an hour of it is still outstanding —
        // and the ack came back anyway.
        let t = Arc::clone(&transport);
        assert!(wait_until(move || t.attempts() == 4).await, "the drain did start a retry");
        assert!(
            took < Duration::from_millis(250),
            "the ack waited {took:?} on a delivery that is still in flight"
        );
    }
}
