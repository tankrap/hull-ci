//! Fair-share scheduling and admission control — design D§4.5, the multi-tenant scheduler's core.
//!
//! M1 had no scheduler at all: every step that the DAG unblocked was handed straight to the fleet, in
//! whatever order the drivers happened to wake up. For one tenant that is correct and free. For many
//! it is the noisy-neighbour row of design D§1's threat table with no control in the box: a tenant
//! that dispatches ten thousand steps takes the whole fleet, and the neighbour who clicked *check*
//! and is watching a spinner waits behind all of it.
//!
//! Three mechanisms, each bounding a different resource, exactly as D§4.5 lays them out.
//!
//! ## 1. Weighted fair queueing across tenants
//!
//! Each step, **at the moment it is chosen**, is stamped with a virtual finish time
//! `vft = max(vft_last, virtual_now − ε) + cost / weight`, and the scheduler always dispatches the
//! smallest. `cost` is estimated node-seconds; `weight` comes from the tenant's plan. The guarantee
//! is the classic WFQ one applied to tenants instead of packets: **a backlogged flow gets exactly its
//! weighted share, no more.** A tenant that floods only advances *its own* virtual clock, so its
//! ten-thousandth queued step is stamped ten thousand costs into the future while a neighbour's first
//! step is stamped one — and the neighbour goes next, not 10 000th.
//!
//! Two things D§4.5 does not spell out, decided here:
//!
//! * **`virtual_now` is the start tag of the most recently dispatched step** — Start-time Fair
//!   Queueing (Goyal, Vin & Cheng, 1996) rather than textbook WFQ's simulated-GPS clock. Textbook
//!   virtual time is defined against a server of *known constant rate*; our server is a node fleet
//!   whose instantaneous rate is unknown, varies with autoscaling (D§12), and drops to zero whenever
//!   the fleet is full. SFQ's clock is defined purely by the work actually dispatched, so it stays
//!   correct under a variable-rate server. That is the property we need and the reason for the swap.
//! * **The tag is assigned at selection, not at enqueue.** Assigning at enqueue would freeze the
//!   ordering the instant a step became ready, and then priority (below) could not reorder anything
//!   without also changing the tenant's share. Tagging at selection is what lets priority live
//!   strictly *inside* the tenant and fairness live strictly *between* tenants.
//!
//! ## 2. The idle-credit clamp
//!
//! `max(vft_last, virtual_now − ε)` is the whole of it, and it is the classic WFQ bug when it is
//! missing. Without the clamp a tenant that is idle while others work keeps a `vft_last` frozen in
//! the distant past; when it returns, every step it enqueues tags smaller than anything else in the
//! system and it drains its entire backlog before anyone else is served — a starvation window
//! proportional to how long it was away. With the clamp a returning tenant starts near the current
//! virtual time and may bank at most ε of credit. ε is a real knob, not a fudge: it is how much
//! service a tenant may carry across a gap, so it should be about one step, which is why it defaults
//! to the same value as the default cost estimate.
//!
//! ## 3. Priority classes within a tenant, and admission control across the plan
//!
//! `interactive` (an actor clicked check) preempts `background` (merge-queue, nightly, and D§9.1
//! independence-tree jobs), then FIFO. Priority chooses *which* of a tenant's steps is its head; it
//! never changes how often that tenant's head is chosen, so it is structurally incapable of being a
//! fairness bypass.
//!
//! Admission is two caps from the tenant's plan — concurrent running steps, and node-minutes per
//! rolling hour. A tenant over either cap is skipped during selection: its steps **stay queued and
//! keep their position**, because D§4.5 is emphatic that over cap is *a wait, not a failure*. Only
//! the queue-wait clock ([`crate::timeouts`], D§10.2) turns a long enough wait into `errored` with
//! `reason: capacity` — never `red`, because the code did not fail, the tenant ran out of plan.
//!
//! ## What a tenant can see
//!
//! Nothing about anyone else. Accounting is per tenant, [`FairQueue::depth`] answers only for the
//! tenant asked about, and there is deliberately **no global-depth accessor and no queue-position
//! field on anything that reaches a node or a callback** — D§1's scheduler-side-channel row wants
//! "there is nothing to observe" rather than "we filtered it out". The cost estimator is keyed
//! `(tenant, step_name)` for the same reason it is in D§6.1: a shared estimate would be a
//! cross-tenant timing oracle for "has anyone else built this step".

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hull_ci_proto::Dispatch;

use crate::model::{JobId, StepId, StepState};

/// The window the node-minute quota is measured over (design D§4.5: "per rolling hour").
const ROLLING_WINDOW: Duration = Duration::from_secs(3600);

/// How many recent runs of one step key the p50 cost estimate is taken over. Small on purpose: the
/// estimate should track a pipeline that just got slower, not average it away over a week.
const COST_SAMPLES: usize = 16;

/// Floor on a step's estimated cost, in seconds.
///
/// A zero-cost step would advance its tenant's virtual clock by nothing, so the tenant could take
/// turns without ever paying for them — the one arithmetic slip that turns this mechanism into its
/// exact opposite. Cheap steps are real (a memo-adjacent lint pass finishes in milliseconds), so the
/// floor is small rather than absent.
const MIN_COST_SECS: f64 = 0.001;

/// Which of a tenant's steps is served first (design D§4.5).
///
/// Ordered so `Interactive` sorts before `Background`, because that *is* the rule: someone is
/// watching a spinner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// An actor clicked check.
    Interactive,
    /// Merge-queue, nightly, and design D§9.1 independence-tree jobs — work no human is waiting on.
    Background,
}

impl Priority {
    pub fn as_str(self) -> &'static str {
        match self {
            Priority::Interactive => "interactive",
            Priority::Background => "background",
        }
    }
}

/// Which class a dispatch belongs to.
///
/// A seam rather than a dispatch field because contract v1 has no field for it (spec §5) and the
/// control plane must not invent one from job-supplied bytes: a pipeline that could assert
/// `interactive` would have found a way to jump its own tenant's queue. What the class really
/// depends on is *why Hull dispatched* — a human clicking check, versus the merge queue or the
/// nightly sweep — which is Hull's knowledge, not ours, so this is where that knowledge plugs in
/// when the contract grows a way to carry it.
///
/// Implementations must be cheap and pure: this is consulted on every scheduling pass.
pub trait Prioritizer: Send + Sync + 'static {
    fn priority(&self, dispatch: &Dispatch) -> Priority;
}

/// The default: an unclassified dispatch is presumed to have a human waiting on it.
///
/// Being wrong in this direction costs a nightly job nothing anyone can measure — priority only
/// reorders *within* a tenant's own share, so a misfiled background job can delay its own tenant's
/// other work and no one else's. Being wrong in the other direction puts every human's click behind
/// every batch job, which is the outcome D§4.5 introduced priority classes to prevent.
pub struct AssumeInteractive;

impl Prioritizer for AssumeInteractive {
    fn priority(&self, _dispatch: &Dispatch) -> Priority {
        Priority::Interactive
    }
}

/// One tenant's slice of the fleet, from its Hull plan (design D§4.5).
#[derive(Debug, Clone, Copy)]
pub struct TenantPlan {
    /// Share of scheduling capacity, relative to every other tenant's weight.
    pub weight: f64,
    /// Cap on steps running at once — the tenant's *concurrent footprint*.
    pub max_running_steps: usize,
    /// Cap on node-minutes consumed in any rolling hour — the tenant's *total* footprint. The two
    /// caps are not redundant: concurrency bounds the instantaneous blast radius, node-minutes bound
    /// what a tenant can spend over time at any concurrency.
    pub node_minutes_per_hour: f64,
}

impl TenantPlan {
    /// The weight, made safe to divide by.
    ///
    /// A zero or negative weight divides to infinity or flips the comparison, either of which hands
    /// the tenant *unbounded* priority — the failure mode is silent and is the opposite of what the
    /// operator meant to configure, so it is corrected here rather than trusted.
    fn safe_weight(&self) -> f64 {
        if self.weight.is_finite() && self.weight > 0.0 {
            self.weight
        } else {
            1.0
        }
    }
}

impl Default for TenantPlan {
    /// Generous but finite. A default of "unlimited" would mean a fresh deployment has admission
    /// control switched off, which is exactly the configuration D§4.5 exists to rule out.
    fn default() -> Self {
        TenantPlan { weight: 1.0, max_running_steps: 16, node_minutes_per_hour: 1200.0 }
    }
}

/// How this control plane divides its fleet.
#[derive(Clone)]
pub struct FairShare {
    /// Plan for a tenant we have no specific entry for.
    pub default_plan: TenantPlan,
    /// Per-tenant plans, keyed by the tenant half of `repo` ([`Dispatch::tenant`]).
    pub plans: HashMap<String, TenantPlan>,
    /// Total steps the fleet can run at once, when the control plane knows it.
    ///
    /// `None` means "ask the fleet and take [`NoCapacity`] for an answer" — M1's behaviour, and the
    /// honest default until the node roster of D§5.1 is feeding real `slots_total` back. Fairness is
    /// not lost when it is `None`: the fleet is still offered work in weighted-fair order, so
    /// whichever assignments the fleet does accept are the fair ones. What `None` gives up is the
    /// ability to *hold back* work the fleet would have taken from the wrong tenant.
    ///
    /// [`NoCapacity`]: crate::seams::NodeError::NoCapacity
    pub fleet_slots: Option<usize>,
    /// Estimated node-seconds for a step key we have never run.
    pub default_cost: Duration,
    /// ε — how much service a tenant may carry across an idle gap. See the module docs.
    pub idle_credit: Duration,
    /// How a dispatch is sorted into a priority class.
    pub prioritizer: Arc<dyn Prioritizer>,
}

impl FairShare {
    pub fn plan(&self, tenant: &str) -> TenantPlan {
        self.plans.get(tenant).copied().unwrap_or(self.default_plan)
    }

    /// Give one tenant a plan of its own.
    pub fn with_plan(mut self, tenant: impl Into<String>, plan: TenantPlan) -> Self {
        self.plans.insert(tenant.into(), plan);
        self
    }
}

impl Default for FairShare {
    fn default() -> Self {
        FairShare {
            default_plan: TenantPlan::default(),
            plans: HashMap::new(),
            fleet_slots: None,
            // A minute is a plausible p50 for a CI step and is only ever the estimate for a step key
            // we have never seen; one run replaces it with the truth.
            default_cost: Duration::from_secs(60),
            // One default step's worth of credit: enough that the gap between two steps of the same
            // pipeline costs a tenant nothing, small enough that an hour of idleness does not buy a
            // starvation window.
            idle_credit: Duration::from_secs(60),
            prioritizer: Arc::new(AssumeInteractive),
        }
    }
}

/// A step the scheduler has chosen. The caller hands it to the fleet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub job_id: JobId,
    pub step_id: StepId,
    pub tenant: String,
}

/// One tenant's view of its own queue — and only its own (design D§1, scheduler side-channel).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Depth {
    pub queued: usize,
    pub running: usize,
}

/// What the control plane saw when it last looked at one step.
#[derive(Debug, Clone)]
pub struct StepView {
    pub step_id: StepId,
    pub name: String,
    pub state: StepState,
    pub started_at: Option<Instant>,
    pub finished_at: Option<Instant>,
}

/// One job's steps, as observed. The scheduler's accounting is **derived** from these observations
/// rather than from a hook on every state transition: a step leaves flight through a node report, a
/// lease expiry, a timeout sweep, a fail-fast cancel and a graph skip, and a scheduler that had to be
/// told about all five would eventually be told about four.
#[derive(Debug, Clone)]
pub struct JobView {
    pub job_id: JobId,
    pub tenant: String,
    pub priority: Priority,
    pub steps: Vec<StepView>,
}

/// A step waiting for its turn. Tagged at selection, so it carries only its estimated cost.
#[derive(Debug, Clone)]
struct Waiting {
    job_id: JobId,
    step_id: StepId,
    cost: f64,
}

/// Where one step currently sits. `since == None` is queued; `Some` is running, from that instant.
#[derive(Debug, Clone)]
struct Placement {
    name: String,
    since: Option<Instant>,
}

#[derive(Debug, Clone)]
struct JobMeta {
    tenant: String,
    priority: Priority,
    steps: HashMap<StepId, Placement>,
}

#[derive(Debug, Default)]
struct Tenant {
    /// The virtual finish time of the last step this tenant was granted — its position in the
    /// weighted-fair order.
    vft_last: f64,
    /// One deque per [`Priority`], indexed by `priority as usize`. FIFO within a class.
    queues: [VecDeque<Waiting>; 2],
    /// Steps in flight, and when each started — the concurrency cap and the in-progress half of the
    /// node-minute cap both read this.
    running: HashMap<(JobId, StepId), Instant>,
    /// `(finished_at, ran_for)` for completed steps, trimmed to the rolling window.
    ledger: VecDeque<(Instant, Duration)>,
}

/// The scheduler. In-memory and deterministic: no clock of its own, no background thread, and ties
/// broken by tenant name so a test that runs twice gets the same answer twice.
pub struct FairQueue {
    cfg: FairShare,
    /// SFQ's virtual clock: the start tag of the most recently dispatched step. See the module docs
    /// for why it is defined by dispatched work rather than by elapsed time.
    virtual_now: f64,
    tenants: BTreeMap<String, Tenant>,
    jobs: HashMap<JobId, JobMeta>,
    /// p50 node-seconds per `(tenant, step_name)`. Tenant-scoped so it can never answer "has anyone
    /// else run this" (design D§6.1).
    costs: HashMap<(String, String), VecDeque<f64>>,
}

impl FairQueue {
    pub fn new(cfg: FairShare) -> Self {
        FairQueue {
            cfg,
            virtual_now: 0.0,
            tenants: BTreeMap::new(),
            jobs: HashMap::new(),
            costs: HashMap::new(),
        }
    }

    // ── Bookkeeping primitives ───────────────────────────────────────────────────────────────────

    /// Record which tenant and priority class a job's steps belong to. Idempotent.
    ///
    /// A job's tenant is fixed at admission and never re-read: it is derived from `repo`, which is
    /// the idempotency key (spec §9), so a job whose tenant appeared to change would be two jobs.
    pub fn admit_job(&mut self, job_id: &str, tenant: &str, priority: Priority) {
        self.tenants.entry(tenant.to_string()).or_default();
        self.jobs
            .entry(job_id.to_string())
            .and_modify(|m| m.priority = priority)
            .or_insert_with(|| JobMeta {
                tenant: tenant.to_string(),
                priority,
                steps: HashMap::new(),
            });
    }

    /// Put a schedulable step in its tenant's queue. A step already accounted for is left alone, so
    /// the caller may reconcile as often as it likes.
    pub fn enqueue(&mut self, job_id: &str, step_id: &str, step_name: &str) {
        let Some(meta) = self.jobs.get(job_id) else { return };
        if meta.steps.contains_key(step_id) {
            return;
        }
        let (tenant, priority) = (meta.tenant.clone(), meta.priority);
        let cost = self.estimate(&tenant, step_name);

        if let Some(meta) = self.jobs.get_mut(job_id) {
            meta.steps.insert(
                step_id.to_string(),
                Placement { name: step_name.to_string(), since: None },
            );
        }
        let waiting =
            Waiting { job_id: job_id.to_string(), step_id: step_id.to_string(), cost };
        self.tenants.entry(tenant).or_default().queues[priority as usize].push_back(waiting);
    }

    /// Stop accounting for a step that did not run to completion — cancelled, timed out, or handed
    /// back by the fleet.
    ///
    /// It still **pays** for whatever time it held a slot, because the fleet really was occupied and
    /// the node-minute quota is a measure of consumption. What it does not do is **teach**: the
    /// duration of a step that was interrupted says nothing about what that step costs to run, and a
    /// grant the fleet refused would teach an estimate of *zero* — which would make that tenant's
    /// work look free and hand it the queue, throttling exactly the wrong tenant.
    pub fn release(&mut self, job_id: &str, step_id: &str, at: Instant) {
        self.unplace(job_id, step_id, at, false);
    }

    /// [`release`](Self::release), plus: this step ran to completion, so how long it took is what
    /// that step key costs and the estimator should say so next time.
    pub fn finish(&mut self, job_id: &str, step_id: &str, at: Instant) {
        self.unplace(job_id, step_id, at, true);
    }

    fn unplace(&mut self, job_id: &str, step_id: &str, at: Instant, learn: bool) {
        let Some(meta) = self.jobs.get_mut(job_id) else { return };
        let tenant = meta.tenant.clone();
        let Some(placement) = meta.steps.remove(step_id) else { return };
        let Some(since) = placement.since else { return };

        let ran = at.saturating_duration_since(since);
        if let Some(t) = self.tenants.get_mut(&tenant) {
            t.running.remove(&(job_id.to_string(), step_id.to_string()));
            t.ledger.push_back((at, ran));
        }
        if learn {
            self.observe_cost(&tenant, &placement.name, ran);
        }
    }

    /// Hand a granted step back to the queue — the fleet had no capacity for it, or its lease was
    /// lost (design D§5.3).
    ///
    /// It goes to the **tail** of its class, and its tenant keeps the virtual-time charge it paid to
    /// be selected. Both are deliberate: a refund would let a tenant whose steps the fleet keeps
    /// refusing retry for free, forever, at the head of the queue. Paying for a turn it could not
    /// use costs that tenant a little and costs its neighbours nothing, which is the safe direction
    /// for an error the scheduler cannot diagnose.
    pub fn requeue(&mut self, job_id: &str, step_id: &str, step_name: &str, at: Instant) {
        self.release(job_id, step_id, at);
        self.enqueue(job_id, step_id, step_name);
    }

    /// Drop everything we hold for a job that has reached a verdict, freeing its share of the caps.
    pub fn forget_job(&mut self, job_id: &str, at: Instant) {
        let Some(step_ids) = self.jobs.get(job_id).map(|m| m.steps.keys().cloned().collect::<Vec<_>>())
        else {
            return;
        };
        for step_id in step_ids {
            self.release(job_id, &step_id, at);
        }
        self.jobs.remove(job_id);
    }

    /// Bring the scheduler's accounting in line with what one job's steps actually are.
    pub fn reconcile(&mut self, view: &JobView, now: Instant) {
        self.admit_job(&view.job_id, &view.tenant, view.priority);
        for step in &view.steps {
            let held = self
                .jobs
                .get(&view.job_id)
                .and_then(|m| m.steps.get(&step.step_id))
                .map(|p| p.since.is_some());
            match (step.state, held) {
                (StepState::Ready, None) => self.enqueue(&view.job_id, &step.step_id, &step.name),
                // Granted, and then given back — the fleet answered `NoCapacity`, or a lease expired
                // and the step returned to the queue (design D§5.3).
                (StepState::Ready, Some(true)) => {
                    self.requeue(&view.job_id, &step.step_id, &step.name, now)
                }
                (StepState::Leased | StepState::Running, Some(true)) => {}
                // In flight without our having granted it. Not reachable through the driver, but the
                // accounting must describe the fleet's reality rather than our record of it.
                (StepState::Leased | StepState::Running, _) => {
                    self.release(&view.job_id, &step.step_id, now);
                    self.adopt(&view.job_id, &step.step_id, &step.name, step.started_at.unwrap_or(now));
                }
                // Only `passed` and `failed` mean a step ran to its own conclusion. A `cached` step
                // never ran, and `errored`/`skipped` were cut short — none of the three is evidence
                // about what this step key costs, so none of them teaches the estimator.
                (StepState::Passed | StepState::Failed, Some(_)) => {
                    self.finish(&view.job_id, &step.step_id, step.finished_at.unwrap_or(now))
                }
                (state, Some(_)) if state.is_terminal() => {
                    self.release(&view.job_id, &step.step_id, step.finished_at.unwrap_or(now))
                }
                _ => {}
            }
        }
    }

    // ── Selection ────────────────────────────────────────────────────────────────────────────────

    /// Choose the steps to dispatch now, smallest virtual finish time first, skipping any tenant
    /// that is over one of its plan caps.
    ///
    /// Skipping is not dropping: a step whose tenant is over cap stays exactly where it is, untagged
    /// and unpenalized, and is reconsidered on the next pass (design D§4.5 — "over cap is a wait").
    pub fn select(&mut self, now: Instant) -> Vec<Grant> {
        self.prune_ledgers(now);

        let mut budget = match self.cfg.fleet_slots {
            Some(total) => total.saturating_sub(self.in_flight()),
            None => usize::MAX,
        };
        let mut grants = Vec::new();

        while budget > 0 {
            self.drop_stale_heads();
            let Some((tenant, start, vft)) = self.best(now) else { break };
            let Some(waiting) = self.pop_head(&tenant) else { break };

            // The charge lands whether or not the fleet takes the step (see `requeue`).
            if let Some(t) = self.tenants.get_mut(&tenant) {
                t.vft_last = vft;
                t.running.insert((waiting.job_id.clone(), waiting.step_id.clone()), now);
            }
            // SFQ: the virtual clock is the start tag of the work just dispatched. `max` because a
            // tenant that was behind can be granted a step whose start tag is in the past, and time
            // must not run backwards for everyone else.
            self.virtual_now = self.virtual_now.max(start);
            if let Some(placement) =
                self.jobs.get_mut(&waiting.job_id).and_then(|m| m.steps.get_mut(&waiting.step_id))
            {
                placement.since = Some(now);
            }

            grants.push(Grant { job_id: waiting.job_id, step_id: waiting.step_id, tenant });
            budget -= 1;
        }
        grants
    }

    /// The admissible tenant whose head tags smallest: `(tenant, start tag, finish tag)`.
    ///
    /// Ties go to the lexicographically first tenant, because [`BTreeMap`] iterates in order and the
    /// comparison is strict. Arbitrary, but *deterministic* — a scheduler whose output depends on
    /// hash order cannot be tested for the property it exists to provide.
    fn best(&self, now: Instant) -> Option<(String, f64, f64)> {
        let floor = self.virtual_now - self.cfg.idle_credit.as_secs_f64();
        let mut best: Option<(String, f64, f64)> = None;
        for (name, tenant) in &self.tenants {
            let Some(head) = head(tenant) else { continue };
            if !self.admissible(name, tenant, now) {
                continue;
            }
            // The idle-credit clamp. Without the `max`, a tenant returning from an idle spell brings
            // a stale `vft_last` and outbids everyone until it has caught up (see the module docs).
            let start = tenant.vft_last.max(floor);
            let vft = start + head.cost / self.cfg.plan(name).safe_weight();
            let better = match &best {
                Some((_, _, best_vft)) => vft < *best_vft,
                None => true,
            };
            if better {
                best = Some((name.clone(), start, vft));
            }
        }
        best
    }

    /// Both plan caps, in the order that is cheapest to check.
    fn admissible(&self, name: &str, tenant: &Tenant, now: Instant) -> bool {
        let plan = self.cfg.plan(name);
        if tenant.running.len() >= plan.max_running_steps {
            return false;
        }
        node_seconds(tenant, now) < plan.node_minutes_per_hour * 60.0
    }

    fn pop_head(&mut self, name: &str) -> Option<Waiting> {
        let tenant = self.tenants.get_mut(name)?;
        let class = head_class(tenant)?;
        tenant.queues[class].pop_front()
    }

    /// Discard queue entries whose step is no longer waiting — cancelled, timed out, or resolved by
    /// a memo hit while it sat there.
    ///
    /// Lazy deletion: a cancel touches one hash map instead of walking a ten-thousand-entry deque,
    /// and the entry is dropped the moment it would otherwise have been looked at. The cost is that
    /// a tenant with no live work can hold dead entries until someone tries to serve it, which is
    /// bounded by the job store's own retention.
    fn drop_stale_heads(&mut self) {
        let jobs = &self.jobs;
        for tenant in self.tenants.values_mut() {
            for queue in tenant.queues.iter_mut() {
                while let Some(front) = queue.front() {
                    let waiting = jobs
                        .get(&front.job_id)
                        .and_then(|m| m.steps.get(&front.step_id))
                        .is_some_and(|p| p.since.is_none());
                    if waiting {
                        break;
                    }
                    queue.pop_front();
                }
            }
        }
    }

    // ── Accounting ───────────────────────────────────────────────────────────────────────────────

    /// Adopt a step the fleet is already running.
    fn adopt(&mut self, job_id: &str, step_id: &str, name: &str, since: Instant) {
        let Some(meta) = self.jobs.get_mut(job_id) else { return };
        let tenant = meta.tenant.clone();
        meta.steps
            .insert(step_id.to_string(), Placement { name: name.to_string(), since: Some(since) });
        self.tenants
            .entry(tenant)
            .or_default()
            .running
            .insert((job_id.to_string(), step_id.to_string()), since);
    }

    fn in_flight(&self) -> usize {
        self.tenants.values().map(|t| t.running.len()).sum()
    }

    fn prune_ledgers(&mut self, now: Instant) {
        for tenant in self.tenants.values_mut() {
            while let Some((at, _)) = tenant.ledger.front() {
                if now.saturating_duration_since(*at) < ROLLING_WINDOW {
                    break;
                }
                tenant.ledger.pop_front();
            }
        }
    }

    /// The p50 of what this step key has cost this tenant, or the configured default.
    ///
    /// p50 rather than a mean because CI step durations are long-tailed — one cache-cold run that
    /// took twenty minutes should not make every later run of that step look expensive and quietly
    /// throttle the tenant that owns it.
    fn estimate(&self, tenant: &str, step_name: &str) -> f64 {
        let samples = self.costs.get(&(tenant.to_string(), step_name.to_string()));
        let estimate = match samples {
            Some(s) if !s.is_empty() => {
                let mut sorted: Vec<f64> = s.iter().copied().collect();
                sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                sorted[sorted.len() / 2]
            }
            _ => self.cfg.default_cost.as_secs_f64(),
        };
        estimate.max(MIN_COST_SECS)
    }

    fn observe_cost(&mut self, tenant: &str, step_name: &str, ran: Duration) {
        let samples = self.costs.entry((tenant.to_string(), step_name.to_string())).or_default();
        samples.push_back(ran.as_secs_f64());
        while samples.len() > COST_SAMPLES {
            samples.pop_front();
        }
    }

    // ── Introspection ────────────────────────────────────────────────────────────────────────────

    /// How much work **this** tenant has waiting and in flight.
    ///
    /// There is no counterpart that answers for the fleet, and that absence is the control for
    /// design D§1's scheduler-side-channel row: a caller cannot leak what it cannot ask for.
    pub fn depth(&self, tenant: &str) -> Depth {
        let Some(t) = self.tenants.get(tenant) else { return Depth { queued: 0, running: 0 } };
        let queued = t
            .queues
            .iter()
            .flat_map(|q| q.iter())
            .filter(|w| {
                self.jobs
                    .get(&w.job_id)
                    .and_then(|m| m.steps.get(&w.step_id))
                    .is_some_and(|p| p.since.is_none())
            })
            .count();
        Depth { queued, running: t.running.len() }
    }
}

/// Which priority class a tenant's next step comes from — the *one* statement of design D§4.5's
/// within-tenant order, so that the step whose cost is tagged and the step that is actually
/// dispatched can never be two different steps.
///
/// They were two functions once. Nothing failed, because the two orders agreed and the estimates
/// were equal — which is exactly how a scheduler ends up charging a tenant for a cheap lint pass and
/// dispatching its hour-long integration suite.
fn head_class(tenant: &Tenant) -> Option<usize> {
    tenant.queues.iter().position(|q| !q.is_empty())
}

/// A tenant's next step: the oldest interactive one, else the oldest background one.
fn head(tenant: &Tenant) -> Option<&Waiting> {
    head_class(tenant).and_then(|class| tenant.queues[class].front())
}

/// Node-seconds this tenant has spent inside the rolling window, finished work plus work in flight.
///
/// Counting the in-flight part matters: without it a tenant could sit exactly under its quota with
/// sixteen hour-long steps running and be admitted more, and the cap would only notice an hour later
/// when they all landed at once.
fn node_seconds(tenant: &Tenant, now: Instant) -> f64 {
    let finished: f64 = tenant
        .ledger
        .iter()
        .filter(|(at, _)| now.saturating_duration_since(*at) < ROLLING_WINDOW)
        .map(|(_, ran)| ran.as_secs_f64())
        .sum();
    let live: f64 = tenant
        .running
        .values()
        .map(|since| now.saturating_duration_since(*since).as_secs_f64())
        .sum();
    finished + live
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A queue with no fleet-slot limit and roomy plans, so a test that is about ordering is not
    /// quietly also about admission.
    fn queue(cfg: FairShare) -> FairQueue {
        FairQueue::new(cfg)
    }

    fn config() -> FairShare {
        FairShare {
            default_plan: TenantPlan {
                weight: 1.0,
                max_running_steps: usize::MAX,
                node_minutes_per_hour: f64::MAX,
            },
            ..FairShare::default()
        }
    }

    /// How long a served step is pretended to have run. Equal to the default cost estimate, so the
    /// estimator learns exactly what it already assumed and an ordering test stays about ordering.
    const SERVED_FOR: Duration = Duration::from_secs(60);

    /// One tenant, one job, `n` interactive steps queued back to back.
    fn flood(q: &mut FairQueue, tenant: &str, n: usize) {
        q.admit_job(tenant, tenant, Priority::Interactive);
        for i in 0..n {
            q.enqueue(tenant, &format!("{tenant}-{i}"), "test");
        }
    }

    /// Serve `rounds` steps one at a time and answer with the tenant served in each round. One at a
    /// time is the point: fairness is only observable when the server is scarce.
    fn serve(q: &mut FairQueue, rounds: usize, now: Instant) -> Vec<String> {
        serve_steps(q, rounds, now).into_iter().map(|(tenant, _)| tenant).collect()
    }

    fn serve_steps(q: &mut FairQueue, rounds: usize, now: Instant) -> Vec<(String, StepId)> {
        let mut order = Vec::new();
        for _ in 0..rounds {
            let Some(g) = q.select(now).first().cloned() else { break };
            q.finish(&g.job_id, &g.step_id, now + SERVED_FOR);
            order.push((g.tenant, g.step_id));
        }
        order
    }

    /// A queue whose only scarcity is one fleet slot.
    fn one_slot() -> FairQueue {
        queue(FairShare { fleet_slots: Some(1), ..config() })
    }

    #[test]
    fn a_flooding_tenant_does_not_delay_a_neighbours_single_step() {
        // The property design D§1's fairness SLO is made of. A p99 cannot be measured in a unit
        // test, but the ordering that produces it can: `solo` enqueued *after* ten thousand of
        // `flood`'s steps must not be served ten-thousand-and-first. WFQ tags `flood`'s nth step at
        // n·cost and `solo`'s first at one cost, so `solo` goes second.
        let mut q = one_slot();
        let now = Instant::now();
        flood(&mut q, "flood", 10_000);
        flood(&mut q, "solo", 1);

        let order = serve(&mut q, 4, now);
        assert_eq!(order[0], "flood", "the tenant that queued first still goes first");
        assert_eq!(order[1], "solo", "and the neighbour goes second, not 10 001st");
        assert_eq!(&order[2..], ["flood", "flood"], "then the flood drains at its own share");
        assert_eq!(q.depth("solo"), Depth { queued: 0, running: 0 }, "solo is done");
    }

    #[test]
    fn a_backlogged_tenant_gets_its_weighted_share_and_no_more() {
        // The other half of the WFQ guarantee: weight buys proportion, not precedence. Three-to-one
        // over 40 turns is 30/10, and the assertion is tight because the schedule is deterministic.
        let cfg = config()
            .with_plan("big", TenantPlan { weight: 3.0, ..TenantPlan::default() })
            .with_plan("small", TenantPlan { weight: 1.0, ..TenantPlan::default() });
        let mut q = queue(FairShare { fleet_slots: Some(1), ..cfg });
        let now = Instant::now();
        flood(&mut q, "big", 100);
        flood(&mut q, "small", 100);

        let order = serve(&mut q, 40, now);
        let big = order.iter().filter(|t| *t == "big").count();
        assert_eq!(big, 30, "3:1 weights divide 40 turns 30:10, got {order:?}");
    }

    #[test]
    fn an_idle_tenant_cannot_bank_credit_and_starve_everyone_catching_up() {
        // The classic WFQ bug, asserted in both directions so the clamp cannot be deleted without a
        // test failing. `returner` idles while `busy` runs 50 steps, then comes back with 5.
        //
        // With ε effectively unbounded — the bug — `returner`'s virtual clock is still at zero, so
        // every step it queues tags below anything `busy` holds and it drains its entire backlog
        // before `busy` is served again: a starvation window as long as it was away.
        let unclamped =
            FairShare { fleet_slots: Some(1), idle_credit: Duration::from_secs(86_400), ..config() };
        assert_eq!(returning_tenant_run(unclamped), 5, "unclamped, the returner takes all five");

        // Clamped, it gets exactly two: one step of banked credit (ε defaults to one step's cost)
        // plus the one step of head start that the tenant *in service* always has, because its
        // `vft_last` is a full cost ahead of the virtual clock. Then the two interleave.
        assert_eq!(
            returning_tenant_run(FairShare { fleet_slots: Some(1), ..config() }),
            2,
            "clamped, it takes its ε of credit and then shares"
        );
    }

    /// `busy` runs 50 steps alone; `returner` then queues 5. Answers with how many of `returner`'s
    /// steps were served before `busy` got a turn again. Named so ties break towards `busy`, which
    /// keeps the count a statement about the clamp rather than about the tie-break.
    fn returning_tenant_run(cfg: FairShare) -> usize {
        let mut q = queue(cfg);
        let now = Instant::now();
        flood(&mut q, "busy", 100);
        serve(&mut q, 50, now);

        flood(&mut q, "returner", 5);
        serve(&mut q, 6, now).iter().take_while(|t| *t == "returner").count()
    }

    #[test]
    fn priority_reorders_a_tenants_own_steps() {
        // Design D§4.5: interactive preempts background, then FIFO. The background steps are queued
        // first, so a FIFO-only scheduler would fail this.
        let mut q = one_slot();
        let now = Instant::now();
        q.admit_job("nightly", "acme", Priority::Background);
        for i in 0..3 {
            q.enqueue("nightly", &format!("bg-{i}"), "test");
        }
        q.admit_job("click", "acme", Priority::Interactive);
        q.enqueue("click", "human", "test");

        let served: Vec<StepId> = serve_steps(&mut q, 4, now).into_iter().map(|(_, s)| s).collect();
        assert_eq!(served[0], "human", "someone is watching a spinner");
        assert_eq!(&served[1..], ["bg-0", "bg-1", "bg-2"], "then FIFO within the class");
    }

    #[test]
    fn priority_never_lets_a_tenant_take_more_than_its_share() {
        // The reason priority is a *within-tenant* order and not a global one. `loud` marks
        // everything interactive and floods; `quiet` files a single background step. If priority
        // crossed the tenant boundary, `quiet` would go last of 101. It goes second.
        let mut q = one_slot();
        let now = Instant::now();
        q.admit_job("loud", "loud", Priority::Interactive);
        for i in 0..100 {
            q.enqueue("loud", &format!("loud-{i}"), "test");
        }
        q.admit_job("quiet", "quiet", Priority::Background);
        q.enqueue("quiet", "quiet-0", "test");

        let order = serve(&mut q, 3, now);
        assert_eq!(order, ["loud", "quiet", "loud"], "priority sorts inside a share, never between");
    }

    #[test]
    fn a_tenant_at_its_concurrency_cap_keeps_its_steps_queued() {
        // Admission, not rejection: design D§4.5's "it stays queued (it still holds its `vft`
        // position)". Nothing here errors, and the moment a slot frees the next step is chosen.
        let cfg = config().with_plan(
            "capped",
            TenantPlan { max_running_steps: 2, ..TenantPlan::default() },
        );
        let mut q = queue(cfg);
        let now = Instant::now();
        flood(&mut q, "capped", 5);

        let first = q.select(now);
        assert_eq!(first.len(), 2, "exactly the cap goes out");
        assert_eq!(q.depth("capped"), Depth { queued: 3, running: 2 }, "the rest wait");
        assert!(q.select(now).is_empty(), "and asking again does not squeeze more through");

        q.release(&first[0].job_id, &first[0].step_id, now);
        assert_eq!(q.select(now).len(), 1, "one slot back, one step out");
    }

    #[test]
    fn a_tenant_over_its_node_minute_quota_waits_for_the_window_to_roll() {
        // The second cap, and the one that bounds a tenant's spend rather than its blast radius. A
        // step that ran 10 minutes exhausts a 10-node-minute plan; nothing more is admitted until an
        // hour has passed and the ledger entry falls out of the window.
        let cfg = config().with_plan(
            "thrifty",
            TenantPlan { max_running_steps: 4, node_minutes_per_hour: 10.0, ..TenantPlan::default() },
        );
        let mut q = queue(cfg);
        let t0 = Instant::now();
        flood(&mut q, "thrifty", 3);

        let granted = q.select(t0);
        assert_eq!(granted.len(), 3, "under quota, all three go");
        for g in &granted {
            q.release(&g.job_id, &g.step_id, t0 + Duration::from_secs(600));
        }

        let t1 = t0 + Duration::from_secs(600);
        q.admit_job("thrifty", "thrifty", Priority::Interactive);
        q.enqueue("thrifty", "over-quota", "test");
        assert!(q.select(t1).is_empty(), "30 node-minutes spent against a 10-minute plan");
        assert_eq!(q.depth("thrifty").queued, 1, "queued, not errored — a plan limit is a wait");

        let t2 = t0 + ROLLING_WINDOW + Duration::from_secs(601);
        assert_eq!(q.select(t2).len(), 1, "the window rolled and the tenant is solvent again");
    }

    #[test]
    fn a_tenant_sees_its_own_queue_and_nothing_else() {
        // Design D§1's scheduler-side-channel row. `watcher`'s answer must not move when `noisy`
        // queues ten thousand steps, and there is no accessor that would tell it that they exist.
        let mut q = queue(config());
        let now = Instant::now();
        flood(&mut q, "watcher", 2);
        let before = q.depth("watcher");
        flood(&mut q, "noisy", 10_000);
        assert_eq!(q.depth("watcher"), before, "a neighbour's flood is not observable");
        assert_eq!(q.depth("stranger"), Depth { queued: 0, running: 0 }, "nor is a tenant we know");
        assert_eq!(q.select(now).len(), 10_002, "and both are still scheduled");
    }

    #[test]
    fn a_step_the_fleet_refused_goes_back_to_the_queue_rather_than_holding_a_slot() {
        // `NoCapacity` is a wait (design D§4.5), so the grant must not keep occupying the tenant's
        // concurrency cap — otherwise a fleet that is briefly full would permanently retire slots
        // from every tenant that touched it.
        let cfg = config()
            .with_plan("t", TenantPlan { max_running_steps: 1, ..TenantPlan::default() });
        let mut q = queue(cfg);
        let now = Instant::now();
        flood(&mut q, "t", 2);

        let g = q.select(now).first().cloned().expect("a grant");
        assert_eq!(q.depth("t"), Depth { queued: 1, running: 1 });
        q.requeue(&g.job_id, &g.step_id, "test", now);
        assert_eq!(q.depth("t"), Depth { queued: 2, running: 0 }, "the slot is back");
        assert_eq!(q.select(now).len(), 1, "and the tenant can be served again");

        // And the refusal taught the estimator nothing. If it had recorded the zero seconds this
        // step "ran" for, every later step of this key would tag at the floor cost and the tenant
        // whose work the fleet keeps refusing would end up *outbidding* everyone else.
        assert_eq!(q.estimate("t", "test"), 60.0, "a step that never ran says nothing about cost");
    }

    #[test]
    fn a_terminal_step_teaches_the_estimator_what_that_step_key_costs() {
        // Design D§4.5: "`cost` is estimated node-seconds (historical p50 for that `step_key`, else a
        // default)". The estimate is per (tenant, step name) — a shared one would answer "has anyone
        // else run this", which is the timing oracle of D§6.1.
        let mut q = queue(config());
        let now = Instant::now();
        assert_eq!(q.estimate("acme", "test"), 60.0, "no history, so the default");

        q.admit_job("j", "acme", Priority::Interactive);
        for i in 0..3 {
            q.enqueue("j", &format!("s{i}"), "test");
        }
        for (i, g) in q.select(now).into_iter().enumerate() {
            q.finish(&g.job_id, &g.step_id, now + Duration::from_secs(10 * (i as u64 + 1)));
        }
        assert_eq!(q.estimate("acme", "test"), 20.0, "p50 of 10s, 20s, 30s");
        assert_eq!(q.estimate("other", "test"), 60.0, "and it never crosses a tenant boundary");
    }

    #[test]
    fn the_virtual_charge_is_for_the_step_that_actually_went_out() {
        // The tag and the dispatch must name the same step. When they were computed separately
        // nothing caught the difference, because in every test the two heads cost the same — and the
        // bug it hides is a good one: park one cheap background step behind expensive interactive
        // work and the tenant is billed for the cheap one on every turn.
        let mut q = queue(FairShare { fleet_slots: Some(1), ..config() });
        let now = Instant::now();
        q.observe_cost("acme", "slow", Duration::from_secs(600));
        q.observe_cost("acme", "quick", Duration::from_secs(1));

        q.admit_job("nightly", "acme", Priority::Background);
        q.enqueue("nightly", "bg-0", "quick");
        q.admit_job("click", "acme", Priority::Interactive);
        q.enqueue("click", "fg-0", "slow");

        let granted = q.select(now);
        assert_eq!(granted[0].step_id, "fg-0", "the interactive step goes");
        assert_eq!(q.tenants["acme"].vft_last, 600.0, "and 600 node-seconds is what it costs");
    }

    #[test]
    fn reconcile_derives_the_accounting_from_what_the_steps_actually_are() {
        // The scheduler is told nothing; it looks. This is the path every driver pass takes, and it
        // has to be idempotent, because the driver runs it on every wake.
        let mut q = queue(config());
        let now = Instant::now();
        let view = |state: StepState| JobView {
            job_id: "j1".into(),
            tenant: "acme".into(),
            priority: Priority::Interactive,
            steps: vec![StepView {
                step_id: "s0".into(),
                name: "test".into(),
                state,
                started_at: Some(now),
                finished_at: Some(now + Duration::from_secs(5)),
            }],
        };

        q.reconcile(&view(StepState::Pending), now);
        assert_eq!(q.depth("acme"), Depth { queued: 0, running: 0 }, "a gated step is not queued");

        q.reconcile(&view(StepState::Ready), now);
        q.reconcile(&view(StepState::Ready), now);
        assert_eq!(q.depth("acme"), Depth { queued: 1, running: 0 }, "and it is queued exactly once");

        assert_eq!(q.select(now).len(), 1);
        q.reconcile(&view(StepState::Running), now);
        assert_eq!(q.depth("acme"), Depth { queued: 0, running: 1 });

        // Back to `ready` is a lost lease (design D§5.3) — it must return to the queue, not vanish.
        q.reconcile(&view(StepState::Ready), now);
        assert_eq!(q.depth("acme"), Depth { queued: 1, running: 0 });

        q.reconcile(&view(StepState::Passed), now);
        assert_eq!(q.depth("acme"), Depth { queued: 0, running: 0 }, "and finishing releases it");
    }

    #[test]
    fn a_cancelled_step_is_dropped_when_the_scheduler_next_looks_at_it() {
        // Lazy deletion: fail-fast (design D§6.6) cancels steps by the hundred, and walking a
        // ten-thousand-entry deque per cancel would make the cheap case pay for the rare one.
        let mut q = queue(FairShare { fleet_slots: Some(1), ..config() });
        let now = Instant::now();
        flood(&mut q, "t", 3);
        q.release("t", "t-0", now);
        q.release("t", "t-1", now);

        let order = q.select(now);
        assert_eq!(order.len(), 1);
        assert_eq!(order[0].step_id, "t-2", "the cancelled entries are skipped, not served");
    }

    #[test]
    fn forgetting_a_job_returns_everything_it_held() {
        let mut q = queue(config());
        let now = Instant::now();
        flood(&mut q, "t", 4);
        q.select(now);
        assert_eq!(q.depth("t"), Depth { queued: 0, running: 4 });

        q.forget_job("t", now + Duration::from_secs(30));
        assert_eq!(q.depth("t"), Depth { queued: 0, running: 0 }, "a settled job holds nothing");
    }

    #[test]
    fn a_misconfigured_weight_cannot_buy_infinite_priority() {
        // A zero weight divides to infinity and a negative one flips the comparison; either way the
        // tenant would be served forever. Silently wrong in the operator's favour is not acceptable
        // for the one number the whole mechanism divides by.
        for weight in [0.0, -4.0, f64::NAN] {
            let cfg = config().with_plan("bad", TenantPlan { weight, ..TenantPlan::default() });
            let mut q = queue(FairShare { fleet_slots: Some(1), ..cfg });
            let now = Instant::now();
            flood(&mut q, "bad", 10);
            flood(&mut q, "good", 10);
            let order = serve(&mut q, 4, now);
            assert_eq!(order, ["bad", "good", "bad", "good"], "weight {weight} fell back to 1.0");
        }
    }
}
