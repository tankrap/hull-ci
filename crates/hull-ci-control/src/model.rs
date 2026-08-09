//! The job and step model — design D§4.3.
//!
//! ```text
//! job  : queued → fetching → planning → running → {green | red | errored} → reported
//! step : pending → ready → leased → running → {passed | failed | errored | cached | skipped}
//! ```
//!
//! `reported` is deliberately **not** part of the verdict. The verdict is what the job decided; the
//! report state is whether Hull has heard about it. Keeping them apart is what lets the callback
//! sender retry for an hour (design D§10.1) without the job pretending to still be running, and what
//! lets a duplicate dispatch (spec §9) re-report a finished job without re-running a single step.
//!
//! The transition tables are exhaustive rather than permissive: an illegal transition is a bug we
//! want to fail loudly on in a test, not silently absorb into a wrong verdict.

use std::time::{Duration, Instant};

use hull_ci_proto::{AuthorClass, Dispatch, Reason, Status, Verdict};

pub type JobId = String;
pub type StepId = String;

/// Where a job is in its life. `Green`/`Red`/`Errored` mirror [`Status`]; the two report states are
/// the delivery half (design D§10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Queued,
    Fetching,
    Planning,
    Running,
    Green,
    Red,
    Errored,
    /// The verdict reached Hull.
    Reported,
    /// Retries exhausted. Parked and alerted — never silently dropped (design D§10.1).
    ReportFailed,
}

impl JobState {
    pub fn from_status(status: Status) -> JobState {
        match status {
            Status::Green => JobState::Green,
            Status::Red => JobState::Red,
            Status::Errored => JobState::Errored,
        }
    }

    /// A job that has decided. It may still owe Hull a callback.
    pub fn has_verdict(self) -> bool {
        matches!(
            self,
            JobState::Green
                | JobState::Red
                | JobState::Errored
                | JobState::Reported
                | JobState::ReportFailed
        )
    }

    /// A job that will never run another step. Duplicate dispatch re-reports these (spec §9).
    pub fn is_finished(self) -> bool {
        self.has_verdict()
    }

    /// Hull has **not** confirmed hearing this job's answer.
    ///
    /// True in every state except [`Reported`](JobState::Reported), the live ones included, because
    /// this is the in-memory spelling of exactly the condition under which the write-ahead journal
    /// keeps an entry (see [`crate::journal`]): the entry is written at accept and dropped only when a
    /// delivery lands. The two readings have to agree. A debt the journal still holds but that memory
    /// has already forgotten cannot be retried by this process at all — nothing in it can see the
    /// entry — and spec §10 gives no second chance, since Hull never polls us and clears its in-flight
    /// set only in the callback handler. The tree then stays wedged until a human forces a rerun.
    ///
    /// Used by [`JobStore::evict`](crate::store::JobStore::evict) to decide what retention may drop.
    pub fn owes_a_verdict(self) -> bool {
        !matches!(self, JobState::Reported)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            JobState::Queued => "queued",
            JobState::Fetching => "fetching",
            JobState::Planning => "planning",
            JobState::Running => "running",
            JobState::Green => "green",
            JobState::Red => "red",
            JobState::Errored => "errored",
            JobState::Reported => "reported",
            JobState::ReportFailed => "report_failed",
        }
    }

    /// The legal edges of design D§4.3, plus two the prose implies:
    /// * any pre-verdict state may jump straight to `errored` — the job wall clock (D§10.2) and a
    ///   fetch failure both fire before `running` exists;
    /// * `report_failed` may return to `reported`, because an operator-driven redelivery of a parked
    ///   job is a heal, not a new job.
    pub fn can_transition_to(self, next: JobState) -> bool {
        use JobState::*;
        match (self, next) {
            (Queued, Fetching) => true,
            (Fetching, Planning) => true,
            (Planning, Running) => true,
            (Running, Green | Red | Errored) => true,
            // Planning may decide the verdict without ever running: "nothing detectable to run"
            // is `errored` with `reason: no_tests` (design D§4.4).
            (Queued | Fetching | Planning, Errored) => true,
            (Green | Red | Errored, Reported | ReportFailed) => true,
            (ReportFailed, Reported) => true,
            _ => false,
        }
    }
}

/// Where one step is. `Cached` is a memo hit (design D§6.1) and `Skipped` is a sibling cancelled by
/// fail-fast (design D§6.6); both are terminal and neither is a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepState {
    Pending,
    Ready,
    Leased,
    Running,
    Passed,
    Failed,
    Errored,
    Cached,
    Skipped,
}

impl StepState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            StepState::Passed
                | StepState::Failed
                | StepState::Errored
                | StepState::Cached
                | StepState::Skipped
        )
    }

    /// Still occupying capacity somewhere — a candidate for fail-fast cancellation.
    pub fn is_in_flight(self) -> bool {
        !self.is_terminal()
    }

    pub fn as_str(self) -> &'static str {
        match self {
            StepState::Pending => "pending",
            StepState::Ready => "ready",
            StepState::Leased => "leased",
            StepState::Running => "running",
            StepState::Passed => "passed",
            StepState::Failed => "failed",
            StepState::Errored => "errored",
            StepState::Cached => "cached",
            StepState::Skipped => "skipped",
        }
    }

    pub fn can_transition_to(self, next: StepState) -> bool {
        use StepState::*;
        match (self, next) {
            (Pending, Ready) => true,
            (Ready, Leased) => true,
            (Leased, Running) => true,
            (Leased | Running, Passed | Failed | Errored) => true,
            // A lease that expires puts the step back on the queue (design D§5.3).
            (Leased | Running, Ready) => true,
            // A memo hit resolves a step before it is ever scheduled (design D§6.1).
            (Pending | Ready, Cached) => true,
            // The other half of a memo hit. A recorded `failed` is real signal about the code on
            // exactly these inputs (D§6.1), and it is served as `failed` rather than as `cached`,
            // because `cached` folds green (see `aggregate::fold`) — marking a remembered failure
            // `cached` would turn a red job green, which is the worst bug this layer could have.
            (Pending | Ready, Failed) => true,
            // Fail-fast cancels anything not yet terminal (design D§6.6).
            (Pending | Ready | Leased | Running, Skipped) => true,
            // Queue-wait / step wall clock expiry (design D§10.2).
            (Pending | Ready, Errored) => true,
            _ => false,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StateError {
    #[error("illegal job transition {from} → {to}")]
    Job { from: &'static str, to: &'static str },
    #[error("illegal step transition {from} → {to}")]
    Step { from: &'static str, to: &'static str },
}

/// What the planner emitted for one step. `argv` is opaque data that is executed **inside the
/// sandbox only** (design D§4.4) — the control plane never runs it, never shells it out, and never
/// interpolates it into anything.
#[derive(Debug, Clone)]
pub struct StepSpec {
    pub name: String,
    pub argv: Vec<String>,
    pub image: String,
    /// Pipeline override for the step wall clock; `None` takes the default (design D§10.2).
    pub timeout: Option<Duration>,
    /// A failure here does not decide the job red (design D§6.6).
    pub continue_on_error: bool,
    /// Names of steps that must reach a terminal, non-failing state before this one may be scheduled
    /// (design D§4.4 `needs`).
    ///
    /// Empty means "ready immediately", which is every step in M1 and why M1 could schedule the whole
    /// plan at once. The planner guarantees the graph is acyclic — a `needs` target must already have
    /// been declared when the step is evaluated — so nothing downstream has to detect cycles at
    /// runtime; it only has to respect the edges.
    pub needs: Vec<String>,
    /// Tenant secret **names** this step declared (design D§7.4).
    ///
    /// Carried through the control plane and out onto the [`Assignment`](hull_ci_proto::Assignment)
    /// unchanged, and never resolved here: the control plane holds no key material and has no way to
    /// turn one of these into a value. It is a request the secret broker adjudicates against the
    /// job's author class, which is a fact about the actor and not something this list can raise.
    pub secrets: Vec<String>,
    /// Path globs deciding this step's memo key (design D§6.1) — the pipeline's `inputs`.
    ///
    /// Resolved against the *verified tree* by [`SubtreeDigest`](crate::memo::SubtreeDigest), never
    /// here: the control plane touches no filesystem (spec §14.1), so a glob is a string until the
    /// digest seam expands it.
    ///
    /// **Empty means "never cacheable"**, not "no restriction". An empty input set would key every
    /// run of this step identically and serve the first `passed` forever — see
    /// [`NotCacheable::NoInputs`](crate::memo::NotCacheable::NoInputs).
    pub inputs: Vec<String>,
    /// Environment the step is permitted to see, as `(name, value)` — D§6.1's `env_allowlist_values`.
    ///
    /// **Values, not just names.** The same step run with `PROFILE=release` did different work from
    /// the same step run with `PROFILE=debug`, so a key over names alone would serve one build's
    /// verdict for the other's.
    pub env_allowlist: Vec<(String, String)>,
}

impl StepSpec {
    pub fn new(name: impl Into<String>, argv: Vec<String>, image: impl Into<String>) -> Self {
        StepSpec {
            name: name.into(),
            argv,
            image: image.into(),
            timeout: None,
            continue_on_error: false,
            needs: Vec::new(),
            secrets: Vec::new(),
            // Empty by default, which means **not cacheable** by default (design D§6.1). A planner
            // that has not been taught to carry `inputs` through therefore gets the old behaviour —
            // every step runs — rather than a memo keyed on nothing.
            inputs: Vec::new(),
            env_allowlist: Vec::new(),
        }
    }

    /// Declare the steps this one waits on (design D§4.4).
    pub fn needs(mut self, needs: Vec<String>) -> Self {
        self.needs = needs;
        self
    }

    /// Declare the tenant secret names this step asks for (design D§7.4). A request, not a grant.
    pub fn secrets(mut self, secrets: Vec<String>) -> Self {
        self.secrets = secrets;
        self
    }

    /// Declare the path globs this step's memo key is computed over (design D§6.1). Declaring none
    /// is what makes a step uncacheable.
    pub fn inputs(mut self, inputs: Vec<String>) -> Self {
        self.inputs = inputs;
        self
    }

    /// Declare the environment the step is allowed to see, values included (design D§6.1).
    pub fn env_allowlist(mut self, env: Vec<(String, String)>) -> Self {
        self.env_allowlist = env;
        self
    }

    pub fn continue_on_error(mut self) -> Self {
        self.continue_on_error = true;
        self
    }
}

#[derive(Debug, Clone)]
pub struct Step {
    pub id: StepId,
    pub spec: StepSpec,
    pub state: StepState,
    pub attempt: u32,
    /// The node holding the lease. Verdict integrity (design D§10.4) is exactly this field: a result
    /// from anyone else is dropped.
    pub node_id: Option<String>,
    pub lease_expires_at: Option<Instant>,
    /// When the step became schedulable — the clock the queue-wait timeout runs against.
    pub ready_at: Option<Instant>,
    /// When a node actually started it — the clock the step wall clock runs against.
    pub started_at: Option<Instant>,
    pub finished_at: Option<Instant>,
    pub exit_code: Option<i32>,
    pub log_key: Option<String>,
    /// Node-supplied detail. **Untrusted** (spec §14.5): sanitize on every use.
    pub detail: String,
    /// Set only when `state == Errored`, so the aggregator can name a [`Reason`] instead of guessing.
    pub error_reason: Option<Reason>,
    /// This step's memo key (design D§6.1), or `None` when the step is not cacheable at all.
    ///
    /// `None` is the common and safe case — a step with no declared `inputs`, a glob that resolved
    /// to nothing, an uncacheable dependency, or a control plane with no digester wired. It is
    /// deliberately the *only* thing that gates a memo write: a step with no key is never looked up
    /// and never recorded, so every refusal in [`crate::memo`] holds in both directions with no
    /// second check to keep in sync.
    pub memo_key: Option<crate::memo::StepKey>,
}

impl Step {
    pub fn new(id: StepId, spec: StepSpec) -> Self {
        Step {
            id,
            spec,
            state: StepState::Pending,
            attempt: 0,
            node_id: None,
            lease_expires_at: None,
            ready_at: None,
            started_at: None,
            finished_at: None,
            exit_code: None,
            log_key: None,
            detail: String::new(),
            error_reason: None,
            memo_key: None,
        }
    }

    pub fn transition(&mut self, next: StepState) -> Result<(), StateError> {
        if !self.state.can_transition_to(next) {
            return Err(StateError::Step { from: self.state.as_str(), to: next.as_str() });
        }
        self.state = next;
        Ok(())
    }

    /// A failure that does not decide the verdict (design D§6.6) still counts as "we ran it".
    pub fn failed_fatally(&self) -> bool {
        self.state == StepState::Failed && !self.spec.continue_on_error
    }
}

#[derive(Debug, Clone)]
pub struct Job {
    pub id: JobId,
    /// The dispatch verbatim. `callback_url` and `source_url` are **opaque** (spec §5) and are only
    /// ever used as received.
    pub dispatch: Dispatch,
    /// Derived from the actor, never assertable by a pipeline (design D§1).
    pub author_class: AuthorClass,
    pub state: JobState,
    pub steps: Vec<Step>,
    pub verdict: Option<Verdict>,
    pub created_at: Instant,
    /// The job wall clock (design D§10.2, default 60 min).
    pub deadline_at: Instant,
    pub report_attempts: u32,
    /// Every distinct `callback_url` that has asked about this tree, in arrival order, starting with
    /// the dispatch that created the job.
    ///
    /// **Work is deduplicated by `(repo, tree_id)`; delivery is not.** Two different changes can share
    /// one tree — that is the entire premise of tree-keyed memoization (a rebase, a cherry-pick, a
    /// revert of a revert) — and each arrives with its *own* `callback_url`. Spec §9 says Hull's
    /// in-flight de-dup is best-effort and in-memory, so a second dispatch for a tree we already know
    /// is expected: after a Hull restart, across replicas, or with `{"force": true}`. Reporting only
    /// to the first URL would leave that second change unverified forever, waiting on an answer that
    /// was delivered somewhere else. §9's own wording is the hint — be idempotent "per `(tree_id)`
    /// **or** per `callback_url`": the tree keys the *work*, the callback keys the *answer*.
    pub callback_urls: Vec<String>,
    /// What the callback sender is doing right now, while it is doing it.
    ///
    /// `None` before delivery starts and after it stops. Everything else about a job is observable
    /// while it happens; delivery was the exception, and it is the one an operator asks about when a
    /// deployment looks stuck (design D§11.1). `report_attempts` remains the *settled* count — this
    /// is the live one, and they answer different questions.
    pub delivery: Option<crate::callback::DeliveryProgress>,
    /// A delivery attempt owns this job's verdict **right now**.
    ///
    /// The claim that keeps two senders off one job (see `Control::claim_delivery`). Taken and
    /// released under the store lock, so the check and the take are one step: a verdict delivered
    /// twice is harmless by spec §9, but two senders racing on the same job also race on
    /// `report_attempts`, on the `Reported` transition, and on the journal entry one of them is about
    /// to forget while the other is still trying.
    ///
    /// **Not** [`delivery`](Self::delivery), which is observability: that field is published by the
    /// sender's progress sink and is therefore `None` for the whole window between a delivery being
    /// decided on and its first attempt beginning. A guard reading it would have a hole exactly one
    /// task-spawn wide — which is precisely the moment the redelivery drain runs, since both are
    /// started from an arriving dispatch.
    pub delivering: bool,
    /// When a delivery for this job was last claimed or released — the clock the redelivery cooldown
    /// runs against (see `ControlConfig::redeliver_interval`).
    ///
    /// Stamped at both ends of a delivery, so the cooldown measures the gap *between* runs rather than
    /// between their starts: a run against an unreachable Hull spends the whole retry budget, and a
    /// cooldown measured from its start would already have expired by the time that run gave up.
    pub last_delivery_at: Option<Instant>,
    /// When this job first reached a terminal state, for retention (see [`JobStore::evict`]).
    ///
    /// `None` while the job is live, which is what makes eviction safe by construction: there is no
    /// value to compare against, so a running job cannot be swept out from under its own driver.
    ///
    /// [`JobStore::evict`]: crate::store::JobStore::evict
    pub settled_at: Option<Instant>,
}

impl Job {
    /// Record a `callback_url` that must receive this job's verdict. Returns whether it was new.
    ///
    /// De-duplicated, because an ordinary retry of the *same* dispatch must not make us deliver the
    /// same verdict twice to the same place.
    pub fn add_callback_url(&mut self, url: &str) -> bool {
        if self.callback_urls.iter().any(|u| u == url) {
            return false;
        }
        self.callback_urls.push(url.to_string());
        true
    }
}

impl Job {
    pub fn new(
        id: JobId,
        dispatch: Dispatch,
        author_class: AuthorClass,
        now: Instant,
        job_timeout: Duration,
    ) -> Self {
        let callback_urls = vec![dispatch.callback_url.clone()];
        Job {
            id,
            dispatch,
            author_class,
            state: JobState::Queued,
            steps: Vec::new(),
            verdict: None,
            created_at: now,
            deadline_at: now + job_timeout,
            report_attempts: 0,
            callback_urls,
            delivery: None,
            delivering: false,
            last_delivery_at: None,
            settled_at: None,
        }
    }

    /// A verdict Hull never received, that nothing is currently retrying, and that has been left
    /// alone long enough to be worth another go.
    ///
    /// The predicate the redelivery drain selects on *and* re-checks under the lock it takes the
    /// claim with (`Control::drain_undelivered`), written once so the two cannot drift apart. Each
    /// clause prevents a different failure:
    ///
    /// * `ReportFailed` only — a job still delivering has not failed yet, and a `Reported` one has
    ///   nothing owing. Re-sending either would be traffic Hull did not need.
    /// * `!delivering` — a second sender for a job that already has one is the double-send this claim
    ///   exists to stop. During a *redelivery* the state stays `ReportFailed` the whole time, so the
    ///   state clause alone would not catch it.
    /// * the cooldown — a burst of dispatches is a burst of drains, and without this each one would
    ///   be another retry against a Hull that is, by hypothesis, still down.
    pub fn awaits_redelivery(&self, now: Instant, cooldown: Duration) -> bool {
        self.state == JobState::ReportFailed
            && !self.delivering
            && self.last_delivery_at.is_none_or(|t| now.saturating_duration_since(t) >= cooldown)
    }

    /// The idempotency key of spec §9 / design D§4.1: `(repo, tree_id)`.
    ///
    /// Returns the [`TreeKey`](crate::claims::TreeKey) the claim store is keyed by rather than a bare
    /// pair, so there is one type for this concept: the key crosses a process boundary now, and a
    /// tuple that happened to be in the right order was fine while it never left this struct.
    pub fn key(&self) -> crate::claims::TreeKey {
        crate::claims::TreeKey::new(self.dispatch.repo.clone(), self.dispatch.tree_id.clone())
    }

    pub fn transition(&mut self, next: JobState) -> Result<(), StateError> {
        self.transition_at(next, Instant::now())
    }

    /// [`transition`](Self::transition) with an explicit clock, so retention is testable without
    /// sleeping.
    pub fn transition_at(&mut self, next: JobState, now: Instant) -> Result<(), StateError> {
        if !self.state.can_transition_to(next) {
            return Err(StateError::Job { from: self.state.as_str(), to: next.as_str() });
        }
        self.state = next;
        // Stamped on the first terminal transition only. A `ReportFailed → Reported` recovery must
        // not restart the retention clock, or a job that keeps retrying delivery keeps renewing its
        // own lease on memory.
        if next.is_finished() && self.settled_at.is_none() {
            self.settled_at = Some(now);
        }
        Ok(())
    }

    pub fn step_mut(&mut self, step_id: &str) -> Option<&mut Step> {
        self.steps.iter_mut().find(|s| s.id == step_id)
    }

    pub fn step(&self, step_id: &str) -> Option<&Step> {
        self.steps.iter().find(|s| s.id == step_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_walks_the_designed_path_and_refuses_shortcuts() {
        use JobState::*;
        for (a, b) in [
            (Queued, Fetching),
            (Fetching, Planning),
            (Planning, Running),
            (Running, Green),
            (Green, Reported),
        ] {
            assert!(a.can_transition_to(b), "{a:?} → {b:?} is on the D§4.3 path");
        }
        assert!(!Queued.can_transition_to(Running), "a job cannot skip fetch and plan");
        assert!(!Reported.can_transition_to(Green), "a reported job is done");
        assert!(!Green.can_transition_to(Red), "one verdict, ever (D§6.6)");
    }

    #[test]
    fn a_job_may_error_before_it_ever_runs() {
        // Fetch timeout and "nothing detectable to run" both decide the job with no steps at all.
        assert!(JobState::Queued.can_transition_to(JobState::Errored));
        assert!(JobState::Fetching.can_transition_to(JobState::Errored));
        assert!(JobState::Planning.can_transition_to(JobState::Errored));
    }

    #[test]
    fn a_lost_lease_returns_a_step_to_the_queue_not_to_failure() {
        // Design D§5.3: a missed renewal is our problem, so the step is retried, not marked red.
        assert!(StepState::Leased.can_transition_to(StepState::Ready));
        assert!(StepState::Running.can_transition_to(StepState::Ready));
        assert!(!StepState::Passed.can_transition_to(StepState::Failed));
    }

    #[test]
    fn continue_on_error_failure_is_not_a_fatal_failure() {
        let mut s = Step::new("s1".into(), StepSpec::new("lint", vec!["x".into()], "img").continue_on_error());
        s.state = StepState::Failed;
        assert!(!s.failed_fatally());
    }
}
