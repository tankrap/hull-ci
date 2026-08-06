//! Read-only, owned views of control-plane state — the only door an operator surface gets in.
//!
//! Design D§11 asks for one operator dashboard ("where is time going right now"). Anything that
//! renders that is **cross-tenant by nature**: it shows every tenant's jobs to one viewer. So the
//! shape of this module is a security decision, not an ergonomics one.
//!
//! ## Two rules, both structural
//!
//! 1. **Owned copies, never `&Job`.** A borrow would hand the caller `Job::dispatch`, and a
//!    `Dispatch` carries `source_url`, `callback_url` and `fetch_token` — the credentials and
//!    capability URLs spec §14.2 keeps away from everything that is not the fetch broker. There is
//!    no field on [`JobSnapshot`] that can carry any of them, so a renderer cannot leak one by
//!    accident, by refactor, or by being asked to add "just the callback URL for debugging".
//!    D§1's through-line, applied here: *where a control could be "filter it out", prefer "there is
//!    nothing to filter"*.
//! 2. **The untrusted fields are named as untrusted.** [`StepSnapshot::detail`] and
//!    [`VerdictSnapshot::summary`] are built from job output (spec §14.5). They have been through
//!    `sanitize_summary`, which strips control characters and caps length — it does **not** make
//!    them safe to interpolate into HTML, SQL, or a shell. That is the consumer's job and the doc
//!    comments say so at every hop.
//!
//! Nothing here mutates. Every method takes `&self`, copies under the existing lock, and returns.

use std::time::{Duration, Instant};

use hull_ci_proto::{AuthorClass, Reason, Status};

use crate::control::Control;
use crate::fairshare::{Admission, Depth};
use crate::model::{Job, JobState, StepState};

/// One step, as an operator sees it.
#[derive(Debug, Clone)]
pub struct StepSnapshot {
    pub step_id: String,
    /// The step's pipeline name — author-controlled text from `.hull/ci.star`. Untrusted, like
    /// everything else the tree supplies.
    pub name: String,
    pub state: StepState,
    pub attempt: u32,
    /// The node holding (or that held) the lease. Verdict integrity is this field (design D§10.4).
    pub node_id: Option<String>,
    pub exit_code: Option<i32>,
    /// **UNTRUSTED** — built from job stdout/stderr (spec §14.5). Sanitized for control characters
    /// and length; *not* escaped for any output format. Escape it again at the boundary you render
    /// it into.
    pub detail: String,
    /// How long the step has been running, or ran for. `None` before a node took it.
    pub ran_for: Option<Duration>,
}

/// The one verdict, if the job has reached it.
#[derive(Debug, Clone)]
pub struct VerdictSnapshot {
    pub status: Status,
    /// Present exactly when `status` is `errored` (design G4).
    pub reason: Option<Reason>,
    /// **UNTRUSTED** — see [`StepSnapshot::detail`]. `details_url` is deliberately absent: a
    /// snapshot that carried no URL at all is a rule that can be tested in one line.
    pub summary: Option<String>,
}

/// One job, as an operator sees it: enough to answer "what is this and why is it taking so long",
/// and nothing that could be replayed against Hull.
#[derive(Debug, Clone)]
pub struct JobSnapshot {
    pub job_id: String,
    /// The tenant half of `repo` — the isolation boundary every quota and cache key is kept per
    /// (design D§1).
    pub tenant: String,
    pub repo: String,
    pub tree_id: String,
    /// Derived from the actor and repo membership; never assertable by a pipeline (design D§1).
    pub author_class: AuthorClass,
    pub state: JobState,
    /// Since the dispatch was accepted.
    pub age: Duration,
    /// Since the job reached a verdict, or `None` while it is live.
    pub settled_for: Option<Duration>,
    /// Attempts made, known once delivery has *finished*. See [`delivering`](Self::delivering) for
    /// the live view — the two answer different questions, and reading the settled one as though it
    /// were live is exactly what made a retrying job look inert.
    pub report_attempts: u32,
    /// The delivery in flight right now, or `None` when there is none.
    ///
    /// "attempt 3 of 12, waiting" and "nothing happening" are genuinely different states, and before
    /// this existed an operator could only ever see the second (design D§11.1).
    pub delivering: Option<crate::callback::DeliveryProgress>,
    /// How many distinct `callback_url`s are waiting on this verdict — the *count*, because two
    /// changes sharing a tree is the interesting operational fact and the URLs themselves are not
    /// ours to hand out (see [`Job::callback_urls`]).
    pub callback_targets: usize,
    pub steps: Vec<StepSnapshot>,
    pub verdict: Option<VerdictSnapshot>,
}

/// What one tenant is currently getting from the fleet.
#[derive(Debug, Clone)]
pub struct TenantSnapshot {
    pub tenant: String,
    /// Queued and running steps, from the scheduler's own accounting.
    pub depth: Depth,
    /// Which plan caps this tenant is over, if any — the reason its queued steps are being skipped.
    pub admission: Admission,
    pub weight: f64,
    pub max_running_steps: usize,
    pub node_minutes_per_hour: f64,
    /// Node-seconds consumed in the rolling hour. Measured, not estimated.
    pub node_seconds_used: f64,
    /// Jobs of this tenant still held in the store, live or retained.
    pub jobs_held: usize,
}

impl Control {
    /// Every job still in the store, newest dispatch first, redacted per this module's rules.
    ///
    /// One pass under the job lock. It is O(jobs × steps) in a copy, which is why the caller is
    /// expected to be an operator page on a human's refresh interval and not anything on the
    /// dispatch path.
    pub fn snapshot_jobs(&self) -> Vec<JobSnapshot> {
        let now = Instant::now();
        let mut jobs: Vec<JobSnapshot> =
            self.with_jobs(|iter| iter.map(|job| snapshot_job(job, now)).collect());
        // Newest first — least age first. The thing an operator wants is what just happened, and a
        // store holding an hour of settled jobs would otherwise bury it.
        jobs.sort_by(|a, b| a.age.cmp(&b.age));
        jobs
    }

    /// The fair-share picture for the tenants that currently have jobs in the store.
    ///
    /// Assembled tenant by tenant from [`Control::queue_depth`] and [`Control::queue_admission`],
    /// both of which answer only about the tenant named. There is deliberately no "give me every
    /// tenant in the queue" accessor on [`FairQueue`]: its absence is the control for D§1's
    /// scheduler-side-channel row, and an operator page is not a reason to weaken it. What this
    /// enumerates is the *job store*, which the same operator is already looking at.
    ///
    /// [`FairQueue`]: crate::fairshare::FairQueue
    pub fn snapshot_tenants(&self) -> Vec<TenantSnapshot> {
        let now = Instant::now();
        let mut tenants: Vec<(String, usize)> = Vec::new();
        self.with_jobs(|iter| {
            for job in iter {
                let tenant = job.dispatch.tenant();
                match tenants.iter_mut().find(|(name, _)| name == tenant) {
                    Some((_, held)) => *held += 1,
                    None => tenants.push((tenant.to_string(), 1)),
                }
            }
        });
        tenants.sort_by(|a, b| a.0.cmp(&b.0));

        tenants
            .into_iter()
            .map(|(tenant, jobs_held)| {
                let plan = self.config().fair_share.plan(&tenant);
                TenantSnapshot {
                    depth: self.queue_depth(&tenant),
                    admission: self.queue_admission(&tenant, now),
                    weight: plan.weight,
                    max_running_steps: plan.max_running_steps,
                    node_minutes_per_hour: plan.node_minutes_per_hour,
                    node_seconds_used: self.queue_node_seconds(&tenant, now),
                    jobs_held,
                    tenant,
                }
            })
            .collect()
    }
}

fn snapshot_job(job: &Job, now: Instant) -> JobSnapshot {
    JobSnapshot {
        job_id: job.id.clone(),
        tenant: job.dispatch.tenant().to_string(),
        repo: job.dispatch.repo.clone(),
        tree_id: job.dispatch.tree_id.clone(),
        author_class: job.author_class,
        state: job.state,
        age: now.saturating_duration_since(job.created_at),
        settled_for: job.settled_at.map(|t| now.saturating_duration_since(t)),
        report_attempts: job.report_attempts,
        delivering: job.delivery,
        callback_targets: job.callback_urls.len(),
        steps: job
            .steps
            .iter()
            .map(|s| StepSnapshot {
                step_id: s.id.clone(),
                name: s.spec.name.clone(),
                state: s.state,
                attempt: s.attempt,
                node_id: s.node_id.clone(),
                exit_code: s.exit_code,
                detail: s.detail.clone(),
                ran_for: s.started_at.map(|start| {
                    s.finished_at.unwrap_or(now).saturating_duration_since(start)
                }),
            })
            .collect(),
        verdict: job.verdict.as_ref().map(|v| VerdictSnapshot {
            status: v.status,
            reason: v.reason,
            summary: v.summary.clone(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{dispatch, fast_config, harness, NodeMode, OkFetcher, StaticPlanner};
    use std::sync::Arc;

    /// A control plane holding one accepted job, with the fleet refusing everything so the job sits
    /// still while the snapshot is taken.
    fn parked() -> Arc<Control> {
        harness(
            fast_config(),
            Arc::new(OkFetcher),
            Arc::new(StaticPlanner::steps(1)),
            NodeMode::NoCapacity,
        )
        .control
    }

    #[tokio::test]
    async fn a_snapshot_carries_no_url_and_no_token_from_the_dispatch() {
        // The rule this module exists to make structural (spec §14.2). Asserted against the fields a
        // real dispatch actually carries, so adding a URL to `JobSnapshot` later fails here.
        let control = parked();
        let mut d = dispatch("acme/widget", "tree1");
        d.fetch_token = Some("tok-do-not-leak".into());
        d.source_url = "https://hull.example/api/tree/tree1/tar?sig=do-not-leak".into();
        control.accept(d);

        let jobs = control.snapshot_jobs();
        assert_eq!(jobs.len(), 1);
        let rendered = format!("{:?}", jobs[0]);
        assert!(!rendered.contains("do-not-leak"), "no dispatch credential survives the copy");
        assert!(!rendered.contains("hull.example"), "and no URL does either: {rendered}");
        assert_eq!(jobs[0].tenant, "acme", "the tenant is the isolation boundary, so it is kept");
        assert_eq!(jobs[0].callback_targets, 1, "the count is the operational fact, not the URL");
    }

    #[tokio::test]
    async fn the_tenant_view_is_assembled_from_per_tenant_answers_only() {
        let control = parked();
        control.accept(dispatch("acme/widget", "tree1"));
        control.accept(dispatch("acme/other", "tree2"));
        control.accept(dispatch("globex/thing", "tree3"));

        let tenants = control.snapshot_tenants();
        let names: Vec<&str> = tenants.iter().map(|t| t.tenant.as_str()).collect();
        assert_eq!(names, ["acme", "globex"], "one row per tenant with work, sorted");
        assert_eq!(tenants[0].jobs_held, 2);
        assert_eq!(tenants[0].max_running_steps, control.config().fair_share.default_plan.max_running_steps);
        assert!(!tenants[0].admission.blocked(), "a roomy default plan blocks nobody");
    }
}
