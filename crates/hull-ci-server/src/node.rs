//! The [`NodeSink`] seam, backed by a [`NodeAgent`] in this process.
//!
//! M1 is explicitly *one node* (design D§13), so in-process is the right amount of machinery: no
//! lease stream, no heartbeat transport, no reconnect logic for a fleet of one that cannot partition
//! from itself. What matters is that it is in-process **behind the seam** rather than instead of it.
//! Everything on the far side of `assign` is already the shape D§5.3 describes — a leased
//! [`Assignment`] goes out, a [`StepReport`] comes back from the identity that holds the lease — so
//! M3 replaces this file with a transport and neither the control plane nor the agent changes.
//!
//! Four things this file owns, none of which the control plane may:
//!
//! 1. **The isolation gate.** `assign` runs the agent's admission check *before* leasing anything, so
//!    work no backend here can contain is refused at the door rather than discovered inside a sandbox
//!    (design D§7.2). The agent re-checks; two checks, because being wrong once is a credential
//!    exfiltration hole and being wrong the other way is a requeue.
//! 2. **Workspace materialization** (D§6.2) — see [`crate::workspace`] for why it is a copy.
//! 3. **Teardown.** The workspace is removed on every path, including cancellation, because it is
//!    single-use in the same sense the sandbox is (§14.1).
//! 4. **Minting the secret capability** (D§7.4: "At placement, control mints a short-TTL, single-use
//!    capability"). This is the placement site — the call the control plane makes to grant the lease
//!    — so it is where a capability comes into existence, and it comes into existence bound to the
//!    node that was just leased the step.
//!
//! That last point is load-bearing for a check the broker cannot make on its own. D§7.4 says "the
//! broker verifies the node is the lease-holder", and it cannot: the lease table is the control
//! plane's. What holds here instead is a property of *when*: a capability exists only because a lease
//! was just granted to this node, in this call, and it dies in sixty seconds. That is weaker than
//! consulting a lease table — it does not notice a lease revoked in between — and it is worth naming
//! as such rather than letting the code read as though the stronger check exists.
//!
//! # The one wart: reporting before the lease is recorded
//!
//! [`NodeSink::assign`] is synchronous and returns the node id; the control plane records the lease
//! *after* it returns. A step that finishes in microseconds can therefore have its report arrive
//! before the step it belongs to is marked leased, and design D§10.4 requires that a report from a
//! non-lease-holder be dropped. Rather than weaken that check — it is the thing that makes "a step may
//! run twice" harmless — the report waits, briefly and boundedly, for the lease to exist. A proper
//! handshake (`assign` returning a lease the node then presents) is the M3 fix; it needs a wire
//! protocol change, so it is not this milestone's to make.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use hull_ci_control::seams::{NodeError, NodeSink, VerifiedTree};
use hull_ci_control::{Control, ReportRejected};
use hull_ci_node::agent::NodeErrorKind;
use hull_ci_node::NodeAgent;
use hull_ci_proto::{sanitize_summary, Assignment, StepOutcome, StepReport, SUMMARY_MAX_CHARS};
use hull_ci_secrets::{CapabilityRequest, CapabilityToken, SecretError, SecretService};
use tokio::task::JoinHandle;

/// How long a finished step will wait for its own lease to be recorded before giving up. Generous
/// against the microseconds it actually takes, and bounded so a genuinely cancelled step does not
/// spin: a step whose lease never appears has been skipped, and its report is correctly dropped.
const LEASE_WAIT: Duration = Duration::from_secs(2);
const LEASE_POLL: Duration = Duration::from_millis(10);

/// A one-node "fleet" that runs assignments in this process.
pub struct InProcessFleet {
    agent: Arc<NodeAgent>,
    work_root: PathBuf,
    /// Set once, after the control plane exists. `Weak` because the control plane owns this sink
    /// (through `Deps`), and an `Arc` back would be a cycle that never drops.
    control: OnceLock<Weak<Control>>,
    /// In-flight steps, so fail-fast cancellation (D§6.6) can actually stop one.
    running: Mutex<HashMap<StepKey, JoinHandle<()>>>,
    /// The broker, on the control side of the seam. `None` in `HULL_CI_SECRETS=off`, in which case no
    /// capability is ever minted and a step that declared secrets simply runs without them.
    secrets: Option<Arc<SecretService>>,
}

type StepKey = (String, String);

impl InProcessFleet {
    pub fn new(agent: NodeAgent, work_root: PathBuf) -> Arc<Self> {
        Arc::new(InProcessFleet {
            agent: Arc::new(agent),
            work_root,
            control: OnceLock::new(),
            running: Mutex::new(HashMap::new()),
            secrets: None,
        })
    }

    /// [`new`](Self::new), with the broker this fleet mints against at placement (D§7.4).
    pub fn with_secrets(agent: NodeAgent, work_root: PathBuf, secrets: Arc<SecretService>) -> Arc<Self> {
        Arc::new(InProcessFleet {
            agent: Arc::new(agent),
            work_root,
            control: OnceLock::new(),
            running: Mutex::new(HashMap::new()),
            secrets: Some(secrets),
        })
    }

    /// Mint this placement's capability, or explain why there is none.
    ///
    /// Three outcomes, and the middle one is the interesting one:
    ///
    /// * **No broker, or nothing declared** → `Ok(None)`. The step runs with the base environment.
    /// * **`OutsiderRefused`** → `Ok(None)`, and the job *still runs*. D§7.4 is explicit that an
    ///   outsider-authored job "is passed no secret names and the broker refuses to mint a capability
    ///   for it" — refused a secret, not refused a run. That is also the boundary GitHub draws for a
    ///   fork's `pull_request` workflow. A step that needed the variable fails on its own terms,
    ///   which is the correct signal: the change genuinely cannot be verified by that step from a
    ///   fork.
    /// * **Anything else** → a refusal of the *assignment*. A member's job naming a secret that does
    ///   not exist, or a tenant with no key material, is a configuration error, and D§7.4 puts that
    ///   error at placement where it reads as one — rather than inside a sandbox spawn, where it
    ///   would look like an infrastructure flake.
    ///
    /// The author-class decision is **not** duplicated here. It belongs to the broker, which derives
    /// it from the assignment the control plane built (D§1), and a second copy of that rule in the
    /// composition root is a second place for it to drift.
    fn mint_capability(&self, a: &Assignment) -> Result<Option<CapabilityToken>, NodeError> {
        let (Some(service), false) = (&self.secrets, a.secrets.is_empty()) else {
            return Ok(None);
        };
        let request = CapabilityRequest::for_assignment(a, self.node_id(), a.secrets.clone());
        match service.mint(&request) {
            Ok((token, grant)) => {
                tracing::info!(
                    job = %a.job_id, step = %a.step_id, cap_id = %grant.cap_id,
                    // Names and the id, never a value and never the token itself.
                    names = ?grant.names, expires_at = grant.expires_at,
                    "minted a secret capability at placement"
                );
                Ok(Some(token))
            }
            Err(SecretError::OutsiderRefused) => {
                tracing::info!(
                    job = %a.job_id, step = %a.step_id, declared = ?a.secrets,
                    "outsider-authored job: no capability minted, the step runs without its declared secrets (D§7.4)"
                );
                Ok(None)
            }
            Err(e) => Err(NodeError::Rejected(format!("could not mint a secret capability: {e}"))),
        }
    }

    /// Point the fleet at the control plane it reports to.
    ///
    /// Separate from construction because the control plane is built *from* this sink: something has
    /// to be second. Reports before this is called are impossible — nothing can be assigned until the
    /// control plane exists to assign it.
    pub fn attach(&self, control: &Arc<Control>) {
        let _ = self.control.set(Arc::downgrade(control));
    }

    pub fn node_id(&self) -> &str {
        &self.agent.config().node_id
    }

    pub fn agent(&self) -> &NodeAgent {
        &self.agent
    }

    fn workspace_path(&self, a: &Assignment) -> PathBuf {
        // Both components are ids this process minted (`job_…`, `step_…`, hex only — see
        // `hull_ci_control::ids`), never bytes from a dispatch, so no path component here is
        // attacker-controlled.
        self.work_root.join(&a.job_id).join(&a.step_id)
    }
}

impl NodeSink for InProcessFleet {
    fn assign(&self, assignment: &Assignment, tree: &VerifiedTree) -> Result<String, NodeError> {
        // The gate, first and before any state changes: §14.1 / D§7.2. `admission_check` refuses
        // outsider work on a backend whose `admits_untrusted()` is false — which is every backend M1
        // has — and refuses a tier this node does not implement.
        if let Err(why) = self.agent.admission_check(assignment) {
            tracing::warn!(
                job = %assignment.job_id,
                step = %assignment.step_id,
                reason = %why,
                "refusing an assignment this node cannot contain"
            );
            return Err(NodeError::Rejected(why));
        }

        let Some(control) = self.control.get().and_then(Weak::upgrade) else {
            // Either `attach` was never called or the control plane is gone. Either way there is
            // nobody to report to, and running the job anyway would burn a sandbox for a verdict that
            // could never be delivered.
            return Err(NodeError::Rejected("node fleet is not attached to a control plane".into()));
        };

        // Minted after the isolation gate and before the lease is handed back, so a capability never
        // exists for work this node has already refused to run.
        let capability = self.mint_capability(assignment)?;

        let node_id = self.agent.config().node_id.clone();
        let key: StepKey = (assignment.job_id.clone(), assignment.step_id.clone());
        let run = Run {
            agent: Arc::clone(&self.agent),
            control,
            node_id: node_id.clone(),
            assignment: assignment.clone(),
            tree_path: tree.path.clone(),
            workspace: self.workspace_path(assignment),
            capability,
        };

        let handle = tokio::spawn(run.execute());
        self.running.lock().unwrap_or_else(|e| e.into_inner()).insert(key, handle);
        Ok(node_id)
    }

    fn cancel(&self, job_id: &str, step_id: &str) {
        let key: StepKey = (job_id.to_string(), step_id.to_string());
        let handle = self.running.lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
        let Some(handle) = handle else { return };

        // Aborting drops the sandbox instance mid-`exec`; the backends set `kill_on_drop`, so the
        // child dies with it. That is teardown by destructor rather than by protocol — honest for one
        // in-process node, and exactly what M3's real lease revocation replaces.
        handle.abort();
        let workspace = self.work_root.join(job_id).join(step_id);
        tokio::task::spawn_blocking(move || crate::workspace::discard(&workspace));
        tracing::info!(job = %job_id, step = %step_id, "assignment cancelled");
    }
}

/// One assignment's life on this node, owned by the spawned task so nothing borrows the sink.
struct Run {
    agent: Arc<NodeAgent>,
    control: Arc<Control>,
    node_id: String,
    assignment: Assignment,
    tree_path: PathBuf,
    workspace: PathBuf,
    /// This placement's capability, if one was minted. Travels with the run rather than on the
    /// [`Assignment`] — a bearer credential does not belong on the value that is serialized and
    /// logged (see the field's note on `Assignment::secrets`).
    capability: Option<CapabilityToken>,
}

impl Run {
    async fn execute(self) {
        let report = match self.materialize().await {
            Ok(()) => {
                self.agent.note_warm_tree(self.assignment.tree_id.clone());
                self.agent
                    .run_assignment_with(&self.assignment, &self.workspace, self.capability.as_ref())
                    .await
            }
            // A workspace we could not build is our failure, and the step never ran: `errored` with
            // the infra marker, never `red` (spec §7).
            Err(detail) => infra_error(&self.assignment, &detail),
        };

        deliver(&self.control, &report, &self.node_id).await;

        let workspace = self.workspace.clone();
        let _ = tokio::task::spawn_blocking(move || crate::workspace::discard(&workspace)).await;
    }

    async fn materialize(&self) -> Result<(), String> {
        let (tree, workspace) = (self.tree_path.clone(), self.workspace.clone());
        match tokio::task::spawn_blocking(move || crate::workspace::materialize(&tree, &workspace)).await {
            Ok(Ok(report)) => {
                // Logged rather than ignored because it is the only way an operator learns that a
                // deployment is byte-copying every tree — the symptom is otherwise "the runner is
                // slow", with no hint that `HULL_CI_STORE_ROOT` and `HULL_CI_WORK_ROOT` are on two
                // filesystems or that the store's filesystem has no reflink (see [`crate::workspace`]).
                tracing::debug!(
                    job = %self.assignment.job_id,
                    step = %self.assignment.step_id,
                    cloned = report.cloned,
                    copied = report.copied,
                    fallback_reason = report.fallback_reason.as_deref().unwrap_or("-"),
                    "materialized the workspace"
                );
                Ok(())
            }
            Ok(Err(e)) => Err(format!("could not materialize the workspace: {e}")),
            Err(e) => Err(format!("workspace materialization did not complete: {e}")),
        }
    }
}

/// Hand the report to the control plane, waiting out the lease-recording race described in the
/// module docs. Every other refusal is terminal and is logged rather than retried — a report the
/// control plane refuses on lease-holder grounds is a report it is *supposed* to refuse (D§10.4).
async fn deliver(control: &Control, report: &StepReport, node_id: &str) {
    let deadline = tokio::time::Instant::now() + LEASE_WAIT;
    loop {
        match control.record_step_report(report, node_id) {
            Ok(()) => return,
            Err(ReportRejected::NotInFlight) if tokio::time::Instant::now() < deadline => {
                // Either the lease has not been recorded yet, or the step is already terminal
                // (cancelled by fail-fast). Waiting distinguishes them without weakening the check.
                tokio::time::sleep(LEASE_POLL).await;
            }
            Err(e) => {
                tracing::info!(
                    job = %report.job_id,
                    step = %report.step_id,
                    error = %e,
                    "step report was not recorded"
                );
                return;
            }
        }
    }
}

/// The report for a failure that happened on our side of the seam, before or instead of a run.
///
/// Built here rather than by the agent because the agent's equivalent is private and, more to the
/// point, this failure is not the agent's: it never saw the assignment. The shape matches the
/// agent's — typed `reason` plus the same `detail` prefix — so the control plane cannot tell which
/// side produced it, which is the property that keeps the mapping in one place.
fn infra_error(a: &Assignment, detail: &str) -> StepReport {
    tracing::error!(job = %a.job_id, step = %a.step_id, detail, "node could not run the assignment");
    StepReport {
        job_id: a.job_id.clone(),
        step_id: a.step_id.clone(),
        outcome: StepOutcome::Errored,
        reason: Some(NodeErrorKind::Infra.reason()),
        exit_code: None,
        log_key: None,
        detail: format!(
            "{}{}",
            NodeErrorKind::Infra.prefix(),
            sanitize_summary(detail, SUMMARY_MAX_CHARS)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hull_ci_node::{LocalProcessBackend, NodeConfig};
    use hull_ci_proto::{AuthorClass, IsolationTier};

    fn fleet(work_root: PathBuf) -> Arc<InProcessFleet> {
        let agent = NodeAgent::new(
            NodeConfig { node_id: "node-test".into(), ..Default::default() },
            Arc::new(LocalProcessBackend::new_for_development_only()),
        );
        InProcessFleet::new(agent, work_root)
    }

    fn assignment(class: AuthorClass) -> Assignment {
        Assignment {
            job_id: "job_0000000000000001".into(),
            step_id: "step_00_0000abcd".into(),
            step_name: "test".into(),
            tenant: "acme".into(),
            repo: "acme/widget".into(),
            tree_id: "tree1".into(),
            argv: vec!["/bin/true".into()],
            secrets: Vec::new(),
            image: "n/a".into(),
            tier: IsolationTier::Container,
            author_class: class,
            timeout_secs: 30,
            lease_secs: 30,
        }
    }

    fn tree(path: PathBuf) -> VerifiedTree {
        VerifiedTree { tree_id: "tree1".into(), path, cached: false }
    }

    #[tokio::test]
    async fn untrusted_work_is_refused_at_the_door_and_never_reaches_a_sandbox() {
        // The M1 isolation gate (D§7.2, D§13). No backend in this milestone admits untrusted work,
        // so an outsider assignment must be refused *before* anything is leased or materialized.
        let work = tempfile::tempdir().unwrap();
        let store = tempfile::tempdir().unwrap();
        let f = fleet(work.path().to_path_buf());

        let err = f
            .assign(&assignment(AuthorClass::Outsider), &tree(store.path().to_path_buf()))
            .expect_err("an outsider must not run on a backend that cannot contain it");
        match err {
            NodeError::Rejected(why) => assert!(why.contains("cannot admit untrusted work"), "{why}"),
            other => panic!("expected a refusal, got {other}"),
        }
        assert!(
            std::fs::read_dir(work.path()).unwrap().next().is_none(),
            "a refused assignment leaves no workspace behind"
        );
    }

    #[tokio::test]
    async fn an_unattached_fleet_refuses_rather_than_running_work_it_cannot_report() {
        let work = tempfile::tempdir().unwrap();
        let store = tempfile::tempdir().unwrap();
        let f = fleet(work.path().to_path_buf());

        let err = f.assign(&assignment(AuthorClass::Member), &tree(store.path().to_path_buf())).unwrap_err();
        assert!(matches!(err, NodeError::Rejected(_)));
    }

    #[test]
    fn the_workspace_path_is_built_only_from_ids_we_minted() {
        let work = tempfile::tempdir().unwrap();
        let f = fleet(work.path().to_path_buf());
        let a = assignment(AuthorClass::Member);
        let path = f.workspace_path(&a);
        assert_eq!(path, work.path().join("job_0000000000000001").join("step_00_0000abcd"));
        assert!(path.starts_with(work.path()), "no component of a dispatch reaches the filesystem");
    }

    #[test]
    fn an_infra_error_carries_the_reason_and_the_marker_the_agent_would_have_used() {
        let r = infra_error(&assignment(AuthorClass::Member), "could not materialize the workspace: nope");
        assert_eq!(r.outcome, StepOutcome::Errored);
        assert_eq!(r.reason, Some(hull_ci_proto::Reason::Infra));
        assert_eq!(NodeErrorKind::from_detail(&r.detail), Some(NodeErrorKind::Infra));
    }
}
