//! The sandbox seam: `spawn → exec → collect → destroy`, plus a capability query.
//!
//! Design D§7.2: "**The backend is a trait** (`spawn → exec → collect → destroy`, plus a capability
//! query for what §14 controls it can actually enforce). Two implementations: **Firecracker**
//! (untrusted — the default and the fleet), and the **locked-down container** (the trusted tier, and
//! the M1 bring-up backend)." This module is that trait and nothing else — no runtime, no policy — so
//! that M3 *adds* [`SandboxBackend`] impl number three without the scheduler or the node agent
//! changing shape (D§13).
//!
//! Three invariants are encoded here rather than left to each backend:
//!
//! 1. **Single use** (§14.1: "A sandbox MUST NOT be reused across jobs"). [`UseGuard`] is a state
//!    machine every backend embeds: a second `exec`, or an `exec` naming a different job, is an error
//!    from the type's own bookkeeping — not from each backend remembering to check.
//! 2. **argv only** (D§7.2: "The node binary never interpolates user strings into a host command
//!    line"). [`ExecRequest`] carries `Vec<String>`; there is no field anywhere in this crate that
//!    takes a command *string*, so there is nothing for a backend to `sh -c`.
//! 3. **Destroy is not optional.** [`SandboxInstance::destroy`] consumes the box, so the type system
//!    forbids using a sandbox after teardown, and [`UseGuard`]'s `Drop` shouts if an instance is
//!    dropped without one.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use hull_ci_proto::{AuthorClass, BackendCapabilities, IsolationTier};

use crate::capture::{CapturedOutput, OutputCaps};
use crate::controls::EnforcedControls;
use crate::env::EnvVar;

/// Boxed future alias. Hand-rolled rather than pulled from `futures`/`async-trait` so the node agent
/// takes no dependency beyond the workspace's, and so the trait stays object-safe: the node holds an
/// `Arc<dyn SandboxBackend>` chosen at startup from host detection.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Resource ceilings for one sandbox (§14.4: "Enforce CPU, memory, PID, and disk limits and a
/// wall-clock timeout").
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ResourceLimits {
    pub cpus: f32,
    pub memory_bytes: u64,
    pub pids: u32,
    /// Size of the writable tmpfs scratch that dies with the job (§14.4).
    pub tmpfs_bytes: u64,
    /// Workspace disk ceiling. Frequently *not* enforceable (see the container backend); a backend
    /// that cannot apply it reports `disk_limit: false` rather than pretending.
    pub disk_bytes: u64,
}

impl Default for ResourceLimits {
    /// D§7.1's declared slot shape: "one slot per CPU group (default 2 cores + 4 GB)".
    fn default() -> Self {
        ResourceLimits {
            cpus: 2.0,
            memory_bytes: 4 * 1024 * 1024 * 1024,
            pids: 2048,
            tmpfs_bytes: 1024 * 1024 * 1024,
            disk_bytes: 16 * 1024 * 1024 * 1024,
        }
    }
}

/// Everything a backend needs to build one sandbox for one job.
#[derive(Debug, Clone)]
pub struct SandboxSpec {
    pub job_id: String,
    pub step_id: String,
    /// Base image / rootfs identifier, interpreted by the backend.
    pub image: String,
    /// Host path of the already-materialized tree (D§6.2). The node does **not** fetch: the tree
    /// arrives already fetched and verified by the broker, which is how §14.2's "no source auth in the
    /// job" holds structurally rather than by scrubbing.
    pub workspace: PathBuf,
    /// Mount point of the workspace inside the sandbox.
    pub workdir: String,
    pub limits: ResourceLimits,
    /// Allowlist-built environment (§14.2). Never the node's own environment.
    pub env: Vec<EnvVar>,
    /// Whose authority the code carries (D§1). Separate axis from the tier; backends use it only for
    /// the defence-in-depth refusal below, never to weaken the box.
    pub author_class: AuthorClass,
}

/// One command to run inside a spawned sandbox.
#[derive(Debug, Clone)]
pub struct ExecRequest {
    /// Must match the job the sandbox was spawned for (§14.1 single-use).
    pub job_id: String,
    /// argv. Element 0 is the program; nothing is ever concatenated into a command line.
    pub argv: Vec<String>,
    /// Wall clock for this command. Expiry is `errored`, never `red` (§14.4, §7).
    pub timeout: Duration,
    pub caps: OutputCaps,
}

/// How a command ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecStatus {
    Exited(i32),
    /// Killed by a signal — including the kernel OOM killer when the memory limit bites.
    Signalled(i32),
    /// The wall clock fired and we killed it. **Maps to `errored`, never `red`** (§14.4): we stopped
    /// the job, so we do not know what the code would have said.
    TimedOut,
}

impl ExecStatus {
    pub(crate) fn from_exit(status: std::process::ExitStatus) -> ExecStatus {
        match status.code() {
            Some(c) => ExecStatus::Exited(c),
            None => {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    ExecStatus::Signalled(status.signal().unwrap_or(0))
                }
                #[cfg(not(unix))]
                {
                    ExecStatus::Exited(-1)
                }
            }
        }
    }
}

/// The result of one `exec`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ExecOutcome {
    pub status: ExecStatus,
    pub duration: Duration,
}

/// Failure modes of the sandbox layer itself. All of these are *our* faults or refusals and fold to
/// `errored`, never `red` (§7).
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("backend unavailable on this host: {0}")]
    Unavailable(String),
    #[error("sandbox `{sandbox}` was already used (state {state:?}); §14.1 forbids reuse")]
    Reused { sandbox: String, state: Lifecycle },
    #[error("sandbox `{sandbox}` is bound to job `{bound}` and may not run job `{attempted}` (§14.1)")]
    CrossJobReuse { sandbox: String, bound: String, attempted: String },
    #[error("argv is empty; there is no command to run")]
    EmptyArgv,
    #[error("environment variable `{0}` is credential-shaped and must not enter a sandbox (§14.2)")]
    ForbiddenEnv(String),
    #[error("workspace `{0}` does not exist")]
    MissingWorkspace(PathBuf),
    #[error("backend `{backend}` cannot admit untrusted work: {unmet}")]
    UntrustedRefused { backend: &'static str, unmet: String },
    #[error("sandbox runtime failed: {0}")]
    Runtime(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Where a sandbox is in its one and only life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    Fresh,
    Executed,
    Collected,
    Destroyed,
}

/// The single-use state machine (§14.1).
///
/// Lives here rather than in each backend so that "a sandbox is never handed to a second job" is one
/// tested mechanism instead of two hopeful ones. The `Drop` impl is a leak detector: teardown is
/// async, so `Drop` cannot perform it, but it can make a missed teardown loud instead of invisible.
#[derive(Debug)]
pub struct UseGuard {
    sandbox_id: String,
    job_id: String,
    state: Lifecycle,
}

impl UseGuard {
    pub fn new(sandbox_id: impl Into<String>, job_id: impl Into<String>) -> Self {
        UseGuard { sandbox_id: sandbox_id.into(), job_id: job_id.into(), state: Lifecycle::Fresh }
    }

    pub fn sandbox_id(&self) -> &str {
        &self.sandbox_id
    }

    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    pub fn state(&self) -> Lifecycle {
        self.state
    }

    /// Claim the sandbox's one execution.
    pub fn begin_exec(&mut self, job_id: &str) -> Result<(), SandboxError> {
        if job_id != self.job_id {
            return Err(SandboxError::CrossJobReuse {
                sandbox: self.sandbox_id.clone(),
                bound: self.job_id.clone(),
                attempted: job_id.to_string(),
            });
        }
        if self.state != Lifecycle::Fresh {
            return Err(SandboxError::Reused { sandbox: self.sandbox_id.clone(), state: self.state });
        }
        self.state = Lifecycle::Executed;
        Ok(())
    }

    /// Claim the sandbox's output. Allowed after a failed spawn too (`Fresh`), because empty output
    /// from a sandbox that never ran is a legitimate, useful answer.
    pub fn begin_collect(&mut self) -> Result<(), SandboxError> {
        match self.state {
            Lifecycle::Fresh | Lifecycle::Executed => {
                self.state = Lifecycle::Collected;
                Ok(())
            }
            state => Err(SandboxError::Reused { sandbox: self.sandbox_id.clone(), state }),
        }
    }

    pub fn mark_destroyed(&mut self) {
        self.state = Lifecycle::Destroyed;
    }
}

impl Drop for UseGuard {
    fn drop(&mut self) {
        if self.state != Lifecycle::Destroyed {
            // §14.1: the rootfs must be destroyed after each job. If we get here, something survived
            // that should not have, and an operator needs to know now rather than at the next audit.
            tracing::error!(
                sandbox = %self.sandbox_id,
                job = %self.job_id,
                state = ?self.state,
                "sandbox dropped without destroy(); §14.1 requires the rootfs be destroyed after each job"
            );
        }
    }
}

/// A sandbox backend: the factory, and the authority on what §14 controls it enforces.
pub trait SandboxBackend: Send + Sync {
    /// Stable short name for logs and refusals.
    fn name(&self) -> &'static str;

    /// Which isolation tier this backend implements (D§1: a property of the box, never of the actor).
    fn tier(&self) -> IsolationTier;

    /// The long-form, per-clause enforcement facts for this host and configuration.
    fn controls(&self) -> EnforcedControls;

    /// The wire capability answer the scheduler acts on. Derived from [`controls`](Self::controls) —
    /// a backend must not be able to report a capability it does not enforce (D§7.2).
    fn capabilities(&self) -> BackendCapabilities {
        self.controls().to_capabilities()
    }

    /// Build a fresh, single-use sandbox for exactly one job.
    fn spawn<'a>(
        &'a self,
        spec: &'a SandboxSpec,
    ) -> BoxFuture<'a, Result<Box<dyn SandboxInstance>, SandboxError>>;
}

/// A live sandbox. Exactly one job, exactly one `exec`, then `collect` and `destroy`.
pub trait SandboxInstance: Send {
    fn id(&self) -> &str;

    fn job_id(&self) -> &str;

    fn lifecycle(&self) -> Lifecycle;

    /// Run the argv inside the sandbox under a wall clock (§14.4).
    fn exec<'a>(&'a mut self, req: &'a ExecRequest) -> BoxFuture<'a, Result<ExecOutcome, SandboxError>>;

    /// Take the capped capture of everything the job printed (§14.4, §14.5 — untrusted data).
    fn collect(&mut self) -> BoxFuture<'_, Result<CapturedOutput, SandboxError>>;

    /// Destroy the sandbox (§14.1). Consumes the box: there is no "after" to reuse.
    fn destroy(self: Box<Self>) -> BoxFuture<'static, Result<(), SandboxError>>;
}

/// Shared validation every backend runs before touching the host.
///
/// Centralised so a new backend cannot forget one: empty argv (nothing to run), a credential-shaped
/// environment (§14.2), or a missing workspace are all refusals, not attempts.
pub fn validate_spec(spec: &SandboxSpec) -> Result<(), SandboxError> {
    if let Err(name) = crate::env::reject_forbidden(&spec.env) {
        return Err(SandboxError::ForbiddenEnv(name));
    }
    if !spec.workspace.is_dir() {
        return Err(SandboxError::MissingWorkspace(spec.workspace.clone()));
    }
    Ok(())
}

/// Shared validation for one command.
pub fn validate_exec(req: &ExecRequest) -> Result<(), SandboxError> {
    if req.argv.is_empty() || req.argv[0].trim().is_empty() {
        return Err(SandboxError::EmptyArgv);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sandbox_is_never_handed_to_a_second_job() {
        // §14.1: "A sandbox MUST NOT be reused across jobs."
        let mut g = UseGuard::new("sbx-1", "job-a");
        g.begin_exec("job-a").expect("first use is the one use");
        let err = g.begin_exec("job-a").expect_err("a second exec must be refused");
        assert!(matches!(err, SandboxError::Reused { .. }));

        let mut g2 = UseGuard::new("sbx-2", "job-a");
        let err = g2.begin_exec("job-b").expect_err("a different job must be refused");
        match err {
            SandboxError::CrossJobReuse { bound, attempted, .. } => {
                assert_eq!(bound, "job-a");
                assert_eq!(attempted, "job-b");
            }
            other => panic!("wrong error: {other}"),
        }
        // Even after the refusal the sandbox is not silently usable by its own job.
        g2.begin_exec("job-a").expect("its own job may still run once");
        assert!(g2.begin_exec("job-a").is_err());
    }

    #[test]
    fn collect_happens_once_and_never_after_destroy() {
        let mut g = UseGuard::new("sbx", "job");
        g.begin_exec("job").unwrap();
        g.begin_collect().unwrap();
        assert!(g.begin_collect().is_err());
        g.mark_destroyed();
        assert_eq!(g.state(), Lifecycle::Destroyed);
        assert!(g.begin_exec("job").is_err());
    }

    #[test]
    fn collect_is_allowed_when_the_sandbox_never_ran() {
        let mut g = UseGuard::new("sbx", "job");
        g.begin_collect().expect("empty output from a failed spawn is a legitimate answer");
        g.mark_destroyed();
    }

    #[test]
    fn empty_argv_is_refused_rather_than_shelled_out() {
        let req = ExecRequest {
            job_id: "j".into(),
            argv: vec![],
            timeout: Duration::from_secs(1),
            caps: OutputCaps::default(),
        };
        assert!(matches!(validate_exec(&req), Err(SandboxError::EmptyArgv)));
    }
}
