//! The local-process backend — **development only, untrusted input forbidden**.
//!
//! Spec §14.1 is unambiguous about what this is: "A shared interpreter, a bare `chroot`, or a plain
//! host subprocess is **NOT** sufficient." This backend is a plain host subprocess. It exists for two
//! legitimate reasons and no others:
//!
//! 1. Developing the node agent on a machine with no Linux container runtime (this crate is being
//!    written on macOS, where the whole container tier lives inside a VM that may not be running).
//! 2. Being the test vehicle for the host-side §14.4 controls — the wall clock and the output cap —
//!    which are ours and hold regardless of the sandbox.
//!
//! It therefore reports [`EnforcedControls`] with **only** the two host-side controls set, and
//! `BackendCapabilities` all `false`, so `admits_untrusted()` is `false` and the scheduler will not
//! place foreign work here. The node agent additionally refuses an `AuthorClass::Outsider` assignment
//! on any backend that does not admit untrusted work (defence in depth: the scheduler is the control,
//! this is the backstop).
//!
//! Note what is *not* claimed. `single_use` is `false`: we give each job a fresh scratch directory and
//! delete it, but there is no rootfs to destroy, so "nothing survives into the next job" is simply not
//! true here — the host filesystem, the package caches and any process the job leaves behind all
//! persist. Claiming `single_use` because we clean a directory would be exactly the dishonesty this
//! module's existence is most at risk of.

use std::path::PathBuf;

use hull_ci_proto::IsolationTier;

use crate::capture::{CapturedOutput, OutputCapture};
use crate::controls::EnforcedControls;
use crate::process::{command_from_argv, run_to_completion};
use crate::sandbox::{
    validate_exec, validate_spec, BoxFuture, ExecOutcome, ExecRequest, Lifecycle, SandboxBackend,
    SandboxError, SandboxInstance, SandboxSpec, UseGuard,
};

/// A backend that runs the job as a child process of the node. Not a sandbox.
#[derive(Debug, Default)]
pub struct LocalProcessBackend {
    _private: (),
}

impl LocalProcessBackend {
    /// Construct the development backend.
    ///
    /// The name is deliberately unpleasant. There is no `new()`: an operator wiring this into a node
    /// that faces real dispatches should have to type the reason out.
    pub fn new_for_development_only() -> Self {
        tracing::warn!(
            "local-process backend in use: this is NOT a §14.1 sandbox. Trusted, local input only."
        );
        LocalProcessBackend { _private: () }
    }

    /// The controls a host subprocess actually enforces: the two that are ours, and nothing else.
    pub fn controls_reported() -> EnforcedControls {
        EnforcedControls {
            wall_clock_timeout: true,
            output_cap: true,
            env_allowlist: true,
            ..EnforcedControls::NONE
        }
    }
}

impl SandboxBackend for LocalProcessBackend {
    fn name(&self) -> &'static str {
        "local-process"
    }

    fn tier(&self) -> IsolationTier {
        // There is no weaker tier in the proto to report, and inventing one would be worse: the tier
        // is what the scheduler partitions on, and the honest signal here is the capability struct,
        // which says this backend enforces essentially nothing.
        IsolationTier::Container
    }

    fn controls(&self) -> EnforcedControls {
        Self::controls_reported()
    }

    /// The host's own `PATH`, unlike every real backend.
    ///
    /// This backend runs jobs as plain host subprocesses, so the toolchain is wherever the developer
    /// installed it — an `nvm`-managed `npm`, a `rustup` `cargo`. Under the fixed
    /// [`SANDBOX_PATH`](crate::env::SANDBOX_PATH) those resolve to nothing and every autodetected
    /// command dies with `ENOENT`, which the node then reports as `errored`/infra: a claim that *our
    /// infrastructure* failed, about a tree that was fine. Wrong, and misleading in the direction
    /// that wastes someone's afternoon.
    ///
    /// Conceding the host PATH here gives away nothing: this backend already reports every §14
    /// control unmet, and a subprocess with no namespace, no cgroup, and no rootfs could read the
    /// host's filesystem regardless of what PATH we handed it. Real backends keep the fixed one.
    fn job_path(&self) -> String {
        std::env::var("PATH").unwrap_or_else(|_| crate::env::SANDBOX_PATH.to_string())
    }

    fn spawn<'a>(
        &'a self,
        spec: &'a SandboxSpec,
    ) -> BoxFuture<'a, Result<Box<dyn SandboxInstance>, SandboxError>> {
        Box::pin(async move {
            validate_spec(spec)?;
            // A scratch directory per job. This is hygiene, not isolation — see the module docs.
            let scratch = tempfile::Builder::new()
                .prefix("hull-ci-scratch-")
                .tempdir()
                .map_err(SandboxError::Io)?;
            let id = format!("local-{}", spec.job_id);
            Ok(Box::new(LocalInstance {
                guard: UseGuard::new(id.clone(), spec.job_id.clone()),
                id,
                workspace: spec.workspace.clone(),
                env: rehome(&spec.env, scratch.path().to_string_lossy().as_ref()),
                scratch: Some(scratch),
                capture: None,
            }) as Box<dyn SandboxInstance>)
        })
    }
}

/// Point `HOME`/`TMPDIR` at the job's scratch directory. In a real sandbox these are in-sandbox paths;
/// here they must be host paths that exist, or half of the toolchains fail for the wrong reason.
fn rehome(env: &[(String, String)], scratch: &str) -> Vec<(String, String)> {
    env.iter()
        .map(|(k, v)| match k.as_str() {
            "HOME" | "TMPDIR" => (k.clone(), scratch.to_string()),
            _ => (k.clone(), v.clone()),
        })
        .collect()
}

struct LocalInstance {
    guard: UseGuard,
    id: String,
    workspace: PathBuf,
    env: Vec<(String, String)>,
    scratch: Option<tempfile::TempDir>,
    capture: Option<CapturedOutput>,
}

impl SandboxInstance for LocalInstance {
    fn id(&self) -> &str {
        &self.id
    }

    fn job_id(&self) -> &str {
        self.guard.job_id()
    }

    fn lifecycle(&self) -> Lifecycle {
        self.guard.state()
    }

    fn exec<'a>(&'a mut self, req: &'a ExecRequest) -> BoxFuture<'a, Result<ExecOutcome, SandboxError>> {
        Box::pin(async move {
            validate_exec(req)?;
            self.guard.begin_exec(&req.job_id)?;

            let mut cmd = command_from_argv(&req.argv, &self.env)?;
            cmd.current_dir(&self.workspace);
            // Kill the whole child tree when the handle drops, so a timed-out job does not outlive the
            // step. Without a sandbox this is the only teardown we have.
            cmd.kill_on_drop(true);
            let child = cmd.spawn().map_err(SandboxError::Io)?;

            let mut capture = OutputCapture::new(req.caps);
            let outcome = run_to_completion(child, req.timeout, &mut capture).await?;
            self.capture = Some(capture.finish());
            Ok(outcome)
        })
    }

    fn collect(&mut self) -> BoxFuture<'_, Result<CapturedOutput, SandboxError>> {
        Box::pin(async move {
            self.guard.begin_collect()?;
            Ok(self.capture.take().unwrap_or_else(|| CapturedOutput::empty(Default::default())))
        })
    }

    fn destroy(mut self: Box<Self>) -> BoxFuture<'static, Result<(), SandboxError>> {
        Box::pin(async move {
            // Only the scratch directory dies. The host does not, which is the whole reason this
            // backend reports `single_use: false`.
            if let Some(scratch) = self.scratch.take() {
                if let Err(e) = scratch.close() {
                    tracing::warn!(error = %e, "could not remove job scratch directory");
                }
            }
            self.guard.mark_destroyed();
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::OutputCaps;
    use hull_ci_proto::AuthorClass;
    use std::time::Duration;

    fn spec(ws: &std::path::Path, job: &str) -> SandboxSpec {
        SandboxSpec {
            job_id: job.into(),
            step_id: "step".into(),
            image: "n/a".into(),
            workspace: ws.to_path_buf(),
            workdir: ws.to_string_lossy().into_owned(),
            limits: Default::default(),
            env: crate::env::base_env("/tmp"),
            author_class: AuthorClass::Member,
            broker_authorised: Vec::new(),
        }
    }

    fn req(job: &str, argv: &[&str], secs: u64) -> ExecRequest {
        ExecRequest {
            job_id: job.into(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            timeout: Duration::from_secs(secs),
            caps: OutputCaps::default(),
        }
    }

    #[test]
    fn it_advertises_no_isolation_at_all() {
        let b = LocalProcessBackend::new_for_development_only();
        let caps = b.capabilities();
        assert!(!caps.egress_deny && !caps.metadata_blackhole && !caps.single_use && !caps.cross_tenant_safe);
        assert!(!caps.admits_untrusted());
        // Single-use is false on purpose: there is no rootfs to destroy.
        assert!(!b.controls().single_use);
        // The two host-side controls are real and are claimed.
        assert!(b.controls().wall_clock_timeout && b.controls().output_cap);
    }

    #[tokio::test]
    async fn runs_argv_and_reports_the_exit_code() {
        let t = tempfile::tempdir().unwrap();
        let b = LocalProcessBackend::new_for_development_only();
        let mut sbx = b.spawn(&spec(t.path(), "job-1")).await.unwrap();
        let out = sbx.exec(&req("job-1", &["/bin/echo", "hello"], 30)).await.unwrap();
        assert_eq!(out.status, crate::sandbox::ExecStatus::Exited(0));
        let captured = sbx.collect().await.unwrap();
        assert!(captured.text().contains("hello"));
        sbx.destroy().await.unwrap();
    }

    #[tokio::test]
    async fn a_timeout_is_reported_as_timed_out_not_as_a_failure() {
        let t = tempfile::tempdir().unwrap();
        let b = LocalProcessBackend::new_for_development_only();
        let mut sbx = b.spawn(&spec(t.path(), "job-2")).await.unwrap();
        let out = sbx.exec(&ExecRequest { timeout: Duration::from_millis(200), ..req("job-2", &["/bin/sleep", "30"], 0) })
            .await
            .unwrap();
        assert_eq!(out.status, crate::sandbox::ExecStatus::TimedOut);
        sbx.destroy().await.unwrap();
    }

    #[tokio::test]
    async fn a_sandbox_is_never_handed_to_a_second_job() {
        // §14.1 at the instance level, not just in the guard's unit test.
        let t = tempfile::tempdir().unwrap();
        let b = LocalProcessBackend::new_for_development_only();
        let mut sbx = b.spawn(&spec(t.path(), "job-3")).await.unwrap();
        sbx.exec(&req("job-3", &["/bin/echo", "one"], 30)).await.unwrap();

        let second = sbx.exec(&req("job-3", &["/bin/echo", "two"], 30)).await;
        assert!(matches!(second, Err(SandboxError::Reused { .. })));

        let foreign = sbx.exec(&req("job-4", &["/bin/echo", "three"], 30)).await;
        assert!(matches!(foreign, Err(SandboxError::CrossJobReuse { .. })));

        let captured = sbx.collect().await.unwrap();
        let text = captured.text();
        assert!(text.contains("one"));
        assert!(!text.contains("two") && !text.contains("three"), "the refused runs never happened");
        sbx.destroy().await.unwrap();
    }

    #[tokio::test]
    async fn the_scratch_directory_dies_with_the_job() {
        let t = tempfile::tempdir().unwrap();
        let b = LocalProcessBackend::new_for_development_only();
        let mut sbx = b.spawn(&spec(t.path(), "job-5")).await.unwrap();
        // `pwd` proves the job runs in its workspace; `$HOME` is the per-job scratch directory.
        sbx.exec(&req("job-5", &["/bin/sh", "-c", "pwd; echo $HOME"], 30)).await.unwrap();
        let text = sbx.collect().await.unwrap().text();
        let mut lines = text.lines();
        let cwd = PathBuf::from(lines.next().unwrap().trim());
        let scratch = PathBuf::from(lines.next().unwrap().trim());
        assert_eq!(
            cwd.canonicalize().unwrap(),
            t.path().canonicalize().unwrap(),
            "the job runs in its workspace"
        );
        assert!(scratch.is_dir());

        sbx.destroy().await.unwrap();
        assert!(!scratch.exists(), "the scratch directory dies with the job");
        assert!(t.path().exists(), "…but the workspace is the caller's to keep or drop");
    }

    #[tokio::test]
    async fn a_missing_workspace_is_refused_before_anything_runs() {
        let b = LocalProcessBackend::new_for_development_only();
        let s = spec(std::path::Path::new("/definitely/not/here"), "job-6");
        assert!(matches!(b.spawn(&s).await, Err(SandboxError::MissingWorkspace(_))));
    }

    #[tokio::test]
    async fn a_credential_shaped_env_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let b = LocalProcessBackend::new_for_development_only();
        let mut s = spec(t.path(), "job-7");
        s.env.push(("AWS_SECRET_ACCESS_KEY".into(), "hunter2".into()));
        assert!(matches!(b.spawn(&s).await, Err(SandboxError::ForbiddenEnv(_))));
    }
}
