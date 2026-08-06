//! The locked-down container backend — M1's bring-up scaffold (`IsolationTier::Container`).
//!
//! Design D§13: "*Isolation backend for M1: the **locked-down container** (§7.2 trusted tier) — as a
//! scaffold, not the product.* It clears §14.1's single-use rule without the Firecracker build-out,
//! and the sandbox interface is a trait from day one so M3 *adds* the Firecracker backend without
//! touching the scheduler. A container is not a boundary you can put between tenants, so **M1 is
//! single-tenant, trusted-input only and MUST NOT take untrusted or multi-tenant input.**"
//!
//! The shape D§7.2 specifies: "user namespace + cgroup v2 (cpu/mem/pids/io) + default-deny seccomp +
//! **read-only rootfs** + tmpfs `/tmp` + all capabilities dropped + `no-new-privileges`", single-use.
//!
//! # Honesty about the host
//!
//! macOS has no cgroups and no Linux namespaces. Docker Desktop supplies them from inside a Linux VM,
//! and if that VM is not running there is no sandbox here at all. So the capability answer is
//! **probed, not assumed**: [`probe_docker`] asks the daemon what it can do (`docker info` reports
//! `MemoryLimit`, `PidsLimit`, `CpuCfsQuota`, `SecurityOptions`, `CgroupVersion` — the daemon's own
//! statement about its host), and [`controls_for`] turns that plus the configuration into
//! [`EnforcedControls`]. If the daemon is unreachable, every flag is `false` and
//! [`ContainerBackend::detect`] refuses to construct — a backend that cannot run a container must not
//! advertise one.
//!
//! Two flags are `false` on **every** host, by construction rather than by detection:
//!
//! - `kernel_isolation` (→ `cross_tenant_safe`): a container shares the host kernel. That is the whole
//!   reason M1 is single-tenant, and no amount of hardening changes it (§14.1, D§7.2).
//! - `disk_limit`: `--storage-opt size=` works only on specific storage-driver/filesystem
//!   combinations (overlay2 on xfs with pquota). We do not detect it, so we do not claim it. §14.4's
//!   disk clause is therefore *unmet* on this backend and says so via
//!   [`EnforcedControls::unmet_clauses`].

use std::path::PathBuf;
use std::time::Duration;

use hull_ci_proto::IsolationTier;

use crate::capture::{CapturedOutput, OutputCapture};
use crate::controls::EnforcedControls;
use crate::process::{command_from_argv, run_to_completion};
use crate::sandbox::{
    validate_exec, validate_spec, BoxFuture, ExecOutcome, ExecRequest, ExecStatus, Lifecycle,
    SandboxBackend, SandboxError, SandboxInstance, SandboxSpec, UseGuard,
};

/// Sandbox network posture (§14.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkMode {
    /// `--network none`: the container gets loopback and nothing else. This is a real default-deny
    /// egress **and** a real metadata blackhole (169.254.169.254 has no route to reach), which is why
    /// it is the only mode that lets those two capabilities be reported `true`.
    None,
    /// A named docker network. We cannot see its nftables rules from here, so both `egress_deny` and
    /// `metadata_blackhole` drop to `false` — the operator may well have locked it down, but this code
    /// has no evidence of it, and reporting an unverified control is exactly the failure mode that
    /// turns this design into a security hole.
    Named(String),
}

/// Configuration for the container backend.
#[derive(Debug, Clone)]
pub struct ContainerConfig {
    /// Runtime CLI. Docker-compatible (`docker`, `podman`, `nerdctl`).
    pub runtime: String,
    pub network: NetworkMode,
    /// `uid:gid` the job runs as (§14.4 non-root). 65534 is `nobody` on essentially every distro.
    pub user: String,
    /// Host path of a seccomp profile. `None` leaves the runtime's built-in default profile in force,
    /// which for Docker is itself an allowlist (default-deny for everything not on it).
    pub seccomp_profile: Option<PathBuf>,
    /// How long a `create`/`rm` control command may take before we give up on the daemon.
    pub control_timeout: Duration,
}

impl Default for ContainerConfig {
    fn default() -> Self {
        ContainerConfig {
            runtime: "docker".into(),
            network: NetworkMode::None,
            user: "65534:65534".into(),
            seccomp_profile: None,
            control_timeout: Duration::from_secs(60),
        }
    }
}

/// What the container runtime told us about itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DockerProbe {
    pub cli_present: bool,
    pub daemon_reachable: bool,
    /// The *daemon's* OS, not ours. On macOS this is `linux` (the Desktop VM) whenever the daemon is
    /// up — which is what makes namespaces and cgroups available at all.
    pub server_os: Option<String>,
    pub server_version: Option<String>,
    pub cgroup_version: Option<String>,
    /// e.g. `builtin/default`, or `unconfined` when the daemon has seccomp switched off.
    pub seccomp_profile: Option<String>,
    pub memory_limit: bool,
    pub pids_limit: bool,
    pub cpu_cfs_quota: bool,
    pub rootless: bool,
    /// Why the probe failed, when it did.
    pub failure: Option<String>,
}

/// The node's own tooling environment — *not* the job environment.
///
/// The runtime CLI needs a few variables to find its daemon. This is deliberately a separate, tiny
/// allowlist from [`crate::env::base_env`]: nothing here ever reaches a sandbox, and the job's
/// environment never inherits from the node's (§14.2).
fn runtime_env() -> Vec<(String, String)> {
    let mut env = vec![(
        "PATH".to_string(),
        std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".into()),
    )];
    for name in ["HOME", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY"] {
        if let Ok(v) = std::env::var(name) {
            env.push((name.to_string(), v));
        }
    }
    env
}

/// Ask the runtime what it is and what it can enforce.
pub async fn probe_docker(runtime: &str) -> DockerProbe {
    let argv = vec![runtime.to_string(), "info".to_string(), "--format".to_string(), "{{json .}}".to_string()];
    let mut probe = DockerProbe::default();

    let mut cmd = match command_from_argv(&argv, &runtime_env()) {
        Ok(c) => c,
        Err(e) => {
            probe.failure = Some(e.to_string());
            return probe;
        }
    };
    let child = match cmd.spawn() {
        Ok(c) => {
            probe.cli_present = true;
            c
        }
        Err(e) => {
            probe.failure = Some(format!("cannot execute `{runtime}`: {e}"));
            return probe;
        }
    };

    let mut capture = OutputCapture::new(crate::capture::OutputCaps::new(1024 * 1024, 100_000));
    let outcome = match run_to_completion(child, Duration::from_secs(15), &mut capture).await {
        Ok(o) => o,
        Err(e) => {
            probe.failure = Some(format!("`{runtime} info` failed: {e}"));
            return probe;
        }
    };
    let text = capture.finish().text();
    if outcome.status != ExecStatus::Exited(0) {
        probe.failure = Some(format!(
            "`{runtime} info` exited {:?}: {}",
            outcome.status,
            text.lines().find(|l| !l.trim().is_empty()).unwrap_or("no output")
        ));
        return probe;
    }

    let json: serde_json::Value = match serde_json::from_str(text.trim()) {
        Ok(v) => v,
        Err(e) => {
            probe.failure = Some(format!("could not parse `{runtime} info`: {e}"));
            return probe;
        }
    };
    probe.daemon_reachable = true;
    probe.server_os = json["OSType"].as_str().map(str::to_string);
    probe.server_version = json["ServerVersion"].as_str().map(str::to_string);
    probe.cgroup_version = json["CgroupVersion"].as_str().map(str::to_string);
    probe.memory_limit = json["MemoryLimit"].as_bool().unwrap_or(false);
    probe.pids_limit = json["PidsLimit"].as_bool().unwrap_or(false);
    probe.cpu_cfs_quota = json["CpuCfsQuota"].as_bool().unwrap_or(false);
    if let Some(opts) = json["SecurityOptions"].as_array() {
        for opt in opts.iter().filter_map(|v| v.as_str()) {
            if opt.contains("name=rootless") {
                probe.rootless = true;
            }
            if opt.contains("name=seccomp") {
                probe.seccomp_profile = opt
                    .split(',')
                    .find_map(|kv| kv.strip_prefix("profile="))
                    .map(str::to_string)
                    .or(Some("builtin/default".to_string()));
            }
        }
    }
    probe
}

/// Turn a probe plus a configuration into per-clause enforcement facts.
///
/// A pure function so the mapping is testable without a daemon — which matters, because the mapping
/// *is* the security property (D§7.2).
pub fn controls_for(probe: &DockerProbe, config: &ContainerConfig) -> EnforcedControls {
    if !probe.daemon_reachable {
        // No daemon, no container, no controls. Note that the host-side controls (timeout, output cap)
        // are also false here: with nothing to run they enforce nothing.
        return EnforcedControls::NONE;
    }
    let namespaced = probe.server_os.as_deref() == Some("linux");
    let isolated_network = namespaced && config.network == NetworkMode::None;
    let seccomp_on = config.seccomp_profile.is_some()
        || matches!(probe.seccomp_profile.as_deref(), Some(p) if p != "unconfined");

    EnforcedControls {
        // §14.1
        single_use: true,          // one container per job, `rm -f` in destroy, never restarted
        kernel_isolation: false,   // shared host kernel — true for every container, on every host

        // §14.2
        env_allowlist: true,       // ours, host-side: the env is built from an allowlist
        metadata_blackhole: isolated_network,

        // §14.3
        egress_deny: isolated_network,
        no_inbound: isolated_network,

        // §14.4 — flags we pass and the daemon applies
        non_root: namespaced,
        read_only_rootfs: namespaced,
        tmpfs_scratch: namespaced,
        caps_dropped: namespaced,
        no_new_privileges: namespaced,
        seccomp_default_deny: namespaced && seccomp_on,
        // …and the cgroup controllers the daemon says it actually has.
        cpu_limit: probe.cpu_cfs_quota,
        memory_limit: probe.memory_limit,
        pid_limit: probe.pids_limit,
        // Not attempted, so not claimed: `--storage-opt size=` needs a specific driver/filesystem.
        disk_limit: false,
        // Host-side, ours, and independent of the runtime.
        wall_clock_timeout: true,
        output_cap: true,
    }
}

/// The M1 container backend.
#[derive(Debug)]
pub struct ContainerBackend {
    config: ContainerConfig,
    probe: DockerProbe,
    controls: EnforcedControls,
}

impl ContainerBackend {
    /// Probe the host and build a backend, or refuse.
    ///
    /// Refusal is the point: on a host with no reachable container runtime there is no §14.1 boundary,
    /// and the alternative — constructing a backend that quietly runs jobs on the host — is the exact
    /// thing §14.1 calls "a full remote-code-execution and credential-exfiltration hole".
    pub async fn detect(config: ContainerConfig) -> Result<Self, SandboxError> {
        let probe = probe_docker(&config.runtime).await;
        if !probe.daemon_reachable {
            return Err(SandboxError::Unavailable(
                probe.failure.unwrap_or_else(|| format!("`{}` daemon is not reachable", config.runtime)),
            ));
        }
        Ok(Self::from_probe(config, probe))
    }

    /// Build from an already-taken probe. Used by [`detect`](Self::detect) and by tests, which is how
    /// the capability mapping is verified on a host with no daemon.
    pub fn from_probe(config: ContainerConfig, probe: DockerProbe) -> Self {
        let controls = controls_for(&probe, &config);
        ContainerBackend { config, probe, controls }
    }

    pub fn probe(&self) -> &DockerProbe {
        &self.probe
    }

    /// The `create` argv for this backend's configuration.
    pub fn create_argv(&self, spec: &SandboxSpec, name: &str, argv: &[String]) -> Vec<String> {
        create_argv(&self.config, spec, name, argv)
    }
}

/// The `create` argv. A free function, pure and public, so the §14.4 flag set is directly assertable
/// in tests rather than inferred from a running container.
pub fn create_argv(
    config: &ContainerConfig,
    spec: &SandboxSpec,
    name: &str,
    argv: &[String],
) -> Vec<String> {
    {
        let l = &spec.limits;
        let mut a: Vec<String> = vec![
            config.runtime.clone(),
            "create".into(),
            "--name".into(),
            name.into(),
            // §14.4: non-root, read-only rootfs, writable tmpfs scratch that dies with the job.
            "--user".into(),
            config.user.clone(),
            "--read-only".into(),
            "--tmpfs".into(),
            format!("/tmp:rw,noexec,nosuid,nodev,size={}", l.tmpfs_bytes),
            // §14.4: drop all capabilities, no-new-privileges.
            "--cap-drop".into(),
            "ALL".into(),
            "--security-opt".into(),
            "no-new-privileges".into(),
            // §14.4: CPU, memory and PID ceilings.
            "--cpus".into(),
            format!("{:.2}", l.cpus),
            "--memory".into(),
            l.memory_bytes.to_string(),
            "--pids-limit".into(),
            l.pids.to_string(),
        ];

        // §14.4 default-deny seccomp. With no explicit profile the runtime's built-in allowlist
        // applies; we only pass the flag when we have a profile of our own to install.
        if let Some(p) = &config.seccomp_profile {
            a.push("--security-opt".into());
            a.push(format!("seccomp={}", p.display()));
        }

        // §14.3 network posture.
        match &config.network {
            NetworkMode::None => {
                a.push("--network".into());
                a.push("none".into());
            }
            NetworkMode::Named(n) => {
                a.push("--network".into());
                a.push(n.clone());
            }
        }

        // §14.4: "No host filesystem mounts into the sandbox beyond the extracted tree."
        a.push("--mount".into());
        a.push(format!(
            "type=bind,source={},target={}",
            spec.workspace.display(),
            spec.workdir
        ));
        a.push("--workdir".into());
        a.push(spec.workdir.clone());

        // §14.2: the allowlisted environment, one `--env NAME=VALUE` argv element each. Never a shell
        // assignment, never a string we build by concatenating a command.
        for (k, v) in &spec.env {
            a.push("--env".into());
            a.push(format!("{k}={v}"));
        }

        // Broker-delivered secrets go in by **name only** (D§7.4). `--env NAME=VALUE` would put the
        // plaintext in the runtime CLI's argv, which is world-readable through `/proc` on Linux for
        // as long as `create` runs — a local disclosure to every other user on the node, against a
        // value §14.2's whole discipline exists to contain. The bare `--env NAME` form tells the
        // runtime to copy the variable out of *its own* environment instead, and `control_command`
        // below is what puts it there. See `ContainerInstance::exec`.
        for name in spec.secret_names() {
            a.push("--env".into());
            a.push(name.to_string());
        }

        // Labels let an operator find and reap orphans after a node crash without guessing names.
        a.push("--label".into());
        a.push(format!("hull-ci.job={}", spec.job_id));
        a.push("--label".into());
        a.push(format!("hull-ci.step={}", spec.step_id));

        // The image's own ENTRYPOINT is overridden so the image cannot wrap, alter, or ignore the
        // argv we were told to run.
        a.push("--entrypoint".into());
        a.push(argv[0].clone());
        a.push(spec.image.clone());
        a.extend(argv[1..].iter().cloned());
        a
    }
}

/// Run one runtime control command (`create`, `kill`, `rm`) and return its status and output.
///
/// `extra_env` is added to the **CLI's own** environment, not the job's. It exists for exactly one
/// caller: `create`, which passes broker-delivered secrets by name (`--env NAME`) so the values never
/// appear in an argv any other user on the host can read. Everything else passes an empty slice.
async fn control_command(
    config: &ContainerConfig,
    argv: Vec<String>,
    extra_env: &[(String, String)],
) -> Result<(ExecStatus, String), SandboxError> {
    let mut env = runtime_env();
    env.extend_from_slice(extra_env);
    let mut cmd = command_from_argv(&argv, &env)?;
    let child = cmd.spawn()?;
    let mut capture = OutputCapture::new(crate::capture::OutputCaps::new(256 * 1024, 10_000));
    let outcome = run_to_completion(child, config.control_timeout, &mut capture).await?;
    Ok((outcome.status, capture.finish().text()))
}

impl SandboxBackend for ContainerBackend {
    fn name(&self) -> &'static str {
        "container"
    }

    fn tier(&self) -> IsolationTier {
        IsolationTier::Container
    }

    fn controls(&self) -> EnforcedControls {
        self.controls
    }

    fn spawn<'a>(
        &'a self,
        spec: &'a SandboxSpec,
    ) -> BoxFuture<'a, Result<Box<dyn SandboxInstance>, SandboxError>> {
        Box::pin(async move {
            validate_spec(spec)?;
            if !self.probe.daemon_reachable {
                return Err(SandboxError::Unavailable(format!(
                    "`{}` daemon is not reachable",
                    self.config.runtime
                )));
            }
            let name = format!("hull-ci-{}-{}", sanitize_name(&spec.job_id), short_id());
            // `spawn` reserves the box; the container itself is created on the single `exec`, because
            // a docker container's argv is fixed at `create` time and the argv is not known until
            // then. The single-use guarantee is unaffected — the guard admits exactly one `exec`, so
            // exactly one container is ever created under this name.
            Ok(Box::new(ContainerInstance {
                guard: UseGuard::new(name.clone(), spec.job_id.clone()),
                name,
                config: self.config.clone(),
                spec: spec.clone(),
                capture: None,
                created: false,
            }) as Box<dyn SandboxInstance>)
        })
    }
}

fn sanitize_name(job_id: &str) -> String {
    // Container names are a host-side identifier built from a control-plane string. Restricting it to
    // `[A-Za-z0-9_.-]` means a hostile job id cannot become an argv element that means something else.
    let s: String = job_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '-' })
        .take(48)
        .collect();
    if s.is_empty() {
        "job".into()
    } else {
        s
    }
}

fn short_id() -> String {
    // Not cryptographic — only needs to make a name unique within a node. Monotonic clock nanos do it
    // without pulling in a rng dependency.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 + d.as_secs().wrapping_mul(1_000_000_000))
        .unwrap_or(0);
    format!("{nanos:x}")
}

/// A live container. Owns its configuration rather than borrowing the backend so that teardown is a
/// `'static` future — an instance must be destroyable independently of the backend that made it.
struct ContainerInstance {
    guard: UseGuard,
    name: String,
    config: ContainerConfig,
    spec: SandboxSpec,
    capture: Option<CapturedOutput>,
    created: bool,
}

impl SandboxInstance for ContainerInstance {
    fn id(&self) -> &str {
        &self.name
    }

    fn job_id(&self) -> &str {
        self.guard.job_id()
    }

    fn lifecycle(&self) -> Lifecycle {
        self.guard.state()
    }

    fn exec<'b>(&'b mut self, req: &'b ExecRequest) -> BoxFuture<'b, Result<ExecOutcome, SandboxError>> {
        Box::pin(async move {
            validate_exec(req)?;
            self.guard.begin_exec(&req.job_id)?;

            let create = create_argv(&self.config, &self.spec, &self.name, &req.argv);
            // The one place a delivered secret is materialized on this host: the `create` CLI's own
            // environment, for the length of that one process. `create_argv` named the variables;
            // this supplies the values out of band (see the `--env NAME` block there).
            let secrets: Vec<(String, String)> =
                self.spec.secret_env.iter().map(|(n, v)| (n.clone(), v.to_string())).collect();
            let (status, out) = control_command(&self.config, create, &secrets).await?;
            if status != ExecStatus::Exited(0) {
                return Err(SandboxError::Runtime(format!("container create failed ({status:?}): {out}")));
            }
            self.created = true;

            let start = vec![
                self.config.runtime.clone(),
                "start".into(),
                "--attach".into(),
                self.name.clone(),
            ];
            let mut cmd = command_from_argv(&start, &runtime_env())?;
            let child = cmd.spawn()?;
            let mut capture = OutputCapture::new(req.caps);
            let outcome = run_to_completion(child, req.timeout, &mut capture).await?;
            self.capture = Some(capture.finish());

            if outcome.status == ExecStatus::TimedOut {
                // Killing the CLI we attached with does not stop the container: the daemon owns it.
                // §14.4's wall clock only means something if the process actually dies.
                let kill = vec![self.config.runtime.clone(), "kill".into(), self.name.clone()];
                if let Err(e) = control_command(&self.config, kill, &[]).await {
                    tracing::error!(container = %self.name, error = %e, "could not kill a timed-out container");
                }
            }
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
        // §14.1: "Destroy the whole microVM/rootfs after each job so nothing (a planted binary, a
        // poisoned cache, a lingering process) survives into the next job." `rm --force --volumes`
        // takes the writable layer with it.
        let argv = vec![
            self.config.runtime.clone(),
            "rm".into(),
            "--force".into(),
            "--volumes".into(),
            self.name.clone(),
        ];
        let created = self.created;
        Box::pin(async move {
            let result = if created {
                match control_command(&self.config, argv, &[]).await {
                    Ok((ExecStatus::Exited(0), _)) => Ok(()),
                    Ok((status, out)) => Err(SandboxError::Runtime(format!(
                        "container rm failed ({status:?}): {out}"
                    ))),
                    Err(e) => Err(e),
                }
            } else {
                Ok(())
            };
            self.guard.mark_destroyed();
            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hull_ci_proto::AuthorClass;
    use std::path::Path;

    fn linux_probe() -> DockerProbe {
        DockerProbe {
            cli_present: true,
            daemon_reachable: true,
            server_os: Some("linux".into()),
            server_version: Some("27.0.0".into()),
            cgroup_version: Some("2".into()),
            seccomp_profile: Some("builtin/default".into()),
            memory_limit: true,
            pids_limit: true,
            cpu_cfs_quota: true,
            rootless: false,
            failure: None,
        }
    }

    fn spec(ws: &Path) -> SandboxSpec {
        SandboxSpec {
            job_id: "job-1".into(),
            step_id: "step-1".into(),
            image: "hull-ci/base:1".into(),
            workspace: ws.to_path_buf(),
            workdir: "/workspace".into(),
            limits: Default::default(),
            env: crate::env::base_env("/tmp"),
            author_class: AuthorClass::Member,
            broker_authorised: Vec::new(),
            secret_env: Vec::new(),
        }
    }

    #[test]
    fn a_reachable_linux_daemon_enforces_most_of_14_4_but_never_cross_tenant_safety() {
        let c = controls_for(&linux_probe(), &ContainerConfig::default());
        assert!(c.single_use && c.non_root && c.read_only_rootfs && c.tmpfs_scratch);
        assert!(c.caps_dropped && c.no_new_privileges && c.seccomp_default_deny);
        assert!(c.cpu_limit && c.memory_limit && c.pid_limit);
        assert!(c.egress_deny && c.metadata_blackhole && c.no_inbound);
        assert!(!c.disk_limit, "we do not attempt a disk quota, so we must not claim one");
        assert!(!c.kernel_isolation, "a container shares the host kernel — always (§14.1)");
        assert!(!c.to_capabilities().admits_untrusted(), "M1 is single-tenant by construction");
        assert_eq!(
            c.unmet_clauses(),
            vec![
                "§14.1 kernel/hardware isolation (microVM-class boundary)",
                "§14.4 disk limit"
            ]
        );
    }

    #[test]
    fn an_unreachable_daemon_claims_nothing() {
        // The state of *this* host: docker CLI installed, daemon down.
        let probe = DockerProbe { cli_present: true, daemon_reachable: false, ..Default::default() };
        let c = controls_for(&probe, &ContainerConfig::default());
        assert_eq!(c, EnforcedControls::NONE);
        assert!(!c.to_capabilities().single_use);
    }

    #[test]
    fn a_named_network_forfeits_the_network_capabilities() {
        // We cannot see the rules on someone else's bridge, so we do not claim they exist.
        let config = ContainerConfig { network: NetworkMode::Named("ci".into()), ..Default::default() };
        let c = controls_for(&linux_probe(), &config);
        assert!(!c.egress_deny);
        assert!(!c.metadata_blackhole);
        assert!(!c.no_inbound);
        assert!(c.non_root, "the privilege controls are unaffected by the network choice");
    }

    #[test]
    fn a_daemon_without_cgroup_controllers_reports_the_missing_limits() {
        let probe = DockerProbe { memory_limit: false, pids_limit: false, cpu_cfs_quota: false, ..linux_probe() };
        let c = controls_for(&probe, &ContainerConfig::default());
        assert!(!c.memory_limit && !c.pid_limit && !c.cpu_limit);
        assert!(c.unmet_clauses().iter().any(|s| s.contains("memory limit")));
    }

    #[test]
    fn unconfined_seccomp_is_reported_as_absent() {
        let probe = DockerProbe { seccomp_profile: Some("unconfined".into()), ..linux_probe() };
        assert!(!controls_for(&probe, &ContainerConfig::default()).seccomp_default_deny);
    }

    #[test]
    fn create_argv_carries_every_14_4_flag_and_never_a_shell() {
        let t = tempfile::tempdir().unwrap();
        let backend = ContainerBackend::from_probe(ContainerConfig::default(), linux_probe());
        let spec = spec(t.path());
        let argv = backend.create_argv(&spec, "hull-ci-job-1-abc", &["cargo".into(), "test".into()]);

        let joined = argv.join(" ");
        for expected in [
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "--network none",
            "--user 65534:65534",
            "--pids-limit",
            "--memory",
            "--cpus",
            "--tmpfs /tmp:rw,noexec,nosuid,nodev",
            "--entrypoint cargo",
        ] {
            assert!(joined.contains(expected), "missing {expected} in {joined}");
        }
        assert!(!argv.iter().any(|a| a == "sh" || a == "-c" || a == "bash"), "no shell, ever (D§7.2)");
        assert_eq!(argv.last().unwrap(), "test");
        assert!(argv.iter().any(|a| a == "hull-ci/base:1"));
        // The environment goes in as discrete argv elements, one per variable.
        assert!(argv.windows(2).any(|w| w[0] == "--env" && w[1] == "CI=true"));
    }

    #[test]
    fn a_delivered_secret_never_appears_in_the_runtimes_argv() {
        // A local disclosure that is easy to ship by accident: `--env NAME=VALUE` puts the plaintext
        // in the `docker create` process's own argv, which on Linux every other user on the host can
        // read out of `/proc` for as long as that process lives. Broker-delivered values therefore go
        // in by name, and the value reaches the daemon through the CLI's environment instead (see
        // `ContainerInstance::exec`).
        let ws = tempfile::tempdir().unwrap();
        let mut s = spec(ws.path());
        s.broker_authorised = vec!["NPM_TOKEN".into()];
        s.secret_env = vec![("NPM_TOKEN".into(), zeroize::Zeroizing::new("npm_s3cr3tvalue".into()))];

        let argv = create_argv(&ContainerConfig::default(), &s, "sbx", &["cargo".into(), "test".into()]);
        assert!(
            argv.windows(2).any(|w| w[0] == "--env" && w[1] == "NPM_TOKEN"),
            "the variable must be named: {argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a.contains("npm_s3cr3tvalue")),
            "and its value must appear nowhere in the argv: {argv:?}"
        );
        // The ordinary allowlisted environment is unaffected and still travels as NAME=VALUE, which
        // is fine — none of it is a credential.
        assert!(argv.windows(2).any(|w| w[0] == "--env" && w[1] == "CI=true"));
    }

    #[test]
    fn a_hostile_job_id_cannot_become_an_argv_flag() {
        assert_eq!(sanitize_name("../../etc/passwd"), "..-..-etc-passwd");
        assert!(!sanitize_name("--privileged x").contains(' '));
        assert_eq!(sanitize_name(""), "job");
        assert!(sanitize_name(&"a".repeat(200)).len() <= 48);
    }

    #[tokio::test]
    async fn detect_refuses_when_there_is_no_daemon() {
        // On this host (macOS, Docker Desktop not running) this is the live path: no boundary, so no
        // backend. The alternative — falling back to the host — is the §14.1 hole.
        let config = ContainerConfig { runtime: "definitely-not-a-runtime".into(), ..Default::default() };
        let err = ContainerBackend::detect(config).await.expect_err("must refuse");
        assert!(matches!(err, SandboxError::Unavailable(_)));
    }

    /// The live path, for a host that actually has a daemon and the image.
    ///
    /// `#[ignore]` because this crate is developed on macOS with the Docker VM usually down, and a
    /// test that silently passes when the thing it tests did not run is worse than one that is
    /// obviously skipped. Run it on a Linux node with:
    /// `cargo test -p hull-ci-node -- --ignored container::tests::live`.
    #[tokio::test]
    #[ignore = "requires a running container daemon and the alpine image"]
    async fn live_container_runs_argv_and_is_destroyed() {
        let t = tempfile::tempdir().unwrap();
        let backend = ContainerBackend::detect(ContainerConfig::default()).await.expect("daemon");
        assert!(backend.controls().egress_deny, "the live probe must confirm --network none");

        let mut s = spec(t.path());
        s.image = "alpine:3".into();
        let mut sbx = backend.spawn(&s).await.expect("spawn");
        let req = ExecRequest {
            job_id: s.job_id.clone(),
            argv: vec!["/bin/echo".into(), "live-ok".into()],
            timeout: Duration::from_secs(120),
            caps: crate::capture::OutputCaps::default(),
        };
        let outcome = sbx.exec(&req).await.expect("exec");
        assert_eq!(outcome.status, ExecStatus::Exited(0));
        assert!(sbx.collect().await.unwrap().text().contains("live-ok"));

        let name = sbx.id().to_string();
        sbx.destroy().await.expect("destroy");
        // §14.1: nothing survives the job.
        let (status, _) = control_command(
            &ContainerConfig::default(),
            vec!["docker".into(), "inspect".into(), name],
            &[],
        )
        .await
        .unwrap();
        assert_ne!(status, ExecStatus::Exited(0), "the container must no longer exist");
    }

    /// §14 as tests, not assertions (design D§14). Each of these asserts a control the capability
    /// struct *claims*, against a live daemon — because a backend that reports `egress_deny: true`
    /// and does not enforce it is strictly worse than one that admits it cannot, and nothing but a
    /// live probe can tell those two apart.
    #[tokio::test]
    #[ignore = "requires a running container daemon and the alpine image"]
    async fn live_a_job_cannot_reach_the_cloud_metadata_endpoint() {
        // Spec §14.2 names this one directly: the classic RCE → instance-role credential path.
        let out = run_live(&["/bin/sh", "-c",
            "wget -q -T 2 -O- http://169.254.169.254/latest/meta-data/ 2>&1; echo rc=$?"]).await;
        assert!(out.contains("rc=1"), "the metadata endpoint must be unreachable, got: {out}");
        assert!(!out.contains("ami-"), "and nothing that looks like instance metadata came back: {out}");
    }

    #[tokio::test]
    #[ignore = "requires a running container daemon and the alpine image"]
    async fn live_a_job_has_no_egress_at_all() {
        // Spec §14.3: default egress-deny. Tested against DNS and a raw IP separately, because a
        // resolver failure and a routing failure look the same from inside and only one of them is
        // the control we mean to be asserting.
        let dns = run_live(&["/bin/sh", "-c", "wget -q -T 2 -O- http://example.com 2>&1; echo rc=$?"]).await;
        assert!(dns.contains("rc=1"), "named egress must fail: {dns}");

        let raw = run_live(&["/bin/sh", "-c", "wget -q -T 2 -O- http://1.1.1.1 2>&1; echo rc=$?"]).await;
        assert!(raw.contains("rc=1"), "egress to a raw IP must fail too: {raw}");
    }

    #[tokio::test]
    #[ignore = "requires a running container daemon and the alpine image"]
    async fn live_a_job_runs_unprivileged_on_a_read_only_root() {
        // §14.4: non-root, read-only rootfs, writable tmpfs scratch.
        let who = run_live(&["/bin/sh", "-c", "id -u"]).await;
        assert!(!who.trim_start().starts_with('0'), "a job must not run as root, got uid: {who}");

        let ro = run_live(&["/bin/sh", "-c", "touch /planted 2>&1; echo rc=$?"]).await;
        assert!(ro.contains("rc=1"), "the root filesystem must be read-only: {ro}");

        let tmp = run_live(&["/bin/sh", "-c", "touch /tmp/scratch && echo tmp-ok"]).await;
        assert!(tmp.contains("tmp-ok"), "but /tmp must be writable: {tmp}");
    }

    #[tokio::test]
    #[ignore = "requires a running container daemon and the alpine image"]
    async fn live_nothing_a_job_plants_survives_into_the_next_one() {
        // §14.1's single-use rule, observed rather than trusted. The first job writes into the one
        // place it *can* write; the second must not find it.
        let first = run_live(&["/bin/sh", "-c", "echo planted > /tmp/evidence && cat /tmp/evidence"]).await;
        assert!(first.contains("planted"), "the first job should have written its marker: {first}");

        let second = run_live(&["/bin/sh", "-c", "cat /tmp/evidence 2>&1; echo rc=$?"]).await;
        assert!(second.contains("rc=1"), "a fresh sandbox must not carry the last job's writes: {second}");
    }

    /// Run one argv in a single-use live container and return its captured output.
    async fn run_live(argv: &[&str]) -> String {
        let t = tempfile::tempdir().unwrap();
        let backend = ContainerBackend::detect(ContainerConfig::default()).await.expect("daemon");
        let mut s = spec(t.path());
        s.image = "alpine:3".into();
        let mut sbx = backend.spawn(&s).await.expect("spawn");
        let req = ExecRequest {
            job_id: s.job_id.clone(),
            argv: argv.iter().map(|a| a.to_string()).collect(),
            timeout: Duration::from_secs(120),
            caps: crate::capture::OutputCaps::default(),
        };
        let _ = sbx.exec(&req).await.expect("exec");
        let out = sbx.collect().await.unwrap().text().to_string();
        sbx.destroy().await.expect("destroy");
        out
    }

    #[tokio::test]
    async fn spawn_refuses_without_a_daemon_rather_than_running_on_the_host() {
        let t = tempfile::tempdir().unwrap();
        let probe = DockerProbe { cli_present: true, daemon_reachable: false, ..Default::default() };
        let backend = ContainerBackend::from_probe(ContainerConfig::default(), probe);
        // `Box<dyn SandboxInstance>` is not `Debug`, so match rather than `expect_err`.
        match backend.spawn(&spec(t.path())).await {
            Err(SandboxError::Unavailable(_)) => {}
            Err(other) => panic!("wrong refusal: {other}"),
            Ok(_) => panic!("a backend with no daemon must not hand out a sandbox"),
        }
    }
}
