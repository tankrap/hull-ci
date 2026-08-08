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
//! # Why there is a reaper
//!
//! §14.1's single-use rule is a statement about what is left behind, and this backend's teardown
//! runs in a future: `destroy()` is an `async fn` the node awaits after a job. Every way that future
//! fails to run — the node is `SIGKILL`ed, the host loses power, the `run_assignment` future is
//! dropped on a cancelled lease — leaves a container the daemon is perfectly happy to keep running,
//! with the job's workspace still bind-mounted, past whatever wall clock §14.4 was enforcing. An
//! audit demonstrated it directly: killing the attaching CLI leaves the container `Up`, because the
//! CLI is not the container's parent — the daemon is.
//!
//! Nothing in a destructor can close that, because the case that matters most is the one where no
//! destructor runs at all. So the guarantee is placed where it can actually hold: [`reap_orphans`]
//! runs at node start, before this backend has created anything, and removes every container
//! carrying **this runner's** label. See [`ContainerConfig::runner_id`] for what makes that "this
//! runner's" and not "everybody's". [`ContainerInstance`]'s `Drop` is a best-effort second line,
//! documented at the impl.
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
use std::sync::Arc;
use std::time::Duration;

use hull_ci_proto::IsolationTier;

use crate::capture::{CapturedOutput, OutputCapture};
use crate::controls::EnforcedControls;
use crate::pool::{PoolConfig, PoolKey, PoolMember, PoolStats, SandboxPool};
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
    /// it is a mode that lets those two capabilities be reported `true` with no evidence beyond the
    /// flag itself.
    ///
    /// **The default, and it stays the default.** §14.3: "A job **SHOULD** run with no outbound
    /// network."
    None,
    /// A named docker network. We cannot see its nftables rules from here, so both `egress_deny` and
    /// `metadata_blackhole` drop to `false` — the operator may well have locked it down, but this code
    /// has no evidence of it, and reporting an unverified control is exactly the failure mode that
    /// turns this design into a security hole.
    Named(String),
    /// A network on which the only reachable destination is meant to be the package proxy (§14.3's
    /// "restrict egress to an allowlisted, authenticated package proxy", D§7.3).
    ///
    /// **This is the mode that weakens the strongest guarantee in this crate**, so it carries its own
    /// evidence: a [`ProxyNetwork`] whose `posture` is `None` claims nothing at all, and the posture
    /// can only be filled in by [`probe_network_posture`], which finds out by *trying*. Naming a
    /// docker network `internal` is not evidence; being unable to reach 1.1.1.1 from inside it is.
    ProxyOnly(ProxyNetwork),
}

/// A sandbox network with a package proxy on it, and what was actually observed about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyNetwork {
    /// The docker network jobs are attached to.
    pub network: String,
    /// `host:port` of the proxy **as a sandbox on this network sees it** — normally the network's own
    /// gateway address, because the recommended deployment runs the proxy in the node's network
    /// namespace rather than as a peer container. See [`probe_network_posture`].
    pub endpoint: String,
    /// What a live probe container observed from inside this network. `None` means nobody has
    /// looked, and [`controls_for`] therefore claims nothing — the honest default is a property of
    /// the type rather than a rule someone has to remember.
    pub posture: Option<NetworkPosture>,
}

impl ProxyNetwork {
    /// Declare the configuration. The posture is deliberately absent: only [`probe_network_posture`]
    /// can supply one, so there is no way to write a `ProxyNetwork` that asserts a posture nobody
    /// measured.
    pub fn new(network: impl Into<String>, endpoint: impl Into<String>) -> Self {
        ProxyNetwork { network: network.into(), endpoint: endpoint.into(), posture: None }
    }

    fn proxy_host_port(&self) -> (String, String) {
        match self.endpoint.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.to_string()),
            None => (self.endpoint.clone(), "80".to_string()),
        }
    }
}

/// Ports scanned on the sandbox network's gateway — which **is the node itself**.
///
/// D§7.3 says the proxy must be the only reachable destination: "never the open internet, never Hull,
/// never the internal content store, never other nodes." A bridge network's gateway is the node's own
/// address on that bridge, and traffic to it takes the kernel's `INPUT` path rather than `FORWARD` —
/// so `--internal`, which installs `FORWARD` drops, does **not** stop a sandbox reaching a service the
/// node has bound on `0.0.0.0`. That is the one real hole in this posture, and it is the reason this
/// list exists.
///
/// `2375`/`2376` are the ones that matter most: an unauthenticated Docker API reachable from inside a
/// sandbox is a complete host takeover, and it is a port people leave open.
///
/// **This is a sample, not a proof.** Finding a port open disproves the posture; finding none does
/// not prove there is nothing else listening. [`NetworkPosture::caveats`] says so out loud, and an
/// operator who wants the strong version binds the node's services to a specific interface rather
/// than to `0.0.0.0`.
pub const GATEWAY_SCAN_PORTS: &[u16] = &[
    22, 80, 443, 2375, 2376, 2379, 3000, 3306, 5000, 5432, 6379, 6443, 8000, 8080, 8443, 9090, 9100,
    10250,
];

/// What a probe container observed from inside a sandbox network.
///
/// Every field is the result of *doing the thing*, not of reading configuration. The one exception is
/// [`declared_internal`](Self::declared_internal), which is the daemon's own statement — kept because
/// it is a useful cross-check, and deliberately not sufficient on its own.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkPosture {
    /// The daemon reports `Internal: true` for this network.
    pub declared_internal: bool,
    /// The sandbox's routing table has **no default route**. The strongest single fact here: without
    /// one, and without `CAP_NET_ADMIN` to add one, the sandbox can only address its own subnet.
    pub no_default_route: bool,
    /// A raw public IP (`1.1.1.1:80`) could not be reached.
    pub public_ip_unreachable: bool,
    /// A public hostname could not be resolved.
    pub public_dns_unresolvable: bool,
    /// `169.254.169.254:80` could not be reached (§14.2 names this one directly).
    ///
    /// **Not sufficient on its own** — see [`NetworkPosture::metadata_blackholed`]. On a host with no
    /// metadata service at all (a laptop, a bare-metal node, Docker Desktop's VM) this is `true` on
    /// every network including a wide-open one, because nothing is listening there to refuse the
    /// connection either way.
    pub metadata_unreachable: bool,
    /// The configured proxy endpoint accepted a connection. Not a *safety* fact — it is the
    /// usability one, and a proxy posture with no proxy on it is a broken deployment rather than an
    /// unsafe one.
    pub proxy_reachable: bool,
    /// A peer container on the same network could not be reached — i.e. inter-container
    /// communication is off, so one job cannot open a connection to another's.
    pub peer_unreachable: bool,
    /// A sandbox could not add its own default route (i.e. `CAP_NET_ADMIN` really is dropped, so the
    /// "no default route" fact above is not something a job can undo).
    pub cannot_add_route: bool,
    /// Ports found listening on the network gateway — the node — other than the proxy's. **Any**
    /// entry here disproves "the proxy is the only reachable destination".
    pub gateway_ports_open: Vec<u16>,
    /// Set when the probe could not be run at all. A posture that failed to run claims nothing.
    pub failure: Option<String>,
}

impl NetworkPosture {
    /// Whether this posture proves §14.3's egress-deny **for this deployment's network**.
    ///
    /// Every conjunct is required, and each one covers a way the others can be true while the
    /// posture is still open:
    ///
    /// * `declared_internal` — the daemon agrees with us about what this network is.
    /// * `no_default_route` + `cannot_add_route` — the structural fact and the fact that a job cannot
    ///   undo it. Without the second, the first is a default a hostile job edits.
    /// * `public_ip_unreachable` + `public_dns_unresolvable` — behaviour, tested separately because
    ///   a resolver failure and a routing failure look identical from inside and only one of them is
    ///   the control being asserted.
    /// * `gateway_ports_open.is_empty()` — nothing of the node's own is reachable. See
    ///   [`GATEWAY_SCAN_PORTS`] for why this is a sample rather than a proof.
    pub fn egress_denied(&self) -> bool {
        self.failure.is_none()
            && self.declared_internal
            && self.no_default_route
            && self.cannot_add_route
            && self.public_ip_unreachable
            && self.public_dns_unresolvable
            && self.gateway_ports_open.is_empty()
    }

    /// Whether the cloud metadata endpoint is genuinely unreachable (§14.2).
    ///
    /// **Deliberately not just [`metadata_unreachable`](Self::metadata_unreachable).** That field is
    /// a connect probe, and a connect probe cannot tell "this address is blackholed" from "nothing
    /// happens to be listening on it". On any host without a metadata service — a developer laptop,
    /// a bare-metal node, the Docker Desktop VM this crate is built on — the connect fails on a
    /// *wide-open bridge network* exactly as it does under `--network none`. A live test caught this
    /// by asserting the open-bridge control and finding `metadata_blackhole: true` on a network with
    /// full internet access.
    ///
    /// So the claim rests on the structural fact instead: `169.254.169.254` is off-subnet, so with no
    /// default route there is nowhere to send it, and with `CAP_NET_ADMIN` dropped a job cannot make
    /// one. The connect probe stays as corroboration — if it *did* answer, something is very wrong —
    /// but it is not what carries the claim.
    pub fn metadata_blackholed(&self) -> bool {
        self.failure.is_none()
            && self.metadata_unreachable
            && self.no_default_route
            && self.cannot_add_route
    }

    /// What this posture did **not** establish, in the operator's words.
    ///
    /// Logged at node start alongside [`EnforcedControls::unmet_clauses`]. The difference between the
    /// two matters: `unmet_clauses` lists controls that are off, and this lists controls that are on
    /// but whose evidence has an edge. A reader deserves both.
    pub fn caveats(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.failure.is_some() {
            out.push("the network posture probe did not run, so nothing about this network is known".into());
            return out;
        }
        out.push(format!(
            "the gateway port scan covers {} well-known ports, so an unusual port bound on the \
             node's `0.0.0.0` would not have been found; bind node services to a specific interface \
             for the strong version",
            GATEWAY_SCAN_PORTS.len()
        ));
        out.push(
            "the metadata-endpoint claim rests on there being no route off-subnet, not on the \
             connect probe: on a host with no metadata service the probe fails identically on an \
             open network"
                .into(),
        );
        if !self.peer_unreachable {
            out.push(
                "inter-container communication is ON for this network, so one job can open a \
                 connection to another job's sandbox (create the network with \
                 `--opt com.docker.network.bridge.enable_icc=false`)"
                    .into(),
            );
        }
        out.push(
            "the node itself can always open a connection into a sandbox on a bridge network; \
             §14.3's `no inbound` is reported here as `no inbound from another sandbox`"
                .into(),
        );
        if !self.proxy_reachable {
            out.push(
                "the configured proxy endpoint did not answer, so jobs on this network can reach \
                 nothing at all"
                    .into(),
            );
        }
        out
    }
}

/// The label key every container this backend creates carries, and the only thing [`reap_orphans`]
/// matches on.
pub const RUNNER_LABEL: &str = "hull-ci.runner";

/// The runner identity a [`ContainerConfig`] carries when nobody sets one.
///
/// Deliberately a **fixed** string rather than something process-unique. The reaper's entire job is
/// to find containers left behind by a *previous incarnation of this runner*, and an id that changed
/// on every boot could never match one — a per-process default would compile, run, reap nothing, and
/// look exactly like a working feature.
///
/// The price of a fixed default is the collision case, and it is worth stating plainly: two node
/// agents sharing one daemon and both left at this default would reap each other's **live**
/// containers at start. So the composition root sets [`ContainerConfig::runner_id`] from
/// `NodeConfig::node_id`, which the scheduler's node roster already requires to be unique across the
/// fleet (D§5.1), and [`ContainerBackend::detect`] says so out loud when it finds the default still
/// in place.
pub const DEFAULT_RUNNER_ID: &str = "hull-ci-node-0";

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
    /// **Stable identity of this runner**, stamped on every container as `hull-ci.runner=<id>`.
    ///
    /// Two requirements pull in opposite directions and both have to hold, which is why this is
    /// configuration rather than something derived:
    ///
    /// * **Stable across restarts**, or [`reap_orphans`] cannot recognise the containers this
    ///   runner's previous incarnation left behind — which is the only thing it exists to do.
    /// * **Unique across runners sharing a daemon**, or one node's start reaps another node's
    ///   in-flight jobs. Several nodes on one daemon is a normal development and CI topology, so the
    ///   reaper never removes a container that does not carry *this* id — never by name prefix,
    ///   never by the `hull-ci.job` label, never "everything that looks like ours".
    ///
    /// Defaults to [`DEFAULT_RUNNER_ID`].
    pub runner_id: String,
    /// Warm sandbox pooling (D§6.4, [`crate::pool`]).
    ///
    /// **Off by default.** A pool member is a container holding its configured memory resident before
    /// any job exists to want it, so a deployment that did not ask for that does not get it. Turning
    /// it on changes latency and nothing else: a job that finds no member creates one the cold way,
    /// and a pool that cannot warm at all costs an `error` line rather than a verdict.
    pub pool: PoolConfig,
}

impl Default for ContainerConfig {
    fn default() -> Self {
        ContainerConfig {
            runtime: "docker".into(),
            network: NetworkMode::None,
            user: "65534:65534".into(),
            seccomp_profile: None,
            control_timeout: Duration::from_secs(60),
            runner_id: DEFAULT_RUNNER_ID.into(),
            pool: PoolConfig::default(),
        }
    }
}

impl ContainerConfig {
    /// The `--label` / `--filter` value that ties a container to this runner.
    ///
    /// One function for both the writing side ([`create_argv`]) and the reading side
    /// ([`reap_orphans`]), because a reaper whose filter does not exactly match the label the
    /// creator wrote is a reaper that silently removes nothing — and "silently removes nothing" is
    /// indistinguishable from "there was nothing to remove".
    pub fn runner_label(&self) -> String {
        format!("{RUNNER_LABEL}={}", sanitize_name(&self.runner_id))
    }
}

/// What one [`reap_orphans`] pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reaped {
    /// Container ids removed.
    pub removed: Vec<String>,
    /// Containers found but not removable, and why. Reported rather than swallowed: an orphan that
    /// could not be removed is still an orphan, and the operator is the only one who can act on it.
    pub failures: Vec<String>,
}

/// Remove every container carrying this runner's label. Runs at node start (§14.1).
///
/// This is the teardown for the cases no teardown code can reach: a node killed with `SIGKILL`, a
/// host that lost power, a `create` whose CLI was killed while the daemon went on creating the
/// container. In every one of those the daemon still holds a container with the job's workspace
/// bind-mounted and its wall clock long expired — under `--network none` an unreachable one, but
/// under a proxy network with inter-container communication left on, a **peer another job can open a
/// connection to** (see [`NetworkPosture::peer_unreachable`]).
///
/// # Why it is safe with several nodes on one daemon
///
/// The filter is `label=hull-ci.runner=<this runner's id>` and nothing else — an exact key/value
/// match, verified against docker 28.0.4 (a filter value that is a *prefix* of a container's label
/// matches nothing). A runner therefore cannot see, let alone remove, a container another runner
/// created, whatever its name, image or job label. The contract that makes that true is on
/// [`ContainerConfig::runner_id`]: distinct ids for distinct runners.
///
/// # Why it runs before anything else
///
/// [`ContainerBackend::detect`] calls this **before** [`probe_network_posture`], because the posture
/// probe starts a peer container carrying this same label. Reaping afterwards would remove the peer
/// the probe is currently measuring against, and the probe would conclude that inter-container
/// communication is off when nobody had asked the question.
pub async fn reap_orphans(config: &ContainerConfig) -> Result<Reaped, SandboxError> {
    let label = config.runner_label();
    let list = vec![
        config.runtime.clone(),
        "ps".into(),
        "--all".into(),
        "--quiet".into(),
        "--filter".into(),
        format!("label={label}"),
    ];
    let (status, out) = control_command(config, list, &[]).await?;
    if status != ExecStatus::Exited(0) {
        return Err(SandboxError::Runtime(format!(
            "could not list containers for reaping ({status:?}): {out}"
        )));
    }

    let mut reaped = Reaped::default();
    for id in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let rm = vec![
            config.runtime.clone(),
            "rm".into(),
            "--force".into(),
            "--volumes".into(),
            id.to_string(),
        ];
        match control_command(config, rm, &[]).await {
            Ok((ExecStatus::Exited(0), _)) => reaped.removed.push(id.to_string()),
            Ok((status, out)) => reaped.failures.push(format!("{id}: rm exited {status:?}: {out}")),
            Err(e) => reaped.failures.push(format!("{id}: {e}")),
        }
    }

    if !reaped.removed.is_empty() {
        // Warn, not info. Every entry here is a container that outlived the job it was created for,
        // which means a node died holding one — the operator wants to know that happened even though
        // we have now cleaned up after it.
        tracing::warn!(
            runner = %config.runner_id,
            removed = ?reaped.removed,
            "reaped orphaned job containers left by a previous incarnation of this runner (§14.1)"
        );
    }
    for failure in &reaped.failures {
        tracing::error!(runner = %config.runner_id, %failure, "could not reap an orphaned container");
    }
    Ok(reaped)
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

/// Image used for the network-posture probe. Small, and has `ip`, `nc`, `nslookup` and `timeout`.
pub const PROBE_IMAGE: &str = "alpine:3";

/// The probe script. A constant, and **no configuration is interpolated into it** — every operator
/// value arrives through `--env`, so a network name or endpoint from a config file can never become
/// shell syntax. (D§7.2's "no raw shell on any host, ever" is a rule about *job* code; this script is
/// ours and contains nothing anybody outside this file wrote. The `--env` discipline is what keeps
/// that true.)
///
/// `timeout N nc HOST PORT </dev/null` is the reachability primitive: `0` for an accepted connection,
/// `1` for a refused one, `124`/`143` for a timeout. BusyBox's `nc` has no `-z` or `-w`, and using
/// them anyway makes `nc` exit non-zero on the unrecognised option — which reads exactly like
/// "unreachable" and would make every one of these probes silently vacuous.
const POSTURE_SCRIPT: &str = r#"
ip route >/dev/null 2>&1; echo "iprc=$?"
echo "default_route=$(ip route 2>/dev/null | grep -c '^default')"
timeout 3 nc 1.1.1.1 80 </dev/null >/dev/null 2>&1; echo "raw_ip=$?"
timeout 3 nc 169.254.169.254 80 </dev/null >/dev/null 2>&1; echo "metadata=$?"
nslookup example.com >/dev/null 2>&1; echo "public_dns=$?"
timeout 5 nc "$PROXY_HOST" "$PROXY_PORT" </dev/null >/dev/null 2>&1; echo "proxy=$?"
if [ -n "$PEER_IP" ]; then
  timeout 3 nc "$PEER_IP" 8080 </dev/null >/dev/null 2>&1; echo "peer=$?"
else
  echo "peer=skip"
fi
for p in $SCAN_PORTS; do
  timeout 2 nc "$GW" "$p" </dev/null >/dev/null 2>&1 && echo "gwopen=$p"
done
ip route add default via "$GW" >/dev/null 2>&1; echo "route_add=$?"
echo "probe_done=1"
"#;

/// Find out what a sandbox on `network` can actually reach, by putting a container there and trying.
///
/// This is the function that makes [`NetworkMode::ProxyOnly`] safe to offer at all. Moving off
/// `--network none` weakens the strongest guarantee this crate has, and the failure mode — a backend
/// that reports `egress_deny: true` while a job can reach the internet — is worse than having no
/// proxy at all, because the scheduler believes the struct. So the posture is **measured**:
///
/// 1. Ask the daemon whether the network is `Internal` and what its gateway is.
/// 2. Start a peer container on the network, so "can one job reach another" is a question with a
///    real answer rather than an assumption about `enable_icc`.
/// 3. Run a probe container **with the same hardening a job gets** (`--cap-drop ALL`, non-root) and
///    have it try: a raw public IP, a public hostname, the cloud metadata endpoint, the proxy, the
///    peer, a list of ports on the node, and adding its own default route.
/// 4. Tear the peer down.
///
/// Anything that goes wrong sets [`NetworkPosture::failure`], and a posture with a failure proves
/// nothing — [`NetworkPosture::egress_denied`] returns `false` and the capabilities follow.
pub async fn probe_network_posture(
    config: &ContainerConfig,
    proxy: &ProxyNetwork,
) -> NetworkPosture {
    let mut posture = NetworkPosture::default();
    let fail = |mut p: NetworkPosture, why: String| {
        p.failure = Some(why);
        p
    };

    // 1. The daemon's own statement, and the gateway address we will scan.
    let inspect = vec![
        config.runtime.clone(),
        "network".into(),
        "inspect".into(),
        proxy.network.clone(),
        "--format".into(),
        "{{json .}}".into(),
    ];
    let (status, out) = match control_command(config, inspect, &[]).await {
        Ok(v) => v,
        Err(e) => return fail(posture, format!("could not inspect network `{}`: {e}", proxy.network)),
    };
    if status != ExecStatus::Exited(0) {
        return fail(posture, format!("network `{}` does not exist ({status:?})", proxy.network));
    }
    let json: serde_json::Value = match serde_json::from_str(out.trim()) {
        Ok(v) => v,
        Err(e) => return fail(posture, format!("could not parse `network inspect`: {e}")),
    };
    posture.declared_internal = json["Internal"].as_bool().unwrap_or(false);
    let gateway = json["IPAM"]["Config"]
        .as_array()
        .and_then(|c| c.first())
        .and_then(|c| c["Gateway"].as_str())
        .map(str::to_string);
    let Some(gateway) = gateway else {
        // No gateway address means the scan cannot run, and a posture with an unscanned gateway is
        // one we must not certify.
        return fail(posture, format!("network `{}` reports no gateway address", proxy.network));
    };

    // 2. A peer on the network, so the inter-container question is answered by observation.
    let peer_name = format!("hull-ci-probe-peer-{}", short_id());
    let peer_argv = vec![
        config.runtime.clone(),
        "run".into(),
        "--detach".into(),
        "--name".into(),
        peer_name.clone(),
        "--network".into(),
        proxy.network.clone(),
        "--label".into(),
        "hull-ci.probe=peer".into(),
        // Reapable (§14.1). A peer left behind by a probe that was interrupted is a live container
        // on the sandbox network — the exact thing `peer_unreachable` exists to detect — so it has
        // to carry the runner label like everything else this backend creates.
        "--label".into(),
        config.runner_label(),
        PROBE_IMAGE.to_string(),
        "nc".into(),
        "-l".into(),
        "-p".into(),
        "8080".into(),
    ];
    let peer_ip = match control_command(config, peer_argv, &[]).await {
        Ok((ExecStatus::Exited(0), _)) => peer_ip_of(config, &peer_name).await,
        // A peer we could not start is not a reason to abandon the whole probe; it is a reason not to
        // claim the one fact it was there to establish.
        _ => None,
    };

    // 3. The probe proper, hardened like a job so that `cannot_add_route` is a fact about the
    //    configuration jobs actually run under.
    let scan: Vec<String> = GATEWAY_SCAN_PORTS.iter().map(|p| p.to_string()).collect();
    let (proxy_host, proxy_port) = proxy.proxy_host_port();
    let env = [
        ("GW", gateway.as_str()),
        ("PEER_IP", peer_ip.as_deref().unwrap_or("")),
        ("PROXY_HOST", proxy_host.as_str()),
        ("PROXY_PORT", proxy_port.as_str()),
        ("SCAN_PORTS", scan.join(" ").as_str()),
    ]
    .map(|(k, v)| (k.to_string(), v.to_string()));

    let mut probe_argv = vec![
        config.runtime.clone(),
        "run".into(),
        "--rm".into(),
        "--network".into(),
        proxy.network.clone(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--user".into(),
        config.user.clone(),
        "--label".into(),
        "hull-ci.probe=posture".into(),
        "--label".into(),
        config.runner_label(),
    ];
    for (k, v) in &env {
        probe_argv.push("--env".into());
        probe_argv.push(format!("{k}={v}"));
    }
    probe_argv.extend([
        "--entrypoint".to_string(),
        "/bin/sh".to_string(),
        PROBE_IMAGE.to_string(),
        "-c".to_string(),
        POSTURE_SCRIPT.to_string(),
    ]);

    let probe_result = control_command(config, probe_argv, &[]).await;

    // 4. Tear the peer down whatever happened. A probe container left running *is* a peer on the
    //    sandbox network, which is the exact thing the peer check exists to detect — so leaking one
    //    would quietly change the posture of every job placed afterwards.
    let rm = vec![config.runtime.clone(), "rm".into(), "--force".into(), peer_name.clone()];
    if let Err(e) = control_command(config, rm, &[]).await {
        tracing::error!(peer = %peer_name, error = %e, "could not remove a posture-probe peer");
    }

    let (status, output) = match probe_result {
        Ok(v) => v,
        Err(e) => return fail(posture, format!("posture probe could not run: {e}")),
    };
    if status != ExecStatus::Exited(0) {
        return fail(posture, format!("posture probe exited {status:?}: {output}"));
    }
    let mut posture = parse_posture(&output, posture, peer_ip.is_some());

    exclude_proxy_port(&mut posture, &gateway, &proxy_host, &proxy_port);
    posture
}

/// Drop the proxy's own port from the gateway findings.
///
/// The proxy is the one destination that is *supposed* to answer, so finding it is the expected
/// result rather than a violation. The `proxy_host == gateway` guard is the part that matters: if the
/// proxy is a peer container rather than a node process, then an open port of that same number **on
/// the node** is a different service entirely and a genuine finding, so it stays.
fn exclude_proxy_port(posture: &mut NetworkPosture, gateway: &str, proxy_host: &str, proxy_port: &str) {
    if proxy_host != gateway {
        return;
    }
    if let Ok(port) = proxy_port.parse::<u16>() {
        posture.gateway_ports_open.retain(|p| *p != port);
    }
}

/// Read the probe's `key=value` output into a posture.
///
/// A pure function, so the parse — which is where a misread line turns into a false capability — is
/// testable without a daemon.
pub fn parse_posture(output: &str, mut posture: NetworkPosture, had_peer: bool) -> NetworkPosture {
    let mut done = false;
    let mut ip_works = false;
    // A tool the probe image does not have. Every reachability line here is "rc != 0 means
    // unreachable", so a missing `nc`, `timeout` or `nslookup` — `127` from the shell — reads as the
    // *strongest possible* posture: nothing was reachable because nothing was ever tried. The live
    // tests pair each probe with an open-network control that would catch it, but those are
    // `#[ignore]`d and run on a developer's machine; this runs on the node, against whatever
    // `PROBE_IMAGE` resolved to there. So the rc that means "no such command" is refused here rather
    // than believed.
    let mut missing_tool: Option<(&str, &str)> = None;
    let mut saw: std::collections::BTreeSet<&str> = Default::default();
    for line in output.lines().map(str::trim) {
        let Some((key, value)) = line.split_once('=') else { continue };
        saw.insert(key);
        if value == "127" {
            missing_tool = Some((key, value));
        }
        match key {
            // `ip route` failing is not the same question as "is there a default route": the
            // `default_route` line counts matching lines, so an absent `ip` yields `0`, which reads
            // as the good answer. This is the rc that tells them apart.
            "iprc" => ip_works = value == "0",
            "default_route" => posture.no_default_route = value == "0",
            // `0` means the connection was accepted. Anything else — refused (`1`), timed out
            // (`124`/`143`) — means it was not, which is what "unreachable" means here.
            "raw_ip" => posture.public_ip_unreachable = value != "0",
            "metadata" => posture.metadata_unreachable = value != "0",
            "public_dns" => posture.public_dns_unresolvable = value != "0",
            "proxy" => posture.proxy_reachable = value == "0",
            "peer" => posture.peer_unreachable = had_peer && value != "0",
            // `ip route add` failing is the *good* outcome: it means `CAP_NET_ADMIN` is gone and a
            // job cannot restore the route the whole posture rests on.
            "route_add" => posture.cannot_add_route = value != "0",
            "gwopen" => {
                if let Ok(port) = value.parse::<u16>() {
                    posture.gateway_ports_open.push(port);
                }
            }
            "probe_done" => done = true,
            _ => {}
        }
    }
    if !done {
        // A truncated probe is a probe that did not answer the questions after the truncation point,
        // and the fields it never set are `false`-by-default in a way that reads as a *good* posture
        // (`no_default_route: false` is safe, but `public_ip_unreachable: false` is too). Refusing
        // the whole thing is the only reading that cannot flatter.
        posture.failure = Some(format!("posture probe output was truncated: {output}"));
    } else if let Some((key, rc)) = missing_tool {
        posture.failure = Some(format!(
            "posture probe step `{key}` exited {rc} (no such command in `{PROBE_IMAGE}`), so its \
             `unreachable` answer is the absence of a tool rather than the absence of a route"
        ));
    } else if !ip_works {
        posture.failure = Some(
            "posture probe could not run `ip route`, so `no default route` would be the absence of \
             a tool rather than a fact about the network"
                .to_string(),
        );
    }
    posture
}

/// The peer's address on the sandbox network.
async fn peer_ip_of(config: &ContainerConfig, name: &str) -> Option<String> {
    let argv = vec![
        config.runtime.clone(),
        "inspect".into(),
        name.into(),
        "--format".into(),
        "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}".into(),
    ];
    match control_command(config, argv, &[]).await {
        Ok((ExecStatus::Exited(0), out)) => {
            let ip = out.trim().to_string();
            (!ip.is_empty()).then_some(ip)
        }
        _ => None,
    }
}

/// The three §14.3-adjacent capabilities, and where each one's evidence comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NetworkFacts {
    egress_deny: bool,
    metadata_blackhole: bool,
    no_inbound: bool,
}

impl NetworkFacts {
    /// Claims nothing. Every path that lacks evidence returns this.
    const UNKNOWN: NetworkFacts =
        NetworkFacts { egress_deny: false, metadata_blackhole: false, no_inbound: false };
}

/// Decide what the network posture lets this backend *claim*.
///
/// A named function with an exhaustive `match` rather than a chain of booleans, because this is the
/// single most dangerous derivation in the crate: a wrong `true` here means the scheduler is told a
/// job cannot reach the internet when it can. An exhaustive match means adding a
/// [`NetworkMode`] variant is a compile error here rather than a silent inheritance of whatever the
/// previous arm happened to compute.
fn network_facts(namespaced: bool, mode: &NetworkMode) -> NetworkFacts {
    if !namespaced {
        // No Linux namespaces means no netns, so there is no network posture to speak of whatever
        // the configuration says.
        return NetworkFacts::UNKNOWN;
    }
    match mode {
        // The strong case, and the only one that needs no evidence beyond the flag: `--network none`
        // gives the container a netns with loopback and nothing else. There is no interface to send
        // on, so there is nothing to verify.
        NetworkMode::None => {
            NetworkFacts { egress_deny: true, metadata_blackhole: true, no_inbound: true }
        }
        // Someone else's bridge. We have no evidence about its rules, and an unverified claim is the
        // failure mode this whole module exists to avoid.
        NetworkMode::Named(_) => NetworkFacts::UNKNOWN,
        NetworkMode::ProxyOnly(proxy) => match &proxy.posture {
            // Never probed → nothing observed → nothing claimed.
            None => NetworkFacts::UNKNOWN,
            Some(posture) => NetworkFacts {
                egress_deny: posture.egress_denied(),
                // Its own predicate rather than a raw field: a connect probe against an address
                // nothing listens on proves nothing at all. See `NetworkPosture::metadata_blackholed`
                // — a live control test on an open bridge is what turned that from an opinion into a
                // requirement.
                metadata_blackhole: posture.metadata_blackholed(),
                // **Narrower than §14.3's literal words**, and deliberately so. On a bridge network
                // the gateway is the node, and the node can always open a connection to a container
                // it created — that is true of every container backend and is not a property a
                // probe could change. What this reports is the part that is a real boundary: no
                // *other sandbox* can reach this one. `NetworkPosture::caveats` says this out loud
                // so the narrowing is visible to an operator rather than buried here.
                no_inbound: posture.failure.is_none() && posture.peer_unreachable,
            },
        },
    }
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
    let net = network_facts(namespaced, &config.network);
    let seccomp_on = config.seccomp_profile.is_some()
        || matches!(probe.seccomp_profile.as_deref(), Some(p) if p != "unconfined");

    EnforcedControls {
        // §14.1
        single_use: true,          // one container per job, `rm -f` in destroy, never restarted
        kernel_isolation: false,   // shared host kernel — true for every container, on every host

        // §14.2
        env_allowlist: true,       // ours, host-side: the env is built from an allowlist
        metadata_blackhole: net.metadata_blackhole,

        // §14.3
        egress_deny: net.egress_deny,
        no_inbound: net.no_inbound,

        // §14.4 — flags we pass and the daemon applies
        //
        // `non_root` is the one that has to look at the *value*, not just at the flag: `--user` is
        // always passed, but `--user 0:0` and `--user ""` both put the job at uid 0 (verified live —
        // `id -u` answers `0` for both, and `65534` for the default). A flag that is present and
        // means "root" is not the §14.4 control, so the claim follows the configured user.
        non_root: namespaced && runs_as_non_root(&config.user),
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

/// Whether `--user <value>` actually lands the job somewhere other than uid 0 (§14.4).
///
/// The uid half is all that matters here: a supplementary gid does not make a root process
/// unprivileged. An empty value means the flag carries nothing and the image's own `USER` decides,
/// which for most base images is root — so it is not a control either.
fn runs_as_non_root(user: &str) -> bool {
    let uid = user.split(':').next().unwrap_or("").trim();
    !uid.is_empty() && uid != "0" && uid != "root"
}

/// Resource ceilings the runtime would read as **no ceiling at all**, named for a refusal message.
///
/// `--memory 0`, `--pids-limit 0` and any `--cpus` that renders as `0.00` are all "unset" to the
/// daemon — verified live: `docker create --cpus 0.00 --memory 0 --pids-limit 0` inspects to
/// `NanoCpus=0 Memory=0 PidsLimit=<unset>`, i.e. an unbounded container. [`controls_for`] reports
/// these three from what the daemon *can* enforce, which is a fact about the host and cannot see a
/// per-job limit set to zero. So the two are kept consistent from the other end: a backend that
/// claims the limit never runs a job without it.
fn unlimited_resources(l: &crate::sandbox::ResourceLimits) -> Vec<&'static str> {
    let mut out = Vec::new();
    if format!("{:.2}", l.cpus) == "0.00" {
        out.push("cpus");
    }
    if l.memory_bytes == 0 {
        out.push("memory");
    }
    if l.pids == 0 {
        out.push("pids");
    }
    out
}

/// The M1 container backend.
#[derive(Debug)]
pub struct ContainerBackend {
    config: ContainerConfig,
    probe: DockerProbe,
    controls: EnforcedControls,
    /// Pre-created sandboxes for this backend's hot configurations (D§6.4).
    ///
    /// `None` when the operator did not ask for one, which is the default. Every path through
    /// [`spawn`](SandboxBackend::spawn) works identically with it absent — that is the property that
    /// makes a pool safe to add to a backend whose job is enforcing §14.
    pool: Option<Arc<SandboxPool>>,
}

impl ContainerBackend {
    /// Probe the host and build a backend, or refuse.
    ///
    /// Refusal is the point: on a host with no reachable container runtime there is no §14.1 boundary,
    /// and the alternative — constructing a backend that quietly runs jobs on the host — is the exact
    /// thing §14.1 calls "a full remote-code-execution and credential-exfiltration hole".
    /// Probe the host and build a backend, or refuse.
    ///
    /// In [`NetworkMode::ProxyOnly`] this also runs [`probe_network_posture`] and folds the result
    /// into the configuration, so the capabilities the backend reports are derived from what a
    /// container on that network was actually able to reach. That probe costs a few seconds of
    /// container churn at startup, once — which is the correct price for not guessing about the one
    /// control that decides whether a job can talk to the internet.
    ///
    /// It also runs [`reap_orphans`] first, which is what makes §14.1's single-use rule survive a
    /// node that died without tearing its sandbox down. Node start is the only moment at which "every
    /// container carrying this runner's label is an orphan" is true by construction: this process has
    /// not created one yet.
    pub async fn detect(config: ContainerConfig) -> Result<Self, SandboxError> {
        let probe = probe_docker(&config.runtime).await;
        if !probe.daemon_reachable {
            return Err(SandboxError::Unavailable(
                probe.failure.unwrap_or_else(|| format!("`{}` daemon is not reachable", config.runtime)),
            ));
        }
        if config.runner_id == DEFAULT_RUNNER_ID {
            // Not an error — a single-node host is the common case and the default is correct there.
            // But the failure mode of two nodes sharing it is one node reaping the other's running
            // jobs, and that is not something an operator should have to deduce from a requeue storm.
            tracing::warn!(
                runner = %config.runner_id,
                "container backend is using the default runner id; if more than one node shares \
                 this daemon, set a distinct one (HULL_CI_NODE_ID) or they will reap each other's \
                 running containers at start"
            );
        }
        // Before the posture probe, which starts a peer container carrying this same label.
        if let Err(e) = reap_orphans(&config).await {
            // A reap that could not run is not a reason to refuse the backend — it leaves us exactly
            // where we were before there was a reaper, which is where every job ran until now. It is
            // very much a reason to say so at `error`, because §14.1 is no longer being kept by
            // anything but `destroy()`.
            tracing::error!(
                runner = %config.runner_id,
                error = %e,
                "could not reap orphaned containers at start; a previous incarnation's sandboxes may \
                 still be running (§14.1)"
            );
        }
        let mut config = config;
        if let NetworkMode::ProxyOnly(proxy) = &config.network {
            let mut proxy = proxy.clone();
            let posture = probe_network_posture(&config, &proxy).await;
            if let Some(failure) = &posture.failure {
                tracing::error!(network = %proxy.network, %failure, "sandbox network posture could not be established");
            }
            for caveat in posture.caveats() {
                tracing::warn!(network = %proxy.network, %caveat, "sandbox network posture caveat");
            }
            if !posture.egress_denied() {
                // Loud, because this is a deployment that asked for a proxy posture and did not get
                // one. The backend still constructs — a job that can reach more than it should is
                // still a job that runs — but `egress_deny` is now `false`, so the scheduler will not
                // place anything on it that needed the guarantee.
                tracing::error!(
                    network = %proxy.network,
                    posture = ?posture,
                    "the sandbox network did NOT prove egress-deny; this backend now reports \
                     egress_deny=false (§14.3)"
                );
            }
            proxy.posture = Some(posture);
            config.network = NetworkMode::ProxyOnly(proxy);
        }
        Ok(Self::from_probe(config, probe))
    }

    /// Build from an already-taken probe. Used by [`detect`](Self::detect) and by tests, which is how
    /// the capability mapping is verified on a host with no daemon.
    pub fn from_probe(config: ContainerConfig, probe: DockerProbe) -> Self {
        let controls = controls_for(&probe, &config);
        // Built from the *configuration*, not from whether the daemon answered: a backend with no
        // daemon refuses to spawn long before a pool would matter, and a pool that quietly existed
        // only on some hosts would be one more thing whose absence is invisible.
        let pool = config.pool.enabled().then(|| {
            tracing::info!(
                depth = config.pool.depth,
                total = config.pool.total,
                root = %config.pool.root.display(),
                "warm sandbox pool on: this node pre-creates sandboxes per hot configuration and \
                 hands each to exactly one job before destroying it. Pre-boot, not reuse (D§6.4, \
                 §14.1). A job that finds no member creates one the cold way and never waits."
            );
            Arc::new(SandboxPool::new(config.pool.clone(), config.control_timeout))
        });
        ContainerBackend { config, probe, controls, pool }
    }

    pub fn probe(&self) -> &DockerProbe {
        &self.probe
    }

    pub fn config(&self) -> &ContainerConfig {
        &self.config
    }

    /// What the warm pool has actually done (D§6.4).
    ///
    /// `None` means there is no pool. The counters exist because of one specific way a pool fails:
    /// **a pool that silently never warms passes every functional test**, since every job takes the
    /// cold path and works. A hit has to be an asserted fact, never a stopwatch.
    pub fn pool_stats(&self) -> Option<PoolStats> {
        self.pool.as_ref().map(|p| p.stats())
    }

    /// Destroy every idle pool member. For a node shutting down cleanly.
    ///
    /// Not the guarantee — [`reap_orphans`] at the next node start is, because a `SIGKILL` runs no
    /// shutdown code. Every member carries the runner label, so the reaper finds them all.
    pub async fn drain_pool(&self) {
        if let Some(pool) = &self.pool {
            pool.drain().await;
        }
    }

    /// What was observed about the sandbox network, when there is one to observe.
    pub fn network_posture(&self) -> Option<&NetworkPosture> {
        match &self.config.network {
            NetworkMode::ProxyOnly(proxy) => proxy.posture.as_ref(),
            NetworkMode::None | NetworkMode::Named(_) => None,
        }
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

        // §14.3 network posture. Note there is no arm that omits `--network`: a container created
        // without one joins the default bridge, which has full egress. The absence of a flag must
        // never be a way to reach this state, so every variant names its network explicitly.
        match &config.network {
            NetworkMode::None => {
                a.push("--network".into());
                a.push("none".into());
            }
            NetworkMode::Named(n) => {
                a.push("--network".into());
                a.push(n.clone());
            }
            NetworkMode::ProxyOnly(proxy) => {
                a.push("--network".into());
                a.push(proxy.network.clone());
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

        // §14.1 teardown, in the two places it can be made to hold without a live process.
        //
        // `--rm` sets `HostConfig.AutoRemove`, which is a **daemon-side** promise: when this
        // container exits, the daemon removes it, whether or not anybody is still attached. That
        // closes the narrower half of the orphan problem — a node killed while a job was finishing
        // — and it closes it in the one place a dead node cannot. Verified against docker 28.0.4
        // that it does not cost us the exit status: `create --rm` + `start --attach` on a container
        // exiting 7 still returns 7, and the container is gone afterwards.
        //
        // It does **not** close the wider half: a container still running when the node dies never
        // exits, so AutoRemove never fires. That one is `reap_orphans`'s, and the label below is
        // what it matches on — the reason the label exists is no longer "so an operator can reap
        // orphans" but "so this runner reaps its own, at start, without guessing names".
        a.push("--rm".into());
        a.push("--label".into());
        a.push(config.runner_label());
        a.push("--label".into());
        a.push(format!("hull-ci.job={}", spec.job_id));
        a.push("--label".into());
        a.push(format!("hull-ci.step={}", spec.step_id));

        // The image's own ENTRYPOINT is overridden so the image cannot wrap, alter, or ignore the
        // argv we were told to run.
        a.push("--entrypoint".into());
        a.push(argv[0].clone());

        // `--` ends the runtime's flag parsing, and it is load-bearing rather than decorative.
        //
        // `spec.image` is a *pipeline-controlled* string (`image("rust:1.83")` in `.hull/ci.star`,
        // validated only for length and control characters), and it lands in the first positional
        // slot. Without a terminator the CLI parses flags right up to that slot, so an image of
        // `--privileged` is not an image at all — it is a flag, and the next argv element becomes the
        // image. Verified against docker 28.0.4:
        //
        //   docker create --entrypoint /bin/echo --privileged alpine:3
        //     → HostConfig.Privileged = true, image = alpine:3
        //   docker create --entrypoint /bin/echo -- --privileged alpine:3
        //     → `invalid reference format`, i.e. read as an image name, which is what it is
        //
        // Today's two argv shapes (`/bin/sh -c <script>` from a pipeline, `cargo test` from
        // autodetection) happen to strand the parser before it finds an image, so the injection is a
        // create failure rather than a privileged container. That is an accident of the argv shape,
        // not a control — one two-element argv anywhere upstream turns it back into a host takeover.
        // The terminator makes the shape irrelevant.
        a.push("--".into());
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
pub(crate) async fn control_command(
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
            // §14.4's cpu/memory/pid clauses, checked against the values rather than against the
            // daemon's ability to apply them. `controls_for` says this backend enforces them; a job
            // whose limits are all "unset" would make that a lie, so it does not run.
            let unlimited = unlimited_resources(&spec.limits);
            if !unlimited.is_empty() {
                return Err(SandboxError::Runtime(format!(
                    "refusing to run without the resource limits this backend reports as enforced \
                     (§14.4): {} would be passed to the runtime as `no limit`",
                    unlimited.join(", ")
                )));
            }
            // D§6.4. `key` is the *complete recipe* a member is built from, so a member can only be
            // reached by a job whose configuration is identical — including the network posture,
            // which is the one a mismatch would silently un-enforce (§14.3). See [`crate::pool`].
            let key = PoolKey::for_job(&self.config, spec);
            let slot = match &self.pool {
                Some(pool) => self.claim_warm(pool, &key, spec).await,
                None => Slot::Cold,
            };

            let name = match &slot {
                // A member's name was chosen when it was created, before this job existed.
                Slot::Warm(member) => member.name().to_string(),
                Slot::Cold => format!("hull-ci-{}-{}", sanitize_name(&spec.job_id), short_id()),
            };
            // On the cold path `spawn` only reserves the box: the container is created on the single
            // `exec`, because a docker container's argv is fixed at `create` time and the argv is not
            // known until then. A warm member's container already exists — which is the whole point —
            // and its argv arrives through `docker exec`. Either way the single-use guarantee is
            // untouched: the guard admits exactly one `exec` (§14.1).
            let created = matches!(slot, Slot::Warm(_));
            Ok(Box::new(ContainerInstance {
                guard: UseGuard::new(name.clone(), spec.job_id.clone()),
                name,
                config: match &slot {
                    // The member's own configuration, rebuilt from its key — not the backend's. They
                    // agree today; taking the member's means they cannot come apart tomorrow.
                    Slot::Warm(member) => member.config().clone(),
                    Slot::Cold => self.config.clone(),
                },
                spec: spec.clone(),
                capture: None,
                created,
                slot,
                pool: self.pool.clone().map(|p| (p, key)),
            }) as Box<dyn SandboxInstance>)
        })
    }
}

impl ContainerBackend {
    /// Try to take a warm member for this job, and give it its workspace.
    ///
    /// **Every failure here is a [`Slot::Cold`], never an error.** D§6.4 buys latency; a pool that
    /// could fail a job would be trading a verdict for it. The one exception is documented on
    /// [`crate::pool::adopt_workspace`] and needs a filesystem that has started refusing renames in
    /// both directions, at which point the workspace is genuinely unusable.
    async fn claim_warm(&self, pool: &Arc<SandboxPool>, key: &PoolKey, spec: &SandboxSpec) -> Slot {
        let Some(member) = pool.claim(key).await else { return Slot::Cold };
        // The step D§6.4 calls "bind the workspace": the mount was fixed at `create`, so the
        // contents move into it rather than the mount point moving to them.
        match crate::pool::adopt_workspace(&spec.workspace, member.mount_dir()) {
            Ok(()) => Slot::Warm(Box::new(member)),
            Err(e) => {
                tracing::error!(
                    container = %member.name(),
                    error = %e,
                    "could not move the workspace into a warm sandbox; this job takes the cold path \
                     (is the pool root on the same filesystem as the work root?)"
                );
                pool.discard_claimed(member).await;
                Slot::Cold
            }
        }
    }
}

/// Where this sandbox's container came from.
///
/// An enum rather than an `Option<PoolMember>` so that every place that has to behave differently —
/// `exec`, `destroy`, `Drop` — is a `match` a new variant would break, rather than an `if let` a new
/// variant would quietly fall through.
enum Slot {
    /// Nothing exists yet; `exec` creates the container.
    Cold,
    /// A sandbox created before this job existed, handed to this job alone, destroyed afterwards
    /// (D§6.4 — pre-boot, not reuse).
    ///
    /// Boxed because a [`PoolMember`] carries a whole [`ContainerConfig`] and `Cold` carries
    /// nothing; every `ContainerInstance` would otherwise pay for the pooled case whether or not it
    /// is in it, including on a node with no pool at all.
    Warm(Box<PoolMember>),
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

pub(crate) fn short_id() -> String {
    // Not cryptographic — it only has to make a name unique on one node. But "unique" has to actually
    // hold: the clock alone does not.
    //
    // `SystemTime::now()` is *named* in nanoseconds and delivered at whatever resolution the platform
    // keeps, which on macOS is coarser than a nanosecond. Two calls close enough together therefore
    // return the same value, and the caller gets `network with name … already exists` or a container
    // name clash. That was observed, not theorised: the live probes collided roughly one run in three
    // once they started creating networks in parallel.
    //
    // The clock still supplies cross-process uniqueness; a process-local counter supplies the part the
    // clock cannot, so no two calls in this process can ever agree however fast they arrive.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 + d.as_secs().wrapping_mul(1_000_000_000))
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{nanos:x}{seq:x}")
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
    slot: Slot,
    /// The pool this sandbox's key belongs to, so teardown can top it back up (D§6.4).
    ///
    /// Present on **cold** instances too, and deliberately: a miss is exactly the signal that this
    /// configuration is hot and has nothing warm, so the first job of a key is what causes the pool
    /// to learn it. That is the whole of the demand prediction — D§6.4 describes a per-image mix over
    /// the last hour, and what is here instead is "warm what just ran", which needs no history, no
    /// persistence and no clock.
    pool: Option<(Arc<SandboxPool>, PoolKey)>,
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

            // The one place a delivered secret is materialized on this host: the CLI's own
            // environment, for the length of that one process. The argv builders name the variables;
            // this supplies the values out of band (see the `--env NAME` block in `create_argv`).
            let secrets: Vec<(String, String)> =
                self.spec.secret_env.iter().map(|(n, v)| (n.clone(), v.to_string())).collect();

            // Two shapes, and the `match` is what keeps them from drifting into one another.
            let run = match &self.slot {
                Slot::Cold => {
                    let create = create_argv(&self.config, &self.spec, &self.name, &req.argv);
                    // **Before** the create, not after it, and this ordering is the whole point.
                    //
                    // `self.created` gates whether `destroy` issues an `rm` at all, and it used to be
                    // set from the CLI's exit status. But the CLI's exit status is a statement about
                    // the CLI: a `create` that hits `control_timeout` while the daemon goes on to
                    // create the container exits non-zero, leaves `created = false`, and `destroy`
                    // then skips the `rm` for a container that exists. The daemon's work is not
                    // observable from a process we killed, so the flag has to mean "an attempt was
                    // made that the daemon may have completed" rather than "the CLI said yes".
                    //
                    // The cost of the conservative reading is one `rm` against a container that was
                    // never created, and that costs nothing: `docker rm --force` on a missing
                    // container exits 0 (verified against docker 28.0.4), so a failed create still
                    // ends in a clean `destroy`.
                    self.created = true;
                    let (status, out) = control_command(&self.config, create, &secrets).await?;
                    if status != ExecStatus::Exited(0) {
                        return Err(SandboxError::Runtime(create_failure(
                            &self.spec.image,
                            status,
                            &out,
                        )));
                    }
                    vec![
                        self.config.runtime.clone(),
                        "start".into(),
                        "--attach".into(),
                        self.name.clone(),
                    ]
                }
                // The container was created and started before this job existed, so there is nothing
                // to create: the argv goes straight in (D§6.4's "bind the workspace and exec"). The
                // workspace was moved into the member's mount directory at `spawn`.
                Slot::Warm(_) => exec_argv(&self.config, &self.spec, &self.name, &req.argv),
            };

            let warm = matches!(self.slot, Slot::Warm(_));
            // On the cold path the values went in at `create` and the `start` CLI needs none of
            // them; on the warm path this *is* the create-equivalent, so they go here.
            //
            // `docker exec --env NAME` copies the value out of the CLI's own environment exactly as
            // `docker create --env NAME` does — verified against docker 28.0.4. Without it the
            // pooled path would have to pass secrets as `NAME=VALUE` in an argv every local user can
            // read out of `/proc`, which is the disclosure the by-name channel exists to prevent.
            let env = if warm { &secrets[..] } else { &[][..] };
            let mut runtime_env = runtime_env();
            runtime_env.extend_from_slice(env);
            let mut cmd = command_from_argv(&run, &runtime_env)?;
            let child = cmd.spawn()?;
            let mut capture = OutputCapture::new(req.caps);
            let outcome = run_to_completion(child, req.timeout, &mut capture).await?;
            let captured = capture.finish();
            let text = captured.text().to_string();
            self.capture = Some(captured);

            // On the cold path a command the image does not have fails at `create`/`start` and is an
            // `errored` verdict. Through `docker exec` the same mistake is exit **126** with the
            // runtime's own line on stderr, which would otherwise be reported as the *job* exiting
            // 126 — a `red` verdict about code nobody ran. §7 is unambiguous that we must not do
            // that, so the two paths are brought back into agreement here.
            if warm {
                if let Some(why) = exec_never_started(outcome.status, &text) {
                    return Err(SandboxError::Runtime(why));
                }
            }

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
        //
        // A warm member is destroyed by exactly the same call, which is what makes D§6.4 conformant:
        // a pool member is single-use, and this is its one use ending. Its mount directory — which by
        // now holds the job's whole workspace — goes with it, which is D§6.2's "teardown = drop the
        // snapshot" for the pooled path.
        let argv = vec![
            self.config.runtime.clone(),
            "rm".into(),
            "--force".into(),
            "--volumes".into(),
            self.name.clone(),
        ];
        let created = self.created;
        let mount_dir = match &self.slot {
            Slot::Warm(member) => Some(member.mount_dir().to_path_buf()),
            Slot::Cold => None,
        };
        let pool = self.pool.take();
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
            if let Some(dir) = &mount_dir {
                crate::pool::remove_mount_dir(dir);
            }
            // D§6.4's refill, amortized onto teardown in this repo's established style — the way
            // `hull-ci-fetch` sweeps at commit and the memo evicts at accept. There is no timer to
            // own, supervise or shut down, and this runs *after* the job's output has been collected,
            // so nothing waits on it. It never returns an error and never fails a verdict.
            if let Some((pool, key)) = pool {
                pool.refill(&key).await;
            }
            self.guard.mark_destroyed();
            result
        })
    }
}

/// The `docker exec` argv for a job running in a pre-created pool member (D§6.4).
///
/// The counterpart to [`create_argv`], and deliberately much shorter: every §14.4 control — the
/// user, the read-only rootfs, the dropped capabilities, `no-new-privileges`, the seccomp profile,
/// the cgroup ceilings — is a property of the **container**, and an exec joins it rather than
/// re-declaring it. Verified against docker 28.0.4 inside a member created by `create_argv`: `id -u`
/// is the configured user, `CapEff` and `CapBnd` are zero, `NoNewPrivs` is `1`, `/` is read-only,
/// `--network none` still refuses egress, and `memory.max`/`pids.max` are the container's.
///
/// What that leaves is the three things an exec must supply, and one flag it must never pass:
///
/// * `--workdir`, because an exec starts in the image's working directory rather than the
///   container's configured one.
/// * `--env NAME=VALUE` for the allowlisted job environment (§14.2), which a member created before
///   the job existed could not have.
/// * `--env NAME` for broker-delivered secrets, so the value travels through the CLI's own
///   environment and never through an argv (D§7.4).
/// * **Never `--user`.** `docker exec --user 0:0` really does run the exec as uid 0 — verified — so
///   the one flag that could undo §14.4's non-root control on this path is the one flag that is not
///   here. Omitting it means the exec inherits the container's user, which is the control.
///
/// The `--` terminator is here for the same reason it is in [`create_argv`]: `argv[0]` is a
/// pipeline-controlled string, and a flag list that is explicitly ended cannot be extended by it.
pub fn exec_argv(
    config: &ContainerConfig,
    spec: &SandboxSpec,
    name: &str,
    argv: &[String],
) -> Vec<String> {
    let mut a = vec![config.runtime.clone(), "exec".into(), "--workdir".into(), spec.workdir.clone()];
    for (k, v) in &spec.env {
        a.push("--env".into());
        a.push(format!("{k}={v}"));
    }
    for secret in spec.secret_names() {
        a.push("--env".into());
        a.push(secret.to_string());
    }
    a.push("--".into());
    a.push(name.to_string());
    a.extend(argv.iter().cloned());
    a
}

/// Did `docker exec` fail to *start* the command, rather than the command failing?
///
/// The distinction is §7's, and it is the difference between `errored` and `red`. On the cold path a
/// command the image does not have is a `create`/`start` failure and can only be `errored`; through
/// an exec it is exit 126 (or 127) with the runtime's own line on stderr, which without this would be
/// reported as the *job* exiting 126 — a red verdict about code that never ran.
///
/// The match is on docker's own `OCI runtime exec failed` prefix, and it is only ever used to turn a
/// verdict *towards* `errored`, which is the direction §7 says to be wrong in. A phrasing change in a
/// future runtime costs the distinction, not correctness.
fn exec_never_started(status: ExecStatus, output: &str) -> Option<String> {
    if !matches!(status, ExecStatus::Exited(126) | ExecStatus::Exited(127)) {
        return None;
    }
    output
        .lines()
        .find(|l| l.contains("OCI runtime exec failed") || l.contains("exec failed:"))
        .map(|line| {
            format!(
                "the sandbox could not start the command ({status:?}); this is an infrastructure \
                 failure and not a test result. Runtime said: {line}"
            )
        })
}

impl Drop for ContainerInstance {
    /// Best-effort teardown for an instance that is dropped without `destroy()` (§14.1).
    ///
    /// # What was chosen, and why it is not the guarantee
    ///
    /// A destructor cannot be where §14.1 lives. `destroy()` is async because removing a container
    /// is a request to a daemon over a socket, and the two ways to run that from `Drop` are both
    /// worse than the disease:
    ///
    /// * **Blocking on it** — `block_on`, or a synchronous `rm` — would stall whichever thread is
    ///   unwinding, inside a Tokio worker, on a daemon that may be the very thing that has stopped
    ///   answering. A `control_timeout`-long stall per dropped sandbox, on the runtime's own
    ///   threads, is how a node stops taking work at all. `block_on` inside a runtime thread panics
    ///   outright.
    /// * **Forking a detached `rm` and never waiting on it** would leave a zombie process per drop,
    ///   for as long as the node lives.
    ///
    /// So this **spawns** the removal onto the current runtime and returns immediately: it never
    /// blocks, and the task properly reaps its child. It covers the cases where the node itself
    /// survives — a dropped `run_assignment` future, an early `?` return, an unwinding panic — which
    /// is the common half of the problem, and it says so when it cannot run.
    ///
    /// It does **not** cover the case the audit was actually about: `SIGKILL`, a lost host, a
    /// runtime torn down before the task is polled. No destructor covers those. [`reap_orphans`] at
    /// node start does, which is why that is the guarantee and this is a courtesy.
    fn drop(&mut self) {
        // `destroy()` marks the guard before dropping the box, so the ordinary path is a no-op here.
        // `!created` means no `create` was ever issued, so there is nothing that could exist.
        if !self.created || self.guard.state() == Lifecycle::Destroyed {
            return;
        }
        let config = self.config.clone();
        let name = self.name.clone();
        let job = self.guard.job_id().to_string();
        // A warm member's mount directory holds the job's workspace by this point, so it goes the
        // same way the container does — and it is removed *after* the container, so nothing is
        // reading it.
        let mount_dir = match &self.slot {
            Slot::Warm(member) => Some(member.mount_dir().to_path_buf()),
            Slot::Cold => None,
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                tracing::warn!(
                    container = %name,
                    %job,
                    "sandbox dropped without destroy(); removing the container best-effort (§14.1)"
                );
                handle.spawn(async move {
                    let argv = vec![
                        config.runtime.clone(),
                        "rm".into(),
                        "--force".into(),
                        "--volumes".into(),
                        name.clone(),
                    ];
                    match control_command(&config, argv, &[]).await {
                        Ok((ExecStatus::Exited(0), _)) => {}
                        Ok((status, out)) => tracing::error!(
                            container = %name, ?status, %out,
                            "best-effort removal of a dropped sandbox failed; it will be reaped at next node start"
                        ),
                        Err(e) => tracing::error!(
                            container = %name, error = %e,
                            "best-effort removal of a dropped sandbox failed; it will be reaped at next node start"
                        ),
                    }
                    if let Some(dir) = &mount_dir {
                        crate::pool::remove_mount_dir(dir);
                    }
                });
            }
            Err(_) => tracing::error!(
                container = %name,
                %job,
                "sandbox dropped without destroy() and outside a Tokio runtime, so nothing could be \
                 issued; it will be reaped at next node start (§14.1)"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hull_ci_proto::AuthorClass;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

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

    /// A posture in which everything the probe could establish was established.
    fn proven_posture() -> NetworkPosture {
        NetworkPosture {
            declared_internal: true,
            no_default_route: true,
            public_ip_unreachable: true,
            public_dns_unresolvable: true,
            metadata_unreachable: true,
            proxy_reachable: true,
            peer_unreachable: true,
            cannot_add_route: true,
            gateway_ports_open: Vec::new(),
            failure: None,
        }
    }

    fn proxy_config(posture: Option<NetworkPosture>) -> ContainerConfig {
        let mut proxy = ProxyNetwork::new("hull-ci-sandbox", "172.18.0.1:3128");
        proxy.posture = posture;
        ContainerConfig { network: NetworkMode::ProxyOnly(proxy), ..Default::default() }
    }

    #[test]
    fn an_unprobed_proxy_network_claims_nothing_at_all() {
        // The most important test in this file. A `ProxyNetwork` built from configuration alone has
        // no posture, and a backend that has not looked must not report that a job cannot reach the
        // internet — because the scheduler believes it.
        let c = controls_for(&linux_probe(), &proxy_config(None));
        assert!(!c.egress_deny, "an unmeasured network proves nothing (§14.3)");
        assert!(!c.metadata_blackhole);
        assert!(!c.no_inbound);
        assert!(c.non_root, "the privilege controls are unaffected by the network choice");
        assert!(c.unmet_clauses().iter().any(|s| s.contains("§14.3 default egress-deny")));
    }

    #[test]
    fn a_proven_proxy_posture_reports_egress_deny_truthfully() {
        let c = controls_for(&linux_probe(), &proxy_config(Some(proven_posture())));
        assert!(c.egress_deny, "every conjunct held, so the claim is earned");
        assert!(c.metadata_blackhole);
        assert!(c.no_inbound);
        // …and it is still not cross-tenant safe, because that was never a network question.
        assert!(!c.to_capabilities().admits_untrusted());
    }

    #[test]
    fn any_single_missing_fact_takes_egress_deny_down_with_it() {
        // Each of these is a way for a network to look locked down and not be. None of them may be
        // survivable, because `egress_deny: true` with any one of them false is a lie.
        let cases: Vec<(&str, NetworkPosture)> = vec![
            ("the daemon does not call it internal", NetworkPosture { declared_internal: false, ..proven_posture() }),
            ("a default route exists", NetworkPosture { no_default_route: false, ..proven_posture() }),
            ("a job can add its own route", NetworkPosture { cannot_add_route: false, ..proven_posture() }),
            ("a raw public IP answered", NetworkPosture { public_ip_unreachable: false, ..proven_posture() }),
            ("a public name resolved", NetworkPosture { public_dns_unresolvable: false, ..proven_posture() }),
            (
                "the node has a port open on the gateway",
                NetworkPosture { gateway_ports_open: vec![2375], ..proven_posture() },
            ),
            (
                "the probe did not run",
                NetworkPosture { failure: Some("no daemon".into()), ..proven_posture() },
            ),
        ];
        for (why, posture) in cases {
            assert!(!posture.egress_denied(), "{why}: posture must not certify itself");
            let c = controls_for(&linux_probe(), &proxy_config(Some(posture)));
            assert!(!c.egress_deny, "{why}: the capability must follow the posture");
        }
    }

    #[test]
    fn a_reachable_docker_api_on_the_node_is_what_the_gateway_scan_is_for() {
        // The scan's whole reason to exist: `--internal` installs FORWARD drops, which do nothing
        // about the node's own listening sockets, and an unauthenticated Docker API reachable from
        // inside a sandbox is a complete host takeover.
        assert!(GATEWAY_SCAN_PORTS.contains(&2375) && GATEWAY_SCAN_PORTS.contains(&2376));
        let posture = NetworkPosture { gateway_ports_open: vec![2375], ..proven_posture() };
        assert!(!posture.egress_denied());
    }

    #[test]
    fn a_metadata_endpoint_that_answers_sinks_the_blackhole_claim() {
        let leaky = NetworkPosture { metadata_unreachable: false, ..proven_posture() };
        let c = controls_for(&linux_probe(), &proxy_config(Some(leaky)));
        assert!(c.egress_deny, "the other facts still hold");
        assert!(!c.metadata_blackhole, "but this one does not");
        assert!(c.unmet_clauses().iter().any(|s| s.contains("metadata")));
    }

    #[test]
    fn an_unreachable_metadata_endpoint_is_not_by_itself_a_blackhole() {
        // The regression guard for a bug a live control test caught. `169.254.169.254` refuses a
        // connection on any host that simply has no metadata service — a laptop, bare metal, the
        // Docker Desktop VM — so on a **wide-open bridge with full internet access** the connect
        // probe came back "unreachable" and the backend reported `metadata_blackhole: true`.
        //
        // The claim has to rest on the routing fact: link-local is off-subnet, so no default route
        // means nowhere to send it, and dropped `CAP_NET_ADMIN` means a job cannot make one.
        let open_network_no_metadata_service = NetworkPosture {
            metadata_unreachable: true, // nothing was listening
            no_default_route: false,    // …but the network is wide open
            cannot_add_route: true,
            ..NetworkPosture::default()
        };
        assert!(
            !open_network_no_metadata_service.metadata_blackholed(),
            "an absent service must not be mistaken for a blackhole"
        );
        let c = controls_for(&linux_probe(), &proxy_config(Some(open_network_no_metadata_service)));
        assert!(!c.metadata_blackhole);

        // And a job that could add its own route could route to it, so that sinks it too.
        let escapable = NetworkPosture { cannot_add_route: false, ..proven_posture() };
        assert!(!escapable.metadata_blackholed());

        // The proven posture still earns the claim, on the routing fact.
        assert!(proven_posture().metadata_blackholed());
    }

    #[test]
    fn a_reachable_peer_costs_only_the_inbound_claim() {
        // ICC left on: jobs can reach each other, which is a real §14.3 failure, but it does not make
        // the internet reachable and must not be reported as though it did.
        let chatty = NetworkPosture { peer_unreachable: false, ..proven_posture() };
        let c = controls_for(&linux_probe(), &proxy_config(Some(chatty.clone())));
        assert!(c.egress_deny);
        assert!(!c.no_inbound);
        assert!(
            chatty.caveats().iter().any(|c| c.contains("enable_icc=false")),
            "and the operator is told how to fix it: {:?}",
            chatty.caveats()
        );
    }

    #[test]
    fn a_posture_always_declares_what_it_did_not_establish() {
        // Two different things a reader deserves: `unmet_clauses` lists controls that are off, and
        // `caveats` lists controls that are on but whose evidence has an edge.
        let caveats = proven_posture().caveats();
        assert!(
            caveats.iter().any(|c| c.contains("well-known ports")),
            "the port scan is a sample and must say so: {caveats:?}"
        );
        assert!(
            caveats.iter().any(|c| c.contains("node itself can always open a connection")),
            "the narrowed meaning of `no inbound` must be visible: {caveats:?}"
        );
        let unprobed = NetworkPosture { failure: Some("boom".into()), ..Default::default() };
        assert_eq!(unprobed.caveats().len(), 1);
        assert!(unprobed.caveats()[0].contains("did not run"));
    }

    #[test]
    fn a_proxy_network_cannot_be_constructed_with_a_posture_nobody_measured() {
        // The honest default is a property of the type: `new` has no posture parameter, so a config
        // file cannot assert one.
        let p = ProxyNetwork::new("net", "10.0.0.1:3128");
        assert!(p.posture.is_none());
        assert_eq!(p.proxy_host_port(), ("10.0.0.1".to_string(), "3128".to_string()));
        // An endpoint with no port is read as :80 rather than silently scanning port 0.
        assert_eq!(
            ProxyNetwork::new("net", "proxy.internal").proxy_host_port(),
            ("proxy.internal".to_string(), "80".to_string())
        );
    }

    #[test]
    fn probe_output_is_parsed_into_exactly_what_it_says() {
        let output = "\
iprc=0
default_route=0
raw_ip=1
metadata=124
public_dns=1
proxy=0
peer=143
gwopen=2375
gwopen=22
route_add=1
probe_done=1
";
        let p = parse_posture(output, NetworkPosture { declared_internal: true, ..Default::default() }, true);
        assert!(p.no_default_route);
        assert!(p.public_ip_unreachable, "rc=1 is a refused connection, which is unreachable");
        assert!(p.metadata_unreachable, "rc=124 is a timeout, which is also unreachable");
        assert!(p.public_dns_unresolvable);
        assert!(p.proxy_reachable, "rc=0 is the one that means `answered`");
        assert!(p.peer_unreachable);
        assert!(p.cannot_add_route, "`ip route add` failing is the good outcome");
        assert_eq!(p.gateway_ports_open, vec![2375, 22]);
        assert!(p.failure.is_none());
        assert!(!p.egress_denied(), "…but the open gateway ports still sink it");
    }

    #[test]
    fn an_open_network_parses_as_an_open_network() {
        // The control case: the same script run on an ordinary bridge. If this ever parsed as a
        // locked-down posture, every probe in this file would be decorative.
        let output = "\
iprc=0
default_route=1
raw_ip=0
metadata=0
public_dns=0
proxy=0
peer=0
route_add=0
probe_done=1
";
        let p = parse_posture(output, NetworkPosture { declared_internal: false, ..Default::default() }, true);
        assert!(!p.no_default_route);
        assert!(!p.public_ip_unreachable);
        assert!(!p.metadata_unreachable);
        assert!(!p.public_dns_unresolvable);
        assert!(!p.peer_unreachable);
        assert!(!p.cannot_add_route);
        assert!(!p.egress_denied());
    }

    #[test]
    fn a_truncated_probe_is_a_failed_probe_rather_than_a_flattering_one() {
        // The subtle one. Fields the probe never reached default to `false`, and for
        // `public_ip_unreachable` that reads as "the internet was reachable" — but for
        // `no_default_route` it reads as "there was a default route". Half the defaults flatter and
        // half do not, so a probe that did not finish must be refused wholesale.
        let p = parse_posture("iprc=0\ndefault_route=0\nraw_ip=1\n", NetworkPosture::default(), true);
        assert!(p.failure.is_some(), "no `probe_done` sentinel means no answer");
        assert!(!p.egress_denied());
    }

    #[test]
    fn a_peer_that_never_started_does_not_become_evidence_of_isolation() {
        // If the peer container failed to start there is no peer, and "could not connect to nothing"
        // is not a demonstration that ICC is off.
        let output = "iprc=0\ndefault_route=0\nraw_ip=1\nmetadata=1\npublic_dns=1\nproxy=0\npeer=skip\nroute_add=1\nprobe_done=1\n";
        let p = parse_posture(output, NetworkPosture { declared_internal: true, ..Default::default() }, false);
        assert!(!p.peer_unreachable, "no peer means no result, not a passing result");
        assert!(p.egress_denied(), "the egress facts are independent and still hold");
    }

    #[test]
    fn the_proxys_own_port_is_expected_on_the_gateway_but_only_on_the_gateway() {
        let mut on_gateway =
            NetworkPosture { gateway_ports_open: vec![8443, 2375], ..proven_posture() };
        exclude_proxy_port(&mut on_gateway, "172.18.0.1", "172.18.0.1", "8443");
        assert_eq!(on_gateway.gateway_ports_open, vec![2375], "the proxy is meant to answer; 2375 is not");

        // A proxy that is a peer container instead: port 8443 open *on the node* is some other
        // service, and excluding it because the numbers match would hide a real finding.
        let mut peer_proxy = NetworkPosture { gateway_ports_open: vec![8443], ..proven_posture() };
        exclude_proxy_port(&mut peer_proxy, "172.18.0.1", "172.18.0.5", "8443");
        assert_eq!(peer_proxy.gateway_ports_open, vec![8443]);
        assert!(!peer_proxy.egress_denied());
    }

    #[test]
    fn create_argv_attaches_the_sandbox_to_the_proxy_network() {
        let t = tempfile::tempdir().unwrap();
        let config = proxy_config(Some(proven_posture()));
        let argv = create_argv(&config, &spec(t.path()), "sbx", &["cargo".into(), "test".into()]);
        assert!(argv.windows(2).any(|w| w[0] == "--network" && w[1] == "hull-ci-sandbox"));
        assert!(!argv.iter().any(|a| a == "none"));
        // Every §14.4 flag is unchanged: the network mode is orthogonal to the privilege posture.
        let joined = argv.join(" ");
        for expected in ["--read-only", "--cap-drop ALL", "--security-opt no-new-privileges"] {
            assert!(joined.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn every_network_mode_names_a_network_explicitly() {
        // A container created with no `--network` joins the default bridge, which has full egress.
        // The absence of a flag must never be a path to that state.
        let t = tempfile::tempdir().unwrap();
        for network in [
            NetworkMode::None,
            NetworkMode::Named("ci".into()),
            NetworkMode::ProxyOnly(ProxyNetwork::new("sandbox", "10.0.0.1:3128")),
        ] {
            let config = ContainerConfig { network, ..Default::default() };
            let argv = create_argv(&config, &spec(t.path()), "sbx", &["true".into()]);
            assert_eq!(
                argv.iter().filter(|a| *a == "--network").count(),
                1,
                "exactly one --network, always: {argv:?}"
            );
        }
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

    /// A value delivered by name never becomes a command-line element — whatever put it there.
    ///
    /// Found by audit: the package-proxy grant, a live bearer token that spends the tenant's upstream
    /// registry credentials, was travelling in `spec.env` and therefore rendering as
    /// `--env NAME=VALUE` on the `docker create` command line. That is readable by any other local
    /// user through `/proc/<pid>/cmdline` for the life of the process, and it is exactly the
    /// disclosure the by-name channel exists to prevent for broker secrets. The grant is no less a
    /// credential for having been minted locally, so it now takes the same channel.
    #[test]
    fn a_by_name_value_is_never_rendered_into_a_command_line() {
        let t = tempfile::tempdir().unwrap();
        let mut s = spec(t.path());
        s.broker_authorised = vec!["npm_config_registry".into()];
        s.secret_env = vec![(
            "npm_config_registry".into(),
            zeroize::Zeroizing::new("http://gw/j/GRANT-TOKEN-xyz/u/npm/".to_string()),
        )];

        let joined =
            create_argv(&ContainerConfig::default(), &s, "hull-ci-test", &["/bin/true".into()])
                .join(" ");
        assert!(!joined.contains("GRANT-TOKEN-xyz"), "the value reached argv: {joined}");
        assert!(
            joined.contains("--env npm_config_registry"),
            "…the name should travel by itself: {joined}"
        );
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
        let backend = ContainerBackend::detect(live_config()).await.expect("daemon");
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

    /// A [`ContainerConfig`] whose runner id is unique to this call.
    ///
    /// Every live probe needs its own, because [`ContainerBackend::detect`] now reaps every
    /// container carrying its runner's label at start (§14.1) and `cargo test` runs these in
    /// parallel. Sharing [`DEFAULT_RUNNER_ID`] across probes would have one probe's node start
    /// remove a container another probe was in the middle of measuring — the same "passes alone,
    /// fails as a suite" trap [`stub_port`] documents, and for a security probe that is the worst
    /// of both: it looks verified and is not.
    fn live_config() -> ContainerConfig {
        ContainerConfig {
            runner_id: format!("hull-ci-test-{}", short_id()),
            ..ContainerConfig::default()
        }
    }

    /// Run one argv in a single-use live container and return its captured output.
    async fn run_live(argv: &[&str]) -> String {
        run_live_on(&ContainerConfig::default(), argv).await
    }

    /// [`run_live`], on a given network posture.
    async fn run_live_on(config: &ContainerConfig, argv: &[&str]) -> String {
        let t = tempfile::tempdir().unwrap();
        let config = ContainerConfig { runner_id: live_config().runner_id, ..config.clone() };
        let backend = ContainerBackend::detect(config).await.expect("daemon");
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

    // ---------------------------------------------------------------------------------------
    // §14.3 with the package proxy on: the live probes for the mode that gives a job a network.
    //
    // These matter more than any other test in this crate. Moving off `--network none` weakens the
    // strongest guarantee here, and the way that goes wrong is silent: a backend reports
    // `egress_deny: true`, the scheduler believes it, and a job has the internet. So each probe below
    // is paired with a **control** — the same assertion run on an ordinary bridge network, where it
    // must come out the other way. A probe that cannot fail is not evidence.
    // ---------------------------------------------------------------------------------------

    /// A docker network created for one test, plus a stand-in proxy on the node's own netns.
    ///
    /// The topology is the one D§7.3 recommends and [`GATEWAY_SCAN_PORTS`] explains: an `--internal`
    /// bridge with inter-container communication **off**, so the only address a sandbox can reach is
    /// the gateway — which is the node — and the only thing listening there is meant to be the proxy.
    struct LiveNetwork {
        name: String,
        proxy_container: Option<String>,
        gateway: String,
        proxy_port: u16,
    }

    impl LiveNetwork {
        /// The locked-down topology: internal, ICC off.
        async fn internal(proxy_port: u16) -> LiveNetwork {
            LiveNetwork::create(
                &[
                    "--internal".to_string(),
                    "--opt".to_string(),
                    "com.docker.network.bridge.enable_icc=false".to_string(),
                ],
                proxy_port,
            )
            .await
        }

        /// The control: an ordinary user-defined bridge, with everything an operator would get by
        /// forgetting the flags. Every probe must come out the opposite way here.
        async fn open_bridge(proxy_port: u16) -> LiveNetwork {
            LiveNetwork::create(&[], proxy_port).await
        }

        async fn create(opts: &[String], proxy_port: u16) -> LiveNetwork {
            let cfg = ContainerConfig::default();
            let name = format!("hull-ci-test-{}", short_id());
            let mut argv = vec![cfg.runtime.clone(), "network".into(), "create".into()];
            argv.extend(opts.iter().cloned());
            argv.push(name.clone());
            let (status, out) = control_command(&cfg, argv, &[]).await.expect("network create");
            assert_eq!(status, ExecStatus::Exited(0), "could not create network: {out}");

            let inspect = vec![
                cfg.runtime.clone(),
                "network".into(),
                "inspect".into(),
                name.clone(),
                "--format".into(),
                "{{(index .IPAM.Config 0).Gateway}}".into(),
            ];
            let (_, gateway) = control_command(&cfg, inspect, &[]).await.expect("inspect");
            LiveNetwork {
                name,
                proxy_container: None,
                gateway: gateway.trim().to_string(),
                proxy_port,
            }
        }

        /// Put something on the node's own network namespace that accepts TCP on the proxy port.
        ///
        /// `--network host` is how the *node's* netns is reached from a test; in a real deployment
        /// the proxy is simply a process on the node and needs no container at all. This is the hop
        /// D§7.3 is describing when it says the proxy is the only reachable destination: it is
        /// reachable because the gateway address belongs to the node, and traffic to it takes the
        /// kernel's `INPUT` path rather than the `FORWARD` path `--internal` blocks.
        async fn with_proxy_stub(mut self) -> LiveNetwork {
            let cfg = ContainerConfig::default();
            let name = format!("hull-ci-test-proxy-{}", short_id());
            let argv = vec![
                cfg.runtime.clone(),
                "run".into(),
                "--detach".into(),
                "--name".into(),
                name.clone(),
                "--network".into(),
                "host".into(),
                "node:20-alpine".into(),
                "node".into(),
                "-e".into(),
                format!(
                    "require('http').createServer((q,s)=>s.end('PROXY-STUB-OK')).listen({},'0.0.0.0')",
                    self.proxy_port
                ),
            ];
            let (status, out) = control_command(&cfg, argv, &[]).await.expect("proxy stub");
            assert_eq!(status, ExecStatus::Exited(0), "could not start the proxy stub: {out}");
            self.proxy_container = Some(name);
            // The listener needs a moment before the posture probe asks it anything.
            tokio::time::sleep(Duration::from_secs(2)).await;
            self
        }

        fn proxy_network(&self) -> ProxyNetwork {
            ProxyNetwork::new(&self.name, format!("{}:{}", self.gateway, self.proxy_port))
        }

        fn config(&self) -> ContainerConfig {
            ContainerConfig {
                network: NetworkMode::ProxyOnly(self.proxy_network()),
                // `live_config`, not `default`: this config is handed to `ContainerBackend::detect`,
                // whose start-of-node reap must not reach a parallel probe's containers.
                ..live_config()
            }
        }

        async fn destroy(self) {
            let cfg = ContainerConfig::default();
            if let Some(c) = &self.proxy_container {
                let _ = control_command(
                    &cfg,
                    vec![cfg.runtime.clone(), "rm".into(), "--force".into(), c.clone()],
                    &[],
                )
                .await;
            }
            let _ = control_command(
                &cfg,
                vec![cfg.runtime.clone(), "network".into(), "rm".into(), self.name.clone()],
                &[],
            )
            .await;
        }
    }

    /// A free port for this test's stub, outside [`GATEWAY_SCAN_PORTS`] so the gateway scan result is
    /// about the *node* rather than about our own stub.
    ///
    /// **Allocated per call, not fixed.** A constant here made every live test bind the same port, so
    /// running two of them together — which `cargo test` does by default — had one job reaching the
    /// *other* test's server and failing on its reply. The probes passed individually and failed as a
    /// suite, which for a security probe is the worst of both: it looks verified and is not. The
    /// binding is dropped before the caller starts its stub, so there is a small race with the rest
    /// of the machine; that is a far smaller risk than a guaranteed collision with ourselves.
    fn stub_port() -> u16 {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("a free ephemeral port")
            .local_addr()
            .expect("bound address")
            .port();
        assert!(
            !GATEWAY_SCAN_PORTS.contains(&port),
            "ephemeral port {port} collides with the gateway scan list; retry the test"
        );
        port
    }

    #[tokio::test]
    #[ignore = "requires a running container daemon, the alpine and node images, and network creation rights"]
    async fn live_the_locked_down_sandbox_network_proves_egress_deny() {
        // The posture, measured rather than assumed. Every field is a thing a container on this
        // network actually tried.
        let net = LiveNetwork::internal(stub_port()).await.with_proxy_stub().await;
        let posture = probe_network_posture(&live_config(), &net.proxy_network()).await;
        net.destroy().await;

        assert!(posture.failure.is_none(), "the probe must have run: {posture:?}");
        assert!(posture.declared_internal, "the daemon agrees this network is internal");
        assert!(posture.no_default_route, "a sandbox here has no default route at all");
        assert!(posture.cannot_add_route, "…and cannot add one, because CAP_NET_ADMIN is dropped");
        assert!(posture.public_ip_unreachable, "a raw public IP is unreachable");
        assert!(posture.public_dns_unresolvable, "a public hostname does not resolve");
        assert!(posture.metadata_unreachable, "the cloud metadata endpoint is unreachable (§14.2)");
        assert!(posture.peer_unreachable, "one job cannot reach another's sandbox");
        assert!(posture.proxy_reachable, "…but the proxy answers, which is the entire point");
        assert!(
            posture.gateway_ports_open.is_empty(),
            "nothing else of the node's is reachable: {:?}",
            posture.gateway_ports_open
        );
        assert!(posture.egress_denied(), "so the posture certifies itself: {posture:?}");
    }

    #[tokio::test]
    #[ignore = "requires a running container daemon, the alpine and node images, and network creation rights"]
    async fn live_the_posture_probe_is_not_vacuous() {
        // The control, and the reason to believe the test above. The identical probe on an ordinary
        // bridge must come out the other way on every field — otherwise the probes are measuring
        // nothing and the "locked down" result is an artefact.
        //
        // This is the same standard the pre-existing §14 probes were held to: `wget` returns rc=0
        // with a network and rc=1 without, so rc=1 means something.
        let net = LiveNetwork::open_bridge(stub_port()).await.with_proxy_stub().await;
        let posture = probe_network_posture(&live_config(), &net.proxy_network()).await;
        net.destroy().await;

        assert!(posture.failure.is_none(), "the probe must have run: {posture:?}");
        assert!(!posture.declared_internal, "an ordinary bridge is not internal");
        assert!(!posture.no_default_route, "it has a default route");
        assert!(!posture.public_ip_unreachable, "and therefore reaches a raw public IP");
        assert!(!posture.public_dns_unresolvable, "and resolves public names");
        assert!(!posture.peer_unreachable, "and its containers can reach each other");
        assert!(
            !posture.egress_denied(),
            "so it must not certify itself, and a deployment that pointed at it would be told so"
        );
        // The one probe that does *not* flip, and the reason `metadata_blackholed` exists: this host
        // runs no metadata service, so `169.254.169.254` refuses a connection here exactly as it does
        // on the locked-down network. The connect probe cannot carry the claim; the routing fact can.
        assert!(
            !posture.metadata_blackholed(),
            "an open network must never report a metadata blackhole, whatever the connect probe said \
             (metadata_unreachable was {})",
            posture.metadata_unreachable
        );
    }

    #[tokio::test]
    #[ignore = "requires a running container daemon, the alpine and node images, and network creation rights"]
    async fn live_the_capability_struct_reports_the_truth_in_both_postures() {
        // The property the whole design rests on: what the backend *claims* tracks what a container
        // on its network can *do*, in both directions.

        // 1. The default. `--network none`, and every network capability true.
        let none = ContainerBackend::detect(live_config()).await.expect("daemon");
        assert!(none.controls().egress_deny, "`--network none` is still the default and still holds");
        assert!(none.controls().metadata_blackhole && none.controls().no_inbound);
        assert!(none.network_posture().is_none(), "there is no network to have a posture");

        // 2. The proxy posture, proven.
        let good = LiveNetwork::internal(stub_port()).await.with_proxy_stub().await;
        let backend = ContainerBackend::detect(good.config()).await.expect("daemon");
        let claims_on_good = backend.controls();
        let posture = backend.network_posture().cloned();
        good.destroy().await;
        assert!(claims_on_good.egress_deny, "a proven posture earns the claim: {posture:?}");
        assert!(claims_on_good.metadata_blackhole);
        assert!(claims_on_good.no_inbound);

        // 3. The same code, an open network. The claim must collapse.
        let open = LiveNetwork::open_bridge(stub_port()).await.with_proxy_stub().await;
        let backend = ContainerBackend::detect(open.config()).await.expect("daemon");
        let claims_on_open = backend.controls();
        open.destroy().await;
        assert!(
            !claims_on_open.egress_deny,
            "a network a job can escape from must not report egress-deny"
        );
        assert!(!claims_on_open.metadata_blackhole);
        assert!(!claims_on_open.no_inbound);
        assert!(claims_on_open
            .unmet_clauses()
            .iter()
            .any(|s| s.contains("§14.3 default egress-deny")));

        // 4. And in neither case does a container become cross-tenant safe.
        assert!(!claims_on_good.to_capabilities().admits_untrusted());
        assert!(!claims_on_open.to_capabilities().admits_untrusted());
    }

    #[tokio::test]
    #[ignore = "requires a running container daemon, the alpine and node images, and network creation rights"]
    async fn live_a_job_on_the_proxy_network_reaches_the_proxy_and_nothing_else() {
        // The §14.3 probes at the bottom of this file, re-run under the posture that *gives the job a
        // network*. Same standard, same shape: rc=0 means reachable, and every one of these must be
        // rc≠0 except the proxy.
        let net = LiveNetwork::internal(stub_port()).await.with_proxy_stub().await;
        let config = net.config();
        let gateway = net.gateway.clone();
        let port = net.proxy_port;

        let out = run_live_on(
            &config,
            &[
                "/bin/sh",
                "-c",
                &format!(
                    "wget -q -T 5 -O- http://{gateway}:{port}/ 2>&1; echo \" proxy_rc=$?\"; \
                     wget -q -T 3 -O- http://1.1.1.1 >/dev/null 2>&1; echo raw_rc=$?; \
                     wget -q -T 3 -O- http://example.com >/dev/null 2>&1; echo dns_rc=$?; \
                     wget -q -T 3 -O- http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1; echo meta_rc=$?"
                ),
            ],
        )
        .await;
        net.destroy().await;

        assert!(out.contains("PROXY-STUB-OK"), "the job must be able to reach the proxy: {out}");
        assert!(out.contains("proxy_rc=0"), "…and get a clean fetch from it: {out}");
        assert!(out.contains("raw_rc=1"), "a raw IP must still be unreachable: {out}");
        assert!(out.contains("dns_rc=1"), "a public hostname must still be unreachable: {out}");
        assert!(out.contains("meta_rc=1"), "the metadata endpoint must still be unreachable: {out}");
        assert!(!out.contains("ami-"), "and nothing resembling instance metadata came back: {out}");
    }

    #[tokio::test]
    #[ignore = "requires a running container daemon, the alpine and node images, and network creation rights"]
    async fn live_the_egress_probes_would_notice_if_the_network_were_open() {
        // The control for the test above: on an ordinary bridge, the same three probes come back
        // rc=0. Without this, `raw_rc=1` might mean "the network is locked down" or might mean "this
        // machine has no internet", and the two are indistinguishable from inside.
        let net = LiveNetwork::open_bridge(stub_port()).await;
        let config = net.config();
        let out = run_live_on(
            &config,
            &[
                "/bin/sh",
                "-c",
                "wget -q -T 5 -O- http://1.1.1.1 >/dev/null 2>&1; echo raw_rc=$?; \
                 wget -q -T 5 -O- http://example.com >/dev/null 2>&1; echo dns_rc=$?",
            ],
        )
        .await;
        net.destroy().await;

        assert!(
            out.contains("raw_rc=0") && out.contains("dns_rc=0"),
            "these probes must be able to succeed, or their failure elsewhere proves nothing \
             (is this host offline?): {out}"
        );
    }

    #[tokio::test]
    #[ignore = "requires a running container daemon, the alpine and node images, and network creation rights"]
    async fn live_a_job_cannot_restore_the_route_the_posture_rests_on() {
        // `no_default_route` is only worth anything if a job cannot undo it. §14.4's `--cap-drop ALL`
        // takes CAP_NET_ADMIN with it, and this is that being true rather than being assumed.
        let net = LiveNetwork::internal(stub_port()).await.with_proxy_stub().await;
        let config = net.config();
        let gateway = net.gateway.clone();
        let out = run_live_on(
            &config,
            &[
                "/bin/sh",
                "-c",
                &format!(
                    "ip route add default via {gateway} >/dev/null 2>&1; echo add_rc=$?; \
                     wget -q -T 3 -O- http://1.1.1.1 >/dev/null 2>&1; echo raw_rc=$?"
                ),
            ],
        )
        .await;
        net.destroy().await;

        assert!(out.contains("add_rc=1") || out.contains("add_rc=2"), "adding a route must fail: {out}");
        assert!(out.contains("raw_rc=1"), "and the internet must still be unreachable: {out}");
    }

    // ---------------------------------------------------------------------------------------
    // End to end: a real job, on a real locked-down network, fetching through the *real* proxy.
    //
    // Everything above proves the two halves separately — the network posture is provable, and the
    // proxy enforces its rules over a socket. This proves the composition, which is the only thing a
    // deployment actually has: a job with no route to anywhere resolves a package, the upstream
    // credential is spent by the proxy and never enters the sandbox, and the same job still cannot
    // reach a raw IP.
    // ---------------------------------------------------------------------------------------

    /// The tenant's upstream credential. The job must never see this string.
    const E2E_UPSTREAM_SECRET: &str = "npm_e2e_s3cr3t_never_in_a_job";

    /// A minimal HTTP upstream on loopback, recording the `Authorization` it was sent.
    ///
    /// Hand-rolled rather than pulled from a framework so this crate's *test* build does not acquire
    /// an HTTP server dependency for one fixture. It answers exactly one shape of request, which is
    /// all the proxy will send it.
    async fn e2e_upstream() -> (u16, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("upstream bind");
        let port = listener.local_addr().unwrap().port();
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { continue };
                let recorder = recorder.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 8192];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..n]).to_string();
                    for line in request.lines() {
                        if let Some(v) = line.to_ascii_lowercase().strip_prefix("authorization:") {
                            recorder.lock().unwrap().push(v.trim().to_string());
                        }
                    }
                    let body = "PACKAGE-FROM-UPSTREAM";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });
        (port, seen)
    }

    /// A TCP relay in the node's own network namespace, forwarding the sandbox-facing port to a
    /// process on the developer's machine.
    ///
    /// **This exists only because of where this crate is built.** In a real deployment the proxy is a
    /// process on the node and binds the gateway address directly, with no relay in the picture. On
    /// macOS the container runtime lives inside a Linux VM, and a Rust process on the host cannot bind
    /// an address on that VM's bridge — so the relay stands in for exactly one thing: the kernel hop
    /// that would otherwise deliver a packet from the sandbox to a socket on the node. It performs no
    /// HTTP logic and makes no policy decision; everything the test asserts is still decided by the
    /// real proxy on the other side of it.
    async fn e2e_relay(listen_port: u16, host_port: u16) -> String {
        let cfg = ContainerConfig::default();
        let name = format!("hull-ci-test-relay-{}", short_id());
        let script = format!(
            "const net=require('net');net.createServer(c=>{{\
               const u=net.connect({host_port},'host.docker.internal');\
               c.on('error',()=>u.destroy());u.on('error',()=>c.destroy());\
               c.pipe(u);u.pipe(c);}}).listen({listen_port},'0.0.0.0')"
        );
        let argv = vec![
            cfg.runtime.clone(),
            "run".into(),
            "--detach".into(),
            "--name".into(),
            name.clone(),
            "--network".into(),
            "host".into(),
            "node:20-alpine".into(),
            "node".into(),
            "-e".into(),
            script,
        ];
        let (status, out) = control_command(&cfg, argv, &[]).await.expect("relay");
        assert_eq!(status, ExecStatus::Exited(0), "could not start the relay: {out}");
        tokio::time::sleep(Duration::from_secs(2)).await;
        name
    }

    #[tokio::test]
    #[ignore = "requires a running container daemon, the alpine and node images, and network creation rights"]
    async fn live_a_job_with_no_egress_resolves_a_package_through_the_real_proxy() {
        use hull_ci_proxy::allowlist::{Allowlist, AuthScheme, Upstream};
        use hull_ci_proxy::credentials::StaticCredentials;
        use hull_ci_proxy::ratelimit::RateLimit;
        use hull_ci_proxy::server::PackageProxy;

        // 1. An upstream registry that requires a credential.
        let (upstream_port, seen_auth) = e2e_upstream().await;
        let allowlist = Allowlist::from_upstreams(vec![Upstream::authenticated(
            "npm",
            &format!("http://127.0.0.1:{upstream_port}"),
            "NPM_TOKEN",
            AuthScheme::Bearer,
        )
        .unwrap()])
        .unwrap();

        // 2. The real proxy, holding the tenant's credential, with a grant for exactly this job.
        let creds = Arc::new(StaticCredentials::new().with("acme", "NPM_TOKEN", E2E_UPSTREAM_SECRET));
        let proxy = PackageProxy::new(allowlist, creds);
        let (grant, _) = proxy.grants().mint(
            "acme",
            "job-1",
            ["npm".to_string()].into_iter().collect(),
            u64::MAX / 2,
            RateLimit::default(),
        );
        let grant = grant.expose().to_string();
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.expect("proxy bind");
        let proxy_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { proxy.serve(listener).await });

        // 3. The locked-down sandbox network, with the proxy reachable on its gateway.
        let sandbox_port = stub_port();
        let net = LiveNetwork::internal(sandbox_port).await;
        let relay = e2e_relay(sandbox_port, proxy_port).await;
        let gateway = net.gateway.clone();
        let config = net.config();

        // The posture is still measured, and must still hold with the proxy in place.
        let posture = probe_network_posture(&live_config(), &net.proxy_network()).await;
        assert!(posture.egress_denied(), "the network must still deny egress: {posture:?}");
        assert!(posture.proxy_reachable, "…and the real proxy must be the thing answering");

        // 4. The job. No route anywhere, one URL that works.
        let out = run_live_on(
            &config,
            &[
                "/bin/sh",
                "-c",
                &format!(
                    "wget -q -T 10 -O- http://{gateway}:{sandbox_port}/j/{grant}/u/npm/express 2>&1; \
                     echo \" fetch_rc=$?\"; \
                     wget -q -T 5 -O- http://{gateway}:{sandbox_port}/j/{grant}/u/pypi/x >/dev/null 2>&1; \
                     echo denied_rc=$?; \
                     wget -q -T 3 -O- http://1.1.1.1 >/dev/null 2>&1; echo raw_rc=$?"
                ),
            ],
        )
        .await;

        let cfg = ContainerConfig::default();
        let _ = control_command(&cfg, vec![cfg.runtime.clone(), "rm".into(), "--force".into(), relay], &[]).await;
        net.destroy().await;

        // The job resolved a package…
        assert!(out.contains("PACKAGE-FROM-UPSTREAM"), "the job must get its package: {out}");
        assert!(out.contains("fetch_rc=0"), "…cleanly: {out}");
        // …an upstream outside its grant was refused…
        assert!(out.contains("denied_rc=1"), "an unallowlisted upstream must be refused: {out}");
        // …the internet is still unreachable…
        assert!(out.contains("raw_rc=1"), "egress-deny still holds during a fetch: {out}");
        // …the credential was spent by the proxy…
        assert_eq!(
            seen_auth.lock().unwrap().first().map(String::as_str),
            Some(&*format!("bearer {E2E_UPSTREAM_SECRET}")),
            "the upstream must have received the tenant's credential"
        );
        // …and it never entered the sandbox.
        assert!(
            !out.contains(E2E_UPSTREAM_SECRET),
            "the upstream credential must never appear in a job's output (D§7.4): {out}"
        );
    }

    // ── §14.1 across a crash, against a real daemon ────────────────────────────────────────────
    //
    // The unit tests above settle our control flow. These settle the thing the audit actually
    // observed, which is a fact about the daemon rather than about us: the container runtime, not
    // the CLI, owns the container, so killing the CLI leaves it running. Each "the orphan is gone"
    // below is paired with a run in which the identical probe finds it — a probe that cannot fail is
    // not evidence, which is the standard the §14.3 probes in this file are already held to.

    /// Does the daemon still have this container?
    ///
    /// One helper for every orphan assertion in this section, so the "gone" case and the control
    /// case are literally the same question asked twice.
    async fn container_exists(config: &ContainerConfig, name: &str) -> bool {
        let argv = vec![config.runtime.clone(), "inspect".into(), name.to_string()];
        matches!(control_command(config, argv, &[]).await, Ok((ExecStatus::Exited(0), _)))
    }

    async fn container_running(config: &ContainerConfig, name: &str) -> bool {
        let argv = vec![
            config.runtime.clone(),
            "inspect".into(),
            name.to_string(),
            "--format".into(),
            "{{.State.Running}}".into(),
        ];
        matches!(control_command(config, argv, &[]).await, Ok((ExecStatus::Exited(0), out)) if out.trim() == "true")
    }

    /// Create and start a job container exactly the way `exec` does, then kill the attaching CLI —
    /// which is what a node crash looks like from the daemon's side. Returns the container's name.
    ///
    /// The argv is a long sleep on purpose: `--rm` (AutoRemove) removes a container **when it
    /// exits**, so a container that never exits is precisely the case AutoRemove cannot reach and
    /// the reaper must.
    async fn leak_an_orphan(config: &ContainerConfig) -> String {
        let ws = tempfile::tempdir().expect("workspace");
        let mut s = spec(ws.path());
        s.image = "alpine:3".into();
        let name = format!("hull-ci-orphan-{}", short_id());
        let create = create_argv(config, &s, &name, &["/bin/sleep".into(), "600".into()]);
        let (status, out) = control_command(config, create, &[]).await.expect("create");
        assert_eq!(status, ExecStatus::Exited(0), "could not create the orphan: {out}");

        let start = vec![config.runtime.clone(), "start".into(), "--attach".into(), name.clone()];
        let mut child = command_from_argv(&start, &runtime_env())
            .expect("start command")
            .spawn()
            .expect("spawn the attaching CLI");
        // Let the daemon actually start it before we pull the rug out.
        for _ in 0..100 {
            if container_running(config, &name).await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        child.start_kill().expect("kill the attaching CLI");
        let _ = child.wait().await;
        name
    }

    #[tokio::test]
    #[ignore = "requires a running container daemon and the alpine image"]
    async fn live_killing_the_attaching_cli_leaves_the_container_running() {
        // The audit's finding itself, asserted rather than believed. Everything else in this section
        // is only worth building because this is true: the CLI is not the container's parent, so its
        // death is not the container's death, and `--rm` cannot help because the container never
        // exits.
        let config = live_config();
        let name = leak_an_orphan(&config).await;
        assert!(
            container_running(&config, &name).await,
            "the daemon owns the container; killing the CLI must not have stopped it"
        );

        reap_orphans(&config).await.expect("reap");
        assert!(!container_exists(&config, &name).await, "and the reaper is what removes it");
    }

    #[tokio::test]
    #[ignore = "requires a running container daemon and the alpine image"]
    async fn live_the_reaper_removes_this_runners_orphan_and_the_probe_would_have_found_it() {
        // The negative test and its positive control, in one run so the pairing cannot drift apart.
        //
        // The control is the same reaper, the same probe and the same orphan, with exactly one thing
        // changed: the runner id it is asked about. If `container_exists` came back `false` for a
        // reason other than the reaper — a container that never started, a name we got wrong — the
        // control would report `false` too, and the test would fail instead of passing vacuously.
        let mine = live_config();
        let name = leak_an_orphan(&mine).await;

        // Control: a reaper that is not this runner's must leave the orphan alone.
        let someone_else = ContainerConfig { runner_id: live_config().runner_id, ..mine.clone() };
        let swept = reap_orphans(&someone_else).await.expect("reap");
        assert!(swept.removed.is_empty(), "another runner's reaper removed something: {swept:?}");
        assert!(
            container_exists(&mine, &name).await,
            "the probe finds the orphan when the reaper that would remove it has not run"
        );

        // The test proper.
        let reaped = reap_orphans(&mine).await.expect("reap");
        assert_eq!(reaped.removed.len(), 1, "exactly this runner's one orphan: {reaped:?}");
        assert!(reaped.failures.is_empty(), "{reaped:?}");
        assert!(!container_exists(&mine, &name).await, "…and the same probe no longer finds it");
    }

    #[tokio::test]
    #[ignore = "requires a running container daemon and the alpine image"]
    async fn live_two_runners_on_one_daemon_do_not_reap_each_other() {
        // The property that makes a reaper safe to run at all. Several nodes against one daemon is
        // an ordinary development and CI topology, and a reaper that swept by name prefix or by the
        // `hull-ci.job` label would turn one node's restart into every other node's outage.
        let alpha = live_config();
        let beta = live_config();
        assert_ne!(alpha.runner_label(), beta.runner_label(), "two runners, two labels");
        let alpha_orphan = leak_an_orphan(&alpha).await;
        let beta_orphan = leak_an_orphan(&beta).await;

        let reaped = reap_orphans(&alpha).await.expect("reap alpha");
        assert_eq!(reaped.removed.len(), 1, "alpha reaped more than its own: {reaped:?}");
        assert!(!container_exists(&alpha, &alpha_orphan).await, "alpha's orphan is gone");
        assert!(
            container_running(&beta, &beta_orphan).await,
            "beta's container is still running its job and must be untouched"
        );

        // …and beta can still reap its own afterwards, so alpha's pass did not merely miss it.
        let reaped = reap_orphans(&beta).await.expect("reap beta");
        assert_eq!(reaped.removed.len(), 1, "{reaped:?}");
        assert!(!container_exists(&beta, &beta_orphan).await);
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires a running container daemon and the alpine image"]
    async fn live_a_create_the_daemon_completed_but_we_never_heard_about_is_still_torn_down() {
        // The audit's second path, against the real daemon: a `create` that hits `control_timeout`
        // *after* the daemon has created the container. The runtime here is a wrapper that runs the
        // real `docker create` and then hangs, which is what an unresponsive daemon connection looks
        // like from our side and produces the same state on the daemon's side.
        let t = tempfile::tempdir().unwrap();
        let wrapper = fake_runtime(
            t.path(),
            "#!/bin/sh\n\
             if [ \"$1\" = create ]; then docker \"$@\"; sleep 30; fi\nexec docker \"$@\"\n",
        );
        let config = ContainerConfig {
            runtime: wrapper,
            control_timeout: Duration::from_secs(5),
            runner_id: live_config().runner_id,
            ..Default::default()
        };
        let real = ContainerConfig::default();
        let ws = tempfile::tempdir().unwrap();
        let mut s = spec(ws.path());
        s.image = "alpine:3".into();

        let backend = ContainerBackend::from_probe(config.clone(), linux_probe());
        let mut sbx = backend.spawn(&s).await.expect("spawn");
        let name = sbx.id().to_string();
        let req = ExecRequest {
            job_id: s.job_id.clone(),
            argv: vec!["/bin/sleep".into(), "600".into()],
            timeout: Duration::from_secs(60),
            caps: crate::capture::OutputCaps::default(),
        };
        sbx.exec(&req).await.expect_err("the create timed out, so exec must not report success");

        // The control that makes the assertion afterwards mean something: the daemon really did
        // create the container we were about to give up on. Without this line, "gone after destroy"
        // could just as well mean "never created".
        assert!(
            container_exists(&real, &name).await,
            "the daemon completed the create even though our CLI never came back"
        );

        sbx.destroy().await.expect("destroy");
        assert!(
            !container_exists(&real, &name).await,
            "a create we timed out on must still be torn down (§14.1)"
        );
    }

    #[tokio::test]
    #[ignore = "requires a running container daemon and the alpine image"]
    async fn live_a_container_that_exits_after_its_node_died_removes_itself() {
        // The half `--rm` covers, and why it is worth setting alongside the reaper: AutoRemove is the
        // *daemon's* promise, so it is kept even though the process that asked for it is gone. Its
        // control is the first test in this section — a container that never exits is still there
        // afterwards, which is exactly why the reaper exists as well.
        let config = live_config();
        let ws = tempfile::tempdir().unwrap();
        let mut s = spec(ws.path());
        s.image = "alpine:3".into();
        let name = format!("hull-ci-autorm-{}", short_id());
        let create = create_argv(&config, &s, &name, &["/bin/sleep".into(), "3".into()]);
        let (status, out) = control_command(&config, create, &[]).await.expect("create");
        assert_eq!(status, ExecStatus::Exited(0), "{out}");

        let start = vec![config.runtime.clone(), "start".into(), "--attach".into(), name.clone()];
        let mut child =
            command_from_argv(&start, &runtime_env()).expect("start").spawn().expect("spawn");
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(container_exists(&config, &name).await, "it exists while it runs");
        child.start_kill().expect("kill the attaching CLI");
        let _ = child.wait().await;

        for _ in 0..100 {
            if !container_exists(&config, &name).await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            !container_exists(&config, &name).await,
            "AutoRemove must fire on exit even with nobody attached"
        );
        // And there is nothing left for the reaper to find, which is the point.
        assert!(reap_orphans(&config).await.expect("reap").removed.is_empty());
    }

    // ── the isolation audit's regressions ───────────────────────────────────────────────────────

    #[test]
    fn a_hostile_image_ref_cannot_become_a_runtime_flag() {
        // The image is a *pipeline*-controlled string and it sits in the first positional slot, which
        // is the slot the runtime CLI parses flags right up to. Verified against docker 28.0.4:
        // `docker create --entrypoint /bin/echo --privileged alpine:3` creates a **privileged**
        // container from `alpine:3`, because `--privileged` was read as a flag and the next element
        // became the image. Putting `--` in front of the image is what stops the image from ever
        // being read as anything else.
        let t = tempfile::tempdir().unwrap();
        let mut s = spec(t.path());
        s.image = "--privileged".into();
        let argv = create_argv(&ContainerConfig::default(), &s, "sbx", &["/bin/sh".into(), "-c".into(), "id".into()]);

        let end = argv.iter().position(|a| a == "--").expect("the flag list must be terminated");
        assert_eq!(argv[end + 1], "--privileged", "the image sits immediately after the terminator");
        assert!(
            !argv[..end].iter().any(|a| a == "--privileged"),
            "nothing the pipeline wrote may appear where the CLI is still parsing flags: {argv:?}"
        );
        // And the ordinary case is unchanged: image, then the command's arguments.
        let ok = create_argv(&ContainerConfig::default(), &spec(t.path()), "sbx", &["cargo".into(), "test".into()]);
        let end = ok.iter().position(|a| a == "--").unwrap();
        assert_eq!(&ok[end + 1..], &["hull-ci/base:1".to_string(), "test".to_string()]);
    }

    #[test]
    fn a_root_user_is_not_reported_as_the_non_root_control() {
        // `--user` is always passed, so the flag's presence proves nothing: `--user 0:0` and
        // `--user ""` both run the job as uid 0 (verified live). The claim has to follow the value.
        for user in ["0:0", "0", "root", ""] {
            let config = ContainerConfig { user: user.into(), ..Default::default() };
            let c = controls_for(&linux_probe(), &config);
            assert!(!c.non_root, "`--user {user}` is uid 0, which is not §14.4's non-root control");
            assert!(c.unmet_clauses().iter().any(|s| s.contains("non-root")));
            // Everything else about the box is unaffected — only the claim that was untrue moves.
            assert!(c.read_only_rootfs && c.caps_dropped && c.egress_deny);
        }
        assert!(controls_for(&linux_probe(), &ContainerConfig::default()).non_root);
        assert!(runs_as_non_root("nobody") && runs_as_non_root("65534:65534"));
    }

    #[tokio::test]
    async fn a_job_with_no_real_resource_ceiling_is_refused_rather_than_run_unbounded() {
        // `--memory 0`, `--pids-limit 0` and a `--cpus` that renders `0.00` are "unset" to the daemon:
        // `docker create --cpus 0.00 --memory 0 --pids-limit 0` inspects to `NanoCpus=0 Memory=0`
        // and no PidsLimit at all. `controls_for` reads those three off the *daemon's* controllers, so
        // it cannot see a zeroed per-job limit — which would leave the backend claiming a ceiling that
        // no container ever got.
        let t = tempfile::tempdir().unwrap();
        let backend = ContainerBackend::from_probe(ContainerConfig::default(), linux_probe());
        assert!(backend.controls().memory_limit && backend.controls().cpu_limit && backend.controls().pid_limit);

        use crate::sandbox::ResourceLimits;
        for limits in [
            ResourceLimits { memory_bytes: 0, ..Default::default() },
            ResourceLimits { pids: 0, ..Default::default() },
            ResourceLimits { cpus: 0.0, ..Default::default() },
            // Not zero, but rounds to `--cpus 0.00`, which the daemon reads identically.
            ResourceLimits { cpus: 0.004, ..Default::default() },
        ] {
            let mut s = spec(t.path());
            s.limits = limits;
            match backend.spawn(&s).await {
                Err(SandboxError::Runtime(why)) => assert!(why.contains("§14.4"), "{why}"),
                Err(other) => panic!("wrong refusal: {other}"),
                Ok(_) => panic!("a backend claiming cpu/memory/pid limits must not run a job without them"),
            }
        }
    }

    #[test]
    fn a_probe_image_without_the_tools_proves_nothing_instead_of_everything() {
        // The failure mode this crate has already been bitten by three times, in its purest form: a
        // probe that cannot fail. Every reachability line reads "rc != 0 means unreachable", so an
        // image whose `nc`/`timeout`/`nslookup` are missing answers `127` to all of them and parses
        // as a perfectly locked-down network. The live tests pair each probe with an open-network
        // control, but they are `#[ignore]`d — the node runs this parse against whatever `PROBE_IMAGE`
        // resolved to on *its* host.
        let no_tools = "\
iprc=0
default_route=0
raw_ip=127
metadata=127
public_dns=127
proxy=127
peer=127
route_add=127
probe_done=1
";
        let p = parse_posture(no_tools, NetworkPosture { declared_internal: true, ..Default::default() }, true);
        assert!(p.failure.is_some(), "127 is `no such command`, not `unreachable`");
        assert!(!p.egress_denied(), "so nothing may be certified from it");
        assert!(!p.metadata_blackholed());
        let c = controls_for(&linux_probe(), &proxy_config(Some(p)));
        assert!(!c.egress_deny && !c.metadata_blackhole && !c.no_inbound);

        // The same trap one level down: `default_route` counts lines out of `ip route`, so an absent
        // `ip` produces `0` — which reads as "no default route", the fact the whole posture rests on.
        let no_ip = "\
iprc=127
default_route=0
raw_ip=1
metadata=1
public_dns=1
proxy=0
peer=1
route_add=1
probe_done=1
";
        let p = parse_posture(no_ip, NetworkPosture { declared_internal: true, ..Default::default() }, true);
        assert!(p.failure.is_some(), "an absent `ip` must not read as an absent route");
        assert!(!p.egress_denied());

        // A probe that never emitted the line at all (an older image, a changed script) is refused
        // for the same reason.
        let silent = "default_route=0\nraw_ip=1\nmetadata=1\npublic_dns=1\nproxy=0\npeer=1\nroute_add=1\nprobe_done=1\n";
        assert!(parse_posture(silent, NetworkPosture { declared_internal: true, ..Default::default() }, true)
            .failure
            .is_some());

        // …and a genuinely locked-down network still certifies: 1 and 124 are answers, 127 is not.
        let real = "iprc=0\ndefault_route=0\nraw_ip=1\nmetadata=124\npublic_dns=1\nproxy=0\npeer=1\nroute_add=1\nprobe_done=1\n";
        let p = parse_posture(real, NetworkPosture { declared_internal: true, ..Default::default() }, true);
        assert!(p.failure.is_none() && p.egress_denied(), "{p:?}");
    }

    // ── §14.1 across a crash: the label, the reaper, and the two ordering bugs ──────────────────
    //
    // The audit's finding, in its own words: "killing the attaching CLI leaves the container
    // **running**". `destroy()` is an async function, so every way it fails to run — SIGKILL, a lost
    // host, a dropped `run_assignment` future — left a live container with the workspace mounted and
    // its wall clock expired. These tests cover the parts that can be settled without a daemon; the
    // `live_` ones below settle the rest against a real one.

    #[test]
    fn every_container_this_backend_creates_carries_the_label_the_reaper_matches() {
        // The reaper can only remove what the creator marked, and it matches on an exact key/value.
        // A label written one way and filtered another is a reaper that removes nothing — which is
        // indistinguishable, in a log, from a reaper that found nothing to remove.
        let t = tempfile::tempdir().unwrap();
        let config = ContainerConfig { runner_id: "node-7".into(), ..Default::default() };
        let argv = create_argv(&config, &spec(t.path()), "sbx", &["/bin/true".into()]);
        assert!(
            argv.windows(2).any(|w| w[0] == "--label" && w[1] == config.runner_label()),
            "the runner label must be on the create argv: {argv:?}"
        );
        assert_eq!(config.runner_label(), "hull-ci.runner=node-7");
        // …and `--rm`, the daemon-side half: a container that exits after its node died still goes
        // away, because AutoRemove is the daemon's promise rather than the CLI's.
        assert!(argv.iter().any(|a| a == "--rm"), "AutoRemove must be set: {argv:?}");
    }

    #[test]
    fn two_runners_sharing_a_daemon_write_labels_that_cannot_match_each_other() {
        // The safety property `reap_orphans` rests on. Verified against docker 28.0.4 that a filter
        // value which is a *prefix* of a label matches nothing, so these two are genuinely disjoint
        // rather than merely different-looking.
        let alpha = ContainerConfig { runner_id: "node-a".into(), ..Default::default() };
        let beta = ContainerConfig { runner_id: "node-a-2".into(), ..Default::default() };
        assert_ne!(alpha.runner_label(), beta.runner_label());

        // A runner id is operator configuration and lands in an argv element and a filter string, so
        // it goes through the same sanitiser a job id does: nothing in it can become a second flag.
        let hostile = ContainerConfig { runner_id: "--privileged x".into(), ..Default::default() };
        assert!(!hostile.runner_label().contains(' '));
        assert!(hostile.runner_label().starts_with("hull-ci.runner="));
    }

    /// Write an executable stand-in for the runtime CLI, which records every argv it is handed.
    ///
    /// Lets the three bugs below be settled deterministically: "did `destroy` issue an `rm`" is a
    /// question about our control flow, and answering it against a real daemon would make it a
    /// question about timing as well.
    #[cfg(unix)]
    fn fake_runtime(dir: &Path, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("fake-runtime");
        std::fs::write(&path, body).expect("write the stand-in runtime");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        path.display().to_string()
    }

    /// The argv lines a [`fake_runtime`] recorded.
    #[cfg(unix)]
    fn recorded(log: &Path) -> String {
        std::fs::read_to_string(log).unwrap_or_default()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_create_that_times_out_is_still_torn_down() {
        // The second half of the audit's §14.1 finding: `self.created` was set from the *CLI's* exit
        // status, so a `create` that hit `control_timeout` while the daemon went on creating the
        // container left `created = false` and `destroy` skipped the `rm` entirely. The flag has to
        // mean "an attempt was made the daemon may have completed", not "the CLI said yes".
        let t = tempfile::tempdir().unwrap();
        let log = t.path().join("calls.log");
        let runtime = fake_runtime(
            t.path(),
            &format!(
                "#!/bin/sh\necho \"$@\" >> {log}\nif [ \"$1\" = create ]; then sleep 30; fi\nexit 0\n",
                log = log.display()
            ),
        );
        let config = ContainerConfig {
            runtime,
            // Generous: the assertion below is about ordering, not about speed, and a
            // fork+exec on a loaded machine has been seen to take longer than a tight budget.
            control_timeout: Duration::from_secs(3),
            runner_id: "node-under-test".into(),
            ..Default::default()
        };
        let ws = tempfile::tempdir().unwrap();
        let mut s = spec(ws.path());
        s.image = "alpine:3".into();
        let backend = ContainerBackend::from_probe(config.clone(), linux_probe());

        let mut sbx = backend.spawn(&s).await.expect("spawn");
        let name = sbx.id().to_string();
        let req = ExecRequest {
            job_id: s.job_id.clone(),
            argv: vec!["/bin/true".into()],
            timeout: Duration::from_secs(5),
            caps: crate::capture::OutputCaps::default(),
        };
        let err = sbx.exec(&req).await.expect_err("a create we never heard back from is not a success");
        assert!(matches!(err, SandboxError::Runtime(_)), "wrong error: {err}");
        assert!(recorded(&log).contains("create "), "the create was in fact attempted");

        sbx.destroy().await.expect("destroy");
        assert!(
            recorded(&log).contains(&format!("rm --force --volumes {name}")),
            "a create that timed out must still be torn down: {}",
            recorded(&log)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_sandbox_that_never_created_anything_issues_no_rm() {
        // The positive control for the test above, and the reason its assertion means something: the
        // same probe over the same log comes out the other way when there is nothing to remove. If
        // `destroy` issued an `rm` unconditionally, "the rm is there" would be true for every
        // possible bug in the ordering.
        let t = tempfile::tempdir().unwrap();
        let log = t.path().join("calls.log");
        let runtime = fake_runtime(
            t.path(),
            &format!("#!/bin/sh\necho \"$@\" >> {log}\nexit 0\n", log = log.display()),
        );
        let config = ContainerConfig { runtime, ..Default::default() };
        let ws = tempfile::tempdir().unwrap();
        let backend = ContainerBackend::from_probe(config, linux_probe());

        // Spawned and torn down without ever running: `spawn` reserves the name, `exec` is what
        // creates the container, and this never gets there.
        let sbx = backend.spawn(&spec(ws.path())).await.expect("spawn");
        sbx.destroy().await.expect("destroy");
        assert!(
            !recorded(&log).contains("rm --force"),
            "nothing was created, so nothing is removed: {}",
            recorded(&log)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_sandbox_dropped_without_destroy_still_removes_its_container() {
        // `ContainerInstance` had no `Drop` at all: a dropped `run_assignment` future — a cancelled
        // lease, an early `?`, a panic unwinding through the node — left the container behind with
        // nothing scheduled to remove it. This is the best-effort second line; see the `Drop` impl
        // for why it is not the guarantee.
        let t = tempfile::tempdir().unwrap();
        let log = t.path().join("calls.log");
        let runtime = fake_runtime(
            t.path(),
            &format!("#!/bin/sh\necho \"$@\" >> {log}\nexit 0\n", log = log.display()),
        );
        let config = ContainerConfig { runtime, ..Default::default() };
        let ws = tempfile::tempdir().unwrap();
        let mut s = spec(ws.path());
        s.image = "alpine:3".into();
        let backend = ContainerBackend::from_probe(config, linux_probe());

        let mut sbx = backend.spawn(&s).await.expect("spawn");
        let name = sbx.id().to_string();
        let req = ExecRequest {
            job_id: s.job_id.clone(),
            argv: vec!["/bin/true".into()],
            timeout: Duration::from_secs(5),
            caps: crate::capture::OutputCaps::default(),
        };
        sbx.exec(&req).await.expect("exec");
        // `rm --force`, not `rm ` — every create argv now carries `--rm`, and a probe that
        // matches the flag it is meant to ignore is a probe that can never fail.
        assert!(!recorded(&log).contains("rm --force"), "nothing has been torn down yet");

        // The whole point: no `destroy()`, just a drop.
        drop(sbx);
        // The removal is *spawned*, never awaited in the destructor — a destructor that blocks on a
        // daemon socket is how a node stops taking work. So the test yields to the runtime rather
        // than expecting the effect to have happened by the time `drop` returned.
        for _ in 0..200 {
            if recorded(&log).contains("rm --force --volumes") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            recorded(&log).contains(&format!("rm --force --volumes {name}")),
            "a dropped sandbox must still try to take its container with it: {}",
            recorded(&log)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_destroyed_sandbox_is_not_removed_a_second_time_by_its_drop() {
        // The control for the test above: `destroy()` marks the guard, so the ordinary path must not
        // also fire the destructor's removal. Without this, the previous test would pass even if
        // `Drop` ignored the lifecycle entirely.
        let t = tempfile::tempdir().unwrap();
        let log = t.path().join("calls.log");
        let runtime = fake_runtime(
            t.path(),
            &format!("#!/bin/sh\necho \"$@\" >> {log}\nexit 0\n", log = log.display()),
        );
        let config = ContainerConfig { runtime, ..Default::default() };
        let ws = tempfile::tempdir().unwrap();
        let mut s = spec(ws.path());
        s.image = "alpine:3".into();
        let backend = ContainerBackend::from_probe(config, linux_probe());

        let mut sbx = backend.spawn(&s).await.expect("spawn");
        let req = ExecRequest {
            job_id: s.job_id.clone(),
            argv: vec!["/bin/true".into()],
            timeout: Duration::from_secs(5),
            caps: crate::capture::OutputCaps::default(),
        };
        sbx.exec(&req).await.expect("exec");
        sbx.destroy().await.expect("destroy");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            recorded(&log).matches("rm --force --volumes").count(),
            1,
            "exactly one removal on the ordinary path: {}",
            recorded(&log)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_reaper_asks_for_this_runners_label_and_removes_what_it_is_given() {
        let t = tempfile::tempdir().unwrap();
        let log = t.path().join("calls.log");
        // `ps` answers with two container ids; everything else just records and succeeds.
        let runtime = fake_runtime(
            t.path(),
            &format!(
                "#!/bin/sh\necho \"$@\" >> {log}\n\
                 if [ \"$1\" = ps ]; then echo abc123; echo def456; fi\nexit 0\n",
                log = log.display()
            ),
        );
        let config = ContainerConfig { runtime, runner_id: "node-9".into(), ..Default::default() };

        let reaped = reap_orphans(&config).await.expect("reap");
        assert_eq!(reaped.removed, vec!["abc123", "def456"]);
        assert!(reaped.failures.is_empty());

        let calls = recorded(&log);
        assert!(
            calls.contains("--filter label=hull-ci.runner=node-9"),
            "the filter must be this runner's label, exactly: {calls}"
        );
        assert!(calls.contains("ps --all --quiet"), "stopped orphans count too: {calls}");
        assert!(calls.contains("rm --force --volumes abc123"), "{calls}");
        assert!(calls.contains("rm --force --volumes def456"), "{calls}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_reaper_that_is_given_nothing_removes_nothing() {
        // The control: the same code path over a daemon that reports no matching containers. This is
        // what a second runner on the same daemon sees, and it must be a no-op rather than a sweep.
        let t = tempfile::tempdir().unwrap();
        let log = t.path().join("calls.log");
        let runtime = fake_runtime(
            t.path(),
            &format!("#!/bin/sh\necho \"$@\" >> {log}\nexit 0\n", log = log.display()),
        );
        let config = ContainerConfig { runtime, runner_id: "node-9".into(), ..Default::default() };
        assert_eq!(reap_orphans(&config).await.expect("reap"), Reaped::default());
        assert!(!recorded(&log).contains("rm --force"), "no ids, no removals: {}", recorded(&log));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_daemon_that_will_not_answer_the_listing_is_an_error_rather_than_an_empty_sweep() {
        // A `ps` that fails must not read as "there are no orphans". The distinction matters at node
        // start: one of those means §14.1 is being kept, the other means nobody looked.
        let t = tempfile::tempdir().unwrap();
        let runtime =
            fake_runtime(t.path(), "#!/bin/sh\necho 'cannot connect to the daemon' >&2\nexit 1\n");
        let config = ContainerConfig { runtime, ..Default::default() };
        assert!(matches!(reap_orphans(&config).await, Err(SandboxError::Runtime(_))));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_orphan_that_cannot_be_removed_is_reported_rather_than_swallowed() {
        let t = tempfile::tempdir().unwrap();
        let runtime = fake_runtime(
            t.path(),
            "#!/bin/sh\nif [ \"$1\" = ps ]; then echo stuck1; exit 0; fi\n\
             echo 'device or resource busy' >&2\nexit 1\n",
        );
        let config = ContainerConfig { runtime, ..Default::default() };
        let reaped = reap_orphans(&config).await.expect("the listing succeeded");
        assert!(reaped.removed.is_empty());
        assert_eq!(reaped.failures.len(), 1, "an orphan we could not remove is still an orphan");
        assert!(reaped.failures[0].contains("stuck1"));
    }

    // ── D§6.4 warm pools: the parts that can be settled without a daemon ───────────────────────
    //
    // The live probes further down settle what a *container* does. These settle our control flow:
    // which argv is issued for a warm slot, that a member never gets the one flag that could weaken
    // it, and that the whole miss → warm → hit → destroy cycle really runs — because the way a warm
    // pool fails is that it silently never warms, and every job then works perfectly on the cold
    // path.

    #[test]
    fn an_exec_supplies_the_job_and_inherits_every_control_from_the_container() {
        // The three things a member created before the job existed could not have, and the one flag
        // that must never appear. `docker exec --user 0:0` really does run as uid 0 (verified against
        // docker 28.0.4), so it is the single flag on this path that could undo §14.4's non-root
        // control — and it is not here.
        let t = tempfile::tempdir().unwrap();
        let mut s = spec(t.path());
        s.broker_authorised = vec!["NPM_TOKEN".into()];
        s.secret_env = vec![("NPM_TOKEN".into(), zeroize::Zeroizing::new("npm_s3cr3tvalue".into()))];

        let argv = exec_argv(
            &ContainerConfig::default(),
            &s,
            "hull-ci-warm-1",
            &["cargo".into(), "test".into()],
        );
        let joined = argv.join(" ");

        assert!(joined.contains("exec --workdir /workspace"), "{joined}");
        assert!(argv.windows(2).any(|w| w[0] == "--env" && w[1] == "CI=true"));
        // Delivered secrets travel by name, exactly as they do at `create`: `--env NAME=VALUE` puts
        // the plaintext in an argv every other local user can read out of `/proc`.
        assert!(argv.windows(2).any(|w| w[0] == "--env" && w[1] == "NPM_TOKEN"));
        assert!(!joined.contains("npm_s3cr3tvalue"), "the value reached an argv: {joined}");
        assert!(
            !argv.iter().any(|a| a == "--user"),
            "an exec must never re-declare the user: `--user 0:0` runs as root ({joined})"
        );
        assert!(
            !argv.iter().any(|a| a == "--privileged" || a == "--cap-add"),
            "nor anything that could add back what the container dropped: {joined}"
        );
        assert!(!argv.iter().any(|a| a == "sh" || a == "-c"), "no shell, ever (D§7.2)");

        // The flag list is terminated before the container name, so a pipeline-controlled argv[0]
        // lands where flags are no longer being parsed — the same reason `create_argv` does it.
        let end = argv.iter().position(|a| a == "--").expect("the flag list must be terminated");
        assert_eq!(argv[end + 1], "hull-ci-warm-1");
        assert_eq!(&argv[end + 2..], &["cargo".to_string(), "test".to_string()]);
    }

    #[test]
    fn a_command_the_image_does_not_have_is_errored_rather_than_a_red_verdict() {
        // On the cold path this is a `create`/`start` failure and can only be `errored`. Through an
        // exec it is exit 126 with the runtime's own line, which without this would be reported as
        // the *job* exiting 126 — a red verdict about code that never ran (§7).
        let oci = "OCI runtime exec failed: exec failed: unable to start container process: exec: \
                   \"cargo\": executable file not found in $PATH: unknown";
        let why = exec_never_started(ExecStatus::Exited(126), oci).expect("must be recognised");
        assert!(why.contains("infrastructure failure and not a test result"), "{why}");
        assert!(why.contains("executable file not found"), "the runtime's own text survives: {why}");

        // …and the control: a job that genuinely exits 126 is a job that exited 126.
        assert!(exec_never_started(ExecStatus::Exited(126), "permission denied\n").is_none());
        assert!(exec_never_started(ExecStatus::Exited(1), oci).is_none());
        assert!(exec_never_started(ExecStatus::Exited(0), "").is_none());
    }

    /// A runtime stand-in that answers everything the pool asks: `create`, `start`, `inspect`
    /// (running), `exec` and `rm`. Every call is recorded, so "did a warm container get created, and
    /// did the next job run inside it" is a question about the log rather than about timing.
    #[cfg(unix)]
    fn pooling_runtime(dir: &Path, log: &Path) -> String {
        fake_runtime(
            dir,
            &format!(
                "#!/bin/sh\necho \"$@\" >> {log}\n\
                 if [ \"$1\" = inspect ]; then echo true; fi\nexit 0\n",
                log = log.display()
            ),
        )
    }

    #[cfg(unix)]
    fn pooled_config(runtime: String, root: &Path, depth: usize) -> ContainerConfig {
        ContainerConfig {
            runtime,
            runner_id: "node-pooled".into(),
            control_timeout: Duration::from_secs(5),
            pool: PoolConfig { depth, total: 4, root: root.to_path_buf(), ..PoolConfig::default() },
            ..Default::default()
        }
    }

    /// Run one whole job — spawn, exec, collect, destroy — and hand back the sandbox's id.
    #[cfg(unix)]
    async fn run_one(backend: &ContainerBackend, spec: &SandboxSpec) -> String {
        let mut sbx = backend.spawn(spec).await.expect("spawn");
        let id = sbx.id().to_string();
        let req = ExecRequest {
            job_id: spec.job_id.clone(),
            argv: vec!["/bin/true".into()],
            timeout: Duration::from_secs(5),
            caps: crate::capture::OutputCaps::default(),
        };
        sbx.exec(&req).await.expect("exec");
        sbx.collect().await.expect("collect");
        sbx.destroy().await.expect("destroy");
        id
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_pool_warms_at_teardown_and_the_next_job_runs_in_a_container_that_already_existed() {
        // The whole cycle, asserted rather than inferred: the first job misses and takes the cold
        // path, teardown warms one member, and the second job of the same shape runs in **the
        // container that was created during the first job's teardown**.
        //
        // That last clause is the one that matters. A pool that silently never warms passes every
        // functional test — every job takes the cold path and works — so the hit is established from
        // the recorded call log (this name was created before this job was spawned) and from the
        // counters, never from a stopwatch.
        let t = tempfile::tempdir().unwrap();
        let log = t.path().join("calls.log");
        let root = t.path().join("pool");
        let config = pooled_config(pooling_runtime(t.path(), &log), &root, 1);
        let backend = ContainerBackend::from_probe(config, linux_probe());

        let ws1 = tempfile::tempdir().unwrap();
        let mut first = spec(ws1.path());
        first.image = "alpine:3".into();
        let cold_id = run_one(&backend, &first).await;

        let stats = backend.pool_stats().expect("a pool was configured");
        assert_eq!(stats.misses, 1, "the first job of a shape has nothing warm: {stats:?}");
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.warmed, 1, "…and teardown warmed one for the next: {stats:?}");

        // The log as it stood *before* the second job was spawned. Everything asserted below about
        // "already existed" is a statement about this snapshot.
        let before = recorded(&log);
        assert!(before.contains(&format!("start --attach {cold_id}")), "the first job ran cold");

        let ws2 = tempfile::tempdir().unwrap();
        let mut second = spec(ws2.path());
        second.image = "alpine:3".into();
        second.job_id = "job-2".into();
        let warm_id = run_one(&backend, &second).await;

        let stats = backend.pool_stats().unwrap();
        assert_eq!(stats.hits, 1, "the second job must have found the member: {stats:?}");
        assert_ne!(warm_id, cold_id);
        assert!(
            before.contains(&format!("create --name {warm_id}")),
            "the container the second job ran in was created before that job was spawned: {before}"
        );

        let after = recorded(&log);
        assert!(
            after.contains("exec --workdir /workspace") && after.contains(&warm_id),
            "the job's argv went in through `docker exec`: {after}"
        );
        assert_eq!(
            after.matches(&format!("create --name {warm_id}")).count(),
            1,
            "the member was created once, not once per job: {after}"
        );
        // §14.1: the member is destroyed after its one job.
        assert!(
            after.contains(&format!("rm --force --volumes {warm_id}")),
            "a member must be destroyed after its one job: {after}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_member_is_handed_to_one_job_and_the_next_job_gets_a_different_one() {
        // §14.1's prohibition, at the level the pool could break it: not "can this sandbox run twice"
        // (the `UseGuard` settles that) but "can the pool hand the same container to two jobs". It
        // cannot, because `claim` removes what it hands over and there is no path that puts one back.
        let t = tempfile::tempdir().unwrap();
        let log = t.path().join("calls.log");
        let root = t.path().join("pool");
        let config = pooled_config(pooling_runtime(t.path(), &log), &root, 1);
        let backend = ContainerBackend::from_probe(config, linux_probe());

        let mut ids = Vec::new();
        for n in 0..4 {
            let ws = tempfile::tempdir().unwrap();
            let mut s = spec(ws.path());
            s.image = "alpine:3".into();
            s.job_id = format!("job-{n}");
            ids.push(run_one(&backend, &s).await);
        }
        let unique: std::collections::BTreeSet<&String> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "a container served two jobs: {ids:?}");

        let stats = backend.pool_stats().unwrap();
        assert_eq!(stats.hits, 3, "three of the four found a member: {stats:?}");
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.warmed, 4, "and each teardown warmed exactly one replacement");
        // Every container this backend touched was removed, warm or cold.
        let calls = recorded(&log);
        for id in &ids {
            assert!(calls.contains(&format!("rm --force --volumes {id}")), "{id} survived: {calls}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_job_whose_shape_has_nothing_warm_creates_a_container_rather_than_waiting() {
        // Exhaustion is a cold create, never a queue: D§6.4 buys latency, and a pool that made a job
        // wait for a refill would be spending the thing it exists to save.
        let t = tempfile::tempdir().unwrap();
        let log = t.path().join("calls.log");
        let root = t.path().join("pool");
        let config = pooled_config(pooling_runtime(t.path(), &log), &root, 1);
        let backend = ContainerBackend::from_probe(config, linux_probe());

        // Warm a member for one shape…
        let ws = tempfile::tempdir().unwrap();
        let mut alpine = spec(ws.path());
        alpine.image = "alpine:3".into();
        run_one(&backend, &alpine).await;
        assert_eq!(backend.pool_stats().unwrap().warmed, 1);

        // …then run a job of a *different* shape. Nothing warm matches it, and it still runs.
        let ws = tempfile::tempdir().unwrap();
        let mut other = spec(ws.path());
        other.image = "debian:12".into();
        other.job_id = "job-other".into();
        let id = run_one(&backend, &other).await;

        let stats = backend.pool_stats().unwrap();
        assert_eq!(stats.hits, 0, "a member for another image must not have been used: {stats:?}");
        assert_eq!(stats.misses, 2);
        let calls = recorded(&log);
        assert!(
            calls.contains(&format!("create --name {id}")) && calls.contains("debian:12"),
            "the job created its own container the cold way: {calls}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_pool_that_cannot_warm_costs_latency_and_never_a_job() {
        // The requirement that outranks the feature: warming is housekeeping, and housekeeping must
        // not be able to fail a verdict. Here `create` fails for every warm attempt (the runtime
        // refuses anything whose name starts `hull-ci-warm-`) and every job still runs.
        let t = tempfile::tempdir().unwrap();
        let log = t.path().join("calls.log");
        let runtime = fake_runtime(
            t.path(),
            &format!(
                "#!/bin/sh\necho \"$@\" >> {log}\n\
                 case \"$*\" in *hull-ci-warm-*) exit 125;; esac\n\
                 if [ \"$1\" = inspect ]; then echo true; fi\nexit 0\n",
                log = log.display()
            ),
        );
        let config = pooled_config(runtime, &t.path().join("pool"), 1);
        let backend = ContainerBackend::from_probe(config, linux_probe());

        for n in 0..2 {
            let ws = tempfile::tempdir().unwrap();
            let mut s = spec(ws.path());
            s.image = "alpine:3".into();
            s.job_id = format!("job-{n}");
            run_one(&backend, &s).await;
        }
        let stats = backend.pool_stats().unwrap();
        assert_eq!(stats.warmed, 0, "nothing could be warmed: {stats:?}");
        assert_eq!(stats.warm_failures, 2, "…and the operator is told, twice: {stats:?}");
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 2, "every job took the cold path and every job ran");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_pooled_job_takes_its_workspace_with_it_and_leaves_the_mount_directory_gone() {
        // D§6.2's "teardown = drop the snapshot", on the pooled path. The workspace moves *into* the
        // member's mount directory at claim, so destroying the member has to take that directory
        // with it — otherwise a node accumulates one checkout per pooled job on disk.
        let t = tempfile::tempdir().unwrap();
        let log = t.path().join("calls.log");
        let root = t.path().join("pool");
        let config = pooled_config(pooling_runtime(t.path(), &log), &root, 1);
        let backend = ContainerBackend::from_probe(config, linux_probe());

        let ws1 = tempfile::tempdir().unwrap();
        let mut first = spec(ws1.path());
        first.image = "alpine:3".into();
        run_one(&backend, &first).await;
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1, "one member is waiting");

        let ws2 = tempfile::tempdir().unwrap();
        std::fs::write(ws2.path().join("Cargo.toml"), b"[package]").unwrap();
        let mut second = spec(ws2.path());
        second.image = "alpine:3".into();
        second.job_id = "job-2".into();

        let mut sbx = backend.spawn(&second).await.expect("spawn");
        assert_eq!(backend.pool_stats().unwrap().hits, 1);
        // The job's tree really did move into the member's directory — this is D§6.4's "bind the
        // workspace", done the only way docker allows.
        let member_dir = std::fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.join("Cargo.toml").exists())
            .expect("the workspace must be inside a member's mount directory");
        assert_eq!(std::fs::read_dir(ws2.path()).unwrap().count(), 0, "and out of the caller's");

        let req = ExecRequest {
            job_id: second.job_id.clone(),
            argv: vec!["/bin/true".into()],
            timeout: Duration::from_secs(5),
            caps: crate::capture::OutputCaps::default(),
        };
        sbx.exec(&req).await.expect("exec");
        sbx.destroy().await.expect("destroy");
        assert!(!member_dir.exists(), "the job's workspace must die with its sandbox (§14.1, D§6.2)");
    }

    // ── D§6.4 warm pools, against a real daemon ────────────────────────────────────────────────
    //
    // The unit tests above settle our control flow against a stand-in runtime. These settle the two
    // things only a daemon can answer: that a container created *before* a job existed can be given
    // that job's workspace and argv at all, and that doing so leaves every §14 control exactly where
    // the cold path leaves it. The second is the one that matters — a fast sandbox that is not a
    // sandbox is worse than a slow one — so the isolation probes below are the same assertions the
    // cold-path probes at the top of this file make, re-run through a pool member.
    //
    // Each also asserts the **hit** from a counter and from the container's identity, never from a
    // clock: a pool that silently never warms would otherwise pass every one of them, because every
    // job would simply take the cold path and work.

    /// A [`ContainerConfig`] with a warm pool, on a runner id unique to this call.
    fn live_pooled_config(root: &Path, depth: usize) -> ContainerConfig {
        ContainerConfig {
            pool: PoolConfig {
                depth,
                total: 4,
                root: root.to_path_buf(),
                ..PoolConfig::default()
            },
            ..live_config()
        }
    }

    /// Every container this runner currently has, by name.
    async fn container_names(config: &ContainerConfig) -> Vec<String> {
        let argv = vec![
            config.runtime.clone(),
            "ps".into(),
            "--all".into(),
            "--filter".into(),
            format!("label={}", config.runner_label()),
            "--format".into(),
            "{{.Names}}".into(),
        ];
        match control_command(config, argv, &[]).await {
            Ok((ExecStatus::Exited(0), out)) => {
                out.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect()
            }
            _ => Vec::new(),
        }
    }

    /// Which docker network a container is actually attached to.
    async fn container_network(config: &ContainerConfig, name: &str) -> String {
        let argv = vec![
            config.runtime.clone(),
            "inspect".into(),
            name.to_string(),
            "--format".into(),
            "{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}".into(),
        ];
        match control_command(config, argv, &[]).await {
            Ok((ExecStatus::Exited(0), out)) => out.trim().to_string(),
            _ => String::new(),
        }
    }

    /// One whole job on an existing backend: spawn, exec, collect, destroy. Returns the sandbox id
    /// and what the job printed.
    async fn run_job(backend: &ContainerBackend, spec: &SandboxSpec, argv: &[&str]) -> (String, String) {
        let mut sbx = backend.spawn(spec).await.expect("spawn");
        let id = sbx.id().to_string();
        let req = ExecRequest {
            job_id: spec.job_id.clone(),
            argv: argv.iter().map(|a| a.to_string()).collect(),
            timeout: Duration::from_secs(120),
            caps: crate::capture::OutputCaps::default(),
        };
        let _ = sbx.exec(&req).await.expect("exec");
        let out = sbx.collect().await.unwrap().text().to_string();
        sbx.destroy().await.expect("destroy");
        (id, out)
    }

    /// A job spec of a given shape, with its own workspace directory.
    fn live_job(ws: &Path, job_id: &str) -> SandboxSpec {
        let mut s = spec(ws);
        s.image = "alpine:3".into();
        s.job_id = job_id.into();
        s
    }

    #[tokio::test]
    #[ignore = "requires a running container daemon and the alpine image"]
    async fn live_a_pooled_job_runs_in_a_container_that_existed_before_it_and_never_a_second_job() {
        // D§6.4's claim, made checkable: the second job of a shape runs in a container the daemon
        // already had, and that container is gone afterwards.
        //
        // "Already had" is established from the daemon's own listing taken *before* the job was
        // spawned — a causal ordering, not an elapsed time. Nothing here is timed.
        let root = tempfile::tempdir().unwrap();
        let config = live_pooled_config(root.path(), 1);
        let backend = ContainerBackend::detect(config.clone()).await.expect("daemon");

        let ws1 = tempfile::tempdir().unwrap();
        let (cold_id, out) = run_job(&backend, &live_job(ws1.path(), "job-1"), &["/bin/echo", "one"]).await;
        assert!(out.contains("one"), "the first job must run: {out}");
        let stats = backend.pool_stats().expect("a pool was configured");
        assert_eq!(stats.misses, 1, "nothing was warm for the first job of a shape: {stats:?}");
        assert_eq!(stats.warmed, 1, "…and its teardown warmed one: {stats:?}");

        // What the daemon had before the second job existed.
        let before = container_names(&config).await;
        assert!(!before.contains(&cold_id), "the first job's container is gone (§14.1)");
        assert_eq!(before.len(), 1, "exactly one idle member is waiting: {before:?}");

        let ws2 = tempfile::tempdir().unwrap();
        let (warm_id, out) = run_job(&backend, &live_job(ws2.path(), "job-2"), &["/bin/echo", "two"]).await;
        assert!(out.contains("two"), "the pooled job must run: {out}");
        let stats = backend.pool_stats().unwrap();
        assert_eq!(stats.hits, 1, "the second job must have found the member: {stats:?}");
        assert!(
            before.contains(&warm_id),
            "the pooled job ran in a container the daemon did not already have: {warm_id} not in {before:?}"
        );

        // §14.1: one job, then destroyed. Never handed to a second.
        assert!(!container_exists(&config, &warm_id).await, "a used member must not survive its job");
        let ws3 = tempfile::tempdir().unwrap();
        let (third_id, _) = run_job(&backend, &live_job(ws3.path(), "job-3"), &["/bin/echo", "three"]).await;
        assert_ne!(third_id, warm_id, "a member was handed to a second job (§14.1)");
        assert_eq!(backend.pool_stats().unwrap().hits, 2, "…and it was still a pooled run");

        backend.drain_pool().await;
        assert!(container_names(&config).await.is_empty(), "nothing of this runner's is left");
    }

    #[tokio::test]
    #[ignore = "requires a running container daemon and the alpine image"]
    async fn live_a_pooled_sandbox_is_still_a_sandbox() {
        // **The test that decides whether this feature may ship.** A pre-created container is only
        // acceptable if `docker exec` inherits every control the cold path gets at `create`, so this
        // re-runs the §14 probes from the top of this file *through a pool member* — and asserts the
        // hit first, because a pool that silently never warms would otherwise make this a very
        // thorough test of the cold path.
        let root = tempfile::tempdir().unwrap();
        let config = live_pooled_config(root.path(), 1);
        let backend = ContainerBackend::detect(config.clone()).await.expect("daemon");
        assert!(backend.controls().egress_deny, "the backend claims `--network none`");

        // The probe. Identical for both runs, so "the pooled sandbox is the same sandbox" is one
        // string compared twice rather than two lists of assertions that could drift.
        const PROBE: &[&str] = &[
            "/bin/sh",
            "-c",
            "echo uid=$(id -u); \
             touch /planted 2>/dev/null; echo ro_rc=$?; \
             touch /tmp/scratch 2>/dev/null; echo tmp_rc=$?; \
             wget -q -T 2 -O- http://1.1.1.1 >/dev/null 2>&1; echo raw_rc=$?; \
             wget -q -T 2 -O- http://example.com >/dev/null 2>&1; echo dns_rc=$?; \
             wget -q -T 2 -O- http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1; echo meta_rc=$?; \
             echo nnp=$(grep ^NoNewPrivs /proc/self/status | tr -d ' \\t' ); \
             echo caps=$(grep ^CapEff /proc/self/status | tr -d ' \\t'); \
             echo mem=$(cat /sys/fs/cgroup/memory.max 2>/dev/null); \
             echo pids=$(cat /sys/fs/cgroup/pids.max 2>/dev/null); \
             echo planted > /tmp/evidence; \
             cat /tmp/evidence",
        ];

        // 1. Cold, to establish what the probe says about a sandbox this crate already trusts.
        let ws1 = tempfile::tempdir().unwrap();
        let (_, cold) = run_job(&backend, &live_job(ws1.path(), "job-cold"), PROBE).await;
        assert_eq!(backend.pool_stats().unwrap().misses, 1, "the first job of a shape is cold");

        // 2. Pooled — and it really is pooled, asserted before anything is concluded from it.
        let ws2 = tempfile::tempdir().unwrap();
        let (warm_id, warm) = run_job(&backend, &live_job(ws2.path(), "job-warm"), PROBE).await;
        assert_eq!(
            backend.pool_stats().unwrap().hits,
            1,
            "this job took the cold path, so nothing below says anything about pooling"
        );

        // §14.4: non-root, read-only rootfs, writable tmpfs scratch, capabilities gone,
        // no-new-privileges, and the cgroup ceilings.
        assert!(warm.contains("uid=65534"), "a pooled job must not run as root: {warm}");
        assert!(warm.contains("ro_rc=1"), "the root filesystem must be read-only: {warm}");
        assert!(warm.contains("tmp_rc=0"), "…but /tmp must be writable: {warm}");
        assert!(warm.contains("nnp=NoNewPrivs:1"), "no-new-privileges must survive an exec: {warm}");
        assert!(
            warm.contains("caps=CapEff:0000000000000000"),
            "every capability must still be dropped: {warm}"
        );
        assert!(warm.contains("mem=4294967296"), "the memory ceiling is the container's: {warm}");
        assert!(warm.contains("pids=2048"), "the pid ceiling is the container's: {warm}");

        // §14.2/§14.3: no egress, no name resolution, no metadata endpoint.
        assert!(warm.contains("raw_rc=1"), "a pooled job must have no egress to a raw IP: {warm}");
        assert!(warm.contains("dns_rc=1"), "…nor to a public name: {warm}");
        assert!(warm.contains("meta_rc=1"), "…nor to the cloud metadata endpoint: {warm}");
        assert!(!warm.contains("ami-"), "and nothing resembling instance metadata came back: {warm}");

        // The strongest form of all of the above: the pooled sandbox and the cold one are
        // indistinguishable from inside. If a future flag stops being inherited by an exec, this
        // fails without anyone having had to think of that flag in advance.
        assert_eq!(
            cold.trim(),
            warm.trim(),
            "a pooled sandbox must be the same sandbox as a cold one, control for control"
        );

        // §14.1: nothing the pooled job planted survives, and nothing of it is left on the daemon or
        // on disk.
        assert!(warm.contains("planted"), "the job did write its marker: {warm}");
        assert!(!container_exists(&config, &warm_id).await, "the member must be gone");
        let ws3 = tempfile::tempdir().unwrap();
        let (_, next) = run_job(
            &backend,
            &live_job(ws3.path(), "job-after"),
            &["/bin/sh", "-c", "cat /tmp/evidence 2>&1; echo rc=$?"],
        )
        .await;
        assert_eq!(backend.pool_stats().unwrap().hits, 2, "…and this one was pooled too");
        assert!(next.contains("rc=1"), "a pooled sandbox must not carry the last job's writes: {next}");

        backend.drain_pool().await;
        // Every member's mount directory is gone too: the workspace dies with the sandbox (D§6.2).
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0, "mount directories survived");
    }

    #[tokio::test]
    #[ignore = "requires a running container daemon, the alpine image, and network creation rights"]
    async fn live_a_member_created_for_one_network_is_never_handed_to_a_job_needing_the_other() {
        // The failure this module is built to make unrepresentable: a job that must have no network
        // handed a container sitting on the package-proxy network. §14.3's guarantee would be gone,
        // and silently — the posture probe that would have caught it ran at creation, against a
        // different container.
        //
        // Both postures are warmed into **one pool**, so the negative result cannot be "the pool was
        // empty": the member is right there, on the other key, and the claim still comes back empty.
        let net = LiveNetwork::internal(stub_port()).await;
        let root = tempfile::tempdir().unwrap();
        let base = live_pooled_config(root.path(), 1);
        let no_network = base.clone();
        let proxied =
            ContainerConfig { network: NetworkMode::ProxyOnly(net.proxy_network()), ..base.clone() };

        let ws = tempfile::tempdir().unwrap();
        let quiet = PoolKey::for_job(&no_network, &live_job(ws.path(), "job-1"));
        let networked = PoolKey::for_job(&proxied, &live_job(ws.path(), "job-1"));
        assert_ne!(quiet, networked);

        let pool = SandboxPool::new(base.pool.clone(), base.control_timeout);
        pool.refill(&quiet).await;
        pool.refill(&networked).await;
        assert_eq!(pool.stats().warmed, 2, "both members must exist for this to prove anything");

        // Each member really is on the network its key names — the fact the whole comparison rests
        // on, taken from the daemon rather than from our own bookkeeping.
        let members = container_names(&base).await;
        assert_eq!(members.len(), 2, "{members:?}");
        let mut networks: Vec<String> = Vec::new();
        for name in &members {
            networks.push(container_network(&base, name).await);
        }
        networks.sort();
        assert_eq!(networks, vec![net.name.clone(), "none".to_string()].tap_sorted());

        // The test proper, in both directions. A claim gets its own posture's member and only ever
        // that one; taking it does not make the *other* posture's member available.
        let first = pool.claim(&quiet).await.expect("its own key finds it");
        assert_eq!(container_network(&base, first.name()).await, "none");
        assert!(
            pool.claim(&quiet).await.is_none(),
            "a job needing no network was given the member sitting on the proxy network (§14.3)"
        );
        let second = pool.claim(&networked).await.expect("the other key finds the other member");
        assert_eq!(container_network(&base, second.name()).await, net.name);
        assert!(pool.claim(&networked).await.is_none());

        let stats = pool.stats();
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 2, "and both refusals were misses, so both jobs go cold: {stats:?}");
        assert_eq!(stats.key_mismatches, 0, "nothing was filed wrongly; the keys simply differ");

        pool.discard_claimed(first).await;
        pool.discard_claimed(second).await;
        pool.drain().await;
        net.destroy().await;
        assert!(container_names(&base).await.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires a running container daemon and the alpine image"]
    async fn live_idle_pool_members_are_removed_by_the_reaper_at_node_start() {
        // An idle member is the one container `--rm` can never collect: AutoRemove fires when a
        // container *exits*, and a member is deliberately one that does not. So a `SIGKILL` leaves
        // every idle member running with a host directory mounted into it, and `reap_orphans` at the
        // next node start is the only thing that removes them.
        //
        // Paired with its control, in one run: the same reaper, the same probe, one thing changed —
        // the runner id it is asked about.
        let root = tempfile::tempdir().unwrap();
        let config = live_pooled_config(root.path(), 2);
        let ws = tempfile::tempdir().unwrap();
        let key = PoolKey::for_job(&config, &live_job(ws.path(), "job-1"));

        let pool = SandboxPool::new(config.pool.clone(), config.control_timeout);
        pool.refill(&key).await;
        pool.refill(&key).await;
        assert_eq!(pool.stats().warmed, 2, "two idle members: {:?}", pool.stats());

        let members = container_names(&config).await;
        assert_eq!(members.len(), 2, "{members:?}");
        for name in &members {
            // Alive, idle, and therefore beyond AutoRemove's reach — which is why the reaper matters.
            assert!(container_running(&config, name).await, "{name} is not running");
        }

        // Control: another runner's reaper must leave them alone. Without this, "gone after the
        // reap" could equally mean "never there".
        let someone_else = ContainerConfig { runner_id: live_config().runner_id, ..config.clone() };
        let swept = reap_orphans(&someone_else).await.expect("reap");
        assert!(swept.removed.is_empty(), "another runner's reaper removed something: {swept:?}");
        assert_eq!(container_names(&config).await.len(), 2, "…and they are still there");

        // The test proper: this runner's node start removes every one of its idle members.
        let reaped = reap_orphans(&config).await.expect("reap");
        assert_eq!(reaped.removed.len(), 2, "the reaper must find idle pool members: {reaped:?}");
        assert!(reaped.failures.is_empty(), "{reaped:?}");
        assert!(container_names(&config).await.is_empty(), "…and the same probe finds nothing");

        pool.drain().await;
    }

    #[tokio::test]
    #[ignore = "requires a running container daemon and the alpine image"]
    async fn live_an_exhausted_pool_falls_back_to_a_cold_create_and_the_job_still_runs() {
        // Exhaustion must never be a queue. Two jobs of one shape are spawned while only one member
        // is warm: the first takes it, the second creates its own, and both produce a verdict.
        let root = tempfile::tempdir().unwrap();
        let config = live_pooled_config(root.path(), 1);
        let backend = ContainerBackend::detect(config.clone()).await.expect("daemon");

        // One member, warmed by the first job's teardown.
        let ws0 = tempfile::tempdir().unwrap();
        run_job(&backend, &live_job(ws0.path(), "job-0"), &["/bin/echo", "zero"]).await;
        assert_eq!(backend.pool_stats().unwrap().warmed, 1);

        // Two sandboxes held open at once, so the second genuinely finds the pool empty.
        let ws1 = tempfile::tempdir().unwrap();
        let ws2 = tempfile::tempdir().unwrap();
        let first_spec = live_job(ws1.path(), "job-1");
        let second_spec = live_job(ws2.path(), "job-2");
        let mut first = backend.spawn(&first_spec).await.expect("spawn");
        let mut second = backend.spawn(&second_spec).await.expect("spawn");

        let stats = backend.pool_stats().unwrap();
        assert_eq!(stats.hits, 1, "exactly one of the two found a member: {stats:?}");
        assert_eq!(stats.misses, 2, "…and the other missed rather than waiting: {stats:?}");

        for (spec, sbx, word) in [
            (&first_spec, &mut first, "one"),
            (&second_spec, &mut second, "two"),
        ] {
            let req = ExecRequest {
                job_id: spec.job_id.clone(),
                argv: vec!["/bin/echo".into(), word.into()],
                timeout: Duration::from_secs(120),
                caps: crate::capture::OutputCaps::default(),
            };
            let outcome = sbx.exec(&req).await.expect("exec");
            assert_eq!(outcome.status, ExecStatus::Exited(0), "the {word} job must run");
            assert!(sbx.collect().await.unwrap().text().contains(word));
        }
        let (a, b) = (first.id().to_string(), second.id().to_string());
        assert_ne!(a, b);
        first.destroy().await.expect("destroy");
        second.destroy().await.expect("destroy");
        assert!(!container_exists(&config, &a).await);
        assert!(!container_exists(&config, &b).await);

        backend.drain_pool().await;
    }

    /// Sort a `Vec<String>` inline, so an expectation reads as one expression.
    trait TapSorted {
        fn tap_sorted(self) -> Self;
    }
    impl TapSorted for Vec<String> {
        fn tap_sorted(mut self) -> Self {
            self.sort();
            self
        }
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

/// Why `create` failed, in a form an operator can act on.
///
/// The runtime's own text is kept — it is the ground truth, and sometimes the only detail — but a
/// missing image gets a sentence in front of it, because it is the one failure that is *certain* on
/// a fresh deployment and the runtime's phrasing points the wrong way. Docker answers "pull access
/// denied ... repository does not exist or may require 'docker login'", which reads as a credentials
/// problem. For the default image it is not one: `hull-ci/m1` is built locally and published to no
/// registry, so no login will ever produce it, and an operator who takes the runtime at its word
/// goes looking for a registry secret that does not exist.
///
/// The verdict summary is truncated to one line (§7), so the actionable half has to come first —
/// which is the other reason not to let the runtime's text lead.
fn create_failure(image: &str, status: ExecStatus, out: &str) -> String {
    if looks_like_missing_image(out) {
        return format!(
            "sandbox image `{image}` is not present locally and cannot be pulled - build it with \
             `docker build -t {image} images/m1`. This image is built locally by design and is \
             published to no registry, so `docker login` will not help. Runtime said: {out}"
        );
    }
    format!("container create failed ({status:?}): {out}")
}

/// Does this runtime output mean "the image is not here"?
///
/// A substring match on someone else's error text, which is exactly the kind of thing that rots —
/// so it is only ever used to *add* a sentence. Every branch still returns the runtime's own output,
/// and a miss costs the operator the hint rather than the information.
fn looks_like_missing_image(out: &str) -> bool {
    let out = out.to_ascii_lowercase();
    out.contains("pull access denied")
        || out.contains("manifest unknown")
        || out.contains("not found: manifest")
        || (out.contains("unable to find image") && out.contains("locally"))
}

#[cfg(test)]
mod create_failure_tests {
    use super::*;

    /// Verbatim from `docker create hull-ci/m1:latest` on a host that has never built it
    /// (docker 28.0.4). Kept as a fixture rather than paraphrased: the whole point of
    /// `looks_like_missing_image` is that it matches what the runtime really says.
    const DOCKER_MISSING: &str = "Unable to find image 'hull-ci/m1:latest' locally\ndocker: Error \
        response from daemon: pull access denied for hull-ci/m1, repository does not exist or may \
        require 'docker login': denied: requested access to the resource is denied";

    #[test]
    fn a_missing_image_is_explained_before_the_runtime_is_quoted() {
        let msg = create_failure("hull-ci/m1:latest", ExecStatus::Exited(1), DOCKER_MISSING);
        let hint = msg.find("build it with").expect("the fix must be stated");
        let quote = msg.find("Runtime said").expect("the runtime's own text must survive");
        assert!(hint < quote, "the actionable half must come first: a summary is truncated");
        assert!(msg.contains("docker build -t hull-ci/m1:latest images/m1"));
        assert!(msg.contains("`docker login` will not help"), "the misleading advice is answered");
    }

    #[test]
    fn every_other_failure_is_passed_through_unembellished() {
        // Guessing wrong here would be worse than not guessing: an operator chasing a fabricated
        // image problem is further from the truth than one reading the runtime verbatim.
        for out in [
            "Error response from daemon: invalid mount config for type \"bind\"",
            "docker: Error response from daemon: no space left on device",
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
        ] {
            let msg = create_failure("hull-ci/m1:latest", ExecStatus::Exited(125), out);
            assert!(msg.starts_with("container create failed"), "{out} was rewritten: {msg}");
            assert!(msg.contains(out));
        }
    }

    #[test]
    fn podman_and_docker_phrasings_are_both_recognised() {
        assert!(looks_like_missing_image(DOCKER_MISSING));
        assert!(looks_like_missing_image("Error: initializing source: manifest unknown"));
        assert!(!looks_like_missing_image("permission denied while trying to connect"));
    }
}
