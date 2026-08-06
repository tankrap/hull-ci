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
    pub async fn detect(config: ContainerConfig) -> Result<Self, SandboxError> {
        let probe = probe_docker(&config.runtime).await;
        if !probe.daemon_reachable {
            return Err(SandboxError::Unavailable(
                probe.failure.unwrap_or_else(|| format!("`{}` daemon is not reachable", config.runtime)),
            ));
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
        ContainerBackend { config, probe, controls }
    }

    pub fn probe(&self) -> &DockerProbe {
        &self.probe
    }

    pub fn config(&self) -> &ContainerConfig {
        &self.config
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

        // Labels let an operator find and reap orphans after a node crash without guessing names.
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
        run_live_on(&ContainerConfig::default(), argv).await
    }

    /// [`run_live`], on a given network posture.
    async fn run_live_on(config: &ContainerConfig, argv: &[&str]) -> String {
        let t = tempfile::tempdir().unwrap();
        let backend = ContainerBackend::detect(config.clone()).await.expect("daemon");
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
                ..Default::default()
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
        let posture = probe_network_posture(&ContainerConfig::default(), &net.proxy_network()).await;
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
        let posture = probe_network_posture(&ContainerConfig::default(), &net.proxy_network()).await;
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
        let none = ContainerBackend::detect(ContainerConfig::default()).await.expect("daemon");
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
        let posture = probe_network_posture(&ContainerConfig::default(), &net.proxy_network()).await;
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
