//! The node agent and its sandbox backends. **All job execution happens here, inside a single-use
//! sandbox.**
//!
//! Spec §14 is normative for this crate in a way it is not for any other: everything a CI job's tree
//! can do — `build.rs`, proc-macros, test bodies, `npm` lifecycle scripts, a `Makefile` — happens on
//! the far side of the seam in [`sandbox`]. The rest of the system decides *what* to run; this crate
//! is the only place that runs it.
//!
//! # The shape
//!
//! - [`sandbox`] — the [`SandboxBackend`]/[`SandboxInstance`] traits: `spawn → exec → collect →
//!   destroy`, plus a capability query. This is the seam design D§7.2 asks for, so that M3 *adds* a
//!   Firecracker backend without the scheduler or this agent changing shape.
//! - [`controls`] — [`EnforcedControls`], one flag per §14 clause, from which the wire
//!   `BackendCapabilities` is **derived**. A backend cannot report a capability it does not enforce,
//!   because it does not write the wire struct by hand.
//! - [`container`] — M1's bring-up backend (`IsolationTier::Container`): single-use, non-root,
//!   read-only rootfs, tmpfs `/tmp`, all caps dropped, `no-new-privileges`, seccomp, cgroup limits,
//!   `--network none`. What it can enforce is **probed at runtime**, not assumed.
//! - [`pool`] — D§6.4's warm sandbox pools: a few containers per hot configuration, created before
//!   any job wants them, each handed to **exactly one** job and destroyed afterwards. Pre-boot, not
//!   reuse — see that module for why §14.1 is untouched, and for the key that makes handing a job a
//!   sandbox built for a different network posture unrepresentable rather than merely unlikely.
//! - [`local`] — a host subprocess for development. Reports ~nothing and is documented
//!   untrusted-input-forbidden.
//! - [`capture`] — the §14.4 output cap (50 MB / 500k lines, truncate-with-marker, keep the tail).
//! - [`detect`] — M1 test-command autodetection, and the `no_tests`-vs-infra distinction §9.1 rests on.
//! - [`agent`] — [`NodeAgent`]: state, heartbeats, one assignment → one [`StepReport`].
//! - [`env`] — the allowlist-built job environment (§14.2).
//! - [`secrets`] — this node's Ed25519 identity and its route to the secret broker (D§7.4).
//! - [`packages`] — the thin seam to the package proxy (§14.3): mint a per-job grant, hand back some
//!   environment variables, revoke when the step ends. The proxy itself lives in another crate and
//!   another process, because it holds tenant registry credentials and D§7.1 says a node holds none.
//!
//! # What this node cannot do, by construction
//!
//! Design D§7.1: the agent "holds **no tenant credentials and no CI shared secret** — neither the
//! fetch path nor the callback path goes through it (§14.2), and there is nothing in its memory a
//! successful sandbox escape would want except the ability to be a node." That is a property of what
//! is *absent* here: there is no HTTP client, no `source_url`, and no `callback_url` anywhere in this
//! crate. [`NodeAgent::run_assignment`] takes a workspace path that somebody else fetched and
//! verified (D§6.2, "materialize, don't fetch").
//!
//! **M3 narrows that claim in one place, and it is worth being exact about where.** With a broker
//! configured, this crate holds two things it did not before:
//!
//! * **Its own enrolment keypair** ([`secrets::SecretsClient`]). It authenticates the node and
//!   authorises nothing: stealing it lets an attacker *be this node*, which is exactly what D§7.1's
//!   "except the ability to be a node" already conceded. It cannot decrypt a stored secret, cannot
//!   mint a capability, and reaches no tenant but whichever one has a job placed here.
//! * **One job's declared secret values, for the length of one spawn.** Redeemed immediately before
//!   `spawn`, dropped immediately after, never written to disk, and only ever for a
//!   `member`-authored job — because the broker refuses to mint for anyone else. That is not a
//!   loophole in D§7.1 but D§7.4's stated design ("holds them in memory **only for the spawn**"), and
//!   the exposure it buys is bounded to the job that asked for them.
//!
//! What is still absent is what mattered: no *platform* credential, no other tenant's anything, and
//! no key that could open a secret at rest. A sandbox escape during a spawn reaches the values that
//! job was about to be handed anyway.
//!
//! Likewise there is no API in this crate that accepts a command *string*. Everything is `Vec<String>`
//! argv, all the way to the sandbox — D§7.2: "No raw shell on any host, ever."
//!
//! # What this host can actually enforce
//!
//! This crate was built on macOS, which has no cgroups v2 and no Linux namespaces of its own; a
//! Docker-compatible daemon supplies both from inside a Linux VM, and if that daemon is down there is
//! no boundary here at all. So the capability answer is computed from a live probe
//! ([`container::probe_docker`]) rather than from a constant, and it can be `false` for reasons that
//! have nothing to do with this code being finished:
//!
//! | §14 control | Container, `--network none` | Container, proxy network | Container, no daemon | Local process |
//! |---|---|---|---|---|
//! | 14.1 single-use | yes | yes | n/a (refuses to construct) | **no** — no rootfs is destroyed |
//! | 14.1 kernel isolation → `cross_tenant_safe` | **no** — shared kernel, always | **no** | n/a | **no** |
//! | 14.2 env allowlist | yes | yes | n/a | yes |
//! | 14.2 metadata blackhole | yes, via `--network none` | **only if probed** | n/a | **no** |
//! | 14.3 egress-deny / no inbound | yes, via `--network none` | **only if probed** | n/a | **no** |
//! | 14.4 non-root, ro-rootfs, tmpfs, caps, NNP, seccomp | yes | yes | n/a | **no** |
//! | 14.4 cpu/mem/pid limits | as the daemon reports them | same | n/a | **no** |
//! | 14.4 disk limit | **no** — not attempted, so not claimed | **no** | n/a | **no** |
//! | 14.4 wall clock + output cap | yes | yes | n/a | yes |
//!
//! # The one place a job gets a network (§14.3)
//!
//! `--network none` is the default and stays the default. [`NetworkMode::ProxyOnly`] is the opt-in
//! exception §14.3 allows — "Where dependency resolution needs it, restrict egress to an allowlisted,
//! authenticated package proxy" — and it is the only configuration in this crate that gives untrusted
//! code a socket to the outside of its netns. That makes it the one place where a wrong `true` in
//! [`EnforcedControls`] would be actively dangerous rather than merely conservative, so it carries a
//! different standard of evidence from everything else here:
//!
//! * A [`ProxyNetwork`] built from configuration has **no posture** and therefore claims **nothing**.
//!   The honest default is a property of the type, not a rule to remember.
//! * [`probe_network_posture`] fills one in by putting a container on the network and *trying* — a
//!   raw public IP, a public hostname, the metadata endpoint, a peer container, a port scan of the
//!   node itself, and an attempt to add a default route.
//! * Every one of those probes is paired with a **control** in the live tests, run on an ordinary
//!   bridge, where it must come out the other way. A probe that cannot fail is not evidence.
//!
//! One result of holding that line: the metadata-endpoint claim does **not** rest on the connect
//! probe, because a control test showed the connect fails identically on a wide-open network (this
//! host runs no metadata service, so nothing answers `169.254.169.254` either way). It rests on there
//! being no route off-subnet and no `CAP_NET_ADMIN` to make one. See
//! [`NetworkPosture::metadata_blackholed`].
//!
//! `cross_tenant_safe` is `false` on every backend in this crate, so `admits_untrusted()` is `false`
//! on every backend in this crate. That is not an oversight — it is design D§13's M1 statement
//! ("**M1 is single-tenant, trusted-input only and MUST NOT take untrusted or multi-tenant input**")
//! expressed as a value the scheduler reads, rather than as a sentence in a document.
//!
//! # What survives a crash (§14.1)
//!
//! §14.1's "destroy the whole rootfs after each job" is the one clause whose enforcement lives in
//! code that might not run. `destroy()` is async, so a `SIGKILL`, a lost host or a dropped
//! `run_assignment` future used to leave a live container with the job's workspace bind-mounted and
//! its wall clock long expired. Three mechanisms now hold it, in decreasing order of how much they
//! can be relied on:
//!
//! 1. [`container::reap_orphans`] at node start, which is the **guarantee**: every container
//!    carrying this runner's `hull-ci.runner` label is removed before any job is placed. Node start
//!    is the only moment at which "this label means orphan" is true by construction.
//! 2. `--rm` (AutoRemove) on every container, which is the **daemon's** promise rather than ours, so
//!    a container that exits after its node died still goes away. It cannot help with one that never
//!    exits, which is why (1) exists.
//! 3. `ContainerInstance`'s `Drop`, which spawns a best-effort removal and never blocks. It covers
//!    the cases where the node survives — a cancelled lease, a panic — and nothing else.
//!
//! The reaper is scoped by an exact `hull-ci.runner=<id>` label match and never removes another
//! runner's containers, so several nodes may share one daemon. See [`ContainerConfig::runner_id`]
//! for the identity contract that makes that true.
//!
//! **Warm pool members are covered by the same three mechanisms, and they need to be.** A member is
//! a container with a host directory bind-mounted into it that is *deliberately* idle, so mechanism
//! (2) — AutoRemove on exit — can never fire for one: it does not exit. That leaves (1), and it is
//! the reason [`pool`] creates every member through [`container::create_argv`] rather than through
//! an argv of its own: the runner label is written by the same function that writes it for a job
//! container, so a member cannot be created without one. A `SIGKILL` therefore leaves idle members
//! running until the next node start, exactly as it leaves a job's container running, and the same
//! sweep collects both. [`ContainerBackend::drain_pool`] is the clean-shutdown courtesy, on the same
//! terms as `Drop`: it covers the case where the node survives, and nothing else.

pub mod agent;
pub mod capture;
pub mod container;
pub mod controls;
pub mod detect;
pub mod env;
pub mod local;
pub mod packages;
pub mod pool;
pub mod process;
pub mod sandbox;
pub mod secrets;

pub use agent::{ControlLink, LinkError, NodeAgent, NodeConfig, NodeErrorKind};
pub use capture::{CapturedOutput, OutputCapture, OutputCaps, DEFAULT_MAX_BYTES, DEFAULT_MAX_LINES};
pub use container::{
    probe_network_posture, ContainerBackend, ContainerConfig, DockerProbe, NetworkMode,
    NetworkPosture, ProxyNetwork,
};
pub use controls::EnforcedControls;
pub use detect::{detect_test_command, DetectedCommand, Detection};
pub use local::LocalProcessBackend;
pub use packages::PackageAccess;
pub use pool::{PoolConfig, PoolKey, PoolMember, PoolStats, SandboxPool};
pub use sandbox::{
    ExecOutcome, ExecRequest, ExecStatus, Lifecycle, ResourceLimits, SandboxBackend, SandboxError,
    SandboxInstance, SandboxSpec,
};
pub use secrets::{NodeClock, SecretRedeemer, SecretsClient, SystemNodeClock};

/// Pick the strongest backend this host can actually provide.
///
/// Order is strongest-first and the fallback is **opt-in**: if no container runtime answers, this
/// returns the error rather than quietly running jobs on the host. §14.1 calls that fallback "a full
/// remote-code-execution and credential-exfiltration hole", so silently taking it — the single most
/// tempting convenience in this whole crate — is the one thing the API makes impossible.
pub async fn detect_backend(
    config: ContainerConfig,
) -> Result<std::sync::Arc<dyn SandboxBackend>, SandboxError> {
    let backend = ContainerBackend::detect(config).await?;
    Ok(std::sync::Arc::new(backend))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn there_is_no_silent_fallback_to_the_host() {
        // On a host with no reachable runtime the answer is an error, not a weaker sandbox. A caller
        // who wants the local backend has to name `LocalProcessBackend::new_for_development_only`.
        let config = ContainerConfig { runtime: "not-a-real-runtime-binary".into(), ..Default::default() };
        assert!(matches!(detect_backend(config).await, Err(SandboxError::Unavailable(_))));
    }

    #[test]
    fn no_backend_in_m1_admits_untrusted_work() {
        // The M1 conformance gap, asserted rather than documented (D§7.2, D§13).
        assert!(!LocalProcessBackend::new_for_development_only().capabilities().admits_untrusted());
        let container = ContainerBackend::from_probe(
            ContainerConfig::default(),
            DockerProbe {
                cli_present: true,
                daemon_reachable: true,
                server_os: Some("linux".into()),
                seccomp_profile: Some("builtin/default".into()),
                memory_limit: true,
                pids_limit: true,
                cpu_cfs_quota: true,
                ..Default::default()
            },
        );
        assert!(!container.capabilities().admits_untrusted());
        assert!(container.capabilities().egress_deny, "but it does enforce what it claims");
    }
}
