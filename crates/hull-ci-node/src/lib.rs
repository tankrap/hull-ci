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
//! - [`local`] — a host subprocess for development. Reports ~nothing and is documented
//!   untrusted-input-forbidden.
//! - [`capture`] — the §14.4 output cap (50 MB / 500k lines, truncate-with-marker, keep the tail).
//! - [`detect`] — M1 test-command autodetection, and the `no_tests`-vs-infra distinction §9.1 rests on.
//! - [`agent`] — [`NodeAgent`]: state, heartbeats, one assignment → one [`StepReport`].
//! - [`env`] — the allowlist-built job environment (§14.2).
//!
//! # What this node cannot do, by construction
//!
//! Design D§7.1: the agent "holds **no tenant credentials and no CI shared secret** — neither the
//! fetch path nor the callback path goes through it (§14.2), and there is nothing in its memory a
//! successful sandbox escape would want except the ability to be a node." That is a property of what
//! is *absent* here: there is no HTTP client, no secret type, no `source_url`, and no `callback_url`
//! anywhere in this crate. [`NodeAgent::run_assignment`] takes a workspace path that somebody else
//! fetched and verified (D§6.2, "materialize, don't fetch").
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
//! | §14 control | Container backend, daemon up | Container backend, no daemon | Local process |
//! |---|---|---|---|
//! | 14.1 single-use | yes | n/a (refuses to construct) | **no** — no rootfs is destroyed |
//! | 14.1 kernel isolation → `cross_tenant_safe` | **no** — shared kernel, always | n/a | **no** |
//! | 14.2 env allowlist | yes | n/a | yes |
//! | 14.2 metadata blackhole | yes, via `--network none` | n/a | **no** |
//! | 14.3 egress-deny / no inbound | yes, via `--network none` | n/a | **no** |
//! | 14.4 non-root, ro-rootfs, tmpfs, caps, NNP, seccomp | yes | n/a | **no** |
//! | 14.4 cpu/mem/pid limits | as the daemon reports them | n/a | **no** |
//! | 14.4 disk limit | **no** — not attempted, so not claimed | n/a | **no** |
//! | 14.4 wall clock + output cap | yes | n/a | yes |
//!
//! `cross_tenant_safe` is `false` on every backend in this crate, so `admits_untrusted()` is `false`
//! on every backend in this crate. That is not an oversight — it is design D§13's M1 statement
//! ("**M1 is single-tenant, trusted-input only and MUST NOT take untrusted or multi-tenant input**")
//! expressed as a value the scheduler reads, rather than as a sentence in a document.

pub mod agent;
pub mod capture;
pub mod container;
pub mod controls;
pub mod detect;
pub mod env;
pub mod local;
pub mod process;
pub mod sandbox;

pub use agent::{ControlLink, LinkError, NodeAgent, NodeConfig, NodeErrorKind};
pub use capture::{CapturedOutput, OutputCapture, OutputCaps, DEFAULT_MAX_BYTES, DEFAULT_MAX_LINES};
pub use container::{ContainerBackend, ContainerConfig, DockerProbe, NetworkMode};
pub use controls::EnforcedControls;
pub use detect::{detect_test_command, DetectedCommand, Detection};
pub use local::LocalProcessBackend;
pub use sandbox::{
    ExecOutcome, ExecRequest, ExecStatus, Lifecycle, ResourceLimits, SandboxBackend, SandboxError,
    SandboxInstance, SandboxSpec,
};

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
