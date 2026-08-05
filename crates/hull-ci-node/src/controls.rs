//! What a backend actually enforces, clause by clause.
//!
//! `BackendCapabilities` (in `hull-ci-proto`) is the *wire* answer — four booleans the scheduler acts
//! on. [`EnforcedControls`] is the node-local long form: one flag per §14 requirement, so that the
//! wire answer is **derived** from enforcement facts instead of asserted by hand. That derivation is
//! the whole point. Design D§7.2: "A backend that cannot enforce §14.3 egress-deny reports so, and the
//! scheduler refuses to place untrusted work on it — the conformance gap is a property the code knows
//! about, not a comment in a doc."
//!
//! The rule for every field here: **set it `true` only if this process, on this host, with this
//! configuration, actually causes the control to be applied.** A flag that is optimistic about the
//! host is worse than a flag that is missing, because the scheduler will believe it.

use hull_ci_proto::BackendCapabilities;

/// Per-clause enforcement facts for one backend on one host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnforcedControls {
    // §14.1 — isolation boundary
    /// One job per sandbox, sandbox destroyed afterwards.
    pub single_use: bool,
    /// A kernel or hardware boundary between the job and the host kernel (microVM / gVisor). A shared
    /// host kernel is **not** this, however locked down the container is (D§7.2).
    pub kernel_isolation: bool,

    // §14.2 — credentials & environment
    /// The job environment is built from an allowlist rather than inherited.
    pub env_allowlist: bool,
    /// Cloud metadata endpoints unreachable from the sandbox.
    pub metadata_blackhole: bool,

    // §14.3 — network
    /// Default-deny egress from the sandbox.
    pub egress_deny: bool,
    /// No inbound network reaches the sandbox.
    pub no_inbound: bool,

    // §14.4 — privilege & resources
    pub non_root: bool,
    pub read_only_rootfs: bool,
    pub tmpfs_scratch: bool,
    pub caps_dropped: bool,
    pub no_new_privileges: bool,
    pub seccomp_default_deny: bool,
    pub cpu_limit: bool,
    pub memory_limit: bool,
    pub pid_limit: bool,
    pub disk_limit: bool,
    pub wall_clock_timeout: bool,
    pub output_cap: bool,
}

impl EnforcedControls {
    /// Enforces nothing. The honest starting point for any backend: turn flags on as you implement
    /// them, never the reverse.
    pub const NONE: EnforcedControls = EnforcedControls {
        single_use: false,
        kernel_isolation: false,
        env_allowlist: false,
        metadata_blackhole: false,
        egress_deny: false,
        no_inbound: false,
        non_root: false,
        read_only_rootfs: false,
        tmpfs_scratch: false,
        caps_dropped: false,
        no_new_privileges: false,
        seccomp_default_deny: false,
        cpu_limit: false,
        memory_limit: false,
        pid_limit: false,
        disk_limit: false,
        wall_clock_timeout: false,
        output_cap: false,
    };

    /// The wire form the scheduler consumes.
    ///
    /// `cross_tenant_safe` is deliberately tied to [`kernel_isolation`](Self::kernel_isolation) and
    /// nothing else: co-residency of two tenants is a question about the kernel boundary, and a
    /// container that has every other flag set is still a shared kernel (§14.1, D§7.2). This is why
    /// the M1 container backend can never report `admits_untrusted()`.
    pub fn to_capabilities(self) -> BackendCapabilities {
        BackendCapabilities {
            egress_deny: self.egress_deny,
            metadata_blackhole: self.metadata_blackhole,
            single_use: self.single_use,
            cross_tenant_safe: self.kernel_isolation,
        }
    }

    /// The §14 clauses this backend does **not** satisfy, as human-readable strings.
    ///
    /// Logged once at node start and attached to refusals, so an operator never has to diff a struct
    /// against the spec by eye to learn what this node is not allowed to be given.
    pub fn unmet_clauses(self) -> Vec<&'static str> {
        let checks: [(bool, &'static str); 18] = [
            (self.single_use, "§14.1 single-use sandbox, destroyed after each job"),
            (self.kernel_isolation, "§14.1 kernel/hardware isolation (microVM-class boundary)"),
            (self.env_allowlist, "§14.2 environment scrubbed to an allowlist"),
            (self.metadata_blackhole, "§14.2 cloud metadata endpoint blocked"),
            (self.egress_deny, "§14.3 default egress-deny"),
            (self.no_inbound, "§14.3 no inbound network to the sandbox"),
            (self.non_root, "§14.4 non-root user"),
            (self.read_only_rootfs, "§14.4 read-only root filesystem"),
            (self.tmpfs_scratch, "§14.4 writable tmpfs scratch that dies with the job"),
            (self.caps_dropped, "§14.4 all capabilities dropped"),
            (self.no_new_privileges, "§14.4 no-new-privileges"),
            (self.seccomp_default_deny, "§14.4 default-deny seccomp profile"),
            (self.cpu_limit, "§14.4 CPU limit"),
            (self.memory_limit, "§14.4 memory limit"),
            (self.pid_limit, "§14.4 PID limit"),
            (self.disk_limit, "§14.4 disk limit"),
            (self.wall_clock_timeout, "§14.4 wall-clock timeout"),
            (self.output_cap, "§14.4 captured output cap"),
        ];
        checks.iter().filter(|(ok, _)| !ok).map(|(_, name)| *name).collect()
    }

    /// Whether every §14 clause is enforced. Nothing in M1 answers `true`; it exists so the M3
    /// Firecracker backend has an assertion to aim at rather than a prose target.
    pub fn fully_conforming(self) -> bool {
        self.unmet_clauses().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_enforced_admits_nothing() {
        let caps = EnforcedControls::NONE.to_capabilities();
        assert!(!caps.admits_untrusted());
        assert_eq!(EnforcedControls::NONE.unmet_clauses().len(), 18);
    }

    #[test]
    fn a_shared_kernel_is_never_cross_tenant_safe() {
        // The regression test for the tempting mistake: a container with every hardening flag set is
        // still one kernel away from the other tenant (§14.1, D§7.2).
        let hardened_container = EnforcedControls {
            single_use: true,
            kernel_isolation: false,
            env_allowlist: true,
            metadata_blackhole: true,
            egress_deny: true,
            no_inbound: true,
            non_root: true,
            read_only_rootfs: true,
            tmpfs_scratch: true,
            caps_dropped: true,
            no_new_privileges: true,
            seccomp_default_deny: true,
            cpu_limit: true,
            memory_limit: true,
            pid_limit: true,
            disk_limit: true,
            wall_clock_timeout: true,
            output_cap: true,
        };
        let caps = hardened_container.to_capabilities();
        assert!(caps.egress_deny && caps.single_use && caps.metadata_blackhole);
        assert!(!caps.cross_tenant_safe);
        assert!(!caps.admits_untrusted(), "M1 is single-tenant by construction");

        let microvm = EnforcedControls { kernel_isolation: true, ..hardened_container };
        assert!(microvm.to_capabilities().admits_untrusted());
        assert!(microvm.fully_conforming());
    }

    #[test]
    fn unmet_clauses_name_what_is_missing() {
        let c = EnforcedControls { egress_deny: false, ..EnforcedControls::NONE };
        assert!(c.unmet_clauses().iter().any(|s| s.contains("§14.3 default egress-deny")));
    }
}
