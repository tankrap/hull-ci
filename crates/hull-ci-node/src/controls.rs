//! What a backend actually enforces, clause by clause.
//!
//! [`EnforcedControls`] is where the §14 answer is **measured**: one flag per requirement, each set
//! from a live probe of this host plus this configuration. `BackendCapabilities` (in `hull-ci-proto`)
//! is where the same answer is **claimed** — the value that crosses to the scheduler, which believes
//! it. The two are separate types because only one of them crosses a trust boundary; they carry the
//! same eighteen clauses because a claim that carries fewer clauses than the gate needs is how the
//! gate ends up reading four of them. See `BackendCapabilities::admits_untrusted`.
//!
//! Design D§7.2: "A backend that cannot enforce §14.3 egress-deny reports so, and the scheduler
//! refuses to place untrusted work on it — the conformance gap is a property the code knows about,
//! not a comment in a doc."
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

    /// The wire form the scheduler consumes — **every clause, not a summary**.
    ///
    /// Written out field by field with no `..` fallback, so a clause added to either type is a
    /// compile error here rather than a silent `false` on the wire. The mapping is one-to-one except
    /// for the name: `cross_tenant_safe` *is* [`kernel_isolation`](Self::kernel_isolation), because
    /// co-residency of two tenants is a question about the kernel boundary and nothing else — a
    /// container with every other flag set is still a shared kernel (§14.1, D§7.2). That is why the
    /// M1 container backend can never report `admits_untrusted()`.
    pub fn to_capabilities(self) -> BackendCapabilities {
        BackendCapabilities {
            single_use: self.single_use,
            cross_tenant_safe: self.kernel_isolation,
            env_allowlist: self.env_allowlist,
            metadata_blackhole: self.metadata_blackhole,
            egress_deny: self.egress_deny,
            no_inbound: self.no_inbound,
            non_root: self.non_root,
            read_only_rootfs: self.read_only_rootfs,
            tmpfs_scratch: self.tmpfs_scratch,
            caps_dropped: self.caps_dropped,
            no_new_privileges: self.no_new_privileges,
            seccomp_default_deny: self.seccomp_default_deny,
            cpu_limit: self.cpu_limit,
            memory_limit: self.memory_limit,
            pid_limit: self.pid_limit,
            disk_limit: self.disk_limit,
            wall_clock_timeout: self.wall_clock_timeout,
            output_cap: self.output_cap,
        }
    }

    /// The §14 clauses this backend does **not** satisfy, as human-readable strings.
    ///
    /// Logged once at node start and attached to refusals, so an operator never has to diff a struct
    /// against the spec by eye to learn what this node is not allowed to be given.
    ///
    /// Delegates to the wire type rather than keeping a second list: two copies of §14 in one
    /// workspace is two copies that can disagree about what the spec says.
    pub fn unmet_clauses(self) -> Vec<&'static str> {
        self.to_capabilities().unmet_clauses()
    }

    /// Whether every §14 clause is enforced. Nothing in M1 answers `true`; it exists so the M3
    /// Firecracker backend has an assertion to aim at rather than a prose target.
    ///
    /// Strictly stronger than `admits_untrusted()`, and deliberately not the same question — see
    /// `hull_ci_proto::Clause::required_for_untrusted`.
    pub fn fully_conforming(self) -> bool {
        self.to_capabilities().fully_conforming()
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

    /// Every field, as an `EnforcedControls` with only that one turned on.
    fn one_control_at_a_time() -> Vec<(&'static str, EnforcedControls)> {
        let n = EnforcedControls::NONE;
        vec![
            ("single_use", EnforcedControls { single_use: true, ..n }),
            ("kernel_isolation", EnforcedControls { kernel_isolation: true, ..n }),
            ("env_allowlist", EnforcedControls { env_allowlist: true, ..n }),
            ("metadata_blackhole", EnforcedControls { metadata_blackhole: true, ..n }),
            ("egress_deny", EnforcedControls { egress_deny: true, ..n }),
            ("no_inbound", EnforcedControls { no_inbound: true, ..n }),
            ("non_root", EnforcedControls { non_root: true, ..n }),
            ("read_only_rootfs", EnforcedControls { read_only_rootfs: true, ..n }),
            ("tmpfs_scratch", EnforcedControls { tmpfs_scratch: true, ..n }),
            ("caps_dropped", EnforcedControls { caps_dropped: true, ..n }),
            ("no_new_privileges", EnforcedControls { no_new_privileges: true, ..n }),
            ("seccomp_default_deny", EnforcedControls { seccomp_default_deny: true, ..n }),
            ("cpu_limit", EnforcedControls { cpu_limit: true, ..n }),
            ("memory_limit", EnforcedControls { memory_limit: true, ..n }),
            ("pid_limit", EnforcedControls { pid_limit: true, ..n }),
            ("disk_limit", EnforcedControls { disk_limit: true, ..n }),
            ("wall_clock_timeout", EnforcedControls { wall_clock_timeout: true, ..n }),
            ("output_cap", EnforcedControls { output_cap: true, ..n }),
        ]
    }

    #[test]
    fn nothing_measured_here_is_dropped_on_the_way_to_the_wire() {
        // What went wrong before: the wire form carried four of the eighteen clauses, so
        // `admits_untrusted()` could only ever weigh four of them however carefully this struct was
        // filled in. The projection is now total, and this is what keeps it total — a field added to
        // `EnforcedControls` and forgotten in `to_capabilities` turns exactly one clause into a
        // permanent `false`, which no compiler error would catch.
        assert_eq!(one_control_at_a_time().len(), hull_ci_proto::Clause::ALL.len());
        for (name, controls) in one_control_at_a_time() {
            let missing = controls.unmet_clauses();
            assert_eq!(
                missing.len(),
                hull_ci_proto::Clause::ALL.len() - 1,
                "`{name}` did not reach the wire: {missing:?}"
            );
        }
    }
}
