//! The two contracts hull-ci speaks, in one crate so no component can drift from another.
//!
//! **Outward — Hull CI Integration Standard, contract v1** (`CI-SPEC.md`): the [`Dispatch`] Hull POSTs
//! us and the [`Verdict`] we POST back. These types are law; they change only when the spec does.
//!
//! **Inward — the control↔node protocol**: [`NodeState`], [`Assignment`], [`StepReport`]. These are
//! ours to evolve, but they live here rather than in either component so the control plane and the
//! node agent are compiled against one definition instead of two hand-synced ones.
//!
//! Nothing in this crate does I/O. It is types, parsing, and the invariants that are cheap to encode
//! in the type system — notably that a [`Verdict`] carries a [`Reason`] only when it is `errored`.

use serde::{Deserialize, Serialize};

/// The contract version we speak, sent by Hull as `X-Hull-CI-Version` (spec §13).
pub const CONTRACT_VERSION: &str = "1";

/// Header carrying the shared secret on both dispatch and callback (spec §8).
pub const SECRET_HEADER: &str = "X-Hull-CI-Secret";

/// Header carrying the contract version on a dispatch (spec §5).
pub const VERSION_HEADER: &str = "X-Hull-CI-Version";

// ── Outward contract: Hull → us (spec §5) ────────────────────────────────────────────────────────

/// The job Hull POSTs to our CI endpoint.
///
/// **Forward-compatible by construction** (spec §5: "ignore unknown fields"). Serde drops unknown
/// keys by default and we deliberately do *not* set `deny_unknown_fields` — Hull MAY add fields in
/// later revisions without bumping the version header, and rejecting those would be non-conforming.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dispatch {
    /// `tenant/repo`. Routing and logging only.
    pub repo: String,
    /// keel change id — the revision under test.
    pub change: String,
    /// keel tree content-address. The cache key for a verdict, and what [`source_url`] resolves to.
    ///
    /// [`source_url`]: Dispatch::source_url
    pub tree_id: String,
    /// Human summary of the change. Display only — untrusted text, never interpolated into a command.
    #[serde(default)]
    pub intent: String,
    /// Actor handle. Display only, and the input to author-class derivation (design D§1).
    #[serde(default)]
    pub author: String,
    /// GET this for the change's tree as a `tar` archive. The *only* fetch path (spec §6) — there is
    /// no git clone in contract v1. **Opaque**: never construct or rewrite it.
    pub source_url: String,
    /// Where the verdict goes (spec §7). **Opaque**: use verbatim, never construct it.
    pub callback_url: String,

    /// Reserved, not yet in the spec (design G2): a short-lived bearer scoped to this `tree_id`.
    /// Consumed by the fetch broker only and MUST NOT enter a sandbox (spec §14.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetch_token: Option<String>,
}

impl Dispatch {
    /// The tenant half of `repo` (`tenant/repo`), or the whole string if it is unqualified.
    ///
    /// The tenant is the hard isolation boundary for every shared surface (design D§1), so this is
    /// load-bearing rather than cosmetic: cache scopes, blob dedup, log keys, and fair-share
    /// accounting all key off it.
    pub fn tenant(&self) -> &str {
        self.repo.split('/').next().unwrap_or(&self.repo)
    }

    /// The repo half of `repo` (`tenant/repo`), or `""` if unqualified.
    pub fn repo_name(&self) -> &str {
        self.repo.split_once('/').map(|(_, r)| r).unwrap_or("")
    }

    /// Reject a dispatch that is structurally unusable before any work is queued.
    ///
    /// Deliberately minimal: the spec tells us to tolerate anything we don't recognise, so this
    /// checks only the fields without which there is no job — not "fields we would have preferred."
    pub fn validate(&self) -> Result<(), ContractError> {
        for (name, value) in [
            ("repo", &self.repo),
            ("change", &self.change),
            ("tree_id", &self.tree_id),
            ("source_url", &self.source_url),
            ("callback_url", &self.callback_url),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::MissingField(name));
            }
        }
        Ok(())
    }
}

// ── Outward contract: us → Hull (spec §7) ────────────────────────────────────────────────────────

/// The verdict. `green`/`red` are statements about the code; `errored` is a statement about us.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Checks passed. Hull memoizes by `tree_id` and sets keel verification green.
    Green,
    /// Checks failed. Memoized, verification red.
    Red,
    /// We could not produce a verdict. **Not** memoized — an outage must never poison a tree.
    Errored,
}

impl Status {
    /// Whether Hull will memoize this verdict (spec §7). Mirrored in our own step memo (design D§6.1).
    pub fn is_memoizable(self) -> bool {
        matches!(self, Status::Green | Status::Red)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Status::Green => "green",
            Status::Red => "red",
            Status::Errored => "errored",
        }
    }
}

/// Why an `errored` verdict errored (design G4 — proposed as an additive spec field).
///
/// This exists because spec §9.1 gives `errored` a *specific* meaning on an independence tree
/// ("no pre-existing test exercises this change" → `self_attested`) that Hull today cannot
/// distinguish from an infrastructure failure. Until Hull reads it, sending it is harmless: §5's
/// forward-compatibility rule means unknown fields are ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// No pipeline and nothing detectable to run. Hull SHOULD read this as `self_attested`.
    NoTests,
    /// A step, the job, or the fetch exceeded its wall clock.
    Timeout,
    /// Node loss, sandbox failure, extraction failure — our fault.
    Infra,
    /// The tenant's plan quota kept the step queued past the queue-wait timeout.
    Capacity,
}

/// What we POST to `callback_url`.
///
/// Construct with [`Verdict::green`] / [`Verdict::red`] / [`Verdict::errored`] rather than by struct
/// literal: those enforce that `reason` accompanies exactly the `errored` case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub status: Status,
    /// One-line human summary. **Built from untrusted job output** (spec §14.5) — always run it
    /// through [`sanitize_summary`] rather than formatting job bytes in directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Additive (design G4): link to a human-readable log view. Display only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details_url: Option<String>,
    /// Additive (design G4): present only when `status` is `errored`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
}

impl Verdict {
    pub fn green(summary: impl Into<String>) -> Self {
        Verdict { status: Status::Green, summary: Some(summary.into()), details_url: None, reason: None }
    }

    pub fn red(summary: impl Into<String>) -> Self {
        Verdict { status: Status::Red, summary: Some(summary.into()), details_url: None, reason: None }
    }

    /// An `errored` verdict always carries *why* — that is the whole point of the field (G4).
    pub fn errored(reason: Reason, summary: impl Into<String>) -> Self {
        Verdict {
            status: Status::Errored,
            summary: Some(summary.into()),
            details_url: None,
            reason: Some(reason),
        }
    }

    pub fn with_details_url(mut self, url: impl Into<String>) -> Self {
        self.details_url = Some(url.into());
        self
    }
}

/// Make untrusted job output safe to put in a one-line `summary` (spec §14.5).
///
/// Job output is attacker-controlled: it may contain ANSI escapes, control characters, terminal
/// manipulation, bidirectional-override characters, or megabytes of padding meant to push real
/// content out of view. We strip rather than escape, because the destination is a plain one-line
/// label in Hull's UI, and cap the length so a job cannot flood it.
pub fn sanitize_summary(raw: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(raw.len().min(max_chars));
    let mut chars = raw.chars().peekable();
    let mut last_was_space = false;

    while let Some(c) = chars.next() {
        // Drop ANSI/OSC escape sequences wholesale rather than letting the introducer through.
        if c == '\u{1b}' {
            if matches!(chars.peek(), Some('[')) {
                chars.next();
                for t in chars.by_ref() {
                    if t.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        // Control characters (including newlines and NUL) collapse to a single space: a summary is
        // one line by definition, and embedded newlines are how output smuggles fake structure.
        let c = if c.is_control() { ' ' } else { c };
        // Bidi overrides and other invisible formatting can reorder displayed text misleadingly.
        if matches!(c, '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
            continue;
        }
        if c == ' ' {
            if last_was_space {
                continue;
            }
            last_was_space = true;
        } else {
            last_was_space = false;
        }
        if out.chars().count() >= max_chars {
            break;
        }
        out.push(c);
    }
    out.trim().to_string()
}

/// The default cap for a summary line (design D§6.6).
pub const SUMMARY_MAX_CHARS: usize = 200;

// ── Inward: tenancy and trust axes (design D§1) ──────────────────────────────────────────────────

/// How strong the box is. A property of the **sandbox**, set by platform policy — never by a pipeline.
///
/// On any multi-tenant instance this is always [`IsolationTier::MicroVm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationTier {
    /// Firecracker microVM. The default, and the whole multi-tenant fleet.
    MicroVm,
    /// Locked-down OCI container. Single-tenant operators only, plus the M1 bring-up scaffold.
    Container,
}

/// Whose authority the code carries. A property of the **actor**, derived from the dispatch's
/// `author` and repo membership — never assertable by a pipeline (design D§1).
///
/// This is a *separate axis* from [`IsolationTier`], and keeping them separate is load-bearing: a
/// member's job on the hosted fleet runs in a microVM **and** may write the shared cache and receive
/// tenant secrets. Collapsing the two axes (as an earlier design draft did) makes both unreachable
/// on the exact configuration the product ships as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorClass {
    /// A principal of the tenant with write access to the repo. May write the shared cache scope and
    /// receive tenant-declared secrets.
    Member,
    /// A fork PR or unknown contributor. Reads the shared cache, writes only a throwaway layer, and
    /// receives no secrets — checked at the secret broker, which never consults the pipeline.
    Outsider,
}

impl AuthorClass {
    /// Whether a job of this class may write its scope's shared cache layer (design D§6.3).
    pub fn may_write_shared_cache(self) -> bool {
        matches!(self, AuthorClass::Member)
    }

    /// Whether the secret broker may mint a capability for a job of this class (design D§7.4).
    pub fn may_receive_secrets(self) -> bool {
        matches!(self, AuthorClass::Member)
    }
}

// ── Inward: control ↔ node protocol ──────────────────────────────────────────────────────────────

/// What a node advertises on each heartbeat (design D§5.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeState {
    pub node_id: String,
    pub tier: IsolationTier,
    pub labels: Vec<String>,
    pub slots_total: u32,
    pub slots_free: u32,
    /// Trees this node already holds extracted, for `tree_affinity` scoring (design D§5.2).
    #[serde(default)]
    pub warm_trees: Vec<String>,
    /// Which §14 controls this backend can actually enforce. The scheduler refuses to place
    /// untrusted work on a backend that reports `egress_deny: false` — the M1 conformance gap is a
    /// property the code knows about rather than a note in a document (design D§7.2).
    pub capabilities: BackendCapabilities,
}

/// What a sandbox backend can enforce. Reported by the node, honoured by the scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCapabilities {
    /// Default-deny egress in the sandbox's own network namespace (spec §14.3).
    pub egress_deny: bool,
    /// Cloud metadata endpoints blackholed (spec §14.2).
    pub metadata_blackhole: bool,
    /// One job per sandbox, destroyed afterward (spec §14.1).
    pub single_use: bool,
    /// Hardware/kernel isolation strong enough to place two tenants' jobs on one host (spec §14.1).
    pub cross_tenant_safe: bool,
}

impl BackendCapabilities {
    /// Whether this backend may run work from an untrusted author on a shared fleet.
    ///
    /// The M1 container scaffold answers `false`, which is exactly why M1 is single-tenant.
    pub fn admits_untrusted(self) -> bool {
        self.egress_deny && self.metadata_blackhole && self.single_use && self.cross_tenant_safe
    }
}

/// A leased unit of work, control → node (design D§5.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assignment {
    pub job_id: String,
    pub step_id: String,
    pub step_name: String,
    /// Verified tree to materialize the workspace from.
    pub tree_id: String,
    /// argv, executed inside the sandbox only — never interpolated into a host command line.
    pub argv: Vec<String>,
    pub image: String,
    pub tier: IsolationTier,
    pub author_class: AuthorClass,
    pub timeout_secs: u64,
    /// Seconds until the lease expires unless renewed.
    pub lease_secs: u64,
}

/// A node's terminal report for one assignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepReport {
    pub job_id: String,
    pub step_id: String,
    pub outcome: StepOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Object-store key of the captured log, `tenant/repo/tree_id/step/attempt` (design D§11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_key: Option<String>,
    /// Already sanitized by the node; the aggregator sanitizes again on the way out (defence in depth).
    #[serde(default)]
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepOutcome {
    Passed,
    Failed,
    /// Infrastructure problem. Folds to `errored`, never `red` (spec §7).
    Errored,
}

// ── Errors ───────────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ContractError {
    #[error("dispatch is missing required field `{0}`")]
    MissingField(&'static str),
    #[error("unsupported contract version `{0}` (this runner speaks {CONTRACT_VERSION})")]
    UnsupportedVersion(String),
}

/// Accept a dispatch's `X-Hull-CI-Version`.
///
/// Additive revisions do not bump the header (spec §13), so an exact match is the only thing we can
/// meaningfully check — and an unknown *major* must be refused rather than guessed at, because by
/// definition we do not know what it renamed.
pub fn check_version(header: Option<&str>) -> Result<(), ContractError> {
    match header {
        // Absent is tolerated: the spec does not make the header mandatory on the receiving side.
        None => Ok(()),
        Some(v) if v == CONTRACT_VERSION => Ok(()),
        Some(v) => Err(ContractError::UnsupportedVersion(v.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_ignores_unknown_fields() {
        // Spec §5: Hull MAY add fields without bumping the version; rejecting them is non-conforming.
        let json = r#"{
            "repo": "tankrap/hull", "change": "21ea", "tree_id": "f7a2",
            "intent": "fix", "author": "justin",
            "source_url": "https://h/api/repos/tankrap/hull/tree/f7a2/tar",
            "callback_url": "https://h/api/repos/tankrap/hull/change/21ea/ci-result",
            "some_future_field": {"nested": true}
        }"#;
        let d: Dispatch = serde_json::from_str(json).expect("unknown fields must not fail parsing");
        assert_eq!(d.tenant(), "tankrap");
        assert_eq!(d.repo_name(), "hull");
        assert!(d.validate().is_ok());
    }

    #[test]
    fn dispatch_rejects_missing_essentials() {
        let d = Dispatch {
            repo: "t/r".into(),
            change: "c".into(),
            tree_id: "  ".into(),
            intent: String::new(),
            author: String::new(),
            source_url: "u".into(),
            callback_url: "c".into(),
            fetch_token: None,
        };
        assert_eq!(d.validate(), Err(ContractError::MissingField("tree_id")));
    }

    #[test]
    fn only_green_and_red_are_memoizable() {
        assert!(Status::Green.is_memoizable());
        assert!(Status::Red.is_memoizable());
        assert!(!Status::Errored.is_memoizable(), "an outage must never poison a tree (spec §7)");
    }

    #[test]
    fn errored_verdict_always_carries_a_reason() {
        let v = Verdict::errored(Reason::NoTests, "no test command detected");
        assert_eq!(v.reason, Some(Reason::NoTests));
        assert!(Verdict::green("ok").reason.is_none());
        assert!(Verdict::red("2 failed").reason.is_none());
    }

    #[test]
    fn verdict_serializes_to_the_spec_shape() {
        let json = serde_json::to_value(Verdict::green("42 tests, 0 failed, in 8.1s")).unwrap();
        assert_eq!(json["status"], "green");
        assert_eq!(json["summary"], "42 tests, 0 failed, in 8.1s");
        // Additive fields stay absent unless set, so a stock Hull sees exactly the v1 shape.
        assert!(json.get("reason").is_none());
        assert!(json.get("details_url").is_none());
    }

    #[test]
    fn sanitize_strips_ansi_control_and_bidi() {
        let hostile = "ok \u{1b}[31mRED\u{1b}[0m\nline2\u{0}\u{202e}reversed";
        let clean = sanitize_summary(hostile, SUMMARY_MAX_CHARS);
        assert!(!clean.contains('\u{1b}'), "ANSI introducer must be gone");
        assert!(!clean.contains('\n'), "a summary is one line");
        assert!(!clean.contains('\u{0}'));
        assert!(!clean.contains('\u{202e}'), "bidi override can misrepresent the text");
        assert_eq!(clean, "ok RED line2 reversed");
    }

    #[test]
    fn sanitize_caps_length_so_a_job_cannot_flood_the_ui() {
        let flood = "A".repeat(10_000);
        assert_eq!(sanitize_summary(&flood, SUMMARY_MAX_CHARS).chars().count(), SUMMARY_MAX_CHARS);
    }

    #[test]
    fn version_header_gate() {
        assert!(check_version(Some("1")).is_ok());
        assert!(check_version(None).is_ok());
        assert!(matches!(check_version(Some("2")), Err(ContractError::UnsupportedVersion(_))));
    }

    #[test]
    fn author_class_is_what_gates_cache_and_secrets_not_tier() {
        // The regression test for the axis collision (design D§1): a member is privileged
        // regardless of running in the strongest sandbox we have.
        assert!(AuthorClass::Member.may_write_shared_cache());
        assert!(AuthorClass::Member.may_receive_secrets());
        assert!(!AuthorClass::Outsider.may_write_shared_cache());
        assert!(!AuthorClass::Outsider.may_receive_secrets());
    }

    #[test]
    fn m1_container_backend_does_not_admit_untrusted_work() {
        let m1 = BackendCapabilities {
            egress_deny: false,
            metadata_blackhole: false,
            single_use: true,
            cross_tenant_safe: false,
        };
        assert!(!m1.admits_untrusted(), "M1 is single-tenant by construction, not by convention");

        let fleet = BackendCapabilities {
            egress_deny: true,
            metadata_blackhole: true,
            single_use: true,
            cross_tenant_safe: true,
        };
        assert!(fleet.admits_untrusted());
    }
}
