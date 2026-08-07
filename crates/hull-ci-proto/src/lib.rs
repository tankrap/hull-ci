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

use std::borrow::Cow;

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
    /// The tenant half of `repo` (`tenant/repo`), or the whole string if it is unqualified —
    /// **normalized**, so one tenant has exactly one spelling.
    ///
    /// The tenant is the hard isolation boundary for every shared surface (design D§1), so this is
    /// load-bearing rather than cosmetic: cache scopes, blob dedup, log keys, and fair-share
    /// accounting all key off it. That claim used to be a comment on a `split('/').next()`, and an
    /// isolation audit measured what the gap cost: one tenant under four spellings (`acme`,
    /// `acme `, `Acme`, `/acme`) opened four independent WFQ flows and four independent quota
    /// buckets, three of which fell through to the more generous default plan — 17 concurrent grants
    /// against a plan cap of 2. Nothing about that needed an attacker; it needed a `repo` string
    /// written two ways.
    ///
    /// So the normalization happens here, at the one accessor every tenant-scoped decision goes
    /// through, and again in [`canonicalize`](Self::canonicalize) at the door. Both, not either:
    /// this one is total and cannot fail, which is what makes every call site downstream able to
    /// treat the answer as *the* tenant.
    ///
    /// # Where the line is drawn
    ///
    /// * **Whitespace is stripped**, around the string and around the segment. Every identifier
    ///   grammar in this system already forbids it outright ([`check_path_segment`],
    ///   `hull_ci_plan::validate`), so padding is transport sloppiness rather than a name.
    /// * **Case is not folded**, and `Acme` is therefore a different tenant from `acme`. This is the
    ///   one place where the split above is the *cheaper* mistake, because folding decides that two
    ///   names Hull holds as distinct accounts are one principal — and the trust lookup, the
    ///   secrets, the shared-cache write bit and the memo all key off the answer. The full argument,
    ///   including why the "storage already merges them" reasoning does not apply to a store that
    ///   hashes the tenant, is on [`tenant_of`].
    /// * **Nothing else is rewritten.** Spec §5 says to tolerate what we do not recognise, and a
    ///   tenant name we find unusual is still Hull's name for a real customer.
    ///
    /// # The one input this cannot answer for
    ///
    /// If the first segment is empty — `"/widget"`, `"//x"`, `"/"` — there is no tenant to return
    /// and this answers with the whole trimmed `repo` instead. Deliberately *not* `""`: the empty
    /// string is an ordinary, and therefore *shared*, key in the step memo, in `FairShare::plans`
    /// and in the trusted-tenant set, so returning it hands several unrelated dispatches one
    /// namespace. The whole repo string cannot collide with any legal tenant, because a legal tenant
    /// contains no `/`. [`canonicalize`](Self::canonicalize) refuses those repos outright, so on any
    /// dispatch that reached a job this branch is unreachable; it exists for the [`Dispatch`] built
    /// in code that never went through the door.
    pub fn tenant(&self) -> Cow<'_, str> {
        tenant_of(&self.repo)
    }

    /// The repo half of `repo` (`tenant/repo`), or `""` if unqualified.
    ///
    /// Case is not folded here — as it is not in [`tenant`](Self::tenant), for a different reason.
    /// The repo half is not an isolation boundary at all; it is a name Hull displays and puts in
    /// URLs, and `acme/Widget` costing a duplicate job is a smaller wrong than renaming somebody's
    /// repository.
    pub fn repo_name(&self) -> &str {
        self.repo.trim().split_once('/').map(|(_, r)| r.trim()).unwrap_or("")
    }

    /// Reject a dispatch that is structurally unusable before any work is queued.
    ///
    /// Deliberately minimal about *fields*: the spec tells us to tolerate anything we don't
    /// recognise, so this checks only the ones without which there is no job — not "fields we would
    /// have preferred." What it is **not** minimal about is `repo`, because `repo` is where the
    /// tenant comes from and the tenant is the boundary; see [`canonical_repo`] for that rule and
    /// for what it refuses.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.required_fields()?;
        canonical_repo(&self.repo).map(|_| ())
    }

    /// [`validate`](Self::validate), and then write the canonical `repo` back.
    ///
    /// This is what ingest calls, and the reason it takes `&mut self`: the tenant is only one string
    /// if somebody stores the one string. `repo` is read again downstream — it is half the
    /// idempotency key of spec §9 (`Job::key`), it travels on the `Assignment`, and it is the prefix
    /// of every log object (D§11) — and each of those readers splitting and folding it for
    /// themselves is how the four spellings of the audit became four tenants in the first place.
    ///
    /// Normalizing at the door also keeps the *rejection* at the door, which matters more than it
    /// looks: a `repo` we would refuse is refused with a 400 that names the field, before a job
    /// exists, rather than surfacing an hour later as a step whose log key silently went nowhere.
    pub fn canonicalize(&mut self) -> Result<(), ContractError> {
        self.required_fields()?;
        self.repo = canonical_repo(&self.repo)?;
        Ok(())
    }

    /// The fields without which there is no job (spec §5). Shared by `validate` and `canonicalize`
    /// so the two cannot come to different conclusions about the same dispatch.
    fn required_fields(&self) -> Result<(), ContractError> {
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

/// The tenant a `tenant/repo` string names, normalized — [`Dispatch::tenant`]'s rule, as a function.
///
/// A free function because the tenant is derived from `repo` in more than one component (the
/// membership lookup in `hull-ci-server` reads a bare `&str`), and every one of them writing its own
/// `split('/').next()` is exactly how one tenant became four. There is one rule and it is here; the
/// reasoning behind each part of it is on [`Dispatch::tenant`], where a reader looking for the
/// boundary will go first.
pub fn tenant_of(repo: &str) -> Cow<'_, str> {
    let repo = repo.trim();
    let first = repo.split('/').next().unwrap_or(repo).trim();
    if first.is_empty() {
        // No tenant, and no invented one either — see `Dispatch::tenant`.
        return Cow::Borrowed(repo);
    }
    // Case is *not* folded, and that is the one deliberate asymmetry in this function.
    //
    // Folding looks like the tidier answer — one tenant, one spelling — but it decides that `ACME`
    // and `acme` name the same principal, and nothing upstream gives us the right to decide that:
    // Hull normalizes tenant names nowhere, so it can hold both as distinct accounts. Folding then
    // hands the second one the first one's trust (`TrustedTenants` matches on the folded form), and
    // with it the secrets, the shared-cache writes and the memo — an escalation across the boundary
    // this module exists to hold. The store does not fold either: it hashes the tenant, so folding
    // here would also make the scheduler and the content store disagree about how many tenants there
    // are.
    //
    // Leaving case alone costs a *split*: `ACME/widget` gets its own quota bucket, and a
    // `HULL_CI_TRUSTED_TENANTS=acme` does not match it, so it runs as an outsider. That is the
    // failure this direction has, and it is closed — an operator repairs it by spelling the config
    // the way Hull spells the tenant. The other direction fails open, and no config repairs it.
    Cow::Borrowed(first)
}

/// The longest `repo` we will accept, in characters.
///
/// Generous — the largest forge names in the wild are an owner of 39 plus a repo of 100 — because
/// this bound is not trying to have an opinion about names. It is here because `repo` becomes the
/// prefix of every log object and a component of a workspace path, and an unbounded string in a key
/// is an unbounded key.
pub const MAX_REPO_LEN: usize = 256;

/// `repo` (`tenant/repo`, spec §5) in its one canonical spelling, or the reason it has none.
///
/// # Normalize or refuse, and how that was decided
///
/// Two spellings of one tenant is a split boundary — separate quota buckets, separate memo
/// namespaces, a `TrustedTenants` entry that matches one of them. One spelling of two tenants is a
/// *merged* boundary, which is strictly worse. So the rule is: **normalize only what cannot be a
/// distinct name, refuse only what cannot be a name at all, and pass everything else through.**
/// Spec §5's "tolerate what you do not recognise" is the constraint that makes the third clause
/// load-bearing — a refusal here is a change that never gets verified, so it has to be earned.
///
/// Normalized: surrounding whitespace only, around the string and around each segment
/// (`tenant_of` explains why case is deliberately left alone).
///
/// Refused, each because the string cannot be used rather than because it is unusual:
///
/// * **an empty segment** — `"/widget"`, `"acme//x"`, `"acme/"`. There is no tenant in the first
///   case, and in the others there is a path component that is not a name. This is the audit's
///   `/widget`, whose tenant was the empty string.
/// * **`.` or `..` as a segment** — not names, and the only ones that *mean* something to a path
///   resolver. The step-name grammar happens to exclude `.` today, which is what has been keeping
///   `..` out of log keys; an accident of one grammar is not a control, so this says it.
/// * **whitespace, control characters and invisible formatting inside a segment** — a name that
///   cannot be seen is a name that cannot be told apart from another one, which is the whole
///   problem this function exists to solve.
/// * **`\`** — a path separator on one of the two operating systems this key may be resolved on,
///   and an escape everywhere else.
/// * **longer than [`MAX_REPO_LEN`]**.
///
/// Everything else survives, including non-ASCII letters, `.` inside a segment (`acme/my.repo`),
/// and more than two segments.
pub fn canonical_repo(repo: &str) -> Result<String, ContractError> {
    let trimmed = repo.trim();
    if trimmed.is_empty() {
        return Err(ContractError::MissingField("repo"));
    }
    if trimmed.chars().count() > MAX_REPO_LEN {
        return Err(ContractError::Malformed { field: "repo", why: "longer than 256 characters" });
    }

    let mut out = String::with_capacity(trimmed.len());
    for (i, raw) in trimmed.split('/').enumerate() {
        let segment = raw.trim();
        check_path_segment(segment).map_err(|why| ContractError::Malformed { field: "repo", why })?;
        if i > 0 {
            out.push('/');
        }
        // No case folding, in either segment: `tenant_of` explains why the tenant half must not be
        // folded, and folding the repo half would rewrite a name Hull displays.
        out.push_str(segment);
    }
    Ok(out)
}

/// One component of any path-like string we accept from the wire — a `repo` segment, a `log_key`
/// segment — or why it is not usable as one.
///
/// **One rule, one function, on purpose.** `repo` and `log_key` are the same kind of value arriving
/// from two different places (Hull and a node), they are concatenated into the same object key
/// (D§11), and a traversal that one of them refuses and the other permits is a traversal. Writing
/// the rule twice is how they would come to disagree.
///
/// An allowlist would be the stronger shape, but it would have to be an allowlist of *characters*,
/// and this string carries a customer's tenant and repository names — which we do not get to
/// restrict to ASCII on spec §5's tolerance rule. So it is a denylist of the characters that make a
/// segment mean something other than itself, which is a closed set: the ones a path resolver reads
/// (`.`, `..`, `/`, `\`, empty) and the ones a reader cannot see (control, whitespace, invisible
/// formatting). Confusable *visible* characters are out of scope here for the same reason they are
/// in [`sanitize_summary`]: they need a table and a normalization pass, and claiming otherwise
/// would be the more dangerous half-measure.
pub fn check_path_segment(segment: &str) -> Result<(), &'static str> {
    if segment.is_empty() {
        return Err("empty path segment");
    }
    if segment == "." || segment == ".." {
        return Err("`.` and `..` are not names");
    }
    if segment.chars().any(|c| c.is_whitespace() || c.is_control() || is_invisible_formatting(c)) {
        return Err("whitespace, control or invisible characters in a path segment");
    }
    if segment.contains('\\') {
        return Err("`\\` is a path separator, not a name character");
    }
    Ok(())
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        //
        // `char::is_control` is `General_Category=Cc` and **nothing else**, so it does not cover
        // U+2028 LINE SEPARATOR (Zl) or U+2029 PARAGRAPH SEPARATOR (Zp). Those are unconditional
        // forced line breaks in CSS — they break a line even under `white-space: normal` — so a job
        // that printed one put a second *visible* line into a field this function promises is one
        // line, and could render a forged `SECURITY SCAN: clean` under a real summary in the
        // operator panel. They collapse to a space with the rest.
        let c = if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') { ' ' } else { c };
        // Invisible formatting: bidi controls that reorder displayed text, and zero-width characters
        // that hide or pad it. Enumerated rather than sampled — the previous three ranges missed
        // U+061C ARABIC LETTER MARK (a bidi control), every zero-width joiner/space, the BOM, and
        // the Unicode tag block, all of which are invisible in every renderer a summary reaches.
        if is_invisible_formatting(c) {
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

/// Characters that occupy no width but change how the text around them reads.
///
/// Two families, one rule. **Bidi controls** (U+061C, the LRM/RLM pair, the embedding/override set,
/// the isolate set) reorder the glyphs on either side of them, so `0 failed` can be made to read as
/// something else without a single visible character changing. **Zero-width formatting** (the
/// joiners, the word joiner, the BOM, soft hyphen, the interlinear-annotation and Unicode tag
/// blocks) is invisible padding: it splits a word a reader scans for, and the tag block in
/// particular is a whole hidden side-channel that survives copy-paste.
///
/// Written as an explicit table because this crate has no Unicode-property dependency and should not
/// grow one for a one-line label. It is the `General_Category=Cf` set plus U+180E, which is the list
/// every renderer treats as zero-width. What it deliberately does **not** try to do is defeat
/// *homoglyphs* (Cyrillic `р` for Latin `p`) or stacked combining marks: those need a confusables
/// table and a normalization pass, they are a property of the font more than of the string, and
/// pretending a one-line sanitizer handles them would be the more dangerous claim.
fn is_invisible_formatting(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'                  // SOFT HYPHEN
        | '\u{061c}'                // ARABIC LETTER MARK — a bidi control the old ranges missed
        | '\u{180e}'                // MONGOLIAN VOWEL SEPARATOR
        | '\u{200b}'..='\u{200f}'   // ZWSP, ZWNJ, ZWJ, LRM, RLM
        | '\u{202a}'..='\u{202e}'   // bidi embedding and override
        | '\u{2060}'..='\u{2064}'   // word joiner and the invisible operators
        | '\u{2066}'..='\u{206f}'   // bidi isolates and the deprecated formatting set
        | '\u{feff}'                // BOM / zero-width no-break space
        | '\u{fff9}'..='\u{fffb}'   // interlinear annotation
        | '\u{110bd}' | '\u{110cd}' // Kaithi number signs
        | '\u{13430}'..='\u{1343f}' // Egyptian hieroglyph format controls
        | '\u{1bca0}'..='\u{1bca3}' // shorthand format controls
        | '\u{1d173}'..='\u{1d17a}' // musical format controls
        | '\u{e0001}'               // deprecated language tag
        | '\u{e0020}'..='\u{e007f}' // tag characters — an invisible channel that survives copy-paste
    )
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

/// What a sandbox backend can enforce, **one field per §14 clause**. Reported by the node, honoured
/// by the scheduler.
///
/// # Why every clause is on the wire
///
/// This carried four booleans until an isolation audit pointed out what that meant:
/// [`admits_untrusted`](Self::admits_untrusted) read four of §14's eighteen clauses, so a backend
/// with a real microVM boundary, no seccomp profile, no memory ceiling and no output cap answered
/// `true`. The gate cannot weigh a clause the wire does not carry, so the wire now carries all of
/// them and the gate is written out clause by clause.
///
/// Every field is `#[serde(default)]`, and the direction of each one is the reason that is safe:
/// they all state what the backend **does** enforce, so a field a peer omits — an older node, a
/// truncated payload, a hand-written test fixture — reads as `false`, i.e. "not enforced". A
/// capability struct can therefore only ever *understate* a backend, never flatter it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BackendCapabilities {
    // §14.1 — isolation boundary
    /// One job per sandbox, destroyed afterward (spec §14.1).
    #[serde(default)]
    pub single_use: bool,
    /// Hardware/kernel isolation strong enough to place two tenants' jobs on one host (spec §14.1).
    #[serde(default)]
    pub cross_tenant_safe: bool,

    // §14.2 — credentials & environment
    /// The job environment is built from an allowlist rather than inherited (spec §14.2).
    #[serde(default)]
    pub env_allowlist: bool,
    /// Cloud metadata endpoints blackholed (spec §14.2).
    #[serde(default)]
    pub metadata_blackhole: bool,

    // §14.3 — network
    /// Default-deny egress in the sandbox's own network namespace (spec §14.3).
    #[serde(default)]
    pub egress_deny: bool,
    /// No inbound network reaches the sandbox (spec §14.3).
    #[serde(default)]
    pub no_inbound: bool,

    // §14.4 — privilege & resources
    #[serde(default)]
    pub non_root: bool,
    #[serde(default)]
    pub read_only_rootfs: bool,
    #[serde(default)]
    pub tmpfs_scratch: bool,
    #[serde(default)]
    pub caps_dropped: bool,
    #[serde(default)]
    pub no_new_privileges: bool,
    #[serde(default)]
    pub seccomp_default_deny: bool,
    #[serde(default)]
    pub cpu_limit: bool,
    #[serde(default)]
    pub memory_limit: bool,
    #[serde(default)]
    pub pid_limit: bool,
    #[serde(default)]
    pub disk_limit: bool,
    #[serde(default)]
    pub wall_clock_timeout: bool,
    #[serde(default)]
    pub output_cap: bool,
}

/// One §14 clause, and whether admitting untrusted work may proceed without it.
///
/// A named enum rather than a list of field reads, because [`Clause::required_for_untrusted`] is an
/// **exhaustive match**: adding a clause to §14 is a compile error here until somebody decides which
/// side of the gate it falls on. That is the property the previous four-boolean gate lacked — it
/// could not fail to compile when §14 grew, so it silently kept answering about four clauses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Clause {
    SingleUse,
    KernelIsolation,
    EnvAllowlist,
    MetadataBlackhole,
    EgressDeny,
    NoInbound,
    NonRoot,
    ReadOnlyRootfs,
    TmpfsScratch,
    CapsDropped,
    NoNewPrivileges,
    SeccompDefaultDeny,
    CpuLimit,
    MemoryLimit,
    PidLimit,
    DiskLimit,
    WallClockTimeout,
    OutputCap,
}

impl Clause {
    /// Every §14 clause, in spec order. The array length is the count `unmet_clauses` asserts against.
    pub const ALL: [Clause; 18] = [
        Clause::SingleUse,
        Clause::KernelIsolation,
        Clause::EnvAllowlist,
        Clause::MetadataBlackhole,
        Clause::EgressDeny,
        Clause::NoInbound,
        Clause::NonRoot,
        Clause::ReadOnlyRootfs,
        Clause::TmpfsScratch,
        Clause::CapsDropped,
        Clause::NoNewPrivileges,
        Clause::SeccompDefaultDeny,
        Clause::CpuLimit,
        Clause::MemoryLimit,
        Clause::PidLimit,
        Clause::DiskLimit,
        Clause::WallClockTimeout,
        Clause::OutputCap,
    ];

    /// The clause in the operator's words, spec reference first.
    pub fn description(self) -> &'static str {
        match self {
            Clause::SingleUse => "§14.1 single-use sandbox, destroyed after each job",
            Clause::KernelIsolation => "§14.1 kernel/hardware isolation (microVM-class boundary)",
            Clause::EnvAllowlist => "§14.2 environment scrubbed to an allowlist",
            Clause::MetadataBlackhole => "§14.2 cloud metadata endpoint blocked",
            Clause::EgressDeny => "§14.3 default egress-deny",
            Clause::NoInbound => "§14.3 no inbound network to the sandbox",
            Clause::NonRoot => "§14.4 non-root user",
            Clause::ReadOnlyRootfs => "§14.4 read-only root filesystem",
            Clause::TmpfsScratch => "§14.4 writable tmpfs scratch that dies with the job",
            Clause::CapsDropped => "§14.4 all capabilities dropped",
            Clause::NoNewPrivileges => "§14.4 no-new-privileges",
            Clause::SeccompDefaultDeny => "§14.4 default-deny seccomp profile",
            Clause::CpuLimit => "§14.4 CPU limit",
            Clause::MemoryLimit => "§14.4 memory limit",
            Clause::PidLimit => "§14.4 PID limit",
            Clause::DiskLimit => "§14.4 disk limit",
            Clause::WallClockTimeout => "§14.4 wall-clock timeout",
            Clause::OutputCap => "§14.4 captured output cap",
        }
    }

    /// Whether [`BackendCapabilities::admits_untrusted`] refuses when this clause is unmet.
    ///
    /// # The rule, and why it is this one
    ///
    /// A clause is **required** if the harm it prevents lands *outside* the sandbox — on the
    /// platform, on the host, or on another tenant. A clause is **waivable** if the harm it prevents
    /// lands *inside* the sandbox, because the required clauses already say what that sandbox is: a
    /// kernel-isolated box, with no network, destroyed when the job ends. A job that defeats a
    /// waivable clause has won control of a box that shares nothing and does not outlive it.
    ///
    /// That rule is what keeps this gate **passable**. Requiring all eighteen would refuse a
    /// correct Firecracker backend on a host whose kernel has no seccomp, or one whose guest disk is
    /// a fixed-size block device rather than a quota'd filesystem — and a gate no correct backend can
    /// pass is a gate that gets deleted the first time it blocks a deploy. Requiring only the clauses
    /// whose absence is a real escape keeps the refusal credible.
    ///
    /// Each waiver below names the required clause that contains it. If any of those were ever
    /// downgraded to waivable, every waiver resting on it would have to be revisited — which is why
    /// the reasons are written here rather than in a design document.
    pub fn required_for_untrusted(self) -> bool {
        match self {
            // ── Required: the boundary itself ────────────────────────────────────────────────
            //
            // §14.1. Without a kernel/hardware boundary there is no isolation to reason about and
            // every waiver below loses its justification. This is the load-bearing clause.
            Clause::KernelIsolation => true,
            // §14.1. Cross-job survival is the one harm no boundary contains: job A plants, the
            // sandbox is reused, and job B — another tenant — runs on it. The harm is *between*
            // sandboxes, so no property of one sandbox prevents it.
            Clause::SingleUse => true,

            // ── Required: the platform's own secrets, which live outside the box ─────────────
            //
            // §14.2. An inherited environment hands the job the CI shared secret and the host's
            // cloud keys. Isolation does not help against a credential we put inside the box
            // ourselves.
            Clause::EnvAllowlist => true,
            // §14.2 names this one by name. The instance-role credential lives on the host's
            // metadata service, outside the sandbox, and the sandbox reaches it over a network path
            // that looks entirely legitimate from inside the guest.
            Clause::MetadataBlackhole => true,

            // ── Required: the network, which is how anything leaves ─────────────────────────
            //
            // §14.3. Exfiltration is the whole point of attacking a CI runner, and the destination
            // is by definition outside the boundary. A microVM with the open internet in it is a
            // very well-isolated place to stage data from.
            Clause::EgressDeny => true,
            // §14.3. Inbound is how one tenant's job reaches another's — a channel between two
            // sandboxes, which is exactly what the kernel boundary is not able to close on its own.
            Clause::NoInbound => true,

            // ── Required: the two resources whose exhaustion is an outage for other tenants ──
            //
            // §14.4. Uncapped CPU and memory are not confined by isolation: a microVM with no
            // memory ceiling still takes the *host's* memory, and the tenants co-resident on that
            // node are the ones who pay. D§1 lists noisy-neighbour as a cross-tenant channel for
            // this reason.
            Clause::CpuLimit => true,
            Clause::MemoryLimit => true,

            // ── Required: the two controls that protect the runner from the job's output ────
            //
            // §14.4 ties the wall clock to reporting `errored`, but its first job is simpler: a
            // sandbox with no clock holds a node slot forever, which is a denial of service against
            // every other tenant in the queue. Nothing inside the box bounds it.
            Clause::WallClockTimeout => true,
            // §14.4 says why in the spec's own words: "Cap captured output so a job can't OOM the
            // runner by flooding logs." The buffer being flooded is the *node's*, on the far side of
            // the boundary, so the guest's own memory ceiling does not bound it.
            Clause::OutputCap => true,

            // ── Waivable: hardening *inside* a box that is already isolated, empty and doomed ──
            //
            // All six of these limit what a job can do to its own sandbox. Under the required
            // `KernelIsolation` + `SingleUse` + `EgressDeny` set, a job that wins all six has: root
            // in a guest kernel that is not the host's, a rootfs that is destroyed when the job
            // ends, and nowhere to send anything. They are defence in depth against a guest escape,
            // and they remain worth having — `unmet_for_untrusted` never hides them, and
            // `fully_conforming` still demands them — but their absence is not itself an escape.
            //
            // This is the concrete case the audit raised: a correct Firecracker backend on a host
            // without seccomp. It is admitted, and the missing profile is still reported.
            Clause::NonRoot => false,
            Clause::ReadOnlyRootfs => false,
            Clause::TmpfsScratch => false,
            Clause::CapsDropped => false,
            Clause::NoNewPrivileges => false,
            Clause::SeccompDefaultDeny => false,

            // §14.4 PID limit. A fork bomb exhausts the *guest's* process table; the host's is
            // behind the kernel boundary. Under a shared kernel this would be required — but a
            // shared kernel already fails `KernelIsolation` and never reaches this question.
            Clause::PidLimit => false,
            // §14.4 disk limit. Same shape: a microVM's writable storage is a fixed-size virtio-blk
            // device plus a guest tmpfs sized at boot (D§7.2), so "fill the disk" fills a device
            // whose size the host chose. The host filesystem is not mounted into the guest at all.
            // Note this is also the clause the M1 container backend has never claimed, and that
            // backend is refused on `KernelIsolation` long before this matters.
            Clause::DiskLimit => false,
        }
    }
}

impl BackendCapabilities {
    /// Whether this backend enforces one named clause.
    ///
    /// The single point where a [`Clause`] meets a field, so the enum and the struct cannot drift:
    /// a new clause has no arm here until somebody writes one.
    pub fn enforces(self, clause: Clause) -> bool {
        match clause {
            Clause::SingleUse => self.single_use,
            Clause::KernelIsolation => self.cross_tenant_safe,
            Clause::EnvAllowlist => self.env_allowlist,
            Clause::MetadataBlackhole => self.metadata_blackhole,
            Clause::EgressDeny => self.egress_deny,
            Clause::NoInbound => self.no_inbound,
            Clause::NonRoot => self.non_root,
            Clause::ReadOnlyRootfs => self.read_only_rootfs,
            Clause::TmpfsScratch => self.tmpfs_scratch,
            Clause::CapsDropped => self.caps_dropped,
            Clause::NoNewPrivileges => self.no_new_privileges,
            Clause::SeccompDefaultDeny => self.seccomp_default_deny,
            Clause::CpuLimit => self.cpu_limit,
            Clause::MemoryLimit => self.memory_limit,
            Clause::PidLimit => self.pid_limit,
            Clause::DiskLimit => self.disk_limit,
            Clause::WallClockTimeout => self.wall_clock_timeout,
            Clause::OutputCap => self.output_cap,
        }
    }

    /// Every §14 clause this backend does **not** enforce, waivable or not.
    ///
    /// The operator-facing list. It never shrinks because a clause is waivable — a waiver changes
    /// whether the scheduler refuses, not whether the gap is reported.
    pub fn unmet_clauses(self) -> Vec<&'static str> {
        Clause::ALL
            .iter()
            .filter(|c| !self.enforces(**c))
            .map(|c| c.description())
            .collect()
    }

    /// The unmet clauses that are the *reason* [`admits_untrusted`](Self::admits_untrusted) is false.
    ///
    /// Attached to the node's refusal so an operator reads "this is what would have to change",
    /// rather than the full gap list with the actionable entries buried in it.
    pub fn unmet_for_untrusted(self) -> Vec<&'static str> {
        Clause::ALL
            .iter()
            .filter(|c| c.required_for_untrusted() && !self.enforces(**c))
            .map(|c| c.description())
            .collect()
    }

    /// Whether every §14 clause is enforced — the strict answer, waivers and all.
    ///
    /// Kept distinct from [`admits_untrusted`](Self::admits_untrusted) on purpose: this is what a
    /// backend aims at, that is what the scheduler gates on, and conflating them is what turns a
    /// gate into something nobody can pass.
    pub fn fully_conforming(self) -> bool {
        Clause::ALL.iter().all(|c| self.enforces(*c))
    }

    /// Whether this backend may run work from an untrusted author on a shared fleet.
    ///
    /// **What this guarantees, in one sentence:** a backend answers `true` only when it reports a
    /// kernel/hardware boundary, a sandbox destroyed after a single job, an allowlisted environment,
    /// no egress, no route to the cloud metadata endpoint, no inbound from another sandbox, CPU and
    /// memory ceilings, a wall clock, and an output cap — i.e. every §14 clause whose absence would
    /// let a hostile job reach past its own sandbox — while tolerating a missing *in-sandbox*
    /// hardening clause (non-root, read-only rootfs, tmpfs scratch, dropped capabilities,
    /// no-new-privileges, seccomp, PID and disk ceilings) only because winning those still leaves
    /// the job inside a networkless box that is destroyed when it ends.
    ///
    /// See [`Clause::required_for_untrusted`] for the per-clause reasoning. The M1 container
    /// scaffold answers `false` on `cross_tenant_safe` alone, which is exactly why M1 is
    /// single-tenant.
    pub fn admits_untrusted(self) -> bool {
        self.unmet_for_untrusted().is_empty()
    }
}

/// A leased unit of work, control → node (design D§5.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assignment {
    pub job_id: String,
    pub step_id: String,
    pub step_name: String,
    /// Owning tenant — the hard isolation boundary (design D§1).
    ///
    /// Carried explicitly rather than re-derived from `repo` at each use, because every
    /// tenant-scoped decision on the node (cache namespace, log key, workspace path) reads it, and a
    /// field that must be parsed out of another field is a field that will eventually be parsed
    /// wrong. Without it the node cannot construct [`StepReport::log_key`] at all.
    pub tenant: String,
    /// `tenant/repo`, as it arrived on the dispatch. Routing and log-key construction only.
    pub repo: String,
    /// Verified tree to materialize the workspace from.
    pub tree_id: String,
    /// argv, executed inside the sandbox only — never interpolated into a host command line.
    pub argv: Vec<String>,
    /// Tenant secret **names** this step declared (design D§7.4, `secrets = ["NPM_TOKEN"]`).
    ///
    /// Names only, and that is the invariant to hold on to: no secret *value* is ever on an
    /// assignment, in a plan, or in the job store. The short-TTL capability the node redeems at exec
    /// time travels *beside* this type rather than on it, for the same reason `VerifiedTree` does —
    /// a bearer credential does not belong on the value that gets serialized, retried and logged.
    ///
    /// Declaring a name is a request, not a grant. The broker adjudicates it against the job's author
    /// class and never consults this list for authority (D§1), so an outsider's assignment may name
    /// whatever it likes and receive nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<String>,
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
    /// Why, when `outcome` is [`StepOutcome::Errored`].
    ///
    /// The internal wire needs this for the same reason the outward callback does (design G4): spec
    /// §9.1 makes "no pre-existing test exercises this change" a statement about *coverage*
    /// (`self_attested`), which an infrastructure flake must not be able to impersonate. Without a
    /// typed channel here the node has to smuggle the distinction through free text and the control
    /// plane has to parse it back out — a lossy round-trip through prose, in the one place where the
    /// difference decides whether a human gets pulled into a review.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Object-store key of the captured log, `tenant/repo/tree_id/step/attempt` (design D§11).
    ///
    /// **Node-supplied, so it is a claim about where a log went and not an instruction about where
    /// to put one.** The node builds it from its [`Assignment`], but every component is a string
    /// that started somewhere else — `repo` came from Hull, `step_name` came from a pipeline, and
    /// `hull_ci_plan`'s step-name grammar deliberately permits `/`. A step named `a/../../b` would
    /// therefore have written a key outside its own tenant's prefix, and the only thing preventing
    /// it was that the same grammar has no `.` in its charset. That is an accident of one table, not
    /// a control, so the control is [`check_log_key`] plus the caller's own prefix check — see
    /// `Control::record_step_report`, which is the point where the expected prefix is known.
    ///
    /// Nothing writes objects by this key yet. It is validated now precisely because of that: the
    /// first writer inherits whatever the control plane has been storing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_key: Option<String>,
    /// Already sanitized by the node; the aggregator sanitizes again on the way out (defence in depth).
    #[serde(default)]
    pub detail: String,
}

/// The longest `log_key` we will store, in characters.
///
/// The key is `tenant/repo/tree_id/step/attempt` (D§11), whose parts are already individually
/// bounded — [`MAX_REPO_LEN`], a 64-character tree id, a 64-character step name. This is the
/// backstop for their sum, and for a node that is not building the key we think it is.
pub const MAX_LOG_KEY_LEN: usize = 1024;

/// Whether a node's reported [`StepReport::log_key`] is usable as an object-store key.
///
/// Structure only — it says the key is a sequence of ordinary names and therefore cannot address
/// anything but what it spells. It deliberately does **not** say the key belongs to the step that
/// reported it: that needs the job's tenant, repo and tree id, which live in the control plane, so
/// the prefix check belongs there (`Control::record_step_report`). Split that way because they fail
/// differently — a key that fails *here* is malformed and cannot be stored by anybody, and a key
/// that fails the prefix check is well-formed and points at somebody else's prefix.
///
/// Traversal is what this closes: no empty segment (so no leading `/` and no `//`), no `.` or `..`,
/// no `\`. Those are [`check_path_segment`]'s rules, shared with `repo` so the two halves of the
/// same key cannot disagree about what a name is.
pub fn check_log_key(key: &str) -> Result<(), ContractError> {
    let len = key.chars().count();
    if len == 0 || len > MAX_LOG_KEY_LEN {
        return Err(ContractError::Malformed { field: "log_key", why: "empty or longer than 1024 characters" });
    }
    for segment in key.split('/') {
        check_path_segment(segment)
            .map_err(|why| ContractError::Malformed { field: "log_key", why })?;
    }
    Ok(())
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
    /// A field that is present but cannot be used as what it is for.
    ///
    /// `why` is a fixed string rather than the offending value: this message is returned to the
    /// caller and written to a log, and the value is exactly the attacker-controlled bytes we
    /// refused (spec §14.5). Naming the field and the rule is enough for an operator to fix it.
    #[error("dispatch field `{field}` is unusable: {why}")]
    Malformed { field: &'static str, why: &'static str },
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

    // ── The tenant boundary (design D§1) ─────────────────────────────────────────────────────────

    fn with_repo(repo: &str) -> Dispatch {
        Dispatch {
            repo: repo.into(),
            change: "21ea".into(),
            tree_id: "f7a2".into(),
            intent: String::new(),
            author: String::new(),
            source_url: "https://h/tar".into(),
            callback_url: "https://h/ci-result".into(),
            fetch_token: None,
        }
    }

    #[test]
    fn one_tenant_has_exactly_one_spelling() {
        // The audit finding, as a test. These four `repo` values name one customer, and before
        // normalization they produced four tenants: four WFQ flows, four quota buckets, three of
        // them on the generous default plan.
        // Whitespace only. Case is a *different tenant*, pinned by `case_is_not_folded_...` below.
        let accepted = ["acme/widget", " acme/widget ", "acme /widget", "acme/ widget", "acme/widget "];
        for repo in accepted {
            let mut d = with_repo(repo);
            assert_eq!(d.tenant(), "acme", "{repo:?} must read as one tenant");
            d.canonicalize().unwrap_or_else(|e| panic!("{repo:?} is a legitimate dispatch: {e}"));
            assert_eq!(d.repo, "acme/widget", "{repo:?} must be stored one way");
            assert_eq!(d.tenant(), "acme");
        }

        // …and the fourth spelling, whose tenant was the empty string, does not get in at all.
        let mut slashed = with_repo("/widget");
        assert_eq!(
            slashed.canonicalize(),
            Err(ContractError::Malformed { field: "repo", why: "empty path segment" })
        );
        assert_ne!(slashed.tenant(), "", "and it is never the empty tenant even unvalidated");
    }

    #[test]
    fn the_empty_tenant_is_not_reachable() {
        // The empty string is an ordinary key in the step memo, in `FairShare::plans` and in the
        // trusted-tenant set, so several unrelated dispatches landing on it share one namespace.
        // Every shape that used to produce it is refused at the door, and `tenant()` — which cannot
        // fail — never answers with it either.
        for repo in ["/widget", "//x", "/", "/acme/widget", "  /widget"] {
            let mut d = with_repo(repo);
            assert!(d.canonicalize().is_err(), "{repo:?} must not become a job");
            assert!(!d.tenant().is_empty(), "{repo:?} still yielded the empty tenant");
        }
    }

    #[test]
    fn a_repo_cannot_carry_a_path_that_is_not_a_name() {
        // `repo` is the prefix of every log object (D§11) and a component of a workspace path. A
        // segment that a path resolver *reads* rather than stores is refused, and so is one a human
        // reading a log line cannot see.
        for repo in [
            "acme/../globex/widget",
            "../acme/widget",
            "./acme/widget",
            "acme/..",
            "ac\\me/widget",
            "acme/wid\nget",
            "ac\u{200b}me/widget", // zero-width space: two tenants, one appearance
            "acme/wid get",
            "acme\u{0}/widget",
        ] {
            assert!(
                matches!(with_repo(repo).validate(), Err(ContractError::Malformed { field: "repo", .. })),
                "{repo:?} must be refused"
            );
        }
        assert!(with_repo(&format!("acme/{}", "x".repeat(MAX_REPO_LEN))).validate().is_err());
    }

    #[test]
    fn refusal_is_for_the_unusable_and_not_the_merely_unusual() {
        // The other failure mode: a bound that refuses real dispatches is an outage, and spec §5
        // tells us to tolerate what we do not recognise. None of these is a shape we would have
        // chosen, and every one of them still names a repository.
        for repo in [
            "acme/my.repo",          // a dot inside a name is not a dot segment
            "acme/widget.git",
            "acme-corp/widget_v2",
            "acme/group/subgroup/widget", // more than two segments
            "widget",                     // unqualified: its own tenant, as it always was
            "acme/rødgrød",               // non-ASCII names are Hull's business, not ours
            "ACME/Widget",                // a distinct tenant, but a perfectly usable name
            "9/w",
            "a~b/c",
        ] {
            let mut d = with_repo(repo);
            d.canonicalize().unwrap_or_else(|e| panic!("{repo:?} is a legitimate repo, refused: {e}"));
        }
        // Canonicalization does not rename anybody: not the tenant (which would merge two
        // accounts) and not the repo (which would rewrite a name Hull displays).
        let mut d = with_repo("ACME/Widget");
        d.canonicalize().unwrap();
        assert_eq!(d.repo, "ACME/Widget", "canonicalization preserves case in both halves");
        assert_eq!(d.repo_name(), "Widget");
    }

    /// The security half of the normalization rule, at the unit level.
    ///
    /// `tenant_of` is where a tidying instinct would reach for `to_ascii_lowercase`, and doing so
    /// would merge two accounts Hull holds as distinct — handing one the other's trust, secrets,
    /// cache-write bit and memo. Whitespace collapses; case must not.
    #[test]
    fn case_is_not_folded_because_a_merged_tenant_is_worse_than_a_split_one() {
        assert_eq!(tenant_of("ACME/widget"), "ACME");
        assert_eq!(tenant_of("Acme/widget"), "Acme");
        assert_eq!(tenant_of("acme/widget"), "acme");
        assert_ne!(tenant_of("ACME/widget"), tenant_of("acme/widget"));
        // ...while whitespace still collapses, so the split is only ever the one we chose.
        assert_eq!(tenant_of(" ACME /widget"), "ACME");
    }

    #[test]
    fn a_log_key_cannot_leave_the_prefix_it_spells() {
        // Traversal was being blocked only by `.` being absent from the step-name charset — an
        // accident of that grammar, not a stated control. These are the keys a step name containing
        // `/` could have produced.
        for bad in [
            "acme/acme/widget/f7a2/../../globex/1",
            "/acme/acme/widget/f7a2/test/1",
            "acme//widget/f7a2/test/1",
            "acme/acme/widget/f7a2/./1",
            "acme\\..\\globex/1",
            "acme/acme/widget/f7a2/te st/1",
            "acme/acme/widget/f7a2/te\nst/1",
            "",
        ] {
            assert!(check_log_key(bad).is_err(), "{bad:?} must not be stored as a key");
        }
        assert!(check_log_key(&"x".repeat(MAX_LOG_KEY_LEN + 1)).is_err());

        // The keys a node actually builds — including the legal `/` in a step name (D§4.4 allows
        // `test/unit`) — are untouched.
        for ok in [
            "acme/acme/widget/f7a2/test/1",
            "acme/acme/widget/f7a2/test/unit/1",
            "acme/acme/my.repo/f7a2/build-x_1/12",
        ] {
            assert!(check_log_key(ok).is_ok(), "{ok:?} is a key a node legitimately builds");
        }
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
    fn a_summary_really_is_one_line() {
        // U+2028/U+2029 are `Zl`/`Zp`, not `Cc`, so `char::is_control` says nothing about them —
        // and CSS makes them *unconditional* forced line breaks. A job that printed one got a second
        // visible line in the operator panel's verdict cell, under a summary the panel labels as
        // one line: exactly the "forge additional structure" §14.5 forbids.
        let forged = "3 tests, 0 failed\u{2028}\u{2028}SECURITY SCAN: clean";
        let clean = sanitize_summary(forged, SUMMARY_MAX_CHARS);
        assert!(!clean.contains('\u{2028}'), "a line separator is a line break: {clean:?}");
        assert!(!clean.contains('\u{2029}'));
        assert_eq!(clean, "3 tests, 0 failed SECURITY SCAN: clean");
    }

    #[test]
    fn invisible_formatting_does_not_survive() {
        // Every one of these is zero-width or a bidi control, so none of them can be seen in the
        // label the summary becomes — which is what makes them useful for hiding or reordering text.
        for hidden in [
            '\u{00ad}', '\u{061c}', '\u{180e}', '\u{200b}', '\u{200c}', '\u{200d}', '\u{200e}',
            '\u{200f}', '\u{202a}', '\u{202e}', '\u{2060}', '\u{2066}', '\u{2069}', '\u{feff}',
            '\u{e0041}',
        ] {
            let clean = sanitize_summary(&format!("0{hidden} failed"), SUMMARY_MAX_CHARS);
            assert_eq!(clean, "0 failed", "U+{:04X} survived", hidden as u32);
        }
        // …and ordinary text is untouched, including non-ASCII a real summary may legitimately hold.
        assert_eq!(sanitize_summary("café — 3 ok ✓", SUMMARY_MAX_CHARS), "café — 3 ok ✓");
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

    /// A backend that enforces every §14 clause. The only starting point a gate test may use:
    /// building the "good" case field by field is how a test ends up asserting about four booleans.
    fn fully_conforming_backend() -> BackendCapabilities {
        let mut caps = BackendCapabilities::default();
        for clause in Clause::ALL {
            caps = caps.with(clause, true);
        }
        assert!(caps.fully_conforming());
        caps
    }

    impl BackendCapabilities {
        /// Test-only setter, exhaustive so it cannot drift from `enforces`.
        fn with(mut self, clause: Clause, on: bool) -> BackendCapabilities {
            match clause {
                Clause::SingleUse => self.single_use = on,
                Clause::KernelIsolation => self.cross_tenant_safe = on,
                Clause::EnvAllowlist => self.env_allowlist = on,
                Clause::MetadataBlackhole => self.metadata_blackhole = on,
                Clause::EgressDeny => self.egress_deny = on,
                Clause::NoInbound => self.no_inbound = on,
                Clause::NonRoot => self.non_root = on,
                Clause::ReadOnlyRootfs => self.read_only_rootfs = on,
                Clause::TmpfsScratch => self.tmpfs_scratch = on,
                Clause::CapsDropped => self.caps_dropped = on,
                Clause::NoNewPrivileges => self.no_new_privileges = on,
                Clause::SeccompDefaultDeny => self.seccomp_default_deny = on,
                Clause::CpuLimit => self.cpu_limit = on,
                Clause::MemoryLimit => self.memory_limit = on,
                Clause::PidLimit => self.pid_limit = on,
                Clause::DiskLimit => self.disk_limit = on,
                Clause::WallClockTimeout => self.wall_clock_timeout = on,
                Clause::OutputCap => self.output_cap = on,
            }
            self
        }
    }

    #[test]
    fn m1_container_backend_does_not_admit_untrusted_work() {
        // The M1 shape: every hardening flag a locked-down container can set, and the one it never
        // can. It must not admit untrusted work, and the reason it does not must be the boundary.
        let m1 = fully_conforming_backend()
            .with(Clause::KernelIsolation, false)
            .with(Clause::DiskLimit, false);
        assert!(!m1.admits_untrusted(), "M1 is single-tenant by construction, not by convention");
        assert_eq!(
            m1.unmet_for_untrusted(),
            vec!["§14.1 kernel/hardware isolation (microVM-class boundary)"],
            "and the shared kernel is the whole reason — the disk quota is waivable"
        );

        assert!(fully_conforming_backend().admits_untrusted());
    }

    #[test]
    fn the_gate_reads_every_clause_and_names_the_side_each_one_is_on() {
        // The audit finding, as a test. The old gate read four of eighteen clauses, so a backend
        // that had a microVM boundary and nothing else answered `true`. Turning each clause off on
        // its own is the only way to show which ones the gate can actually see.
        let mut required = Vec::new();
        let mut waived = Vec::new();
        for clause in Clause::ALL {
            let caps = fully_conforming_backend().with(clause, false);
            assert!(!caps.fully_conforming(), "{clause:?}: a missing clause is always a gap");
            assert!(
                caps.unmet_clauses().contains(&clause.description()),
                "{clause:?}: a waiver must never hide the gap from an operator"
            );
            if caps.admits_untrusted() { waived.push(clause) } else { required.push(clause) }
            assert_eq!(
                clause.required_for_untrusted(),
                !caps.admits_untrusted(),
                "{clause:?}: the gate must follow `required_for_untrusted` and nothing else"
            );
        }
        // Written out rather than counted, because the point of this test is that a future edit to
        // `required_for_untrusted` has to come here and say so.
        assert_eq!(
            required,
            vec![
                Clause::SingleUse,
                Clause::KernelIsolation,
                Clause::EnvAllowlist,
                Clause::MetadataBlackhole,
                Clause::EgressDeny,
                Clause::NoInbound,
                Clause::CpuLimit,
                Clause::MemoryLimit,
                Clause::WallClockTimeout,
                Clause::OutputCap,
            ],
            "every clause whose harm lands outside the sandbox"
        );
        assert_eq!(
            waived,
            vec![
                Clause::NonRoot,
                Clause::ReadOnlyRootfs,
                Clause::TmpfsScratch,
                Clause::CapsDropped,
                Clause::NoNewPrivileges,
                Clause::SeccompDefaultDeny,
                Clause::PidLimit,
                Clause::DiskLimit,
            ],
            "every clause whose harm lands inside a box that is isolated, networkless and doomed"
        );
    }

    #[test]
    fn the_backend_the_old_gate_would_have_admitted_is_now_refused() {
        // The audit's exact counter-example: "a future kernel-isolated backend with no seccomp, no
        // memory limit and no output cap would answer `true`". Two of those three are required, so
        // it is refused — and the seccomp gap, which is waivable, is still reported.
        let caps = fully_conforming_backend()
            .with(Clause::SeccompDefaultDeny, false)
            .with(Clause::MemoryLimit, false)
            .with(Clause::OutputCap, false);
        // What the four-boolean gate saw, unchanged and still all true:
        assert!(caps.egress_deny && caps.metadata_blackhole && caps.single_use && caps.cross_tenant_safe);
        assert!(!caps.admits_untrusted(), "…and it is no longer enough");
        assert_eq!(
            caps.unmet_for_untrusted(),
            vec!["§14.4 memory limit", "§14.4 captured output cap"]
        );
        assert!(caps.unmet_clauses().contains(&"§14.4 default-deny seccomp profile"));

        // The gate stays passable for the backend this design is actually for: a correct microVM on
        // a host whose kernel offers no seccomp filtering.
        let firecracker_without_seccomp =
            fully_conforming_backend().with(Clause::SeccompDefaultDeny, false);
        assert!(
            firecracker_without_seccomp.admits_untrusted(),
            "a gate no correct backend can pass is a gate that gets deleted"
        );
        assert!(!firecracker_without_seccomp.fully_conforming(), "…but it is still not conforming");
    }

    #[test]
    fn a_capability_field_a_peer_omits_reads_as_not_enforced() {
        // Why every field states what *is* enforced rather than what is missing: a truncated or
        // older payload must understate a backend, never flatter it.
        let empty: BackendCapabilities = serde_json::from_str("{}").expect("all fields default");
        assert_eq!(empty, BackendCapabilities::default());
        assert!(!empty.admits_untrusted());
        assert_eq!(empty.unmet_clauses().len(), Clause::ALL.len());

        // A payload carrying only the four booleans the wire used to have — which is exactly what a
        // node built before this change would send — still cannot answer `true`.
        let old_wire: BackendCapabilities = serde_json::from_str(
            r#"{"egress_deny":true,"metadata_blackhole":true,"single_use":true,"cross_tenant_safe":true}"#,
        )
        .expect("the old four fields still parse");
        assert!(
            !old_wire.admits_untrusted(),
            "an old node cannot be admitted on the strength of the fields it happens to send"
        );
    }
}
