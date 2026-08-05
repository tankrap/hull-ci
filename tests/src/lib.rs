//! **Black-box conformance suite for the Hull CI Integration Standard** (`CI-SPEC.md`).
//!
//! The suite judges a CI endpoint over HTTP and nothing else. It knows the endpoint's URL and the
//! shared secret; it knows no types, no internals, and no source tree of the thing it is testing.
//! That is deliberate on two counts:
//!
//! 1. **It exists before the implementation does.** `hull-ci`'s crates are empty scaffolding today.
//!    A suite written against them would have to be rewritten as they fill in; a suite written
//!    against the wire is the fixed point they get built towards, and `scripts/fake-ci.py` gives it a
//!    baseline to be green against on day one.
//! 2. **It cannot be satisfied by agreement with itself.** Nothing here imports `hull-ci-proto`; the
//!    header names and JSON shapes are transcribed from the spec. If our own constants drift from the
//!    document, this suite is what notices.
//!
//! One thing must not be black-box, and is not: **how the suite names a tree**. `tree_id` is opaque
//! on the wire (§5) and re-hashing is only a **MAY** (§6), but our own runner re-hashes with keel's
//! real encoding and refuses a mismatch (design D§4.2). A suite that invented its own address would
//! fail every happy-path test against our own service and report the service broken. So addressing
//! is a knob — [`tree::Addressing`], set by `HULL_CI_TREE_ID` — and `tests/keel_addressing.rs`
//! (behind `--features crosscheck`, the only file here that imports `hull-ci`) proves the keel mode
//! agrees with keel itself and with Hull's archive layout. Nothing on the judging path imports our
//! code.
//!
//! ## Layout
//!
//! * [`hull`] — the stub Hull: sends dispatches (§5), serves `source_url` (§6), receives callbacks
//!   (§7/§8), and records everything.
//! * [`tree`] — synthetic keel trees, their tar serialisation, and their content address in either
//!   addressing mode.
//! * [`http`] — a small HTTP/1.1 client and server, so the harness shares no transport stack with
//!   its subject.
//! * `tests/conformance.rs` — the §11 checklist, one test per checklist line.
//! * `tests/adversarial.rs` — the design D§14 adversarial cases.
//! * `tests/keel_addressing.rs` — the harness's own proof that keel mode is genuine.
//!
//! ## What a black-box suite cannot see
//!
//! Stated here once rather than as tests that always pass:
//!
//! * **Isolation (§14.1–§14.4).** Whether a job ran in a single-use microVM, as a non-root user, with
//!   egress denied and `169.254.169.254` blackholed, is invisible from the far end of an HTTP
//!   callback. Those clauses are provable only from inside the runner — they belong in `hull-ci`'s
//!   own integration tests, where the sandbox can be inspected and a job can be told to try to escape.
//! * **"No git" in general (§11.3).** The suite proves the runner fetched `source_url`, and that it
//!   made no git-shaped request to *Hull* — the only host it is given. It cannot prove the runner did
//!   not clone from somewhere else entirely; no observer at Hull's end can. Verifying that requires
//!   watching the runner's own egress (see `no_git_shaped_requests_to_hull`).
//! * **The runner's internal memoisation.** §9 puts de-duplication in Hull. From here, a second
//!   dispatch producing one callback and a second dispatch producing two are both conforming; what
//!   the suite can and does assert is that they never *disagree*.

pub mod config;
pub mod http;
pub mod hull;
pub mod tree;

pub use hull::{Callback, JobSpec, Source, StubHull};

/// Every control character in `s`, for the §14.5 assertions and their failure messages.
pub fn control_characters(s: &str) -> Vec<char> {
    s.chars().filter(|c| c.is_control()).collect()
}

/// Characters that are not control codes but can still misrepresent a line (bidi overrides).
pub fn bidi_characters(s: &str) -> Vec<char> {
    s.chars()
        .filter(|c| {
            matches!(c, '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .collect()
}

/// Render a summary safely inside a panic message — the whole point is that it may be hostile.
pub fn escape_for_message(s: &str) -> String {
    s.chars().flat_map(|c| c.escape_debug()).take(400).collect()
}

/// A one-line description of what the CI actually sent us, for failure messages.
pub fn describe_requests(requests: &[http::HttpRequest]) -> String {
    if requests.is_empty() {
        return "(none)".to_string();
    }
    requests.iter().map(|r| r.line()).collect::<Vec<_>>().join(", ")
}

/// The statuses spec §7 allows on a callback.
pub const VALID_STATUSES: [&str; 3] = ["green", "red", "errored"];
