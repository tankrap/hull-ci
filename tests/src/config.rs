//! How the suite is pointed at a CI endpoint. All knobs are environment variables, all have defaults,
//! and none of them reach the public internet.

use std::time::Duration;

use crate::tree::Addressing;

/// The CI endpoint under test (spec §4). Default matches `fake-ci.py`'s default port.
pub fn endpoint() -> String {
    std::env::var("HULL_CI_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:9099".to_string())
}

/// The shared secret (spec §8) the endpoint under test is configured with.
///
/// It has a default so the suite is one command to run, but it is not optional: §11.2 cannot be
/// asserted against an endpoint that has no secret, and a suite that silently skipped that line would
/// report a green baseline it had not earned. Configure the endpoint with this value (or set both
/// sides to your own).
pub fn secret() -> String {
    std::env::var("HULL_CI_SECRET").unwrap_or_else(|_| "conformance-secret".to_string())
}

/// A secret that is well-formed but wrong, for the rejection cases.
pub fn wrong_secret() -> String {
    format!("{}-WRONG", secret())
}

/// How long a job may take between dispatch and callback before the suite calls it lost.
pub fn callback_timeout() -> Duration {
    Duration::from_millis(env_u64("HULL_CI_CALLBACK_TIMEOUT_MS", 20_000))
}

/// How long to wait before concluding that something which must *not* happen has not happened.
pub fn settle() -> Duration {
    Duration::from_millis(env_u64("HULL_CI_SETTLE_MS", 1_500))
}

/// The cap a `summary` must respect (design D§6.6; `hull_ci_proto::SUMMARY_MAX_CHARS`).
///
/// Spec §7 says "one-line human summary" and §14.5 says truncate, without naming a number; this is
/// our number, and a third-party CI with a different one can raise it here.
pub fn summary_max_chars() -> usize {
    env_u64("HULL_CI_SUMMARY_MAX_CHARS", 200) as usize
}

/// Whether to run the checks that are stricter than the letter of CI-SPEC.
///
/// Three cases in this suite enforce a **MAY** or **SHOULD** in the spec that our own design (D§4.2,
/// D§14) promotes to a MUST for *our* runner: `tree_id` re-hashing, refusing an unknown major
/// version, and summary sanitisation. A spec-minimal third-party CI can legitimately fail those, so
/// `HULL_CI_SKIP_STRICT=1` turns them off. They are on by default because the primary subject of this
/// suite is hull-ci, which is held to the stricter bar.
pub fn strict() -> bool {
    std::env::var("HULL_CI_SKIP_STRICT").is_err()
}

/// Announce a strict check that was switched off, so a skip is never mistaken for a pass.
pub fn skipped_strict(clause: &str) {
    eprintln!("SKIPPED (HULL_CI_SKIP_STRICT=1): {clause} — not asserted against this endpoint");
}

/// How the suite names the trees it serves — `HULL_CI_TREE_ID=opaque|keel`, default `opaque`.
///
/// `opaque` (the default) is right for any CI that does not re-hash: `tree_id` is opaque on the wire
/// (§5) and re-hashing is a **MAY** (§6), so no third party can be expected to reproduce a
/// particular address. `keel` is right for a CI that *does* re-hash with keel's real encoding, which
/// `hull-ci` does and makes mandatory (design D§4.2) — in `opaque` mode such a runner would
/// correctly report `errored` for every job, and the suite would be reporting our own service broken
/// over a disagreement that is the suite's.
///
/// Unlike the other knobs this one **refuses an unrecognised value** rather than falling back to the
/// default: silently addressing trees the other way would turn every happy-path test into a
/// `tree_id` mismatch, and the resulting red suite would be blamed on the endpoint.
pub fn addressing() -> Addressing {
    match std::env::var("HULL_CI_TREE_ID").ok().as_deref() {
        None | Some("") | Some("opaque") => Addressing::Opaque,
        Some("keel") => {
            #[cfg(feature = "keel")]
            {
                Addressing::Keel
            }
            // keel's encoder is a real dependency (a pinned `keel-store` git rev), so it is behind a
            // cargo feature and the default build stays offline, tiny, and free of any dependency
            // shared with the service under test. Asking for the mode without it is a mistake worth
            // stopping for, not something to paper over with the opaque address.
            #[cfg(not(feature = "keel"))]
            panic!(
                "HULL_CI_TREE_ID=keel needs the `keel` cargo feature (it pulls in keel's own object \
                 encoder). Re-run with: cargo test --features keel"
            )
        }
        Some(other) => panic!(
            "HULL_CI_TREE_ID={other:?} is not a tree addressing mode. Use `opaque` (default — an \
             arbitrary content address, for any CI that does not re-hash) or `keel` (a genuine keel \
             tree id, for a CI that does)."
        ),
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}
