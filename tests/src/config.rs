//! How the suite is pointed at a CI endpoint. All knobs are environment variables, all have defaults,
//! and none of them reach the public internet.

use std::time::Duration;

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

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}
