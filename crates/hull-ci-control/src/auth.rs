//! Dispatch authentication — spec §8, design D§4.1 step 1.
//!
//! The shared secret is a **bearer credential**: whoever presents it can inject jobs into the
//! runner. Comparing it with `==` leaks its prefix through timing, one byte at a time, to anyone who
//! can measure our response latency — which is exactly the situation an internet-facing ingest
//! endpoint is in. So the compare is constant-time with respect to the *contents*.
//!
//! Length is not treated as secret (a length oracle on a shared secret is not a practical attack and
//! every constant-time library makes the same call), but we still fold the length difference into
//! the accumulator rather than returning early, so the loop's shape does not depend on the bytes.

use hull_ci_proto::SECRET_HEADER;

/// Compare two byte strings without an early exit on the first differing byte.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff: u64 = (a.len() ^ b.len()) as u64;
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        diff |= (x ^ y) as u64;
    }
    // `black_box` keeps an optimizer from noticing that a nonzero `diff` can never become zero and
    // hoisting an early exit back into the loop above.
    std::hint::black_box(diff) == 0
}

/// Why a dispatch was refused at the door.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Either no secret is configured (spec §8 makes it a SHOULD, not a MUST) or the presented one
    /// matched.
    Ok,
    /// A secret is configured and the header was absent.
    Missing,
    /// A secret is configured and the header did not match.
    Mismatch,
}

impl AuthOutcome {
    pub fn is_ok(self) -> bool {
        matches!(self, AuthOutcome::Ok)
    }
}

/// Check the `X-Hull-CI-Secret` header on an inbound dispatch (spec §11: "Verifies
/// `X-Hull-CI-Secret` on dispatch when a secret is configured").
///
/// `configured` is `None` for an endpoint with no secret, which is a legitimate — if discouraged —
/// configuration; in that case anything presented is accepted, because we have nothing to check it
/// against and refusing would break a conforming Hull that sends no header.
pub fn check_secret(configured: Option<&str>, presented: Option<&str>) -> AuthOutcome {
    match (configured, presented) {
        (None, _) => AuthOutcome::Ok,
        (Some(_), None) => AuthOutcome::Missing,
        (Some(want), Some(got)) => {
            if constant_time_eq(want.as_bytes(), got.as_bytes()) {
                AuthOutcome::Ok
            } else {
                AuthOutcome::Mismatch
            }
        }
    }
}

/// The header name, re-exported so callers do not hand-write the string.
pub const HEADER: &str = SECRET_HEADER;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_agrees_with_equality() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"s3cret", b"s3cret"));
        assert!(!constant_time_eq(b"s3cret", b"s3crey"));
        assert!(!constant_time_eq(b"s3cret", b"s3cre"));
        assert!(!constant_time_eq(b"s3cret", b"s3crett"));
        assert!(!constant_time_eq(b"", b"a"));
    }

    #[test]
    fn secret_policy() {
        assert_eq!(check_secret(None, None), AuthOutcome::Ok);
        assert_eq!(check_secret(None, Some("anything")), AuthOutcome::Ok);
        assert_eq!(check_secret(Some("k"), None), AuthOutcome::Missing);
        assert_eq!(check_secret(Some("k"), Some("k")), AuthOutcome::Ok);
        assert_eq!(check_secret(Some("k"), Some("K")), AuthOutcome::Mismatch);
    }
}
