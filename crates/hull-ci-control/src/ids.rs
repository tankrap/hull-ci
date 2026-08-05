//! Identifiers and the tiny PRNG behind retry jitter.
//!
//! We mint our own ids rather than echoing anything from the dispatch, because ids end up in log
//! keys, `details_url`s, and object-store paths — and spec §14.5 says nothing from a job (or from an
//! attacker who can shape a dispatch) may ever be interpolated into a field name or a URL. A
//! locally-generated hex id is structurally incapable of carrying a path traversal or a control
//! character.
//!
//! The PRNG is deliberately not a dependency: retry jitter (design D§10.1) needs decorrelated
//! delays, not cryptographic randomness, and pulling `rand` into the control plane for a hotspot
//! breaker would be a poor trade.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// SplitMix64 (Steele et al.) — a fast, well-distributed 64-bit mixer.
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// A non-cryptographic random `u64`. Used only for jitter and id uniqueness.
pub(crate) fn rand_u64() -> u64 {
    static STATE: AtomicU64 = AtomicU64::new(0x243F_6A88_85A3_08D3);
    let seed = STATE.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    splitmix64(seed ^ nanos)
}

/// A fresh job id. Hex only, so it is safe in a URL, a log key, and a filesystem path.
pub fn new_job_id() -> String {
    format!("job_{:016x}", rand_u64())
}

/// A step id, scoped to its job so a stray report can never be mistaken for another job's step.
pub fn new_step_id(index: usize) -> String {
    format!("step_{index:02}_{:08x}", rand_u64() as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_hex_only_so_they_cannot_carry_a_path_or_a_control_char() {
        let id = new_job_id();
        assert!(id.starts_with("job_"));
        assert!(id["job_".len()..].chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(new_job_id(), new_job_id(), "ids must not collide back-to-back");
    }
}
