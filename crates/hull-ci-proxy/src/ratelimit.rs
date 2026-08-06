//! Per-grant rate limiting (D§7.4: "at this rate limit").
//!
//! A token bucket, at one-second resolution, keyed per grant and therefore per job.
//!
//! # What this is actually for
//!
//! Not fairness. The proxy is the *only* destination a sandbox can reach (§14.3), which makes it the
//! only channel a hostile job has for two things: hammering an upstream registry from Hull's IP
//! (which gets Hull rate-limited or blocked, hurting every other tenant), and using package
//! resolution as a slow covert channel. A per-job ceiling bounds both, and bounds them at the one
//! place that can see them — the node cannot, because it sees no packets.
//!
//! # What it deliberately does not do
//!
//! It counts **requests**, not bytes. A byte budget is the more natural fit for exfiltration and for
//! upstream cost, but it can only be charged *after* a response has been streamed, which means the
//! request that blows the budget has already completed. Counting requests is charged before anything
//! leaves, so the limit is a gate rather than a report. The byte dimension is a real gap and is named
//! as one in [`crate::audit`], which records transferred bytes so an operator can see the shape of it.
//!
//! One-second resolution is chosen so the bucket has no clock of its own: it is driven by the epoch
//! seconds the caller already has, which is what makes the whole thing testable without sleeping.

/// Requests per second, plus the burst a job may take at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    pub per_second: u32,
    /// Bucket capacity. `npm install` on a cold cache opens a lot of connections at once, so a burst
    /// well above the steady rate is the difference between a limit and a broken build.
    pub burst: u32,
}

impl RateLimit {
    pub fn new(per_second: u32, burst: u32) -> Self {
        RateLimit { per_second, burst }
    }
}

impl Default for RateLimit {
    /// Sized from what a real resolution looks like rather than from a round number: a cold
    /// `npm install` of a mid-size tree is a few thousand requests over a minute or two, bursty at
    /// the start. 20/s sustained with a burst of 200 covers that with room, and still puts a hard
    /// ceiling of ~1200 requests/minute on a job that has decided to do something else.
    fn default() -> Self {
        RateLimit { per_second: 20, burst: 200 }
    }
}

/// A token bucket driven by caller-supplied epoch seconds.
#[derive(Debug)]
pub struct TokenBucket {
    limit: RateLimit,
    /// Fractional tokens are not needed at one-second resolution, so this stays integral and cannot
    /// drift.
    tokens: u32,
    last_refill: Option<u64>,
}

impl TokenBucket {
    /// A bucket starts **full**, so a job's first burst is not punished for arriving first.
    pub fn new(limit: RateLimit) -> Self {
        TokenBucket { limit, tokens: limit.burst, last_refill: None }
    }

    /// Take one token, refilling for elapsed time first. `false` means "over the limit".
    pub fn take(&mut self, now: u64) -> bool {
        self.refill(now);
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    fn refill(&mut self, now: u64) {
        let last = match self.last_refill {
            Some(t) => t,
            None => {
                self.last_refill = Some(now);
                return;
            }
        };
        // A clock that went backwards (NTP step, a test driving time down) refills nothing rather
        // than panicking on the subtraction or granting a windfall.
        let elapsed = now.saturating_sub(last);
        if elapsed == 0 {
            return;
        }
        self.last_refill = Some(now);
        let gained = elapsed.saturating_mul(self.limit.per_second as u64);
        self.tokens = self.tokens.saturating_add(gained.min(u32::MAX as u64) as u32).min(self.limit.burst);
    }

    pub fn available(&self) -> u32 {
        self.tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bucket_starts_full_so_the_first_burst_is_not_punished() {
        let mut b = TokenBucket::new(RateLimit::new(1, 5));
        for i in 0..5 {
            assert!(b.take(100), "burst token {i}");
        }
        assert!(!b.take(100), "and then the limit bites");
    }

    #[test]
    fn tokens_refill_at_the_configured_rate_and_stop_at_the_burst() {
        let mut b = TokenBucket::new(RateLimit::new(10, 20));
        for _ in 0..20 {
            assert!(b.take(100));
        }
        assert!(!b.take(100));
        // One second → 10 more.
        assert_eq!(b.available(), 0);
        assert!(b.take(101));
        assert_eq!(b.available(), 9);
        // An hour of idling does not bank an hour of requests.
        b.take(3_701);
        assert_eq!(b.available(), 19, "capped at burst, minus the one just taken");
    }

    #[test]
    fn a_clock_that_goes_backwards_grants_nothing() {
        // NTP steps happen. The failure to avoid is a job that gets a free bucket by making time
        // appear to move backwards, and the other failure is an overflow panic.
        let mut b = TokenBucket::new(RateLimit::new(10, 10));
        for _ in 0..10 {
            assert!(b.take(1_000));
        }
        assert!(!b.take(900), "a backwards clock refills nothing");
        assert!(!b.take(1_000));
        assert!(b.take(1_001), "and forward progress still works");
    }

    #[test]
    fn an_absurd_elapsed_time_does_not_overflow() {
        let mut b = TokenBucket::new(RateLimit::new(u32::MAX, 100));
        assert!(b.take(0));
        assert!(b.take(u64::MAX));
        assert_eq!(b.available(), 99);
    }

    #[test]
    fn a_zero_rate_bucket_drains_and_never_refills() {
        // The shape of "this grant may make exactly `burst` requests, ever".
        let mut b = TokenBucket::new(RateLimit::new(0, 2));
        assert!(b.take(1) && b.take(1));
        assert!(!b.take(1));
        assert!(!b.take(100_000));
    }

    #[test]
    fn the_default_fits_a_cold_npm_install() {
        let d = RateLimit::default();
        assert!(d.burst >= 100, "a cold resolution opens many connections at once");
        assert!(d.per_second >= 10 && d.per_second <= 100, "a ceiling, not a throttle");
    }
}
