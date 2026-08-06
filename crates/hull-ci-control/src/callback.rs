//! Verdict delivery — spec §7/§8, design D§10.1.
//!
//! This is the **one externally visible output of the whole system**. Everything else can be
//! reconstructed; an undelivered verdict is indistinguishable, from the user's chair, from "CI is
//! broken". So delivery gets its own state, its own retry loop, and an alert when it gives up.
//!
//! Three rules, all from the contract:
//!
//! 1. POST to `callback_url` **verbatim** (spec §5: opaque, "do not construct it yourself"). This
//!    module never parses, normalizes, or appends to it — it is a string we received and a string we
//!    send. That is also why a compromised dispatch cannot make us fan a request out to a URL we
//!    assembled from job bytes.
//! 2. Echo `X-Hull-CI-Secret` (spec §8: Hull *requires* it on the callback and answers 401 without
//!    it, recording no verdict).
//! 3. Retry with exponential backoff + jitter. Spec §10 says the callback is idempotent and §9 makes
//!    duplicate delivery explicitly safe, so retrying is free of side effects.
//!
//! The transport is a trait so the retry logic can be tested against an injected failure instead of
//! the network.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use hull_ci_proto::{Verdict, SECRET_HEADER};

use crate::ids::rand_u64;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One delivery attempt's inputs. Built once and reused across retries, because a retry must send
/// the *same* verdict to the *same* URL — that is what makes it idempotent.
#[derive(Debug, Clone)]
pub struct CallbackRequest {
    /// Verbatim from the dispatch. Never constructed, never rewritten.
    pub url: String,
    /// `None` only when the endpoint has no configured secret (spec §8).
    pub secret: Option<String>,
    pub verdict: Verdict,
    /// For logs and traces; never placed in the URL or a header.
    pub job_id: String,
}

#[derive(Debug, Clone, Copy)]
pub struct CallbackResponse {
    pub status: u16,
}

impl CallbackResponse {
    pub fn is_success(self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Whether another attempt could plausibly succeed.
    ///
    /// 5xx and the two "come back later" codes are transient. Every other 4xx means Hull has
    /// understood us and refused — a wrong secret (401), an unknown change (404), a malformed
    /// status (400, spec §7). Hammering those for an hour turns our bug into Hull's load problem and
    /// delays the alert that a human actually needs to see.
    pub fn is_retryable(self) -> bool {
        self.status >= 500 || self.status == 408 || self.status == 429
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("callback transport failed: {0}")]
    Send(String),
}

/// The seam between "decide when to send" and "actually send".
pub trait CallbackTransport: Send + Sync + 'static {
    fn post<'a>(
        &'a self,
        req: &'a CallbackRequest,
    ) -> BoxFuture<'a, Result<CallbackResponse, TransportError>>;
}

/// Backoff schedule: 1 s → 5 min, ~12 attempts (design D§10.1).
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    pub base: Duration,
    pub max_delay: Duration,
    pub max_attempts: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            base: Duration::from_secs(1),
            max_delay: Duration::from_secs(5 * 60),
            max_attempts: 12,
        }
    }
}

impl RetryPolicy {
    /// Delay before the attempt after `attempt` (1-based) failed.
    ///
    /// Exponential with **equal jitter** — half the computed delay, plus a random slice of the other
    /// half. Full jitter would let a retry fire almost immediately after a failure, and no jitter at
    /// all synchronizes every parked job in the fleet into one thundering herd against a Hull that
    /// is, by hypothesis, already unwell.
    pub fn delay(&self, attempt: u32) -> Duration {
        let exp = self
            .base
            .checked_mul(1u32.checked_shl(attempt.saturating_sub(1)).unwrap_or(u32::MAX))
            .unwrap_or(self.max_delay)
            .min(self.max_delay);
        let half = exp / 2;
        let spread = half.as_nanos() as u64;
        let jitter = if spread == 0 { 0 } else { rand_u64() % spread };
        half + Duration::from_nanos(jitter)
    }
}

/// The outcome of the whole delivery, not of one attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    Delivered { attempts: u32, status: u16 },
    /// Parked in `report_failed`. Design D§10.1: "no heroics are required — but silent
    /// non-delivery looks exactly like *CI is broken* to a user, so the alert is not optional."
    Parked { attempts: u32, last: String },
}

impl Delivery {
    pub fn is_delivered(&self) -> bool {
        matches!(self, Delivery::Delivered { .. })
    }
}

/// What a delivery is doing *right now*, reported as it happens.
///
/// Exists because an operator could not distinguish "retrying, attempt 3 of 12" from "has not tried
/// at all": the outcome was recorded only once every retry had finished, so for the whole retry
/// budget — up to an hour (D§10.1) — a job mid-delivery looked identical to one that had never
/// started. That is exactly the window in which someone is looking, and exactly the question they are
/// asking (D§11.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryProgress {
    /// The attempt now in flight, 1-based.
    pub attempt: u32,
    pub max_attempts: u32,
    /// `true` while sleeping before the next attempt, `false` while a request is outstanding.
    pub waiting: bool,
}

/// Sink for [`DeliveryProgress`]. A closure rather than a channel, so the caller can write straight
/// into the record it already holds and `deliver_reporting` stays testable with a plain `Vec`.
pub type ProgressSink<'a> = &'a (dyn Fn(DeliveryProgress) + Send + Sync);

/// Send the verdict, retrying until it lands or the schedule is exhausted.
pub async fn deliver(
    transport: &dyn CallbackTransport,
    req: &CallbackRequest,
    policy: &RetryPolicy,
) -> Delivery {
    deliver_reporting(transport, req, policy, &|_| {}).await
}

/// [`deliver`], announcing each attempt as it begins and each wait as it starts.
pub async fn deliver_reporting(
    transport: &dyn CallbackTransport,
    req: &CallbackRequest,
    policy: &RetryPolicy,
    progress: ProgressSink<'_>,
) -> Delivery {
    let max_attempts = policy.max_attempts.max(1);
    let mut last = String::from("no attempt made");
    for attempt in 1..=max_attempts {
        progress(DeliveryProgress { attempt, max_attempts, waiting: false });
        match transport.post(req).await {
            Ok(resp) if resp.is_success() => {
                tracing::info!(
                    job_id = %req.job_id,
                    status = %req.verdict.status.as_str(),
                    attempts = attempt,
                    "verdict delivered"
                );
                return Delivery::Delivered { attempts: attempt, status: resp.status };
            }
            Ok(resp) if !resp.is_retryable() => {
                // Hull understood and refused. More attempts cannot change that answer.
                last = format!("HTTP {} (not retryable)", resp.status);
                tracing::error!(
                    job_id = %req.job_id,
                    status = resp.status,
                    "callback refused by Hull — parking, no verdict recorded"
                );
                return Delivery::Parked { attempts: attempt, last };
            }
            Ok(resp) => last = format!("HTTP {}", resp.status),
            Err(e) => last = e.to_string(),
        }

        if attempt == max_attempts {
            break;
        }
        let wait = policy.delay(attempt);
        tracing::warn!(job_id = %req.job_id, attempt, ?wait, error = %last, "callback failed, retrying");
        // Announced before the sleep, not after: the wait is most of the elapsed time, so a panel
        // that only learned about attempts would show nothing for the majority of the retry budget.
        progress(DeliveryProgress { attempt, max_attempts, waiting: true });
        tokio::time::sleep(wait).await;
    }

    // Alert level on purpose: this is the failure mode a user experiences as an outage.
    tracing::error!(
        alert = true,
        job_id = %req.job_id,
        attempts = max_attempts,
        error = %last,
        "verdict UNDELIVERED after all retries — job parked in report_failed"
    );
    Delivery::Parked { attempts: max_attempts, last }
}

/// The real transport: `reqwest`, JSON body, secret echoed, URL untouched.
pub struct HttpCallback {
    client: reqwest::Client,
}

impl HttpCallback {
    pub fn new(request_timeout: Duration) -> Result<Self, TransportError> {
        let client = reqwest::Client::builder()
            .timeout(request_timeout)
            // A callback that redirects is not something the contract describes, and following one
            // would leak the shared secret to whatever host the redirect names (spec §8: it is a
            // bearer credential).
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| TransportError::Send(e.to_string()))?;
        Ok(HttpCallback { client })
    }
}

impl CallbackTransport for HttpCallback {
    fn post<'a>(
        &'a self,
        req: &'a CallbackRequest,
    ) -> BoxFuture<'a, Result<CallbackResponse, TransportError>> {
        Box::pin(async move {
            // `req.url` goes in exactly as it arrived (spec §5).
            let mut builder = self.client.post(&req.url).json(&req.verdict);
            if let Some(secret) = &req.secret {
                builder = builder.header(SECRET_HEADER, secret);
            }
            let resp = builder.send().await.map_err(|e| TransportError::Send(e.to_string()))?;
            Ok(CallbackResponse { status: resp.status().as_u16() })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defect this exists to prevent: progress was only knowable once delivery *finished*, so a
    /// job retrying for the better part of an hour was indistinguishable from one that had never
    /// tried. Assert that every attempt — and every wait between them — is announced as it starts.
    #[tokio::test]
    async fn every_attempt_and_every_wait_is_announced_while_it_happens() {
        use std::sync::Mutex;

        let seen: Mutex<Vec<DeliveryProgress>> = Mutex::new(Vec::new());
        let transport = crate::testing::ScriptedTransport::failing_then_ok(2);
        let req = CallbackRequest {
            url: "https://hull.example/cb".into(),
            secret: None,
            verdict: hull_ci_proto::Verdict::green("ok"),
            job_id: "job-1".into(),
        };
        // Milliseconds, so the test exercises the schedule without waiting out a real one.
        let policy = RetryPolicy { base: Duration::from_millis(1), max_delay: Duration::from_millis(4), ..RetryPolicy::default() };

        let outcome = deliver_reporting(&transport, &req, &policy, &|p| {
            seen.lock().unwrap().push(p);
        })
        .await;

        assert!(outcome.is_delivered(), "the third attempt succeeds");
        let seen = seen.into_inner().unwrap();

        // Three attempts announced before they ran, and a wait announced before each of the two
        // sleeps. The waits matter most: they are nearly all of the elapsed time, so a sink that only
        // heard about attempts would still leave the panel blank for most of the window.
        let attempts: Vec<u32> = seen.iter().filter(|p| !p.waiting).map(|p| p.attempt).collect();
        assert_eq!(attempts, [1, 2, 3], "each attempt is announced as it begins");
        let waits: Vec<u32> = seen.iter().filter(|p| p.waiting).map(|p| p.attempt).collect();
        assert_eq!(waits, [1, 2], "and each backoff is announced before it is slept");
        assert!(seen.iter().all(|p| p.max_attempts == policy.max_attempts));
    }

    /// A delivery that never lands still reports throughout — this is the case an operator is
    /// actually staring at, and the one where silence used to be indistinguishable from inactivity.
    #[tokio::test]
    async fn a_delivery_that_never_lands_still_reports_every_step_of_the_way() {
        use std::sync::Mutex;

        let seen: Mutex<Vec<DeliveryProgress>> = Mutex::new(Vec::new());
        let transport = crate::testing::ScriptedTransport::always_failing();
        let req = CallbackRequest {
            url: "https://hull.example/cb".into(),
            secret: None,
            verdict: hull_ci_proto::Verdict::red("2 failed"),
            job_id: "job-1".into(),
        };
        let policy = RetryPolicy { max_attempts: 4, base: Duration::from_millis(1), max_delay: Duration::from_millis(4) };

        let outcome = deliver_reporting(&transport, &req, &policy, &|p| {
            seen.lock().unwrap().push(p);
        })
        .await;

        assert!(!outcome.is_delivered());
        let seen = seen.into_inner().unwrap();
        let attempts: Vec<u32> = seen.iter().filter(|p| !p.waiting).map(|p| p.attempt).collect();
        assert_eq!(attempts, [1, 2, 3, 4], "all four announced, not just the last");
        // No wait after the final attempt: there is nothing left to wait for.
        let waits: Vec<u32> = seen.iter().filter(|p| p.waiting).map(|p| p.attempt).collect();
        assert_eq!(waits, [1, 2, 3]);
    }

    use crate::testing::ScriptedTransport;
    use hull_ci_proto::Verdict;

    fn req() -> CallbackRequest {
        CallbackRequest {
            url: "https://hull.example/api/repos/t/r/change/21ea/ci-result?sig=abc".into(),
            secret: Some("s3cret".into()),
            verdict: Verdict::green("ok"),
            job_id: "job_0000000000000001".into(),
        }
    }

    fn fast() -> RetryPolicy {
        // Same code path, no wall-clock cost: the schedule is unit-tested separately.
        RetryPolicy { base: Duration::ZERO, max_delay: Duration::ZERO, max_attempts: 12 }
    }

    #[tokio::test]
    async fn a_transient_failure_is_retried_until_it_lands() {
        let t = ScriptedTransport::failing_then_ok(3);
        let out = deliver(&t, &req(), &fast()).await;
        assert_eq!(out, Delivery::Delivered { attempts: 4, status: 200 });
        assert_eq!(t.attempts(), 4);
    }

    #[tokio::test]
    async fn exhausted_retries_park_the_job_rather_than_dropping_the_verdict() {
        let t = ScriptedTransport::always_failing();
        let out = deliver(&t, &req(), &fast()).await;
        match out {
            Delivery::Parked { attempts, .. } => assert_eq!(attempts, 12, "the full schedule is tried"),
            other => panic!("expected Parked, got {other:?}"),
        }
        assert_eq!(t.attempts(), 12);
    }

    #[tokio::test]
    async fn a_refusal_is_not_retried() {
        // 401 = our secret is wrong (spec §8). Twelve more attempts will also be 401.
        let t = ScriptedTransport::always_status(401);
        let out = deliver(&t, &req(), &fast()).await;
        assert!(matches!(out, Delivery::Parked { attempts: 1, .. }));
        assert_eq!(t.attempts(), 1);
    }

    #[tokio::test]
    async fn a_503_is_retried_but_a_400_is_not() {
        let t = ScriptedTransport::always_status(503);
        assert!(!deliver(&t, &req(), &fast()).await.is_delivered());
        assert_eq!(t.attempts(), 12);

        let t = ScriptedTransport::always_status(400);
        assert!(!deliver(&t, &req(), &fast()).await.is_delivered());
        assert_eq!(t.attempts(), 1);
    }

    #[tokio::test]
    async fn the_callback_url_is_sent_verbatim_and_the_secret_is_echoed() {
        let t = ScriptedTransport::failing_then_ok(1);
        let r = req();
        deliver(&t, &r, &fast()).await;
        for seen in t.seen() {
            assert_eq!(seen.url, r.url, "spec §5: opaque — never rebuilt, not even across a retry");
            assert_eq!(seen.secret.as_deref(), Some("s3cret"), "spec §8 requires the echo");
            assert_eq!(
                serde_json::to_value(&seen.verdict).unwrap()["status"],
                "green",
                "a retry re-affirms the same verdict, which is what makes it idempotent"
            );
        }
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        let p = RetryPolicy::default();
        // Equal jitter: each delay is in [exp/2, exp).
        assert!(p.delay(1) >= Duration::from_millis(500) && p.delay(1) < Duration::from_secs(1));
        assert!(p.delay(5) >= Duration::from_secs(8) && p.delay(5) < Duration::from_secs(16));
        assert!(p.delay(30) <= p.max_delay, "an overflowing shift must clamp, not panic");
    }
}
