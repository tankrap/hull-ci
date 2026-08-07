//! Ingest — `POST /hull`, the configured CI endpoint. Design D§4.1, spec §5/§8/§11.
//!
//! ```text
//! 1. constant-time compare X-Hull-CI-Secret        → 401 on mismatch
//! 2. reject unknown X-Hull-CI-Version major        → 400
//! 3. canonicalize `repo`, or refuse it             → 400   ← the tenant boundary, D§1
//! 4. record job, keyed (repo, tree_id)             ← idempotency, §9
//! 5. 202 {"accepted": true, "job_id": "..."}
//! ```
//!
//! The order is not incidental. Authentication happens **before** we parse a byte of the body, so an
//! unauthenticated caller cannot reach the JSON parser at all; version comes next, because a body we
//! do not know how to read is not one we should try; and the ack is returned only after the job is
//! recorded, because spec §5 makes a 2xx mean *accepted* — Hull tells the user "dispatched" on the
//! strength of it and then stops caring. An ack for a job we lost is a change that hangs unverified.
//!
//! The response is fast by construction: one insert, then a spawned driver. Nothing on this path
//! fetches, plans, or waits on a node.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use hull_ci_proto::{check_version, sanitize_summary, Dispatch, SECRET_HEADER, VERSION_HEADER};

use crate::auth::{check_secret, AuthOutcome};
use crate::control::Control;

/// The HTTP surface. `/hull` is the endpoint an operator configures in Hull's `ci-config` (spec §4).
pub fn router(control: Arc<Control>) -> Router {
    Router::new()
        .route("/hull", post(ingest))
        .route("/healthz", get(healthz))
        .with_state(control)
}

async fn healthz() -> &'static str {
    "ok"
}

type ApiResponse = (StatusCode, Json<serde_json::Value>);

/// Handle one dispatch.
pub async fn ingest(
    State(control): State<Arc<Control>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResponse {
    // 1. Secret (spec §8). Non-UTF-8 header bytes cannot match a configured secret, so they read as
    //    "absent" rather than being coerced.
    let presented = headers.get(SECRET_HEADER).and_then(|v| v.to_str().ok());
    match check_secret(control.secret(), presented) {
        AuthOutcome::Ok => {}
        outcome => {
            // Deliberately one message for both cases: telling a caller whether the header was
            // missing or merely wrong is free information about our configuration.
            tracing::warn!(?outcome, "rejected dispatch: bad or missing secret");
            return error(StatusCode::UNAUTHORIZED, "unauthorized");
        }
    }

    // 2. Version (spec §13). Additive revisions do not bump it, so an unknown value means a
    //    *breaking* revision we would misread — refuse rather than guess.
    let version = headers.get(VERSION_HEADER).and_then(|v| v.to_str().ok());
    if let Err(e) = check_version(version) {
        tracing::warn!(error = %e, "rejected dispatch: unsupported contract version");
        return error(StatusCode::BAD_REQUEST, &e.to_string());
    }

    // 3. Parse. Unknown fields are tolerated by construction (spec §5) — that is a property of the
    //    `Dispatch` type, not of this handler.
    let mut dispatch: Dispatch = match serde_json::from_slice(&body) {
        Ok(d) => d,
        Err(e) => {
            // serde's message can quote the body, which is attacker-controlled: sanitize before it
            // reaches a log line or a response (spec §14.5).
            let detail = sanitize_summary(&e.to_string(), 160);
            tracing::warn!(error = %detail, "rejected dispatch: malformed body");
            return error(StatusCode::BAD_REQUEST, &format!("malformed dispatch: {detail}"));
        }
    };
    // 3. Complete, and usable. `canonicalize` is the one place `repo` is normalized, and it is here
    //    rather than deeper in because the tenant it yields is the isolation boundary for the memo,
    //    the fair-share plan table and the log key (design D§1) — every one of which is an ordinary
    //    map keyed by that string. A boundary that is decided per reader is not a boundary, so it is
    //    decided once, at the door, and written back onto the dispatch every later reader sees.
    if let Err(e) = dispatch.canonicalize() {
        tracing::warn!(error = %e, "rejected dispatch: incomplete or unusable repo");
        return error(StatusCode::BAD_REQUEST, &e.to_string());
    }

    // 4. Record, then ack. `accept` returns once the job exists; the pipeline runs on its own task.
    let accepted = control.accept(dispatch);
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "accepted": true,
            "job_id": accepted.job_id,
            // Additive and purely informational — a conforming Hull ignores it (spec §5).
            "duplicate": accepted.duplicate,
        })),
    )
}

fn error(status: StatusCode, message: &str) -> ApiResponse {
    (status, Json(serde_json::json!({ "accepted": false, "error": message })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{dispatch, fast_config, harness, NodeMode, OkFetcher, StaticPlanner};
    use std::sync::Arc;

    fn headers(secret: Option<&str>, version: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(s) = secret {
            h.insert(SECRET_HEADER, s.parse().unwrap());
        }
        if let Some(v) = version {
            h.insert(VERSION_HEADER, v.parse().unwrap());
        }
        h
    }

    fn control() -> Arc<Control> {
        harness(
            fast_config(),
            Arc::new(OkFetcher),
            Arc::new(StaticPlanner::steps(1)),
            NodeMode::NoCapacity, // nothing runs; these tests are about the door, not the pipeline
        )
        .control
    }

    async fn post_dispatch(
        control: &Arc<Control>,
        h: HeaderMap,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let (status, Json(v)) =
            ingest(State(control.clone()), h, Bytes::from(body.to_string())).await;
        (status, v)
    }

    fn body(repo: &str, tree: &str) -> serde_json::Value {
        serde_json::to_value(dispatch(repo, tree)).unwrap()
    }

    #[tokio::test]
    async fn a_valid_dispatch_is_accepted_with_202_and_a_job_id() {
        let c = control();
        let (status, v) =
            post_dispatch(&c, headers(Some("s3cret"), Some("1")), body("t/r", "tree1")).await;
        assert_eq!(status, StatusCode::ACCEPTED, "spec §5: 2xx means accepted, not done");
        assert_eq!(v["accepted"], true);
        assert!(v["job_id"].as_str().unwrap().starts_with("job_"));
        assert_eq!(v["duplicate"], false);
    }

    #[tokio::test]
    async fn a_wrong_secret_is_401_and_never_reaches_the_parser() {
        let c = control();
        let (status, _) =
            post_dispatch(&c, headers(Some("wrong"), Some("1")), body("t/r", "tree1")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // A missing header is the same answer — and, importantly, the same message.
        let (status, v) = post_dispatch(&c, headers(None, Some("1")), body("t/r", "tree1")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(v["error"], "unauthorized");

        // Nothing was recorded for either attempt.
        let (_, v) = post_dispatch(&c, headers(Some("s3cret"), Some("1")), body("t/r", "tree1")).await;
        assert_eq!(v["duplicate"], false, "an unauthenticated call must not have created the job");
    }

    #[tokio::test]
    async fn an_unknown_contract_version_is_400() {
        let c = control();
        let (status, v) =
            post_dispatch(&c, headers(Some("s3cret"), Some("2")), body("t/r", "tree1")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(v["error"].as_str().unwrap().contains("unsupported contract version"));

        // Absent is fine: spec §5 does not make the header mandatory on our side.
        let (status, _) = post_dispatch(&c, headers(Some("s3cret"), None), body("t/r", "tree1")).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn a_duplicate_dispatch_returns_the_same_job_id() {
        // Spec §9: Hull's in-flight de-dup is best-effort, so a duplicate must be safe here.
        let c = control();
        let h = headers(Some("s3cret"), Some("1"));
        let (_, first) = post_dispatch(&c, h.clone(), body("t/r", "tree1")).await;
        let (status, second) = post_dispatch(&c, h, body("t/r", "tree1")).await;

        assert_eq!(status, StatusCode::ACCEPTED, "a duplicate is still accepted, not an error");
        assert_eq!(first["job_id"], second["job_id"], "one tree, one job, one verdict");
        assert_eq!(second["duplicate"], true);
    }

    #[tokio::test]
    async fn unknown_fields_are_tolerated_but_missing_essentials_are_not() {
        let c = control();
        let mut with_extra = body("t/r", "tree1");
        with_extra["some_future_field"] = serde_json::json!({ "nested": true });
        let (status, _) = post_dispatch(&c, headers(Some("s3cret"), Some("1")), with_extra).await;
        assert_eq!(status, StatusCode::ACCEPTED, "spec §5: forward-compatible");

        let mut incomplete = body("t/r", "tree2");
        incomplete["callback_url"] = serde_json::json!("");
        let (status, v) = post_dispatch(&c, headers(Some("s3cret"), Some("1")), incomplete).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(v["error"].as_str().unwrap().contains("callback_url"));
    }

    // ── The tenant boundary at the door (design D§1) ─────────────────────────────────────────────

    /// The other half of the normalization rule, and the more dangerous direction.
    ///
    /// Collapsing whitespace spellings is a fix; collapsing *case* would be a vulnerability. Hull
    /// normalizes tenant names nowhere, so `acme` and `ACME` can be two distinct accounts — and a
    /// fold here would put the second one inside the first one's quota plan, memo namespace and
    /// (via `TrustedTenants`) its member-class trust. This test exists to fail if someone tidies
    /// `tenant_of` by lowercasing it.
    #[tokio::test]
    async fn a_differently_cased_tenant_is_a_different_tenant() {
        let mut config = fast_config();
        config.fair_share = config.fair_share.clone().with_plan(
            "acme",
            crate::fairshare::TenantPlan { max_running_steps: 2, ..Default::default() },
        );
        let h = harness(
            config,
            Arc::new(OkFetcher),
            Arc::new(StaticPlanner::steps(5)),
            NodeMode::Accept,
        );
        let hdr = headers(Some("s3cret"), Some("1"));

        for (i, repo) in ["acme/widget", "ACME/widget"].iter().enumerate() {
            let (status, _) = post_dispatch(&h.control, hdr.clone(), body(repo, &format!("t{i}"))).await;
            assert_eq!(status, StatusCode::ACCEPTED);
        }

        let mut tenants = h.control.snapshot_tenants();
        tenants.sort_by(|a, b| a.tenant.cmp(&b.tenant));
        assert_eq!(tenants.len(), 2, "case must not merge two accounts: {tenants:#?}");
        assert_eq!(tenants[0].tenant, "ACME");
        assert_eq!(tenants[1].tenant, "acme");
        assert_eq!(
            tenants[0].max_running_steps,
            crate::fairshare::TenantPlan::default().max_running_steps,
            "the uppercase tenant gets the default plan, not the plan configured for `acme`"
        );
    }

    #[tokio::test]
    async fn one_tenant_under_four_spellings_gets_one_flow_and_one_quota_bucket() {
        // The isolation audit's finding, end to end. `Dispatch::tenant()` was
        // `repo.split('/').next()` over an unnormalized string, so one customer written four ways
        // was four tenants: four weighted-fair flows, four quota buckets, and three of them on the
        // *default* plan rather than on the plan the operator configured for this tenant. The audit
        // measured 17 concurrent grants against a cap of 2.
        //
        // Nothing here is an attack. The first path segment comes from Hull, not from a name a
        // tenant picks — which is exactly why this had gone unnoticed, and exactly why it is worth
        // fixing before something else starts choosing that string.
        let mut config = fast_config();
        config.fair_share = config.fair_share.clone().with_plan(
            "acme",
            crate::fairshare::TenantPlan { max_running_steps: 2, ..Default::default() },
        );
        let h = harness(
            config,
            Arc::new(OkFetcher),
            Arc::new(StaticPlanner::steps(5)),
            NodeMode::Accept,
        );
        let hdr = headers(Some("s3cret"), Some("1"));

        // One customer, four whitespace spellings, four different trees so these are four real
        // jobs. Case is deliberately *not* in this list — `Acme` is a different tenant on purpose,
        // and `a_differently_cased_tenant_is_a_different_tenant` is the test that pins that.
        for (i, repo) in ["acme/widget", "acme /widget", " acme/widget", "acme/ widget"].iter().enumerate() {
            let (status, _) = post_dispatch(&h.control, hdr.clone(), body(repo, &format!("tree{i}"))).await;
            assert_eq!(status, StatusCode::ACCEPTED, "{repo:?} is a legitimate dispatch");
        }

        let node = Arc::clone(&h.node);
        assert!(
            crate::testing::wait_until(move || node.assigned().len() == 2).await,
            "the plan's two slots are taken"
        );
        let node = Arc::clone(&h.node);
        assert!(
            crate::testing::stays_false(move || node.assigned().len() > 2).await,
            "one tenant, one cap — not one cap per spelling of its name"
        );

        let tenants = h.control.snapshot_tenants();
        assert_eq!(tenants.len(), 1, "four spellings must not be four tenants: {tenants:#?}");
        assert_eq!(tenants[0].tenant, "acme");
        assert_eq!(tenants[0].jobs_held, 4);
        assert_eq!(tenants[0].max_running_steps, 2, "and all four are on the configured plan");
        assert_eq!(h.control.queue_depth("acme").running, 2);
        for spelling in ["acme ", " acme", "acme/widget", ""] {
            assert_eq!(
                h.control.queue_depth(spelling).running,
                0,
                "{spelling:?} must not be a tenant of its own"
            );
        }
    }

    #[tokio::test]
    async fn a_repo_with_no_usable_tenant_is_refused_at_the_door() {
        // `Dispatch::tenant()` split on `/` and took the first component, so `/widget` yielded the
        // **empty** tenant — an ordinary key in the step memo, in `FairShare::plans` and in the
        // trusted-tenant set, and therefore a namespace several unrelated dispatches would share.
        // It is refused here, before a job exists, rather than absorbed.
        let c = control();
        for repo in ["/widget", "//x", "/", "acme/../globex", "acme/widget/../.."] {
            let (status, v) = post_dispatch(&c, headers(Some("s3cret"), Some("1")), body(repo, "t")).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{repo:?} must not become a job");
            assert!(v["error"].as_str().unwrap().contains("repo"), "the operator is told which field");
        }

        // …and the line stops there. Spec §5 tells us to tolerate what we do not recognise, so a
        // repo that is merely unusual is still a repo, and a refusal that caught these would be an
        // outage for whoever owns them.
        for repo in ["acme/my.repo", "acme/group/sub/widget", "widget", "acme/rødgrød", "ACME/Widget"] {
            let (status, _) = post_dispatch(&c, headers(Some("s3cret"), Some("1")), body(repo, "t")).await;
            assert_eq!(status, StatusCode::ACCEPTED, "{repo:?} is a real repository");
        }
    }

    #[tokio::test]
    async fn a_malformed_body_is_400_and_the_error_cannot_smuggle_control_characters() {
        let c = control();
        let (status, Json(v)) = ingest(
            State(c.clone()),
            headers(Some("s3cret"), Some("1")),
            Bytes::from("{\"repo\": \"\u{1b}[31m\u{0}not json"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let msg = v["error"].as_str().unwrap();
        assert!(!msg.contains('\u{1b}') && !msg.contains('\u{0}') && !msg.contains('\n'));
    }
}
