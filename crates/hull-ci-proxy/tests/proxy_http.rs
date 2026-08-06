//! The proxy over a real socket, against a real upstream.
//!
//! The unit tests in the crate prove each rule in isolation. These prove the rules still hold when
//! composed into an actual request/response — which is where the interesting failures live, because
//! every leak this crate exists to prevent is a leak *between* two layers: a header the allowlist
//! never saw, a credential the redirect handler forwarded, a refusal that happened after the body
//! had already started streaming.
//!
//! The fake upstream records what it was *sent* in a side channel rather than echoing it into a
//! response body. That distinction is the point of the whole file: "the upstream received the
//! credential" and "the job received the credential" are two different questions, and a test that
//! reads the credential out of the proxied body cannot tell them apart.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use hull_ci_proxy::allowlist::{Allowlist, AuthScheme, Upstream};
use hull_ci_proxy::audit::MemoryAudit;
use hull_ci_proxy::credentials::StaticCredentials;
use hull_ci_proxy::grant::GrantRegistry;
use hull_ci_proxy::ratelimit::RateLimit;
use hull_ci_proxy::server::PackageProxy;

/// The credential the tenant holds for the private upstream. Nothing a job receives may contain it.
const UPSTREAM_SECRET: &str = "npm_s3cr3tvalue_do_not_leak";

/// What the fake upstream saw, per request path.
#[derive(Debug, Default)]
struct Seen {
    authorization: Vec<Option<String>>,
    paths: Vec<String>,
    cookies: Vec<Option<String>>,
}

type SharedSeen = Arc<Mutex<Seen>>;

async fn upstream_pkg(State(seen): State<SharedSeen>, headers: HeaderMap) -> Response {
    record(&seen, "/pkg", &headers);
    (StatusCode::OK, "package-bytes").into_response()
}

/// Lives under the path prefix the `public` upstream is scoped to, so "which upstream is this
/// request for" is a question the allowlist actually has to answer.
async fn upstream_public_pkg(State(seen): State<SharedSeen>, headers: HeaderMap) -> Response {
    record(&seen, "/public/pkg", &headers);
    (StatusCode::OK, "public-package-bytes").into_response()
}

/// An upstream that quotes the credential it was given back in a `www-authenticate` header and sets
/// a cookie — the two response headers most likely to carry something a job must not see.
async fn upstream_401(State(seen): State<SharedSeen>, headers: HeaderMap) -> Response {
    record(&seen, "/needs-auth", &headers);
    let mut response =
        (StatusCode::UNAUTHORIZED, "denied").into_response();
    response.headers_mut().insert(
        "www-authenticate",
        format!("Bearer realm=\"x\", error=\"bad token {UPSTREAM_SECRET}\"").parse().unwrap(),
    );
    response.headers_mut().insert("set-cookie", "session=abc123".parse().unwrap());
    response
}

async fn upstream_redirect_internal(State(seen): State<SharedSeen>, headers: HeaderMap) -> Response {
    record(&seen, "/redirect-internal", &headers);
    let mut response = StatusCode::FOUND.into_response();
    response.headers_mut().insert("location", "/pkg".parse().unwrap());
    response
}

/// A redirect to a host nobody allowlisted — the classic credential-leak-by-redirect.
async fn upstream_redirect_offlist(State(seen): State<SharedSeen>, headers: HeaderMap) -> Response {
    record(&seen, "/redirect-offlist", &headers);
    let mut response = StatusCode::FOUND.into_response();
    response.headers_mut().insert("location", "http://evil.example.test/steal".parse().unwrap());
    response
}

/// A chunked response with no `Content-Length`, so the audit's byte count has to come from the
/// stream rather than from a declared header.
async fn upstream_chunked(State(seen): State<SharedSeen>, headers: HeaderMap) -> Response {
    record(&seen, "/chunked", &headers);
    let chunks: Vec<Result<axum::body::Bytes, std::io::Error>> =
        vec![Ok("aaaa".into()), Ok("bbbb".into()), Ok("cc".into())];
    axum::body::Body::from_stream(futures_util::stream::iter(chunks)).into_response()
}

fn record(seen: &SharedSeen, path: &str, headers: &HeaderMap) {
    let mut s = seen.lock().unwrap();
    s.paths.push(path.to_string());
    s.authorization
        .push(headers.get("authorization").and_then(|v| v.to_str().ok()).map(str::to_string));
    s.cookies.push(headers.get("cookie").and_then(|v| v.to_str().ok()).map(str::to_string));
}

struct Harness {
    proxy_base: String,
    seen: SharedSeen,
    audit: Arc<MemoryAudit>,
    grants: Arc<GrantRegistry>,
    upstream_base: String,
}

impl Harness {
    /// The job-facing URL for one upstream label under a given grant.
    fn url(&self, grant: &str, label: &str, tail: &str) -> String {
        format!("{}/j/{}/u/{}/{}", self.proxy_base, grant, label, tail)
    }
}

/// Bring up a fake upstream and a proxy in front of it, both on loopback.
async fn harness(rate: RateLimit) -> Harness {
    let seen: SharedSeen = Arc::new(Mutex::new(Seen::default()));
    let upstream = Router::new()
        .route("/pkg", get(upstream_pkg))
        .route("/public/pkg", get(upstream_public_pkg))
        .route("/needs-auth", get(upstream_401))
        .route("/redirect-internal", get(upstream_redirect_internal))
        .route("/redirect-offlist", get(upstream_redirect_offlist))
        .route("/chunked", get(upstream_chunked))
        .with_state(seen.clone());
    let up_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = up_listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(up_listener, upstream).await.unwrap() });

    let upstream_base = format!("http://{up_addr}");
    let allowlist = Allowlist::from_upstreams(vec![
        // Authenticated: the interesting one.
        Upstream::authenticated("private", &upstream_base, "NPM_TOKEN", AuthScheme::Bearer).unwrap(),
        // Public, same host, different path prefix — so "which upstream am I" is a real question.
        Upstream::public("public", &format!("{upstream_base}/public")).unwrap(),
    ])
    .unwrap();

    let creds = Arc::new(StaticCredentials::new().with("acme", "NPM_TOKEN", UPSTREAM_SECRET));
    let audit = Arc::new(MemoryAudit::new());
    let grants = Arc::new(GrantRegistry::new());
    let proxy = PackageProxy::new(allowlist, creds)
        .with_audit(audit.clone())
        .with_grants(grants.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { proxy.serve(listener).await.unwrap() });

    let _ = rate;
    Harness { proxy_base: format!("http://{addr}"), seen, audit, grants, upstream_base }
}

fn upstreams(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap()
}

fn far_future() -> u64 {
    u64::MAX / 2
}

/// A [`Fetch`](hull_ci_proxy::audit::Fetch) record lands when the response body *finishes*
/// streaming, which is after the client has read it but not necessarily before the next line of a
/// test runs. Polling for it keeps the audit's "count what crossed, not what was declared" property
/// (which is the reason for the late emit) from making every audit assertion racy.
async fn wait_for_fetch(h: &Harness) -> hull_ci_proxy::audit::Fetch {
    for _ in 0..100 {
        if let Some(fetch) = h.audit.fetches().pop() {
            return fetch;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("no fetch record was ever emitted");
}

#[tokio::test]
async fn a_job_fetches_through_the_proxy_and_never_sees_the_upstream_credential() {
    // The single most important assertion in this crate (D§7.4): the upstream got the credential,
    // the job did not, and there is no header or byte in the job's response that carries it.
    let h = harness(RateLimit::default()).await;
    let (token, _) = h.grants.mint("acme", "job-1", upstreams(&["private"]), far_future(), RateLimit::default());

    let response = client().get(h.url(token.expose(), "private", "pkg")).send().await.unwrap();
    assert_eq!(response.status(), 200);

    // Headers the job received: none of them may carry a credential.
    let headers = response.headers().clone();
    for (name, value) in headers.iter() {
        let rendered = format!("{name}: {}", value.to_str().unwrap_or(""));
        assert!(!rendered.contains(UPSTREAM_SECRET), "credential in a response header: {rendered}");
    }
    assert!(headers.get("authorization").is_none());
    assert!(headers.get("www-authenticate").is_none());

    let body = response.text().await.unwrap();
    assert_eq!(body, "package-bytes");
    assert!(!body.contains(UPSTREAM_SECRET));

    // …and the upstream *did* get it, which is what makes the above a real result rather than an
    // artefact of the credential never being spent at all.
    let seen = h.seen.lock().unwrap();
    assert_eq!(seen.authorization.last().unwrap().as_deref(), Some(&*format!("Bearer {UPSTREAM_SECRET}")));
}

#[tokio::test]
async fn a_public_upstream_is_never_handed_the_tenants_credential() {
    let h = harness(RateLimit::default()).await;
    let (token, _) = h.grants.mint("acme", "job-1", upstreams(&["public"]), far_future(), RateLimit::default());

    let response = client().get(h.url(token.expose(), "public", "pkg")).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let seen = h.seen.lock().unwrap();
    assert_eq!(seen.paths.last().unwrap(), "/public/pkg");
    assert_eq!(seen.authorization.last().unwrap(), &None, "a public registry gets no credential");
}

#[tokio::test]
async fn an_upstream_that_quotes_the_credential_back_cannot_reach_the_job() {
    // A 401 body/header quoting the rejected token is common. The header allowlist is what stops it.
    let h = harness(RateLimit::default()).await;
    let (token, _) = h.grants.mint("acme", "job-1", upstreams(&["private"]), far_future(), RateLimit::default());

    let response = client().get(h.url(token.expose(), "private", "needs-auth")).send().await.unwrap();
    assert_eq!(response.status(), 401, "the upstream's status is passed through");
    assert!(response.headers().get("www-authenticate").is_none(), "…but not its headers");
    assert!(response.headers().get("set-cookie").is_none());
    for (_, value) in response.headers().iter() {
        assert!(!value.to_str().unwrap_or("").contains(UPSTREAM_SECRET));
    }
}

#[tokio::test]
async fn the_jobs_own_credentials_never_reach_an_upstream() {
    // Auth terminates at the proxy in *both* directions: a job cannot use the proxy to carry its own
    // Authorization or Cookie to an allowlisted host.
    let h = harness(RateLimit::default()).await;
    let (token, _) = h.grants.mint("acme", "job-1", upstreams(&["private"]), far_future(), RateLimit::default());

    let response = client()
        .get(h.url(token.expose(), "private", "pkg"))
        .header("authorization", "Bearer job-supplied-token")
        .header("cookie", "job=cookie")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let seen = h.seen.lock().unwrap();
    assert_eq!(
        seen.authorization.last().unwrap().as_deref(),
        Some(&*format!("Bearer {UPSTREAM_SECRET}")),
        "the proxy's credential replaced the job's, rather than both being sent"
    );
    assert_eq!(seen.cookies.last().unwrap(), &None, "the job's cookie did not travel");
}

#[tokio::test]
async fn an_upstream_outside_the_allowlist_is_refused_and_recorded() {
    let h = harness(RateLimit::default()).await;
    let (token, _) = h.grants.mint("acme", "job-1", upstreams(&["private"]), far_future(), RateLimit::default());

    let response = client().get(h.url(token.expose(), "pypi", "simple/")).send().await.unwrap();
    assert_eq!(response.status(), 403);
    assert!(h.seen.lock().unwrap().paths.is_empty(), "nothing was sent upstream at all");

    let refusals = h.audit.refusals();
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0].job_id.as_deref(), Some("job-1"));
    assert!(refusals[0].reason.contains("pypi"));
    assert!(!refusals[0].path.contains(token.expose()), "the grant is redacted in the audit record");
}

#[tokio::test]
async fn a_grant_cannot_reach_an_allowlisted_upstream_it_was_not_minted_for() {
    // Per-job scoping: `public` exists in the deployment allowlist, but not in this job's grant.
    let h = harness(RateLimit::default()).await;
    let (token, _) = h.grants.mint("acme", "job-1", upstreams(&["private"]), far_future(), RateLimit::default());

    let response = client().get(h.url(token.expose(), "public", "pkg")).send().await.unwrap();
    assert_eq!(response.status(), 403);
    assert!(h.audit.refusals()[0].reason.contains("not in this job's grant"));
    assert!(h.seen.lock().unwrap().paths.is_empty());
}

#[tokio::test]
async fn a_forged_or_expired_grant_buys_nothing() {
    let h = harness(RateLimit::default()).await;
    for bad in ["hpkg_deadbeef.cafe", "nonsense", ""] {
        let response = client().get(h.url(bad, "private", "pkg")).send().await.unwrap();
        assert_eq!(response.status(), 401, "grant {bad:?}");
    }
    // And a real grant that has expired.
    let (token, _) = h.grants.mint("acme", "job-1", upstreams(&["private"]), 1, RateLimit::default());
    let response = client().get(h.url(token.expose(), "private", "pkg")).send().await.unwrap();
    assert_eq!(response.status(), 401);
    assert!(h.seen.lock().unwrap().paths.is_empty(), "an unauthenticated request never goes upstream");
}

#[tokio::test]
async fn a_grant_that_ended_with_its_job_stops_working_mid_flight() {
    let h = harness(RateLimit::default()).await;
    let (token, _) = h.grants.mint("acme", "job-1", upstreams(&["private"]), far_future(), RateLimit::default());
    assert_eq!(client().get(h.url(token.expose(), "private", "pkg")).send().await.unwrap().status(), 200);

    assert_eq!(h.grants.revoke_job("job-1"), 1);
    assert_eq!(client().get(h.url(token.expose(), "private", "pkg")).send().await.unwrap().status(), 401);
}

#[tokio::test]
async fn only_reads_are_served() {
    let h = harness(RateLimit::default()).await;
    let (token, _) = h.grants.mint("acme", "job-1", upstreams(&["private"]), far_future(), RateLimit::default());

    for method in [reqwest::Method::PUT, reqwest::Method::POST, reqwest::Method::DELETE] {
        let response = client()
            .request(method.clone(), h.url(token.expose(), "private", "pkg"))
            .body("exfiltrated workspace")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 405, "{method} must not be proxied");
    }
    assert!(h.seen.lock().unwrap().paths.is_empty(), "no write ever reached the upstream");
}

#[tokio::test]
async fn connect_is_refused_by_name() {
    // The design decision, asserted: a tunnel would make the credential unspendable at the proxy and
    // the allowlist blind to everything but a hostname.
    let h = harness(RateLimit::default()).await;
    let response = client()
        .request(reqwest::Method::from_bytes(b"CONNECT").unwrap(), format!("{}/", h.proxy_base))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 405);
    assert!(response.text().await.unwrap().contains("CONNECT is not served"));
}

#[tokio::test]
async fn the_rate_limit_bites_and_names_itself() {
    let h = harness(RateLimit::default()).await;
    let (token, _) = h.grants.mint("acme", "job-1", upstreams(&["private"]), far_future(), RateLimit::new(0, 2));

    for i in 0..2 {
        assert_eq!(
            client().get(h.url(token.expose(), "private", "pkg")).send().await.unwrap().status(),
            200,
            "burst request {i}"
        );
    }
    let response = client().get(h.url(token.expose(), "private", "pkg")).send().await.unwrap();
    assert_eq!(response.status(), 429);
    assert!(response.text().await.unwrap().contains("rate limit"));
    assert_eq!(h.seen.lock().unwrap().paths.len(), 2, "the limited request never went upstream");
}

#[tokio::test]
async fn one_jobs_rate_limit_is_not_anothers() {
    let h = harness(RateLimit::default()).await;
    let (a, _) = h.grants.mint("acme", "job-a", upstreams(&["private"]), far_future(), RateLimit::new(0, 1));
    let (b, _) = h.grants.mint("acme", "job-b", upstreams(&["private"]), far_future(), RateLimit::new(0, 1));

    assert_eq!(client().get(h.url(a.expose(), "private", "pkg")).send().await.unwrap().status(), 200);
    assert_eq!(client().get(h.url(a.expose(), "private", "pkg")).send().await.unwrap().status(), 429);
    assert_eq!(
        client().get(h.url(b.expose(), "private", "pkg")).send().await.unwrap().status(),
        200,
        "job-b has its own bucket"
    );
}

#[tokio::test]
async fn a_redirect_off_the_allowlist_is_refused_rather_than_followed() {
    // The hop where a credential would otherwise walk off the allowlist.
    let h = harness(RateLimit::default()).await;
    let (token, _) = h.grants.mint("acme", "job-1", upstreams(&["private"]), far_future(), RateLimit::default());

    let response =
        client().get(h.url(token.expose(), "private", "redirect-offlist")).send().await.unwrap();
    assert_eq!(response.status(), 403);
    assert!(h.audit.refusals().iter().any(|r| r.reason.contains("evil.example.test")));
}

#[tokio::test]
async fn a_redirect_inside_the_allowlist_is_followed_and_counted() {
    let h = harness(RateLimit::default()).await;
    let (token, _) = h.grants.mint("acme", "job-1", upstreams(&["private"]), far_future(), RateLimit::default());

    let response =
        client().get(h.url(token.expose(), "private", "redirect-internal")).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "package-bytes");

    let fetch = wait_for_fetch(&h).await;
    assert_eq!(fetch.redirects, 1);
    assert!(fetch.authenticated, "the credential was re-derived for the hop we landed on");
    // Both legs carried the credential, because both are the same allowlisted upstream.
    let seen = h.seen.lock().unwrap();
    assert_eq!(seen.paths, vec!["/redirect-internal", "/pkg"]);
    assert!(seen.authorization.iter().all(|a| a.as_deref() == Some(&*format!("Bearer {UPSTREAM_SECRET}"))));
}

#[tokio::test]
async fn the_audit_counts_bytes_that_actually_crossed_not_bytes_that_were_declared() {
    // A chunked response declares no `Content-Length`, which is exactly how a job would move volume
    // without it showing up in the log.
    let h = harness(RateLimit::default()).await;
    let (token, _) = h.grants.mint("acme", "job-1", upstreams(&["private"]), far_future(), RateLimit::default());

    let response = client().get(h.url(token.expose(), "private", "chunked")).send().await.unwrap();
    assert!(response.headers().get("content-length").is_none());
    assert_eq!(response.text().await.unwrap(), "aaaabbbbcc");

    let fetch = wait_for_fetch(&h).await;
    assert_eq!(fetch.bytes, 10, "counted from the stream, not from a declared header");
    assert_eq!(fetch.upstream, "private");
    assert_eq!(fetch.job_id, "job-1");
    assert!(!fetch.url.contains(token.expose()), "no grant in an audit URL");
}

#[tokio::test]
async fn a_content_length_response_is_audited_too() {
    // Regression guard for a bug this suite caught: hyper stops polling a body the moment
    // `Content-Length` is satisfied and never delivers the end-of-stream, so an audit that emitted
    // at end-of-stream recorded **nothing** for the ordinary case — a package fetch with a declared
    // length — while still passing a chunked-response test. The record is emitted on `Drop` now.
    let h = harness(RateLimit::default()).await;
    let (token, _) = h.grants.mint("acme", "job-1", upstreams(&["private"]), far_future(), RateLimit::default());

    let response = client().get(h.url(token.expose(), "private", "pkg")).send().await.unwrap();
    assert_eq!(response.headers().get("content-length").unwrap(), "13");
    assert_eq!(response.text().await.unwrap(), "package-bytes");

    let fetch = wait_for_fetch(&h).await;
    assert_eq!(fetch.bytes, 13);
    assert_eq!(fetch.status, 200);
    assert!(fetch.authenticated);
}

#[tokio::test]
async fn path_traversal_cannot_escape_the_upstreams_base_over_the_wire() {
    // `public` is scoped to `/pkg` on the same host as `private`. Walking up must not reach the rest.
    let h = harness(RateLimit::default()).await;
    let (token, _) = h.grants.mint("acme", "job-1", upstreams(&["public"]), far_future(), RateLimit::default());

    for tail in ["../needs-auth", "..%2fneeds-auth", "a/../../needs-auth"] {
        let response = client().get(h.url(token.expose(), "public", tail)).send().await.unwrap();
        assert_eq!(response.status(), 403, "tail {tail}");
    }
    assert!(h.seen.lock().unwrap().paths.is_empty(), "nothing escaped to the upstream");
}

#[tokio::test]
async fn absolute_form_runs_the_identical_policy_path() {
    // The second door must not be the weaker one.
    let h = harness(RateLimit::default()).await;
    let (token, _) = h.grants.mint("acme", "job-1", upstreams(&["private"]), far_future(), RateLimit::default());

    // A client configured the `http_proxy` way, so the request goes out in absolute form with the
    // grant in `Proxy-Authorization` — the shape a tool that was never told about mirror URLs sends.
    let proxied = reqwest::Client::builder()
        .proxy(
            reqwest::Proxy::http(&h.proxy_base)
                .unwrap()
                .custom_http_auth(format!("Bearer {}", token.expose()).parse().unwrap()),
        )
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let response = proxied.get(format!("{}/pkg", h.upstream_base)).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "package-bytes");
    assert_eq!(
        h.seen.lock().unwrap().authorization.last().unwrap().as_deref(),
        Some(&*format!("Bearer {UPSTREAM_SECRET}"))
    );

    // A host nobody allowlisted, through the same door.
    let response = proxied.get("http://evil.example.test/steal").send().await.unwrap();
    assert_eq!(response.status(), 403);
}

#[tokio::test]
async fn healthz_answers_without_a_grant_and_says_nothing_else() {
    // The node's posture probe calls this from inside the sandbox network before any job exists.
    let h = harness(RateLimit::default()).await;
    let response = client().get(format!("{}/healthz", h.proxy_base)).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let body = response.text().await.unwrap();
    assert_eq!(body.trim(), "ok");
    assert!(!body.contains("npm"), "liveness must not enumerate the allowlist");
}
