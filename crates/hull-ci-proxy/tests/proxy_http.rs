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
    proxy: Arc<PackageProxy>,
}

impl Harness {
    /// The job-facing URL for one upstream label under a given grant.
    fn url(&self, grant: &str, label: &str, tail: &str) -> String {
        format!("{}/j/{}/u/{}/{}", self.proxy_base, grant, label, tail)
    }
}

/// Bring up a fake upstream and a proxy in front of it, both on loopback.
async fn harness(rate: RateLimit) -> Harness {
    let creds = Arc::new(StaticCredentials::new().with("acme", "NPM_TOKEN", UPSTREAM_SECRET));
    stand_up(rate, |_| creds).await
}

/// The shared bring-up. `credentials` is built from the upstream's base URL because a broker-backed
/// source needs to know which secret names the allowlist references before it can mint anything.
async fn stand_up<F>(rate: RateLimit, credentials: F) -> Harness
where
    F: FnOnce(&str) -> Arc<dyn hull_ci_proxy::UpstreamCredentials>,
{
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

    let audit = Arc::new(MemoryAudit::new());
    let grants = Arc::new(GrantRegistry::new());
    let proxy = Arc::new(
        PackageProxy::new(allowlist, credentials(&upstream_base))
            .with_audit(audit.clone())
            .with_grants(grants.clone()),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serving = Arc::clone(&proxy);
    tokio::spawn(async move { serving.serve(listener).await.unwrap() });

    let _ = rate;
    Harness { proxy_base: format!("http://{addr}"), seen, audit, grants, upstream_base, proxy }
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

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The broker path
//
// Everything above proves the proxy's *rules* over a socket, with a development credential map
// standing in for the real source. This section replaces that map with the actual secret broker —
// per-tenant KEK envelope encryption, an enrolled proxy principal, and a job-scoped single-use
// capability minted alongside each job's package grant (D§7.4, `hull_ci_secrets::package`).
//
// It is a separate section rather than a parameterisation of the tests above because the questions
// are different. Above: does the proxy spend a credential correctly? Here: whose credential, on
// whose authority, and for how long — which are the questions a static map cannot be asked.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

use hull_ci_proto::AuthorClass;
use hull_ci_proxy::brokered::{BrokeredCredentials, InProcessRedeemer};
use hull_ci_proxy::credentials::NoCredentials;
use hull_ci_secrets::{
    DevKeyManager, MemorySealedStore, ProxyCapabilityRequest, ProxyCredentialService, ProxyIdentity,
    ProxyRegistry, SecretBroker,
};

/// The second tenant's credential. Distinct from [`UPSTREAM_SECRET`] and stored under the **same
/// name**, which is what makes "a tenant cannot obtain another tenant's credential" a real question
/// rather than a naming coincidence.
const GLOBEX_SECRET: &str = "globex_s3cr3t_do_not_leak";

struct Brokered {
    service: Arc<ProxyCredentialService>,
    creds: Arc<BrokeredCredentials>,
}

impl Brokered {
    /// Do what control does at placement: mint the job's package grant *and* the proxy's
    /// credential capability for it, then register the capability with the proxy.
    ///
    /// Returns the grant token the job would be handed. The two mints happen together on purpose —
    /// the proxy's authority to spend the tenant's credential exists because this job does.
    fn place(&self, h: &Harness, tenant: &str, job_id: &str, class: AuthorClass) -> String {
        let expires_at = now() + 3_600;
        let (token, _) =
            h.grants.mint(tenant, job_id, upstreams(&["private", "public"]), expires_at, RateLimit::default());

        match self.service.mint(&ProxyCapabilityRequest {
            tenant: tenant.into(),
            job_id: job_id.into(),
            proxy_id: "proxy-a".into(),
            // What the deployment allowlist says this job's granted upstreams need.
            declared: h
                .proxy
                .allowlist()
                .credential_names_for(["private", "public"])
                .into_iter()
                .collect(),
            author_class: class,
            expires_at,
        }) {
            Ok((capability, _)) => self.creds.authorise_job(tenant, job_id, capability),
            // The outsider path, exactly as a composition root drives it: the broker refuses, so
            // control registers the refusal rather than leaving the job unknown.
            Err(e) => self.creds.deny_job(tenant, job_id, e.to_string()),
        }
        token.expose().to_string()
    }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// The proxy in front of the real broker, with two tenants who each hold a registry token.
async fn brokered_harness() -> (Harness, Brokered) {
    let broker =
        Arc::new(SecretBroker::new(Arc::new(DevKeyManager::new()), Arc::new(MemorySealedStore::new())));
    for (tenant, value) in [("acme", UPSTREAM_SECRET), ("globex", GLOBEX_SECRET)] {
        broker.provision_tenant(tenant).unwrap();
        broker.put_secret(tenant, "NPM_TOKEN", value.as_bytes()).unwrap();
    }
    let service = Arc::new(ProxyCredentialService::new(broker, Arc::new(ProxyRegistry::new())));

    let identity = Arc::new(ProxyIdentity::generate());
    service.enrol_proxy("proxy-a", identity.public()).unwrap();
    let creds = Arc::new(BrokeredCredentials::new(
        identity,
        Arc::new(InProcessRedeemer::new(Arc::clone(&service))),
    ));

    let for_proxy = Arc::clone(&creds);
    let h = stand_up(RateLimit::default(), move |_| for_proxy).await;
    (h, Brokered { service, creds })
}

#[tokio::test]
async fn a_brokered_credential_reaches_the_upstream_and_never_the_job() {
    // The strengthened version of this crate's most important assertion. The credential now comes
    // out of an envelope-encrypted store via a single-use capability, and the job must still see no
    // trace of it — not in a success, not in an upstream 401, not in a refusal the proxy itself
    // wrote, and not in a redirect it followed. Every one of those is a *different* response
    // constructor, and it only takes one of them to be a copy-and-remove for the guarantee to fail.
    let (h, b) = brokered_harness().await;
    let token = b.place(&h, "acme", "job-1", AuthorClass::Member);

    let mut bodies = Vec::new();
    for tail in ["pkg", "needs-auth", "redirect-internal", "redirect-offlist", "../escape"] {
        let response = client().get(h.url(&token, "private", tail)).send().await.unwrap();
        for (name, value) in response.headers().iter() {
            let rendered = format!("{name}: {}", value.to_str().unwrap_or(""));
            assert!(!rendered.contains(UPSTREAM_SECRET), "credential in a response header: {rendered}");
        }
        assert!(response.headers().get("www-authenticate").is_none());
        assert!(response.headers().get("set-cookie").is_none());
        bodies.push(response.text().await.unwrap());
    }
    for body in &bodies {
        assert!(!body.contains(UPSTREAM_SECRET), "credential in a job-visible body: {body}");
    }
    assert_eq!(bodies[0], "package-bytes", "…and the fetch genuinely worked");

    // The upstream *did* receive it, which is what makes the above a result rather than an artefact
    // of the credential never being spent at all.
    let seen = h.seen.lock().unwrap();
    assert!(
        seen.authorization.iter().any(|a| a.as_deref() == Some(&*format!("Bearer {UPSTREAM_SECRET}"))),
        "the broker's value never reached the upstream: {seen:?}"
    );

    // Nor does it reach the audit trail, which is the other thing a job's operator reads.
    for fetch in h.audit.fetches() {
        assert!(!format!("{fetch:?}").contains(UPSTREAM_SECRET));
    }
    for refusal in h.audit.refusals() {
        assert!(!format!("{refusal:?}").contains(UPSTREAM_SECRET));
    }
}

#[tokio::test]
async fn a_tenant_cannot_obtain_another_tenants_upstream_credential() {
    // Both tenants have a secret named `NPM_TOKEN`, both jobs reach the same upstream through the
    // same proxy process, and each must spend its own. This is the D§1 "secret bleed" row, checked
    // where it would actually break: a single shared process holding both.
    let (h, b) = brokered_harness().await;
    let acme = b.place(&h, "acme", "job-acme", AuthorClass::Member);
    let globex = b.place(&h, "globex", "job-globex", AuthorClass::Member);

    assert_eq!(client().get(h.url(&acme, "private", "pkg")).send().await.unwrap().status(), 200);
    assert_eq!(
        h.seen.lock().unwrap().authorization.last().unwrap().as_deref(),
        Some(&*format!("Bearer {UPSTREAM_SECRET}"))
    );

    assert_eq!(client().get(h.url(&globex, "private", "pkg")).send().await.unwrap().status(), 200);
    let seen = h.seen.lock().unwrap();
    assert_eq!(
        seen.authorization,
        vec![
            Some(format!("Bearer {UPSTREAM_SECRET}")),
            Some(format!("Bearer {GLOBEX_SECRET}")),
        ],
        "each job spent its own tenant's token, in order, and neither ever spent the other's"
    );
}

#[tokio::test]
async fn a_grant_whose_tenant_disagrees_with_the_registration_is_refused_not_resolved() {
    // The cross-tenant *bug* shape rather than the attack shape: the job's package grant says one
    // tenant and the capability the proxy holds for that job says another. Serving either would be a
    // disclosure, so neither is preferred.
    let (h, b) = brokered_harness().await;
    // Control registered the job's credential capability under `acme`…
    b.place(&h, "acme", "job-x", AuthorClass::Member);
    // …and minted the package grant for `globex` under the same job id.
    let (mismatched, _) = h.grants.mint(
        "globex",
        "job-x",
        upstreams(&["private"]),
        now() + 3_600,
        RateLimit::default(),
    );

    let response = client().get(h.url(mismatched.expose(), "private", "pkg")).send().await.unwrap();
    assert_eq!(response.status(), 403, "a policy refusal, not an outage");
    let body = response.text().await.unwrap();
    assert!(body.contains("registered under tenant"), "{body}");
    assert!(!body.contains(UPSTREAM_SECRET) && !body.contains(GLOBEX_SECRET));
    assert!(h.seen.lock().unwrap().paths.is_empty(), "no request went upstream on either token");
}

#[tokio::test]
async fn an_outsider_authored_job_cannot_spend_the_tenants_registry_credential() {
    // Decided in `hull_ci_secrets::package`: the job never sees the value, but *use* is authority —
    // a fork PR that can make the proxy fetch a private package has pulled it into a build it
    // controls. The refusal is per-upstream, so the public one in the same grant still resolves.
    let (h, b) = brokered_harness().await;
    let token = b.place(&h, "acme", "job-fork", AuthorClass::Outsider);

    let response = client().get(h.url(&token, "private", "pkg")).send().await.unwrap();
    assert_eq!(response.status(), 403, "the author's authority, not an infrastructure failure");
    let body = response.text().await.unwrap();
    assert!(body.contains("outsider"), "the refusal has to be actionable by the author: {body}");
    assert!(h.seen.lock().unwrap().paths.is_empty(), "nothing was fetched on the tenant's token");

    // …and the same fork PR still builds against anything public.
    let response = client().get(h.url(&token, "public", "pkg")).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(h.seen.lock().unwrap().authorization.last().unwrap(), &None);
}

#[tokio::test]
async fn revoking_a_tenant_stops_its_proxy_access() {
    // D§7.4 break-glass path one, checked at the proxy. Revocation must bite *before* the capability
    // is spent, which is why the fetch below is this job's first.
    let (h, b) = brokered_harness().await;
    let token = b.place(&h, "acme", "job-1", AuthorClass::Member);
    assert_eq!(b.service.broker().revoke_tenant("acme"), 1, "the proxy capability, revoked with the rest");

    let response = client().get(h.url(&token, "private", "pkg")).send().await.unwrap();
    assert_eq!(response.status(), 502);
    assert!(response.text().await.unwrap().contains("revoked"));
    assert!(h.seen.lock().unwrap().paths.is_empty());
}

#[tokio::test]
async fn crypto_shredding_a_tenant_stops_its_proxy_access_and_leaves_others_alone() {
    // Break-glass path two. Deleting the KEK makes the tenant's stored registry token unrecoverable
    // — including from any backup — and the proxy simply cannot serve it any more.
    let (h, b) = brokered_harness().await;
    let acme = b.place(&h, "acme", "job-acme", AuthorClass::Member);
    let globex = b.place(&h, "globex", "job-globex", AuthorClass::Member);

    b.service.broker().shred_tenant("acme").unwrap();

    let response = client().get(h.url(&acme, "private", "pkg")).send().await.unwrap();
    assert_eq!(response.status(), 502);
    assert!(!response.text().await.unwrap().contains(UPSTREAM_SECRET));

    // Blast-radius isolation: one KEK per tenant is what makes this a local event.
    assert_eq!(client().get(h.url(&globex, "private", "pkg")).send().await.unwrap().status(), 200);
    assert_eq!(
        h.seen.lock().unwrap().authorization.last().unwrap().as_deref(),
        Some(&*format!("Bearer {GLOBEX_SECRET}"))
    );
}

#[tokio::test]
async fn releasing_a_job_drops_its_grant_and_its_credentials_together() {
    // §14.1's "nothing survives into the next job", applied to the two pieces of a job's state that
    // do not live in a rootfs. One call, because the half that gets forgotten when they are two is
    // always the one that frees a secret.
    let (h, b) = brokered_harness().await;
    let token = b.place(&h, "acme", "job-1", AuthorClass::Member);
    assert_eq!(client().get(h.url(&token, "private", "pkg")).send().await.unwrap().status(), 200);
    assert_eq!(b.creds.live_jobs(), 1);

    assert_eq!(h.proxy.release_job("job-1"), 1);
    assert_eq!(b.creds.live_jobs(), 0, "the credential went with the grant");
    assert_eq!(client().get(h.url(&token, "private", "pkg")).send().await.unwrap().status(), 401);
}

#[tokio::test]
async fn a_job_the_proxy_was_never_told_about_is_refused_rather_than_served() {
    // A package grant minted without the matching credential capability — the wiring bug. It fails
    // closed, and the refusal names the bug rather than blaming the registry.
    let (h, b) = brokered_harness().await;
    let (orphan, _) =
        h.grants.mint("acme", "ghost", upstreams(&["private"]), now() + 3_600, RateLimit::default());
    let _ = &b;

    let response = client().get(h.url(orphan.expose(), "private", "pkg")).send().await.unwrap();
    assert_eq!(response.status(), 502);
    let body = response.text().await.unwrap();
    assert!(body.contains("no upstream-credential capability"), "{body}");
    assert!(h.seen.lock().unwrap().paths.is_empty(), "never sent anonymously in its place");
}

#[tokio::test]
async fn with_no_credential_source_an_authenticated_upstream_is_refused_not_downgraded() {
    // The honest-degradation rule, over a socket: a proxy with no broker refuses the upstreams that
    // need one and serves the ones that do not. It never makes the request anonymously, because a
    // deployment that looks configured and is quietly unauthenticated is the one failure mode this
    // path must not have.
    let h = stand_up(RateLimit::default(), |_| Arc::new(NoCredentials)).await;
    let (token, _) = h.grants.mint(
        "acme",
        "job-1",
        upstreams(&["private", "public"]),
        now() + 3_600,
        RateLimit::default(),
    );

    let response = client().get(h.url(token.expose(), "private", "pkg")).send().await.unwrap();
    assert_eq!(response.status(), 502);
    assert!(response.text().await.unwrap().contains("no credential source"));
    assert!(h.seen.lock().unwrap().paths.is_empty(), "no anonymous request in place of the refusal");

    // A public upstream is unaffected: it never wanted a credential.
    assert_eq!(client().get(h.url(token.expose(), "public", "pkg")).send().await.unwrap().status(), 200);
    assert_eq!(h.seen.lock().unwrap().authorization.last().unwrap(), &None);
}

#[tokio::test]
async fn one_capability_serves_a_whole_install_and_a_concurrent_burst() {
    // The shape mismatch this design resolves: a single-use capability against the hundreds of
    // parallel requests an `npm install` makes. Redeemed once, then served from memory — a lost race
    // here would surface as an intermittent build failure, which is why the redemption is
    // serialised per job.
    let (h, b) = brokered_harness().await;
    let token = b.place(&h, "acme", "job-1", AuthorClass::Member);

    let mut requests = Vec::new();
    for _ in 0..24 {
        let url = h.url(&token, "private", "pkg");
        requests.push(tokio::spawn(async move { client().get(url).send().await.unwrap().status() }));
    }
    for request in requests {
        assert_eq!(request.await.unwrap(), 200);
    }
    let seen = h.seen.lock().unwrap();
    assert_eq!(seen.paths.len(), 24);
    assert!(
        seen.authorization.iter().all(|a| a.as_deref() == Some(&*format!("Bearer {UPSTREAM_SECRET}"))),
        "every request carried the credential, and none of them raced the capability away"
    );
}
