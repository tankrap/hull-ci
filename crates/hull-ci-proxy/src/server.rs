//! The HTTP surface: the one endpoint a sandbox may reach.
//!
//! # Why this terminates instead of tunnelling
//!
//! The obvious build for "let a job reach a registry" is a `CONNECT` forward proxy: point
//! `https_proxy` at it and let TLS pass through. This one refuses `CONNECT` outright, because a
//! tunnel cannot do the two things §14.3 and D§7.4 actually ask for.
//!
//! * D§7.4: "the proxy holds upstream registry credentials and **authenticates outbound**." Inside a
//!   `CONNECT` tunnel the TLS session is between the *job* and the upstream. The proxy has no place
//!   to put a credential, so the only way to authenticate is to give the credential to the job —
//!   which is the exact thing the sentence exists to prevent.
//! * §14.3 and D§7.5 want to know what a job fetched. A tunnel sees an SNI hostname and a byte
//!   count. It cannot tell "resolved `express`" from "uploaded the workspace", so the allowlist
//!   degrades from a rule about *requests* to a rule about *hosts*, and an allowlisted host becomes a
//!   general-purpose bidirectional egress channel out of a sandbox that otherwise has none.
//!
//! So the job speaks **plain HTTP to the proxy**, and the proxy speaks **authenticated HTTPS to the
//! upstream**. This is what every real package proxy does (Artifactory, Nexus, Verdaccio), and it is
//! why the job-facing URL is a mirror URL rather than a `*_proxy` variable.
//!
//! Plain HTTP on the job-facing side is not a downgrade in this deployment: that hop lives entirely
//! inside the sandbox network, which is an isolated segment with exactly two endpoints on it
//! (D§7.3). The transport that matters — proxy to upstream — is TLS, and it is the hop the job
//! cannot influence.
//!
//! # Two request shapes
//!
//! | shape | example | who sends it |
//! |---|---|---|
//! | mirror | `GET /j/<grant>/u/npm/express` | `npm`, `pip`, `cargo` configured with a registry URL |
//! | absolute-form | `GET https://registry.npmjs.org/express` + `Proxy-Authorization` | an `http_proxy`-aware client |
//!
//! Both run the identical policy path — [`Allowlist`], grant, method, credential — so there is no
//! second, weaker door.
//!
//! # Headers are rebuilt, never copied
//!
//! In both directions. §14.2's environment discipline ("Everything else is dropped, not filtered, so
//! an added host variable can't leak by default") is the same argument, and header forwarding fails
//! the same way: copy-and-remove leaks whatever nobody thought of. So [`REQUEST_HEADERS`] and
//! [`RESPONSE_HEADERS`] are literal lists, and anything absent from them does not travel.

use std::sync::Arc;

use axum::body::Body;
use axum::http::header::{HeaderMap, HeaderName, HeaderValue};
use axum::http::{Method, Request, Response, StatusCode, Uri};
use axum::Router;
use bytes::Bytes;
use hull_ci_secrets::{Clock, SystemClock};
use url::Url;

use crate::allowlist::{check_method, Allowlist, DenyReason, Upstream};
use crate::audit::{redact_path, AuditSink, Fetch, Refusal, TracingAudit};
use crate::credentials::{inject, CredentialError, Injected, UpstreamCredentials};
use crate::grant::{Grant, GrantError, GrantRegistry, GrantToken};

/// Request headers forwarded to an upstream. Everything else is dropped.
///
/// Note what is **absent** and why it matters: `authorization` and `cookie` (the job's own, which
/// must never reach an upstream — auth terminates here), `proxy-authorization` (the grant token,
/// which is meaningless upstream and is a credential), `host` and `x-forwarded-*` (rebuilt by the
/// client from the resolved URL; forwarding the job's would let it lie about where it is).
pub const REQUEST_HEADERS: &[&str] = &[
    "accept",
    "accept-encoding",
    "user-agent",
    "if-none-match",
    "if-modified-since",
    "range",
    // npm sends these on every request and some registries vary on them.
    "npm-command",
    "npm-session",
];

/// Response headers returned to the job. Everything else is dropped.
///
/// `set-cookie`, `www-authenticate` and `proxy-authenticate` are the security-relevant absences: an
/// upstream 401 routinely quotes the credential it rejected in `www-authenticate`, and a cookie is a
/// credential the job has no business holding.
pub const RESPONSE_HEADERS: &[&str] = &[
    "content-type",
    "content-length",
    "content-encoding",
    "etag",
    "last-modified",
    "cache-control",
    "accept-ranges",
    "content-range",
    "vary",
];

/// How many redirects the proxy will follow.
///
/// Followed *here* rather than by the HTTP client, because each hop has to be re-run through the
/// allowlist and re-credentialed. A client-followed redirect either carries the `Authorization`
/// header to a host nobody allowlisted (the classic credential-leak-by-redirect) or drops it and
/// fails confusingly; neither is a decision to delegate.
pub const MAX_REDIRECTS: u8 = 5;

/// Everything a request needs. Cheap to clone: the expensive members are behind `Arc`.
#[derive(Clone)]
pub struct ProxyState {
    allowlist: Arc<Allowlist>,
    grants: Arc<GrantRegistry>,
    credentials: Arc<dyn UpstreamCredentials>,
    audit: Arc<dyn AuditSink>,
    clock: Arc<dyn Clock>,
    client: reqwest::Client,
    max_redirects: u8,
}

impl std::fmt::Debug for ProxyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyState")
            .field("upstreams", &self.allowlist.labels())
            .field("live_grants", &self.grants.len())
            .finish()
    }
}

/// The package proxy.
#[derive(Debug, Clone)]
pub struct PackageProxy {
    state: ProxyState,
}

impl PackageProxy {
    /// Build a proxy over an allowlist and a credential source.
    ///
    /// The allowlist is fixed at construction. There is no route that edits it, and no reload: a
    /// proxy whose allowlist can change at runtime is a proxy whose allowlist can be changed by
    /// whoever finds a way to talk to it, and the set of hosts a fleet may reach is a deployment
    /// decision, not a request-time one.
    ///
    /// Says at startup whether the credential posture is coherent. An authenticated upstream with no
    /// credential source refuses every request for that upstream, and it refuses them *correctly* —
    /// but a deployment discovering that from a failed build hours later is a deployment that looked
    /// configured and was not, which is the one failure mode the credential path must never have.
    pub fn new(allowlist: Allowlist, credentials: Arc<dyn UpstreamCredentials>) -> Self {
        if allowlist.has_authenticated_upstream() {
            tracing::info!(
                source = ?credentials,
                "package proxy will authenticate outbound for at least one upstream; \
                 credentials come from this source and never enter a job (D§7.4)"
            );
        }
        PackageProxy {
            state: ProxyState {
                allowlist: Arc::new(allowlist),
                grants: Arc::new(GrantRegistry::new()),
                credentials,
                audit: Arc::new(TracingAudit),
                clock: Arc::new(SystemClock),
                client: default_client(),
                max_redirects: MAX_REDIRECTS,
            },
        }
    }

    pub fn with_audit(mut self, audit: Arc<dyn AuditSink>) -> Self {
        self.state.audit = audit;
        self
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.state.clock = clock;
        self
    }

    pub fn with_grants(mut self, grants: Arc<GrantRegistry>) -> Self {
        self.state.grants = grants;
        self
    }

    /// Where the control plane mints a job's grant.
    pub fn grants(&self) -> &Arc<GrantRegistry> {
        &self.state.grants
    }

    pub fn allowlist(&self) -> &Allowlist {
        &self.state.allowlist
    }

    /// End a job: drop its bearer **and** anything its credential source is holding for it.
    ///
    /// One call rather than two, because the two halves are the same fact — §14.1's "nothing
    /// survives into the next job" — and the half that gets forgotten when they are separate is
    /// always the one that frees a secret. A composition root that revoked the grant and left the
    /// credential in memory would have a proxy holding a tenant's registry token for a job that no
    /// longer exists, which is exactly the standing access this design refuses to have.
    pub fn release_job(&self, job_id: &str) -> usize {
        let dropped = self.state.grants.revoke_job(job_id);
        self.state.credentials.release_job(job_id);
        dropped
    }

    /// The router. A single fallback rather than a route table, because a forward proxy's "path" is
    /// the request, and a 404 from a route matcher would be indistinguishable from an upstream 404.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/healthz", axum::routing::get(healthz))
            .fallback(handle)
            .with_state(self.state.clone())
    }

    /// Serve until the process ends.
    pub async fn serve(&self, listener: tokio::net::TcpListener) -> std::io::Result<()> {
        axum::serve(listener, self.router()).await
    }
}

/// The upstream HTTP client.
///
/// `redirect(none)` is the load-bearing setting — see [`MAX_REDIRECTS`]. The timeouts exist because
/// an upstream that accepts a connection and then stalls would otherwise hold a job's step open
/// until §14.4's wall clock kills it, reported as a build failure rather than the network problem it
/// is.
fn default_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(300))
        .user_agent(concat!("hull-ci-proxy/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("a client with no TLS backend is a build misconfiguration, not a runtime condition")
}

/// Liveness. Unauthenticated and content-free on purpose: the node's network-posture probe
/// ([`hull_ci_node::container::probe_network_posture`]) calls it from inside the sandbox network to
/// confirm the proxy is the endpoint that answers there, and a probe that needed a grant could not
/// run before any job exists.
async fn healthz() -> &'static str {
    "ok\n"
}

/// What a request resolved to before any policy ran.
enum Target {
    /// `/j/<token>/u/<label>/<tail>`
    Mirror { token: GrantToken, label: String, tail: String },
    /// An absolute-form request URI, with the grant from `Proxy-Authorization`.
    Absolute { token: GrantToken, url: String },
}

fn parse_target(uri: &Uri, headers: &HeaderMap) -> Result<Target, String> {
    if uri.scheme().is_some() && uri.authority().is_some() {
        let token = bearer(headers)
            .ok_or_else(|| "absolute-form request without a Proxy-Authorization grant".to_string())?;
        return Ok(Target::Absolute { token, url: uri.to_string() });
    }
    let path_and_query = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let rest = path_and_query
        .strip_prefix("/j/")
        .ok_or_else(|| "not a package-proxy URL (expected /j/<grant>/u/<upstream>/…)".to_string())?;
    let (token, rest) = rest
        .split_once('/')
        .ok_or_else(|| "not a package-proxy URL (expected /j/<grant>/u/<upstream>/…)".to_string())?;
    let rest = rest
        .strip_prefix("u/")
        .ok_or_else(|| "not a package-proxy URL (expected /j/<grant>/u/<upstream>/…)".to_string())?;
    let (label, tail) = match rest.split_once('/') {
        Some((l, t)) => (l, t),
        // `/j/<t>/u/npm` with no tail is the registry root, which npm does ask for.
        None => (rest, ""),
    };
    Ok(Target::Mirror {
        token: GrantToken::from_wire(token),
        label: label.to_string(),
        tail: tail.to_string(),
    })
}

fn bearer(headers: &HeaderMap) -> Option<GrantToken> {
    for name in ["proxy-authorization", "authorization"] {
        if let Some(v) = headers.get(name).and_then(|v| v.to_str().ok()) {
            if let Some(rest) = v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")) {
                return Some(GrantToken::from_wire(rest.trim()));
            }
        }
    }
    None
}

/// Everything a refusal needs to become both a response and an audit record.
///
/// Two texts, not one, and the split is a control rather than tidiness. `reason` is the rule that
/// fired and goes to the **audit sink**, which an operator reads. `public` is what goes back to the
/// **job**, which is untrusted code, and for some refusals it has to say strictly less — see
/// [`Denied::from`] for [`DenyReason`].
struct Denied {
    status: StatusCode,
    reason: String,
    public: String,
}

impl Denied {
    /// A refusal whose rule is safe to hand back verbatim.
    fn new(status: StatusCode, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Denied { status, public: reason.clone(), reason }
    }

    /// A refusal that tells the audit more than it tells the job.
    fn opaque(status: StatusCode, reason: impl Into<String>, public: impl Into<String>) -> Self {
        Denied { status, reason: reason.into(), public: public.into() }
    }
}

/// What a job is told when it names an upstream it may not reach, for *any* of the reasons it may
/// not reach it.
///
/// One string for three refusals, because the difference between them is exactly the thing the
/// shared 403 exists to hide. See [`Denied::from`].
const UPSTREAM_UNAVAILABLE: &str = "that upstream is not available to this job";

impl From<DenyReason> for Denied {
    /// The status was already chosen to be uninformative; the **body** has to be too.
    ///
    /// "No upstream named `x` is allowlisted", "upstream `x` is not in this job's grant" and "host
    /// `h` is not allowlisted" are three different answers to one question a job should not get an
    /// answer to: *does this deployment have an upstream here, and is it mine?* A job that can tell
    /// them apart walks the label space one guess at a time and recovers the deployment's private
    /// registry topology — the internal mirror labels, which vendors are behind them, which of them
    /// its own tenant is scoped to — from a sandbox that has no other egress at all. Matching
    /// statuses stop that only if the bytes match too, and before this they did not.
    ///
    /// Everything else keeps its text. `PathEscape` and `OriginEscape` quote the job's own input
    /// back at it and reveal nothing it did not send, and `MethodNotAllowed` is a fact about the
    /// proxy rather than about the allowlist. The precise rule still reaches [`Refusal::reason`]
    /// either way, so an operator debugging a build loses nothing.
    fn from(d: DenyReason) -> Self {
        let status = match d {
            DenyReason::MethodNotAllowed(_) => StatusCode::METHOD_NOT_ALLOWED,
            // Everything else is a policy refusal, not a routing failure. 403 rather than 404 so a
            // job cannot probe which upstreams exist by timing or status.
            _ => StatusCode::FORBIDDEN,
        };
        match d {
            DenyReason::UnknownUpstream(_)
            | DenyReason::NotGranted(_)
            | DenyReason::HostNotAllowlisted(_) => {
                Denied::opaque(status, d.to_string(), UPSTREAM_UNAVAILABLE)
            }
            other => Denied::new(status, other.to_string()),
        }
    }
}

impl From<GrantError> for Denied {
    fn from(g: GrantError) -> Self {
        let status = match g {
            GrantError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            _ => StatusCode::UNAUTHORIZED,
        };
        Denied::new(status, g.to_string())
    }
}

impl From<CredentialError> for Denied {
    /// Two statuses, and which one depends on *whose* problem it is
    /// ([`CredentialError::is_policy_refusal`]).
    ///
    /// A misconfigured or unwired credential is the operator's, and 502 says so: the job's request
    /// was fine and the proxy could not complete it. A job with no authority to spend a tenant
    /// credential — an `outsider`-authored one (D§7.4), or a cross-tenant mismatch — is 403, on the
    /// same footing as an upstream outside its grant, because it is the same kind of answer: the
    /// request was understood and refused. Reporting that as 502 would tell a fork PR's author their
    /// build hit an infrastructure problem, and would tell an operator to go looking for one.
    fn from(c: CredentialError) -> Self {
        let status =
            if c.is_policy_refusal() { StatusCode::FORBIDDEN } else { StatusCode::BAD_GATEWAY };
        Denied::new(status, c.to_string())
    }
}

async fn handle(
    axum::extract::State(state): axum::extract::State<ProxyState>,
    req: Request<Body>,
) -> Response<Body> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let logged_path = redact_path(uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"));

    let refuse = |job: Option<String>, d: Denied| -> Response<Body> {
        state.audit.refused(&Refusal {
            job_id: job,
            method: method.to_string(),
            path: logged_path.clone(),
            reason: d.reason.clone(),
            status: d.status.as_u16(),
        });
        // `public`, never `reason`: the audit record above is the operator's copy, and this one goes
        // to untrusted code.
        text(d.status, &format!("hull-ci package proxy: {}\n", d.public))
    };

    // `CONNECT` first, and by name, because it is the request whose *refusal* is the design decision
    // (see the module doc) rather than an incidental method check.
    if method == Method::CONNECT {
        return refuse(
            None,
            Denied::new(
                StatusCode::METHOD_NOT_ALLOWED,
                "CONNECT is not served: this proxy terminates requests so it can authenticate \
                 outbound and record what was fetched (§14.3, D§7.4)",
            ),
        );
    }

    let target = match parse_target(&uri, &headers) {
        Ok(t) => t,
        Err(e) => return refuse(None, Denied::new(StatusCode::BAD_REQUEST, e)),
    };

    let token = match &target {
        Target::Mirror { token, .. } | Target::Absolute { token, .. } => token,
    };
    let grant = match state.grants.authorise(token, state.clock.now_secs()) {
        Ok(g) => g,
        Err(e) => return refuse(None, e.into()),
    };
    let job = Some(grant.job_id.clone());

    if let Err(e) = check_method(method.as_str()) {
        return refuse(job, e.into());
    }

    let resolved = match &target {
        Target::Mirror { label, tail, .. } => state.allowlist.resolve(label, tail),
        Target::Absolute { url, .. } => state.allowlist.resolve_absolute(url),
    };
    let (upstream, url) = match resolved {
        Ok(v) => v,
        Err(e) => return refuse(job, e.into()),
    };

    // The per-job half of the allowlist. The deployment decides what *exists*; the grant decides
    // what *this job* may reach, and the grant's set was fixed when the job was placed.
    if !grant.upstreams.contains(&upstream.name) {
        return refuse(job, DenyReason::NotGranted(upstream.name.clone()).into());
    }

    match forward(&state, &grant, upstream, url, &method, &headers).await {
        Ok(response) => response,
        Err(d) => refuse(job, d),
    }
}

/// Make the outbound request, following allowlisted redirects, and stream the answer back.
async fn forward(
    state: &ProxyState,
    grant: &Grant,
    upstream: &Upstream,
    url: Url,
    method: &Method,
    headers: &HeaderMap,
) -> Result<Response<Body>, Denied> {
    let mut upstream = upstream;
    let mut url = url;
    let mut redirects = 0u8;

    loop {
        // The credential is derived from the *authenticated grant*, never from anything in the
        // request: the grant's tenant and job were fixed when control minted it, and the credential
        // source refuses a lookup whose job it was not told about (D§7.4, [`crate::brokered`]).
        let injected = inject(upstream, grant, state.credentials.as_ref())?;
        let authenticated = injected.is_some();
        let response = send(state, method, &url, headers, injected.as_ref()).await?;
        let status = response.status().as_u16();

        if let Some(location) = redirect_target(&response) {
            if redirects >= state.max_redirects {
                return Err(Denied::new(
                    StatusCode::BAD_GATEWAY,
                    format!("upstream redirected more than {} times", state.max_redirects),
                ));
            }
            // Resolve relative to the URL we just fetched, then re-run the *whole* allowlist on the
            // result. This is the hop where a credential would otherwise walk off the allowlist.
            let next = url.join(&location).map_err(|_| {
                Denied::new(StatusCode::BAD_GATEWAY, format!("upstream sent an unusable redirect to `{location}`"))
            })?;
            let (next_upstream, next_url) =
                state.allowlist.resolve_absolute(next.as_str()).map_err(Denied::from)?;
            if !grant.upstreams.contains(&next_upstream.name) {
                return Err(DenyReason::NotGranted(next_upstream.name.clone()).into());
            }
            redirects += 1;
            upstream = next_upstream;
            url = next_url;
            continue;
        }

        let declared_bytes = response.content_length().unwrap_or(0);
        let record = Fetch {
            tenant: grant.tenant.clone(),
            job_id: grant.job_id.clone(),
            upstream: upstream.name.clone(),
            url: url.to_string(),
            method: method.to_string(),
            status,
            bytes: declared_bytes,
            authenticated,
            redirects,
        };
        return Ok(to_response(state, response, record));
    }
}

async fn send(
    state: &ProxyState,
    method: &Method,
    url: &Url,
    headers: &HeaderMap,
    injected: Option<&Injected>,
) -> Result<reqwest::Response, Denied> {
    let upstream_method = match method.as_str() {
        "GET" => reqwest::Method::GET,
        "HEAD" => reqwest::Method::HEAD,
        // Unreachable: `check_method` already ran. Refused rather than `unreachable!()` so that a
        // future edit to `ALLOWED_METHODS` cannot turn a policy change into a panic on a live proxy.
        other => return Err(DenyReason::MethodNotAllowed(other.to_string()).into()),
    };
    let mut request = state.client.request(upstream_method, url.clone());
    for name in REQUEST_HEADERS {
        if let Some(value) = headers.get(*name) {
            request = request.header(*name, value.clone());
        }
    }
    if let Some(injected) = injected {
        let value = reqwest::header::HeaderValue::from_bytes(injected.expose())
            .map_err(|_| Denied::new(StatusCode::BAD_GATEWAY, "credential is not a valid header value"))?;
        request = request.header(injected.header.as_str(), value);
    }
    request.send().await.map_err(|e| {
        // The upstream's own error text can quote a URL but never our credential — it is reqwest's
        // rendering of a transport failure. The upstream *host* is safe and is the useful part.
        Denied::new(StatusCode::BAD_GATEWAY, format!("upstream `{}` could not be reached: {}", host_of(url), transport_reason(&e)))
    })
}

fn redirect_target(response: &reqwest::Response) -> Option<String> {
    if !response.status().is_redirection() {
        return None;
    }
    response.headers().get("location")?.to_str().ok().map(str::to_string)
}

/// A [`Fetch`] record that is emitted when the response body is **dropped**, carrying the byte count
/// the body actually reached.
///
/// Emitting on `Drop` rather than at end-of-stream is not a stylistic choice; end-of-stream does not
/// reliably happen. When a response carries `Content-Length`, hyper stops polling the body the
/// instant that many bytes have been forwarded and never asks for the `None` that would signal the
/// end — so an emit-on-`None` audit silently records nothing for the overwhelming majority of real
/// package fetches, which is precisely the case §14.3 wants logged. `Drop` also catches the
/// interesting failures for free: a job that disconnects mid-tarball, and an upstream that dies
/// halfway, both still produce a record with the bytes that did cross.
struct AuditOnDrop {
    record: Option<Fetch>,
    bytes: u64,
    sink: Arc<dyn AuditSink>,
}

impl Drop for AuditOnDrop {
    fn drop(&mut self) {
        if let Some(mut record) = self.record.take() {
            record.bytes = self.bytes;
            self.sink.fetched(&record);
        }
    }
}

/// Turn an upstream response into the job-facing one, counting bytes as the body streams.
///
/// [`Fetch::bytes`] is what actually crossed rather than what `Content-Length` claimed. A chunked
/// response declares no length at all, and a job that wanted to move volume without it showing up in
/// the log would use exactly that.
fn to_response(state: &ProxyState, upstream: reqwest::Response, record: Fetch) -> Response<Body> {
    let status = StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let headers = response_headers(upstream.headers());
    let audit = AuditOnDrop { record: Some(record), bytes: 0, sink: state.audit.clone() };

    let stream = futures_util::stream::unfold(
        (upstream.bytes_stream(), audit),
        |(mut body, mut audit)| async move {
            use futures_util::StreamExt;
            match body.next().await {
                Some(Ok(chunk)) => {
                    audit.bytes += chunk.len() as u64;
                    Some((Ok::<Bytes, std::io::Error>(chunk), (body, audit)))
                }
                // The record still goes out — `audit` is dropped with the state when the stream
                // ends here — and records the bytes that made it across before the failure.
                Some(Err(e)) => Some((Err(std::io::Error::other(e.to_string())), (body, audit))),
                None => None,
            }
        },
    );

    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

/// Rebuild the response headers from [`RESPONSE_HEADERS`]. Never a copy-and-remove.
pub fn response_headers(upstream: &reqwest::header::HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for name in RESPONSE_HEADERS {
        if let Some(value) = upstream.get(*name) {
            if let (Ok(n), Ok(v)) =
                (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_bytes(value.as_bytes()))
            {
                out.insert(n, v);
            }
        }
    }
    out
}

fn host_of(url: &Url) -> String {
    url.host_str().unwrap_or("<none>").to_string()
}

/// A transport failure, described without echoing a URL that might carry a query the job wrote.
fn transport_reason(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "timed out"
    } else if e.is_connect() {
        "connection failed"
    } else if e.is_decode() {
        "response could not be decoded"
    } else {
        "request failed"
    }
}

fn text(status: StatusCode, body: &str) -> Response<Body> {
    let mut response = Response::new(Body::from(body.to_string()));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("text/plain; charset=utf-8"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn a_mirror_url_parses_into_a_grant_a_label_and_a_tail() {
        let uri: Uri = "/j/hpkg_aa.bb/u/npm/express/-/express-4.18.2.tgz".parse().unwrap();
        match parse_target(&uri, &HeaderMap::new()).unwrap() {
            Target::Mirror { token, label, tail } => {
                assert_eq!(token.expose(), "hpkg_aa.bb");
                assert_eq!(label, "npm");
                assert_eq!(tail, "express/-/express-4.18.2.tgz");
            }
            _ => panic!("expected the mirror shape"),
        }
    }

    #[test]
    fn a_mirror_url_keeps_the_query_string_the_job_sent() {
        // `pip` puts real meaning in the query, so dropping it silently breaks resolution.
        let uri: Uri = "/j/t/u/pypi/simple/?a=1".parse().unwrap();
        match parse_target(&uri, &HeaderMap::new()).unwrap() {
            Target::Mirror { tail, .. } => assert_eq!(tail, "simple/?a=1"),
            _ => panic!("expected the mirror shape"),
        }
    }

    #[test]
    fn a_registry_root_with_no_tail_is_a_valid_request() {
        let uri: Uri = "/j/t/u/npm".parse().unwrap();
        match parse_target(&uri, &HeaderMap::new()).unwrap() {
            Target::Mirror { label, tail, .. } => {
                assert_eq!(label, "npm");
                assert_eq!(tail, "");
            }
            _ => panic!("expected the mirror shape"),
        }
    }

    #[test]
    fn a_path_that_is_not_a_package_proxy_url_is_refused_before_any_lookup() {
        for path in ["/", "/express", "/u/npm/express", "/j/", "/admin"] {
            let uri: Uri = path.parse().unwrap();
            assert!(parse_target(&uri, &HeaderMap::new()).is_err(), "{path}");
        }
    }

    #[test]
    fn an_absolute_form_request_takes_its_grant_from_proxy_authorization() {
        let uri: Uri = "https://registry.npmjs.org/express".parse().unwrap();
        // Without a header there is no grant, so there is no request.
        assert!(parse_target(&uri, &HeaderMap::new()).is_err());

        let mut headers = HeaderMap::new();
        headers.insert("proxy-authorization", HeaderValue::from_static("Bearer hpkg_aa.bb"));
        match parse_target(&uri, &headers).unwrap() {
            Target::Absolute { token, url } => {
                assert_eq!(token.expose(), "hpkg_aa.bb");
                assert_eq!(url, "https://registry.npmjs.org/express");
            }
            _ => panic!("expected the absolute shape"),
        }
    }

    #[test]
    fn the_request_header_allowlist_drops_every_credential_carrier() {
        // The job's own `authorization` must not reach an upstream: auth terminates at the proxy.
        for banned in ["authorization", "cookie", "proxy-authorization", "host", "x-forwarded-for"] {
            assert!(!REQUEST_HEADERS.contains(&banned), "{banned} must not be forwarded");
        }
        assert!(REQUEST_HEADERS.contains(&"accept"));
        assert!(REQUEST_HEADERS.contains(&"range"), "range requests are how a large tarball resumes");
    }

    #[test]
    fn the_response_header_allowlist_drops_every_credential_carrier() {
        // `www-authenticate` on a 401 routinely quotes the credential the upstream rejected.
        for banned in ["set-cookie", "www-authenticate", "proxy-authenticate", "authorization"] {
            assert!(!RESPONSE_HEADERS.contains(&banned), "{banned} must not be returned");
        }
        let mut upstream = reqwest::header::HeaderMap::new();
        upstream.insert("content-type", reqwest::header::HeaderValue::from_static("application/json"));
        upstream.insert("set-cookie", reqwest::header::HeaderValue::from_static("session=abc"));
        upstream.insert(
            "www-authenticate",
            reqwest::header::HeaderValue::from_static("Bearer realm=\"x\", error=\"npm_s3cr3tvalue\""),
        );
        let out = response_headers(&upstream);
        assert_eq!(out.get("content-type").unwrap(), "application/json");
        assert!(out.get("set-cookie").is_none());
        assert!(out.get("www-authenticate").is_none());
        assert_eq!(out.len(), 1, "rebuilt from the allowlist, not copied and pruned");
    }

    #[test]
    fn the_refusal_body_does_not_leak_which_upstreams_exist_either() {
        // Matching statuses are only half of it. Before this, a job could send `/j/<g>/u/<label>/x`
        // for every label it could think of and read the deployment's allowlist straight out of the
        // 403 bodies — "no upstream named `x`" for one that does not exist, "not in this job's
        // grant" for one that does. The audit still records which was which.
        let absent = Denied::from(DenyReason::UnknownUpstream("acme-internal-mirror".into()));
        let present = Denied::from(DenyReason::NotGranted("acme-internal-mirror".into()));
        let host = Denied::from(DenyReason::HostNotAllowlisted("art.internal.test".into()));

        assert_eq!(absent.status, present.status);
        assert_eq!(absent.public, present.public, "the job must not be able to tell these apart");
        assert_eq!(host.public, present.public, "…including through the absolute-form door");
        assert!(!absent.public.contains("acme-internal-mirror"));
        assert!(!host.public.contains("art.internal.test"));

        // The operator's copy keeps every distinction that was taken away from the job.
        assert!(absent.reason.contains("no upstream named"));
        assert!(present.reason.contains("not in this job's grant"));
        assert!(host.reason.contains("art.internal.test"));

        // A refusal about the job's own input is still quoted back: it reveals nothing it did not
        // send, and a silent 403 there is just a broken pipeline nobody can debug.
        let escape = Denied::from(DenyReason::PathEscape("../../etc/passwd".into()));
        assert_eq!(escape.public, escape.reason);
    }

    #[test]
    fn deny_reasons_map_to_statuses_that_do_not_leak_which_upstreams_exist() {
        // 403 for both, so a job cannot enumerate the allowlist by watching for a 404.
        assert_eq!(Denied::from(DenyReason::UnknownUpstream("x".into())).status, StatusCode::FORBIDDEN);
        assert_eq!(Denied::from(DenyReason::NotGranted("npm".into())).status, StatusCode::FORBIDDEN);
        assert_eq!(
            Denied::from(DenyReason::MethodNotAllowed("PUT".into())).status,
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(Denied::from(GrantError::Invalid).status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            Denied::from(GrantError::RateLimited { limit: 1, burst: 1 }).status,
            StatusCode::TOO_MANY_REQUESTS
        );
        // A missing upstream credential is the operator's fault, and 502 says the job did nothing
        // wrong.
        assert_eq!(
            Denied::from(CredentialError::Missing { upstream: "x".into(), name: "Y".into() }).status,
            StatusCode::BAD_GATEWAY
        );
    }

    #[test]
    fn a_bearer_is_read_from_either_header_and_nowhere_else() {
        let mut headers = HeaderMap::new();
        assert!(bearer(&headers).is_none());
        headers.insert("authorization", HeaderValue::from_static("Basic abc"));
        assert!(bearer(&headers).is_none(), "only Bearer, and only ours");
        headers.insert("authorization", HeaderValue::from_static("Bearer hpkg_x.y"));
        assert_eq!(bearer(&headers).unwrap().expose(), "hpkg_x.y");
    }
}
