//! End-to-end: a tenant secret, from `HULL_CI_SECRETS=dev` to a variable inside a running job.
//!
//! Design D§7.4, milestone M3. Every seam here is the production one — the broker is the assembled
//! process's own, the node signs with the identity that assembly enrolled, and the verdict arrives
//! over HTTP at the real `callback_url`. Nothing in this file reaches past
//! [`hull_ci_secrets::SecretService`] into the broker, because the whole claim under test is that
//! the path *through* the service is the only path there is.
//!
//! ## What these tests are actually for
//!
//! D§7.4 warns that the node-binding failure is invisible: "the code reads as though it enforces node
//! binding either way, the tests pass either way, and the control silently does nothing until the
//! identity check exists." A test that only asserts "a member's job gets its secret" would pass
//! against a broker with no identity check at all. So the tests that matter here are the refusals —
//! [`a_capability_minted_for_this_node_cannot_be_redeemed_by_another`] and
//! [`a_node_whose_enrolment_is_withdrawn_cannot_redeem_and_its_step_does_not_run`] — and each is
//! written so it would fail if the derivation were replaced by a self-asserted `node_id`.
//!
//! ## Two host requirements, same as the sibling suite
//!
//! A `tree_id` computed with keel's own encoder, and `/bin/sh` for the pipeline's `run` strings. The
//! backend is the local-process one, because a docker daemon is not something a test may require.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use hull_ci_proto::{AuthorClass, SECRET_HEADER, VERSION_HEADER};
use hull_ci_secrets::{CapabilityRequest, NodeIdentity, SecretError, SecretService};
use hull_ci_server::admin::ADMIN_TOKEN_HEADER;
use hull_ci_server::config::{SandboxChoice, SecretsMode};
use hull_ci_server::membership::TrustedTenants;
use hull_ci_server::Config;

const SHARED_SECRET: &str = "s3cret-for-the-suite";
const ADMIN_TOKEN: &str = "admin-t0ken";
const NODE_ID: &str = "node-e2e";

/// The tenant secret under test. Long enough to be maskable (`MIN_MASKABLE_LEN`) and distinctive
/// enough that a substring search for it in a verdict, a log, or an admin response means something.
const SECRET_NAME: &str = "NPM_TOKEN";
const SECRET_VALUE: &str = "npm_s3cr3t_e2e_value_9f2a";

// ── The Hull stub ────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Received {
    secret: Option<String>,
    body: serde_json::Value,
}

impl Received {
    fn status(&self) -> &str {
        self.body["status"].as_str().unwrap_or("<missing>")
    }
    fn reason(&self) -> Option<&str> {
        self.body["reason"].as_str()
    }
    fn summary(&self) -> &str {
        self.body["summary"].as_str().unwrap_or("")
    }
    /// The whole callback body as text, for "the value is nowhere in here" assertions.
    fn raw(&self) -> String {
        self.body.to_string()
    }
}

#[derive(Clone, Default)]
struct HullState {
    archives: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    received: Arc<Mutex<Vec<Received>>>,
}

struct HullStub {
    addr: SocketAddr,
    state: HullState,
}

impl HullStub {
    async fn start() -> HullStub {
        let state = HullState::default();
        let app = Router::new()
            .route("/api/tree/:tree_id/tar", get(serve_tar))
            .route("/api/change/:change/ci-result", post(receive_verdict))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        HullStub { addr, state }
    }

    fn publish(&self, tree_id: &str, archive: Vec<u8>) {
        self.state.archives.lock().unwrap().insert(tree_id.to_string(), archive);
    }

    fn source_url(&self, tree_id: &str) -> String {
        format!("http://{}/api/tree/{tree_id}/tar", self.addr)
    }

    fn callback_url(&self) -> String {
        format!("http://{}/api/change/21ea2242186c99ff/ci-result", self.addr)
    }

    async fn verdict(&self) -> Received {
        for _ in 0..600 {
            if let Some(r) = self.state.received.lock().unwrap().first().cloned() {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("no verdict arrived within 30s — spec §7 says one always does");
    }
}

async fn serve_tar(
    State(state): State<HullState>,
    AxumPath(tree_id): AxumPath<String>,
) -> (StatusCode, Vec<u8>) {
    match state.archives.lock().unwrap().get(&tree_id) {
        Some(bytes) => (StatusCode::OK, bytes.clone()),
        None => (StatusCode::NOT_FOUND, Vec::new()),
    }
}

async fn receive_verdict(
    State(state): State<HullState>,
    AxumPath(_change): AxumPath<String>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, Json<serde_json::Value>) {
    let secret = headers.get(SECRET_HEADER).and_then(|v| v.to_str().ok()).map(str::to_string);
    let body: serde_json::Value = serde_json::from_str(&body).expect("the verdict is JSON");
    if secret.as_deref() != Some(SHARED_SECRET) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "unauthorized" })));
    }
    state.received.lock().unwrap().push(Received { secret, body });
    (StatusCode::OK, Json(serde_json::json!({ "recorded": true })))
}

// ── Trees ────────────────────────────────────────────────────────────────────────────────────────

fn keel_tree_id(dir: &Path) -> String {
    let keel_dir = tempfile::tempdir().unwrap();
    let store = keel_store::store::Store::open_with_map_size(keel_dir.path(), 64 * 1024 * 1024).unwrap();
    keel_store::snapshot::snapshot(&store, dir).unwrap().to_hex()
}

fn hull_style_archive(dir: &Path) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut ar = tar::Builder::new(&mut buf);
        ar.mode(tar::HeaderMode::Deterministic);
        ar.append_dir_all(".", dir).unwrap();
        ar.finish().unwrap();
    }
    buf
}

/// A tree whose pipeline declares [`SECRET_NAME`] and runs `star`.
fn secret_tree(star: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".hull")).unwrap();
    std::fs::write(dir.path().join(".hull/ci.star"), star).unwrap();
    dir
}

/// A tree whose step passes **only if the delivered value is exactly right**.
///
/// The expected value lives in a file in the tree rather than in the `run` string on purpose. An
/// argv comparison would put the secret into `Assignment::argv`, into the step's fallback summary,
/// and therefore into the verdict — which would make [`the_secret_value_reaches_no_report_surface`]
/// pass or fail for a reason that has nothing to do with delivery. `$(cat …)` keeps the check exact
/// and the value out of every record of it.
fn tree_that_checks_the_value(marker: &Path) -> tempfile::TempDir {
    let dir = secret_tree(&format!(
        r#"
step(
    "uses-secret",
    run = 'echo ran > "{}"; test "${}" = "$(cat expected.txt)"',
    secrets = ["{}"],
)
"#,
        marker.display(),
        SECRET_NAME,
        SECRET_NAME,
    ));
    std::fs::write(dir.path().join("expected.txt"), SECRET_VALUE).unwrap();
    dir
}

// ── The runner under test ────────────────────────────────────────────────────────────────────────

struct Runner {
    addr: SocketAddr,
    secrets: Arc<SecretService>,
    _work: tempfile::TempDir,
}

impl Runner {
    /// A runner with the dev broker on, one tenant provisioned, and one secret stored.
    ///
    /// The secret is stored through the *assembled* broker rather than a rebuilt one, so what these
    /// tests exercise is the wiring rather than a parallel copy of it.
    async fn start(trusted: &str) -> Runner {
        let work = tempfile::tempdir().unwrap();
        let config = Config {
            secret: Some(SHARED_SECRET.into()),
            store_root: work.path().join("store"),
            work_root: work.path().join("workspaces"),
            sandbox: SandboxChoice::LocalProcess,
            allow_unsandboxed: true,
            trusted: TrustedTenants::parse(trusted),
            node_id: NODE_ID.into(),
            secrets: SecretsMode::Dev,
            admin_token: Some(ADMIN_TOKEN.into()),
            ..Config::default()
        };

        let runner = hull_ci_server::assemble(&config).await.expect("the runner assembles");
        let secrets = runner.secrets.clone().expect("HULL_CI_SECRETS=dev wires a broker");
        secrets.broker().provision_tenant("acme").unwrap();
        secrets.broker().put_secret("acme", SECRET_NAME, SECRET_VALUE.as_bytes()).unwrap();

        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, runner.router).await.unwrap() });
        Runner { addr, secrets, _work: work }
    }

    async fn dispatch(&self, body: serde_json::Value) -> StatusCode {
        let resp = reqwest::Client::new()
            .post(format!("http://{}/hull", self.addr))
            .header(SECRET_HEADER, SHARED_SECRET)
            .header(VERSION_HEADER, "1")
            .json(&body)
            .send()
            .await
            .expect("the ingest endpoint answers");
        StatusCode::from_u16(resp.status().as_u16()).unwrap()
    }

    async fn admin(&self, path: &str) -> String {
        reqwest::Client::new()
            .get(format!("http://{}{path}", self.addr))
            .header(ADMIN_TOKEN_HEADER, ADMIN_TOKEN)
            .send()
            .await
            .expect("the admin endpoint answers")
            .text()
            .await
            .unwrap()
    }
}

fn dispatch_body(repo: &str, tree_id: &str, source_url: &str, callback_url: &str) -> serde_json::Value {
    serde_json::json!({
        "repo": repo,
        "change": "21ea2242186c99ff",
        "tree_id": tree_id,
        "intent": "wire the secret broker",
        "author": "justin",
        "source_url": source_url,
        "callback_url": callback_url,
    })
}

/// Publish the tree, dispatch it, wait for the callback. Returns the verdict and the live runner, so
/// a test can go on to interrogate the admin panel or the broker.
async fn run_one(repo: &str, trusted: &str, tree: &Path) -> (Received, Runner, HullStub) {
    let hull = HullStub::start().await;
    let tree_id = keel_tree_id(tree);
    hull.publish(&tree_id, hull_style_archive(tree));

    let runner = Runner::start(trusted).await;
    let status = runner
        .dispatch(dispatch_body(repo, &tree_id, &hull.source_url(&tree_id), &hull.callback_url()))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "dispatch was not accepted");

    let received = hull.verdict().await;
    assert_eq!(received.secret.as_deref(), Some(SHARED_SECRET), "spec §8 on every callback");
    (received, runner, hull)
}

fn marker_path() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("the-step-ran");
    (dir, path)
}

fn request(job_id: &str, node_id: &str) -> CapabilityRequest {
    CapabilityRequest {
        tenant: "acme".into(),
        job_id: job_id.into(),
        node_id: node_id.into(),
        declared: vec![SECRET_NAME.into()],
        author_class: AuthorClass::Member,
    }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ── Delivery ─────────────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_member_authored_job_receives_the_exact_value_it_declared() {
    // The feature, asserted the only way that means anything: the step compares `$NPM_TOKEN` against
    // the expected value and exits non-zero if they differ, so `green` is a statement that the right
    // bytes arrived inside the sandbox — not merely that a variable was set.
    let (_guard, marker) = marker_path();
    let tree = tree_that_checks_the_value(&marker);
    let (v, _runner, _hull) = run_one("acme/widget", "acme", tree.path()).await;

    assert_eq!(v.status(), "green", "the delivered value did not match: {}", v.summary());
    assert!(marker.exists(), "the step should have run");
}

#[tokio::test(flavor = "multi_thread")]
async fn with_no_broker_configured_the_same_pipeline_runs_without_its_secret() {
    // The `off` default, which is what every deployment gets unless it asks otherwise. The step is
    // identical; the variable is simply absent, so the comparison fails and the job is honestly red.
    // Red rather than errored is right: the step ran and said no.
    let (_guard, marker) = marker_path();
    let tree = tree_that_checks_the_value(&marker);

    let hull = HullStub::start().await;
    let tree_id = keel_tree_id(tree.path());
    hull.publish(&tree_id, hull_style_archive(tree.path()));

    let work = tempfile::tempdir().unwrap();
    let config = Config {
        secret: Some(SHARED_SECRET.into()),
        store_root: work.path().join("store"),
        work_root: work.path().join("workspaces"),
        sandbox: SandboxChoice::LocalProcess,
        allow_unsandboxed: true,
        trusted: TrustedTenants::parse("acme"),
        node_id: NODE_ID.into(),
        ..Config::default()
    };
    assert_eq!(config.secrets, SecretsMode::Off, "the default");
    let runner = hull_ci_server::assemble(&config).await.unwrap();
    assert!(runner.secrets.is_none(), "off means there is no broker at all, not a disabled one");

    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, runner.router).await.unwrap() });
    reqwest::Client::new()
        .post(format!("http://{addr}/hull"))
        .header(SECRET_HEADER, SHARED_SECRET)
        .json(&dispatch_body("acme/widget", &tree_id, &hull.source_url(&tree_id), &hull.callback_url()))
        .send()
        .await
        .unwrap();

    let v = hull.verdict().await;
    assert_eq!(v.status(), "red", "no secret, so the comparison fails: {}", v.summary());
    assert!(marker.exists(), "the step still ran — it just had nothing in the variable");
}

// ── The gate ─────────────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn an_outsider_authored_job_gets_no_secret_and_the_broker_refuses_to_mint() {
    // The pwn-request defence (D§7.4), end to end. The pipeline is byte-identical to the member case
    // above; only the actor differs.
    //
    // On this backend the refusal lands one step earlier than the broker: no M1 backend has
    // `admits_untrusted()`, so the isolation gate refuses an outsider's assignment before a
    // capability is ever minted (`InProcessFleet::assign` checks admission first). The job is
    // therefore `errored`, the step never runs, and no secret is delivered — but that is the
    // *isolation* gate doing the work, so the broker's own refusal is asserted directly underneath,
    // against the same assembled service the live path would have used. Both must hold: on a fleet
    // whose backend does admit untrusted work, the second one is the only one left.
    let (_guard, marker) = marker_path();
    let tree = tree_that_checks_the_value(&marker);
    let (v, runner, _hull) = run_one("evilcorp/widget", "acme", tree.path()).await;

    assert_eq!(v.status(), "errored", "a fork PR must not run on a backend that cannot box it");
    assert_eq!(v.reason(), Some("infra"));
    assert!(!marker.exists(), "the step must not have run");
    assert!(
        !v.raw().contains(SECRET_VALUE),
        "no secret may appear anywhere in an outsider's verdict: {}",
        v.raw()
    );

    // The broker's own refusal, on the assembled service: identical declaration, member vs outsider.
    let outsider =
        CapabilityRequest { author_class: AuthorClass::Outsider, ..request("job-x", NODE_ID) };
    assert_eq!(runner.secrets.mint(&outsider).unwrap_err(), SecretError::OutsiderRefused);
    assert!(runner.secrets.mint(&request("job-x", NODE_ID)).is_ok(), "the member case is fine");
}

// ── Node identity ────────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_capability_minted_for_this_node_cannot_be_redeemed_by_another() {
    // **The test D§7.4 says is easy to write wrongly.** A second node is enrolled — properly, with
    // its own keypair — and presents a capability minted for `node-e2e`. It signs correctly. It is
    // refused, because it never *states* a node id: the service derives one from the verified key and
    // gets `node-other`.
    //
    // If the derivation were replaced by a `node_id` field on the request, this test would fail:
    // there would be nothing stopping the second node writing `node-e2e` in it.
    let runner = Runner::start("acme").await;
    let (token, _) = runner.secrets.mint(&request("job-1", NODE_ID)).unwrap();

    let other = NodeIdentity::generate();
    runner.secrets.enrol_node("node-other", other.public()).unwrap();
    let signed = other.sign(&token, "job-1", &[], now());
    assert_eq!(runner.secrets.redeem(&signed).unwrap_err(), SecretError::WrongNode);

    // A node with no enrolment at all is refused earlier and just as completely.
    let stranger = NodeIdentity::generate();
    assert!(matches!(
        runner.secrets.redeem(&stranger.sign(&token, "job-1", &[], now())),
        Err(SecretError::UnenrolledNode(_))
    ));

    // A syntactically valid but forged signature from the enrolled key's *identity* fails too.
    let mut tampered = other.sign(&token, "job-1", &[], now());
    tampered.signature[0] ^= 0x01;
    assert_eq!(runner.secrets.redeem(&tampered).unwrap_err(), SecretError::BadNodeSignature);

    // None of those attempts burned the capability, so the real node is not collateral damage.
    assert!(runner.secrets.broker().redeem(&token, NODE_ID, &[]).is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_whose_enrolment_is_withdrawn_cannot_redeem_and_its_step_does_not_run() {
    // The identity check on the *live* path, not in a unit test: the node in this process is
    // decommissioned (an ordinary operator action) after assembly, so its signature no longer
    // resolves to an id. The step that declared a secret must then not run at all — a step that ran
    // without the value would fail on its own terms, and a red verdict about the code would be a lie
    // about a tree that was fine.
    let hull = HullStub::start().await;
    let (_guard, marker) = marker_path();
    let tree = tree_that_checks_the_value(&marker);
    let tree_id = keel_tree_id(tree.path());
    hull.publish(&tree_id, hull_style_archive(tree.path()));

    let runner = Runner::start("acme").await;
    assert!(runner.secrets.nodes().revoke(NODE_ID), "the node was enrolled at assembly");

    runner
        .dispatch(dispatch_body("acme/widget", &tree_id, &hull.source_url(&tree_id), &hull.callback_url()))
        .await;

    let v = hull.verdict().await;
    assert_eq!(v.status(), "errored", "an unverifiable node is our failure, never the code's");
    assert_eq!(v.reason(), Some("infra"), "spec §7: never red");
    assert!(!marker.exists(), "the step must not run when its secret could not be delivered");
    assert!(
        v.summary().contains("secret delivery refused"),
        "the operator should be told what happened: {}",
        v.summary()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_capability_cannot_be_redeemed_twice() {
    // Single-use is not only a replay defence, it is the alarm: the second holder of a token learns
    // someone else got there first, with a job id attached. Asserted through the service, so the
    // signature path is exercised on both attempts — a fresh nonce and timestamp each time, which is
    // exactly what an attacker holding the key would do.
    let runner = Runner::start("acme").await;
    let identity = NodeIdentity::generate();
    runner.secrets.enrol_node("node-solo", identity.public()).unwrap();

    let (token, _) = runner.secrets.mint(&request("job-1", "node-solo")).unwrap();
    let delivered = runner.secrets.redeem(&identity.sign(&token, "job-1", &[], now())).unwrap();
    assert_eq!(delivered.get(SECRET_NAME).unwrap().expose(), SECRET_VALUE.as_bytes());

    assert_eq!(
        runner.secrets.redeem(&identity.sign(&token, "job-1", &[], now())).unwrap_err(),
        SecretError::CapabilityConsumed
    );
}

// ── Containment ──────────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn the_secret_value_reaches_no_report_surface_even_when_the_job_prints_it() {
    // The masking backstop (D§7.4), on the hardest honest case: the step deliberately echoes its own
    // secret and then fails, so the tail of that output *is* the verdict's summary. It must arrive
    // redacted at the callback, and must not turn up in any admin response either.
    //
    // Read `hull_ci_secrets::mask` before reading this as protection. It is exact-substring
    // redaction, and the same step could have printed `$(echo "$NPM_TOKEN" | base64)` and defeated
    // it in one line. What this asserts is that the *accident* is caught — a member's pipeline
    // dumping its environment while debugging — not that a hostile job can be contained by masking.
    // Containment is the author-class gate, tested above.
    let tree = secret_tree(&format!(
        r#"step("leaky", run = 'echo "${}"; exit 1', secrets = ["{}"])"#,
        SECRET_NAME, SECRET_NAME
    ));
    let (v, runner, _hull) = run_one("acme/widget", "acme", tree.path()).await;

    assert_eq!(v.status(), "red", "the step exits 1, which is a statement about the code");
    assert!(
        v.summary().contains("***"),
        "the echoed value should have been redacted into the summary: {}",
        v.summary()
    );
    assert!(
        !v.raw().contains(SECRET_VALUE),
        "the value must not appear anywhere in the callback body: {}",
        v.raw()
    );

    // The operator panel is the one deliberately cross-tenant surface in this system (D§1), so it is
    // the one worth checking by hand rather than by inspection.
    for path in ["/admin", "/admin/jobs", "/admin/nodes", "/admin/queue", "/admin/summary"] {
        let body = runner.admin(path).await;
        assert!(!body.contains(SECRET_VALUE), "{path} leaked the secret value");
    }

    // And the names are not a leak: an admin endpoint may perfectly well say a step declared
    // NPM_TOKEN. This assertion exists so the one above cannot pass by the panel being empty.
    assert!(runner.admin("/admin/jobs").await.contains("leaky"), "the panel is not just blank");
}
