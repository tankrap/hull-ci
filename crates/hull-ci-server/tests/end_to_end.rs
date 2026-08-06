//! End-to-end: a real dispatch, over real HTTP, through fetch → plan → run → callback.
//!
//! These tests are the reason M1 exists — design D§13's milestone is "ingest with secret verification
//! → fetch broker (GET `source_url`, verify `tree_id`, hardened extract) → one node → autodetected
//! test command in a single-use sandbox → callback", and nothing short of driving a job through all
//! of it shows that the pieces actually meet. Every seam is the production one: the broker really
//! GETs a URL and really re-hashes the archive, the planner really reads the extracted tree, the node
//! really spawns a process, and the verdict really arrives over HTTP at the exact `callback_url`.
//!
//! What stands in for Hull is [`HullStub`]: an axum server that serves a `tar` at a `source_url` and
//! receives a verdict at a `callback_url`, checking the shared secret on the way in (spec §6, §7, §8).
//! It is deliberately dumb — it asserts nothing on its own, it just records — so the assertions stay
//! in the tests where they can be read.
//!
//! ## The two things these tests need from the host
//!
//! * **A tree id keel would produce.** Computed with keel's own encoder (the same crate at the same
//!   pinned rev `hull-ci-fetch` verifies with), because a tree id we invented would only prove our
//!   verifier agrees with our own arithmetic.
//! * **`make`.** The autodetected command for a `Makefile` tree is `make test`, and `/usr/bin/make`
//!   is on the sandbox's allowlisted `PATH` (`hull_ci_node::env::base_env`). A host without it fails
//!   these two tests loudly rather than skipping them: a green suite that silently did not run the
//!   only end-to-end execution path would be worse than a red one.
//!
//! The backend is the local-process one, because the docker daemon is not a thing a test can require.
//! That is exactly the configuration [`hull_ci_server`] makes an operator opt into, and the isolation
//! gate it does *not* relax is asserted here too
//! (`work_from_an_untrusted_tenant_is_refused_rather_than_run`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use hull_ci_proto::{SECRET_HEADER, VERSION_HEADER};
use hull_ci_server::config::SandboxChoice;
use hull_ci_server::membership::TrustedTenants;
use hull_ci_server::Config;

const SECRET: &str = "s3cret-for-the-suite";

// ── The Hull stub ────────────────────────────────────────────────────────────────────────────────

/// One callback as Hull would have received it.
#[derive(Debug, Clone)]
struct Received {
    path: String,
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
}

#[derive(Clone, Default)]
struct HullState {
    /// `tree_id` → the archive bytes to serve. Deliberately keyed by the id the *dispatch* names, so
    /// a test can serve an archive that does not match it (see the verification test).
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

    fn callback_url(&self, change: &str) -> String {
        format!("http://{}/api/change/{change}/ci-result", self.addr)
    }

    /// Wait for the one callback this job owes us.
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
    AxumPath(change): AxumPath<String>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, Json<serde_json::Value>) {
    let secret = headers.get(SECRET_HEADER).and_then(|v| v.to_str().ok()).map(str::to_string);
    let body: serde_json::Value = serde_json::from_str(&body).expect("the verdict is JSON");
    // Spec §8: Hull rejects a callback whose secret is missing or wrong, and records nothing.
    if secret.as_deref() != Some(SECRET) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "unauthorized" })));
    }
    let status = body["status"].as_str().unwrap_or_default().to_string();
    state.received.lock().unwrap().push(Received {
        path: format!("/api/change/{change}/ci-result"),
        secret,
        body,
    });
    (StatusCode::OK, Json(serde_json::json!({ "recorded": status })))
}

// ── Trees ────────────────────────────────────────────────────────────────────────────────────────

/// The `tree_id` keel gives this directory. keel's encoder, not ours.
fn keel_tree_id(dir: &Path) -> String {
    let keel_dir = tempfile::tempdir().unwrap();
    let store = keel_store::store::Store::open_with_map_size(keel_dir.path(), 64 * 1024 * 1024).unwrap();
    keel_store::snapshot::snapshot(&store, dir).unwrap().to_hex()
}

/// A tar built the way `hull-server`'s `tree_archive` builds one.
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

/// A tree whose `make test` exits with `code`.
fn makefile_tree(code: i32) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("README.md"), "a tree under test\n").unwrap();
    std::fs::write(dir.path().join("Makefile"), format!("test:\n\t@exit {code}\n")).unwrap();
    dir
}

// ── The runner under test ────────────────────────────────────────────────────────────────────────

struct Runner {
    addr: SocketAddr,
    _work: tempfile::TempDir,
}

impl Runner {
    /// Start a runner configured the way an M1 operator would have to configure it: an explicit
    /// unsandboxed opt-in, and an explicit list of tenants whose authors count as members.
    async fn start(trusted: &str) -> Runner {
        let work = tempfile::tempdir().unwrap();
        let config = Config {
            secret: Some(SECRET.into()),
            store_root: work.path().join("store"),
            work_root: work.path().join("workspaces"),
            sandbox: SandboxChoice::LocalProcess,
            allow_unsandboxed: true,
            trusted: TrustedTenants::parse(trusted),
            node_id: "node-e2e".into(),
            ..Config::default()
        };

        let runner = hull_ci_server::assemble(&config).await.expect("the runner assembles");
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, runner.router).await.unwrap() });
        Runner { addr, _work: work }
    }

    /// POST a dispatch exactly as spec §5 describes it.
    async fn dispatch(&self, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let resp = reqwest::Client::new()
            .post(format!("http://{}/hull", self.addr))
            .header(SECRET_HEADER, SECRET)
            .header(VERSION_HEADER, "1")
            .json(&body)
            .send()
            .await
            .expect("the ingest endpoint answers");
        let status = resp.status();
        let body = resp.json().await.unwrap_or(serde_json::Value::Null);
        (StatusCode::from_u16(status.as_u16()).unwrap(), body)
    }
}

fn dispatch_body(repo: &str, tree_id: &str, source_url: &str, callback_url: &str) -> serde_json::Value {
    serde_json::json!({
        "repo": repo,
        "change": "21ea2242186c99ff",
        "tree_id": tree_id,
        "intent": "fixes #6 pagination off-by-one",
        "author": "justin",
        "source_url": source_url,
        "callback_url": callback_url,
    })
}

/// One job, start to finish: publish the tree, dispatch it, wait for the callback.
async fn run_one(repo: &str, trusted: &str, tree: &Path, served: Option<&Path>) -> Received {
    let hull = HullStub::start().await;
    let tree_id = keel_tree_id(tree);
    // `served` lets a test hand over an archive of a *different* directory than the one the dispatch
    // names — which is the whole verification story.
    hull.publish(&tree_id, hull_style_archive(served.unwrap_or(tree)));

    let runner = Runner::start(trusted).await;
    let (status, body) = runner
        .dispatch(dispatch_body(
            repo,
            &tree_id,
            &hull.source_url(&tree_id),
            &hull.callback_url("21ea2242186c99ff"),
        ))
        .await;

    // Spec §5: 2xx means *accepted*, not done.
    assert_eq!(status, StatusCode::ACCEPTED, "dispatch was not accepted: {body}");
    assert_eq!(body["accepted"], true);

    let received = hull.verdict().await;
    // Spec §5/§7/§8, on every job regardless of outcome: the exact callback_url, and the secret.
    assert_eq!(received.path, "/api/change/21ea2242186c99ff/ci-result");
    assert_eq!(received.secret.as_deref(), Some(SECRET));
    received
}

// ── The tests ────────────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_tree_whose_test_command_passes_reports_green() {
    let tree = makefile_tree(0);
    let v = run_one("acme/widget", "acme", tree.path(), None).await;
    assert_eq!(
        v.status(),
        "green",
        "a passing `make test` must report green (is `make` on this host?): {}",
        v.summary()
    );
    assert!(v.reason().is_none(), "green is a statement about the code and carries no reason");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tree_whose_test_command_fails_reports_red() {
    let tree = makefile_tree(1);
    let v = run_one("acme/widget", "acme", tree.path(), None).await;
    assert_eq!(v.status(), "red", "a failing suite is a statement about the code: {}", v.summary());
    assert!(v.reason().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tree_that_does_not_verify_is_errored_never_red() {
    // Design D§4.2 makes re-hashing mandatory. The source served bytes that are not the tree it
    // named, so we ran nothing and have nothing to say about the code — and `red` would be memoized
    // by Hull (spec §7), attaching a permanent failure to a tree over our own broken fetch path.
    let named = makefile_tree(0);
    let served = tempfile::tempdir().unwrap();
    std::fs::write(served.path().join("README.md"), "not the tree you asked for\n").unwrap();

    let v = run_one("acme/widget", "acme", named.path(), Some(served.path())).await;
    assert_eq!(v.status(), "errored");
    assert_ne!(v.status(), "red", "spec §7: infrastructure problems are never red");
    assert_eq!(v.reason(), Some("infra"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tree_with_nothing_to_run_is_errored_no_tests() {
    // Spec §9.1 reads `no_tests` as *self_attested* — a statement about coverage that routes a human
    // into the review, which a generic infra error would not.
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("README.md"), "no tests here\n").unwrap();

    let v = run_one("acme/widget", "acme", tree.path(), None).await;
    assert_eq!(v.status(), "errored");
    assert_eq!(v.reason(), Some("no_tests"));
}

#[tokio::test(flavor = "multi_thread")]
async fn work_from_an_untrusted_tenant_is_refused_rather_than_run() {
    // The M1 isolation gate, end to end (design D§7.2, D§13): the tree verifies and the plan is
    // fine, but no M1 backend can contain an outsider's code, so the job errors instead of running.
    let tree = makefile_tree(0);
    let v = run_one("evilcorp/widget", "acme", tree.path(), None).await;
    assert_eq!(v.status(), "errored", "a fork PR must never run on a backend that cannot box it");
    assert_eq!(v.reason(), Some("infra"));
    assert!(
        v.summary().contains("cannot admit untrusted work"),
        "the refusal should say why: {}",
        v.summary()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_duplicate_dispatch_is_one_job_and_one_run() {
    // Spec §9: Hull's in-flight de-dup is best effort, so a duplicate must be safe. The second
    // dispatch attaches to the live job (or re-reports the finished one) and never runs a step twice.
    let hull = HullStub::start().await;
    let tree = makefile_tree(0);
    let tree_id = keel_tree_id(tree.path());
    hull.publish(&tree_id, hull_style_archive(tree.path()));

    let runner = Runner::start("acme").await;
    let body = dispatch_body(
        "acme/widget",
        &tree_id,
        &hull.source_url(&tree_id),
        &hull.callback_url("21ea2242186c99ff"),
    );

    let (_, first) = runner.dispatch(body.clone()).await;
    let (status, second) = runner.dispatch(body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "a duplicate is accepted, not an error");
    assert_eq!(first["job_id"], second["job_id"], "one tree, one job, one verdict");
    assert_eq!(second["duplicate"], true);

    let v = hull.verdict().await;
    assert_eq!(v.status(), "green", "{}", v.summary());
}

// ── M2: the pipeline is on the live path ─────────────────────────────────────────────────────────

/// A tree carrying a real `.hull/ci.star` with a dependency edge, plus the marker file the M1
/// autodetect path would have used. The marker is there on purpose: if the pipeline were ignored and
/// we silently fell back, the job would still go green and the test would pass for the wrong reason.
/// The step *names* in the verdict are what distinguish the two paths.
fn pipeline_tree(star: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".hull")).unwrap();
    std::fs::write(dir.path().join(".hull/ci.star"), star).unwrap();
    std::fs::write(dir.path().join("Makefile"), "test:\n\t@echo autodetect-would-have-run\n").unwrap();
    dir
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pipeline_with_an_edge_runs_both_steps_in_order_and_reports_green() {
    let tree = pipeline_tree(
        r#"
b = step("build", run = "true")
step("check", run = "true", needs = [b])
"#,
    );
    let v = run_one("acme/widget", "acme", tree.path(), None).await;
    assert_eq!(v.status(), "green", "both steps should pass: {}", v.summary());
    // Two steps, not the one the autodetect fallback would have produced.
    assert!(
        v.summary().contains("2 steps") || v.summary().contains("2 step"),
        "the verdict should account for both pipeline steps: {}",
        v.summary()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failing_pipeline_step_names_itself_in_the_verdict() {
    // Spec §14.5: the summary is built from untrusted job output, so it is constructed rather than
    // concatenated — but it must still say which step failed, or a red verdict is unactionable.
    let tree = pipeline_tree(
        r#"
step("unit", run = "false")
"#,
    );
    let v = run_one("acme/widget", "acme", tree.path(), None).await;
    assert_eq!(v.status(), "red", "a failing pipeline step is a statement about the code: {}", v.summary());
    assert!(v.summary().contains("unit"), "the failing step should be named: {}", v.summary());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dependent_of_a_failed_step_does_not_run_and_the_job_is_red() {
    // D§6.6 fail-fast plus the skip cascade, end to end: `after` must never execute.
    let tree = pipeline_tree(
        r#"
b = step("root", run = "false")
step("after", run = "true", needs = [b])
"#,
    );
    let v = run_one("acme/widget", "acme", tree.path(), None).await;
    assert_eq!(v.status(), "red", "{}", v.summary());
    assert!(v.summary().contains("root"), "the actual failure should be named: {}", v.summary());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_pipeline_is_errored_and_never_silently_autodetected() {
    // The tree has a working Makefile, so a silent fallback would report green and the author would
    // never learn their pipeline does not parse.
    let tree = pipeline_tree("step(\n");
    let v = run_one("acme/widget", "acme", tree.path(), None).await;
    assert_eq!(v.status(), "errored", "a pipeline that does not parse is not a verdict about the code");
    assert!(
        v.summary().contains("ci.star"),
        "the summary should name the file the author has to fix: {}",
        v.summary()
    );
}

// ── M4: the step memo, on the live path ──────────────────────────────────────────────────────────

/// A runner with the step memo enabled, and a Hull stub, both kept alive so two dispatches can share
/// one process — which is the only way to observe a memo at all.
struct MemoRunner {
    addr: SocketAddr,
    _work: tempfile::TempDir,
}

impl MemoRunner {
    async fn start() -> MemoRunner {
        let work = tempfile::tempdir().unwrap();
        let config = Config {
            secret: Some(SECRET.into()),
            store_root: work.path().join("store"),
            work_root: work.path().join("workspaces"),
            sandbox: SandboxChoice::LocalProcess,
            allow_unsandboxed: true,
            trusted: TrustedTenants::parse("acme"),
            node_id: "node-memo".into(),
            memo: true,
            ..Config::default()
        };
        let runner = hull_ci_server::assemble(&config).await.expect("the runner assembles");
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, runner.router).await.unwrap() });
        MemoRunner { addr, _work: work }
    }
}

/// A tree whose pipeline declares `inputs`, so its steps are cacheable at all, and whose step writes
/// a marker file on the host each time it actually runs. Counting markers is how a cached step is
/// distinguished from a fast one — the verdict looks identical either way, which is exactly why a
/// wrong memo is dangerous.
fn cacheable_tree(marker: &Path, extra: Option<(&str, &str)>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".hull")).unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/lib.rs"), "fn main() {}\n").unwrap();
    std::fs::write(
        dir.path().join(".hull/ci.star"),
        format!(
            r#"step("build", run = "echo ran >> {}", inputs = ["src/**"])"#,
            marker.display()
        ),
    )
    .unwrap();
    if let Some((path, body)) = extra {
        std::fs::write(dir.path().join(path), body).unwrap();
    }
    dir
}

fn runs_recorded(marker: &Path) -> usize {
    std::fs::read_to_string(marker).map(|s| s.lines().count()).unwrap_or(0)
}

async fn dispatch_to(runner: &MemoRunner, hull: &HullStub, repo: &str, tree: &Path) -> Received {
    let tree_id = keel_tree_id(tree);
    hull.publish(&tree_id, hull_style_archive(tree));
    let (status, _) = reqwest::Client::new()
        .post(format!("http://{}/hull", runner.addr))
        .header(SECRET_HEADER, SECRET)
        .json(&dispatch_body(repo, &tree_id, &hull.source_url(&tree_id), &hull.callback_url(&tree_id)))
        .send()
        .await
        .map(|r| (r.status(), ()))
        .unwrap();
    assert_eq!(status, StatusCode::ACCEPTED);
    hull.verdict().await
}

#[tokio::test(flavor = "multi_thread")]
async fn an_identical_tree_resolves_from_the_memo_without_running_the_step_again() {
    let marker = tempfile::NamedTempFile::new().unwrap();
    let tree = cacheable_tree(marker.path(), None);
    let runner = MemoRunner::start().await;

    let hull1 = HullStub::start().await;
    let first = dispatch_to(&runner, &hull1, "acme/widget", tree.path()).await;
    assert_eq!(first.status(), "green", "{}", first.summary());
    assert_eq!(runs_recorded(marker.path()), 1, "the first dispatch must actually run the step");

    // A *different* repo of the same tenant, so it is not Hull's own tree memo or our
    // (repo, tree_id) idempotency answering — it is layer 2 (D§1 makes the tenant the boundary).
    let hull2 = HullStub::start().await;
    let second = dispatch_to(&runner, &hull2, "acme/other", tree.path()).await;
    assert_eq!(second.status(), "green", "{}", second.summary());
    assert_eq!(
        runs_recorded(marker.path()),
        1,
        "the second dispatch must resolve from the memo without running the step"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_change_inside_the_declared_inputs_misses_the_memo() {
    // The other half, and the one that makes the test above mean anything: if this also hit, the memo
    // would be returning a constant and the first test would pass for the worst possible reason.
    let marker = tempfile::NamedTempFile::new().unwrap();
    let runner = MemoRunner::start().await;

    let first_tree = cacheable_tree(marker.path(), None);
    let hull1 = HullStub::start().await;
    dispatch_to(&runner, &hull1, "acme/widget", first_tree.path()).await;
    assert_eq!(runs_recorded(marker.path()), 1);

    // Same pipeline, same command, one changed byte *inside* `src/**`.
    let changed = cacheable_tree(marker.path(), None);
    std::fs::write(changed.path().join("src/lib.rs"), "fn main() { /* changed */ }\n").unwrap();
    let hull2 = HullStub::start().await;
    let second = dispatch_to(&runner, &hull2, "acme/widget2", changed.path()).await;
    assert_eq!(second.status(), "green", "{}", second.summary());
    assert_eq!(
        runs_recorded(marker.path()),
        2,
        "a change inside a declared input glob must miss the memo and run again"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_change_outside_every_declared_glob_still_hits() {
    // The point of declaring `inputs` at all: a doc-only edit produces a fresh tree_id — so Hull must
    // dispatch it — and resolves without touching a node (design D§6.1, D§8).
    let marker = tempfile::NamedTempFile::new().unwrap();
    let runner = MemoRunner::start().await;

    let base = cacheable_tree(marker.path(), None);
    let hull1 = HullStub::start().await;
    dispatch_to(&runner, &hull1, "acme/widget", base.path()).await;
    assert_eq!(runs_recorded(marker.path()), 1);

    let doc_edit = cacheable_tree(marker.path(), Some(("README.md", "# docs only\n")));
    assert_ne!(
        keel_tree_id(base.path()),
        keel_tree_id(doc_edit.path()),
        "the trees must genuinely differ, or this test proves nothing"
    );
    let hull2 = HullStub::start().await;
    let second = dispatch_to(&runner, &hull2, "acme/widget3", doc_edit.path()).await;
    assert_eq!(second.status(), "green", "{}", second.summary());
    assert_eq!(
        runs_recorded(marker.path()),
        1,
        "a change outside every declared glob must still resolve from the memo"
    );
}
