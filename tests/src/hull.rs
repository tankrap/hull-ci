//! The stub Hull: the other half of the contract, so the suite needs no real Hull instance.
//!
//! It does exactly the two things spec §3 says Hull does, and nothing else:
//!   * **sends dispatches** (§5) to the CI endpoint under test, and
//!   * **serves `source_url`** (§6, a keel tree tar) and **receives the callback** (§7/§8),
//!     recording every request so a test can assert on what actually came back.
//!
//! Everything it records is per-*job token*: each test mints a fresh token, so tests can run in
//! parallel against one CI endpoint without reading each other's traffic.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use crate::config;
use crate::http::{self, HttpRequest, HttpResponse, Server};
use crate::tree::{self, TreeFile};

/// Header names, restated here rather than imported from `hull-ci-proto`.
///
/// The suite is black-box on purpose: it must be able to judge *any* CI endpoint, and it must not
/// pass merely because our own crate and our own test agree with each other. These strings come from
/// CI-SPEC.md §5/§8, and if someone edits the constants in `hull-ci-proto`, this suite is what
/// notices.
pub const SECRET_HEADER: &str = "X-Hull-CI-Secret";
pub const VERSION_HEADER: &str = "X-Hull-CI-Version";
pub const CONTRACT_VERSION: &str = "1";

/// What `GET source_url` should do for a given job.
#[derive(Debug, Clone)]
pub enum Source {
    /// Serve these bytes as `application/x-tar`.
    Tar(Vec<u8>),
    /// Fail with this status — an induced infrastructure failure (spec §7: `errored`, not `red`).
    Status(u16),
}

/// A recorded callback (spec §7), plus how the stub Hull answered it (spec §8).
#[derive(Debug, Clone)]
pub struct Callback {
    pub token: String,
    /// The path the CI actually POSTed to. Compared verbatim against `callback_url` (§5, §11.4).
    pub path: String,
    pub query: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// `status` from the body, if the body was JSON with a string `status`.
    pub status: Option<String>,
    pub summary: Option<String>,
    /// False when the stub Hull rejected it — bad secret (401) or bad status (400).
    pub accepted: bool,
    pub response_code: u16,
}

impl Callback {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Default)]
struct State {
    sources: HashMap<String, Source>,
    source_fetches: Vec<(String, HttpRequest)>,
    callbacks: Vec<Callback>,
    /// Requests that matched no route. A CI that *reconstructs* a callback URL, or that probes for a
    /// git endpoint, lands here — which is precisely what §11.3 and §11.4 are about.
    unmatched: Vec<HttpRequest>,
}

pub struct StubHull {
    server: Server,
    state: Arc<Mutex<State>>,
    secret: Option<String>,
}

impl StubHull {
    /// Start a stub Hull. `secret` is the shared secret this endpoint requires on the callback (§8);
    /// `None` models an endpoint configured without one.
    pub fn start(secret: Option<String>) -> Self {
        let state = Arc::new(Mutex::new(State::default()));
        let handler_state = Arc::clone(&state);
        let handler_secret = secret.clone();

        let server = http::spawn(move |req: HttpRequest| {
            route(&handler_state, handler_secret.as_deref(), req)
        })
        .expect("stub Hull could not bind a loopback port");

        StubHull { server, state, secret }
    }

    pub fn base_url(&self) -> String {
        self.server.base_url()
    }

    // ── Building and sending a dispatch (spec §5) ────────────────────────────────────────────────

    /// A dispatch for the standard benign fixture tree.
    pub fn job(&self) -> JobSpec {
        self.job_with_tree(&tree::benign_project())
    }

    /// A dispatch whose `source_url` serves `files`, advertised under `files`' own content address.
    pub fn job_with_tree(&self, files: &[TreeFile]) -> JobSpec {
        let tree_id = tree::tree_id(files);
        let job = self.job_raw(&tree_id);
        self.set_source(&job.token, Source::Tar(tree::tar(files)));
        job
    }

    /// A dispatch advertising `tree_id` with **no** source registered yet — the caller supplies one
    /// with [`StubHull::set_source`]. This is how the corrupted-archive case is built: advertise the
    /// address of one tree, serve the bytes of another.
    pub fn job_raw(&self, tree_id: &str) -> JobSpec {
        let token = next_token();
        let change = tree::change_id(tree_id, &token);
        JobSpec {
            token: token.clone(),
            repo: "tankrap/hull".to_string(),
            change: change.clone(),
            tree_id: tree_id.to_string(),
            intent: "conformance: exercise the CI integration contract".to_string(),
            author: "conformance-harness".to_string(),
            // Both URLs are deliberately *unlike* the shapes in the spec's examples. A runner that
            // reconstructs either one from `repo`/`change` instead of using it verbatim (§5) will
            // miss these routes entirely and show up in `unmatched`.
            source_url: format!("{}/keel/tree/{}/tar?token={}", self.base_url(), tree_id, token),
            callback_url: format!(
                "{}/hull/cb/{}/ci-result?attempt=1&nonce={}",
                self.base_url(),
                token,
                &change[..12]
            ),
            extra: Map::new(),
            version_header: Some(CONTRACT_VERSION.to_string()),
            secret_header: self.secret.clone(),
        }
    }

    pub fn set_source(&self, token: &str, source: Source) {
        self.state.lock().unwrap().sources.insert(token.to_string(), source);
    }

    /// POST the dispatch to the CI endpoint under test and return its immediate response (§5: this
    /// is *accepted*, not *done*).
    pub fn dispatch(&self, job: &JobSpec) -> std::io::Result<HttpResponse> {
        let body = job.payload().to_string();
        let mut headers: Vec<(&str, &str)> = vec![("Content-Type", "application/json")];
        if let Some(v) = &job.version_header {
            headers.push((VERSION_HEADER, v.as_str()));
        }
        if let Some(s) = &job.secret_header {
            headers.push((SECRET_HEADER, s.as_str()));
        }
        http::post(&config::endpoint(), &headers, body.as_bytes())
    }

    // ── Observing what came back ─────────────────────────────────────────────────────────────────

    pub fn callbacks(&self, token: &str) -> Vec<Callback> {
        self.state
            .lock()
            .unwrap()
            .callbacks
            .iter()
            .filter(|c| c.token == token)
            .cloned()
            .collect()
    }

    pub fn accepted_callbacks(&self, token: &str) -> Vec<Callback> {
        self.callbacks(token).into_iter().filter(|c| c.accepted).collect()
    }

    pub fn rejected_callbacks(&self, token: &str) -> Vec<Callback> {
        self.callbacks(token).into_iter().filter(|c| !c.accepted).collect()
    }

    pub fn source_fetches(&self, token: &str) -> Vec<HttpRequest> {
        self.state
            .lock()
            .unwrap()
            .source_fetches
            .iter()
            .filter(|(t, _)| t == token)
            .map(|(_, r)| r.clone())
            .collect()
    }

    /// Every request that matched no route — a reconstructed URL, a git probe, anything unexpected.
    pub fn unmatched(&self) -> Vec<HttpRequest> {
        self.state.lock().unwrap().unmatched.clone()
    }

    /// Wait until at least one callback for `token` has been received, or the timeout expires.
    pub fn wait_for_callback(&self, token: &str) -> Option<Callback> {
        self.wait_for_callbacks(token, 1).into_iter().next()
    }

    /// Wait until at least `n` callbacks for `token` have arrived. Returns whatever it has at the
    /// deadline — the assertion, and therefore the error message, belongs to the test.
    pub fn wait_for_callbacks(&self, token: &str, n: usize) -> Vec<Callback> {
        let deadline = Instant::now() + config::callback_timeout();
        loop {
            let got = self.callbacks(token);
            if got.len() >= n || Instant::now() >= deadline {
                return got;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Wait for a source fetch, so a negative callback assertion can distinguish "the CI ignored us"
    /// from "the CI is still working".
    pub fn wait_for_source_fetch(&self, token: &str) -> Vec<HttpRequest> {
        let deadline = Instant::now() + config::callback_timeout();
        loop {
            let got = self.source_fetches(token);
            if !got.is_empty() || Instant::now() >= deadline {
                return got;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Give a CI that was *supposed to do nothing* time to prove otherwise.
    ///
    /// Every negative assertion in the suite ("no callback arrived", "the source was never fetched")
    /// needs a bound, and there is no black-box event that says "the CI has definitely finished
    /// ignoring you". This is the one place the suite is time-based; `HULL_CI_SETTLE_MS` widens it
    /// for a slow endpoint. It is a loopback wait, not a network wait — nothing here depends on the
    /// internet or on a real Hull.
    pub fn settle(&self) {
        std::thread::sleep(config::settle());
    }

    /// Replay a callback the CI already sent, byte for byte, to exercise §9's duplicate-callback rule.
    pub fn replay(&self, callback: &Callback) -> std::io::Result<HttpResponse> {
        let url = format!(
            "{}{}{}",
            self.base_url(),
            callback.path,
            callback.query.as_ref().map(|q| format!("?{q}")).unwrap_or_default()
        );
        let secret = callback.header(SECRET_HEADER).unwrap_or("").to_string();
        let mut headers: Vec<(&str, &str)> = vec![("Content-Type", "application/json")];
        if !secret.is_empty() {
            headers.push((SECRET_HEADER, secret.as_str()));
        }
        http::post(&url, &headers, callback.body.as_bytes())
    }

    /// POST an arbitrary body/secret to a job's `callback_url` — used only by the suite's own
    /// fidelity checks of the §8 receiver rules, never to stand in for the CI's behaviour.
    pub fn post_callback_directly(
        &self,
        job: &JobSpec,
        secret: Option<&str>,
        body: &str,
    ) -> std::io::Result<HttpResponse> {
        let mut headers: Vec<(&str, &str)> = vec![("Content-Type", "application/json")];
        if let Some(s) = secret {
            headers.push((SECRET_HEADER, s));
        }
        http::post(&job.callback_url, &headers, body.as_bytes())
    }
}

// ── The dispatch payload ─────────────────────────────────────────────────────────────────────────

/// One dispatch, plus the knobs the adversarial cases turn.
#[derive(Debug, Clone)]
pub struct JobSpec {
    /// The suite's correlation id. Appears in both URLs; never in the contract.
    pub token: String,
    pub repo: String,
    pub change: String,
    pub tree_id: String,
    pub intent: String,
    pub author: String,
    pub source_url: String,
    pub callback_url: String,
    /// Extra top-level JSON fields (spec §5: a conforming CI ignores what it does not know).
    pub extra: Map<String, Value>,
    /// `X-Hull-CI-Version` to send; `None` omits the header.
    pub version_header: Option<String>,
    /// `X-Hull-CI-Secret` to send; `None` omits the header.
    pub secret_header: Option<String>,
}

impl JobSpec {
    pub fn with_extra(mut self, key: &str, value: Value) -> Self {
        self.extra.insert(key.to_string(), value);
        self
    }

    pub fn with_version(mut self, version: Option<&str>) -> Self {
        self.version_header = version.map(str::to_string);
        self
    }

    pub fn with_secret(mut self, secret: Option<&str>) -> Self {
        self.secret_header = secret.map(str::to_string);
        self
    }

    /// The §5 body, exactly: the seven documented fields, plus whatever `extra` adds.
    pub fn payload(&self) -> Value {
        let mut body = json!({
            "repo": self.repo,
            "change": self.change,
            "tree_id": self.tree_id,
            "intent": self.intent,
            "author": self.author,
            "source_url": self.source_url,
            "callback_url": self.callback_url,
        });
        let map = body.as_object_mut().unwrap();
        for (k, v) in &self.extra {
            map.insert(k.clone(), v.clone());
        }
        body
    }

    /// The path+query a conforming CI must POST to, taken from `callback_url` verbatim.
    pub fn callback_target(&self) -> String {
        self.callback_url
            .split_once("://")
            .and_then(|(_, rest)| rest.find('/').map(|i| rest[i..].to_string()))
            .unwrap_or_default()
    }

    pub fn source_target(&self) -> String {
        self.source_url
            .split_once("://")
            .and_then(|(_, rest)| rest.find('/').map(|i| rest[i..].to_string()))
            .unwrap_or_default()
    }
}

// ── Routing ──────────────────────────────────────────────────────────────────────────────────────

fn route(state: &Arc<Mutex<State>>, secret: Option<&str>, req: HttpRequest) -> HttpResponse {
    let segments: Vec<&str> = req.path.trim_matches('/').split('/').collect();

    match segments.as_slice() {
        // GET /keel/tree/<tree_id>/tar?token=<token>   (spec §6 — content-addressed source)
        ["keel", "tree", _tree, "tar"] if req.method == "GET" => {
            let token = query_param(&req, "token").unwrap_or_default();
            let source = {
                let mut guard = state.lock().unwrap();
                guard.source_fetches.push((token.clone(), req.clone()));
                guard.sources.get(&token).cloned()
            };
            match source {
                Some(Source::Tar(bytes)) => HttpResponse::bytes(200, "application/x-tar", bytes),
                Some(Source::Status(code)) => HttpResponse::json(
                    code,
                    r#"{"error":"induced source failure (conformance harness)"}"#,
                ),
                None => HttpResponse::json(404, r#"{"error":"unknown job token"}"#),
            }
        }

        // POST /hull/cb/<token>/ci-result?...          (spec §7 — the verdict)
        ["hull", "cb", token, "ci-result"] if req.method == "POST" => {
            let token = token.to_string();
            let body = req.body_text();
            let parsed: Option<Value> = serde_json::from_str(&body).ok();
            let status = parsed
                .as_ref()
                .and_then(|v| v.get("status"))
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let summary = parsed
                .as_ref()
                .and_then(|v| v.get("summary"))
                .and_then(|v| v.as_str())
                .map(str::to_string);

            // §8: when the endpoint has a secret, a missing or wrong one on the callback is 401 and
            // **no verdict is recorded**.
            let (accepted, code) = if secret.is_some_and(|s| req.header(SECRET_HEADER) != Some(s)) {
                (false, 401)
            } else if matches!(status.as_deref(), Some("green" | "red" | "errored")) {
                (true, 200)
            } else {
                // §7: "Anything else → 400."
                (false, 400)
            };

            state.lock().unwrap().callbacks.push(Callback {
                token,
                path: req.path.clone(),
                query: req.query.clone(),
                headers: req.headers.clone(),
                body,
                status: status.clone(),
                summary,
                accepted,
                response_code: code,
            });

            match code {
                200 => HttpResponse::json(
                    200,
                    json!({ "recorded": status.unwrap_or_default() }).to_string(),
                ),
                401 => HttpResponse::json(401, r#"{"error":"bad or missing X-Hull-CI-Secret"}"#),
                _ => HttpResponse::json(400, r#"{"error":"status must be green|red|errored"}"#),
            }
        }

        _ => {
            state.lock().unwrap().unmatched.push(req);
            HttpResponse::json(404, r#"{"error":"no such route on the stub Hull"}"#)
        }
    }
}

fn query_param(req: &HttpRequest, name: &str) -> Option<String> {
    req.query.as_ref()?.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

fn next_token() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
    format!("{:08x}{:04x}", nanos ^ (std::process::id() << 8), n & 0xffff)
}
