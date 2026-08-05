//! The **fetch broker**: the one component that turns a [`Dispatch`]'s `source_url` into a verified,
//! on-disk copy of the change's keel tree.
//!
//! Its job is small and its threat model is not. Per spec §14.2 the fetch happens *outside* the
//! sandbox — the broker holds the network identity that can reach Hull, so it necessarily processes
//! attacker-controlled bytes on a host that never runs job code. Everything here follows from that:
//!
//! * **Fetch is content-addressed and git-free** (spec §6). `GET source_url` yields a `tar` of the
//!   tree named by `tree_id`; there is no clone, no ref, no `.git`, and nothing to check out. We do
//!   not shell out to git, and a runner that does is non-conforming.
//! * **Extraction is hardened and rejects rather than sanitizes** ([`extract`]). This is the highest
//!   -value hardening in the runner: one tar parser, on one host, on every tenant's untrusted bytes.
//! * **Verification is mandatory** ([`verify`]). Spec §5 makes re-hashing optional; design D§4.2
//!   makes it required, because every downstream cache — Hull's verdict memo, our step memo, node
//!   tree affinity — is keyed by `tree_id` and is only sound if the bytes we ran really are that
//!   tree. It is done with keel's own encoder, not a local re-implementation.
//! * **The store is tenant-scoped** ([`store`]). Cross-tenant dedup is impossible by construction,
//!   not disabled by a flag (design D§4.2/D7).
//! * **The broker holds no CI secret and no cloud role.** The only credential it ever touches is
//!   [`Dispatch::fetch_token`], which is consumed here, marked sensitive on the wire, never logged,
//!   and never propagated to a node or a sandbox (spec §14.2).
//!
//! Failures map to [`Reason`]: the 5-minute budget yields [`Reason::Timeout`], everything else
//! [`Reason::Infra`]. A fetch failure is never `red` — it is a statement about us, not the code.
//!
//! # Known interop gap (producer side, not ours)
//!
//! `hull-server`'s `tree_archive` builds its tar with `tar::Builder`'s default
//! `follow_symlinks(true)`, so a symlink in the tree is packed as a *copy of its target*. keel
//! addresses a symlink as a `MODE_SYMLINK` entry over a blob holding the target path, so a tree
//! containing one is lossy before it reaches us and can never re-hash to its `tree_id`. We extract
//! symlink entries correctly and the fix is one line on Hull's side (`ar.follow_symlinks(false)`);
//! until then such a change fails verification and reports `errored`, which is the honest outcome —
//! we would otherwise be running code that is not the change under test. Pinned by
//! `hull_archives_dereference_symlinks_so_such_a_tree_cannot_verify_today`.

pub mod extract;
pub mod store;
pub mod verify;

#[cfg(test)]
mod testutil;

use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hull_ci_proto::{sanitize_summary, Dispatch, Reason, Verdict, SUMMARY_MAX_CHARS};

pub use extract::{ExtractError, Extracted, Rejection};
pub use store::{ContentStore, StoreError, StoredTree};
pub use verify::{KeelTreeVerifier, TreeVerifier, VerifyError};

/// Bounds on an archive we have not seen yet.
///
/// Every one of these is a cap on **attacker-controlled input** — the archive is whatever the source
/// endpoint sends, and in a compromised-endpoint or hostile-tenant scenario "whatever" includes a
/// petabyte of zeros, ten million entries, or a tar bomb whose declared sizes are lies. Defaults are
/// generous enough for real repositories and finite, which is the only property that matters.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Cap on bytes read off the wire. Enforced on the stream, so a false `Content-Length` and a
    /// chunked response are both covered.
    pub max_archive_bytes: u64,
    /// Cap on entries. Millions of tiny entries exhaust inodes and our own bookkeeping without ever
    /// approaching a byte cap.
    pub max_entries: usize,
    pub max_file_bytes: u64,
    /// Cap on total extracted bytes — the tar-bomb bound (a small archive that expands hugely).
    pub max_total_bytes: u64,
    /// Cap on path depth. Deep nesting is a stack-exhaustion vector for every recursive consumer,
    /// including our own verifier.
    pub max_path_depth: usize,
    pub max_name_bytes: usize,
    /// Wall clock for the whole fetch. Exceeding it is [`Reason::Timeout`], not `Infra` — a slow
    /// source and a broken source are different operational problems and must read differently.
    pub budget: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_archive_bytes: 2 * 1024 * 1024 * 1024,
            max_entries: 500_000,
            max_file_bytes: 512 * 1024 * 1024,
            max_total_bytes: 4 * 1024 * 1024 * 1024,
            // keel itself caps tree depth at 256; a source path deeper than 64 is already pathological.
            max_path_depth: 64,
            max_name_bytes: 255,
            budget: Duration::from_secs(300),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("dispatch is unusable: {0}")]
    Contract(#[from] hull_ci_proto::ContractError),
    #[error("{0}")]
    BadTreeId(String),
    /// The fetch token could not be encoded as a header. The token itself is **never** included —
    /// this message must stay safe to log verbatim.
    #[error("fetch token is not a valid header value")]
    BadFetchToken,
    /// Non-2xx from the source endpoint. Only the status and the redacted URL, never the query
    /// string (which is where a token would ride).
    #[error("source endpoint returned HTTP {status} for {url}")]
    Http { status: u16, url: String },
    #[error("could not fetch {url}: {detail}")]
    Transport { url: String, detail: String },
    #[error("source endpoint declared {declared} bytes, above the {limit}-byte cap")]
    DeclaredTooLarge { declared: u64, limit: u64 },
    #[error(transparent)]
    Extract(#[from] ExtractError),
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("fetch exceeded its {secs}s budget")]
    Timeout { secs: u64 },
    #[error("internal task failed: {0}")]
    Internal(String),
}

impl FetchError {
    /// How this failure reads on the callback (spec §7, design G4).
    ///
    /// Everything here is `errored`, never `red`: we never got far enough to have an opinion about
    /// the code. A verification mismatch is deliberately `Infra` too — it means the *source* served
    /// us something other than the tree it named, which is our side of the wire, not the author's.
    pub fn reason(&self) -> Reason {
        match self {
            FetchError::Timeout { .. } => Reason::Timeout,
            _ => Reason::Infra,
        }
    }

    /// The verdict to post if this failure ends the job. Sanitized, because parts of the message
    /// (an entry path, a server's status line) originate in untrusted input (spec §14.5).
    pub fn to_verdict(&self) -> Verdict {
        Verdict::errored(self.reason(), sanitize_summary(&self.to_string(), SUMMARY_MAX_CHARS))
    }
}

/// Strip everything from a URL that could carry a credential, for logs and error messages.
///
/// `source_url` is opaque (spec §5) and a future revision may put a scoped token in its query
/// string (spec §6's reserved private-repo mechanism). Since we cannot know which query parameter is
/// sensitive, we drop the query, the fragment and any userinfo wholesale and keep only what is
/// useful for debugging: scheme, host, path.
pub fn redact_url(url: &str) -> String {
    let cut = url.find(['?', '#']).unwrap_or(url.len());
    let (base, truncated) = (&url[..cut], cut < url.len());
    let (scheme, rest) = match base.find("://") {
        Some(i) => (&base[..i + 3], &base[i + 3..]),
        None => ("", base),
    };
    let rest = match (rest.find('@'), rest.find('/')) {
        // userinfo only counts if it precedes the path
        (Some(at), slash) if slash.is_none_or(|s| at < s) => &rest[at + 1..],
        _ => rest,
    };
    format!("{scheme}{rest}{}", if truncated { "?…" } else { "" })
}

/// Fetch, extract, verify, store.
///
/// Cheap to clone and safe to share: one broker serves every job, and the per-tenant scoping lives
/// in the keys, not in the instance.
#[derive(Clone)]
pub struct FetchBroker {
    client: reqwest::Client,
    store: ContentStore,
    limits: Limits,
    verifier: Arc<dyn TreeVerifier>,
}

impl FetchBroker {
    pub fn new(store: ContentStore) -> Result<Self, FetchError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            // No cookie store, no redirect to a different scheme by default, no proxy auth: the
            // broker's HTTP client carries nothing an attacker could get us to spend elsewhere.
            .build()
            .map_err(|e| FetchError::Internal(e.to_string()))?;
        Ok(FetchBroker { client, store, limits: Limits::default(), verifier: Arc::new(KeelTreeVerifier::default()) })
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Swap the verifier. There is no "skip verification" implementation and adding one would defeat
    /// the point of the trait — see [`verify`].
    pub fn with_verifier(mut self, verifier: Arc<dyn TreeVerifier>) -> Self {
        self.verifier = verifier;
        self
    }

    pub fn store(&self) -> &ContentStore {
        &self.store
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Make the dispatch's tree present in the store, fetching it only if it is not already there.
    ///
    /// The store hit is the point of the broker (design D§4.2): a content address is immutable, so
    /// re-fetching a tree we already verified can only ever produce the same bytes. A 12-way sharded
    /// step therefore costs one Hull→broker transfer, not twelve.
    pub async fn ensure(&self, dispatch: &Dispatch) -> Result<StoredTree, FetchError> {
        dispatch.validate()?;
        self.ensure_tree(
            dispatch.tenant(),
            &dispatch.tree_id,
            &dispatch.source_url,
            dispatch.fetch_token.as_deref(),
        )
        .await
    }

    /// [`ensure`](Self::ensure) without a [`Dispatch`].
    ///
    /// These four values are everything the broker uses; the rest of a dispatch (`change`, `intent`,
    /// `callback_url`) is the control plane's business and is deliberately not in scope here — the
    /// broker is the component that must be able to hold the least. Exposed because a caller that has
    /// already destructured the dispatch would otherwise have to *rebuild* one to call us, inventing
    /// values for fields it does not have so that `validate()` passes. A fabricated `callback_url` is
    /// exactly the kind of fiction that later gets used.
    pub async fn ensure_tree(
        &self,
        tenant: &str,
        tree_id: &str,
        source_url: &str,
        fetch_token: Option<&str>,
    ) -> Result<StoredTree, FetchError> {
        let tree_id = verify::normalize_tree_id(tree_id).map_err(|e| FetchError::BadTreeId(e.to_string()))?;

        if self.store.has(tenant, &tree_id) {
            tracing::debug!(tenant, tree_id, "tree already in the content store — no fetch");
            return Ok(StoredTree { tree_id: tree_id.clone(), path: self.store.tree_path(tenant, &tree_id), cached: true });
        }

        let budget = self.limits.budget;
        match tokio::time::timeout(budget, self.fetch_uncached(source_url, fetch_token, tenant, &tree_id)).await {
            Ok(result) => result,
            Err(_) => Err(FetchError::Timeout { secs: budget.as_secs() }),
        }
    }

    async fn fetch_uncached(
        &self,
        source_url: &str,
        fetch_token: Option<&str>,
        tenant: &str,
        tree_id: &str,
    ) -> Result<StoredTree, FetchError> {
        let staging = self.store.staging_dir(tenant)?;
        // One `open(2)`, so it runs inline rather than on a blocking worker — and deliberately not
        // `block_in_place`, which panics outside a multi-thread runtime and would make the broker
        // depend on how its host chose to build the executor.
        let archive = tempfile::NamedTempFile::new_in(&staging)
            .map_err(|e| FetchError::Store(StoreError::Io(e.to_string())))?;

        self.download(source_url, fetch_token, archive.path()).await?;

        // Extraction, hashing and the rename are all blocking filesystem work on potentially
        // gigabytes; keeping them off the async workers is not a nicety when one broker serves the
        // whole fleet.
        let (broker, tenant, tree_id) = (self.clone(), tenant.to_string(), tree_id.to_string());
        tokio::task::spawn_blocking(move || {
            let file = std::fs::File::open(archive.path()).map_err(|e| FetchError::Internal(e.to_string()))?;
            broker.ingest(&tenant, &tree_id, file)
        })
        .await
        .map_err(|e| FetchError::Internal(e.to_string()))?
    }

    /// Stream `source_url` to `dest`, bounded.
    ///
    /// The token, if present, is set as a **sensitive** header value so no middleware or trace layer
    /// can print it, and it is never copied anywhere else: it dies with this request (spec §14.2 —
    /// it must not enter a sandbox, and a node never sees it because a node never fetches).
    async fn download(
        &self,
        source_url: &str,
        fetch_token: Option<&str>,
        dest: &Path,
    ) -> Result<u64, FetchError> {
        use tokio::io::AsyncWriteExt;

        let safe_url = redact_url(source_url);
        let mut req = self.client.get(source_url);
        if let Some(token) = fetch_token {
            let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| FetchError::BadFetchToken)?;
            value.set_sensitive(true);
            req = req.header(reqwest::header::AUTHORIZATION, value);
        }

        let response = req
            .send()
            .await
            .map_err(|e| FetchError::Transport { url: safe_url.clone(), detail: transport_detail(&e) })?;
        let status = response.status();
        if !status.is_success() {
            return Err(FetchError::Http { status: status.as_u16(), url: safe_url });
        }
        // A declared length above the cap saves us the download; a *missing* or lying one changes
        // nothing, because the real enforcement is on bytes received below.
        if let Some(len) = response.content_length() {
            if len > self.limits.max_archive_bytes {
                return Err(FetchError::DeclaredTooLarge { declared: len, limit: self.limits.max_archive_bytes });
            }
        }

        let mut file = tokio::fs::File::create(dest).await.map_err(|e| FetchError::Internal(e.to_string()))?;
        let mut written: u64 = 0;
        let mut response = response;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| FetchError::Transport { url: safe_url.clone(), detail: transport_detail(&e) })?
        {
            written += chunk.len() as u64;
            if written > self.limits.max_archive_bytes {
                return Err(FetchError::Extract(ExtractError::ArchiveTooLarge { limit: self.limits.max_archive_bytes }));
            }
            file.write_all(&chunk).await.map_err(|e| FetchError::Internal(e.to_string()))?;
        }
        file.flush().await.map_err(|e| FetchError::Internal(e.to_string()))?;
        Ok(written)
    }

    /// Extract, verify and publish an archive that is already in hand.
    ///
    /// Split out from the network path on purpose: the whole adversarial surface — the tar parser
    /// and the hash check — is exercised by the tests through this function, with no network in
    /// sight. It is also the seam for any future transport.
    pub fn ingest<R: Read>(&self, tenant: &str, tree_id: &str, archive: R) -> Result<StoredTree, FetchError> {
        let tree_id = verify::normalize_tree_id(tree_id).map_err(|e| FetchError::BadTreeId(e.to_string()))?;
        let staged = self.store.stage(tenant)?;

        let stats = extract::extract_into(archive, staged.path(), &self.limits)?;
        // The mandatory step. On mismatch `staged` is dropped, so the rejected bytes are deleted and
        // nothing was ever visible at the content address.
        self.verifier.verify(staged.path(), &tree_id)?;

        let stored = self.store.commit(tenant, &tree_id, staged)?;
        tracing::info!(
            tenant,
            tree_id = %stored.tree_id,
            files = stats.files,
            dirs = stats.dirs,
            symlinks = stats.symlinks,
            bytes = stats.bytes,
            "verified tree stored"
        );
        Ok(stored)
    }
}

/// reqwest's `Display` includes the full URL, query string and all. Keep the class of failure and
/// drop the rest rather than risk logging a token that rode in a query parameter.
fn transport_detail(e: &reqwest::Error) -> String {
    if e.is_connect() {
        "connection failed".into()
    } else if e.is_timeout() {
        "timed out".into()
    } else if e.is_decode() {
        "malformed response body".into()
    } else if e.is_body() {
        "response body ended early".into()
    } else {
        "request failed".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{tar_bytes, TarEntry};
    use keel_store::object::{Object, Tree, TreeEntry};
    use keel_store::snapshot::{MODE_DIR, MODE_FILE};
    use tempfile::TempDir;

    fn broker() -> (TempDir, FetchBroker) {
        let dir = TempDir::new().unwrap();
        let broker = FetchBroker::new(ContentStore::new(dir.path())).unwrap();
        (dir, broker)
    }

    /// The archive of a small tree, plus the `tree_id` keel would give it.
    fn sample_archive() -> (Vec<u8>, String) {
        let entries = vec![
            TarEntry::dir("./"),
            TarEntry::file("./README.md", b"hello\n"),
            TarEntry::dir("./src"),
            TarEntry::file("./src/main.rs", b"fn main() {}\n"),
        ];
        let src = Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: "main.rs".into(),
                mode: MODE_FILE,
                id: Object::Blob(b"fn main() {}\n".to_vec()).id(),
            }],
        });
        let root = Object::Tree(Tree {
            entries: vec![
                TreeEntry { name: "README.md".into(), mode: MODE_FILE, id: Object::Blob(b"hello\n".to_vec()).id() },
                TreeEntry { name: "src".into(), mode: MODE_DIR, id: src.id() },
            ],
        });
        (tar_bytes(&entries), root.id().to_hex())
    }

    #[test]
    fn ingests_and_verifies_a_real_archive() {
        let (_d, broker) = broker();
        let (archive, tree_id) = sample_archive();

        let stored = broker.ingest("acme", &tree_id, &archive[..]).expect("a faithful archive must verify");
        assert!(!stored.cached);
        assert_eq!(std::fs::read_to_string(stored.path.join("src/main.rs")).unwrap(), "fn main() {}\n");
        assert!(broker.store().has("acme", &tree_id));
    }

    #[test]
    fn an_archive_that_does_not_match_tree_id_is_rejected_and_stored_nowhere() {
        // The whole reason verification is mandatory: a source that serves *something else* must not
        // be able to attach that something else to this tree's address (and its cached verdict).
        let (_d, broker) = broker();
        let (_, honest_id) = sample_archive();
        let tampered = tar_bytes(&[TarEntry::file("./README.md", b"hello\n"), TarEntry::file("./backdoor.sh", b"x")]);

        let err = broker.ingest("acme", &honest_id, &tampered[..]).expect_err("must not verify");
        assert!(matches!(err, FetchError::Verify(VerifyError::Mismatch { .. })), "got {err:?}");
        assert_eq!(err.reason(), Reason::Infra);
        assert!(!broker.store().has("acme", &honest_id), "a rejected tree must never reach its address");
    }

    #[test]
    fn a_second_ingest_of_the_same_tree_is_a_hit() {
        let (_d, broker) = broker();
        let (archive, tree_id) = sample_archive();
        assert!(!broker.ingest("acme", &tree_id, &archive[..]).unwrap().cached);
        assert!(broker.ingest("acme", &tree_id, &archive[..]).unwrap().cached);
    }

    #[test]
    fn a_hostile_archive_never_reaches_verification() {
        let (_d, broker) = broker();
        let (_, tree_id) = sample_archive();
        let hostile = tar_bytes(&[TarEntry::file("../../etc/cron.d/pwn", b"x")]);
        let err = broker.ingest("acme", &tree_id, &hostile[..]).unwrap_err();
        assert!(
            matches!(err, FetchError::Extract(ExtractError::Rejected { reason: Rejection::ParentTraversal, .. })),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn a_cached_tree_is_returned_without_touching_the_network() {
        // `source_url` points nowhere; reaching it would fail the test, which is the assertion.
        let (_d, broker) = broker();
        let (archive, tree_id) = sample_archive();
        broker.ingest("acme", &tree_id, &archive[..]).unwrap();

        let dispatch = Dispatch {
            repo: "acme/widget".into(),
            change: "21ea".into(),
            tree_id: tree_id.clone(),
            intent: String::new(),
            author: String::new(),
            source_url: "http://127.0.0.1:1/never-dialed".into(),
            callback_url: "http://127.0.0.1:1/cb".into(),
            fetch_token: None,
        };
        let stored = broker.ensure(&dispatch).await.expect("store hit");
        assert!(stored.cached);
        assert_eq!(stored.tree_id, tree_id);
    }

    #[tokio::test]
    async fn a_malformed_tree_id_fails_before_any_request() {
        let (_d, broker) = broker();
        let dispatch = Dispatch {
            repo: "acme/widget".into(),
            change: "21ea".into(),
            // Attacker text in `tree_id` would otherwise become a path component in the store.
            tree_id: "../../../etc".into(),
            intent: String::new(),
            author: String::new(),
            source_url: "http://127.0.0.1:1/never-dialed".into(),
            callback_url: "http://127.0.0.1:1/cb".into(),
            fetch_token: None,
        };
        assert!(matches!(broker.ensure(&dispatch).await, Err(FetchError::BadTreeId(_))));
    }

    #[test]
    fn tenants_do_not_share_a_stored_tree() {
        let (_d, broker) = broker();
        let (archive, tree_id) = sample_archive();
        broker.ingest("acme", &tree_id, &archive[..]).unwrap();
        assert!(broker.store().has("acme", &tree_id));
        assert!(!broker.store().has("globex", &tree_id), "cross-tenant dedup is a hard no (D§4.2/D7)");
    }

    /// An archive built exactly the way `hull-server` builds one (`tar::Builder` in
    /// `HeaderMode::Deterministic`, `append_dir_all(".", dir)` over a checked-out tree).
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

    /// End-to-end fidelity against keel itself: keel snapshots a directory, Hull's archiver packs the
    /// same directory, and our broker must land on the same address. Nothing here is our own idea of
    /// what a tree id is — `snapshot()` computes the expected value.
    #[test]
    fn a_tree_snapshotted_by_keel_verifies_through_the_whole_broker() {
        let src = TempDir::new().unwrap();
        std::fs::write(src.path().join("README.md"), b"hello\n").unwrap();
        std::fs::create_dir(src.path().join("src")).unwrap();
        std::fs::write(src.path().join("src/main.rs"), b"fn main() {}\n").unwrap();
        std::fs::write(src.path().join("run.sh"), b"#!/bin/sh\necho hi\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(src.path().join("run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::create_dir(src.path().join("empty")).unwrap();

        let keel_dir = TempDir::new().unwrap();
        let store = keel_store::store::Store::open_with_map_size(keel_dir.path(), 64 * 1024 * 1024).unwrap();
        let tree_id = keel_store::snapshot::snapshot(&store, src.path()).unwrap().to_hex();

        let (_d, broker) = broker();
        let stored = broker
            .ingest("acme", &tree_id, &hull_style_archive(src.path())[..])
            .expect("a real keel tree, packed the way Hull packs it, must verify");
        assert_eq!(stored.tree_id, tree_id);
        assert!(stored.path.join("empty").is_dir(), "an empty directory is part of the tree");
    }

    /// A finding, pinned as a test: `hull-server`'s archiver leaves `tar::Builder::follow_symlinks`
    /// at its default (`true`), so a symlink in the tree is packed as a *copy of its target*. keel
    /// addresses a symlink as `MODE_SYMLINK` over a blob holding the target path, so such a tree can
    /// never re-hash to its `tree_id` — the archive is lossy before we ever see it.
    ///
    /// Our extractor handles symlink entries correctly; the gap is on the producing side, and the
    /// one-line fix is `ar.follow_symlinks(false)` in `hull-server`'s `tree_archive`. When that
    /// lands, this test fails, which is how it should be found.
    #[cfg(unix)]
    #[test]
    fn hull_archives_dereference_symlinks_so_such_a_tree_cannot_verify_today() {
        let src = TempDir::new().unwrap();
        std::fs::write(src.path().join("real.txt"), b"payload\n").unwrap();
        std::os::unix::fs::symlink("real.txt", src.path().join("link.txt")).unwrap();

        let keel_dir = TempDir::new().unwrap();
        let store = keel_store::store::Store::open_with_map_size(keel_dir.path(), 64 * 1024 * 1024).unwrap();
        let tree_id = keel_store::snapshot::snapshot(&store, src.path()).unwrap().to_hex();

        let (_d, broker) = broker();
        let err = broker.ingest("acme", &tree_id, &hull_style_archive(src.path())[..]).unwrap_err();
        assert!(matches!(err, FetchError::Verify(VerifyError::Mismatch { .. })), "got {err:?}");
        assert!(!broker.store().has("acme", &tree_id), "and we refuse to serve the lossy tree");
    }

    #[test]
    fn failures_map_to_the_right_reason() {
        assert_eq!(FetchError::Timeout { secs: 300 }.reason(), Reason::Timeout);
        assert_eq!(FetchError::Http { status: 502, url: "https://h/x".into() }.reason(), Reason::Infra);
        assert_eq!(FetchError::Extract(ExtractError::TooManyEntries { limit: 1 }).reason(), Reason::Infra);
        let v = FetchError::Timeout { secs: 300 }.to_verdict();
        assert_eq!(v.status, hull_ci_proto::Status::Errored);
        assert_eq!(v.reason, Some(Reason::Timeout));
    }

    #[test]
    fn redaction_keeps_the_useful_half_of_a_url() {
        assert_eq!(
            redact_url("https://hull.example/api/repos/t/r/tree/f7a2/tar"),
            "https://hull.example/api/repos/t/r/tree/f7a2/tar"
        );
        // A token in the query is exactly what §6's reserved private-repo mechanism would look like.
        assert_eq!(redact_url("https://hull.example/tar?token=s3cr3t"), "https://hull.example/tar?…");
        assert_eq!(redact_url("https://user:pw@hull.example/tar"), "https://hull.example/tar");
        assert_eq!(redact_url("https://hull.example/a/b@c"), "https://hull.example/a/b@c");
        assert_eq!(redact_url("https://hull.example/tar#frag"), "https://hull.example/tar?…");
    }

    #[test]
    fn no_error_message_can_carry_the_fetch_token() {
        // The token is consumed by the broker alone (spec §14.2). Any error we might log must be
        // provably free of it, so none of these variants interpolate anything but a redacted URL.
        let secret = "s3cr3t-token-value";
        for e in [
            FetchError::BadFetchToken,
            FetchError::Http { status: 403, url: redact_url(&format!("https://h/tar?token={secret}")) },
            FetchError::Transport {
                url: redact_url(&format!("https://h/tar?token={secret}")),
                detail: "connection failed".into(),
            },
        ] {
            assert!(!e.to_string().contains(secret), "leaked the token: {e}");
        }
    }
}
