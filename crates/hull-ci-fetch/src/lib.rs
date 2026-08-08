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
//! * **The store is tenant-scoped, and deduplicated within a tenant** ([`store`]). Each of a
//!   tenant's files is stored once and shared by hard link between the trees that hold it, which is
//!   safe exactly because a stored tree is never written to. Cross-tenant dedup remains impossible
//!   by construction, not disabled by a flag (design D§4.2/D7).
//! * **The store is bounded, from the place it grows.** A commit that publishes a new tree is what
//!   triggers [`ContentStore::reclaim`] for that tenant — amortized, rate-limited, and on a blocking
//!   worker rather than on the fetch that paid for it. See [`ReclaimConfig`].
//! * **The broker holds no CI secret and no cloud role.** The only credential it ever touches is
//!   [`Dispatch::fetch_token`], which is consumed here, marked sensitive on the wire, never logged,
//!   and never propagated to a node or a sandbox (spec §14.2).
//!
//! Failures map to [`Reason`]: the 5-minute budget yields [`Reason::Timeout`], everything else
//! [`Reason::Infra`]. A fetch failure is never `red` — it is a statement about us, not the code.
//!
//! # Symlinks — a producer-side bug this crate found, since fixed
//!
//! `hull-server`'s `tree_archive` used to build its tar with `tar::Builder`'s default
//! `follow_symlinks(true)`, packing a symlink as a *copy of its target*. keel addresses a symlink as
//! a `MODE_SYMLINK` entry over a blob holding the target path, so such an archive could never
//! re-hash to its own `tree_id`: every change touching a symlink would have failed verification
//! **permanently**, because `errored` is not memoized and each re-check would fail identically. Hull
//! now sets `follow_symlinks(false)`, and we extract symlink entries as symlinks.
//!
//! That episode is why this crate verifies unconditionally even though spec §6 only says **MAY**:
//! the producer had been emitting unverifiable archives with nothing in the world able to notice
//! until a verifying consumer existed. See design G5, which proposes promoting §6 to a MUST.

pub mod digest;
pub mod extract;
pub mod store;
pub mod verify;

#[cfg(test)]
mod testutil;

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use hull_ci_proto::{sanitize_summary, Dispatch, Reason, Verdict, SUMMARY_MAX_CHARS};
use tokio::sync::watch;

pub use digest::{DigestError, DigestLimits, GlobDigest, GlobError, TreeDigester, TreeIndex};
pub use extract::{ExtractError, Extracted, Rejection};
pub use store::{ContentStore, DedupReport, ReclaimPolicy, ReclaimReport, StoreError, StoredTree, TreePin};
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

/// When the broker asks the store to collect its own garbage, and against what retention.
///
/// [`ContentStore::reclaim`] is the mechanism; this is the policy, and until it existed the mechanism
/// had no caller at all — no timer, no ceiling, nothing — so the store grew without bound (design
/// D§4.2's "there is no invalidation question, only GC", with the GC never running).
///
/// # On by default, which is the opposite of most switches here
///
/// The two ways to be wrong about reclamation are not symmetrical, and that asymmetry is the whole
/// argument for the default and for the size of [`Self::tree_retention`]:
///
/// * **Reclaim too eagerly and you lose a cache hit.** A reclaimed tree is not lost data. Its bytes
///   are still at `source_url`, and the very next dispatch that wants it re-fetches, re-verifies and
///   re-stores it (spec §6, and `FetchBroker::ensure_tree` is the one path). The cost is one transfer.
/// * **Reclaim too little and the disk fills**, at which point *every* job on this runner fails —
///   staging cannot be written, extraction fails, and the failures are `errored`, which spec §7 does
///   not memoize, so Hull re-dispatches them into the same full disk.
///
/// A cache miss is a slower job; a full disk is a dead runner. That is why this defaults on while
/// `HULL_CI_MEMO` and `HULL_CI_PROXY` default off: those gate a *capability* a deployment can simply
/// not have, and this one gates whether an operator who configures nothing eventually loses the box.
#[derive(Debug, Clone, Copy)]
pub struct ReclaimConfig {
    /// Whether a commit sweeps at all. `false` is exactly the behaviour that shipped before this
    /// existed: the store grows for as long as the process lives.
    pub enabled: bool,
    /// How long a tree survives after its last *use* — [`ReclaimPolicy::tree_retention`], which is
    /// measured from the use stamp and never from the commit, so a tree that keeps getting hits never
    /// looks stale.
    pub tree_retention: Duration,
    /// The shortest gap between two sweeps **of the same tenant**.
    ///
    /// Dispatches arrive at machine rates and a sharded fan-out commits many trees at once, so
    /// without this one busy tenant would turn every commit into a full walk of its trees and blobs.
    /// The same shape, and the same reason, as
    /// `hull_ci_control::ControlConfig::redeliver_interval`.
    pub cooldown: Duration,
}

impl Default for ReclaimConfig {
    /// On, a fortnight, and a quarter of an hour.
    ///
    /// **Fourteen days**, where [`ReclaimPolicy`]'s own default is seven. Seven days is exactly one
    /// working week, which makes it the worst possible round number: a repo built every Monday ages
    /// out over a single bank holiday, a release freeze, or one person's week off — and what it loses
    /// is precisely the warm dependency tree the store exists to hold. Fourteen survives a fortnight
    /// of quiet and still bounds the store, and the direction to be wrong in is the cheap one (see
    /// the type's docs: an over-long retention costs disk, an over-short one costs every hit).
    ///
    /// **Fifteen minutes**, which is ~1/1300 of the retention window. The sweep does not need to be
    /// prompt — nothing becomes collectable suddenly when the threshold is a fortnight — it only
    /// needs to be much finer-grained than the window, and it needs to not run once per commit. At
    /// this rate a tenant committing continuously costs at most four walks an hour; at one per
    /// commit, a 12-way sharded step would cost twelve walks in a second, which is the burst this
    /// number exists to refuse.
    fn default() -> Self {
        ReclaimConfig {
            enabled: true,
            tree_retention: Duration::from_secs(14 * 24 * 60 * 60),
            cooldown: Duration::from_secs(15 * 60),
        }
    }
}

/// One completed sweep: which tenant, and what it did or why it could not.
///
/// Published rather than only logged, for the reason [`ReclaimReport`] exists at all: **a reclaimer
/// that silently never fires passes every "the store is correct" test**, because the store is simply
/// correct and full. A caller — and the test suite, which must assert that reclamation *happened*
/// rather than infer it from the absence of a complaint — can watch this instead of guessing from a
/// disk that is not shrinking.
#[derive(Debug, Clone)]
pub struct Sweep {
    pub tenant: String,
    /// The report, or the reason no sweep was possible at all (the store could not create the scratch
    /// directory removals are renamed into). A `String` and not a [`StoreError`] because this is a
    /// notification, not a thing to match on and act upon: **nothing acts on a failed sweep**. The
    /// store filling up is an operational problem; a job failing because of housekeeping would be a
    /// correctness one, so a sweep's failure ends in a log line and this value.
    pub result: Result<ReclaimReport, String>,
}

/// The rate limiter, and the record of what it has done.
///
/// Behind an `Arc` on the broker, because [`FetchBroker`] is `Clone` and is cloned per fetch — a
/// per-clone cooldown table would rate-limit nothing at all. (The same reason `ContentStore`'s pin
/// table is shared rather than cloned.)
#[derive(Debug)]
struct Sweeps {
    /// When each tenant last swept. Keyed by tenant, and pruned on every check: an entry older than
    /// the cooldown is dropped, because "no entry" and "an entry past its cooldown" mean the same
    /// thing to [`Sweeps::claim`]. So the map holds at most one entry per tenant that swept within
    /// one cooldown window — a bound, rather than one entry per tenant ever served, which would be an
    /// unbounded map inside the fix for an unbounded directory.
    last: Mutex<HashMap<String, Instant>>,
    /// Sweeps this broker has *started*, ever. Incremented under the same lock that grants the claim,
    /// so it counts decisions rather than outcomes — which is what makes "N commits did not produce N
    /// sweeps" answerable without waiting for anything to finish.
    started: AtomicU64,
    /// The completion signal. A `watch` and not a `Notify`: a watch marks itself changed at send
    /// time, so a receiver taken before the commit cannot miss a sweep that finished before it got
    /// around to looking. Missing one would be a lost wakeup in the one place where a false "nothing
    /// happened" is the failure being guarded against.
    done: watch::Sender<Option<Sweep>>,
}

impl Sweeps {
    fn new() -> Sweeps {
        Sweeps {
            last: Mutex::new(HashMap::new()),
            started: AtomicU64::new(0),
            done: watch::channel(None).0,
        }
    }

    /// A panic elsewhere must not wedge the broker: the invariant here is a timestamp, and the worst
    /// a half-updated one can do is delay or duplicate a sweep, both of which are safe.
    fn lock(&self) -> MutexGuard<'_, HashMap<String, Instant>> {
        self.last.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Take the right to sweep this tenant now, or answer `false` because one ran too recently.
    ///
    /// **Check and take under one lock**, for the reason `Control::claim_delivery` gives about the
    /// claim it takes on a delivery: a claim with a gap in it is not a claim. The commits this
    /// arbitrates between are concurrent by construction — a sharded step publishes many trees at
    /// once — so a check-then-set would be sampled by exactly the burst it exists to collapse.
    fn claim(&self, tenant: &str, cooldown: Duration, now: Instant) -> bool {
        let mut last = self.lock();
        last.retain(|_, t| now.checked_duration_since(*t).is_some_and(|since| since < cooldown));
        if last.contains_key(tenant) {
            return false;
        }
        last.insert(tenant.to_string(), now);
        self.started.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Record a finished sweep and restart the cooldown **from now**, not from when the sweep began.
    ///
    /// `Control::release_delivery` does the same thing for the same reason: a run that takes longer
    /// than the interval should be followed by a real pause, rather than by another run that was
    /// already due before this one ended.
    fn finished(&self, tenant: &str, sweep: Sweep) {
        self.lock().insert(tenant.to_string(), Instant::now());
        // `send_replace`, because a send with no receivers is not a failure: nobody is obliged to
        // watch, and the log line is the operator's copy of this.
        self.done.send_replace(Some(sweep));
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
    reclaim: ReclaimConfig,
    /// Shared by every clone, because the clones are the same broker: see [`Sweeps`].
    sweeps: Arc<Sweeps>,
}

impl FetchBroker {
    pub fn new(store: ContentStore) -> Result<Self, FetchError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            // No cookie store, no redirect to a different scheme by default, no proxy auth: the
            // broker's HTTP client carries nothing an attacker could get us to spend elsewhere.
            .build()
            .map_err(|e| FetchError::Internal(e.to_string()))?;
        Ok(FetchBroker {
            client,
            store,
            limits: Limits::default(),
            verifier: Arc::new(KeelTreeVerifier::default()),
            // On by default — see `ReclaimConfig`. A broker built by a caller that has never heard of
            // reclamation still bounds its store, which is the point: the failure this closes is an
            // operator who configured nothing, not one who configured it wrong.
            reclaim: ReclaimConfig::default(),
            sweeps: Arc::new(Sweeps::new()),
        })
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Replace the reclamation policy. The composition root's job — it is the only place that reads
    /// an operator's configuration.
    pub fn with_reclaim(mut self, reclaim: ReclaimConfig) -> Self {
        self.reclaim = reclaim;
        self
    }

    pub fn reclaim_config(&self) -> &ReclaimConfig {
        &self.reclaim
    }

    /// How many sweeps this broker has started since it was built.
    ///
    /// Started, not finished, and that distinction is the useful one: it is the rate limiter's own
    /// count of the decisions it made, so "a burst of commits did not become a burst of walks" is a
    /// question about this number and needs nothing to have completed.
    pub fn sweeps_started(&self) -> u64 {
        self.sweeps.started.load(Ordering::Relaxed)
    }

    /// Watch completed sweeps. See [`Sweep`] for why a sweep announces itself at all.
    ///
    /// The receiver observes every sweep that finishes after it is taken; the value is `None` until
    /// the first one lands.
    pub fn sweeps(&self) -> watch::Receiver<Option<Sweep>> {
        self.sweeps.done.subscribe()
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
            // The normalized tenant (`Dispatch::tenant`), which is what makes the store path one
            // path per tenant rather than one per spelling of a tenant.
            &dispatch.tenant(),
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

        // `open`, not `has`: this is *the* cache hit in the system, so it is the place the store's
        // retention clock has to learn that the tree is still wanted (a tree fetched once and hit
        // daily for a year must never look a year stale), and the place a claim against reclamation
        // has to be taken. `has` is a probe and does neither — see `ContentStore::open`.
        if let Some(pin) = self.store.open(tenant, &tree_id) {
            tracing::debug!(tenant, tree_id, "tree already in the content store — no fetch");
            return Ok(StoredTree {
                tree_id: tree_id.clone(),
                path: self.store.tree_path(tenant, &tree_id),
                cached: true,
                // Nothing was published, so nothing was deduplicated. See `StoredTree::dedup`: this
                // is deliberately not a zeroed report, because "shared nothing" and "did nothing"
                // are the two states a dedup layer must never blur.
                dedup: None,
                pin,
            });
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
        // The dedup counts are logged because a dedup layer's characteristic failure is to stop
        // deduplicating while every tree stays correct — invisible in every other signal this
        // process emits. `reused` falling to zero across a fleet is the symptom.
        let dedup = stored.dedup.clone().unwrap_or_default();
        tracing::info!(
            tenant,
            tree_id = %stored.tree_id,
            files = stats.files,
            dirs = stats.dirs,
            symlinks = stats.symlinks,
            bytes = stats.bytes,
            blobs_created = dedup.blobs_created,
            blobs_reused = dedup.blobs_reused,
            unshared = dedup.unshared,
            unshared_reason = dedup.unshared_reason.as_deref().unwrap_or(""),
            "verified tree stored"
        );

        // The store just grew, so this is where it is asked to shrink. `cached` is excluded on
        // purpose: a hit publishes nothing, and sweeping on hits would put a walk behind the one
        // operation the whole broker exists to make free.
        if !stored.cached {
            self.reclaim_after_commit(tenant);
        }
        Ok(stored)
    }

    /// Amortized reclamation: a tree was just published, so this tenant's store is asked to collect
    /// its garbage.
    ///
    /// **Why here and not in a background task.** This is the pattern `Control::accept` already uses
    /// for job eviction and for the outbox drain, and the reasoning transfers exactly: a commit
    /// arriving is cheap, honest evidence that this process is alive, that time has passed, and —
    /// uniquely for this job — that *the thing being bounded actually grew*. Pressure applied where
    /// growth happens needs no timer to own, no task to supervise, and nothing to shut down; it also
    /// cannot run on a store that is not changing, which is correct rather than a limitation, since a
    /// store that is not growing does not need sweeping.
    ///
    /// **Three properties, each pinned by a test:**
    ///
    /// * **Bounded and rate-limited.** [`Sweeps::claim`] is the whole of it: at most one sweep per
    ///   tenant per [`ReclaimConfig::cooldown`], decided under one lock so a sharded fan-out
    ///   committing twelve trees at once produces one walk and not twelve. `reclaim` walks a tenant's
    ///   trees and stats every one of its blobs, so it is emphatically not free.
    /// * **Never on the path to a verdict.** The claim is taken inline — a lock, a compare, an insert
    ///   — and the walk itself is handed to a *separate* blocking worker. Not inline on this thread:
    ///   this thread is the fetch, and a job is waiting on it for the tree it is about to run against,
    ///   so a store walk between the commit and the caller's return would put housekeeping latency
    ///   into every cold job. Not on an async worker either: it is `readdir` and `stat`, which is
    ///   exactly what `fetch_uncached` puts on `spawn_blocking` and for the same reason. The spawn is
    ///   fire-and-forget, like `Control::drain_undelivered`'s: it spawns and never waits.
    /// * **A sweep can never fail a job.** Nothing here returns a `Result` to the caller: a sweep
    ///   that cannot run at all, and one that fails partway through, are both logged and dropped. On
    ///   the spawned path the containment is total — the `JoinHandle` is dropped, so a panic inside
    ///   the sweep would be caught by the runtime and never seen by the fetch. The store growing is
    ///   an operational problem; a job that failed because of housekeeping would be a correctness
    ///   one, and a store that is full is still a *correct* store, only an expensive one.
    ///
    /// **The tree just committed is not at risk from the sweep it triggers**, twice over: `commit`
    /// stamped its use at this instant, so no retention can call it stale, and the caller is holding
    /// the [`TreePin`] inside the [`StoredTree`] we are about to return, which `reclaim` honours at
    /// any age.
    fn reclaim_after_commit(&self, tenant: &str) {
        if !self.reclaim.enabled {
            return;
        }
        if !self.sweeps.claim(tenant, self.reclaim.cooldown, Instant::now()) {
            tracing::debug!(tenant, "a sweep for this tenant ran within the cooldown; not sweeping again");
            return;
        }

        let (broker, owned) = (self.clone(), tenant.to_string());
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn_blocking(move || broker.sweep(&owned));
            }
            // A synchronous caller — `ingest` is public and is the seam for any future transport —
            // has no worker pool to hand this to. Running it inline is slower for that caller and is
            // the only alternative to not running at all, which is the failure this whole change
            // exists to remove. Deliberately not `block_in_place`: it panics outside a multi-thread
            // runtime, which would make the broker depend on how its host built its executor (the
            // same reasoning `fetch_uncached` records).
            Err(_) => self.sweep(tenant),
        }
    }

    /// One sweep, and the account of it. The only caller is [`Self::reclaim_after_commit`].
    ///
    /// `SystemTime::now()` is read here rather than passed in because this *is* the production
    /// caller; [`ReclaimPolicy::now`] is a parameter so that the store's own retention tests need no
    /// clock at all, and the tests of this path age a tree by writing its use stamp instead.
    fn sweep(&self, tenant: &str) {
        let policy = ReclaimPolicy { tree_retention: self.reclaim.tree_retention, now: SystemTime::now() };
        let result = self.store.reclaim(tenant, &policy);
        match &result {
            // Logged at `info` on every run, including the empty ones. A sweep that removes nothing
            // and a sweep that never ran leave an identical disk behind, and telling those two apart
            // from the outside is the entire reason `ReclaimReport` counts what it kept as well as
            // what it took.
            Ok(report) => tracing::info!(
                tenant,
                trees_removed = report.trees_removed,
                trees_pinned = report.trees_pinned,
                trees_in_retention = report.trees_in_retention,
                blobs_removed = report.blobs_removed,
                blobs_kept = report.blobs_kept,
                blobs_restored = report.blobs_restored,
                bytes_reclaimed = report.bytes_reclaimed,
                errors = report.errors,
                first_error = report.first_error.as_deref().unwrap_or(""),
                retention_secs = self.reclaim.tree_retention.as_secs(),
                "content store reclaimed"
            ),
            // A warning and nothing else. The job that triggered this is already finished with us,
            // and the consequence of the failure is a store that keeps growing — which is what an
            // operator needs to see, and is not something to fail work over.
            Err(e) => tracing::warn!(
                tenant,
                error = %e,
                "could not reclaim this tenant's content store; it will keep growing. No job is \
                 affected — the tree this commit published is stored and verified."
            ),
        }
        self.sweeps.finished(tenant, Sweep { tenant: tenant.to_string(), result: result.map_err(|e| e.to_string()) });
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

    /// A broker that fetches, verifies and stores, and does **not** sweep.
    ///
    /// Reclamation is off here on purpose. These tests are about the archive path, and a sweep
    /// running alongside one of them would make it a test about timing: the sweep a commit spawns
    /// reads the clock and the trees directory whenever it gets around to running, so a test that
    /// commits a tree and then ages it would be racing its own fixture. The reclamation tests below
    /// build their own broker and name the policy they are asserting against.
    fn broker() -> (TempDir, FetchBroker) {
        let dir = TempDir::new().unwrap();
        let broker = FetchBroker::new(ContentStore::new(dir.path()))
            .unwrap()
            .with_reclaim(ReclaimConfig { enabled: false, ..ReclaimConfig::default() });
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

    /// The store's retention clock only works if the runner's *actual* cache hit feeds it, so this
    /// asserts on `ensure_tree` — the function `BrokerFetcher` calls — rather than on the store
    /// method underneath it.
    ///
    /// The failure it exists to catch is a broker that goes back to `has()` + `tree_path()`: that is
    /// a hit the store never learns about, and a tree that is hit every hour would then be reaped as
    /// though it had not been touched since the day it was fetched. It is the same shape as trusting
    /// `atime` on a `noatime` mount — correct-looking, and wrong in the direction that deletes the
    /// most valuable trees first.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_brokers_own_cache_hit_is_what_keeps_a_tree_alive() {
        use std::time::{Duration, SystemTime};

        const WEEK: Duration = Duration::from_secs(7 * 24 * 60 * 60);
        let (_d, broker) = broker();
        let (archive, hot) = sample_archive();
        broker.ingest("acme", &hot, &archive[..]).unwrap();

        // A second tree, same age, that nobody will ask for again: the control that proves the sweep
        // ran at all. Without it an `ensure_tree` that reclaims nothing passes.
        let cold = "cd".repeat(32);
        let staged = broker.store().stage("acme").unwrap();
        std::fs::write(staged.path().join("a"), b"never wanted again").unwrap();
        broker.store().commit("acme", &cold, staged).unwrap();

        // Both look like they have not been wanted for a month.
        let month_ago = SystemTime::now() - 30 * Duration::from_secs(86_400);
        for id in [hot.as_str(), cold.as_str()] {
            broker.store().set_last_used("acme", id, month_ago);
        }

        // One hit through the path a dispatch takes. `source_url` points nowhere, so a fetch would
        // fail the test — this is a store hit and nothing else.
        let stored = broker
            .ensure_tree("acme", &hot, "http://127.0.0.1:1/never-dialed", None)
            .await
            .expect("the tree is in the store");
        assert!(stored.cached);
        // The pin the hit handed back is dropped here; the *record of the use* is what has to last.
        drop(stored);

        let report = broker
            .store()
            .reclaim("acme", &ReclaimPolicy { tree_retention: WEEK, now: SystemTime::now() })
            .unwrap();
        assert_eq!(report.trees_removed, 1, "the sweep has to have done something");
        assert!(broker.store().has("acme", &hot), "a tree the broker served an hour ago is not stale");
        assert!(!broker.store().has("acme", &cold), "and one nobody asked for is");
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
    /// `HeaderMode::Deterministic`, `follow_symlinks(false)`, `append_dir_all(".", dir)` over a
    /// checked-out tree).
    fn hull_style_archive(dir: &Path) -> Vec<u8> {
        hull_archive(dir, false)
    }

    /// The same, but dereferencing symlinks — what Hull produced before the fix, and what any
    /// archiver that forgets `follow_symlinks(false)` produces. Used only to prove we refuse it.
    fn dereferencing_archive(dir: &Path) -> Vec<u8> {
        hull_archive(dir, true)
    }

    fn hull_archive(dir: &Path, follow_symlinks: bool) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut ar = tar::Builder::new(&mut buf);
            ar.mode(tar::HeaderMode::Deterministic);
            ar.follow_symlinks(follow_symlinks);
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
    fn a_dereferenced_symlink_makes_a_tree_unverifiable_and_we_refuse_it() {
        let src = TempDir::new().unwrap();
        std::fs::write(src.path().join("real.txt"), b"payload\n").unwrap();
        std::os::unix::fs::symlink("real.txt", src.path().join("link.txt")).unwrap();

        let keel_dir = TempDir::new().unwrap();
        let store = keel_store::store::Store::open_with_map_size(keel_dir.path(), 64 * 1024 * 1024).unwrap();
        let tree_id = keel_store::snapshot::snapshot(&store, src.path()).unwrap().to_hex();

        // Hull's own archiver had this bug and nothing could see it until a verifying consumer
        // existed; it is fixed, and this is the guard against it or any other producer regressing.
        let (_d, broker) = broker();
        let err = broker.ingest("acme", &tree_id, &dereferencing_archive(src.path())[..]).unwrap_err();
        assert!(matches!(err, FetchError::Verify(VerifyError::Mismatch { .. })), "got {err:?}");
        assert!(!broker.store().has("acme", &tree_id), "and we refuse to serve the lossy tree");

        // The counterpart, and the half that would have caught the original bug directly: packed the
        // way Hull packs today, the very same tree verifies.
        assert!(broker.ingest("acme", &tree_id, &hull_style_archive(src.path())[..]).is_ok());
        assert!(broker.store().has("acme", &tree_id));
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

    // ─────────────────────────────────────────────────────────────────────────────────────────────
    // Amortized reclamation: the broker's half, which is the half that decides whether any of
    // `ContentStore::reclaim` ever runs at all.
    //
    // The failure this suite is built against is **wiring that silently never fires**. A store that
    // is never swept is not an incorrect store — it is a correct store that is full — so every
    // "the tree survived" assertion below is paired, in the same sweep, with a "this one did not",
    // and every removal is asserted on the report's counts *and* on the filesystem. Nothing infers
    // that a sweep happened from the absence of a complaint, and nothing here calls `reclaim`
    // directly: every sweep in this module is one a commit through `ingest` caused.
    //
    // Nothing measures elapsed time. Trees are aged by writing their use stamp, the rate limiter's
    // decisions are counted synchronously at the commit that makes them, and the only timeout is a
    // bound on how long a broken wiring is allowed to hang the suite before it fails.
    // ─────────────────────────────────────────────────────────────────────────────────────────────
    mod amortized_reclaim {
        use super::*;
        use std::path::PathBuf;
        use std::time::SystemTime;

        const MONTH: Duration = Duration::from_secs(30 * 24 * 60 * 60);
        const WEEK: Duration = Duration::from_secs(7 * 24 * 60 * 60);

        /// Sweep on every commit that publishes: the cooldown is what these tests are *not* about,
        /// except where it is, and a zero cooldown means a test that sees no sweep saw no sweep for
        /// the reason it is asserting on.
        fn immediate() -> ReclaimConfig {
            ReclaimConfig { enabled: true, tree_retention: WEEK, cooldown: Duration::ZERO }
        }

        fn broker_with(reclaim: ReclaimConfig) -> (TempDir, FetchBroker) {
            let dir = TempDir::new().unwrap();
            let broker = FetchBroker::new(ContentStore::new(dir.path())).unwrap().with_reclaim(reclaim);
            (dir, broker)
        }

        /// A one-file tree, as a tar and the `tree_id` keel gives it. Distinct contents make distinct
        /// trees, which is how a burst of commits is built.
        fn one_file_archive(content: &[u8]) -> (Vec<u8>, String) {
            let tar = tar_bytes(&[TarEntry::dir("./"), TarEntry::file("./README.md", content)]);
            let root = Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: "README.md".into(),
                    mode: MODE_FILE,
                    id: Object::Blob(content.to_vec()).id(),
                }],
            });
            (tar, root.id().to_hex())
        }

        /// A tree in the store that nobody has wanted for a month: committed normally, then stamped
        /// old. The stamp is written by the store's own writer (`set_last_used`), so this fixture
        /// cannot drift from the format retention actually reads.
        fn stale(store: &ContentStore, tenant: &str, tree_id: &str, bytes: &[u8]) {
            let staged = store.stage(tenant).unwrap();
            std::fs::write(staged.path().join("cold.bin"), bytes).unwrap();
            store.commit(tenant, tree_id, staged).unwrap();
            store.set_last_used(tenant, tree_id, SystemTime::now() - MONTH);
        }

        /// The one directory under a fresh store root: the tenant's scope. Named by a one-way hash,
        /// so a test cannot compute it and has to find it.
        fn tenant_scope_dir(root: &std::path::Path) -> PathBuf {
            let mut dirs: Vec<PathBuf> =
                std::fs::read_dir(root).unwrap().flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
            assert_eq!(dirs.len(), 1, "exactly one tenant has touched this store");
            dirs.pop().unwrap()
        }

        /// Wait for the next sweep to finish and return what it did.
        ///
        /// The timeout is a bound on failure, never an assertion about timing: a commit that does not
        /// reach `reclaim` produces no sweep *ever*, and the alternative to a bound is a suite that
        /// hangs instead of reporting which wire is cut.
        async fn next_sweep(rx: &mut watch::Receiver<Option<Sweep>>) -> Sweep {
            tokio::time::timeout(Duration::from_secs(30), rx.changed())
                .await
                .expect("no sweep ever finished: a commit is not reaching `ContentStore::reclaim`")
                .expect("the broker outlives its watchers");
            rx.borrow_and_update().clone().expect("a finished sweep always publishes its account")
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn committing_a_tree_reclaims_one_nobody_has_wanted_for_a_month() {
            let (_d, broker) = broker_with(immediate());
            let store = broker.store().clone();
            let cold = "cd".repeat(32);
            stale(&store, "acme", &cold, &[7u8; 4096]);
            assert!(store.has("acme", &cold), "the fixture is in the store to begin with");

            let mut sweeps = broker.sweeps();
            let (archive, fresh) = one_file_archive(b"fresh\n");
            let stored = broker.ingest("acme", &fresh, &archive[..]).expect("a faithful archive verifies");
            assert!(!stored.cached, "this commit is what makes the store grow");

            let report = next_sweep(&mut sweeps).await.result.expect("the sweep ran");
            assert_eq!(
                report.trees_removed, 1,
                "publishing a tree did not reclaim a month-stale one: the commit path is not \
                 calling `reclaim`, and the store grows without bound"
            );
            assert_eq!(report.trees_in_retention, 1, "and the tree this very commit published was kept");
            assert_eq!(report.blobs_removed, 1, "the stale tree held the last name on its blob");
            assert_eq!(report.blobs_kept, 1, "while the fresh tree's blob is still referenced");
            assert!(report.bytes_reclaimed >= 4096, "only {} bytes came back", report.bytes_reclaimed);

            // The report is the implementation's own account of itself, so the disk has to agree.
            assert!(!store.has("acme", &cold), "reported removed, still on disk");
            assert!(store.has("acme", &fresh));
            assert_eq!(
                std::fs::read_to_string(store.tree_path("acme", &fresh).join("README.md")).unwrap(),
                "fresh\n",
                "the tree the commit published is intact — a step is about to materialize from it"
            );
        }

        /// The synchronous caller. `ingest` is public and is the seam for any future transport, so a
        /// caller with no tokio runtime to hand the walk to still has to get one — inline, slower for
        /// that caller, and the only alternative to a store that silently never sweeps.
        ///
        /// Deliberately not a `#[tokio::test]`: with no runtime there is nothing to await, so this is
        /// the one test here that reads a finished sweep with no waiting of any kind.
        #[cfg(unix)]
        #[test]
        fn a_broker_with_no_runtime_sweeps_inline_rather_than_not_at_all() {
            let (_d, broker) = broker_with(immediate());
            let store = broker.store().clone();
            let cold = "cd".repeat(32);
            stale(&store, "acme", &cold, &[7u8; 4096]);

            let (archive, fresh) = one_file_archive(b"fresh\n");
            broker.ingest("acme", &fresh, &archive[..]).unwrap();

            // No await, no poll, no timeout: by the time `ingest` has returned, the sweep is over.
            let report = broker
                .sweeps()
                .borrow()
                .clone()
                .expect("a commit from a synchronous caller swept nothing at all")
                .result
                .expect("the sweep ran");
            assert_eq!(report.trees_removed, 1);
            assert!(!store.has("acme", &cold), "and the month-stale tree is gone from disk");
        }

        #[tokio::test]
        async fn a_burst_of_commits_does_not_become_a_burst_of_walks() {
            // The cooldown a deployment actually runs with. `reclaim` stats every blob a tenant
            // holds, so a 12-way sharded step publishing twelve trees at once must cost one walk.
            let (_d, broker) = broker_with(ReclaimConfig { cooldown: Duration::from_secs(15 * 60), ..immediate() });

            for i in 0..5u8 {
                let (archive, id) = one_file_archive(format!("shard {i}\n").as_bytes());
                assert!(!broker.ingest("acme", &id, &archive[..]).unwrap().cached, "five distinct trees");
            }
            assert_eq!(
                broker.sweeps_started(),
                1,
                "five commits produced {} walks; the cooldown is not holding",
                broker.sweeps_started()
            );

            // Per tenant, because `reclaim` is per tenant: one tenant's burst must never be the
            // reason another tenant's store is never swept.
            let (archive, id) = one_file_archive(b"globex\n");
            broker.ingest("globex", &id, &archive[..]).unwrap();
            assert_eq!(broker.sweeps_started(), 2, "a second tenant's commit is not rate-limited by the first's");
        }

        #[tokio::test]
        async fn a_cache_hit_sweeps_nothing_because_a_hit_grows_nothing() {
            // The cooldown is zero here, so the `cached` check is the only thing that can prevent the
            // second sweep — which is the point: a hit is the operation the whole broker exists to
            // make free, and putting a store walk behind it would be the most expensive place to
            // spend the saving.
            let (_d, broker) = broker_with(immediate());
            let (archive, id) = one_file_archive(b"once\n");

            assert!(!broker.ingest("acme", &id, &archive[..]).unwrap().cached);
            assert_eq!(broker.sweeps_started(), 1, "the publishing commit swept");
            assert!(broker.ingest("acme", &id, &archive[..]).unwrap().cached);
            assert_eq!(broker.sweeps_started(), 1, "and the hit did not");
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn a_tree_something_is_using_survives_the_sweep_a_commit_triggers() {
            let (_d, broker) = broker_with(immediate());
            let store = broker.store().clone();
            let in_use = "ab".repeat(32);
            stale(&store, "acme", &in_use, &[9u8; 2048]);

            // The claim a running job holds, taken the way `ContentStore::open` takes it. `pin` and
            // not `open`, because `open` would also stamp the tree freshly used — and then retention
            // would be what saved it, and this test would pass without the pin working at all.
            let pin = store.pin("acme", &in_use);

            let mut sweeps = broker.sweeps();
            let (archive, fresh) = one_file_archive(b"fresh\n");
            broker.ingest("acme", &fresh, &archive[..]).unwrap();

            let report = next_sweep(&mut sweeps).await.result.expect("the sweep ran");
            assert_eq!(
                report.trees_pinned, 1,
                "a stale tree somebody is holding was not skipped: a commit-triggered sweep would \
                 delete a queued job's tree out from under it"
            );
            assert_eq!(report.trees_removed, 0, "and nothing else was old enough to take");
            assert!(store.has("acme", &in_use));
            assert_eq!(
                std::fs::read(store.tree_path("acme", &in_use).join("cold.bin")).unwrap(),
                vec![9u8; 2048],
                "intact, not merely present"
            );
            assert_eq!(report.blobs_removed, 0, "its blob still has a tree naming it");

            // The other half, and the one that catches a pin nobody ever releases: a claim that
            // outlives its job is a store that can never be reclaimed, which is the same full disk
            // arrived at from the opposite direction.
            drop(pin);
            let (archive, second) = one_file_archive(b"second\n");
            broker.ingest("acme", &second, &archive[..]).unwrap();

            let report = next_sweep(&mut sweeps).await.result.expect("the second sweep ran");
            assert_eq!(report.trees_removed, 1, "released, and the next commit's sweep took it");
            assert_eq!(report.trees_in_retention, 2, "leaving exactly the two trees these commits published");
            assert!(!store.has("acme", &in_use));
            assert!(report.bytes_reclaimed >= 2048, "and its bytes came back");
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn a_sweep_that_cannot_run_fails_neither_the_commit_nor_the_job() {
            let (dir, broker) = broker_with(immediate());
            let store = broker.store().clone();

            // `reclaim`'s one hard failure: it cannot make the scratch directory that removals are
            // renamed into, so no removal is possible at all. Arranged by putting a *file* where that
            // directory has to be — a read-only or full filesystem produces the same shape, and this
            // one is reproducible.
            store.stage("acme").unwrap();
            std::fs::write(tenant_scope_dir(dir.path()).join("reclaiming"), b"not a directory").unwrap();

            let mut sweeps = broker.sweeps();
            let (archive, fresh) = one_file_archive(b"fresh\n");
            let stored = broker
                .ingest("acme", &fresh, &archive[..])
                .expect("housekeeping that fails must never fail the commit that triggered it");

            // The job's half: the tree is published, verified and readable, which is everything the
            // step that follows needs.
            assert!(!stored.cached);
            assert!(store.has("acme", &fresh));
            assert_eq!(std::fs::read_to_string(stored.path.join("README.md")).unwrap(), "fresh\n");

            // And the sweep really did fail, which is what keeps this from being a test that passes
            // because nothing was ever attempted.
            let err = next_sweep(&mut sweeps)
                .await
                .result
                .expect_err("the sabotage did not break the sweep, so this proves nothing");
            assert!(err.contains("i/o"), "the failure is reported, not swallowed: {err}");
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn reclamation_turned_off_really_does_nothing() {
            let (_d, broker) = broker_with(ReclaimConfig { enabled: false, ..immediate() });
            let store = broker.store().clone();
            let cold = "cd".repeat(32);
            stale(&store, "acme", &cold, &[7u8; 4096]);

            let sweeps = broker.sweeps();
            let (archive, fresh) = one_file_archive(b"fresh\n");
            broker.ingest("acme", &fresh, &archive[..]).unwrap();

            // Both halves are decided synchronously at the commit, so there is nothing to wait for:
            // `enabled` is checked before the claim, and the claim is what a spawn would follow.
            assert_eq!(broker.sweeps_started(), 0, "`off` must not even claim the right to walk");
            assert!(!sweeps.has_changed().unwrap(), "and nothing finished a sweep either");
            assert!(store.has("acme", &cold), "so the month-stale tree is still here");

            // The control, and it is the difference between this test and one that passes because the
            // fixture was never reclaimable. Same store, same tenant, same month-old stamp; only the
            // switch differs.
            let on = broker.clone().with_reclaim(immediate());
            let mut sweeps = on.sweeps();
            let (archive, second) = one_file_archive(b"second\n");
            on.ingest("acme", &second, &archive[..]).unwrap();
            let report = next_sweep(&mut sweeps).await.result.expect("the sweep ran");
            assert_eq!(report.trees_removed, 1, "with the switch on, that very tree goes");
            assert!(!store.has("acme", &cold));
        }
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
