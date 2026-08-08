//! **Step-level memoization — design D§6.1, layer 2.** The reason this design exists.
//!
//! Hull already memoizes by `tree_id` (layer 1), so an identical tree is never dispatched at all.
//! This is the layer *underneath* that: a rebase, a doc-only edit, an unrelated-crate change, or an
//! independence tree (D§8) produces a **new** tree that Hull has never seen — and most of its steps
//! are nevertheless the same work. A step whose recorded key has a `passed` result is marked
//! [`StepState::Cached`] and never dispatched. If every step is cached, the job resolves without
//! touching a node and the callback goes out in milliseconds.
//!
//! ```text
//! step_key = H( tenant, pipeline_version, tier, author_class,
//!               step_def_canonical, image,
//!               subtree_digest(inputs_glob) …,     ← from keel, no file hashing
//!               env_allowlist_values,
//!               step_key(each dependency) )
//! ```
//!
//! Four things this file treats as non-negotiable, each with the failure it prevents:
//!
//! 1. **The key is tenant-scoped, and so is the store.** D§1's timing/existence-oracle row: cache-hit
//!    vs miss latency reveals whether *another* tenant built the same input. Both halves are here on
//!    purpose — the tenant is hashed into the key *and* the store is keyed by `(tenant, key)` — so a
//!    cross-tenant hit is structurally impossible rather than merely unlikely, and neither half alone
//!    is trusted to be the one that holds.
//! 2. **`errored` is never recorded.** Not "filtered on read" — [`MemoOutcome`] has no variant for
//!    it, so an outage cannot be written down in the first place. This mirrors spec §7's discipline
//!    (Hull memoizes green and red, never errored) one level down, for the same reason: an outage
//!    must not poison anything. `failed` *is* recorded, briefly — it is real signal about the code,
//!    and a repeat dispatch should not rerun the world to rediscover it.
//! 3. **A step with no declared `inputs` is never cacheable.** An empty input set keys every run of
//!    that step identically, so the first `passed` would be served forever, for every tree, until the
//!    entry expired — a stale green on code nobody checked. [`NotCacheable::NoInputs`] is a refusal
//!    at the point of key construction, not a subtlety further down. The same refusal covers globs
//!    that *select* nothing ([`NotCacheable::InputsSelectedNothing`]), which is the same hazard with
//!    a plausible-looking `inputs` list in front of it.
//! 4. **A dependency that cannot be keyed makes its dependents uncacheable.** Dependency keys feed
//!    in, so a changed root invalidates everything downstream; the converse is that an *unknown*
//!    root leaves everything downstream unknowable, and guessing would cache a step against inputs
//!    we did not actually account for.
//!
//! ## Canonicalization
//!
//! Two steps that differ only in field *order* must produce the same key; two that differ in
//! anything affecting execution must not. So every set-shaped field is sorted and de-duplicated
//! (`inputs`, `secrets`, `env_allowlist`, the dependency keys) while every sequence-shaped field
//! keeps its order (`argv` — where order is the meaning). Every field is length-prefixed and
//! tagged, so no two different step definitions can serialize to the same bytes.
//!
//! `needs` *names* are deliberately **not** hashed: the dependency's key is, which is the stronger
//! statement (it covers what the dependency does, not what it is called) and lets a pure rename
//! stay a cache hit.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hull_ci_proto::{AuthorClass, IsolationTier};

use crate::model::{StepSpec, StepState};
use crate::seams::VerifiedTree;

/// Domain separator and format version. Bumping this invalidates every recorded key at once, which
/// is the intended lever if the canonical encoding below ever changes: a key computed under two
/// different encodings that collides is a *wrong* cache hit, and there is no cheaper way to be sure.
const STEP_KEY_DOMAIN: &[u8] = b"hull-ci/step-key/v1";

/// A step's memo key: 64 lowercase hex characters.
///
/// Opaque by construction — there is no way to build one except from a full set of inputs, so a
/// caller cannot accidentally look up a key that omitted the tenant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StepKey(String);

impl StepKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for StepKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ── The subtree-digest seam ──────────────────────────────────────────────────────────────────────

/// One glob's content digest, as [`SubtreeDigest`] answers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputDigest {
    pub digest: String,
    /// How many tree entries the glob selected. Zero means the glob named nothing that exists, which
    /// is a refusal to cache — see [`NotCacheable::InputsSelectedNothing`].
    pub selected: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum DigestError {
    #[error("no subtree digester is wired into this control plane")]
    Unwired,
    #[error("`{glob}` could not be resolved against the tree: {detail}")]
    Failed { glob: String, detail: String },
}

/// Resolving an `inputs` glob to a content digest (design D§6.1).
///
/// A seam for the same reason the other three are ([`crate::seams`]): resolving a glob means reading
/// the extracted tree, and the control plane does not do filesystem work. The implementation lives
/// next to keel's object model in `hull-ci-fetch`, which is where the tree's Merkle structure — and
/// therefore every subtree address this needs — already is.
pub trait SubtreeDigest: Send + Sync + 'static {
    fn digest(&self, tenant: &str, tree: &VerifiedTree, glob: &str) -> Result<InputDigest, DigestError>;

    /// Whether this digester can answer at all. Only the unwired placeholder says no; it exists so
    /// the driver can skip the whole memo phase without a probe call that would touch a filesystem.
    fn available(&self) -> bool {
        true
    }
}

/// The default: no digester, so **nothing is ever cacheable**.
///
/// Unwired means off, not open. A digester that answered a constant would key every tree the same
/// and serve one tree's verdict for another's code — so the placeholder refuses, and a control plane
/// with no digester simply runs every step, which is exactly what it did before layer 2 existed.
pub struct NoDigest;

impl SubtreeDigest for NoDigest {
    fn digest(&self, _tenant: &str, _tree: &VerifiedTree, _glob: &str) -> Result<InputDigest, DigestError> {
        Err(DigestError::Unwired)
    }

    fn available(&self) -> bool {
        false
    }
}

// ── The memo store ───────────────────────────────────────────────────────────────────────────────

/// What may be written to the memo.
///
/// **There is deliberately no `Errored` variant.** Spec §7 draws this line for Hull's tree memo and
/// D§6.1 restates it for ours: an infrastructure failure is a statement about us, not about the
/// code, and caching one would let a five-minute outage decide a tree for as long as the entry
/// lived. Making it unrepresentable is stronger than remembering to filter it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoOutcome {
    Passed,
    Failed,
}

impl MemoOutcome {
    /// The subset of terminal states that may be remembered. `None` for everything else —
    /// `Errored` above all, but also `Cached` (already recorded), `Skipped` (never ran, so it is
    /// evidence of nothing) and any non-terminal state.
    pub fn from_state(state: StepState) -> Option<MemoOutcome> {
        match state {
            StepState::Passed => Some(MemoOutcome::Passed),
            StepState::Failed => Some(MemoOutcome::Failed),
            StepState::Errored
            | StepState::Cached
            | StepState::Skipped
            | StepState::Pending
            | StepState::Ready
            | StepState::Leased
            | StepState::Running => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            MemoOutcome::Passed => "passed",
            MemoOutcome::Failed => "failed",
        }
    }
}

/// `(tenant, step_key) → outcome`.
///
/// The tenant is a **parameter of every operation**, not a component the caller folds into the key
/// itself, so an implementation cannot accidentally offer a lookup that spans tenants (D§1).
pub trait StepMemo: Send + Sync + 'static {
    fn lookup(&self, tenant: &str, key: &StepKey, now: Instant) -> Option<MemoOutcome>;
    fn record(&self, tenant: &str, key: &StepKey, outcome: MemoOutcome, now: Instant);
}

/// How long each outcome survives (design D§6.1).
#[derive(Debug, Clone, Copy)]
pub struct MemoPolicy {
    /// `passed` is cached long-lived: the tree is immutable and the inputs are content-addressed, so
    /// the answer cannot go stale on its own. The bound exists to reclaim memory and to keep a bug
    /// in this file from being permanent, not because the entry expires in any meaningful sense.
    pub passed_ttl: Duration,
    /// `failed` is cached **briefly**. It is real signal — the code genuinely failed on these exact
    /// inputs — and a repeat dispatch should not rerun the world to rediscover it. Short because a
    /// failure is the thing an author is actively trying to change, and because a flaky failure
    /// should cost minutes of wrongness, not days.
    pub failed_ttl: Duration,
    /// Hard ceiling on entries across every tenant. Eviction takes from the tenant holding the
    /// **most** entries (oldest of that tenant first), never simply the oldest in the store: the
    /// capacity is a shared surface, and plain oldest-first lets one tenant's writes evict a
    /// neighbour's whole cache (D§1, noisy-neighbour). Every eviction costs a re-run and can never
    /// cause a wrong answer.
    pub capacity: usize,
}

impl Default for MemoPolicy {
    fn default() -> Self {
        MemoPolicy {
            passed_ttl: Duration::from_secs(7 * 24 * 60 * 60),
            failed_ttl: Duration::from_secs(10 * 60),
            capacity: 100_000,
        }
    }
}

/// An in-process memo. M1 shape, matching the rest of the control plane's state (design D§13): the
/// key derivation and the tenant scoping are the parts that must be right, and they do not change
/// when this becomes a table.
pub struct InMemoryStepMemo {
    policy: MemoPolicy,
    entries: Mutex<HashMap<(String, StepKey), Entry>>,
    /// Insertion counter. A monotonic sequence rather than the wall clock, because `record` takes an
    /// injected `now` that tests move around freely and eviction order must not depend on it.
    next_seq: std::sync::atomic::AtomicU64,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    outcome: MemoOutcome,
    expires_at: Instant,
    /// Insertion order, for eviction.
    seq: u64,
}

impl Default for InMemoryStepMemo {
    fn default() -> Self {
        InMemoryStepMemo::new(MemoPolicy::default())
    }
}

impl InMemoryStepMemo {
    pub fn new(policy: MemoPolicy) -> Self {
        InMemoryStepMemo {
            policy,
            entries: Mutex::new(HashMap::new()),
            next_seq: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(String, StepKey), Entry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl StepMemo for InMemoryStepMemo {
    fn lookup(&self, tenant: &str, key: &StepKey, now: Instant) -> Option<MemoOutcome> {
        let mut entries = self.lock();
        let k = (tenant.to_string(), key.clone());
        let entry = *entries.get(&k)?;
        if now >= entry.expires_at {
            // Dropped on the way past rather than by a sweep: expiry is only observable here, and a
            // background task to own and shut down would be machinery for no gain.
            entries.remove(&k);
            return None;
        }
        Some(entry.outcome)
    }

    fn record(&self, tenant: &str, key: &StepKey, outcome: MemoOutcome, now: Instant) {
        let ttl = match outcome {
            MemoOutcome::Passed => self.policy.passed_ttl,
            MemoOutcome::Failed => self.policy.failed_ttl,
        };
        let seq = self.next_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut entries = self.lock();
        if entries.len() >= self.policy.capacity {
            if let Some(victim) = evictee(&entries, tenant) {
                entries.remove(&victim);
            }
        }
        entries.insert(
            (tenant.to_string(), key.clone()),
            Entry { outcome, expires_at: now + ttl, seq },
        );
    }
}

/// Which entry to drop to make room for a write by `recording`.
///
/// **Not the oldest entry in the store.** The capacity is the one part of this memo that every
/// tenant shares, and oldest-first eviction turns it into a cross-tenant channel in both directions
/// of D§1's threat table: a tenant that writes `capacity` entries evicts every neighbour's cache
/// (noisy neighbour — the neighbour then re-runs work it had already paid for), and a tenant that
/// fills the store and re-reads its own keys can *count* its neighbours' writes by watching how many
/// of its own survive (existence oracle).
///
/// So the largest holder pays. Ties go to the tenant doing the writing, which is what makes a
/// flooding tenant evict itself rather than anyone else; the remaining tie-break is the tenant name,
/// so the choice is deterministic and testable. This is max-min fairness over a fixed store: a
/// tenant with fewer entries than the flooder can never be the one evicted, so no volume of writes
/// by one tenant can displace a smaller neighbour.
///
/// It does **not** make the shared capacity signal-free — a tenant holding the largest share still
/// sees its own entries go when it is the one over quota. Removing that last bit needs a per-tenant
/// partition of the store, which is a storage-layout decision rather than an eviction one.
fn evictee(
    entries: &HashMap<(String, StepKey), Entry>,
    recording: &str,
) -> Option<(String, StepKey)> {
    let mut held: HashMap<&str, usize> = HashMap::new();
    for (tenant, _) in entries.keys() {
        *held.entry(tenant.as_str()).or_default() += 1;
    }
    // Most entries first; a tie is won by the writer, then by name.
    let fullest = held
        .into_iter()
        .max_by(|(a_name, a), (b_name, b)| {
            a.cmp(b)
                .then_with(|| (*a_name == recording).cmp(&(*b_name == recording)))
                .then_with(|| b_name.cmp(a_name))
        })
        .map(|(name, _)| name.to_string())?;
    entries
        .iter()
        .filter(|((tenant, _), _)| *tenant == fullest)
        .min_by_key(|(_, e)| e.seq)
        .map(|(k, _)| k.clone())
}

// ── Configuration ────────────────────────────────────────────────────────────────────────────────

/// Everything layer 2 is wired with. Lives on [`ControlConfig`](crate::ControlConfig) rather than on
/// `Deps` because its default is *disabled*, and a deployment that has not wired a digester must
/// keep behaving exactly as it did before this file existed.
#[derive(Clone)]
pub struct MemoConfig {
    pub digest: Arc<dyn SubtreeDigest>,
    pub store: Arc<dyn StepMemo>,
    /// Identifies the pipeline *semantics* a key was computed under — the evaluator version, the
    /// image policy, anything that changes what a step definition means without changing the
    /// definition itself. Bumping it invalidates every key, which is the point.
    pub pipeline_version: String,
}

impl Default for MemoConfig {
    fn default() -> Self {
        MemoConfig {
            digest: Arc::new(NoDigest),
            store: Arc::new(InMemoryStepMemo::default()),
            pipeline_version: "hull-ci/0".into(),
        }
    }
}

impl MemoConfig {
    /// Whether anything can be cached at all. False on the default wiring, and the driver's cue to
    /// skip the memo phase entirely rather than compute keys nothing will ever look up.
    pub fn enabled(&self) -> bool {
        self.digest.available()
    }
}

// ── Key construction ─────────────────────────────────────────────────────────────────────────────

/// Why a step has no key, and therefore can never be a cache hit or a cache write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotCacheable {
    /// The step declared no `inputs`. **The load-bearing refusal**: with no inputs the key does not
    /// mention the tree at all, so every run of the step in the tenant's history would share one
    /// key and the first `passed` would be served forever.
    NoInputs,
    /// Every declared glob selected nothing that exists in this tree. Same hazard as `NoInputs`,
    /// dressed as a real declaration — `crates/**` in a repo with no `crates/` folds an empty set,
    /// which is the same digest on every tree in existence.
    InputsSelectedNothing,
    /// A glob could not be resolved (malformed, or the tree could not be read). Never guessed past:
    /// a key that silently omitted an input would cache a step against inputs nobody accounted for.
    DigestUnavailable(String),
    /// A step this one `needs` is not itself cacheable, so its key cannot feed into this one.
    DependencyNotCacheable(String),
    /// The plan named a `needs` target that does not exist. The graph reports this as a broken plan;
    /// here it is simply a reason there is no key.
    UndeclaredDependency(String),
}

impl std::fmt::Display for NotCacheable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotCacheable::NoInputs => write!(f, "the step declares no inputs"),
            NotCacheable::InputsSelectedNothing => write!(f, "the step's inputs select nothing in this tree"),
            NotCacheable::DigestUnavailable(d) => write!(f, "an input digest is unavailable: {d}"),
            NotCacheable::DependencyNotCacheable(n) => write!(f, "dependency `{n}` is not cacheable"),
            NotCacheable::UndeclaredDependency(n) => write!(f, "dependency `{n}` is not in the plan"),
        }
    }
}

/// Everything about the *job* that a step key must account for, on top of the step's own definition.
///
/// `tier` and `author_class` are here because both change what the step actually does, and D§6.1's
/// formula omits them. An `outsider`-authored job receives **no tenant secrets** (D§7.4) and its
/// cache access differs (D§6.3), so a `passed` recorded for a member's run of a byte-identical step
/// is not evidence about the outsider's run of it — and serving it would be a cache hit that skipped
/// the step that would have failed. The tier is the same argument for the sandbox.
#[derive(Debug, Clone)]
pub struct JobKeyContext {
    pub tenant: String,
    pub tier: IsolationTier,
    pub author_class: AuthorClass,
}

/// One step's key, or the reason it has none.
pub type KeyResult = Result<StepKey, NotCacheable>;

/// Compute a key for every step of a plan, in dependency order.
///
/// Dependency keys feed into their dependents' keys (D§6.1), which is what makes a changed root
/// invalidate everything downstream. The planner guarantees a `needs` target is declared *before*
/// the step that names it (D§4.4), so one forward pass suffices — the same property that makes
/// cycles unrepresentable.
///
/// Reads the extracted tree through [`SubtreeDigest`], so callers should keep it off an async
/// executor thread.
pub fn plan_step_keys(
    memo: &MemoConfig,
    ctx: &JobKeyContext,
    tree: &VerifiedTree,
    specs: &[StepSpec],
) -> Vec<KeyResult> {
    let mut keys: Vec<KeyResult> = Vec::with_capacity(specs.len());
    for spec in specs {
        let mut dep_keys: Vec<StepKey> = Vec::with_capacity(spec.needs.len());
        let mut refusal = None;
        for need in &spec.needs {
            match specs.iter().position(|s| &s.name == need).and_then(|i| keys.get(i)) {
                Some(Ok(k)) => dep_keys.push(k.clone()),
                Some(Err(_)) => {
                    refusal = Some(NotCacheable::DependencyNotCacheable(need.clone()));
                    break;
                }
                None => {
                    refusal = Some(NotCacheable::UndeclaredDependency(need.clone()));
                    break;
                }
            }
        }
        keys.push(match refusal {
            Some(r) => Err(r),
            None => step_key(memo, ctx, tree, spec, &dep_keys),
        });
    }
    keys
}

/// One step's key — the D§6.1 formula, canonicalized.
pub fn step_key(
    memo: &MemoConfig,
    ctx: &JobKeyContext,
    tree: &VerifiedTree,
    spec: &StepSpec,
    dependency_keys: &[StepKey],
) -> KeyResult {
    // Refusal 1 of 2, and the one that matters most: no inputs, no key, no cache. Checked before any
    // work so the cheap "this pipeline has not declared its inputs" case costs nothing.
    if spec.inputs.is_empty() {
        return Err(NotCacheable::NoInputs);
    }

    let mut globs: Vec<String> = spec.inputs.iter().map(|g| g.trim().to_string()).collect();
    globs.sort();
    globs.dedup();

    let mut digests: Vec<(String, String)> = Vec::with_capacity(globs.len());
    let mut selected_any = false;
    for glob in &globs {
        match memo.digest.digest(&ctx.tenant, tree, glob) {
            Ok(d) => {
                selected_any |= d.selected > 0;
                digests.push((glob.clone(), d.digest));
            }
            Err(e) => return Err(NotCacheable::DigestUnavailable(e.to_string())),
        }
    }
    // Refusal 2 of 2: globs that name nothing key every tree identically, exactly like no inputs at
    // all. A step whose `inputs` are all typos must run, not pass forever.
    if !selected_any {
        return Err(NotCacheable::InputsSelectedNothing);
    }

    let mut h = blake3::Hasher::new();
    h.update(STEP_KEY_DOMAIN);

    // The tenant, first and unconditionally. D§1: a cross-tenant hit must be structurally
    // impossible, and this is half of what makes it so (the store's key is the other half).
    field(&mut h, 0x01, ctx.tenant.as_bytes());
    field(&mut h, 0x02, memo.pipeline_version.as_bytes());
    field(&mut h, 0x03, &[tier_tag(ctx.tier)]);
    field(&mut h, 0x04, &[author_tag(ctx.author_class)]);

    // ── step_def_canonical ──
    field(&mut h, 0x10, spec.name.as_bytes());
    field(&mut h, 0x11, spec.image.as_bytes());
    // `argv` keeps its order: order *is* the meaning of a command line.
    seq(&mut h, 0x12, spec.argv.iter().map(|a| a.as_bytes()));
    // The timeout and the tolerance flag both change what "this step passed" means, so both are in.
    field(&mut h, 0x13, &spec.timeout.map_or(u64::MAX, |d| d.as_secs()).to_le_bytes());
    field(&mut h, 0x14, &[u8::from(spec.continue_on_error)]);
    // A *request* for secrets, not a grant — but a step that asks for a different secret set is a
    // different step, because what it receives changes what it can do.
    set(&mut h, 0x15, spec.secrets.iter().map(String::as_str));

    // ── inputs ──
    h.update(&[0x20]);
    h.update(&(digests.len() as u64).to_le_bytes());
    for (glob, digest) in &digests {
        lp(&mut h, glob.as_bytes());
        lp(&mut h, digest.as_bytes());
    }

    // ── env allowlist ──
    // Values, not just names (D§6.1's `env_allowlist_values`): a step run with `PROFILE=release` did
    // different work from the same step run with `PROFILE=debug`.
    let mut env: Vec<(&str, &str)> = spec.env_allowlist.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    env.sort();
    env.dedup();
    h.update(&[0x21]);
    h.update(&(env.len() as u64).to_le_bytes());
    for (k, v) in env {
        lp(&mut h, k.as_bytes());
        lp(&mut h, v.as_bytes());
    }

    // ── dependencies ──
    // Sorted, so two plans that list the same `needs` in a different order agree. The *keys* go in,
    // not the names: a renamed dependency doing identical work is still a hit, and a dependency
    // whose own inputs moved invalidates everything below it.
    set(&mut h, 0x30, dependency_keys.iter().map(|k| k.as_str()));

    Ok(StepKey(hex(h.finalize().as_bytes())))
}

/// A tagged, length-prefixed field. The tag means two fields can never be confused for one another
/// even if one is empty; the length prefix means `("ab", "c")` and `("a", "bc")` cannot collide.
fn field(h: &mut blake3::Hasher, tag: u8, bytes: &[u8]) {
    h.update(&[tag]);
    lp(h, bytes);
}

/// An ordered sequence.
fn seq<'a>(h: &mut blake3::Hasher, tag: u8, items: impl Iterator<Item = &'a [u8]>) {
    let items: Vec<&[u8]> = items.collect();
    h.update(&[tag]);
    h.update(&(items.len() as u64).to_le_bytes());
    for item in items {
        lp(h, item);
    }
}

/// An unordered set: sorted and de-duplicated, so declaration order cannot change the key.
fn set<'a>(h: &mut blake3::Hasher, tag: u8, items: impl Iterator<Item = &'a str>) {
    let mut items: Vec<&str> = items.collect();
    items.sort_unstable();
    items.dedup();
    seq(h, tag, items.into_iter().map(str::as_bytes));
}

fn lp(h: &mut blake3::Hasher, bytes: &[u8]) {
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(bytes);
}

/// Exhaustive on purpose: adding an isolation tier must be a compile error here, not a silent
/// collision between two tiers' results.
fn tier_tag(tier: IsolationTier) -> u8 {
    match tier {
        IsolationTier::MicroVm => 1,
        IsolationTier::Container => 2,
    }
}

/// Exhaustive for the same reason, and a sharper one: author class decides secret delivery (D§7.4),
/// so two classes sharing a key would let an outsider's job be answered by a member's run.
fn author_tag(class: AuthorClass) -> u8 {
    match class {
        AuthorClass::Member => 1,
        AuthorClass::Outsider => 2,
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A digester that answers from a table: `(tenant, tree_id, glob) → digest`. Real tree walking
    /// is tested in `hull-ci-fetch`; what is tested here is what the *key* does with the answer.
    struct TableDigest {
        entries: Vec<((String, String, String), InputDigest)>,
    }

    impl TableDigest {
        fn new(rows: &[(&str, &str, &str, &str)]) -> Arc<TableDigest> {
            Arc::new(TableDigest {
                entries: rows
                    .iter()
                    .map(|(tenant, tree, glob, digest)| {
                        (
                            ((*tenant).to_string(), (*tree).to_string(), (*glob).to_string()),
                            InputDigest { digest: (*digest).to_string(), selected: 1 },
                        )
                    })
                    .collect(),
            })
        }
    }

    impl SubtreeDigest for TableDigest {
        fn digest(&self, tenant: &str, tree: &VerifiedTree, glob: &str) -> Result<InputDigest, DigestError> {
            let k = (tenant.to_string(), tree.tree_id.clone(), glob.to_string());
            self.entries
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, d)| d.clone())
                .ok_or_else(|| DigestError::Failed { glob: glob.into(), detail: "not in table".into() })
        }
    }

    /// A digester that answers the same digest for every glob on every tree — the shape a lazy
    /// implementation takes, used to isolate what the *other* key components contribute.
    struct ConstDigest(usize);

    impl SubtreeDigest for ConstDigest {
        fn digest(&self, _t: &str, _tree: &VerifiedTree, _glob: &str) -> Result<InputDigest, DigestError> {
            Ok(InputDigest { digest: "c".repeat(64), selected: self.0 })
        }
    }

    fn memo_with(digest: Arc<dyn SubtreeDigest>) -> MemoConfig {
        MemoConfig { digest, ..MemoConfig::default() }
    }

    fn tree(id: &str) -> VerifiedTree {
        VerifiedTree { tree_id: id.into(), path: PathBuf::from("/nonexistent"), cached: false, keep_alive: None }
    }

    fn ctx(tenant: &str) -> JobKeyContext {
        JobKeyContext {
            tenant: tenant.into(),
            tier: IsolationTier::Container,
            author_class: AuthorClass::Member,
        }
    }

    fn spec(name: &str) -> StepSpec {
        StepSpec::new(name, vec!["cargo".into(), "test".into()], "rust:1.83")
            .inputs(vec!["crates/**".into()])
    }

    fn key(memo: &MemoConfig, ctx: &JobKeyContext, tree_id: &str, spec: &StepSpec) -> KeyResult {
        step_key(memo, ctx, &tree(tree_id), spec, &[])
    }

    #[test]
    fn the_same_tree_and_the_same_step_produce_the_same_key() {
        let memo = memo_with(Arc::new(ConstDigest(1)));
        assert_eq!(key(&memo, &ctx("acme"), "t1", &spec("test")), key(&memo, &ctx("acme"), "t1", &spec("test")));
    }

    #[test]
    fn a_step_with_no_inputs_is_never_cacheable() {
        // The refusal that keeps a stale green out of the system. With no inputs the key would not
        // mention the tree at all, so one `passed` would answer every future run of this step.
        let memo = memo_with(Arc::new(ConstDigest(1)));
        let no_inputs = StepSpec::new("test", vec!["cargo".into()], "img");
        assert_eq!(key(&memo, &ctx("acme"), "t1", &no_inputs), Err(NotCacheable::NoInputs));
    }

    #[test]
    fn inputs_that_select_nothing_are_the_same_refusal() {
        // `inputs = ["crates/**"]` in a repo with no `crates/` is an empty set with a plausible
        // declaration in front of it — identical on every tree, so identically unusable.
        let memo = memo_with(Arc::new(ConstDigest(0)));
        assert_eq!(key(&memo, &ctx("acme"), "t1", &spec("test")), Err(NotCacheable::InputsSelectedNothing));
    }

    #[test]
    fn an_unresolvable_glob_refuses_rather_than_keying_around_it() {
        let memo = memo_with(TableDigest::new(&[]));
        assert!(matches!(
            key(&memo, &ctx("acme"), "t1", &spec("test")),
            Err(NotCacheable::DigestUnavailable(_))
        ));
    }

    #[test]
    fn two_tenants_with_byte_identical_trees_and_steps_get_different_keys() {
        // D§1's timing/existence-oracle row. Both tenants' trees hash the same, both steps are
        // byte-identical, and the keys still must not meet.
        let memo = memo_with(Arc::new(ConstDigest(1)));
        let a = key(&memo, &ctx("acme"), "t1", &spec("test")).unwrap();
        let b = key(&memo, &ctx("other"), "t1", &spec("test")).unwrap();
        assert_ne!(a, b, "identical work for two tenants must not share a key");
    }

    /// **Mutation test.** Recompute the key the way a plausible mistake would — omitting the tenant
    /// — and prove the two tenants then collide. If someone deletes the `field(…, 0x01, tenant)`
    /// line above, `two_tenants_with_byte_identical_trees_and_steps_get_different_keys` fails; this
    /// test is the demonstration that the line is what stands between us and a cross-tenant hit.
    #[test]
    fn dropping_the_tenant_from_the_key_would_collide_across_tenants() {
        let without_tenant = |tenant: &str| {
            let mut h = blake3::Hasher::new();
            h.update(STEP_KEY_DOMAIN);
            let _ = tenant; // deliberately unused: this is the bug being modelled
            field(&mut h, 0x02, b"hull-ci/0");
            field(&mut h, 0x10, b"test");
            hex(h.finalize().as_bytes())
        };
        assert_eq!(
            without_tenant("acme"),
            without_tenant("other"),
            "a tenant-free key is the same key for everyone — which is the hit D§1 forbids"
        );
    }

    #[test]
    fn a_changed_input_digest_changes_the_key() {
        let memo = memo_with(TableDigest::new(&[
            ("acme", "t1", "crates/**", "aaaa"),
            ("acme", "t2", "crates/**", "bbbb"),
        ]));
        let t1 = key(&memo, &ctx("acme"), "t1", &spec("test")).unwrap();
        let t2 = key(&memo, &ctx("acme"), "t2", &spec("test")).unwrap();
        assert_ne!(t1, t2);
    }

    #[test]
    fn a_tree_change_outside_every_glob_leaves_the_key_alone() {
        // Two different trees whose `crates/**` content is identical — a doc-only edit. The key is a
        // statement about the declared inputs, not about the tree.
        let memo = memo_with(TableDigest::new(&[
            ("acme", "t1", "crates/**", "aaaa"),
            ("acme", "t2", "crates/**", "aaaa"),
        ]));
        assert_eq!(
            key(&memo, &ctx("acme"), "t1", &spec("test")).unwrap(),
            key(&memo, &ctx("acme"), "t2", &spec("test")).unwrap()
        );
    }

    #[test]
    fn field_order_does_not_change_the_key_but_field_content_does() {
        let memo = memo_with(Arc::new(ConstDigest(1)));
        let c = ctx("acme");

        // Set-shaped fields are order-independent…
        let a = spec("test")
            .inputs(vec!["crates/**".into(), "Cargo.toml".into()])
            .secrets(vec!["NPM_TOKEN".into(), "AWS".into()]);
        let b = spec("test")
            .inputs(vec!["Cargo.toml".into(), "crates/**".into()])
            .secrets(vec!["AWS".into(), "NPM_TOKEN".into()]);
        assert_eq!(key(&memo, &c, "t1", &a).unwrap(), key(&memo, &c, "t1", &b).unwrap());

        // …and every field that affects execution moves the key.
        let base = key(&memo, &c, "t1", &spec("test")).unwrap();
        let mut cases = vec![
            ("name", spec("test2")),
            ("argv", StepSpec::new("test", vec!["cargo".into(), "bench".into()], "rust:1.83").inputs(vec!["crates/**".into()])),
            ("image", StepSpec::new("test", vec!["cargo".into(), "test".into()], "rust:1.84").inputs(vec!["crates/**".into()])),
            ("timeout", { let mut s = spec("test"); s.timeout = Some(Duration::from_secs(60)); s }),
            ("continue_on_error", spec("test").continue_on_error()),
            ("secrets", spec("test").secrets(vec!["AWS".into()])),
            ("inputs", spec("test").inputs(vec!["docs/**".into()])),
            ("env", spec("test").env_allowlist(vec![("PROFILE".into(), "release".into())])),
        ];
        for (what, s) in cases.drain(..) {
            assert_ne!(key(&memo, &c, "t1", &s).unwrap(), base, "{what} must change the key");
        }
    }

    #[test]
    fn argv_order_is_part_of_the_key() {
        // `set` vs `seq`: reordering a command line is a different command.
        let memo = memo_with(Arc::new(ConstDigest(1)));
        let a = StepSpec::new("s", vec!["a".into(), "b".into()], "img").inputs(vec!["x/**".into()]);
        let b = StepSpec::new("s", vec!["b".into(), "a".into()], "img").inputs(vec!["x/**".into()]);
        assert_ne!(key(&memo, &ctx("t"), "t1", &a).unwrap(), key(&memo, &ctx("t"), "t1", &b).unwrap());
    }

    #[test]
    fn env_values_are_in_the_key_not_only_env_names() {
        let memo = memo_with(Arc::new(ConstDigest(1)));
        let release = spec("s").env_allowlist(vec![("PROFILE".into(), "release".into())]);
        let debug = spec("s").env_allowlist(vec![("PROFILE".into(), "debug".into())]);
        assert_ne!(key(&memo, &ctx("t"), "t1", &release).unwrap(), key(&memo, &ctx("t"), "t1", &debug).unwrap());
    }

    #[test]
    fn author_class_and_tier_are_in_the_key() {
        // D§6.1's formula omits both, and both change what the step does: an outsider's job receives
        // no tenant secrets (D§7.4), so a member's `passed` is not evidence about it.
        let memo = memo_with(Arc::new(ConstDigest(1)));
        let member = ctx("acme");
        let outsider = JobKeyContext { author_class: AuthorClass::Outsider, ..ctx("acme") };
        let microvm = JobKeyContext { tier: IsolationTier::MicroVm, ..ctx("acme") };
        let base = key(&memo, &member, "t1", &spec("s")).unwrap();
        assert_ne!(key(&memo, &outsider, "t1", &spec("s")).unwrap(), base);
        assert_ne!(key(&memo, &microvm, "t1", &spec("s")).unwrap(), base);
    }

    #[test]
    fn the_pipeline_version_invalidates_every_key_at_once() {
        let a = memo_with(Arc::new(ConstDigest(1)));
        let b = MemoConfig { pipeline_version: "hull-ci/1".into(), ..memo_with(Arc::new(ConstDigest(1))) };
        assert_ne!(key(&a, &ctx("t"), "t1", &spec("s")).unwrap(), key(&b, &ctx("t"), "t1", &spec("s")).unwrap());
    }

    // ── dependency chaining ──────────────────────────────────────────────────────────────────────

    fn chain(memo: &MemoConfig, build_digest: &str) -> Vec<KeyResult> {
        let specs = vec![
            StepSpec::new("build", vec!["cargo".into(), "build".into()], "img")
                .inputs(vec![build_digest.into()]),
            StepSpec::new("test", vec!["cargo".into(), "test".into()], "img")
                .inputs(vec!["tests/**".into()])
                .needs(vec!["build".into()]),
        ];
        plan_step_keys(memo, &ctx("acme"), &tree("t1"), &specs)
    }

    #[test]
    fn a_changed_dependency_invalidates_its_dependents() {
        // The chaining rule of D§6.1. `test`'s own inputs are untouched; `build`'s moved; `test`'s
        // key must move anyway, or a rebuilt dependency would be paired with a stale dependent.
        let memo = memo_with(TableDigest::new(&[
            ("acme", "t1", "src-v1/**", "aaaa"),
            ("acme", "t1", "src-v2/**", "bbbb"),
            ("acme", "t1", "tests/**", "tttt"),
        ]));
        let v1 = chain(&memo, "src-v1/**");
        let v2 = chain(&memo, "src-v2/**");
        assert_ne!(v1[0], v2[0], "the root's own key moved");
        assert_ne!(v1[1], v2[1], "and so must the dependent's");
    }

    /// **Mutation test.** Key the dependent *without* folding its dependency's key in — the shape of
    /// the bug — and prove the two chains then collide. Delete the `set(&mut h, 0x30, …)` line and
    /// `a_changed_dependency_invalidates_its_dependents` fails.
    #[test]
    fn ignoring_dependency_keys_would_serve_a_stale_dependent() {
        let memo = memo_with(TableDigest::new(&[
            ("acme", "t1", "src-v1/**", "aaaa"),
            ("acme", "t1", "src-v2/**", "bbbb"),
            ("acme", "t1", "tests/**", "tttt"),
        ]));
        let test_spec = StepSpec::new("test", vec!["cargo".into(), "test".into()], "img")
            .inputs(vec!["tests/**".into()])
            .needs(vec!["build".into()]);
        // Same step, two different dependency keys, but the dependency is not folded in:
        let a = step_key(&memo, &ctx("acme"), &tree("t1"), &test_spec, &[]).unwrap();
        let b = step_key(&memo, &ctx("acme"), &tree("t1"), &test_spec, &[]).unwrap();
        assert_eq!(a, b, "with no dependency key folded in, a changed root is invisible to its dependent");
        // …whereas the real path distinguishes them.
        let with_dep = step_key(
            &memo,
            &ctx("acme"),
            &tree("t1"),
            &test_spec,
            &[StepKey("dep-a".into())],
        )
        .unwrap();
        assert_ne!(with_dep, a);
    }

    #[test]
    fn dependency_order_does_not_change_a_key() {
        let memo = memo_with(Arc::new(ConstDigest(1)));
        let deps_a = [StepKey("a".into()), StepKey("b".into())];
        let deps_b = [StepKey("b".into()), StepKey("a".into())];
        assert_eq!(
            step_key(&memo, &ctx("t"), &tree("t1"), &spec("s"), &deps_a).unwrap(),
            step_key(&memo, &ctx("t"), &tree("t1"), &spec("s"), &deps_b).unwrap()
        );
    }

    #[test]
    fn an_uncacheable_dependency_makes_its_dependents_uncacheable() {
        // Guessing past it would cache the dependent against inputs nobody accounted for.
        let memo = memo_with(Arc::new(ConstDigest(1)));
        let specs = vec![
            StepSpec::new("build", vec!["cargo".into()], "img"), // no inputs
            StepSpec::new("test", vec!["cargo".into()], "img")
                .inputs(vec!["tests/**".into()])
                .needs(vec!["build".into()]),
        ];
        let keys = plan_step_keys(&memo, &ctx("acme"), &tree("t1"), &specs);
        assert_eq!(keys[0], Err(NotCacheable::NoInputs));
        assert_eq!(keys[1], Err(NotCacheable::DependencyNotCacheable("build".into())));
    }

    #[test]
    fn an_undeclared_dependency_is_not_cacheable_either() {
        let memo = memo_with(Arc::new(ConstDigest(1)));
        let specs = vec![spec("test").needs(vec!["ghost".into()])];
        assert_eq!(
            plan_step_keys(&memo, &ctx("acme"), &tree("t1"), &specs)[0],
            Err(NotCacheable::UndeclaredDependency("ghost".into()))
        );
    }

    // ── the store ────────────────────────────────────────────────────────────────────────────────

    fn k(s: &str) -> StepKey {
        StepKey(s.into())
    }

    #[test]
    fn errored_can_never_be_written_to_the_memo() {
        // Not a filter — `MemoOutcome` has no variant for it, so the type system carries spec §7's
        // rule one level down. An outage must not poison anything.
        assert_eq!(MemoOutcome::from_state(StepState::Errored), None);
        assert_eq!(MemoOutcome::from_state(StepState::Skipped), None);
        assert_eq!(MemoOutcome::from_state(StepState::Cached), None);
        assert_eq!(MemoOutcome::from_state(StepState::Running), None);
        assert_eq!(MemoOutcome::from_state(StepState::Passed), Some(MemoOutcome::Passed));
        assert_eq!(MemoOutcome::from_state(StepState::Failed), Some(MemoOutcome::Failed));
    }

    #[test]
    fn failed_expires_and_passed_does_not() {
        let memo = InMemoryStepMemo::new(MemoPolicy {
            passed_ttl: Duration::from_secs(3600),
            failed_ttl: Duration::from_secs(60),
            capacity: 10,
        });
        let now = Instant::now();
        memo.record("acme", &k("pass"), MemoOutcome::Passed, now);
        memo.record("acme", &k("fail"), MemoOutcome::Failed, now);

        let soon = now + Duration::from_secs(30);
        assert_eq!(memo.lookup("acme", &k("pass"), soon), Some(MemoOutcome::Passed));
        assert_eq!(memo.lookup("acme", &k("fail"), soon), Some(MemoOutcome::Failed));

        let later = now + Duration::from_secs(120);
        assert_eq!(memo.lookup("acme", &k("fail"), later), None, "a failure is remembered briefly");
        assert_eq!(memo.lookup("acme", &k("pass"), later), Some(MemoOutcome::Passed), "a pass is not");
    }

    #[test]
    fn the_store_never_answers_across_tenants() {
        // The second half of the D§1 control: even a key that somehow collided could not be read by
        // another tenant, because the tenant is part of the lookup and not derivable from the key.
        let memo = InMemoryStepMemo::default();
        let now = Instant::now();
        memo.record("acme", &k("same-key"), MemoOutcome::Passed, now);
        assert_eq!(memo.lookup("acme", &k("same-key"), now), Some(MemoOutcome::Passed));
        assert_eq!(memo.lookup("other", &k("same-key"), now), None, "no cross-tenant read");
        assert_eq!(memo.lookup("", &k("same-key"), now), None);
        assert_eq!(memo.lookup("acme ", &k("same-key"), now), None, "and no near-miss either");
    }

    #[test]
    fn a_flooding_tenant_cannot_evict_a_neighbours_memo() {
        // D§1's noisy-neighbour row, at the memo's one shared dimension: its capacity. With plain
        // oldest-first eviction `attacker` wiped all 50 of `victim`'s entries — a tenant could
        // silently delete a neighbour's whole cache and make it re-run (and re-pay for) work it had
        // already done. The largest holder pays instead, so the flood evicts only itself.
        let memo = InMemoryStepMemo::new(MemoPolicy { capacity: 100, ..MemoPolicy::default() });
        let now = Instant::now();
        for i in 0..50 {
            memo.record("victim", &k(&format!("v{i}")), MemoOutcome::Passed, now);
        }
        for i in 0..5_000 {
            memo.record("attacker", &k(&format!("a{i}")), MemoOutcome::Passed, now);
        }

        let survivors =
            (0..50).filter(|i| memo.lookup("victim", &k(&format!("v{i}")), now).is_some()).count();
        assert_eq!(survivors, 50, "a neighbour's writes must not cost this tenant a single entry");
        assert!(memo.len() <= 100, "and the store is still bounded: {}", memo.len());
    }

    #[test]
    fn a_tenant_below_its_share_is_never_the_one_evicted() {
        // The general form of the rule above, asserted against the *smaller* holder rather than a
        // fixed count: whoever holds fewer entries cannot be displaced, however hard the other side
        // writes. This is what stops the shared capacity from being a lever one tenant aims at
        // another.
        let memo = InMemoryStepMemo::new(MemoPolicy { capacity: 10, ..MemoPolicy::default() });
        let now = Instant::now();
        memo.record("small", &k("only"), MemoOutcome::Passed, now);
        for i in 0..1_000 {
            memo.record("big", &k(&format!("b{i}")), MemoOutcome::Passed, now);
        }
        assert_eq!(
            memo.lookup("small", &k("only"), now),
            Some(MemoOutcome::Passed),
            "one entry belonging to a quiet tenant outlives a thousand from a loud one"
        );
    }

    #[test]
    fn the_store_is_bounded() {
        let memo = InMemoryStepMemo::new(MemoPolicy { capacity: 4, ..MemoPolicy::default() });
        let now = Instant::now();
        for i in 0..20 {
            memo.record("acme", &k(&format!("k{i}")), MemoOutcome::Passed, now);
        }
        assert!(memo.len() <= 4, "held {}", memo.len());
    }

    #[test]
    fn the_default_wiring_caches_nothing() {
        // Unwired means off, not open: a control plane with no digester behaves exactly as it did
        // before layer 2 existed.
        let memo = MemoConfig::default();
        assert!(!memo.enabled());
        assert!(matches!(key(&memo, &ctx("acme"), "t1", &spec("s")), Err(NotCacheable::DigestUnavailable(_))));
    }
}
