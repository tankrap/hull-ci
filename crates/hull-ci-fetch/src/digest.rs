//! `subtree_digest` — resolving a step's `inputs` globs to a content address, design D§6.1.
//!
//! This is the foundation the whole of layer 2 (step memoization) stands on, and the reason the
//! design claims step-level caching is affordable here and painful on a git-shaped substrate. keel's
//! `Tree` is a Merkle node (`TreeEntry { name, mode, id }`), so **a directory entry's `id` already
//! *is* that subtree's content address**. Resolving "what did `crates/**` contain" is therefore a
//! lookup in a structure, never a pass over file bytes.
//!
//! ## The two glob shapes, and why the difference is designed around
//!
//! D§6.1 corrected an earlier draft on exactly this point, and the code keeps the distinction
//! visible rather than hiding it behind one `match_glob`:
//!
//! * a **directory-prefix** glob (`crates/**`, or a bare path like `Cargo.toml`) is an **O(depth)
//!   descent** — a handful of node hops, and the answer is a single `ObjectId` that already exists.
//!   Genuinely a metadata lookup. [`Shape::Prefix`] / [`Shape::Exact`].
//! * a **pattern** glob (`**/*.rs`) has **no single subtree**. Nothing in the tree corresponds to
//!   "every .rs file", so the answer must be folded from a walk of the tree's *node structure*:
//!   O(entries), not O(bytes). On a 100k-file repo that is milliseconds of structure traversal, not
//!   the seconds of content hashing a non-content-addressed CI pays. [`Shape::Pattern`].
//!
//! Both shapes fold to a digest over `(path, mode, id)` triples, and **no file is ever opened**:
//! [`TreeIndex`] carries every id the walk already computed.
//!
//! ## Where the index comes from, honestly
//!
//! On a Hull deployment reading keel's object store the ids are literally already there. Here the
//! broker starts from an *extracted tarball*, so somebody has to walk it once — and somebody already
//! does: [`crate::verify`] hashes exactly this structure to check the archive against `tree_id`, and
//! used to throw the intermediate subtree addresses away. [`TreeIndex`] is that same walk keeping
//! them. The marginal cost of the first digest on a tree is therefore "retain what we computed
//! anyway"; every later glob, step and job on that tree pays nothing (see [`TreeDigester`]).
//!
//! ## Memoization, and why it is sound
//!
//! `(tenant, tree_id, glob) → digest` is cached. Sound **precisely because trees are immutable**: a
//! repeated glob on a repeated tree cannot have a different answer. The `tenant` component is not
//! needed for correctness — a content address is a content address — and is there for D§1's
//! timing/existence-oracle row: a cross-tenant *cache hit* is a cheap oracle for "did another tenant
//! already build this tree", so there is nothing to time if the key cannot cross tenants.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use keel_store::object::ObjectId;
use keel_store::snapshot::MODE_DIR;

use crate::verify::{KeelTreeVerifier, VerifyError};

/// Domain separator. A digest is hashed alongside a `KIND`-style tag so a subtree digest can never
/// be confused with a keel object id, which is a different claim about the same bytes.
const DIGEST_DOMAIN: &[u8] = b"hull-ci/subtree-digest/v1";

// ── The index ────────────────────────────────────────────────────────────────────────────────────

/// One entry of a directory: keel's `TreeEntry`, plus the child structure when it is a directory.
#[derive(Debug, Clone)]
pub struct IndexEntry {
    pub name: String,
    pub mode: u32,
    /// The entry's content address. For a directory this is the **subtree** id — the value D§6.1
    /// says is "already computed", and the one a prefix glob answers with directly.
    pub id: ObjectId,
    /// `Some` iff this entry is a directory.
    pub dir: Option<IndexDir>,
}

/// A directory node: its own address, and its entries **sorted by name**.
///
/// Sorted because `Object::encode` sorts, so this is the order the address was computed over —
/// matching a glob in the same order makes the digest independent of `read_dir` enumeration order
/// without a second sort at every level.
#[derive(Debug, Clone)]
pub struct IndexDir {
    pub id: ObjectId,
    pub entries: Vec<IndexEntry>,
}

impl IndexDir {
    fn child(&self, name: &str) -> Option<&IndexEntry> {
        self.entries.binary_search_by(|e| e.name.as_str().cmp(name)).ok().map(|i| &self.entries[i])
    }
}

/// A whole verified tree's node structure, ids and all.
///
/// Built once per tree (immutable, so "once" is the whole lifetime of that address) and shared by
/// every glob, every step and every job that touches it.
#[derive(Debug, Clone)]
pub struct TreeIndex {
    root: IndexDir,
}

impl TreeIndex {
    /// Walk an extracted tree, keeping the Merkle structure.
    ///
    /// The walk is [`KeelTreeVerifier`]'s — the *same* code that verifies the archive against
    /// `tree_id` — so there is one implementation of keel's mode and encoding rules in this crate.
    /// A second walk here would be a fork of the address format, and a memo keyed on a subtly
    /// different encoding is worse than no memo: it reports hits.
    pub fn build(root: &Path, verifier: &KeelTreeVerifier) -> Result<TreeIndex, VerifyError> {
        Ok(TreeIndex { root: verifier.index_dir(root)? })
    }

    /// The tree's own address — equal to what [`KeelTreeVerifier::tree_id`] computes.
    pub fn tree_id(&self) -> ObjectId {
        self.root.id
    }

    pub fn root(&self) -> &IndexDir {
        &self.root
    }

    /// The digest of everything `glob` selects (design D§6.1).
    pub fn subtree_digest(&self, glob: &str) -> Result<GlobDigest, GlobError> {
        let shape = Shape::parse(glob)?;
        let mut matched: Vec<Matched> = Vec::new();
        match &shape {
            // O(depth). The answer is an id that already existed.
            Shape::Exact(path) | Shape::Prefix(path) => {
                if let Some(entry) = descend(&self.root, path) {
                    // An empty directory has a *constant* address, so selecting one is selecting
                    // nothing — reported as such rather than as a digest that would be identical
                    // across every tree in the world. See `GlobDigest::selected_nothing`.
                    let empty_dir = entry.dir.as_ref().is_some_and(|d| d.entries.is_empty());
                    if !empty_dir {
                        matched.push(Matched {
                            path: path.join("/"),
                            mode: entry.mode,
                            id: entry.id,
                        });
                    }
                } else if path.is_empty() {
                    // `**` on its own: the whole tree.
                    if !self.root.entries.is_empty() {
                        matched.push(Matched { path: String::new(), mode: MODE_DIR, id: self.root.id });
                    }
                }
            }
            // O(entries). No single subtree corresponds to a pattern, so the structure is walked and
            // the matching entries' ids are folded.
            Shape::Pattern(pattern) => {
                let mut prefix: Vec<&str> = Vec::new();
                collect(pattern, &self.root, &mut prefix, &mut matched);
                // A `**` matches zero *or more* segments, so one entry can be reached by more than
                // one route through the same pattern (`**/**/x`). Fold a set, not a bag.
                matched.sort_by(|a, b| a.path.cmp(&b.path));
                matched.dedup_by(|a, b| a.path == b.path);
            }
        }
        Ok(fold(glob, shape.tag(), &matched))
    }
}

/// The answer for one glob against one tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobDigest {
    /// Lowercase hex, 64 chars.
    pub digest: String,
    /// How many tree entries the glob selected. **Zero is load-bearing**: a glob that matches
    /// nothing produces the same digest on every tree in existence, so a caller must treat it the
    /// way it treats a step with no `inputs` at all (design D§6.1, and see
    /// `hull_ci_control::memo`) — as a refusal to cache, not as a cheap universal key.
    pub selected: usize,
}

impl GlobDigest {
    pub fn selected_nothing(&self) -> bool {
        self.selected == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Matched {
    path: String,
    mode: u32,
    id: ObjectId,
}

/// Fold matched entries into one digest.
///
/// Length-prefixed and shape-tagged so no two different selections can serialize to the same bytes:
/// `("ab", id)` and `("a", "b" ++ id)` must not collide, and a prefix glob's single-subtree answer
/// must not collide with a pattern glob that happened to select one directory.
fn fold(glob: &str, shape: u8, matched: &[Matched]) -> GlobDigest {
    let mut h = blake3::Hasher::new();
    h.update(DIGEST_DOMAIN);
    h.update(&[shape]);
    lp(&mut h, glob.as_bytes());
    h.update(&(matched.len() as u64).to_le_bytes());
    for m in matched {
        lp(&mut h, m.path.as_bytes());
        h.update(&m.mode.to_le_bytes());
        h.update(&m.id.0);
    }
    GlobDigest { digest: ObjectId(*h.finalize().as_bytes()).to_hex(), selected: matched.len() }
}

fn lp(h: &mut blake3::Hasher, bytes: &[u8]) {
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(bytes);
}

fn descend<'a>(root: &'a IndexDir, path: &[String]) -> Option<&'a IndexEntry> {
    let (last, parents) = path.split_last()?;
    let mut dir = root;
    for name in parents {
        dir = dir.child(name)?.dir.as_ref()?;
    }
    dir.child(last)
}

/// Walk the node structure, collecting entries the pattern selects. Never opens a file.
fn collect<'p>(pattern: &[String], dir: &'p IndexDir, prefix: &mut Vec<&'p str>, out: &mut Vec<Matched>) {
    let Some((first, rest)) = pattern.split_first() else { return };
    if first == "**" {
        if rest.is_empty() {
            // A trailing `**` selects this whole subtree — which is one already-computed id.
            if !dir.entries.is_empty() {
                out.push(Matched { path: prefix.join("/"), mode: MODE_DIR, id: dir.id });
            }
            return;
        }
        // `**` matches zero segments…
        collect(rest, dir, prefix, out);
        // …or one and then itself again.
        for entry in &dir.entries {
            if let Some(sub) = &entry.dir {
                prefix.push(&entry.name);
                collect(pattern, sub, prefix, out);
                prefix.pop();
            }
        }
        return;
    }
    for entry in &dir.entries {
        if !segment_matches(first, &entry.name) {
            continue;
        }
        if rest.is_empty() {
            prefix.push(&entry.name);
            out.push(Matched { path: prefix.join("/"), mode: entry.mode, id: entry.id });
            prefix.pop();
        } else if let Some(sub) = &entry.dir {
            prefix.push(&entry.name);
            collect(rest, sub, prefix, out);
            prefix.pop();
        }
    }
}

// ── Glob shapes ──────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GlobError {
    /// Empty, absolute, or containing `.`/`..`. Refused rather than normalized: a glob we
    /// "helpfully" repaired would key a step against paths its author never named, and a glob that
    /// escaped the tree root would key it against paths that are not in the tree at all.
    #[error("`{0}` is not a valid inputs glob: it must be a relative path with no `.` or `..` segments")]
    Malformed(String),
    /// Too many `**` segments — see [`MAX_GLOBSTARS`]. The glob itself is not quoted back: it is
    /// author text, and the point of this variant is that the glob was too big to handle.
    #[error("an inputs glob may hold at most {limit} `**` segments")]
    TooManyGlobstars { limit: usize },
}

/// The most `**` segments one `inputs` glob may hold.
///
/// **This is a complexity bound, not a style rule.** `**` matches zero *or more* segments, so
/// [`collect`] explores every way of splitting the tree's depth across the pattern's globstars: with
/// `k` of them over a tree `d` deep, the number of routes is `C(k + d, d)` and nothing memoizes the
/// `(pattern index, node)` pairs. Measured on a 12-deep tree, `**/…/f.rs` costs 5 ms at `k = 4`,
/// 0.4 s at `k = 8`, and 25 s and a gigabyte of `matched` at `k = 14` — and both halves of that
/// input are attacker-chosen: the glob comes from `.hull/ci.star` and the depth from the tar. A
/// pipeline could name a glob (`hull_ci_plan` allows 1 024 characters, so ~340 globstars) that no
/// amount of waiting resolves.
///
/// Four is well past what a glob means: consecutive globstars are redundant (`**/**/x` selects
/// exactly what `**/x` does) and separated ones are how a real pattern spends them
/// (`**/tests/**/*.rs` uses two). Refused rather than collapsed, because this module refuses rather
/// than repairs — see [`GlobError::Malformed`].
pub const MAX_GLOBSTARS: usize = 4;

/// What kind of resolution a glob needs — the D§6.1 distinction, made explicit.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Shape {
    /// No wildcards at all: one entry, reached by descent.
    Exact(Vec<String>),
    /// `dir/**` — a directory subtree, reached by descent. The answer is an existing `ObjectId`.
    Prefix(Vec<String>),
    /// Anything else: no single subtree corresponds to it, so it costs a walk.
    Pattern(Vec<String>),
}

impl Shape {
    /// Distinguish the two costs at parse time, so a pipeline author's `crates/**` never pays a
    /// walk and the linter D§6.1 asks for has something to lint against.
    ///
    /// Metacharacters are `*` (any run of characters within one segment), `?` (one character) and
    /// `**` (any run of whole segments). `[` is **literal** — a character class would be a second
    /// matcher's worth of surface for no expressiveness a CI `inputs` list has ever needed.
    fn parse(glob: &str) -> Result<Shape, GlobError> {
        let bad = || GlobError::Malformed(glob.to_string());
        let trimmed = glob.trim();
        if trimmed.is_empty() || trimmed.starts_with('/') {
            return Err(bad());
        }
        let mut segments: Vec<String> = Vec::new();
        for seg in trimmed.split('/') {
            // A trailing slash (`crates/`) is a directory the author spelled with a separator, not
            // an empty segment; anything else empty is malformed.
            if seg.is_empty() {
                if segments.is_empty() {
                    return Err(bad());
                }
                continue;
            }
            if seg == "." || seg == ".." {
                return Err(bad());
            }
            segments.push(seg.to_string());
        }
        if segments.is_empty() {
            return Err(bad());
        }
        // Before anything walks anything: the cost of a pattern is exponential in this count.
        if segments.iter().filter(|s| s.as_str() == "**").count() > MAX_GLOBSTARS {
            return Err(GlobError::TooManyGlobstars { limit: MAX_GLOBSTARS });
        }

        let wild = |s: &String| s.contains('*') || s.contains('?');
        let last_is_globstar = segments.last().is_some_and(|s| s == "**");
        let leading_wild = segments[..segments.len() - 1].iter().any(wild);

        if last_is_globstar && !leading_wild {
            segments.pop();
            Ok(Shape::Prefix(segments))
        } else if !leading_wild && !segments.last().is_some_and(wild) {
            Ok(Shape::Exact(segments))
        } else {
            Ok(Shape::Pattern(segments))
        }
    }

    /// Hashed into the digest so two shapes can never produce the same bytes for different claims.
    fn tag(&self) -> u8 {
        match self {
            Shape::Exact(_) => 1,
            Shape::Prefix(_) => 2,
            Shape::Pattern(_) => 3,
        }
    }
}

/// `*` / `?` matching within one path segment. Iterative with backtracking, so a hostile pattern
/// like `*a*a*a*a*b` against a long name cannot go exponential.
fn segment_matches(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni) = (0usize, 0usize);
    let (mut star, mut resume) = (usize::MAX, 0usize);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            resume = ni;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            resume += 1;
            ni = resume;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

// ── The digester ─────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum DigestError {
    #[error("could not read the extracted tree: {0}")]
    Index(#[from] VerifyError),
    #[error(transparent)]
    Glob(#[from] GlobError),
}

/// Caps on what the digester holds. Both are memory bounds on a long-lived process, not correctness
/// knobs: every eviction costs a re-walk or a re-fold and can never produce a wrong answer, because
/// the cached value is a pure function of an immutable tree.
#[derive(Debug, Clone, Copy)]
pub struct DigestLimits {
    /// How many whole tree structures to keep. Small: an index is the biggest thing here, and the
    /// working set is "the trees currently being planned".
    pub max_indexes: usize,
    /// How many `(tenant, tree, glob) → digest` answers to keep.
    pub max_digests: usize,
}

impl Default for DigestLimits {
    fn default() -> Self {
        DigestLimits { max_indexes: 8, max_digests: 4096 }
    }
}

/// `(tenant, tree_id, glob) → digest`, with the tree structures behind it.
///
/// Thread-safe and cheap to share. The tenant component of every key is the D§1
/// timing/existence-oracle control: a cross-tenant hit is not "unlikely", it is unrepresentable.
pub struct TreeDigester {
    verifier: KeelTreeVerifier,
    limits: DigestLimits,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// Insertion-ordered so the oldest tree is the one dropped. A handful of entries, so a linear
    /// scan beats carrying an LRU.
    indexes: Vec<(TreeKey, std::sync::Arc<TreeIndex>)>,
    digests: HashMap<(TreeKey, String), GlobDigest>,
}

type TreeKey = (String, String);

impl Default for TreeDigester {
    fn default() -> Self {
        TreeDigester::new(KeelTreeVerifier::default(), DigestLimits::default())
    }
}

impl TreeDigester {
    pub fn new(verifier: KeelTreeVerifier, limits: DigestLimits) -> Self {
        TreeDigester { verifier, limits, state: Mutex::new(State::default()) }
    }

    /// The digest of everything `glob` selects in the tree extracted at `root`.
    ///
    /// `tenant` and `tree_id` are the cache key only — the *answer* depends on the tree alone, which
    /// is what makes caching it sound.
    pub fn digest(
        &self,
        tenant: &str,
        tree_id: &str,
        root: &Path,
        glob: &str,
    ) -> Result<GlobDigest, DigestError> {
        let key = (tenant.to_string(), tree_id.to_string());
        if let Some(hit) = self.cached_digest(&key, glob) {
            return Ok(hit);
        }
        let index = self.index(&key, root)?;
        let digest = index.subtree_digest(glob)?;

        let mut state = self.lock();
        if state.digests.len() >= self.limits.max_digests {
            // Bounded, bluntly. Every entry is recomputable from an immutable tree, so dropping the
            // lot costs latency and nothing else — and a real LRU here would be machinery guarding
            // a value with no correctness stake.
            state.digests.clear();
        }
        state.digests.insert((key, glob.to_string()), digest.clone());
        Ok(digest)
    }

    /// The tree's structure, built once and shared.
    pub fn index(&self, key: &TreeKey, root: &Path) -> Result<std::sync::Arc<TreeIndex>, DigestError> {
        if let Some(hit) = self.lock().indexes.iter().find(|(k, _)| k == key).map(|(_, i)| i.clone()) {
            return Ok(hit);
        }
        // Built outside the lock: this is the one expensive operation in the module, and holding a
        // global mutex across a walk of a 100k-file tree would serialize every other tenant's
        // digests behind it. A concurrent duplicate build wastes a walk and is otherwise harmless —
        // the two results are identical by construction.
        let index = std::sync::Arc::new(TreeIndex::build(root, &self.verifier)?);
        let mut state = self.lock();
        if state.indexes.len() >= self.limits.max_indexes {
            state.indexes.remove(0);
        }
        if !state.indexes.iter().any(|(k, _)| k == key) {
            state.indexes.push((key.clone(), index.clone()));
        }
        Ok(index)
    }

    fn cached_digest(&self, key: &TreeKey, glob: &str) -> Option<GlobDigest> {
        // `HashMap` cannot look up a `(TreeKey, String)` from borrowed halves without allocating, and
        // the allocation is dwarfed by everything it avoids.
        self.lock().digests.get(&(key.clone(), glob.to_string())).cloned()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::TreeVerifier;
    use std::fs;
    use tempfile::TempDir;

    /// A small but realistically-shaped repo.
    fn repo() -> TempDir {
        let d = TempDir::new().unwrap();
        let p = d.path();
        fs::create_dir_all(p.join("crates/a/src")).unwrap();
        fs::create_dir_all(p.join("crates/b/src")).unwrap();
        fs::create_dir_all(p.join("docs")).unwrap();
        fs::write(p.join("Cargo.toml"), b"[workspace]\n").unwrap();
        fs::write(p.join("README.md"), b"hi\n").unwrap();
        fs::write(p.join("crates/a/src/lib.rs"), b"pub fn a() {}\n").unwrap();
        fs::write(p.join("crates/a/Cargo.toml"), b"name = 'a'\n").unwrap();
        fs::write(p.join("crates/b/src/lib.rs"), b"pub fn b() {}\n").unwrap();
        fs::write(p.join("docs/guide.md"), b"docs\n").unwrap();
        d
    }

    fn index(d: &TempDir) -> TreeIndex {
        TreeIndex::build(d.path(), &KeelTreeVerifier::default()).unwrap()
    }

    fn digest(d: &TempDir, glob: &str) -> String {
        index(d).subtree_digest(glob).unwrap().digest
    }

    #[test]
    fn the_index_addresses_the_tree_exactly_as_the_verifier_does() {
        // The property the whole memo rests on: the ids in the index are keel's real addresses, not
        // a parallel hash. If these ever diverge, a digest would be a claim about an encoding
        // nothing else in the system uses.
        let d = repo();
        let v = KeelTreeVerifier::default();
        assert_eq!(index(&d).tree_id().to_hex(), v.tree_id(d.path()).unwrap());
    }

    #[test]
    fn a_directory_prefix_glob_answers_with_an_id_that_already_existed() {
        // D§6.1's first shape: `crates/**` is a descent, and the digest is folded from the subtree's
        // own `ObjectId` — the one the tree walk already computed.
        let d = repo();
        let idx = index(&d);
        let crates = idx.root().child("crates").unwrap();
        let got = idx.subtree_digest("crates/**").unwrap();
        assert_eq!(got.selected, 1, "one entry: the subtree itself");
        assert_eq!(got.digest, fold("crates/**", 2, &[Matched {
            path: "crates".into(),
            mode: MODE_DIR,
            id: crates.id,
        }]).digest);
    }

    #[test]
    fn a_pattern_glob_folds_every_matching_entry() {
        let d = repo();
        let got = index(&d).subtree_digest("**/*.rs").unwrap();
        assert_eq!(got.selected, 2, "crates/a/src/lib.rs and crates/b/src/lib.rs");
    }

    #[test]
    fn a_change_inside_the_glob_changes_the_digest_and_one_outside_does_not() {
        // The entire point of layer 2, in one test.
        let d = repo();
        let inside = digest(&d, "crates/**");
        let unrelated = digest(&d, "docs/**");

        fs::write(d.path().join("crates/a/src/lib.rs"), b"pub fn a() { todo!() }\n").unwrap();
        assert_ne!(digest(&d, "crates/**"), inside, "a file inside the glob must miss");
        assert_eq!(digest(&d, "docs/**"), unrelated, "and a glob that does not cover it must hit");

        fs::write(d.path().join("docs/guide.md"), b"more docs\n").unwrap();
        assert_ne!(digest(&d, "docs/**"), unrelated);
    }

    #[test]
    fn an_added_or_removed_file_moves_a_pattern_digest() {
        // A digest folded only over *matched content* would miss an added file. The entry count and
        // every path are in the fold, so both directions move it.
        let d = repo();
        let before = digest(&d, "**/*.rs");
        fs::write(d.path().join("crates/a/src/extra.rs"), b"// new\n").unwrap();
        let added = digest(&d, "**/*.rs");
        assert_ne!(added, before);
        fs::remove_file(d.path().join("crates/a/src/extra.rs")).unwrap();
        assert_eq!(digest(&d, "**/*.rs"), before, "and back again — it is a content address");
    }

    #[test]
    fn a_rename_that_preserves_content_still_moves_the_digest() {
        // Paths are folded in, not just ids: moving `lib.rs` to `main.rs` is a different build.
        let d = repo();
        let before = digest(&d, "**/*.rs");
        fs::rename(d.path().join("crates/a/src/lib.rs"), d.path().join("crates/a/src/main.rs")).unwrap();
        assert_ne!(digest(&d, "**/*.rs"), before);
    }

    #[test]
    fn the_exec_bit_is_part_of_the_digest() {
        // Mode is in keel's tree encoding and in ours, so `chmod +x` is a different input set — an
        // attacker must not be able to make a script executable without moving the step key.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let d = repo();
            let p = d.path().join("crates/a/src/lib.rs");
            let before = digest(&d, "**/*.rs");
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
            assert_ne!(digest(&d, "**/*.rs"), before);
        }
    }

    #[test]
    fn a_glob_that_selects_nothing_says_so_rather_than_answering_a_universal_key() {
        // The trap: `nonexistent/**` folds an empty set, which is the *same* digest on every tree in
        // existence. Reported as `selected == 0` so the control plane refuses to cache on it.
        let d = repo();
        for glob in ["nonexistent/**", "**/*.py", "no-such-file.txt"] {
            let got = index(&d).subtree_digest(glob).unwrap();
            assert!(got.selected_nothing(), "{glob} should select nothing");
        }
        // An *empty directory* is the same hazard wearing a directory's clothes: its address is a
        // constant, identical in every repository.
        fs::create_dir(d.path().join("empty")).unwrap();
        assert!(index(&d).subtree_digest("empty/**").unwrap().selected_nothing());
    }

    #[test]
    fn shapes_are_classified_by_the_cost_they_imply() {
        assert_eq!(Shape::parse("crates/**").unwrap(), Shape::Prefix(vec!["crates".into()]));
        assert_eq!(Shape::parse("crates/").unwrap(), Shape::Exact(vec!["crates".into()]));
        assert_eq!(Shape::parse("Cargo.toml").unwrap(), Shape::Exact(vec!["Cargo.toml".into()]));
        assert_eq!(Shape::parse("**").unwrap(), Shape::Prefix(vec![]));
        assert!(matches!(Shape::parse("**/*.rs").unwrap(), Shape::Pattern(_)));
        assert!(matches!(Shape::parse("crates/*/src/**").unwrap(), Shape::Pattern(_)));
    }

    #[test]
    fn a_glob_cannot_make_the_walk_exponential() {
        // `**` matches zero-or-more segments, so each one multiplies the number of routes through
        // the tree. Both inputs are attacker-chosen — the glob from `.hull/ci.star`, the depth from
        // the archive — and `hull_ci_plan` permits a 1 024-character glob, i.e. ~340 globstars.
        // Unbounded, that is a planner thread and a gigabyte of `matched` that never come back.
        let hostile = "**/".repeat(340) + "f.rs";
        assert_eq!(
            Shape::parse(&hostile),
            Err(GlobError::TooManyGlobstars { limit: MAX_GLOBSTARS })
        );
        // The bound applies wherever the globstars sit, not just when they are adjacent.
        let spread = (0..MAX_GLOBSTARS + 1).map(|i| format!("**/d{i}")).collect::<Vec<_>>().join("/");
        assert!(matches!(Shape::parse(&spread), Err(GlobError::TooManyGlobstars { .. })));

        // …and every shape a real pipeline writes still resolves, on a deep tree, quickly.
        let d = TempDir::new().unwrap();
        let mut p = d.path().to_path_buf();
        for i in 0..60 {
            p = p.join(format!("d{i}"));
            fs::create_dir(&p).unwrap();
            fs::write(p.join("lib.rs"), b"x").unwrap();
        }
        let idx = index(&d);
        for glob in ["crates/**", "**/*.rs", "**/tests/**/*.rs", "**/**/**/**/lib.rs"] {
            let started = std::time::Instant::now();
            idx.subtree_digest(glob).unwrap_or_else(|e| panic!("{glob} rejected: {e}"));
            assert!(started.elapsed().as_secs() < 5, "{glob} took {:?}", started.elapsed());
        }
    }

    #[test]
    fn a_malformed_glob_is_refused_not_repaired() {
        // A glob we normalized would key the step against paths its author never named; one that
        // escaped the root would key it against paths not in the tree at all.
        for glob in ["", "   ", "/etc/passwd", "../secrets/**", "a/../../b", "./x"] {
            assert!(Shape::parse(glob).is_err(), "{glob:?} must be refused");
        }
    }

    #[test]
    fn a_whole_tree_glob_is_the_root_id() {
        let d = repo();
        let idx = index(&d);
        let got = idx.subtree_digest("**").unwrap();
        assert_eq!(got.selected, 1);
        assert_eq!(got.digest, fold("**", 2, &[Matched { path: String::new(), mode: MODE_DIR, id: idx.tree_id() }]).digest);
    }

    #[test]
    fn two_globs_selecting_the_same_entry_do_not_collide() {
        // The glob string is folded in, so `crates/**` and `crates/` (same subtree, different
        // declared intent) are different inputs — and a step that changed which one it declared has
        // changed its definition.
        let d = repo();
        assert_ne!(digest(&d, "crates/**"), digest(&d, "crates/"));
    }

    #[test]
    fn a_double_star_that_can_match_by_two_routes_folds_the_entry_once() {
        let d = repo();
        let once = index(&d).subtree_digest("**/lib.rs").unwrap();
        let twice = index(&d).subtree_digest("**/**/lib.rs").unwrap();
        assert_eq!(once.selected, 2);
        assert_eq!(twice.selected, 2, "`**` matches zero-or-more, so both routes reach the same file");
    }

    #[test]
    fn segment_matching_handles_the_usual_wildcards() {
        assert!(segment_matches("*.rs", "lib.rs"));
        assert!(!segment_matches("*.rs", "lib.rs.bak"));
        assert!(segment_matches("lib.?s", "lib.rs"));
        assert!(segment_matches("*", "anything"));
        assert!(segment_matches("*a*a*a*b", "aaaaaaaaaaaaaaaaaaaaaaaaab"), "no exponential blowup");
        assert!(!segment_matches("*a*a*a*b", "aaaaaaaaaaaaaaaaaaaaaaaaac"));
        assert!(segment_matches("[abc].rs", "[abc].rs"), "`[` is literal");
    }

    #[test]
    fn the_digester_memoizes_on_an_immutable_tree() {
        // Sound *because* trees are immutable: the same (tenant, tree_id, glob) cannot have two
        // answers, so a repeat is a map hit.
        let d = repo();
        let dg = TreeDigester::default();
        let first = dg.digest("acme", "tree1", d.path(), "crates/**").unwrap();
        // Mutating the directory behind an id that claims to be `tree1` is not a thing that happens
        // — the store's copy is immutable (see `seams::VerifiedTree`) — but it is the sharpest way
        // to prove the second call did not re-walk.
        fs::write(d.path().join("crates/a/src/lib.rs"), b"changed\n").unwrap();
        assert_eq!(dg.digest("acme", "tree1", d.path(), "crates/**").unwrap(), first);
        // A different tree id is a different key, so it walks again and sees the change.
        assert_ne!(dg.digest("acme", "tree2", d.path(), "crates/**").unwrap(), first);
    }

    #[test]
    fn the_digest_cache_never_crosses_tenants() {
        // D§1's timing/existence-oracle row: a cross-tenant hit is a cheap "has anyone else built
        // this tree" oracle. There is nothing to time because the key cannot cross.
        let d = repo();
        let dg = TreeDigester::default();
        let acme = dg.digest("acme", "tree1", d.path(), "crates/**").unwrap();
        fs::write(d.path().join("crates/a/src/lib.rs"), b"changed\n").unwrap();
        let other = dg.digest("other", "tree1", d.path(), "crates/**").unwrap();
        assert_ne!(other, acme, "`other` walked the tree itself rather than reading acme's answer");
    }

    #[test]
    fn the_caches_are_bounded() {
        let d = repo();
        let dg = TreeDigester::new(KeelTreeVerifier::default(), DigestLimits { max_indexes: 2, max_digests: 3 });
        for i in 0..6 {
            dg.digest("acme", &format!("tree{i}"), d.path(), "crates/**").unwrap();
        }
        let state = dg.lock();
        assert!(state.indexes.len() <= 2);
        assert!(state.digests.len() <= 3);
    }
}
