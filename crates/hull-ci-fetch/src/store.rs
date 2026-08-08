//! The internal content store: verified trees on disk, keyed by `(tenant, tree_id)`, with each
//! tenant's file contents held **once** and shared by every tree of that tenant that contains them.
//!
//! Three jobs:
//!
//! 1. **Fetch once per tree, not once per node** (design D§4.2). A 12-way sharded test step must not
//!    pull the same archive from Hull twelve times, so the first thing [`FetchBroker`] does is ask
//!    this store whether the tree is already here. Content addresses are immutable, so a hit is
//!    always safe — there is no invalidation question, only GC.
//! 2. **Keep tenants apart.** The key is `(tenant, tree_id)`, never `tree_id` alone — and, since
//!    M4, the key of a *blob* is `(tenant, content, mode)`, never `(content, mode)` alone.
//! 3. **Store each of a tenant's files once** (design D§4.2, the M4 dedup item). Two trees that
//!    differ by one file used to cost two whole checkouts of disk. The product thesis is that CI is
//!    dominated by bytes you already have, and a store that copies a 400 MiB checkout per commit is
//!    that thesis' most direct contradiction.
//!
//! **Cross-tenant dedup is not a setting.** Two tenants holding byte-identical trees get two copies.
//! Sharing them would save disk and hand out an oracle: a tenant could learn that *somebody else*
//! holds a given tree — by timing a fetch, by a store hit on a tree they never pushed — which for a
//! content-addressed store means learning that a specific file exists somewhere in the fleet. Repo
//! contents, and the fact of a proprietary dependency, leak that way. Design D§4.2/D7 makes this a
//! hard rule, so the API does not offer a tenant-free lookup at all: there is no `has(tree_id)` to
//! call by mistake, and no blob path that can be computed without a tenant.
//!
//! # Layout
//!
//! ```text
//! {root}/{tenant_scope}/
//!     trees/{tree_id}/…                 one directory per tree — unchanged, see below
//!     blobs/{ab}/{cdef…}.{644|755}      one file per distinct (content, mode) this tenant holds
//!     staging/                          scratch: in-flight downloads and half-extracted trees
//! ```
//!
//! **A tree is still a full directory**, and that is the point of the design rather than a leftover
//! of it. Every reader above this module — [`crate::verify`]'s re-hash, [`crate::digest`]'s index
//! walk, `hull-ci-server`'s workspace materializer, and any future `tar` of a stored tree — walks an
//! ordinary directory and needs to know nothing about blobs. Dedup lives *below* the directory
//! entry, at the inode: a tree entry and its blob are two names for one file. Nothing above the
//! filesystem needs a manifest format, a reference index, or a second code path, and no reader can
//! be broken by a dedup bug that a plain `ls` would not also show. (This is the M1 note that used to
//! be here promising "directory-per-tree, simple by choice": the directory stayed, the second copy
//! of the bytes did not.)
//!
//! The blob store sits **inside the tenant scope**, next to `staging` and `trees`, for a mechanical
//! reason as well as the privacy one: `link(2)` cannot cross a filesystem, so putting blobs where
//! they are guaranteed to be on the same device as both staging and trees is what makes the sharing
//! mechanism available at all. A second configurable root would make `EXDEV` the normal case.
//!
//! `{ab}` is the first byte of the content address, hex — a 256-way fan-out. One level, not two:
//! a tenant holding ten million distinct files puts ~40k entries in a shard directory, which every
//! filesystem this runs on indexes rather than scans, while two levels would cost 65k `mkdir`s to
//! reach the same place. The shard exists so a tenant's blob count never lands as one flat directory
//! of millions of entries, which is where `readdir` and directory locking actually fall over.
//!
//! # Why a hard link here, when `workspace.rs` argues the opposite
//!
//! `hull-ci-server`'s workspace materializer refuses hard links in the strongest terms and uses a
//! copy-on-write clone instead. Same mechanism, opposite verdict, and both are right, because the
//! two destinations differ in exactly the property that matters:
//!
//! * **A workspace is written to, by definition.** It exists so `cargo test` can create `target/`
//!   and a hostile tree can do whatever it likes. A second name for the store's inode means the
//!   job's first `>`, `chmod +x` or `truncate` edits the stored tree in place, and a directory whose
//!   *name is a content address* stops hashing to its name — silently, for every later job.
//! * **A store tree is never written to, by contract.** Its path *is* a content address; the whole
//!   reason `workspace.rs` exists is so that no job ever holds a writable handle to one. Nothing in
//!   this process opens a stored tree for writing, and the extractor's own destination is a staging
//!   directory that no reader can see.
//!
//! So a hard link inside the store aliases inodes that are only ever read, while a hard link into a
//! workspace aliases an inode that is about to be written. Sharing an immutable thing is free;
//! sharing a mutable one is corruption. The dangerous case has a test in `workspace.rs`
//! (`a_write_in_one_workspace_cannot_reach_a_second_tree_that_shares_the_blob`) that specifically
//! covers this feature's new stake in it: before dedup, a job that corrupted a store tree ruined one
//! tree; now it would ruin every tree sharing the blob. The CoW clone is what keeps that hypothetical.
//!
//! # What a blob is keyed on, and why the mode is in the key
//!
//! A blob's key is the pair `(blob_id, mode)` — keel's content address for the bytes, and keel's
//! mode class for the file — which is exactly the pair a keel `TreeEntry` records (see
//! [`crate::verify::blob_id`]). Two entries agreeing on that pair are indistinguishable to every
//! tree address in the system, so giving them one inode cannot change what any tree hashes to.
//!
//! The mode is in the key because **a hard link shares an inode and an inode carries the mode**.
//! Key on content alone and the second tree to arrive with `run.sh` at 0644 would take a link to the
//! 0755 inode — flipping the executable bit of a file whose exec bit keel *addresses*. The tree
//! would then hash to something other than the `tree_id` it is filed under: verification passed, and
//! the store quietly broke it afterwards. With the mode in the key, the two are different paths and
//! therefore different inodes, and the failure cannot be written.
//!
//! A file's mode is normalized to the canonical `0644`/`0755` for its class *before* it becomes a
//! blob, so a blob's mode is a function of its key rather than of whichever tree happened to arrive
//! first. [`crate::extract`] already normalizes to those two values for its own reasons, so for
//! every real fetch this changes nothing; it is here so the invariant does not depend on the caller.
//! Both values map to the same keel mode class, so normalizing can never move a tree's address.
//!
//! # Blob lifetime: nothing reclaims them, and nothing reclaims trees either
//!
//! Blobs outlive the trees that reference them, and this is worth stating plainly because the
//! sentence above ("there is no invalidation question, only GC") has always described a GC that does
//! not exist. **Nothing in this repository removes a tree from the content store** — there is no
//! reaper, no retention policy, no size ceiling, and no `remove` on this type; the only deletions
//! here are of *staging* directories that never became a tree. So the store grows without bound
//! today, and adding blobs does not change that in kind: it lowers the growth rate substantially and
//! adds one new shape of garbage, the blob whose last referencing tree was never written because a
//! commit failed after dedup and before the rename.
//!
//! Reclamation, when it is built, is a link-count question and needs no index: a blob with
//! `st_nlink == 1` is referenced by no tree. That is a consequence of the layout, not a promise that
//! anything calls it. It is in the README's known-gaps list for the same reason.
//!
//! [`FetchBroker`]: crate::FetchBroker

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use keel_store::snapshot::MODE_EXEC;

/// A verified tree in the store.
#[derive(Debug, Clone)]
pub struct StoredTree {
    pub tree_id: String,
    /// Directory holding the extracted tree. Read-only as far as the broker is concerned; nodes
    /// materialize their own workspace from it. Since M4 its regular files are shared with the
    /// tenant's blob store, which makes "read-only" load-bearing rather than merely tidy.
    pub path: PathBuf,
    /// True when the tree was already present — the fetch, extract and verify were all skipped.
    pub cached: bool,
    /// What publishing this tree did to its files, or `None` when this call published nothing
    /// (`cached`). Not folded into a zeroed report, because "we shared nothing" and "we did nothing"
    /// are the two states a dedup layer must never be allowed to confuse — the first is the silent
    /// regression this feature is most likely to suffer.
    pub dedup: Option<DedupReport>,
}

/// What one publish did with a tree's files, so **sharing is a reported fact rather than an
/// inference**.
///
/// The failure this exists to prevent: a dedup layer that silently stops deduping still passes every
/// correctness test, because the trees are all still right — only fat. Counts alone would be the
/// implementation's own claim about itself, so the tests below assert these *and* inode identity and
/// link counts; the report is what makes an operator (and a regression) able to see the difference
/// between a store that is sharing and one that is not. `workspace.rs`'s `MaterializeReport` exists
/// for the same reason pointing the other way.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DedupReport {
    /// Regular files that *became* a blob: this tenant held no file with that (content, mode) yet.
    pub blobs_created: usize,
    /// Regular files replaced by a link to a blob the tenant already had. This is the saving: each
    /// one is a file's worth of bytes not written, counting duplicates inside a single tree too.
    pub blobs_reused: usize,
    /// Regular files left as their own private copy because the filesystem refused to link them.
    /// Correct, just fat — see [`ContentStore::share_one`] for why this is not an error.
    pub unshared: usize,
    /// Why the first `unshared` file happened, if any. The first rather than the last, and only one:
    /// a filesystem that cannot link fails identically for every file, and the hundred-thousandth
    /// copy of the reason says nothing the first did not.
    pub unshared_reason: Option<String>,
    /// Symlinks left exactly as the extractor made them. Never blobs — see [`ContentStore::share_one`].
    pub symlinks: usize,
    /// Directories walked (excluding the tree root itself).
    pub directories: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("content store i/o error: {0}")]
    Io(String),
}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        StoreError::Io(e.to_string())
    }
}

/// A filesystem CAS rooted at one directory: a directory per tree, a file per distinct
/// (content, mode) pair, and a hard link joining the two. See the module docs for the layout and for
/// why the link is safe here and forbidden one crate over.
#[derive(Debug, Clone)]
pub struct ContentStore {
    root: PathBuf,
}

impl ContentStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        ContentStore { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The on-disk directory name for a tenant.
    ///
    /// Hashed rather than sanitized, for two reasons. A sanitizer that strips `/` and `..` is
    /// **not injective** — `acme/x` and `acme-x` can collapse to one directory, which is a
    /// cross-tenant dedup bug arriving through the back door, and cross-tenant sharing is the one
    /// thing this store must make impossible. Hashing is injective for every practical purpose and
    /// cannot produce a path component at all, so tenant text never reaches the filesystem.
    ///
    /// Blob dedup raises the stakes on this function rather than changing it: the scope is now the
    /// only thing standing between two tenants and a *shared inode*, which is a stronger form of
    /// sharing than a shared directory and would survive a later reader being careful.
    fn tenant_scope(tenant: &str) -> String {
        let h = blake3::hash(tenant.as_bytes());
        hex::encode(&h.as_bytes()[..16])
    }

    /// Where `(tenant, tree_id)` lives. `tree_id` must already be normalized (64 lowercase hex) —
    /// [`crate::verify::normalize_tree_id`] is the gate, and it runs before anything reaches here.
    pub fn tree_path(&self, tenant: &str, tree_id: &str) -> PathBuf {
        self.root.join(Self::tenant_scope(tenant)).join("trees").join(tree_id)
    }

    /// Is this tree already here, for this tenant? The `if store.has(tree_id) { return }` of D§4.2.
    pub fn has(&self, tenant: &str, tree_id: &str) -> bool {
        self.tree_path(tenant, tree_id).is_dir()
    }

    /// A fresh, empty staging directory on the same filesystem as the final location, so the commit
    /// is a rename and never a copy.
    ///
    /// Extraction happens here, not at the destination: a half-extracted or failed-verification tree
    /// must never be visible at its content address for even an instant, or another worker could
    /// take a `has()` hit on it and run a job against bytes we rejected.
    pub fn stage(&self, tenant: &str) -> Result<tempfile::TempDir, StoreError> {
        Ok(tempfile::TempDir::new_in(self.staging_dir(tenant)?)?)
    }

    /// The tenant's scratch area — staging trees and in-flight archive downloads both live here, on
    /// the store's filesystem so publishing is a rename. Scoped by tenant like everything else, so a
    /// half-downloaded archive is not even transiently in another tenant's directory.
    pub fn staging_dir(&self, tenant: &str) -> Result<PathBuf, StoreError> {
        let staging = self.root.join(Self::tenant_scope(tenant)).join("staging");
        fs::create_dir_all(&staging)?;
        Ok(staging)
    }

    /// Publish a staged tree at its content address, atomically.
    ///
    /// If another worker got there first we keep theirs and drop ours: both are verified to hash to
    /// the same `tree_id`, so they are the same tree by definition, and preferring the existing one
    /// means no reader ever sees the directory change under it.
    ///
    /// **Dedup runs here, and strictly before the rename.** Two reasons, both about the atomicity
    /// this function has always provided:
    ///
    /// * The publish must stay *exactly one* `rename(2)`. A tree is complete or absent; there is no
    ///   instant at which `has()` is true and a file is missing, because at the moment the directory
    ///   appears every file in it is already final. Replacing files with links *after* the rename
    ///   would open precisely that window, and a crash inside it leaves a tree that looks present,
    ///   passes `has()`, and is missing a file forever — the one regression this refactor could
    ///   plausibly cause.
    /// * A crash *during* dedup costs orphaned blobs and nothing else: the staged directory is
    ///   dropped, no tree was ever visible, and a later attempt re-links against blobs that are
    ///   already correct (they are content-addressed, so "already there" and "what we would have
    ///   written" are the same bytes).
    ///
    /// Dedup also runs strictly *after* [`crate::verify`], which is the caller's ordering, so the
    /// bytes that become a shared blob are bytes that re-hashed to their `tree_id` first.
    pub fn commit(&self, tenant: &str, tree_id: &str, staged: tempfile::TempDir) -> Result<StoredTree, StoreError> {
        let dest = self.tree_path(tenant, tree_id);
        if dest.is_dir() {
            return Ok(StoredTree { tree_id: tree_id.to_string(), path: dest, cached: true, dedup: None });
        }
        let dedup = self.link_into_blobs(tenant, staged.path())?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        // `keep` disarms the TempDir's destructor: the directory is about to become the store's.
        let from = staged.keep();
        match fs::rename(&from, &dest) {
            Ok(()) => Ok(StoredTree { tree_id: tree_id.to_string(), path: dest, cached: false, dedup: Some(dedup) }),
            Err(e) => {
                // Lost the race (rename onto a non-empty directory fails), or a real i/o problem.
                // Whatever this call linked into the blob store stays: the winner's tree references
                // the same content-addressed blobs, so at worst a few of them are momentarily
                // orphaned, and every byte of them is bytes the winner would have written anyway.
                let _ = fs::remove_dir_all(&from);
                if dest.is_dir() {
                    Ok(StoredTree { tree_id: tree_id.to_string(), path: dest, cached: true, dedup: None })
                } else {
                    Err(StoreError::Io(e.to_string()))
                }
            }
        }
    }

    /// Where a tenant's blob with this key lives. Private, and it takes a tenant, so there is no way
    /// to name another tenant's blob by accident — the same rule as [`Self::tree_path`], applied to
    /// the sharper kind of sharing.
    fn blob_path(&self, tenant: &str, key: &BlobKey) -> PathBuf {
        self.root
            .join(Self::tenant_scope(tenant))
            .join("blobs")
            .join(&key.id[..2])
            .join(format!("{}.{}", &key.id[2..], key.mode_suffix()))
    }

    /// Replace every regular file in a staged tree with a link to the tenant's single copy of its
    /// contents, creating that copy when the tenant does not have one yet.
    ///
    /// Iterative rather than recursive: the extractor bounds path depth, but a stack-recursive walk
    /// would make that bound load-bearing for *our* stack over what is still attacker-shaped input.
    /// (`hull-ci-server`'s `copy_dir` is iterative for the same reason.)
    ///
    /// `symlink_metadata`, never `metadata`: a symlink is examined, never resolved, and the walk
    /// descends only into real directories. The extractor already guarantees no entry sits under a
    /// symlink, but that is a guarantee made by a different module, and "somebody else validated it"
    /// is how the second copy of a rule stops being true.
    fn link_into_blobs(&self, tenant: &str, root: &Path) -> Result<DedupReport, StoreError> {
        let mut report = DedupReport::default();
        let scratch = link_scratch_path(root)?;
        let mut pending = vec![root.to_path_buf()];

        while let Some(dir) = pending.pop() {
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                let path = entry.path();
                let meta = fs::symlink_metadata(&path)?;

                if meta.is_dir() {
                    report.directories += 1;
                    pending.push(path);
                } else if meta.is_symlink() {
                    // Not a blob, and not negotiable. keel addresses a symlink as a blob over its
                    // *target path*, so a link and a regular file can share a content address — the
                    // tests below use exactly that collision — while being different kinds of thing
                    // on disk. Hard-linking one to the other would turn a symlink into a regular
                    // file (or the reverse) and change the tree's address. Nothing here follows a
                    // link either, which is what keeps the extractor's containment intact.
                    report.symlinks += 1;
                } else if meta.is_file() {
                    self.share_one(tenant, &path, &meta, &scratch, &mut report)?;
                } else {
                    // A device node, fifo or socket. The extractor refuses all of these and
                    // verification would have failed on one, so its presence means something wrote
                    // into staging behind us. Refuse rather than skip: a tree that silently differs
                    // from what was verified is the failure the content address exists to rule out.
                    return Err(StoreError::Io(format!(
                        "unexpected file type in the staged tree at `{}`",
                        path.display()
                    )));
                }
            }
        }
        let _ = fs::remove_file(&scratch);
        Ok(report)
    }

    /// Point one staged file at the tenant's single copy of its contents.
    ///
    /// Two directions, and neither one copies a byte:
    ///
    /// * **First arrival.** `link(2)` the staged file *into* the blob store. The file we already
    ///   have becomes the blob — there is no third copy and no `write`, just a second name for an
    ///   inode that was going to exist anyway.
    /// * **Already there.** Link the blob back over the staged path. The staged inode is unlinked
    ///   and its blocks returned; that is where the saving is realized.
    ///
    /// The replacement goes through a scratch name and a `rename(2)` rather than
    /// `remove_file` + `link`, so the staged path is **never** momentarily absent. The unlink-first
    /// form has a real failure: `link(2)` can fail after the unlink — `EMLINK` when a very popular
    /// blob hits the filesystem's link ceiling (65 000 on ext4, and "the empty file" is exactly the
    /// blob that gets there) — leaving a hole in a tree we are about to publish. `rename(2)` cannot
    /// leave that state.
    ///
    /// **`EEXIST` is the expected case, not an error.** Two fetches racing to store overlapping
    /// trees will both try to create the same blob; the loser takes the reuse path and gets the
    /// winner's bytes, which are its own bytes, because the name is a content address.
    ///
    /// A link failure that is not `EEXIST` leaves the file exactly as it is and records why. A
    /// filesystem that will not link (no hard-link support, a link-count ceiling, a quota) must cost
    /// disk, never a job: the tree is completely correct either way, and turning an optimization's
    /// failure into an `errored` verdict would report a storage problem as a statement about the
    /// author's code. The counter is what keeps that quiet fallback from being invisible.
    fn share_one(
        &self,
        tenant: &str,
        path: &Path,
        meta: &fs::Metadata,
        scratch: &Path,
        report: &mut DedupReport,
    ) -> Result<(), StoreError> {
        let key = BlobKey::of(path, meta)?;
        // Before it can become a blob, and only ever within its own keel mode class, so the blob's
        // mode is a function of its key. See the module docs: without this the mode of a shared
        // inode would be whichever tree arrived first.
        set_canonical_mode(path, &key)?;

        let blob = self.blob_path(tenant, &key);
        if let Some(parent) = blob.parent() {
            // `create_dir_all` is safe here in a way it is not in the extractor: every component
            // below the store root is hex this module generated, so there is no attacker-chosen name
            // for a planted symlink to hide in.
            fs::create_dir_all(parent)?;
        }

        match fs::hard_link(path, &blob) {
            Ok(()) => {
                report.blobs_created += 1;
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // A leftover scratch link can only come from a process that died between the link
                // and the rename below; removing it keeps that from failing this commit.
                let _ = fs::remove_file(scratch);
                match fs::hard_link(&blob, scratch).and_then(|()| fs::rename(scratch, path)) {
                    Ok(()) => {
                        report.blobs_reused += 1;
                        Ok(())
                    }
                    Err(e) => {
                        // The blob exists and we could not link to it (`EMLINK`, a quota). The
                        // staged file is untouched — that is what the scratch name bought — so the
                        // tree is still correct and merely unshared.
                        let _ = fs::remove_file(scratch);
                        report.unshared += 1;
                        report.unshared_reason.get_or_insert_with(|| e.to_string());
                        Ok(())
                    }
                }
            }
            Err(e) => {
                report.unshared += 1;
                report.unshared_reason.get_or_insert_with(|| e.to_string());
                Ok(())
            }
        }
    }
}

/// The two halves of a blob's identity, which are exactly the two halves of a keel `TreeEntry`'s
/// identity for a file: the content address, and the mode class. See the module docs for why the
/// mode cannot be left out, and [`crate::verify::blob_id`] for why both come from the verifier's
/// definitions rather than from a second one here.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BlobKey {
    /// `blake3(0x01 ++ contents)` as lowercase hex — keel's blob id.
    id: String,
    /// True when keel records this file as `MODE_EXEC`.
    exec: bool,
}

impl BlobKey {
    fn of(path: &Path, meta: &fs::Metadata) -> Result<BlobKey, StoreError> {
        let id = crate::verify::blob_id(path).map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(BlobKey { id: id.to_hex(), exec: crate::verify::file_mode(meta) == MODE_EXEC })
    }

    /// The mode written into the blob's file name. Spelled as the octal permission a reader would
    /// see in `ls -l`, because a directory listing of the blob store is how anyone will ever debug
    /// this, and `100755` (keel's encoding) means nothing to `stat`.
    fn mode_suffix(&self) -> &'static str {
        if self.exec {
            "755"
        } else {
            "644"
        }
    }
}

/// The scratch name used to swap a blob link into place, derived from the staged directory's own
/// (unique) name and kept **beside** it rather than inside it.
///
/// Inside the tree it would be a file that the rename normally removes — and that a failure between
/// the link and the rename would publish as part of the tree, changing its address. Beside it, in
/// the tenant's staging area, the worst case is a stray link in scratch space.
fn link_scratch_path(staged_root: &Path) -> Result<PathBuf, StoreError> {
    let name = staged_root
        .file_name()
        .ok_or_else(|| StoreError::Io(format!("staged tree `{}` has no name", staged_root.display())))?;
    Ok(staged_root.with_file_name(format!("{}.blob-link", name.to_string_lossy())))
}

/// Force a file to the canonical permission for its keel mode class.
///
/// Both values keel can address (`0644`, `0755`) survive; anything else in the mode is dropped. That
/// is not a new policy — [`crate::extract::set_mode`] already normalizes to exactly these two, for
/// the same reason (keel records two file modes, so nothing else can round-trip to a `tree_id`) —
/// it is that policy restated where the blob store depends on it.
#[cfg(unix)]
fn set_canonical_mode(path: &Path, key: &BlobKey) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(if key.exec { 0o755 } else { 0o644 }))
}

#[cfg(not(unix))]
fn set_canonical_mode(_path: &Path, _key: &BlobKey) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::{KeelTreeVerifier, TreeVerifier};
    use tempfile::TempDir;

    const TREE: &str = "f7a2d47020c63c8e00000000000000000000000000000000000000000000abcd";
    const TREE2: &str = "0123456789abcdef000000000000000000000000000000000000000000009999";
    const TREE3: &str = "fedcba987654321000000000000000000000000000000000000000000000aaaa";

    fn store() -> (TempDir, ContentStore) {
        let dir = TempDir::new().unwrap();
        let store = ContentStore::new(dir.path());
        (dir, store)
    }

    #[test]
    fn a_committed_tree_is_a_hit_and_keeps_its_content() {
        let (_d, store) = store();
        assert!(!store.has("acme", TREE));

        let staged = store.stage("acme").unwrap();
        fs::write(staged.path().join("a.txt"), b"hi").unwrap();
        let stored = store.commit("acme", TREE, staged).unwrap();

        assert!(!stored.cached);
        assert!(store.has("acme", TREE));
        assert_eq!(fs::read_to_string(stored.path.join("a.txt")).unwrap(), "hi");
    }

    #[test]
    fn the_same_tree_id_is_a_different_directory_for_each_tenant() {
        // The hard rule (D§4.2/D7): identical content, no sharing.
        let (_d, store) = store();
        let a = store.tree_path("acme", TREE);
        let b = store.tree_path("globex", TREE);
        assert_ne!(a, b);

        let staged = store.stage("acme").unwrap();
        fs::write(staged.path().join("secret.txt"), b"acme's source").unwrap();
        store.commit("acme", TREE, staged).unwrap();

        // Globex must see a miss for a tree Acme holds — otherwise a `has()` hit is an oracle for
        // "another tenant has this exact file", and the store answers questions about repos the
        // caller cannot read.
        assert!(store.has("acme", TREE));
        assert!(!store.has("globex", TREE), "cross-tenant dedup must be impossible, not merely off");
    }

    #[test]
    fn tenant_scopes_are_injective_where_a_sanitizer_would_collide() {
        // `acme/x` vs `acme-x` vs `acme..x`: a strip-the-bad-characters scheme maps several of these
        // to one directory; hashing does not. And no tenant string can produce a traversal.
        let names = ["acme", "acme/x", "acme-x", "acme..x", "../../etc", "acme\0x", ""];
        let scopes: Vec<_> = names.iter().map(|t| ContentStore::tenant_scope(t)).collect();
        for (i, a) in scopes.iter().enumerate() {
            assert!(a.bytes().all(|b| b.is_ascii_hexdigit()), "a scope is never attacker text");
            for b in scopes.iter().skip(i + 1) {
                assert_ne!(a, b, "two tenants must never share a scope");
            }
        }
    }

    #[test]
    fn staging_is_outside_the_addressed_namespace() {
        // A tree only becomes visible at its address after verification, so a `has()` hit can never
        // catch a half-written or rejected extraction.
        let (_d, store) = store();
        let staged = store.stage("acme").unwrap();
        fs::write(staged.path().join("partial"), b"...").unwrap();
        assert!(!store.has("acme", TREE));
        assert!(!staged.path().starts_with(store.tree_path("acme", TREE)));
        drop(staged);
    }

    #[test]
    fn committing_over_an_existing_tree_keeps_the_existing_one() {
        let (_d, store) = store();
        let first = store.stage("acme").unwrap();
        fs::write(first.path().join("a.txt"), b"first").unwrap();
        store.commit("acme", TREE, first).unwrap();

        let second = store.stage("acme").unwrap();
        fs::write(second.path().join("a.txt"), b"second").unwrap();
        let path = second.path().to_path_buf();
        let stored = store.commit("acme", TREE, second).unwrap();

        assert!(stored.cached, "the loser of the race reports a hit, not an error");
        assert_eq!(stored.dedup, None, "a call that published nothing did no dedup work");
        assert_eq!(fs::read_to_string(stored.path.join("a.txt")).unwrap(), "first");
        assert!(!path.exists(), "the losing staging directory is cleaned up");
    }

    // ---------------------------------------------------------------------------------------------
    // Dedup (design D§4.2, the M4 item).
    //
    // Everything below asserts on **structure** — inode identity and link counts — and not on
    // contents, because every one of these tests passes on an implementation that stores two full
    // copies. A dedup layer that silently stops deduping leaves every tree correct and every
    // content assertion green; the sharing itself is the only thing that can catch it, so it is what
    // is asserted. Nothing here measures time.
    // ---------------------------------------------------------------------------------------------

    #[cfg(unix)]
    mod dedup {
        use super::*;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        /// Stage a tree of `(relative path, contents, executable)` and publish it at `tree_id`.
        fn commit_tree(store: &ContentStore, tenant: &str, tree_id: &str, files: &[(&str, &[u8], bool)]) -> StoredTree {
            let staged = store.stage(tenant).unwrap();
            for (name, body, exec) in files {
                let p = staged.path().join(name);
                if let Some(parent) = p.parent() {
                    fs::create_dir_all(parent).unwrap();
                }
                fs::write(&p, body).unwrap();
                fs::set_permissions(&p, fs::Permissions::from_mode(if *exec { 0o755 } else { 0o644 })).unwrap();
            }
            store.commit(tenant, tree_id, staged).unwrap()
        }

        /// `(device, inode)` — the identity of a file, as opposed to a copy of one.
        fn id_of(p: &Path) -> (u64, u64) {
            let m = fs::symlink_metadata(p).unwrap();
            (m.dev(), m.ino())
        }

        fn nlink(p: &Path) -> u64 {
            fs::symlink_metadata(p).unwrap().nlink()
        }

        fn mode_of(p: &Path) -> u32 {
            fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
        }

        /// Every blob this tenant holds, as `<shard>/<name>` strings.
        fn blobs(store: &ContentStore, tenant: &str) -> Vec<String> {
            let root = store.root.join(ContentStore::tenant_scope(tenant)).join("blobs");
            let mut out = Vec::new();
            let Ok(shards) = fs::read_dir(&root) else { return out };
            for shard in shards {
                let shard = shard.unwrap();
                for blob in fs::read_dir(shard.path()).unwrap() {
                    out.push(format!(
                        "{}/{}",
                        shard.file_name().to_string_lossy(),
                        blob.unwrap().file_name().to_string_lossy()
                    ));
                }
            }
            out.sort();
            out
        }

        /// The bytes a directory tree actually costs, counting a shared inode **once**.
        ///
        /// This is the `du` question rather than the `ls` one, and it is the only honest way to
        /// state a saving: summing `len()` per path counts a hard link twice and would report a
        /// saving of zero on an implementation that is working perfectly.
        fn allocated_bytes(root: &Path) -> u64 {
            let mut seen = std::collections::HashSet::new();
            let mut total = 0;
            let mut pending = vec![root.to_path_buf()];
            while let Some(dir) = pending.pop() {
                for e in fs::read_dir(&dir).unwrap() {
                    let e = e.unwrap();
                    let m = fs::symlink_metadata(e.path()).unwrap();
                    if m.is_dir() {
                        pending.push(e.path());
                    } else if m.is_file() && seen.insert((m.dev(), m.ino())) {
                        total += m.len();
                    }
                }
            }
            total
        }

        #[test]
        fn two_trees_that_share_a_file_share_its_inode() {
            // The feature, stated as the only thing that can prove it happened. Contents are equal
            // in both the deduped and the duplicated implementation; one inode is not.
            let (_d, store) = store();
            let a = commit_tree(
                &store,
                "acme",
                TREE,
                &[("shared.txt", b"the bytes both trees hold", false), ("only-a.txt", b"a", false)],
            );
            let b = commit_tree(
                &store,
                "acme",
                TREE2,
                &[("shared.txt", b"the bytes both trees hold", false), ("only-b.txt", b"b", false)],
            );

            assert_eq!(
                id_of(&a.path.join("shared.txt")),
                id_of(&b.path.join("shared.txt")),
                "the second tree stored a second copy of a file the tenant already had"
            );
            assert_ne!(
                id_of(&a.path.join("only-a.txt")),
                id_of(&b.path.join("only-b.txt")),
                "different content must never land on one inode"
            );

            // Three names for one file: the blob, and one directory entry in each tree. This is the
            // number that a future reclaimer reads, and the number that silently drops to 2 if a
            // later tree stops being linked.
            assert_eq!(nlink(&a.path.join("shared.txt")), 3);
            assert_eq!(nlink(&a.path.join("only-a.txt")), 2, "an unshared file is still blob + tree");

            assert_eq!(a.dedup.unwrap(), DedupReport { blobs_created: 2, ..DedupReport::default() });
            assert_eq!(
                b.dedup.unwrap(),
                DedupReport { blobs_created: 1, blobs_reused: 1, ..DedupReport::default() },
                "the report must show the reuse; a silent stop is the failure this feature invites"
            );
        }

        #[test]
        fn duplicate_files_inside_one_tree_are_stored_once() {
            // Vendored copies, generated headers, the same LICENSE in twelve crates. The intra-tree
            // case costs nothing extra to support and is a large share of a real saving.
            let (_d, store) = store();
            let t = commit_tree(
                &store,
                "acme",
                TREE,
                &[("a/LICENSE", b"Apache-2.0 ...", false), ("b/LICENSE", b"Apache-2.0 ...", false)],
            );
            assert_eq!(id_of(&t.path.join("a/LICENSE")), id_of(&t.path.join("b/LICENSE")));
            assert_eq!(blobs(&store, "acme").len(), 1);
            assert_eq!(t.dedup.unwrap().blobs_reused, 1);
        }

        #[test]
        fn identical_bytes_with_different_modes_are_never_one_inode() {
            // The trap the mode-in-the-key exists for. A hard link shares an inode and an inode
            // carries the mode, so sharing these two would flip one file's exec bit — and keel
            // *addresses* the exec bit, so the loser's tree would stop hashing to the `tree_id` it
            // is filed under. Verification passed; the store would have broken it afterwards.
            const SCRIPT: &[u8] = b"#!/bin/sh\nexec make test\n";
            let (_d, store) = store();
            let a = commit_tree(&store, "acme", TREE, &[("run.sh", SCRIPT, true)]);
            let b = commit_tree(&store, "acme", TREE2, &[("run.sh", SCRIPT, false)]);

            assert_ne!(
                id_of(&a.path.join("run.sh")),
                id_of(&b.path.join("run.sh")),
                "same bytes, different mode: one inode cannot hold both"
            );
            assert_eq!(mode_of(&a.path.join("run.sh")), 0o755, "the executable file is still executable");
            assert_eq!(mode_of(&b.path.join("run.sh")), 0o644, "and the plain one did not become so");
            assert_eq!(b.dedup.unwrap().blobs_reused, 0, "a mode difference is not a reuse");

            // Two blobs, one per (content, mode) pair, and the mode is visible in the name.
            let names = blobs(&store, "acme");
            assert_eq!(names.len(), 2, "{names:?}");
            assert!(names.iter().any(|n| n.ends_with(".755")));
            assert!(names.iter().any(|n| n.ends_with(".644")));

            // The same trap inside a single tree, where a link would be even easier to write.
            let c = commit_tree(&store, "acme", TREE3, &[("x.sh", SCRIPT, true), ("x.txt", SCRIPT, false)]);
            assert_ne!(id_of(&c.path.join("x.sh")), id_of(&c.path.join("x.txt")));
            assert_eq!(mode_of(&c.path.join("x.sh")) & 0o111, 0o111);
            assert_eq!(mode_of(&c.path.join("x.txt")) & 0o111, 0);
        }

        #[test]
        fn a_blobs_mode_does_not_depend_on_which_tree_arrived_first() {
            // A caller that is not our extractor can stage a file at any mode. Normalizing to the
            // canonical permission for the keel class before it becomes a blob keeps a later tree
            // from inheriting `0600` (or `0777`) because of who got there first. Both spellings are
            // the same keel mode, so no tree's address moves.
            let (_d, store) = store();
            let staged = store.stage("acme").unwrap();
            fs::write(staged.path().join("odd"), b"body").unwrap();
            fs::set_permissions(staged.path().join("odd"), fs::Permissions::from_mode(0o600)).unwrap();
            let a = store.commit("acme", TREE, staged).unwrap();
            assert_eq!(mode_of(&a.path.join("odd")), 0o644);

            let b = commit_tree(&store, "acme", TREE2, &[("odd", b"body", false)]);
            assert_eq!(id_of(&a.path.join("odd")), id_of(&b.path.join("odd")), "they are the same keel entry");
            assert_eq!(mode_of(&b.path.join("odd")), 0o644);
        }

        #[test]
        fn two_tenants_holding_the_same_bytes_hold_two_inodes() {
            // The store's single most important property, and the one a "harmless" refactor of the
            // key would take away. Asserted on inode identity, not on content equality: content is
            // equal in *both* the safe and the catastrophic implementation.
            let (_d, store) = store();
            let a = commit_tree(&store, "acme", TREE, &[("dep.tar", b"a proprietary dependency", false)]);
            let b = commit_tree(&store, "globex", TREE, &[("dep.tar", b"a proprietary dependency", false)]);

            assert_ne!(a.path, b.path);
            assert_ne!(
                id_of(&a.path.join("dep.tar")),
                id_of(&b.path.join("dep.tar")),
                "one inode across tenants is a cross-tenant existence oracle with a shared fate"
            );
            assert_eq!(nlink(&a.path.join("dep.tar")), 2, "acme's file is named by acme's blob and nothing else");
            assert_eq!(nlink(&b.path.join("dep.tar")), 2);
            assert_eq!(b.dedup.unwrap().blobs_reused, 0, "globex reused nothing; it had nothing");
            assert_eq!(blobs(&store, "acme").len(), 1);
            assert_eq!(blobs(&store, "globex").len(), 1);
        }

        #[test]
        fn a_deduped_tree_still_hashes_to_its_tree_id() {
            // The content address is the only thing the store promises. Wired to the real verifier —
            // the same `KeelTreeVerifier` the broker runs before committing — rather than asserted
            // informally, and checked on *both* trees after the second one shares the first's blobs.
            let (_d, store) = store();
            let verifier = KeelTreeVerifier::default();

            let stage_one = |files: &[(&str, &[u8], bool)]| {
                let staged = store.stage("acme").unwrap();
                for (name, body, exec) in files {
                    let p = staged.path().join(name);
                    fs::create_dir_all(p.parent().unwrap()).unwrap();
                    fs::write(&p, body).unwrap();
                    fs::set_permissions(&p, fs::Permissions::from_mode(if *exec { 0o755 } else { 0o644 })).unwrap();
                }
                std::os::unix::fs::symlink("src/main.rs", staged.path().join("link")).unwrap();
                // The address of what was staged, computed before the store touches it.
                let id = verifier.tree_id(staged.path()).unwrap();
                (staged, id)
            };

            let (staged_a, id_a) = stage_one(&[
                ("README.md", b"hello\n", false),
                ("src/main.rs", b"fn main() {}\n", false),
                ("run.sh", b"#!/bin/sh\n", true),
            ]);
            let a = store.commit("acme", &id_a, staged_a).unwrap();
            verifier.verify(&a.path, &id_a).expect("a deduped tree must still be the tree it is filed under");

            // A second tree overlapping the first in two of three files, so most of its entries are
            // now links into blobs the first tree's inodes provided.
            let (staged_b, id_b) = stage_one(&[
                ("README.md", b"hello\n", false),
                ("src/main.rs", b"fn main() {}\n", false),
                ("run.sh", b"#!/bin/sh\necho more\n", true),
            ]);
            let b = store.commit("acme", &id_b, staged_b).unwrap();
            assert_ne!(id_a, id_b);
            assert_eq!(b.dedup.as_ref().unwrap().blobs_reused, 2);
            assert_eq!(id_of(&a.path.join("README.md")), id_of(&b.path.join("README.md")));

            verifier.verify(&b.path, &id_b).expect("the sharing tree hashes to its own id");
            verifier.verify(&a.path, &id_a).expect("and the shared-from tree still hashes to its");
        }

        #[test]
        fn a_symlink_is_never_a_blob_even_when_it_shares_a_content_address() {
            // keel addresses a symlink as a blob over its *target path*, so `link -> real.txt` and a
            // regular file containing "real.txt" have the same keel blob id. They are different
            // kinds of thing on disk, and hard-linking one to the other would change the tree's
            // address (MODE_SYMLINK vs MODE_FILE) as well as let a link stand where a file belongs.
            let (_d, store) = store();
            let staged = store.stage("acme").unwrap();
            fs::write(staged.path().join("real.txt"), b"payload\n").unwrap();
            fs::write(staged.path().join("decoy"), b"real.txt").unwrap();
            std::os::unix::fs::symlink("real.txt", staged.path().join("link")).unwrap();
            let t = store.commit("acme", TREE, staged).unwrap();

            let link = t.path.join("link");
            assert!(fs::symlink_metadata(&link).unwrap().is_symlink(), "the link is still a link");
            assert_eq!(fs::read_link(&link).unwrap(), Path::new("real.txt"));
            assert_ne!(id_of(&link), id_of(&t.path.join("decoy")), "a symlink and a file are not one inode");
            assert_eq!(nlink(&link), 1, "nothing linked the symlink into the blob store");

            let report = t.dedup.unwrap();
            assert_eq!(report.symlinks, 1);
            assert_eq!(report.blobs_created, 2, "only the two regular files became blobs");
            assert_eq!(blobs(&store, "acme").len(), 2);
        }

        #[test]
        fn a_file_type_that_cannot_be_a_blob_is_refused_rather_than_skipped() {
            // Unreachable through the extractor, which rejects sockets, fifos and device nodes — so
            // one in a staged tree means something wrote into staging behind us, and publishing a
            // tree that differs from what was verified is exactly what the address rules out.
            //
            // Rooted somewhere short on purpose: a unix socket's path is capped at ~104 bytes
            // (`sun_path`), and macOS's default temp directory (`/var/folders/…`) plus a 32-character
            // tenant scope plus a staging name sits close enough to that ceiling that `bind` would
            // be a coin flip. The store under test is ordinary; only its root is chosen.
            let dir = tempfile::Builder::new().prefix("hullci").tempdir_in("/tmp").unwrap();
            let store = ContentStore::new(dir.path());
            let staged = store.stage("acme").unwrap();
            let _sock = std::os::unix::net::UnixListener::bind(staged.path().join("sock")).unwrap();
            let err = store.commit("acme", TREE, staged).unwrap_err();
            assert!(err.to_string().contains("unexpected file type"), "{err}");
            assert!(!store.has("acme", TREE), "and nothing was published");
        }

        #[test]
        fn the_publish_is_still_one_rename_so_a_crash_cannot_leave_a_partial_tree() {
            // Dedup runs entirely on the staged tree. Proved by doing the dedup half by hand and
            // asserting the tree is still invisible: at no point is `has()` true while a file is
            // still being replaced. Then the staged directory is dropped — the crash — and the tree
            // is absent rather than present-and-holed.
            let (_d, store) = store();
            let staged = store.stage("acme").unwrap();
            fs::write(staged.path().join("a"), b"one").unwrap();
            fs::write(staged.path().join("b"), b"two").unwrap();

            let report = store.link_into_blobs("acme", staged.path()).unwrap();
            assert_eq!(report.blobs_created, 2, "the files are shared before the rename, not after");
            assert!(!store.has("acme", TREE), "no tree is visible at its address mid-commit");

            let path = staged.path().to_path_buf();
            drop(staged);
            assert!(!path.exists());
            assert!(!store.has("acme", TREE), "a crash during dedup leaves no tree at all");

            // The cost of that crash: two orphaned blobs. Nothing reclaims them — see the module
            // docs and the README's known gaps. A later commit of the same content re-links them.
            assert_eq!(blobs(&store, "acme").len(), 2);
            let t = commit_tree(&store, "acme", TREE, &[("a", b"one", false), ("b", b"two", false)]);
            assert_eq!(t.dedup.unwrap().blobs_reused, 2, "the orphans are reused, not duplicated");
            assert_eq!(blobs(&store, "acme").len(), 2);
        }

        #[test]
        fn no_scratch_link_is_left_inside_a_published_tree() {
            // The swap goes through a scratch name; if that name lived inside the tree, a leftover
            // would be an extra entry and the tree would hash to something else. It lives beside it.
            let (_d, store) = store();
            commit_tree(&store, "acme", TREE, &[("a", b"same", false)]);
            let t = commit_tree(&store, "acme", TREE2, &[("a", b"same", false)]);
            let names: Vec<_> = fs::read_dir(&t.path)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert_eq!(names, vec!["a".to_string()], "the published tree holds exactly its own entries");
        }

        #[test]
        fn concurrent_commits_of_overlapping_trees_all_succeed_and_share() {
            // Two fetches racing to create the same blob is the normal case, not an edge: every
            // node in a sharded step arrives with the same dependencies. `EEXIST` must be tolerated
            // rather than fatal, and the loser must end up with the winner's bytes — which are its
            // own bytes, because the name is a content address.
            const SHARED: &[u8] = b"the dependency every branch of the fan-out holds\n";
            let (_d, store) = store();
            let ids = [TREE, TREE2, TREE3];

            let done: Vec<_> = std::thread::scope(|scope| {
                let handles: Vec<_> = ids
                    .iter()
                    .enumerate()
                    .map(|(i, id)| {
                        let store = store.clone();
                        scope.spawn(move || {
                            commit_tree(
                                &store,
                                "acme",
                                id,
                                &[("vendor/dep.rs", SHARED, false), ("unique", format!("{i}").as_bytes(), false)],
                            )
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().expect("a racing commit must not panic")).collect()
            });

            let first = id_of(&done[0].path.join("vendor/dep.rs"));
            for t in &done {
                assert!(!t.cached);
                let p = t.path.join("vendor/dep.rs");
                assert_eq!(fs::read(&p).unwrap(), SHARED, "the winner's bytes are the right bytes");
                assert_eq!(id_of(&p), first, "one of the racers stored a second copy");
            }
            assert_eq!(nlink(&done[0].path.join("vendor/dep.rs")), 1 + ids.len() as u64);

            // Exactly one blob for the shared file plus one per unique file: the race produced no
            // duplicates and no partial state.
            assert_eq!(blobs(&store, "acme").len(), 1 + ids.len());
            let created: usize = done.iter().map(|t| t.dedup.as_ref().unwrap().blobs_created).sum();
            let reused: usize = done.iter().map(|t| t.dedup.as_ref().unwrap().blobs_reused).sum();
            assert_eq!(created + reused, 2 * ids.len(), "every file is accounted for exactly once");
            assert_eq!(created, 1 + ids.len(), "and only one racer created the shared blob");
        }

        #[test]
        fn the_store_holds_one_blob_per_distinct_content_and_mode() {
            // The invariant behind the saving, stated as a count that a stalled dedup layer fails.
            let (_d, store) = store();
            commit_tree(
                &store,
                "acme",
                TREE,
                &[("a", b"one", false), ("b", b"one", false), ("c", b"one", true), ("d", b"two", false)],
            );
            commit_tree(&store, "acme", TREE2, &[("e", b"one", false), ("f", b"three", false)]);

            // Distinct pairs: (one,644) (one,755) (two,644) (three,644).
            assert_eq!(blobs(&store, "acme").len(), 4, "{:?}", blobs(&store, "acme"));
        }

        #[test]
        fn two_ninety_percent_overlapping_trees_cost_about_one_tree() {
            // The benefit, measured on structure rather than on a clock: the store's allocated bytes
            // for two trees that share 90% of their files, against the same measurement for one.
            // (This repo already has one flaky wall-clock test; a second is not worth a benchmark
            // that a loaded CI machine can fail.)
            const FILES: usize = 20;
            const SHARED: usize = 18;
            const SIZE: usize = 8 * 1024;
            // Distinct per seed by construction. An earlier version of this fixture keyed the fill
            // byte on `seed % 26` and two "different" files collided, which made the measurement
            // report a saving that was partly an accident of the test data.
            let body = |seed: usize| {
                let mut v = vec![b'.'; SIZE];
                v[..8].copy_from_slice(&(seed as u64).to_le_bytes());
                v
            };

            let (_d, store) = store();
            let scope = store.root.join(ContentStore::tenant_scope("acme"));

            let tree_a: Vec<_> = (0..FILES).map(|i| (format!("f{i}"), body(i))).collect();
            let files_a: Vec<_> = tree_a.iter().map(|(n, b)| (n.as_str(), b.as_slice(), false)).collect();
            commit_tree(&store, "acme", TREE, &files_a);
            let one_tree = allocated_bytes(&scope);
            assert_eq!(one_tree, (FILES * SIZE) as u64, "one tree costs its own bytes once, not twice");

            // The second tree differs in its last two files — a realistic "changed two files" push.
            let tree_b: Vec<_> = (0..FILES)
                .map(|i| (format!("f{i}"), if i < SHARED { body(i) } else { body(i + 100) }))
                .collect();
            let files_b: Vec<_> = tree_b.iter().map(|(n, b)| (n.as_str(), b.as_slice(), false)).collect();
            let b = commit_tree(&store, "acme", TREE2, &files_b);
            assert_eq!(b.dedup.as_ref().unwrap().blobs_reused, SHARED);
            assert_eq!(b.dedup.as_ref().unwrap().blobs_created, FILES - SHARED);

            let two_trees = allocated_bytes(&scope);
            let duplicated = 2 * one_tree;
            assert_eq!(
                two_trees,
                one_tree + ((FILES - SHARED) * SIZE) as u64,
                "the second tree must cost only the files it actually changed"
            );
            // Stated as the ratio the milestone claims, so a regression to full copies reads as the
            // number it is: 1.10x of one tree, where storing both whole would be 2.00x.
            assert!(
                two_trees * 100 <= one_tree * 115,
                "two 90%-overlapping trees cost {two_trees} bytes; one tree is {one_tree} and two \
                 full copies would be {duplicated}"
            );
        }

        #[test]
        fn nothing_in_this_type_removes_a_tree_or_a_blob() {
            // The blob-lifetime gap, pinned rather than described: blobs outlive the trees that
            // reference them because *nothing* here removes either. If a reclaimer is ever added,
            // this test is where it announces itself — and `st_nlink == 1` is the condition it will
            // use, so the layout is asserted to support it.
            let (_d, store) = store();
            let t = commit_tree(&store, "acme", TREE, &[("a", b"one", false)]);
            drop(t);
            assert!(store.has("acme", TREE), "there is no eviction, no retention and no size ceiling");
            assert_eq!(blobs(&store, "acme").len(), 1);

            // An orphan is recognizable without an index, which is what makes a future GC cheap.
            let orphan = {
                let staged = store.stage("acme").unwrap();
                fs::write(staged.path().join("x"), b"never published").unwrap();
                store.link_into_blobs("acme", staged.path()).unwrap();
                let key = BlobKey::of(
                    &staged.path().join("x"),
                    &fs::symlink_metadata(staged.path().join("x")).unwrap(),
                )
                .unwrap();
                store.blob_path("acme", &key)
            };
            assert_eq!(nlink(&orphan), 1, "an unreferenced blob has exactly one name");
            assert_eq!(nlink(&store.tree_path("acme", TREE).join("a")), 2, "a referenced one has more");
        }
    }
}
