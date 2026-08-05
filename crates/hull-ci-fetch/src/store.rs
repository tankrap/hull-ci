//! The internal content store: verified trees on disk, keyed by `(tenant, tree_id)`.
//!
//! Two jobs:
//!
//! 1. **Fetch once per tree, not once per node** (design D§4.2). A 12-way sharded test step must not
//!    pull the same archive from Hull twelve times, so the first thing [`FetchBroker`] does is ask
//!    this store whether the tree is already here. Content addresses are immutable, so a hit is
//!    always safe — there is no invalidation question, only GC.
//! 2. **Keep tenants apart.** The key is `(tenant, tree_id)`, never `tree_id` alone.
//!
//! **Cross-tenant dedup is not a setting.** Two tenants holding byte-identical trees get two copies.
//! Sharing them would save disk and hand out an oracle: a tenant could learn that *somebody else*
//! holds a given tree — by timing a fetch, by a store hit on a tree they never pushed — which for a
//! content-addressed store means learning that a specific file exists somewhere in the fleet. Repo
//! contents, and the fact of a proprietary dependency, leak that way. Design D§4.2/D7 makes this a
//! hard rule, so the API does not offer a tenant-free lookup at all: there is no `has(tree_id)` to
//! call by mistake.
//!
//! [`FetchBroker`]: crate::FetchBroker

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// A verified tree in the store.
#[derive(Debug, Clone)]
pub struct StoredTree {
    pub tree_id: String,
    /// Directory holding the extracted tree. Read-only as far as the broker is concerned; nodes
    /// materialize their own workspace from it.
    pub path: PathBuf,
    /// True when the tree was already present — the fetch, extract and verify were all skipped.
    pub cached: bool,
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

/// A filesystem CAS rooted at one directory. Simple by choice for M1: the interesting properties are
/// immutability and tenant scoping, both of which a directory-per-tree gives us directly.
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
    pub fn commit(&self, tenant: &str, tree_id: &str, staged: tempfile::TempDir) -> Result<StoredTree, StoreError> {
        let dest = self.tree_path(tenant, tree_id);
        if dest.is_dir() {
            return Ok(StoredTree { tree_id: tree_id.to_string(), path: dest, cached: true });
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        // `keep` disarms the TempDir's destructor: the directory is about to become the store's.
        let from = staged.keep();
        match fs::rename(&from, &dest) {
            Ok(()) => Ok(StoredTree { tree_id: tree_id.to_string(), path: dest, cached: false }),
            Err(e) => {
                // Lost the race (rename onto a non-empty directory fails), or a real i/o problem.
                let _ = fs::remove_dir_all(&from);
                if dest.is_dir() {
                    Ok(StoredTree { tree_id: tree_id.to_string(), path: dest, cached: true })
                } else {
                    Err(StoreError::Io(e.to_string()))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const TREE: &str = "f7a2d47020c63c8e00000000000000000000000000000000000000000000abcd";

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
        assert_eq!(fs::read_to_string(stored.path.join("a.txt")).unwrap(), "first");
        assert!(!path.exists(), "the losing staging directory is cleaned up");
    }
}
