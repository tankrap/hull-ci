//! Source trees the stub Hull serves at `source_url`, their tar serialisation, and their content
//! address.
//!
//! Spec §6: `GET source_url` returns the change's keel **tree** — named by `tree_id` — as a `tar`
//! archive. The suite therefore has to be able to (a) produce a tar and (b) name it, so that the
//! corrupted-archive case is a genuine `tree_id` mismatch rather than a broken tar.
//!
//! # Two addressing modes
//!
//! `tree_id` is opaque on the wire (§5) and re-hashing is only a **MAY** (§6), so a *general* CI
//! cannot be expected to reproduce any particular hash — but *our* runner re-hashes with keel's real
//! encoding and refuses anything that does not match (design D§4.2, `hull-ci-fetch::verify`). One
//! fixed choice cannot serve both subjects, so the choice is a knob: [`Addressing`], set by
//! `HULL_CI_TREE_ID` (see [`crate::config::addressing`]).
//!
//! * [`Addressing::Opaque`] (default) — [`opaque_tree_id`]: a documented SHA-256 canonicalisation
//!   that any language can reproduce, which the Python reference CIs do. Correct for judging a CI
//!   that does not verify, and the only mode that keeps the suite dependency-free.
//! * [`Addressing::Keel`] — [`keel_tree_id`]: the genuine keel address, computed with keel's own
//!   encoder (`keel-store`, pinned to the rev `hull-server` and `hull-ci-fetch` embed). Point the
//!   suite at a **verifying** runner in this mode; in [`Addressing::Opaque`] such a runner would
//!   correctly report `errored` for every job and the suite would be measuring its own disagreement.
//!
//! Nothing else in the suite moves between modes: the archive bytes, the fixtures and every
//! assertion are identical, and the corrupted-archive case turns on an asymmetry (bytes that are not
//! the bytes that were hashed) that holds under either canonicalisation.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use sha2::{Digest, Sha256};

use crate::config;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// How the suite names a tree. See the module docs; selected by `HULL_CI_TREE_ID`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addressing {
    /// An arbitrary content-derived address ([`opaque_tree_id`]). The default.
    Opaque,
    /// A genuine keel tree address ([`keel_tree_id`]). Requires the `keel` cargo feature.
    Keel,
}

impl Addressing {
    /// The `HULL_CI_TREE_ID` spelling, for messages.
    pub fn name(self) -> &'static str {
        match self {
            Addressing::Opaque => "opaque",
            Addressing::Keel => "keel",
        }
    }
}

// ── One entry in a synthetic tree ────────────────────────────────────────────────────────────────

/// One entry in a synthetic tree: a regular file, or a symlink.
///
/// Only the shapes keel can address are representable — keel records exactly two file modes
/// (`MODE_FILE` 0o644, `MODE_EXEC` 0o755), directories (implied by a path with a `/` in it), and
/// symlinks. There is deliberately no way to build a fixture with a device node or a setuid bit: a
/// conforming producer cannot emit one, so a fixture carrying one would be testing the extractor's
/// rejection path from the wrong side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeFile {
    /// Slash-separated path relative to the tree root. Parent directories are implied.
    pub path: String,
    /// Permission bits as the tar header carries them: 0o644 or 0o755. Ignored for a symlink (tar
    /// records 0o755 for those and keel records only `MODE_SYMLINK`).
    pub mode: u32,
    /// The file's bytes — or, when `symlink` is set, the **target path**, which is precisely the
    /// blob keel addresses for a link (git-style: a symlink's content is its target).
    pub data: Vec<u8>,
    /// Whether this entry is a symlink rather than a regular file.
    pub symlink: bool,
}

impl TreeFile {
    pub fn new(path: &str, data: impl Into<Vec<u8>>) -> Self {
        TreeFile { path: path.to_string(), mode: 0o644, data: data.into(), symlink: false }
    }

    pub fn executable(path: &str, data: impl Into<Vec<u8>>) -> Self {
        TreeFile { path: path.to_string(), mode: 0o755, data: data.into(), symlink: false }
    }

    /// A symlink at `path` pointing at `target` (relative, inside the tree).
    pub fn symlink(path: &str, target: &str) -> Self {
        TreeFile {
            path: path.to_string(),
            mode: 0o755,
            data: target.as_bytes().to_vec(),
            symlink: true,
        }
    }
}

// ── The content address ──────────────────────────────────────────────────────────────────────────

/// The content address the stub Hull advertises for a tree, in the configured [`Addressing`] mode.
pub fn tree_id(files: &[TreeFile]) -> String {
    match config::addressing() {
        Addressing::Opaque => opaque_tree_id(files),
        #[cfg(feature = "keel")]
        Addressing::Keel => keel_tree_id(files),
        // Unreachable: `config::addressing()` refuses to return `Keel` without the feature.
        #[cfg(not(feature = "keel"))]
        Addressing::Keel => unreachable!("config::addressing() gates this"),
    }
}

/// **The harness's stand-in for keel's canonical tree hash** (default mode).
///
/// The CI contract never puts the algorithm on the wire — §5 calls `tree_id` an opaque content
/// address and §6 says a runner **MAY** re-hash to verify — so a black-box suite cannot discover it
/// and no third-party CI can be expected to reproduce it. What the suite *can* assert without
/// knowing the algorithm is the asymmetry the adversarial case turns on: a tree whose bytes are not
/// the bytes that were hashed must not be run
/// (`adversarial::corrupt_archive_must_fail_tree_id_rehash`), and that holds under any sane
/// canonicalisation.
///
/// The canonical form is written out here so that any language can reproduce it — the reference CI
/// under `tests/reference/` does, in stdlib Python:
///
/// ```text
/// SHA-256( "hull-ci-conformance/tree/v1\n"
///          ++ for each entry, sorted by path:
///                regular file: "file <mode, 6 octal digits> <byte length> <path>\n" ++ <file bytes>
///                symlink:      "link 120000 <target length> <path>\n" ++ <target path bytes>  )
/// ```
///
/// This is *not* keel's address, and it is not meant to be: [`keel_tree_id`] is, and it is one env
/// var away.
pub fn opaque_tree_id(files: &[TreeFile]) -> String {
    let mut sorted: Vec<&TreeFile> = files.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));

    let mut hasher = Sha256::new();
    hasher.update(b"hull-ci-conformance/tree/v1\n");
    for f in sorted {
        let mut header = String::new();
        if f.symlink {
            let _ = write!(header, "link 120000 {} {}\n", f.data.len(), f.path);
        } else {
            let _ = write!(header, "file {:06o} {} {}\n", f.mode, f.data.len(), f.path);
        }
        hasher.update(header.as_bytes());
        hasher.update(&f.data);
    }
    hex(hasher.finalize().as_slice())
}

/// **A genuine keel tree address**, computed with keel's own encoder.
///
/// keel names a tree `BLAKE3(Object::encode(Tree))`, where a `Tree` is a `Vec<TreeEntry { name,
/// mode, id }>` sorted by name, a file's `id` is `BLAKE3(0x01 ++ contents)`, a directory's `id` is
/// its own subtree's address, and a symlink is `MODE_SYMLINK` over a blob holding the *target path*.
/// None of that is restated here: this function builds keel's own `Object` values and asks
/// `keel-store` for the address, so there is one definition of the encoding in the system and the
/// suite cannot drift from it in silence. (`hull-ci-fetch::verify` takes the same position for the
/// same reason, and pins the same keel git rev.)
///
/// A hand-rolled reimplementation would be worthless here even if it were correct today: a
/// conformance suite that agrees only with itself proves nothing about the runner it is judging.
#[cfg(feature = "keel")]
pub fn keel_tree_id(files: &[TreeFile]) -> String {
    keel_tree(files).id().to_hex()
}

/// The keel `Tree` object for `files`, recursing on path prefixes.
#[cfg(feature = "keel")]
fn keel_tree(files: &[TreeFile]) -> keel_store::object::Object {
    use keel_store::object::{Object, Tree, TreeEntry};
    use keel_store::snapshot::{MODE_DIR, MODE_EXEC, MODE_FILE, MODE_SYMLINK};
    use std::collections::BTreeMap;

    let mut entries: Vec<TreeEntry> = Vec::new();
    // BTreeMap only to keep the recursion deterministic in a debugger; `Object::encode` sorts.
    let mut subdirs: BTreeMap<String, Vec<TreeFile>> = BTreeMap::new();

    for f in files {
        match f.path.split_once('/') {
            Some((head, rest)) => {
                let mut child = f.clone();
                child.path = rest.to_string();
                subdirs.entry(head.to_string()).or_default().push(child);
            }
            None => {
                let mode = if f.symlink {
                    MODE_SYMLINK
                } else if f.mode & 0o111 != 0 {
                    MODE_EXEC
                } else {
                    MODE_FILE
                };
                // For a symlink `data` is the target path — which is exactly the blob keel hashes.
                let id = Object::Blob(f.data.clone()).id();
                entries.push(TreeEntry { name: f.path.clone(), mode, id });
            }
        }
    }
    for (name, kids) in subdirs {
        entries.push(TreeEntry { name, mode: MODE_DIR, id: keel_tree(&kids).id() });
    }
    Object::Tree(Tree { entries })
}

/// A change id derived from the tree, so fixtures read like real dispatches instead of `"abc"`.
pub fn change_id(tree_id: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"change");
    hasher.update(tree_id.as_bytes());
    hasher.update(salt.as_bytes());
    hex(hasher.finalize().as_slice())
}

// ── The archive ──────────────────────────────────────────────────────────────────────────────────

const TYPE_REGULAR: u8 = b'0';
const TYPE_SYMLINK: u8 = b'2';
const TYPE_DIRECTORY: u8 = b'5';

/// Serialise a tree as a `tar` archive **laid out the way real Hull lays one out**.
///
/// A correct `tree_id` over a differently-shaped archive still fails verification, so the layout is
/// part of the contract this suite has to reproduce. `hull-server`'s `tree_archive` builds its tar
/// with `tar::Builder`, `HeaderMode::Deterministic`, `follow_symlinks(false)` and
/// `append_dir_all(".", &dir)`, which yields:
///
/// * the archive's own root as a **directory entry named `./`**;
/// * every other entry named by its plain relative path — `tar` strips the `.` component, so
///   entries are `README.md` and `src/main.txt`, not `./README.md`;
/// * an **explicit directory entry for every directory** (`src`), with no trailing slash, before its
///   children;
/// * modes normalised to `0o755` for directories, executables and symlinks, `0o644` otherwise;
/// * **symlinks as symlink entries** (`typeflag 2`, target in the link-name field) rather than as a
///   copy of the target — keel addresses a link as `MODE_SYMLINK` over a blob holding the target
///   path, so a dereferenced link could never re-hash to `tree_id`.
///
/// Entries are emitted in sorted order (`tar::Builder` walks `read_dir`, so its order is arbitrary);
/// header dialect and mtime differ too — this writer emits POSIX `ustar` with mtime 0, `tar-rs`
/// emits GNU with a fixed sentinel mtime. Neither reaches the content address or the extractor.
/// `tests/keel_addressing.rs` pins the parts that do, by diffing this archive against one
/// `tar::Builder` actually produced.
pub fn tar(files: &[TreeFile]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut sorted: Vec<&TreeFile> = files.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));

    // The archive's own root, exactly as `append_dir_all(".", dir)` writes it.
    out.extend_from_slice(&header("./", 0o755, 0, TYPE_DIRECTORY, ""));

    let mut dirs: BTreeSet<String> = BTreeSet::new();
    for f in sorted {
        // Sorted paths put a directory's entry before everything under it.
        let components: Vec<&str> = f.path.split('/').collect();
        for i in 0..components.len().saturating_sub(1) {
            let dir = components[..=i].join("/");
            if dirs.insert(dir.clone()) {
                out.extend_from_slice(&header(&dir, 0o755, 0, TYPE_DIRECTORY, ""));
            }
        }

        if f.symlink {
            let target = String::from_utf8(f.data.clone()).expect("symlink targets are UTF-8 paths");
            out.extend_from_slice(&header(&f.path, 0o755, 0, TYPE_SYMLINK, &target));
        } else {
            out.extend_from_slice(&header(&f.path, f.mode, f.data.len(), TYPE_REGULAR, ""));
            out.extend_from_slice(&f.data);
            let pad = (512 - f.data.len() % 512) % 512;
            out.extend(std::iter::repeat(0u8).take(pad));
        }
    }
    // Two zero blocks terminate the archive.
    out.extend(std::iter::repeat(0u8).take(1024));
    out
}

/// One 512-byte POSIX `ustar` header.
fn header(name: &str, mode: u32, size: usize, typeflag: u8, link: &str) -> [u8; 512] {
    assert!(name.len() < 100, "fixture paths stay inside the ustar name field: {name}");
    assert!(link.len() < 100, "fixture symlink targets stay inside the link field: {link}");

    let mut header = [0u8; 512];
    put(&mut header[0..100], name.as_bytes());
    put(&mut header[100..108], format!("{mode:07o}\0").as_bytes());
    put(&mut header[108..116], b"0000000\0"); // uid
    put(&mut header[116..124], b"0000000\0"); // gid
    put(&mut header[124..136], format!("{size:011o}\0").as_bytes());
    put(&mut header[136..148], b"00000000000\0"); // mtime 0 — fixtures must be byte-identical run to run
    put(&mut header[148..156], b"        "); // checksum placeholder: spaces
    header[156] = typeflag;
    put(&mut header[157..257], link.as_bytes());
    put(&mut header[257..263], b"ustar\0");
    put(&mut header[263..265], b"00");
    // uname/gname left empty, as `HeaderMode::Deterministic` leaves them.

    let sum: u32 = header.iter().map(|b| *b as u32).sum();
    put(&mut header[148..156], format!("{sum:06o}\0 ").as_bytes());
    header
}

fn put(dst: &mut [u8], src: &[u8]) {
    let n = src.len().min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
}

/// Write a fixture tree to a real directory — the same tree the [`tar`] archive carries.
///
/// Only used by the tree-addressing cross-check, which needs a tree on disk to hand to a directory
/// walker (keel's, and `tar::Builder`'s). `dir` must already exist.
#[cfg(unix)]
pub fn materialize(files: &[TreeFile], dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut sorted: Vec<&TreeFile> = files.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    for f in sorted {
        let path = dir.join(&f.path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if f.symlink {
            let target = String::from_utf8(f.data.clone()).expect("symlink targets are UTF-8 paths");
            std::os::unix::fs::symlink(target, &path)?;
        } else {
            std::fs::write(&path, &f.data)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(f.mode))?;
        }
    }
    Ok(())
}

/// A value no other call to [`benign_project`] will produce, so each fixture has its own address.
fn next_nonce() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    format!("{:08x}{:04x}{:04x}", nanos, std::process::id() & 0xffff, n & 0xffff)
}

// ── Fixtures ─────────────────────────────────────────────────────────────────────────────────────

/// A benign little project. Deliberately carries several test entry points, because a runner that
/// autodetects (design D§6) will pick one of them, and the suite must not care which.
///
/// **Every call returns a tree with a different content address**, and that is load-bearing rather
/// than incidental.
///
/// `StubHull::job_raw` already gives each job its own `repo` so that jobs do not collide, and its
/// comment explains why. That is necessary but not sufficient against a runner whose content store
/// is scoped to the **tenant** rather than to the repo — which is the design hull-ci ships (D§4.2,
/// D§6.3: caches are shared *within* a tenant, deliberately, so repos under one org can reuse a
/// warmed tree). Every job in this suite runs under tenant `tankrap`, so a fixture with a fixed
/// content address is fetched exactly once per store, ever, and every later job is served from
/// cache.
///
/// That makes the fetch-shaped assertions quietly conditional on the store being cold:
/// `spec_11_3_fetches_the_source_url_it_was_given` sees no request, `spec_11_5` cannot make a fetch
/// fail for a tree already held, and `adversarial_corrupt_archive` cannot substitute bytes for an
/// archive nobody downloads. On a fresh store they pass; on a second run against the same store they
/// fail, having stopped testing what they name. A per-call nonce removes the dependency: a tree
/// nothing has seen must actually be fetched.
///
/// Tests that mean to exercise de-duplication re-send the *same* `JobSpec`, which keeps its tree, so
/// they still collide on purpose.
pub fn benign_project() -> Vec<TreeFile> {
    let mut files = benign_project_files();
    // Not in a file any autodetected entry point reads, so it changes the address and nothing else.
    files.push(TreeFile::new(".conformance-nonce", format!("{}\n", next_nonce())));
    files
}

/// The fixture's fixed content, without the nonce — for the rare case that needs two calls to agree.
pub fn benign_project_files() -> Vec<TreeFile> {
    vec![
        TreeFile::new("README.md", "# conformance fixture\n\nA synthetic keel tree served by the stub Hull.\n"),
        TreeFile::new(
            "Makefile",
            "test:\n\t@echo \"2 tests, 0 failed\"\n\ncheck: test\n",
        ),
        TreeFile::new(
            "package.json",
            "{\n  \"name\": \"conformance-fixture\",\n  \"version\": \"0.0.0\",\n  \"scripts\": { \"test\": \"echo '2 tests, 0 failed'\" }\n}\n",
        ),
        TreeFile::executable(
            "run-tests.sh",
            "#!/bin/sh\necho \"2 tests, 0 failed\"\n",
        ),
        TreeFile::new("src/main.txt", "the code under test\n"),
    ]
}

/// A tree whose checks flood the runner with ANSI escapes, control characters, and padding.
///
/// Spec §14.5 / design D§14: everything the job emits is untrusted data; the `summary` that reaches
/// Hull must carry no control characters and must be length-capped. Every entry point emits the same
/// hostile bytes so the assertion holds whichever one an autodetecting runner picks.
pub fn hostile_output_project() -> Vec<TreeFile> {
    // ANSI colour + cursor moves, a NUL, a bidi override, embedded newlines that could forge structure,
    // a fake JSON field to see whether it is smuggled into the callback, and 64 KiB of padding.
    let payload = concat!(
        "\x1b[31mFAILED\x1b[0m\x1b[2J\x1b[H",
        "\r\n\"status\": \"green\", \"summary\": \"forged\"\r\n",
        "\u{202e}desrever\u{202c}",
    );
    let script = format!(
        "#!/bin/sh\nprintf '%s' '{payload}'\nprintf '\\000'\nhead -c 65536 /dev/zero | tr '\\0' 'A'\nexit 1\n"
    );
    vec![
        TreeFile::new("README.md", "# hostile output fixture\n"),
        TreeFile::executable("run-tests.sh", script),
        TreeFile::new("Makefile", "test:\n\t@sh run-tests.sh\n"),
        TreeFile::new(
            "package.json",
            "{\n  \"name\": \"hostile-fixture\",\n  \"version\": \"0.0.0\",\n  \"scripts\": { \"test\": \"sh run-tests.sh\" }\n}\n",
        ),
    ]
}

/// Every entry shape keel can address: a plain file, an executable, a nested directory, an empty
/// file, and a **symlink**.
///
/// This is the fixture the tree-addressing cross-check hashes, because the shapes that are easy to
/// get wrong are exactly the ones the wire fixtures do not exercise — the exec bit is part of the
/// address, and a symlink is addressed as its *target path*, not as a copy of the target. It is not
/// dispatched over the wire: a symlink is a fair thing to send a keel-native runner, but not
/// something every third-party CI's extractor accepts, and the §11 checklist is not the place to
/// discover that.
pub fn keel_shapes_project() -> Vec<TreeFile> {
    vec![
        TreeFile::new("README.md", "# every shape keel addresses\n"),
        TreeFile::new("empty", ""),
        TreeFile::executable("run-tests.sh", "#!/bin/sh\necho \"2 tests, 0 failed\"\n"),
        TreeFile::new("src/main.txt", "the code under test\n"),
        TreeFile::new("src/nested/deep.txt", "two levels down\n"),
        TreeFile::symlink("latest.md", "README.md"),
    ]
}

// ── Self-tests: the harness's own fixtures must be beyond doubt ─────────────────────────────────
//
// If the tar were malformed, every conformance test would fail with a message blaming the CI. These
// run in the same `cargo test` and cost milliseconds.

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};

    /// The archive the stub Hull serves must be readable by an ordinary `tar` — the spec's own
    /// example is `curl -sL "$source_url" | tar -x -C work`.
    #[test]
    fn tar_is_readable_by_the_system_tar() {
        let files = keel_shapes_project();
        let archive = tar(&files);

        let mut child = Command::new("tar")
            .arg("-tf")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("system tar is required to self-check the harness fixtures");
        child.stdin.as_mut().unwrap().write_all(&archive).unwrap();
        let out = child.wait_with_output().unwrap();

        assert!(
            out.status.success(),
            "the harness produced an unreadable tar: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let listed: Vec<String> =
            String::from_utf8_lossy(&out.stdout).lines().map(|l| l.trim_end_matches('/').to_string()).collect();
        for f in &files {
            assert!(listed.contains(&f.path), "{} missing from the archive: {listed:?}", f.path);
        }
        // The layout real Hull produces: an explicit root, and an explicit entry per directory.
        for dir in [".", "src", "src/nested"] {
            assert!(
                listed.contains(&dir.to_string()),
                "`{dir}` has no directory entry — `tar::Builder::append_dir_all` writes one and an \
                 archive that omits them is not the archive Hull serves: {listed:?}"
            );
        }
    }

    /// The system `tar` must also be able to *extract* it, symlink and all — `-tf` only parses
    /// headers, and a wrong link field shows up only on the way out.
    #[test]
    fn tar_extracts_with_the_shapes_intact() {
        let dir = std::env::temp_dir().join(format!("hull-ci-tarcheck-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut child = Command::new("tar")
            .arg("-xf")
            .arg("-")
            .arg("-C")
            .arg(&dir)
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("system tar is required to self-check the harness fixtures");
        child.stdin.as_mut().unwrap().write_all(&tar(&keel_shapes_project())).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "extract failed: {}", String::from_utf8_lossy(&out.stderr));

        assert_eq!(std::fs::read(dir.join("src/nested/deep.txt")).unwrap(), b"two levels down\n");
        let link = std::fs::symlink_metadata(dir.join("latest.md")).unwrap();
        assert!(
            link.file_type().is_symlink(),
            "the archive must carry a symlink as a link, not as a copy of its target — keel \
             addresses it as MODE_SYMLINK over the target path"
        );
        assert_eq!(std::fs::read_link(dir.join("latest.md")).unwrap().to_str(), Some("README.md"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("run-tests.sh")).unwrap().permissions().mode();
            assert_eq!(mode & 0o111, 0o111, "the exec bit is part of the tree's address");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tree_id_is_deterministic_and_content_sensitive() {
        let a = keel_shapes_project();
        assert_eq!(tree_id(&a), tree_id(&a), "the same tree must always name itself the same way");

        let mut b = a.clone();
        b[0].data.push(b'!');
        assert_ne!(
            tree_id(&a),
            tree_id(&b),
            "a one-byte edit must change the content address, or the corrupted-archive case proves \
             nothing"
        );

        // Both modes must be full-length hex: `hull-ci-fetch::verify::normalize_tree_id` refuses
        // anything else outright, and a suite whose ids it cannot parse would fail for the wrong
        // reason.
        for id in [tree_id(&a), opaque_tree_id(&a)] {
            assert_eq!(id.len(), 64, "tree ids are 64 hex characters: {id}");
            assert!(id.bytes().all(|b| b.is_ascii_hexdigit()), "tree ids are hex: {id}");
        }
    }

    /// The exec bit and a symlink's target are both part of the address, in *either* mode. A mode
    /// that flattened them would let a runner accept a tree with `run-tests.sh` newly executable.
    #[test]
    fn mode_and_symlink_target_are_addressed() {
        let base = keel_shapes_project();

        let mut exec = base.clone();
        exec.iter_mut().find(|f| f.path == "README.md").unwrap().mode = 0o755;
        assert_ne!(tree_id(&base), tree_id(&exec), "the exec bit must change the address");

        let mut relinked = base.clone();
        let link = relinked.iter_mut().find(|f| f.symlink).unwrap();
        link.data = b"src/main.txt".to_vec();
        assert_ne!(tree_id(&base), tree_id(&relinked), "a symlink's target must change the address");
    }

    /// keel mode has to produce ids **keel itself** produces, so it is built on keel's own encoder
    /// rather than a second implementation of the format. This pins that we are on the real thing:
    /// the constant is the one keel's own suite pins (`keel-store`'s `golden_blob_id_is_stable`),
    /// and it fails if the dependency is ever swapped for a local re-implementation or if keel's
    /// canonical encoding drifts under the pinned rev.
    #[cfg(feature = "keel")]
    #[test]
    fn keel_mode_is_on_keels_real_encoder() {
        use keel_store::object::Object;
        assert_eq!(
            Object::Blob(b"keel".to_vec()).id().to_hex(),
            "6b229988e49b9188f2ff4d9c4f4a40cc3d2cd03f47709bcef7cd94fae6a22307",
            "blob id changed — this is no longer keel's canonical encoding"
        );

        // A tree whose keel address is checkable by hand: one file, one entry.
        let one = vec![TreeFile::new("keel", "keel")];
        let expected = {
            use keel_store::object::{Tree, TreeEntry};
            use keel_store::snapshot::MODE_FILE;
            Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: "keel".into(),
                    mode: MODE_FILE,
                    id: Object::Blob(b"keel".to_vec()).id(),
                }],
            })
            .id()
            .to_hex()
        };
        assert_eq!(keel_tree_id(&one), expected);
    }

    /// The two modes must be *different* addresses for the same tree — if they ever agreed, one of
    /// them would be a lie.
    #[cfg(feature = "keel")]
    #[test]
    fn the_two_modes_do_not_agree() {
        let files = keel_shapes_project();
        assert_ne!(opaque_tree_id(&files), keel_tree_id(&files));
    }
}
