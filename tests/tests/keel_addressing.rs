//! **Does keel mode name a tree the way keel does?**
//!
//! Every other test in this suite is black-box: it knows a URL and a secret, imports nothing from
//! `hull-ci`, and would pass or fail identically against any CI. This file is the deliberate
//! exception, and it judges the *harness*, not an endpoint.
//!
//! The reason it has to exist: in `HULL_CI_TREE_ID=keel` the suite advertises a `tree_id` and then
//! asks a runner to accept the archive it serves under that address. Our runner re-hashes with
//! keel's real encoding and refuses a mismatch (`hull-ci-fetch::verify`, design D§4.2). So if the
//! harness's idea of a keel address, or of an archive's layout, were off by even a bit, **every
//! happy-path test would fail against our own service** — and the suite would be reporting the
//! service broken over a disagreement that was the suite's. That failure is silent in a black-box
//! test (a mismatch looks like `errored`, which is also what a genuinely broken runner does), so it
//! is pinned here instead:
//!
//! 1. the archive the stub Hull serves survives the broker's real, hardened extractor;
//! 2. what comes out re-hashes to the `tree_id` the suite advertised, per the broker's real
//!    verifier, and per **keel's own directory walker** — two independent readings;
//! 3. the archive is laid out the way `hull-server`'s `tree_archive` lays one out, checked against
//!    an archive `tar::Builder` actually produced, not against a description of one;
//! 4. and the check bites: a tampered tree fails.
//!
//! Requires `--features crosscheck`; without it this binary is empty. It talks to nothing and needs
//! no endpoint, no network and no Hull.

#![cfg(feature = "crosscheck")]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use hull_ci_conformance::tree::{self, TreeFile};
use hull_ci_fetch::extract::extract_into;
use hull_ci_fetch::verify::{KeelTreeVerifier, TreeVerifier, VerifyError};
use hull_ci_fetch::Limits;
use tempfile::TempDir;

/// Extract the suite's own archive with the broker's own extractor.
fn extract_suite_archive(files: &[TreeFile]) -> TempDir {
    let dest = TempDir::new().expect("temp dir");
    let archive = tree::tar(files);
    extract_into(&archive[..], dest.path(), &Limits::default()).unwrap_or_else(|e| {
        panic!(
            "the fetch broker's extractor refused the harness's own archive: {e}. A conforming \
             producer never emits a shape it rejects, so this is the harness's bug, not the \
             extractor's."
        )
    });
    dest
}

/// keel's own directory walker, as a second opinion on the address.
///
/// [`KeelTreeVerifier`] and this both live in the same pinned `keel-store`, but they are different
/// code: the verifier is `hull-ci-fetch`'s own walk over an extracted directory, while
/// `snapshot_uncached` is the walker keel uses when it commits a work tree — the one that decided
/// what `tree_id` means in the first place. Agreement between them, the suite, and Hull is the whole
/// property this file exists to pin.
fn keels_own_tree_id(root: &Path) -> String {
    let store_dir = TempDir::new().expect("temp dir");
    let store = keel_store::store::Store::open(store_dir.path()).expect("open a keel store");
    keel_store::snapshot::snapshot_uncached(&store, root)
        .expect("keel could not snapshot the extracted tree")
        .to_hex()
}

// ── 1 + 2: the id the suite advertises is the id a verifying runner computes ─────────────────────

#[test]
fn keel_mode_ids_are_what_our_fetch_broker_computes() {
    let files = tree::keel_shapes_project();
    let advertised = tree::keel_tree_id(&files);
    let dest = extract_suite_archive(&files);

    let verifier = KeelTreeVerifier::default();
    verifier.verify(dest.path(), &advertised).unwrap_or_else(|e| {
        panic!(
            "hull-ci-fetch's verifier rejected the tree the harness served under its own \
             advertised tree_id: {e}\n\
             In HULL_CI_TREE_ID=keel this is fatal to the whole suite — every happy-path test would \
             report our runner broken for refusing an archive that really is mis-addressed."
        )
    });
}

#[test]
fn keel_mode_ids_are_what_keels_own_walker_computes() {
    let files = tree::keel_shapes_project();
    let dest = extract_suite_archive(&files);
    assert_eq!(
        keels_own_tree_id(dest.path()),
        tree::keel_tree_id(&files),
        "keel's own snapshot walker names this tree differently from the harness — the harness is \
         wrong by definition, because keel's walker is what `tree_id` means",
    );
}

/// Every shape separately, so a failure names the shape that broke rather than "the fixture".
#[test]
fn each_entry_shape_keel_addresses_round_trips() {
    let cases: Vec<(&str, Vec<TreeFile>)> = vec![
        ("an empty tree", vec![]),
        ("one plain file", vec![TreeFile::new("a.txt", "hello\n")]),
        ("an empty file", vec![TreeFile::new("empty", "")]),
        ("an executable", vec![TreeFile::executable("run.sh", "#!/bin/sh\n")]),
        ("a nested directory", vec![TreeFile::new("a/b/c.txt", "deep\n")]),
        ("a symlink", vec![TreeFile::new("t", "x"), TreeFile::symlink("l", "t")]),
        ("a symlink into a subdirectory", vec![TreeFile::new("d/t", "x"), TreeFile::symlink("l", "d/t")]),
        ("a file whose bytes are not UTF-8", vec![TreeFile::new("bin", vec![0u8, 0xff, 0x80])]),
        ("a 300 KiB file", vec![TreeFile::new("big", vec![b'x'; 300 * 1024])]),
    ];

    for (what, files) in cases {
        let advertised = tree::keel_tree_id(&files);
        let dest = extract_suite_archive(&files);
        assert_eq!(
            KeelTreeVerifier::default().tree_id(dest.path()).unwrap(),
            advertised,
            "{what}: the harness and the broker disagree about this tree's keel address",
        );
        assert_eq!(keels_own_tree_id(dest.path()), advertised, "{what}: keel's own walker disagrees");
    }
}

// ── 3: the archive is laid out the way real Hull lays one out ────────────────────────────────────

/// What one archive entry looks like once the header dialect is set aside.
#[derive(Debug, PartialEq, Eq)]
struct Entry {
    kind: tar::EntryType,
    mode: u32,
    size: u64,
    link: Option<String>,
}

fn entries(archive: &[u8]) -> BTreeMap<String, Entry> {
    let mut out = BTreeMap::new();
    let mut ar = tar::Archive::new(archive);
    for e in ar.entries().expect("readable tar") {
        let e = e.expect("readable entry");
        let name = String::from_utf8_lossy(&e.path_bytes()).into_owned();
        let h = e.header();
        out.insert(
            name,
            Entry {
                kind: h.entry_type(),
                mode: h.mode().unwrap(),
                size: h.size().unwrap(),
                link: e.link_name().unwrap().map(|p| p.to_string_lossy().into_owned()),
            },
        );
    }
    out
}

/// The archive `hull-server`'s `tree_archive` would produce for the same tree.
///
/// Reproduced with the same four calls it makes (`HeaderMode::Deterministic`,
/// `follow_symlinks(false)`, `append_dir_all(".", &dir)`) over a materialised copy of the fixture —
/// so this compares the harness against `tar::Builder`'s actual behaviour rather than against a
/// paraphrase of it in a comment.
fn hull_shaped_archive(files: &[TreeFile]) -> Vec<u8> {
    let dir = TempDir::new().expect("temp dir");
    tree::materialize(files, dir.path()).expect("materialize the fixture");
    let mut buf = Vec::new();
    {
        let mut ar = tar::Builder::new(&mut buf);
        ar.mode(tar::HeaderMode::Deterministic);
        ar.follow_symlinks(false);
        ar.append_dir_all(".", dir.path()).expect("append");
        ar.finish().expect("finish");
    }
    buf
}

#[test]
fn the_archive_matches_the_one_hull_serves() {
    let files = tree::keel_shapes_project();
    let ours = entries(&tree::tar(&files));
    let hulls = entries(&hull_shaped_archive(&files));

    assert_eq!(
        ours.keys().collect::<Vec<_>>(),
        hulls.keys().collect::<Vec<_>>(),
        "the harness's archive does not contain the same entries Hull's does. Entry naming and the \
         explicit directory entries are part of the layout: a correct tree_id over a differently \
         shaped archive still fails verification.",
    );
    for (name, expected) in &hulls {
        assert_eq!(
            ours.get(name),
            Some(expected),
            "entry `{name}` differs from the one `tar::Builder` produces (type/mode/size/link \
             target). Modes and symlink targets are part of the tree's content address.",
        );
    }
    // Not compared, and deliberately: entry order (`tar::Builder` walks `read_dir`, so its order is
    // arbitrary — ours is sorted), the header dialect (GNU vs POSIX ustar) and mtime. None of them
    // reach the extractor or the content address; the fields above all do.
}

#[test]
fn hulls_own_archive_verifies_against_the_suites_tree_id() {
    // The other direction of the same claim: extract the archive built by `tar::Builder` itself and
    // check it against the id the harness advertises. If the two archives ever diverge in a way the
    // entry comparison misses, this still catches it.
    let files = tree::keel_shapes_project();
    let dest = TempDir::new().expect("temp dir");
    let archive = hull_shaped_archive(&files);
    extract_into(&archive[..], dest.path(), &Limits::default()).expect("extract Hull's own archive");
    assert_eq!(
        KeelTreeVerifier::default().tree_id(dest.path()).unwrap(),
        tree::keel_tree_id(&files),
    );
}

// ── 4: and the check bites ───────────────────────────────────────────────────────────────────────

#[test]
fn a_tampered_tree_is_refused() {
    // The adversarial case (`adversarial_corrupt_archive_must_fail_the_tree_id_rehash_rather_than_run`)
    // asserts a *runner* refuses a substituted tree. This asserts the same thing one layer down: the
    // suite's own keel ids are tight enough that a one-byte edit fails, so a green run of that test
    // cannot be an artefact of a loose address.
    let files = tree::keel_shapes_project();
    let advertised = tree::keel_tree_id(&files);
    let dest = extract_suite_archive(&files);

    fs::write(dest.path().join("README.md"), b"# substituted\n").expect("tamper");
    assert!(matches!(
        KeelTreeVerifier::default().verify(dest.path(), &advertised),
        Err(VerifyError::Mismatch { .. })
    ));
}
