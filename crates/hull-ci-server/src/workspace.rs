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
//! So the store copy stays read-only and each step gets its own copy to ruin. In M4 this becomes a
//! CoW clone (reflink / overlay upper layer) and the cost goes to roughly zero; the *shape* — a
//! writable workspace derived from an immutable tree — is the same one, which is why it is worth
//! establishing now rather than retrofitting around a shortcut.
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

use std::fs;
use std::io;
use std::path::Path;

/// Copy `tree` to `dest`, which must not already exist.
///
/// Synchronous by nature (it is filesystem work) — callers run it on a blocking worker.
pub fn materialize(tree: &Path, dest: &Path) -> io::Result<()> {
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
    copy_dir(tree, dest)
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
fn copy_dir(from: &Path, to: &Path) -> io::Result<()> {
    let mut pending = vec![(from.to_path_buf(), to.to_path_buf())];

    while let Some((src_dir, dst_dir)) = pending.pop() {
        for entry in fs::read_dir(&src_dir)? {
            let entry = entry?;
            let src = entry.path();
            let dst = dst_dir.join(entry.file_name());
            // `symlink_metadata`, so a symlink is examined rather than resolved.
            let meta = fs::symlink_metadata(&src)?;

            if meta.is_dir() {
                fs::create_dir(&dst)?;
                copy_permissions(&meta, &dst)?;
                pending.push((src, dst));
            } else if meta.is_symlink() {
                copy_symlink(&src, &dst)?;
            } else if meta.is_file() {
                // `fs::copy` carries the mode across, which matters: the executable bit is part of
                // the tree's content address (keel's `MODE_FILE` vs `0o755`), so a workspace whose
                // scripts lost `+x` is not the tree that was verified.
                fs::copy(&src, &dst)?;
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

    #[test]
    fn the_workspace_is_a_copy_the_job_can_ruin() {
        let store = tempfile::tempdir().unwrap();
        fs::write(store.path().join("Makefile"), "test:\n\ttrue\n").unwrap();
        fs::create_dir(store.path().join("src")).unwrap();
        fs::write(store.path().join("src/main.rs"), "fn main() {}\n").unwrap();

        let work = tempfile::tempdir().unwrap();
        let ws = work.path().join("job/step");
        materialize(store.path(), &ws).unwrap();
        assert_eq!(fs::read_to_string(ws.join("src/main.rs")).unwrap(), "fn main() {}\n");

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

    #[cfg(unix)]
    #[test]
    fn the_executable_bit_survives_because_it_is_part_of_the_address() {
        use std::os::unix::fs::PermissionsExt;
        let store = tempfile::tempdir().unwrap();
        let script = store.path().join("run.sh");
        fs::write(&script, "#!/bin/sh\ntrue\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

        let work = tempfile::tempdir().unwrap();
        let ws = work.path().join("ws");
        materialize(store.path(), &ws).unwrap();
        let mode = fs::metadata(ws.join("run.sh")).unwrap().permissions().mode();
        assert_eq!(mode & 0o111, 0o111, "keel addresses the exec bit; the workspace must keep it");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_copied_as_a_link_never_followed() {
        let store = tempfile::tempdir().unwrap();
        fs::write(store.path().join("real.txt"), "payload\n").unwrap();
        std::os::unix::fs::symlink("real.txt", store.path().join("link.txt")).unwrap();

        let work = tempfile::tempdir().unwrap();
        let ws = work.path().join("ws");
        materialize(store.path(), &ws).unwrap();

        let meta = fs::symlink_metadata(ws.join("link.txt")).unwrap();
        assert!(meta.is_symlink(), "following it would let the tree name host content");
        assert_eq!(fs::read_link(ws.join("link.txt")).unwrap(), std::path::PathBuf::from("real.txt"));
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
}
