//! The paranoid tar reader.
//!
//! This module is the highest-value hardening in the whole runner, for one reason: it is the only
//! place where **attacker-controlled bytes are parsed outside a sandbox**. Everything downstream
//! runs in a single-use microVM (spec §14.1); the broker does not, because it must hold the network
//! identity that fetches `source_url` (spec §14.2). So the tar parse is the one step where a bug is
//! straight-line remote code execution on a host that jobs are supposed to never touch.
//!
//! **The policy is reject, never sanitize.** A sanitizing extractor ("strip the leading `/`", "drop
//! the `..`") silently turns a hostile archive into a different, plausible-looking tree — and the
//! tree we extract is the tree we then hash and hand to the nodes. Rewriting a path would either
//! fail verification (a confusing error, far from its cause) or, worse, produce a tree that is not
//! what `tree_id` names. Refusing is both safer and honest: a conforming producer never emits any of
//! the shapes below, so a rejection means the archive is broken or hostile, and either way there is
//! no verdict to give.
//!
//! Structural properties that make an escape impossible rather than merely checked-for:
//!
//! * The destination must be **empty** when we start, and we track every path we create. So the
//!   in-memory bookkeeping is authoritative — there is no "does this already exist?" question whose
//!   answer an attacker can change between the check and the write (no TOCTOU window).
//! * Every file is opened `create_new` and every directory with `create_dir` (never `create_dir_all`,
//!   which follows symlinks). A write can therefore never land on an existing inode, so it can never
//!   be redirected through one.
//! * No entry may sit under a path we materialized as a symlink, which closes the classic two-entry
//!   attack (`ln -s /etc x` followed by `x/passwd`) even for links whose own target is in-bounds.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use tar::EntryType;
use unicode_normalization::UnicodeNormalization;

use crate::Limits;

/// Why one entry was refused. Each variant names the attack it stops, not just the rule it broke.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Rejection {
    /// `/etc/cron.d/x` — an absolute path escapes the destination by construction.
    #[error("absolute path")]
    AbsolutePath,
    /// `../../.ssh/authorized_keys` — the oldest tar escape there is.
    #[error("`..` traversal")]
    ParentTraversal,
    /// A component that is not valid UTF-8. keel names are Rust `String`s, so such an entry could
    /// never be part of a real keel tree and could never be re-hashed to `tree_id`.
    #[error("path is not valid UTF-8")]
    NonUtf8Path,
    /// NUL or a control byte in a name: truncates in C consumers and can hide the real name in logs.
    #[error("illegal byte in name")]
    IllegalByte,
    /// A backslash in a component. keel's own checkout refuses these (`is_safe_entry_name`), so
    /// accepting one here would produce a tree keel itself will not materialize.
    #[error("backslash in name")]
    BackslashInName,
    #[error("component longer than {limit} bytes")]
    NameTooLong { limit: usize },
    /// Deep nesting is a stack-exhaustion vector for every recursive consumer of the tree, ours
    /// included (keel caps at 256 for exactly this reason).
    #[error("path deeper than {limit} components")]
    TooDeep { limit: usize },
    /// The same path twice. Which one "wins" is a parser detail; a producer that emits both is
    /// trying to make our view of the tree differ from someone else's.
    #[error("duplicate entry")]
    Duplicate,
    /// Two different byte sequences that name the same file on a normalizing filesystem (APFS,
    /// HFS+). On such a host one entry silently overwrites the other, so the extracted tree depends
    /// on the operating system — and a review of one file could be attached to the content of
    /// another.
    #[error("path collides with `{with}` under unicode normalization")]
    UnicodeCollision { with: String },
    /// setuid/setgid/sticky. The tree is later mounted into a sandbox; a setuid bit surviving into
    /// it is a local privilege-escalation primitive handed to the job for free.
    #[error("setuid/setgid/sticky bit set (mode {mode:o})")]
    PrivilegedMode { mode: u32 },
    /// Hardlinks alias an inode we did not create and keel has no concept of them, so there is no
    /// honest way to hash one.
    #[error("hardlink")]
    HardLink,
    /// Device nodes, fifos and sockets. A `/dev/mem`-alike inside a job's workspace is a sandbox
    /// escape primitive, and again there is no keel object that means "character device".
    #[error("special file ({kind})")]
    SpecialFile { kind: &'static str },
    /// An absolute symlink target (`x -> /etc/shadow`) reads as an escape the moment anything in the
    /// sandbox follows it.
    #[error("absolute symlink target")]
    AbsoluteSymlinkTarget,
    /// A relative target with enough `..` to leave the tree.
    #[error("symlink target escapes the tree root")]
    SymlinkEscapesRoot,
    /// The entry's path passes through something we extracted as a symlink; writing it would follow
    /// that link. This is what makes the "plant a link, then write through it" sequence dead.
    #[error("path traverses the symlink `{link}`")]
    SymlinkAncestor { link: String },
    /// The header claims a size above the per-file cap.
    #[error("file exceeds the {limit}-byte per-file cap")]
    FileTooLarge { limit: u64 },
    /// Something already occupies the path — with an empty destination and `create_new` this can
    /// only mean the archive contradicted itself (a file where it earlier put a directory).
    #[error("path conflicts with an earlier entry")]
    Conflict,
}

#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    /// The stream exceeded the archive cap. Enforced on the *stream*, not on a declared length, so a
    /// lying `Content-Length` or a chunked response cannot get past it.
    #[error("archive exceeds the {limit}-byte cap")]
    ArchiveTooLarge { limit: u64 },
    #[error("archive has more than {limit} entries")]
    TooManyEntries { limit: usize },
    #[error("extracted content exceeds the {limit}-byte cap")]
    ContentTooLarge { limit: u64 },
    /// One entry was refused. The path is included verbatim but is untrusted text — sanitize before
    /// putting it anywhere but a log line.
    #[error("rejected entry `{path}`: {reason}")]
    Rejected { path: String, reason: Rejection },
    #[error("malformed tar archive: {0}")]
    Malformed(String),
    #[error("destination is not an empty directory")]
    DestinationNotEmpty,
    #[error("i/o error during extraction: {0}")]
    Io(String),
}

impl ExtractError {
    fn rejected(path: &str, reason: Rejection) -> Self {
        ExtractError::Rejected { path: path.to_string(), reason }
    }
}

/// What an archive extracted to. Counts only, never content — the caller learns the shape of the
/// tree without us handing it attacker-controlled bytes it did not ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Extracted {
    pub files: usize,
    pub dirs: usize,
    pub symlinks: usize,
    pub bytes: u64,
}

/// Extract `reader` (a tar stream) into `dest`, which MUST already exist and be empty.
///
/// Deliberately synchronous and reader-generic: fetch and extraction are separate so the whole
/// adversarial surface is testable offline, against tars we hand-build in the test module.
pub fn extract_into<R: Read>(reader: R, dest: &Path, limits: &Limits) -> Result<Extracted, ExtractError> {
    let mut listing = fs::read_dir(dest).map_err(|e| ExtractError::Io(e.to_string()))?;
    if listing.next().is_some() {
        return Err(ExtractError::DestinationNotEmpty);
    }

    let capped = Capped { inner: reader, remaining: limits.max_archive_bytes, tripped: false };
    let mut archive = tar::Archive::new(capped);
    let mut st = State {
        dest: dest.to_path_buf(),
        limits,
        claimed: HashMap::new(),
        dirs: HashSet::new(),
        symlinks: HashSet::new(),
        out: Extracted::default(),
    };

    let entries = archive.entries().map_err(|e| ExtractError::Malformed(e.to_string()))?;
    for entry in entries {
        let mut entry = entry.map_err(map_stream_err(limits))?;
        st.entry(&mut entry)?;
    }
    Ok(st.out)
}

/// The archive cap has to be enforced while reading, and `tar` surfaces our sentinel as a plain
/// `io::Error`, so recover the real reason here rather than reporting a confusing parse failure.
/// The cap can trip either between entries (in the header parse) or mid-file, so both read paths
/// funnel through this.
fn map_stream_err(limits: &Limits) -> impl Fn(io::Error) -> ExtractError + '_ {
    move |e: io::Error| stream_err(limits, e)
}

fn stream_err(limits: &Limits, e: io::Error) -> ExtractError {
    if e.kind() == io::ErrorKind::InvalidData && e.to_string() == CAP_SENTINEL {
        ExtractError::ArchiveTooLarge { limit: limits.max_archive_bytes }
    } else {
        ExtractError::Malformed(e.to_string())
    }
}

const CAP_SENTINEL: &str = "hull-ci-fetch: archive byte cap exceeded";

/// A reader that dies at a byte budget. The cap is on bytes *actually read*, which is the only
/// number an attacker cannot lie about.
struct Capped<R> {
    inner: R,
    remaining: u64,
    tripped: bool,
}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.tripped {
            return Err(io::Error::new(io::ErrorKind::InvalidData, CAP_SENTINEL));
        }
        let want = buf.len().min(self.remaining.saturating_add(1).min(usize::MAX as u64) as usize);
        let n = self.inner.read(&mut buf[..want])?;
        let n64 = n as u64;
        if n64 > self.remaining {
            self.tripped = true;
            return Err(io::Error::new(io::ErrorKind::InvalidData, CAP_SENTINEL));
        }
        self.remaining -= n64;
        Ok(n)
    }
}

struct State<'a> {
    dest: PathBuf,
    limits: &'a Limits,
    /// NFC-normalized path → the raw path that claimed it. Both duplicate and normalization-collision
    /// detection fall out of one map.
    claimed: HashMap<String, String>,
    /// Directories we created, implicitly or explicitly. Authoritative because `dest` started empty.
    dirs: HashSet<PathBuf>,
    /// Paths we materialized as symlinks; nothing may be written beneath them.
    symlinks: HashSet<PathBuf>,
    out: Extracted,
}

impl State<'_> {
    fn entry<R: Read>(&mut self, entry: &mut tar::Entry<'_, R>) -> Result<(), ExtractError> {
        let kind = entry.header().entry_type();
        // pax global headers carry no file; `tar` folds long-name/pax extensions in for us.
        if kind == EntryType::XGlobalHeader {
            return Ok(());
        }

        // Display form of the raw path, for errors only. Never trusted, never used to build a path.
        let display = String::from_utf8_lossy(&entry.path_bytes()).into_owned();

        if self.out.files + self.out.dirs + self.out.symlinks >= self.limits.max_entries {
            return Err(ExtractError::TooManyEntries { limit: self.limits.max_entries });
        }

        let mode = entry.header().mode().unwrap_or(0o644);
        if mode & 0o7000 != 0 {
            return Err(ExtractError::rejected(&display, Rejection::PrivilegedMode { mode }));
        }

        let path = entry.path().map_err(|_| ExtractError::rejected(&display, Rejection::NonUtf8Path))?;
        let rel = match self.check_path(&path).map_err(|r| ExtractError::rejected(&display, r))? {
            // The empty path is the archive's own root (`tar -C dir .` emits `./`). Nothing to do.
            None => return Ok(()),
            Some(rel) => rel,
        };
        self.check_symlink_ancestors(&rel).map_err(|r| ExtractError::rejected(&display, r))?;

        match kind {
            EntryType::Directory => {
                self.claim(&rel, &display)?;
                self.make_dirs(&rel).map_err(|r| ExtractError::rejected(&display, r))?;
                self.out.dirs += 1;
            }
            EntryType::Regular | EntryType::Continuous => {
                self.claim(&rel, &display)?;
                self.write_file(entry, &rel, mode, &display)?;
                self.out.files += 1;
            }
            EntryType::Symlink => {
                self.claim(&rel, &display)?;
                let target = entry
                    .link_name()
                    .map_err(|_| ExtractError::rejected(&display, Rejection::NonUtf8Path))?
                    .ok_or_else(|| ExtractError::Malformed("symlink entry without a target".into()))?
                    .into_owned();
                self.write_symlink(&rel, &target, &display)?;
                self.out.symlinks += 1;
            }
            EntryType::Link => return Err(ExtractError::rejected(&display, Rejection::HardLink)),
            EntryType::Char => {
                return Err(ExtractError::rejected(&display, Rejection::SpecialFile { kind: "character device" }))
            }
            EntryType::Block => {
                return Err(ExtractError::rejected(&display, Rejection::SpecialFile { kind: "block device" }))
            }
            EntryType::Fifo => return Err(ExtractError::rejected(&display, Rejection::SpecialFile { kind: "fifo" })),
            _ => return Err(ExtractError::rejected(&display, Rejection::SpecialFile { kind: "unsupported type" })),
        }
        Ok(())
    }

    /// Validate a path component-wise. Returns the relative path to use, or `None` for the archive
    /// root. Nothing here rewrites: the only component we drop is `.`, which names the very
    /// directory it appears in and so cannot change where a write lands.
    fn check_path(&self, p: &Path) -> Result<Option<PathBuf>, Rejection> {
        let mut out = PathBuf::new();
        let mut depth = 0usize;
        for c in p.components() {
            match c {
                Component::CurDir => continue,
                Component::ParentDir => return Err(Rejection::ParentTraversal),
                Component::RootDir | Component::Prefix(_) => return Err(Rejection::AbsolutePath),
                Component::Normal(os) => {
                    let name = os.to_str().ok_or(Rejection::NonUtf8Path)?;
                    if name.len() > self.limits.max_name_bytes {
                        return Err(Rejection::NameTooLong { limit: self.limits.max_name_bytes });
                    }
                    if name.contains('\\') {
                        return Err(Rejection::BackslashInName);
                    }
                    if name.chars().any(|ch| ch.is_control()) {
                        return Err(Rejection::IllegalByte);
                    }
                    depth += 1;
                    if depth > self.limits.max_path_depth {
                        return Err(Rejection::TooDeep { limit: self.limits.max_path_depth });
                    }
                    out.push(name);
                }
            }
        }
        Ok(if depth == 0 { None } else { Some(out) })
    }

    /// One map answers both "did we already see this path?" and "does it collide with another under
    /// NFC?". The second question is the one people forget, and it is the one that makes an
    /// extraction's result depend on which filesystem it ran on.
    fn claim(&mut self, rel: &Path, display: &str) -> Result<(), ExtractError> {
        let key: String = rel.to_string_lossy().nfc().collect();
        match self.claimed.insert(key, display.to_string()) {
            None => Ok(()),
            Some(prev) if prev == display => Err(ExtractError::rejected(display, Rejection::Duplicate)),
            Some(prev) => Err(ExtractError::rejected(display, Rejection::UnicodeCollision { with: prev })),
        }
    }

    fn check_symlink_ancestors(&self, rel: &Path) -> Result<(), Rejection> {
        let mut prefix = PathBuf::new();
        for c in rel.components() {
            prefix.push(c);
            if self.symlinks.contains(&prefix) {
                return Err(Rejection::SymlinkAncestor { link: prefix.to_string_lossy().into_owned() });
            }
        }
        Ok(())
    }

    /// Create `rel` and any missing ancestors, one component at a time with `create_dir`.
    ///
    /// Never `create_dir_all`: that helper follows a symlink at an intermediate component, which is
    /// exactly the escape we are here to prevent.
    fn make_dirs(&mut self, rel: &Path) -> Result<(), Rejection> {
        let mut prefix = PathBuf::new();
        for c in rel.components() {
            prefix.push(c);
            if self.dirs.contains(&prefix) {
                continue;
            }
            match fs::create_dir(self.dest.join(&prefix)) {
                Ok(()) => {
                    self.dirs.insert(prefix.clone());
                }
                // `dest` began empty and we track everything we made, so anything already here is a
                // contradiction inside the archive (a file, then a directory of the same name).
                Err(_) => return Err(Rejection::Conflict),
            }
        }
        Ok(())
    }

    fn write_file<R: Read>(
        &mut self,
        entry: &mut tar::Entry<'_, R>,
        rel: &Path,
        mode: u32,
        display: &str,
    ) -> Result<(), ExtractError> {
        let declared = entry.header().size().unwrap_or(0);
        if declared > self.limits.max_file_bytes {
            return Err(ExtractError::rejected(display, Rejection::FileTooLarge { limit: self.limits.max_file_bytes }));
        }
        if let Some(parent) = rel.parent().filter(|p| !p.as_os_str().is_empty()) {
            self.make_dirs(parent).map_err(|r| ExtractError::rejected(display, r))?;
        }

        let abs = self.dest.join(rel);
        // `create_new` is the load-bearing flag: it fails rather than following or truncating
        // anything already at the path, so a write can never be redirected.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&abs)
            .map_err(|_| ExtractError::rejected(display, Rejection::Conflict))?;

        // Copy with a hard stop rather than trusting the declared size — the header is attacker
        // input and a stream that keeps producing bytes must not keep filling our disk.
        let room = self.limits.max_file_bytes.min(self.limits.max_total_bytes - self.out.bytes);
        let mut limited = entry.take(room + 1);
        let written = io::copy(&mut limited, &mut file).map_err(|e| stream_err(self.limits, e))?;
        if written > self.limits.max_file_bytes {
            return Err(ExtractError::rejected(display, Rejection::FileTooLarge { limit: self.limits.max_file_bytes }));
        }
        if written > room {
            return Err(ExtractError::ContentTooLarge { limit: self.limits.max_total_bytes });
        }
        self.out.bytes += written;

        // Modes are normalized to 0644/0755, never copied. keel records exactly two file modes
        // (`MODE_FILE`/`MODE_EXEC`), so anything else could not round-trip to `tree_id` anyway — and
        // normalizing means no odd permission bit rides the archive into a sandbox.
        set_mode(&abs, mode).map_err(|e| ExtractError::Io(e.to_string()))?;
        Ok(())
    }

    fn write_symlink(&mut self, rel: &Path, target: &Path, display: &str) -> Result<(), ExtractError> {
        if target.is_absolute() {
            return Err(ExtractError::rejected(display, Rejection::AbsoluteSymlinkTarget));
        }
        // Resolve lexically against the link's own directory. A link is in-bounds only if it can
        // never leave the tree, and `..` popping past the root is precisely leaving it.
        let mut stack: Vec<&std::ffi::OsStr> = rel
            .parent()
            .map(|p| p.components().filter(|c| matches!(c, Component::Normal(_))).map(|c| c.as_os_str()).collect())
            .unwrap_or_default();
        for c in target.components() {
            match c {
                Component::CurDir => {}
                Component::ParentDir => {
                    if stack.pop().is_none() {
                        return Err(ExtractError::rejected(display, Rejection::SymlinkEscapesRoot));
                    }
                }
                Component::Normal(n) => stack.push(n),
                Component::RootDir | Component::Prefix(_) => {
                    return Err(ExtractError::rejected(display, Rejection::AbsoluteSymlinkTarget))
                }
            }
        }

        if let Some(parent) = rel.parent().filter(|p| !p.as_os_str().is_empty()) {
            self.make_dirs(parent).map_err(|r| ExtractError::rejected(display, r))?;
        }
        symlink(target, &self.dest.join(rel)).map_err(|_| ExtractError::rejected(display, Rejection::Conflict))?;
        self.symlinks.insert(rel.to_path_buf());
        Ok(())
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let normalized = if mode & 0o111 != 0 { 0o755 } else { 0o644 };
    fs::set_permissions(path, fs::Permissions::from_mode(normalized))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(not(unix))]
fn symlink(_target: &Path, _link: &Path) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "symlinks unsupported on this platform"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{tar_bytes, TarEntry};
    use tempfile::TempDir;

    fn extract(entries: Vec<TarEntry>) -> Result<(TempDir, Extracted), ExtractError> {
        extract_with(entries, Limits::default())
    }

    fn extract_with(entries: Vec<TarEntry>, limits: Limits) -> Result<(TempDir, Extracted), ExtractError> {
        let dir = TempDir::new().unwrap();
        let bytes = tar_bytes(&entries);
        let out = extract_into(&bytes[..], dir.path(), &limits)?;
        Ok((dir, out))
    }

    fn rejection(entries: Vec<TarEntry>) -> Rejection {
        match extract(entries) {
            Err(ExtractError::Rejected { reason, .. }) => reason,
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    #[test]
    fn extracts_a_normal_tree() {
        let (dir, out) = extract(vec![
            TarEntry::dir("./"),
            TarEntry::file("./README.md", b"hello\n"),
            TarEntry::dir("./src"),
            TarEntry::file("./src/main.rs", b"fn main() {}\n"),
            TarEntry::file("./run.sh", b"#!/bin/sh\n").mode(0o755),
        ])
        .expect("a well-formed archive must extract");

        assert_eq!(out.files, 3);
        assert_eq!(out.dirs, 1, "the `./` root entry is not a directory of the tree");
        assert_eq!(fs::read_to_string(dir.path().join("src/main.rs")).unwrap(), "fn main() {}\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &str| fs::metadata(dir.path().join(p)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode("run.sh"), 0o755, "the exec bit is the one mode bit that survives");
            assert_eq!(mode("README.md"), 0o644);
        }
    }

    #[test]
    fn creates_missing_parent_directories() {
        // Plenty of producers omit directory entries entirely.
        let (dir, out) = extract(vec![TarEntry::file("a/b/c/d.txt", b"x")]).unwrap();
        assert_eq!(out.files, 1);
        assert!(dir.path().join("a/b/c/d.txt").is_file());
    }

    #[test]
    fn rejects_absolute_paths() {
        assert_eq!(rejection(vec![TarEntry::file("/etc/cron.d/pwn", b"x")]), Rejection::AbsolutePath);
    }

    #[test]
    fn rejects_parent_traversal() {
        assert_eq!(rejection(vec![TarEntry::file("../../.ssh/authorized_keys", b"k")]), Rejection::ParentTraversal);
        assert_eq!(rejection(vec![TarEntry::file("src/../../escape", b"k")]), Rejection::ParentTraversal);
    }

    #[test]
    fn rejects_hardlinks_and_device_nodes() {
        assert_eq!(rejection(vec![TarEntry::hardlink("alias", "/etc/passwd")]), Rejection::HardLink);
        assert!(matches!(
            rejection(vec![TarEntry::special("mem", EntryType::Char)]),
            Rejection::SpecialFile { kind: "character device" }
        ));
        assert!(matches!(
            rejection(vec![TarEntry::special("disk", EntryType::Block)]),
            Rejection::SpecialFile { kind: "block device" }
        ));
        assert!(matches!(
            rejection(vec![TarEntry::special("pipe", EntryType::Fifo)]),
            Rejection::SpecialFile { kind: "fifo" }
        ));
    }

    #[test]
    fn rejects_setuid_and_setgid() {
        assert!(matches!(
            rejection(vec![TarEntry::file("sudo", b"x").mode(0o4755)]),
            Rejection::PrivilegedMode { .. }
        ));
        assert!(matches!(
            rejection(vec![TarEntry::file("sgid", b"x").mode(0o2755)]),
            Rejection::PrivilegedMode { .. }
        ));
        assert!(matches!(
            rejection(vec![TarEntry::dir("sticky").mode(0o1777)]),
            Rejection::PrivilegedMode { .. }
        ));
    }

    #[test]
    fn rejects_duplicate_entries() {
        assert_eq!(
            rejection(vec![TarEntry::file("Cargo.toml", b"a"), TarEntry::file("Cargo.toml", b"b")]),
            Rejection::Duplicate
        );
    }

    #[test]
    fn rejects_paths_differing_only_by_unicode_normalization() {
        // "café" composed (U+00E9) vs decomposed (e + U+0301): different bytes, one file on APFS.
        let composed = "caf\u{e9}.txt";
        let decomposed = "cafe\u{301}.txt";
        assert_ne!(composed.as_bytes(), decomposed.as_bytes());
        assert!(matches!(
            rejection(vec![TarEntry::file(composed, b"a"), TarEntry::file(decomposed, b"b")]),
            Rejection::UnicodeCollision { .. }
        ));
    }

    #[test]
    fn rejects_control_characters_and_backslashes_in_names() {
        assert_eq!(rejection(vec![TarEntry::file("we\u{7}ird", b"x")]), Rejection::IllegalByte);
        assert_eq!(rejection(vec![TarEntry::file("a\\b", b"x")]), Rejection::BackslashInName);
    }

    #[test]
    fn rejects_symlinks_that_escape_the_root() {
        assert_eq!(rejection(vec![TarEntry::symlink("passwd", "/etc/passwd")]), Rejection::AbsoluteSymlinkTarget);
        assert_eq!(rejection(vec![TarEntry::symlink("out", "../../../etc")]), Rejection::SymlinkEscapesRoot);
        // One `..` from a nested link is fine; two from the same place is not.
        assert_eq!(rejection(vec![TarEntry::symlink("a/b/link", "../../../x")]), Rejection::SymlinkEscapesRoot);
    }

    #[test]
    fn allows_an_in_root_symlink() {
        let (dir, out) =
            extract(vec![TarEntry::file("real.txt", b"hi"), TarEntry::symlink("link.txt", "real.txt")]).unwrap();
        assert_eq!(out.symlinks, 1);
        assert_eq!(fs::read_link(dir.path().join("link.txt")).unwrap(), Path::new("real.txt"));
    }

    #[test]
    fn rejects_writing_through_a_planted_symlink() {
        // The classic two-entry attack. The link itself is in-bounds, so only the ancestor check
        // stops the follow-up write.
        let r = rejection(vec![
            TarEntry::dir("sub"),
            TarEntry::symlink("link", "sub"),
            TarEntry::file("link/evil", b"x"),
        ]);
        assert!(matches!(r, Rejection::SymlinkAncestor { .. }), "got {r:?}");
    }

    #[test]
    fn rejects_a_file_where_a_directory_already_is() {
        let r = rejection(vec![TarEntry::file("a/b", b"x"), TarEntry::file("a", b"y")]);
        assert_eq!(r, Rejection::Conflict);
    }

    #[test]
    fn enforces_the_entry_count_cap() {
        let limits = Limits { max_entries: 3, ..Limits::default() };
        let entries: Vec<_> = (0..10).map(|i| TarEntry::file(&format!("f{i}"), b"x")).collect();
        assert!(matches!(
            extract_with(entries, limits),
            Err(ExtractError::TooManyEntries { limit: 3 })
        ));
    }

    #[test]
    fn enforces_the_per_file_cap() {
        let limits = Limits { max_file_bytes: 16, ..Limits::default() };
        let entries = vec![TarEntry::file("big", &vec![b'A'; 4096])];
        match extract_with(entries, limits) {
            Err(ExtractError::Rejected { reason: Rejection::FileTooLarge { limit: 16 }, .. }) => {}
            other => panic!("expected FileTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn enforces_the_total_content_cap() {
        let limits = Limits { max_total_bytes: 100, max_file_bytes: 100, ..Limits::default() };
        let entries: Vec<_> = (0..10).map(|i| TarEntry::file(&format!("f{i}"), &[b'A'; 40])).collect();
        assert!(matches!(extract_with(entries, limits), Err(ExtractError::ContentTooLarge { .. })));
    }

    #[test]
    fn enforces_the_archive_byte_cap() {
        let limits = Limits { max_archive_bytes: 1024, ..Limits::default() };
        let entries: Vec<_> = (0..20).map(|i| TarEntry::file(&format!("f{i}"), &vec![b'A'; 1024])).collect();
        assert!(matches!(extract_with(entries, limits), Err(ExtractError::ArchiveTooLarge { limit: 1024 })));
    }

    #[test]
    fn enforces_the_depth_cap() {
        let limits = Limits { max_path_depth: 4, ..Limits::default() };
        let deep = format!("{}/f", ["d"; 8].join("/"));
        match extract_with(vec![TarEntry::file(&deep, b"x")], limits) {
            Err(ExtractError::Rejected { reason: Rejection::TooDeep { limit: 4 }, .. }) => {}
            other => panic!("expected TooDeep, got {other:?}"),
        }
    }

    #[test]
    fn refuses_a_non_empty_destination() {
        // Re-using a directory would let a previous run's content masquerade as this tree's.
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("leftover"), b"x").unwrap();
        let bytes = tar_bytes(&[TarEntry::file("a", b"x")]);
        assert!(matches!(
            extract_into(&bytes[..], dir.path(), &Limits::default()),
            Err(ExtractError::DestinationNotEmpty)
        ));
    }

    #[test]
    fn nothing_is_written_outside_the_destination() {
        // The end-to-end property, asserted rather than argued: after every hostile archive above,
        // the destination's parent holds nothing but the destination.
        let parent = TempDir::new().unwrap();
        let dest = parent.path().join("tree");
        for entries in [
            vec![TarEntry::file("../escape", b"x")],
            vec![TarEntry::file("/tmp/escape", b"x")],
            vec![TarEntry::symlink("link", "../.."), TarEntry::file("link/escape", b"x")],
        ] {
            let _ = fs::remove_dir_all(&dest);
            fs::create_dir(&dest).unwrap();
            let _ = extract_into(&tar_bytes(&entries)[..], &dest, &Limits::default());
            let stray: Vec<_> = fs::read_dir(parent.path())
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|n| n != "tree")
                .collect();
            assert!(stray.is_empty(), "escaped the destination: {stray:?}");
        }
    }
}
