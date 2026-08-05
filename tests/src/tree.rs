//! Source trees the stub Hull serves at `source_url`, and their content address.
//!
//! Spec §6: `GET source_url` returns the change's keel **tree** — named by `tree_id` — as a `tar`
//! archive. The suite therefore has to be able to (a) produce a tar and (b) name it, so that the
//! corrupted-archive case is a genuine `tree_id` mismatch rather than a broken tar.

use sha2::{Digest, Sha256};
use std::fmt::Write as _;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// One regular file in a synthetic tree.
#[derive(Debug, Clone)]
pub struct TreeFile {
    pub path: String,
    pub mode: u32,
    pub data: Vec<u8>,
}

impl TreeFile {
    pub fn new(path: &str, data: impl Into<Vec<u8>>) -> Self {
        TreeFile { path: path.to_string(), mode: 0o644, data: data.into() }
    }

    pub fn executable(path: &str, data: impl Into<Vec<u8>>) -> Self {
        TreeFile { path: path.to_string(), mode: 0o755, data: data.into() }
    }
}

/// The content address the stub Hull advertises for a tree.
///
/// **This is the harness's stand-in for keel's canonical tree hash.** The CI contract never puts the
/// algorithm on the wire — §5 calls `tree_id` an opaque content address and §6 says a runner **MAY**
/// re-hash to verify — so a black-box suite cannot discover it and no third-party CI can be expected
/// to reproduce it. What the suite *can* assert without knowing the algorithm is the asymmetry the
/// adversarial case turns on: a tree whose bytes are not the bytes that were hashed must not be run
/// (`adversarial::corrupt_archive_must_fail_tree_id_rehash`), and that holds under any sane
/// canonicalisation.
///
/// The canonical form is written out here so that any language can reproduce it — the reference CI
/// under `tests/reference/` does, in stdlib Python:
///
/// ```text
/// SHA-256( "hull-ci-conformance/tree/v1\n"
///          ++ for each file, sorted by path:
///                "file <mode, 6 octal digits> <byte length> <path>\n" ++ <file bytes> )
/// ```
///
/// When `hull-ci-fetch` lands keel's real hash, replace the body of this function with it — it is the
/// single point of change, and the tests above it do not move.
pub fn tree_id(files: &[TreeFile]) -> String {
    let mut sorted: Vec<&TreeFile> = files.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));

    let mut hasher = Sha256::new();
    hasher.update(b"hull-ci-conformance/tree/v1\n");
    for f in sorted {
        let mut header = String::new();
        let _ = write!(header, "file {:06o} {} {}\n", f.mode, f.data.len(), f.path);
        hasher.update(header.as_bytes());
        hasher.update(&f.data);
    }
    hex(hasher.finalize().as_slice())
}

/// A change id derived from the tree, so fixtures read like real dispatches instead of `"abc"`.
pub fn change_id(tree_id: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"change");
    hasher.update(tree_id.as_bytes());
    hasher.update(salt.as_bytes());
    hex(hasher.finalize().as_slice())
}

/// Serialise a tree as a POSIX `ustar` archive — the format `tar -x` and Python's `tarfile` read.
pub fn tar(files: &[TreeFile]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut sorted: Vec<&TreeFile> = files.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));

    for f in sorted {
        assert!(f.path.len() < 100, "fixture paths stay inside the ustar name field: {}", f.path);
        let mut header = [0u8; 512];
        put(&mut header[0..100], f.path.as_bytes());
        put(&mut header[100..108], format!("{:07o}\0", f.mode).as_bytes());
        put(&mut header[108..116], b"0000000\0"); // uid
        put(&mut header[116..124], b"0000000\0"); // gid
        put(&mut header[124..136], format!("{:011o}\0", f.data.len()).as_bytes());
        put(&mut header[136..148], b"00000000000\0"); // mtime 0 — fixtures must be byte-identical run to run
        put(&mut header[148..156], b"        "); // checksum placeholder: spaces
        header[156] = b'0'; // typeflag: regular file
        put(&mut header[257..263], b"ustar\0");
        put(&mut header[263..265], b"00");
        put(&mut header[265..297], b"hull");
        put(&mut header[297..329], b"hull");

        let sum: u32 = header.iter().map(|b| *b as u32).sum();
        put(&mut header[148..156], format!("{sum:06o}\0 ").as_bytes());

        out.extend_from_slice(&header);
        out.extend_from_slice(&f.data);
        let pad = (512 - f.data.len() % 512) % 512;
        out.extend(std::iter::repeat(0u8).take(pad));
    }
    // Two zero blocks terminate the archive.
    out.extend(std::iter::repeat(0u8).take(1024));
    out
}

fn put(dst: &mut [u8], src: &[u8]) {
    let n = src.len().min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
}

// ── Fixtures ─────────────────────────────────────────────────────────────────────────────────────

/// A benign little project. Deliberately carries several test entry points, because a runner that
/// autodetects (design D§6) will pick one of them, and the suite must not care which.
pub fn benign_project() -> Vec<TreeFile> {
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
        let files = benign_project();
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
            String::from_utf8_lossy(&out.stdout).lines().map(str::to_string).collect();
        for f in &files {
            assert!(listed.contains(&f.path), "{} missing from the archive: {listed:?}", f.path);
        }
    }

    #[test]
    fn tree_id_is_deterministic_and_content_sensitive() {
        let a = benign_project();
        assert_eq!(tree_id(&a), tree_id(&a), "the same tree must always name itself the same way");

        let mut b = a.clone();
        b[0].data.push(b'!');
        assert_ne!(
            tree_id(&a),
            tree_id(&b),
            "a one-byte edit must change the content address, or the corrupted-archive case proves \
             nothing"
        );
    }
}
