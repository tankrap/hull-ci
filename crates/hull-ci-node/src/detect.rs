//! Test-command autodetection for M1.
//!
//! M1 has no pipeline file (design D§13), so the command comes from marker files in the tree, matching
//! Hull's built-in runner so that pointing a repo at this runner does not change its behaviour
//! (design D§4.4): `Cargo.toml → cargo test`, `package.json → npm test`, `go.mod → go test ./...`,
//! `Makefile` with a `test` target → `make test`.
//!
//! **Nothing detectable is not an infrastructure failure.** It is `errored` with
//! `reason: no_tests`, which spec §9.1 reads as *self_attested* — "no pre-existing test exercises this
//! change" — and routes to a human reviewer. Reporting it as `red` would claim the code is broken;
//! reporting it as a generic infra error would tell Hull to retry something that will never succeed.
//! The distinction is a statement about coverage, so it travels as [`Detection::None`] and the caller
//! maps it to `Reason::NoTests`.
//!
//! Every byte read here is untrusted (§14.5): the `Makefile` scan is bounded, does no include
//! resolution, and never executes anything. Detection only *chooses* an argv; it never builds a shell
//! string.

use std::path::Path;

/// A command we know how to run, and the marker file that chose it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedCommand {
    /// argv, executed inside the sandbox as argv. Never joined into a command line (D§7.2).
    pub argv: Vec<String>,
    /// The file that decided it — reported so a human can see *why* we ran what we ran.
    pub marker: &'static str,
}

/// The outcome of autodetection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Detection {
    Found(DetectedCommand),
    /// No marker file matched. Maps to `Reason::NoTests`, **not** `Reason::Infra` (§9.1).
    None,
}

/// How much of a `Makefile` we are willing to read. It is attacker-controlled input parsed outside a
/// sandbox, so it gets a bound like every other such surface (design D§9).
const MAKEFILE_SCAN_LIMIT: usize = 1024 * 1024;

/// Marker files in priority order. First match wins; a polyglot repo therefore gets a stable,
/// explainable answer rather than one that depends on directory iteration order.
pub fn detect_test_command(root: &Path) -> Detection {
    if root.join("Cargo.toml").is_file() {
        return found(&["cargo", "test"], "Cargo.toml");
    }
    if root.join("package.json").is_file() {
        return found(&["npm", "test"], "package.json");
    }
    if root.join("go.mod").is_file() {
        return found(&["go", "test", "./..."], "go.mod");
    }
    for name in ["Makefile", "makefile", "GNUmakefile"] {
        let path = root.join(name);
        if path.is_file() && makefile_has_test_target(&path) {
            return found(&["make", "test"], "Makefile");
        }
    }
    Detection::None
}

fn found(argv: &[&str], marker: &'static str) -> Detection {
    Detection::Found(DetectedCommand {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        marker,
    })
}

/// Whether a makefile declares a `test` target.
///
/// Deliberately a lexical scan, not a make parser: we are answering "would `make test` plausibly do
/// something", and running `make -n test` to find out would execute untrusted makefile code on the
/// host, which is precisely what §14.1 forbids.
fn makefile_has_test_target(path: &Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else { return false };
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(MAKEFILE_SCAN_LIMIT)]);
    text.lines().any(is_test_target_line)
}

fn is_test_target_line(line: &str) -> bool {
    // Recipe lines are indented (tab), so a target declaration starts in column zero.
    if line.starts_with(char::is_whitespace) || line.starts_with('#') || line.trim().is_empty() {
        return false;
    }
    let Some((lhs, rhs)) = line.split_once(':') else { return false };
    // `test := ...` / `test ::= ...` are variable assignments, not targets.
    if rhs.starts_with('=') || rhs.starts_with(":=") || lhs.contains('=') {
        return false;
    }
    // `.PHONY: test` declares a property of the target, not the target — its lhs is `.PHONY`.
    lhs.split_whitespace().any(|t| t == "test")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn argv_of(d: Detection) -> Vec<String> {
        match d {
            Detection::Found(c) => c.argv,
            Detection::None => panic!("expected a detection"),
        }
    }

    #[test]
    fn cargo_manifest_selects_cargo_test() {
        let t = dir();
        fs::write(t.path().join("Cargo.toml"), "[package]\nname='x'\n").unwrap();
        assert_eq!(argv_of(detect_test_command(t.path())), ["cargo", "test"]);
    }

    #[test]
    fn package_json_selects_npm_test() {
        let t = dir();
        fs::write(t.path().join("package.json"), "{}").unwrap();
        assert_eq!(argv_of(detect_test_command(t.path())), ["npm", "test"]);
    }

    #[test]
    fn go_mod_selects_go_test() {
        let t = dir();
        fs::write(t.path().join("go.mod"), "module x\n").unwrap();
        assert_eq!(argv_of(detect_test_command(t.path())), ["go", "test", "./..."]);
    }

    #[test]
    fn makefile_with_a_test_target_selects_make_test() {
        let t = dir();
        fs::write(t.path().join("Makefile"), "all:\n\techo hi\n\ntest:\n\techo test\n").unwrap();
        assert_eq!(argv_of(detect_test_command(t.path())), ["make", "test"]);
    }

    #[test]
    fn makefile_without_a_test_target_is_not_detected() {
        let t = dir();
        fs::write(t.path().join("Makefile"), "all:\n\techo hi\n").unwrap();
        assert_eq!(detect_test_command(t.path()), Detection::None);
    }

    #[test]
    fn a_test_variable_is_not_a_test_target() {
        let t = dir();
        fs::write(t.path().join("Makefile"), "test := ./run\nall:\n\techo hi\n").unwrap();
        assert_eq!(detect_test_command(t.path()), Detection::None);
    }

    #[test]
    fn phony_alone_does_not_count_as_a_target() {
        let t = dir();
        fs::write(t.path().join("Makefile"), ".PHONY: test\nall:\n\techo hi\n").unwrap();
        assert_eq!(
            detect_test_command(t.path()),
            Detection::None,
            "declaring test phony without defining it means `make test` has nothing to run"
        );
    }

    #[test]
    fn multi_target_lines_count() {
        let t = dir();
        fs::write(t.path().join("Makefile"), "lint test check:\n\techo hi\n").unwrap();
        assert_eq!(argv_of(detect_test_command(t.path())), ["make", "test"]);
    }

    #[test]
    fn priority_is_stable_for_polyglot_trees() {
        let t = dir();
        fs::write(t.path().join("Cargo.toml"), "").unwrap();
        fs::write(t.path().join("package.json"), "{}").unwrap();
        fs::write(t.path().join("go.mod"), "module x").unwrap();
        fs::write(t.path().join("Makefile"), "test:\n\ttrue\n").unwrap();
        assert_eq!(argv_of(detect_test_command(t.path())), ["cargo", "test"]);
    }

    #[test]
    fn nothing_detectable_is_none_not_an_error() {
        // §9.1: this is a statement about coverage (→ Reason::NoTests → self_attested), not about
        // our infrastructure. Nothing here may look like an infra failure.
        let t = dir();
        fs::write(t.path().join("README.md"), "hi").unwrap();
        assert_eq!(detect_test_command(t.path()), Detection::None);
    }

    #[test]
    fn a_directory_named_like_a_marker_is_not_a_marker() {
        let t = dir();
        fs::create_dir(t.path().join("Cargo.toml")).unwrap();
        assert_eq!(detect_test_command(t.path()), Detection::None);
    }
}
