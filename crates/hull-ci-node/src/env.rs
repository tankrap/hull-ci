//! The job environment — built, never inherited.
//!
//! §14.2: "The job environment MUST be scrubbed: pass only an explicit allowlist of benign variables.
//! It MUST NOT contain the `X-Hull-CI-Secret`, cloud keys, registry tokens, or `source_url` auth."
//! Design D§7.4 states the mechanism: "Environment is otherwise allowlist-only — `PATH`, `HOME`,
//! `LANG`, `CI=true`, declared non-secret pipeline vars ... Everything else is dropped, not filtered,
//! so an added host variable can't leak by default."
//!
//! We construct the environment from a literal list rather than copying the node's own environment and
//! removing things. Deny-lists fail open — a new host variable leaks until someone remembers to add
//! it — and this is the exact surface where failing open means handing an attacker a credential.
//!
//! The node itself holds **no** tenant credential and **no** CI shared secret (D§7.1): the fetch is
//! the broker's job and the callback is the control plane's, so there is nothing here to leak even if
//! the allowlist were wrong. [`reject_forbidden`] is therefore a backstop against a *caller* mistake,
//! not the primary control.

/// A single environment entry destined for the sandbox.
pub type EnvVar = (String, String);

/// The base environment every job gets. Nothing here is a credential, and nothing here comes from the
/// node's own process environment.
pub fn base_env(home: &str) -> Vec<EnvVar> {
    vec![
        ("PATH".into(), "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()),
        ("HOME".into(), home.into()),
        ("LANG".into(), "C.UTF-8".into()),
        // Conventional, and load-bearing for many test suites (`CI=true` disables watch modes and
        // interactive prompts that would otherwise hang until the wall clock kills the step).
        ("CI".into(), "true".into()),
        ("TMPDIR".into(), "/tmp".into()),
    ]
}

/// Substrings that must never appear in a variable name we pass into a sandbox.
///
/// M1 injects no tenant secrets at all (the secret broker is M3, D§7.4), so the correct number of
/// credential-shaped variables entering a sandbox right now is zero. This list exists so that a
/// caller who starts passing extra variables cannot quietly reintroduce §14.2's failure mode.
const FORBIDDEN_NAME_FRAGMENTS: &[&str] = &[
    "SECRET", "TOKEN", "PASSWORD", "PASSWD", "CREDENTIAL", "PRIVATE_KEY", "APIKEY", "API_KEY",
    "AWS_", "GOOGLE_APPLICATION", "AZURE_", "GITHUB_TOKEN", "NPM_TOKEN", "HULL_CI",
];

/// Whether this variable name is credential-shaped and must be refused (§14.2).
pub fn is_forbidden_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    FORBIDDEN_NAME_FRAGMENTS.iter().any(|f| upper.contains(f))
}

/// Refuse an environment that contains anything credential-shaped.
///
/// Returns the offending name; the caller turns that into a refusal rather than stripping the entry,
/// because a caller trying to pass a secret in M1 has a bug we want to hear about, not a value we want
/// to silently drop.
pub fn reject_forbidden(env: &[EnvVar]) -> Result<(), String> {
    for (name, _) in env {
        if is_forbidden_name(name) {
            return Err(name.clone());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_env_is_constructed_not_inherited() {
        // The node's own environment is irrelevant by construction: nothing reads it. If this ever
        // becomes a filter over `std::env::vars()`, this test is the thing that should start failing.
        let env = base_env("/tmp");
        let names: Vec<&str> = env.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["PATH", "HOME", "LANG", "CI", "TMPDIR"]);
        assert!(reject_forbidden(&env).is_ok());
    }

    #[test]
    fn credential_shaped_names_are_refused() {
        for name in [
            "X_HULL_CI_SECRET",
            "AWS_SECRET_ACCESS_KEY",
            "npm_token",
            "GITHUB_TOKEN",
            "MY_PRIVATE_KEY",
        ] {
            assert!(is_forbidden_name(name), "{name} must be refused (§14.2)");
        }
        assert!(!is_forbidden_name("CARGO_TERM_COLOR"));
        assert_eq!(
            reject_forbidden(&[("RUST_LOG".into(), "info".into()), ("NPM_TOKEN".into(), "x".into())]),
            Err("NPM_TOKEN".to_string())
        );
    }
}
