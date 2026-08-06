//! Configuration, from the environment.
//!
//! Every setting here is read once at startup and then owned by the process; nothing is re-read, and
//! nothing is settable over HTTP. Two of them are safety switches rather than preferences
//! ([`Config::sandbox`] and [`Config::allow_unsandboxed`]), and those are written so that the unsafe
//! choice is the one you have to spell out — see [`SandboxChoice`].
//!
//! | Variable | Default | What it is |
//! |---|---|---|
//! | `HULL_CI_BIND` | `127.0.0.1:8080` | listen address for `POST /hull` (spec §4) |
//! | `HULL_CI_SECRET` | *none* | the shared secret (spec §8), checked on dispatch and echoed on the callback |
//! | `HULL_CI_STORE_ROOT` | `$TMPDIR/hull-ci/store` | root of the broker's content store (design D§4.2) |
//! | `HULL_CI_WORK_ROOT` | `$TMPDIR/hull-ci/workspaces` | where per-job workspaces are materialized (D§6.2) |
//! | `HULL_CI_SANDBOX` | `container` | `container` \| `local` — the §14.1 boundary, or the absence of one |
//! | `HULL_CI_ALLOW_UNSANDBOXED` | unset | required to start with `HULL_CI_SANDBOX=local` |
//! | `HULL_CI_TRUSTED_TENANTS` | *empty* | tenants whose authors count as members (design D§1); `*` for all |
//! | `HULL_CI_NODE_ID` | `node-0` | this node's id, as it appears in leases and log keys |
//! | `HULL_CI_IMAGE` | `hull-ci/m1:latest` | image the planner names for its step |
//! | `HULL_CI_DETAILS_BASE_URL` | *none* | base for the verdict's `details_url` (design G4) |
//! | `HULL_CI_ADMIN_TOKEN` | *none* | bearer token for the read-only operator panel; **unset disables it entirely** |
//! | `HULL_CI_SECRETS` | `off` | `off` \| `dev` — the tenant secret broker (design D§7.4) |
//! | `HULL_CI_DEV_SECRETS` | *none* | `tenant/NAME=value,…` seed for `HULL_CI_SECRETS=dev`; **dev only** |
//!
//! `HULL_CI_SECRET` deserves its own note: spec §8 makes configuring one a SHOULD, and this process
//! treats a missing one as a loud warning rather than a refusal, because a loopback bring-up run
//! genuinely does not need it. The moment `HULL_CI_BIND` is not loopback that reasoning stops
//! holding, and the warning says so.

use std::net::SocketAddr;
use std::path::PathBuf;

use hull_ci_control::Timeouts;

use crate::membership::TrustedTenants;

/// Which sandbox backend to run jobs in.
///
/// There is no `Auto` that silently degrades. Spec §14.1 calls a plain host subprocess "NOT
/// sufficient" and design D§13 makes the container the M1 backend, so falling back from one to the
/// other on a host where the daemon happens to be down would turn an operator's isolation
/// expectation into a coin flip decided by `docker`'s uptime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxChoice {
    /// The M1 bring-up backend: a locked-down container (design D§7.2, D§13).
    Container,
    /// A host subprocess. **Not a sandbox.** Requires `HULL_CI_ALLOW_UNSANDBOXED`.
    LocalProcess,
}

impl SandboxChoice {
    fn parse(raw: &str) -> Result<SandboxChoice, ConfigError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "container" | "docker" => Ok(SandboxChoice::Container),
            "local" | "local-process" => Ok(SandboxChoice::LocalProcess),
            other => Err(ConfigError::Value {
                var: "HULL_CI_SANDBOX",
                detail: format!("expected `container` or `local`, got `{other}`"),
            }),
        }
    }
}

/// Whether this deployment can deliver a tenant secret, and what holds the keys (design D§7.4).
///
/// There is no `auto`. Whether a runner can hand a job a credential is not something to infer from
/// the environment: it changes what a sandbox escape reaches, so it is a choice an operator makes in
/// one place and can read back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretsMode {
    /// **The default.** No broker, no node keypair, no capability ever minted. A pipeline's
    /// `secrets = [...]` is warned about at plan time and delivered to nobody, and the sandbox's
    /// credential-shaped-name refusal keeps its pre-M3 meaning exactly.
    Off,
    /// A broker whose key material lives in this process's memory
    /// ([`hull_ci_secrets::DevKeyManager`]), announced loudly at startup. Development and test only;
    /// the [`KeyManager`](hull_ci_secrets::KeyManager) trait is where a KMS goes.
    Dev,
}

impl SecretsMode {
    fn parse(raw: &str) -> Result<SecretsMode, ConfigError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "disabled" => Ok(SecretsMode::Off),
            "dev" | "development" => Ok(SecretsMode::Dev),
            other => Err(ConfigError::Value {
                var: "HULL_CI_SECRETS",
                // No fuzzy matching, for the same reason `SandboxChoice` has none: a typo must not
                // resolve to a mode that hands out credentials.
                detail: format!("expected `off` or `dev`, got `{other}`"),
            }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{var} is invalid: {detail}")]
    Value { var: &'static str, detail: String },
}

/// Everything this process is configured with.
///
/// Public fields on purpose: the end-to-end suite builds one directly rather than mutating the
/// process environment, which is global state that test threads would race on.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub secret: Option<String>,
    pub store_root: PathBuf,
    pub work_root: PathBuf,
    pub sandbox: SandboxChoice,
    /// The operator's explicit acknowledgement that [`SandboxChoice::LocalProcess`] enforces almost
    /// nothing. Without it, that choice refuses to start.
    pub allow_unsandboxed: bool,
    pub trusted: TrustedTenants,
    pub node_id: String,
    /// Image the planner names for its step. Ignored by the local backend, which has no images.
    pub image: String,
    pub details_base_url: Option<String>,
    pub timeouts: Timeouts,
    /// Bearer token for the operator panel ([`crate::admin`]).
    ///
    /// `None` means the panel does not exist: no route is mounted, so there is nothing to
    /// misconfigure, nothing to brute-force, and no default credential. That is deliberate rather
    /// than cautious — the panel is **cross-tenant by nature** (design D§1: every other shared
    /// surface in this system is partitioned by tenant, and this one is not), so a deployment that
    /// did not ask for it must not get it.
    pub admin_token: Option<String>,
    /// Whether tenant secrets can be delivered at all (design D§7.4). See [`SecretsMode`].
    pub secrets: SecretsMode,
    /// `tenant/NAME=value,…` seeded into a [`SecretsMode::Dev`] broker at startup.
    ///
    /// Ignored in [`SecretsMode::Off`], and documented dev-only where it is read
    /// ([`crate::secrets::seed_dev_secrets`]) — it is the one place in this configuration that holds
    /// a plaintext credential, and it exists so a dev stack can be tried at all.
    pub dev_secrets: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        let base = std::env::temp_dir().join("hull-ci");
        Config {
            // Loopback: this endpoint holds the CI shared secret and queues work on a fleet, so
            // exposing it is a deliberate act (mirrors `hull_ci_control::Opts`).
            bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            secret: None,
            store_root: base.join("store"),
            work_root: base.join("workspaces"),
            sandbox: SandboxChoice::Container,
            allow_unsandboxed: false,
            // Empty: every author is an outsider until an operator says otherwise, and no M1 backend
            // admits outsider work. A misconfigured deployment therefore refuses jobs rather than
            // running them unprotected (design D§1, D§13).
            trusted: TrustedTenants::none(),
            node_id: "node-0".into(),
            image: "hull-ci/m1:latest".into(),
            details_base_url: None,
            timeouts: Timeouts::default(),
            // Off. See the field's doc: an operator surface that shows every tenant's jobs is opt-in.
            admin_token: None,
            // Off: a runner nobody asked to hold credentials holds none, so there is nothing for a
            // sandbox escape to reach and nothing for a misconfiguration to hand out.
            secrets: SecretsMode::Off,
            dev_secrets: None,
        }
    }
}

impl Config {
    /// Read the environment. Absent variables take the documented default; present-but-unparseable
    /// ones are an error, never a silent default — a typo'd bind address that quietly listens
    /// somewhere else is worse than a process that will not start.
    pub fn from_env() -> Result<Config, ConfigError> {
        let d = Config::default();
        Ok(Config {
            bind: match var("HULL_CI_BIND") {
                Some(v) => v.parse().map_err(|e| ConfigError::Value {
                    var: "HULL_CI_BIND",
                    detail: format!("{e} (expected `host:port`)"),
                })?,
                None => d.bind,
            },
            secret: var("HULL_CI_SECRET"),
            store_root: var("HULL_CI_STORE_ROOT").map(PathBuf::from).unwrap_or(d.store_root),
            work_root: var("HULL_CI_WORK_ROOT").map(PathBuf::from).unwrap_or(d.work_root),
            sandbox: match var("HULL_CI_SANDBOX") {
                Some(v) => SandboxChoice::parse(&v)?,
                None => d.sandbox,
            },
            allow_unsandboxed: var("HULL_CI_ALLOW_UNSANDBOXED").as_deref().is_some_and(is_truthy),
            trusted: var("HULL_CI_TRUSTED_TENANTS").map(|v| TrustedTenants::parse(&v)).unwrap_or(d.trusted),
            node_id: var("HULL_CI_NODE_ID").unwrap_or(d.node_id),
            image: var("HULL_CI_IMAGE").unwrap_or(d.image),
            details_base_url: var("HULL_CI_DETAILS_BASE_URL"),
            timeouts: d.timeouts,
            // `var` treats an empty value as unset, which matters more here than anywhere else:
            // `HULL_CI_ADMIN_TOKEN=` must disable the panel, never authenticate the empty string.
            admin_token: var("HULL_CI_ADMIN_TOKEN"),
            secrets: match var("HULL_CI_SECRETS") {
                Some(v) => SecretsMode::parse(&v)?,
                None => d.secrets,
            },
            dev_secrets: var("HULL_CI_DEV_SECRETS"),
        })
    }
}

/// A set variable that is empty or whitespace reads as unset. `HULL_CI_SECRET=` is a mistake, and
/// treating it as "no secret configured" is friendlier than authenticating against the empty string.
fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn is_truthy(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_the_safe_one() {
        let d = Config::default();
        assert_eq!(d.sandbox, SandboxChoice::Container, "the sandboxed backend is the default");
        assert!(!d.allow_unsandboxed, "running without a sandbox is never implicit");
        assert!(d.bind.ip().is_loopback());
        assert!(
            !d.trusted.is_trusted("acme"),
            "least privilege: an unconfigured deployment has no trusted tenant, so it runs nothing"
        );
        assert!(d.admin_token.is_none(), "the cross-tenant operator panel is off unless asked for");
        assert_eq!(
            d.secrets,
            SecretsMode::Off,
            "a runner nobody asked to hold tenant credentials holds none (D§7.4)"
        );
    }

    #[test]
    fn the_secrets_mode_refuses_anything_it_does_not_recognise() {
        // Same reasoning as the sandbox choice: a typo must not resolve to the mode that hands out
        // credentials, so there is no fuzzy match and no fallback.
        assert_eq!(SecretsMode::parse("off").unwrap(), SecretsMode::Off);
        assert_eq!(SecretsMode::parse(" DEV ").unwrap(), SecretsMode::Dev);
        assert!(SecretsMode::parse("kms").is_err(), "no KMS mode exists yet, so it must not parse");
        assert!(SecretsMode::parse("").is_err());
    }

    #[test]
    fn the_sandbox_choice_refuses_anything_it_does_not_recognise() {
        // A typo must not resolve to a weaker backend, so there is no fuzzy match and no fallback.
        assert_eq!(SandboxChoice::parse("container").unwrap(), SandboxChoice::Container);
        assert_eq!(SandboxChoice::parse(" LOCAL ").unwrap(), SandboxChoice::LocalProcess);
        assert!(SandboxChoice::parse("none").is_err());
        assert!(SandboxChoice::parse("").is_err());
    }

    #[test]
    fn truthiness_is_explicit() {
        for yes in ["1", "true", "YES", " on "] {
            assert!(is_truthy(yes));
        }
        for no in ["0", "false", "", "maybe"] {
            assert!(!is_truthy(no));
        }
    }
}
