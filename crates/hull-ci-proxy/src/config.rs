//! Configuration, from the environment.
//!
//! | Variable | Default | What it is |
//! |---|---|---|
//! | `HULL_CI_PROXY` | `off` | `off` \| `on` — whether the package proxy exists at all |
//! | `HULL_CI_PROXY_BIND` | `127.0.0.1:3128` | listen address on the node |
//! | `HULL_CI_PROXY_UPSTREAMS` | *empty* | `label=url[,secret=NAME][,auth=bearer\|basic:user\|header:Name]` entries, `;`-separated |
//! | `HULL_CI_PROXY_NETWORK` | *none* | the sandbox network the node attaches jobs to |
//! | `HULL_CI_PROXY_ENDPOINT` | *none* | `host:port` of the proxy **as the sandbox sees it** |
//! | `HULL_CI_PROXY_RATE` | `20/200` | per-job `requests-per-second/burst` |
//!
//! # Why `off` is the default, and why it is a separate switch from the sandbox network
//!
//! Turning the proxy on is the moment a job stops running with `--network none`. Spec §14.3 makes
//! egress-deny the *default* and the proxy the exception ("Where dependency resolution needs it"), so
//! the exception is spelled out per deployment or it does not happen. There is no `auto` and no
//! inference from "an allowlist was configured": a variable that quietly changes the network posture
//! of every job on a fleet is the one variable that must never be set by accident.
//!
//! The two halves are separate because they are enforced in different processes. `HULL_CI_PROXY=on`
//! makes *this* process serve packages; `HULL_CI_PROXY_NETWORK` is what makes the *node* put a
//! sandbox somewhere it can be reached. A deployment that sets one and not the other gets a proxy
//! nobody can reach, or jobs with no network — both are safe failures, and neither is silent.

use std::net::SocketAddr;

use crate::allowlist::{Allowlist, AllowlistError, AuthScheme, Upstream};
use crate::ratelimit::RateLimit;

/// Whether this deployment runs a package proxy (spec §14.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyMode {
    /// **The default.** No proxy, and — provided the node is left alone too — `--network none` for
    /// every job. §14.3's "A job **SHOULD** run with no outbound network."
    #[default]
    Off,
    /// Serve packages from an allowlist. Meaningful only alongside a node configured with a sandbox
    /// network that can reach this process.
    On,
}

impl ProxyMode {
    /// No fuzzy matching, matching `SandboxChoice` and `SecretsMode` in the server crate: a typo
    /// must never resolve to the mode that opens a network path out of a sandbox.
    pub fn parse(raw: &str) -> Result<ProxyMode, ConfigError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "disabled" => Ok(ProxyMode::Off),
            "on" | "enabled" => Ok(ProxyMode::On),
            other => Err(ConfigError::Value {
                var: "HULL_CI_PROXY",
                detail: format!("expected `off` or `on`, got `{other}`"),
            }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{var} is invalid: {detail}")]
    Value { var: &'static str, detail: String },
    #[error("HULL_CI_PROXY_UPSTREAMS is invalid: {0}")]
    Upstreams(#[from] AllowlistError),
}

/// Everything the proxy is configured with.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub mode: ProxyMode,
    pub bind: SocketAddr,
    pub allowlist: Allowlist,
    /// Docker network name the node attaches sandboxes to. `None` leaves the node on
    /// `--network none` regardless of anything else here.
    pub network: Option<String>,
    /// `host:port` as reachable **from inside the sandbox**. Deliberately not derived from
    /// [`bind`](Self::bind): the proxy binds on the node's own address, and what a sandbox can reach
    /// is the network gateway, which is a different address and cannot be inferred from this side.
    pub endpoint: Option<String>,
    pub rate: RateLimit,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            mode: ProxyMode::Off,
            // Loopback, like every other bind default in this workspace. The sandbox does not reach
            // the proxy over loopback — it reaches it over the sandbox network's gateway — so an
            // operator enabling the proxy must choose an address deliberately.
            bind: SocketAddr::from(([127, 0, 0, 1], 3128)),
            // Empty: a proxy with no allowlist is not an open proxy, it is a proxy that serves
            // nothing (`Allowlist::resolve` refuses every label).
            allowlist: Allowlist::new(),
            network: None,
            endpoint: None,
            rate: RateLimit::default(),
        }
    }
}

impl ProxyConfig {
    pub fn from_env() -> Result<ProxyConfig, ConfigError> {
        let d = ProxyConfig::default();
        Ok(ProxyConfig {
            mode: match var("HULL_CI_PROXY") {
                Some(v) => ProxyMode::parse(&v)?,
                None => d.mode,
            },
            bind: match var("HULL_CI_PROXY_BIND") {
                Some(v) => v.parse().map_err(|e| ConfigError::Value {
                    var: "HULL_CI_PROXY_BIND",
                    detail: format!("{e} (expected `host:port`)"),
                })?,
                None => d.bind,
            },
            allowlist: match var("HULL_CI_PROXY_UPSTREAMS") {
                Some(v) => parse_upstreams(&v)?,
                None => d.allowlist,
            },
            network: var("HULL_CI_PROXY_NETWORK"),
            endpoint: var("HULL_CI_PROXY_ENDPOINT"),
            rate: match var("HULL_CI_PROXY_RATE") {
                Some(v) => parse_rate(&v)?,
                None => d.rate,
            },
        })
    }

    /// Whether this configuration actually serves anything.
    ///
    /// `On` with an empty allowlist is a live listener that refuses every request. That is a safe
    /// state but almost certainly a mistake, and the composition root warns on it rather than
    /// leaving an operator to discover it from a build failure.
    pub fn serves_anything(&self) -> bool {
        self.mode == ProxyMode::On && !self.allowlist.is_empty()
    }
}

/// Parse `label=url[,secret=NAME][,auth=…]` entries, `;`-separated.
///
/// `;` between entries and `,` within one, because a URL may contain almost anything else and an
/// operator should not have to think about quoting. An unrecognised key is an **error**, not an
/// ignored token: silently dropping `secert=NPM_TOKEN` would produce an upstream that resolves
/// anonymously and 401s halfway through a build.
pub fn parse_upstreams(raw: &str) -> Result<Allowlist, ConfigError> {
    let mut upstreams = Vec::new();
    for entry in raw.split(';').map(str::trim).filter(|e| !e.is_empty()) {
        let mut parts = entry.split(',').map(str::trim);
        let head = parts.next().unwrap_or_default();
        let (label, url) = head.split_once('=').ok_or_else(|| ConfigError::Value {
            var: "HULL_CI_PROXY_UPSTREAMS",
            detail: format!("entry `{entry}` is not `label=url`"),
        })?;

        let mut secret: Option<String> = None;
        let mut auth = AuthScheme::Bearer;
        for opt in parts {
            let (key, value) = opt.split_once('=').ok_or_else(|| ConfigError::Value {
                var: "HULL_CI_PROXY_UPSTREAMS",
                detail: format!("option `{opt}` is not `key=value`"),
            })?;
            match key {
                "secret" => secret = Some(value.to_string()),
                "auth" => {
                    auth = match value.split_once(':') {
                        Some(("basic", user)) => AuthScheme::Basic { user: user.to_string() },
                        Some(("header", name)) => AuthScheme::Header { name: name.to_string() },
                        None if value == "bearer" => AuthScheme::Bearer,
                        _ => {
                            return Err(ConfigError::Value {
                                var: "HULL_CI_PROXY_UPSTREAMS",
                                detail: format!(
                                    "auth `{value}` is not `bearer`, `basic:<user>` or `header:<Name>`"
                                ),
                            })
                        }
                    }
                }
                other => {
                    return Err(ConfigError::Value {
                        var: "HULL_CI_PROXY_UPSTREAMS",
                        detail: format!("unknown option `{other}` in entry `{entry}`"),
                    })
                }
            }
        }
        upstreams.push(match secret {
            Some(name) => Upstream::authenticated(label, url, name, auth)?,
            None => Upstream::public(label, url)?,
        });
    }
    Ok(Allowlist::from_upstreams(upstreams)?)
}

fn parse_rate(raw: &str) -> Result<RateLimit, ConfigError> {
    let bad = |detail: String| ConfigError::Value { var: "HULL_CI_PROXY_RATE", detail };
    let (per_second, burst) = raw
        .trim()
        .split_once('/')
        .ok_or_else(|| bad(format!("`{raw}` is not `requests-per-second/burst`")))?;
    let per_second: u32 =
        per_second.trim().parse().map_err(|_| bad(format!("`{per_second}` is not a number")))?;
    let burst: u32 = burst.trim().parse().map_err(|_| bad(format!("`{burst}` is not a number")))?;
    if burst == 0 {
        // A zero burst is a bucket that never hands out a token, which is a proxy that refuses every
        // request while looking configured.
        return Err(bad("burst must be at least 1".into()));
    }
    Ok(RateLimit::new(per_second, burst))
}

/// A set variable that is empty or whitespace reads as unset, matching `hull_ci_server::config`.
fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_no_proxy_and_no_network() {
        // §14.3's default. If this test ever fails, every job on every deployment just got a network.
        let d = ProxyConfig::default();
        assert_eq!(d.mode, ProxyMode::Off);
        assert!(d.network.is_none(), "no sandbox network means the node stays on --network none");
        assert!(d.endpoint.is_none());
        assert!(d.allowlist.is_empty());
        assert!(!d.serves_anything());
        assert!(d.bind.ip().is_loopback());
    }

    #[test]
    fn the_mode_refuses_anything_it_does_not_recognise() {
        assert_eq!(ProxyMode::parse("off").unwrap(), ProxyMode::Off);
        assert_eq!(ProxyMode::parse(" ON ").unwrap(), ProxyMode::On);
        // A typo must not resolve to the mode that opens a network path out of a sandbox.
        assert!(ProxyMode::parse("yes").is_err());
        assert!(ProxyMode::parse("true").is_err());
        assert!(ProxyMode::parse("").is_err());
    }

    #[test]
    fn upstreams_parse_into_a_closed_allowlist() {
        let list = parse_upstreams(
            "npm=https://registry.npmjs.org; \
             private=https://art.example.test/api/npm/internal,secret=ART_TOKEN,auth=basic:ci",
        )
        .unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.get("npm").unwrap().credential.is_none());
        let private = list.get("private").unwrap();
        assert_eq!(private.credential.as_deref(), Some("ART_TOKEN"));
        assert_eq!(private.auth, AuthScheme::Basic { user: "ci".into() });
        assert!(list.get("pypi").is_none(), "nothing that was not configured exists");
    }

    #[test]
    fn a_mistyped_option_is_an_error_and_not_a_silently_anonymous_upstream() {
        // `secert=` dropped silently would give an upstream that resolves without auth and 401s
        // halfway through a build, which is a far worse day than a refusal at startup.
        assert!(parse_upstreams("npm=https://r.test,secert=NPM_TOKEN").is_err());
        assert!(parse_upstreams("npm=https://r.test,secret").is_err());
        assert!(parse_upstreams("npm=https://r.test,auth=oauth").is_err());
        assert!(parse_upstreams("just-a-label").is_err());
        assert!(parse_upstreams("npm=not-a-url").is_err());
    }

    #[test]
    fn an_empty_upstream_string_is_an_empty_allowlist_not_an_error() {
        assert!(parse_upstreams("").unwrap().is_empty());
        assert!(parse_upstreams("  ; ; ").unwrap().is_empty());
    }

    #[test]
    fn a_rate_is_a_pair_and_a_zero_burst_is_refused() {
        assert_eq!(parse_rate("20/200").unwrap(), RateLimit::new(20, 200));
        assert_eq!(parse_rate(" 5 / 10 ").unwrap(), RateLimit::new(5, 10));
        // A zero burst refuses every request while looking configured.
        assert!(parse_rate("20/0").is_err());
        assert!(parse_rate("20").is_err());
        assert!(parse_rate("a/b").is_err());
    }

    #[test]
    fn on_with_an_empty_allowlist_serves_nothing() {
        let c = ProxyConfig { mode: ProxyMode::On, ..ProxyConfig::default() };
        assert!(!c.serves_anything(), "the composition root warns rather than pretending");
    }
}
