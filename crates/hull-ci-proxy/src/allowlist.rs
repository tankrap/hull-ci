//! The allowlist: which upstreams exist at all, and how a job-facing path becomes an upstream URL.
//!
//! Spec §14.3: "restrict egress to an allowlisted, authenticated **package proxy** — never the open
//! internet". The proxy is only a restriction if the allowlist is a *closed* set, so every function
//! here is deny-by-default: an upstream that was not configured is [`DenyReason::UnknownUpstream`],
//! not a pass-through.
//!
//! # Why hosts are matched exactly, and never by suffix
//!
//! The tempting shorthand for "allow npmjs.org" is `host.ends_with("npmjs.org")`, which also allows
//! `evil-npmjs.org` and `npmjs.org.attacker.test`. Both are registrable by anyone. So a host matches
//! only if it is byte-equal (ASCII-lowercased) to a configured host, and the port must match too — a
//! different port on the same host is a different service, and "the registry" is not "whatever else
//! that box is listening on".
//!
//! # Why the joined URL is re-checked
//!
//! [`Allowlist::resolve`] does not trust its own arithmetic. A tail like `//evil.example/x` is a
//! protocol-relative URL that [`Url::join`] will happily resolve to a *different host*, and
//! percent-encoded traversal (`..%2f..`) survives naive string checks. So the tail is screened for
//! traversal first, and then the joined result is re-validated against the upstream's own origin and
//! path prefix. If the answer moved, it is refused. Two independent checks, because the failure of
//! either one alone is an open proxy.

use std::collections::{BTreeMap, BTreeSet};

use url::Url;

/// How the proxy authenticates to one upstream (D§7.4: "the proxy holds upstream registry
/// credentials and authenticates outbound").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthScheme {
    /// `Authorization: Bearer <secret>` — npm, most modern registries.
    Bearer,
    /// `Authorization: Basic base64(<user>:<secret>)` — Artifactory, private PyPI, `cargo` mirrors.
    Basic { user: String },
    /// A named header carrying the raw value, for registries that invented their own
    /// (`X-JFrog-Art-Api`, `PRIVATE-TOKEN`).
    Header { name: String },
}

/// One configured upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    /// The label a job names in its URL (`/u/<name>/...`). Job-facing, so it is deliberately *not*
    /// the hostname: a job never needs to know which vendor is behind the label, and an operator can
    /// repoint `npm` at an internal mirror without every pipeline changing.
    pub name: String,
    /// Absolute base URL, including any path prefix the upstream requires. Every resolved URL must
    /// stay at or below this.
    pub base: Url,
    /// Name of the **tenant secret** holding this upstream's credential, resolved through the broker
    /// at request time (D§7.4). `None` for a public registry, which is the common case and must stay
    /// unauthenticated rather than acquiring a credential by accident.
    pub credential: Option<String>,
    pub auth: AuthScheme,
}

impl Upstream {
    /// A public, unauthenticated upstream.
    pub fn public(name: impl Into<String>, base: &str) -> Result<Upstream, AllowlistError> {
        Ok(Upstream {
            name: validated_label(name.into())?,
            base: parse_base(base)?,
            credential: None,
            auth: AuthScheme::Bearer,
        })
    }

    /// An upstream whose credential is the named tenant secret.
    pub fn authenticated(
        name: impl Into<String>,
        base: &str,
        credential: impl Into<String>,
        auth: AuthScheme,
    ) -> Result<Upstream, AllowlistError> {
        Ok(Upstream {
            name: validated_label(name.into())?,
            base: parse_base(base)?,
            credential: Some(credential.into()),
            auth,
        })
    }

    /// Scheme + host + port, the tuple that must be preserved across a join.
    fn origin(&self) -> (String, String, u16) {
        origin_of(&self.base)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AllowlistError {
    #[error("upstream label `{0}` is not valid (expected `[a-z0-9][a-z0-9._-]*`)")]
    BadLabel(String),
    #[error("upstream base `{url}` is not usable: {detail}")]
    BadBase { url: String, detail: String },
    #[error("upstream label `{0}` is configured twice")]
    Duplicate(String),
}

/// Why a request was refused. Every variant is a *log line an operator will read*, so they name the
/// rule rather than the symptom.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DenyReason {
    /// The deny-by-default answer. Nothing was configured under this label.
    #[error("no upstream named `{0}` is allowlisted")]
    UnknownUpstream(String),
    /// Allowlisted globally, but not in *this job's* grant (D§7.4: a grant "grants nothing but
    /// resolve packages for this job").
    #[error("upstream `{0}` is not in this job's grant")]
    NotGranted(String),
    #[error("`{0}` is not an absolute URL")]
    NotAbsolute(String),
    /// An absolute-form request naming a host nobody allowlisted. The interesting case, and the one
    /// suffix matching would have let through.
    #[error("host `{0}` is not allowlisted")]
    HostNotAllowlisted(String),
    #[error("path `{0}` escapes the upstream's base path")]
    PathEscape(String),
    /// The join moved the answer somewhere else — a protocol-relative tail, an embedded scheme.
    #[error("resolved URL `{0}` left the upstream's origin")]
    OriginEscape(String),
    #[error("method `{0}` is not permitted; a package proxy resolves, it does not publish")]
    MethodNotAllowed(String),
}

/// The closed set of upstreams this deployment will talk to.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    by_label: BTreeMap<String, Upstream>,
}

impl Allowlist {
    pub fn new() -> Self {
        Allowlist::default()
    }

    /// Build from a list, refusing duplicates.
    ///
    /// A duplicate label is an error rather than a last-one-wins overwrite: two entries for `npm`
    /// means an operator believes both are in force, and silently dropping one is how a request ends
    /// up at the upstream nobody audited.
    pub fn from_upstreams(upstreams: Vec<Upstream>) -> Result<Allowlist, AllowlistError> {
        let mut list = Allowlist::new();
        for u in upstreams {
            if list.by_label.contains_key(&u.name) {
                return Err(AllowlistError::Duplicate(u.name));
            }
            list.by_label.insert(u.name.clone(), u);
        }
        Ok(list)
    }

    pub fn is_empty(&self) -> bool {
        self.by_label.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_label.len()
    }

    pub fn labels(&self) -> Vec<&str> {
        self.by_label.keys().map(String::as_str).collect()
    }

    pub fn get(&self, label: &str) -> Option<&Upstream> {
        self.by_label.get(label)
    }

    /// The tenant-secret names backing the authenticated upstreams among `labels`.
    ///
    /// This is what control puts in a job's
    /// [`ProxyCapabilityRequest`](hull_ci_secrets::ProxyCapabilityRequest): the credentials the proxy
    /// may spend for this job are bounded by *this job's* slice of the allowlist, not by the
    /// deployment's whole set. A job granted only `npm` cannot cause the private registry's token to
    /// be redeemed, because that token was never in the capability.
    ///
    /// A label with no entry is silently skipped rather than erroring: the grant's set is the
    /// caller's, this function's job is to describe what exists under it, and a request naming an
    /// unknown label is already refused at [`Allowlist::resolve`] with a reason that says so.
    pub fn credential_names_for<'a>(
        &self,
        labels: impl IntoIterator<Item = &'a str>,
    ) -> BTreeSet<String> {
        labels
            .into_iter()
            .filter_map(|label| self.by_label.get(label))
            .filter_map(|u| u.credential.clone())
            .collect()
    }

    /// Whether any configured upstream authenticates at all.
    ///
    /// Used at startup to decide whether an absent credential source is a benign fact (every
    /// upstream is public) or a deployment that will refuse half its requests — see
    /// [`crate::server::PackageProxy::new`].
    pub fn has_authenticated_upstream(&self) -> bool {
        self.by_label.values().any(|u| u.credential.is_some())
    }

    /// Resolve `/u/<label>/<tail>` into an absolute upstream URL.
    ///
    /// `tail` is everything after the label, **including** any query string, exactly as the job sent
    /// it. It is attacker-controlled: a job's `package.json` decides it.
    pub fn resolve(&self, label: &str, tail: &str) -> Result<(&Upstream, Url), DenyReason> {
        let upstream =
            self.by_label.get(label).ok_or_else(|| DenyReason::UnknownUpstream(label.to_string()))?;

        // First screen: reject the shapes that make a join mean something other than "append".
        // Checked on the raw tail *and* on a percent-decoded view, because `..%2f` is a traversal a
        // string comparison against `..` alone does not see.
        reject_traversal(tail)?;

        // `Url::join` needs the base to end in `/` for the tail to be appended rather than to replace
        // the last segment. `parse_base` guarantees that, so this is an append.
        let joined = upstream
            .base
            .join(tail.trim_start_matches('/'))
            .map_err(|_| DenyReason::PathEscape(tail.to_string()))?;

        // Second screen, independent of the first: did we end up where we meant to?
        if origin_of(&joined) != upstream.origin() {
            return Err(DenyReason::OriginEscape(joined.to_string()));
        }
        if !joined.path().starts_with(upstream.base.path()) {
            return Err(DenyReason::PathEscape(joined.path().to_string()));
        }
        Ok((upstream, joined))
    }

    /// Resolve an **absolute-form** request URI (`GET https://registry.npmjs.org/express`), the shape
    /// an `http_proxy`-configured client sends.
    ///
    /// Matched on origin, exactly. The upstream's path prefix still applies, so an upstream scoped to
    /// `https://host/artifactory/api/npm/` does not become "all of `host`".
    pub fn resolve_absolute(&self, raw: &str) -> Result<(&Upstream, Url), DenyReason> {
        let url = Url::parse(raw).map_err(|_| DenyReason::NotAbsolute(raw.to_string()))?;
        if url.host_str().is_none() {
            return Err(DenyReason::NotAbsolute(raw.to_string()));
        }
        let origin = origin_of(&url);
        let upstream = self
            .by_label
            .values()
            .find(|u| u.origin() == origin && url.path().starts_with(u.base.path()))
            .ok_or_else(|| DenyReason::HostNotAllowlisted(host_port(&url)))?;
        // A credential in the URL is the job trying to talk *past* us to the upstream. There is
        // nothing legitimate it can mean here: authentication terminates at the proxy (D§7.4).
        if !url.username().is_empty() || url.password().is_some() {
            return Err(DenyReason::HostNotAllowlisted(host_port(&url)));
        }
        Ok((upstream, url))
    }
}

/// Methods a package proxy serves.
///
/// D§7.4 scopes a job's grant to "resolve packages for this job". Resolution is reads, so writes are
/// refused — and that refusal is doing real work: `PUT`/`POST` to an allowlisted host is a
/// ready-made exfiltration channel out of a sandbox that otherwise has no egress at all, and
/// `npm publish` from inside CI is not a thing this proxy is for. An operator who wants publishing
/// wants a different, separately-audited path.
pub const ALLOWED_METHODS: &[&str] = &["GET", "HEAD"];

pub fn check_method(method: &str) -> Result<(), DenyReason> {
    if ALLOWED_METHODS.contains(&method) {
        Ok(())
    } else {
        Err(DenyReason::MethodNotAllowed(method.to_string()))
    }
}

/// Screen a job-supplied tail for the constructs that turn a join into a redirect.
fn reject_traversal(tail: &str) -> Result<(), DenyReason> {
    let deny = || DenyReason::PathEscape(tail.to_string());
    // A leading `//` is protocol-relative: `join("//evil.example/x")` resolves to `evil.example`.
    if tail.starts_with("//") || tail.starts_with("/\\") || tail.starts_with('\\') {
        return Err(deny());
    }
    // An embedded scheme replaces the base outright.
    if tail.contains("://") {
        return Err(deny());
    }
    // `..` in any form. The decoded view catches `..%2f`, `%2e%2e/` and friends; a decode failure is
    // itself a refusal, since we will not forward what we could not read.
    let decoded = percent_decode(tail).ok_or_else(deny)?;
    for view in [tail, decoded.as_str()] {
        if view.split(['/', '\\']).any(|seg| seg == ".." || seg == "%2e%2e") {
            return Err(deny());
        }
        // A NUL or a newline in a path is a request-smuggling attempt, not a package name.
        if view.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(deny());
        }
    }
    Ok(())
}

/// Decode `%XX` escapes once, for the traversal screen only. Never used to build the outgoing URL —
/// that stays in the job's original encoding so the upstream sees the path the client meant.
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            let hex = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn origin_of(url: &Url) -> (String, String, u16) {
    (
        url.scheme().to_ascii_lowercase(),
        url.host_str().unwrap_or_default().to_ascii_lowercase(),
        // `port_or_known_default` so `https://h` and `https://h:443` are the same origin, and
        // `https://h:8443` is not.
        url.port_or_known_default().unwrap_or(0),
    )
}

fn host_port(url: &Url) -> String {
    match url.port() {
        Some(p) => format!("{}:{p}", url.host_str().unwrap_or_default()),
        None => url.host_str().unwrap_or_default().to_string(),
    }
}

/// Labels appear in a URL path and in log lines, so they are restricted to a shape that cannot be
/// mistaken for a path segment of its own.
fn validated_label(label: String) -> Result<String, AllowlistError> {
    let ok = !label.is_empty()
        && label.len() <= 64
        && label.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && label.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(label)
    } else {
        Err(AllowlistError::BadLabel(label))
    }
}

/// Parse and normalize an upstream base URL.
///
/// Two normalizations, both load-bearing rather than cosmetic:
///
/// * **A trailing `/` is forced**, because `Url::join` replaces the final segment of a base that
///   lacks one — so `https://host/artifactory` + `express` would resolve to `https://host/express`,
///   silently widening the upstream from one repository to the whole server.
/// * **Userinfo is refused.** A credential belongs in the secret broker, not in a configuration
///   string that will be logged, and `https://user:pass@host/` is also the classic way to make a URL
///   *look* like it points at `user` when it points at `host`.
fn parse_base(raw: &str) -> Result<Url, AllowlistError> {
    let bad = |detail: &str| AllowlistError::BadBase { url: raw.to_string(), detail: detail.into() };
    let mut url = Url::parse(raw).map_err(|e| bad(&e.to_string()))?;
    if !matches!(url.scheme(), "https" | "http") {
        return Err(bad("scheme must be https or http"));
    }
    if url.host_str().is_none() {
        return Err(bad("no host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(bad("credentials belong in the secret broker, not in the base URL"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(bad("a base URL may not carry a query or fragment"));
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list() -> Allowlist {
        Allowlist::from_upstreams(vec![
            Upstream::public("npm", "https://registry.npmjs.org").unwrap(),
            Upstream::authenticated(
                "private",
                "https://art.example.test/artifactory/api/npm/internal",
                "ARTIFACTORY_TOKEN",
                AuthScheme::Bearer,
            )
            .unwrap(),
        ])
        .unwrap()
    }

    #[test]
    fn an_upstream_nobody_configured_is_refused_rather_than_proxied() {
        // The deny-by-default answer, which is the entire point of the allowlist (§14.3).
        let err = list().resolve("pypi", "simple/requests/").unwrap_err();
        assert_eq!(err, DenyReason::UnknownUpstream("pypi".into()));
    }

    #[test]
    fn a_configured_upstream_resolves_to_a_url_under_its_base() {
        let l = list();
        let (u, url) = l.resolve("npm", "express/-/express-4.18.2.tgz").unwrap();
        assert_eq!(u.name, "npm");
        assert_eq!(url.as_str(), "https://registry.npmjs.org/express/-/express-4.18.2.tgz");

        // A base with a path prefix keeps it — the upstream is one repository, not a whole server.
        let (_, url) = l.resolve("private", "lodash").unwrap();
        assert_eq!(url.as_str(), "https://art.example.test/artifactory/api/npm/internal/lodash");
    }

    #[test]
    fn a_base_without_a_trailing_slash_does_not_widen_to_the_whole_server() {
        // The `Url::join` footgun: without the forced trailing slash this resolves to
        // `https://art.example.test/lodash`, which is a different (and unaudited) upstream.
        let u = Upstream::public("art", "https://art.example.test/artifactory/api/npm/internal").unwrap();
        assert!(u.base.as_str().ends_with('/'));
        let l = Allowlist::from_upstreams(vec![u]).unwrap();
        let (_, url) = l.resolve("art", "lodash").unwrap();
        assert!(url.as_str().starts_with("https://art.example.test/artifactory/api/npm/internal/"));
    }

    #[test]
    fn path_traversal_cannot_walk_out_of_the_upstreams_base() {
        let l = list();
        for tail in [
            "../../etc/passwd",
            "a/../../../x",
            "..%2f..%2fx",
            "%2e%2e/%2e%2e/x",
            "a/..\\..\\x",
        ] {
            assert!(matches!(l.resolve("private", tail), Err(DenyReason::PathEscape(_))), "{tail}");
        }
    }

    #[test]
    fn a_protocol_relative_tail_cannot_move_the_request_to_another_host() {
        // The one that a naive `format!("{base}{tail}")` and even a plain `Url::join` get wrong:
        // `join("//evil.example/x")` resolves to `https://evil.example/x`, keeping only the scheme.
        let l = list();
        for tail in ["//evil.example/x", "https://evil.example/x", "/\\evil.example/x"] {
            let err = l.resolve("npm", tail).unwrap_err();
            assert!(
                matches!(err, DenyReason::PathEscape(_) | DenyReason::OriginEscape(_)),
                "{tail} gave {err:?}"
            );
        }
    }

    #[test]
    fn control_characters_in_a_path_are_refused() {
        // Request smuggling, not a package name.
        let l = list();
        assert!(l.resolve("npm", "express\r\nX-Injected: 1").is_err());
        assert!(l.resolve("npm", "express%00.tgz").is_err());
    }

    #[test]
    fn hosts_match_exactly_and_never_by_suffix() {
        // `ends_with("npmjs.org")` would allow every one of these, and all of them are registrable.
        let l = list();
        for raw in [
            "https://evil-npmjs.org/express",
            "https://registry.npmjs.org.attacker.test/express",
            "https://attacker.test/registry.npmjs.org/express",
        ] {
            assert!(
                matches!(l.resolve_absolute(raw), Err(DenyReason::HostNotAllowlisted(_))),
                "{raw} must not match"
            );
        }
        assert!(l.resolve_absolute("https://registry.npmjs.org/express").is_ok());
        // Case folding on the host, because DNS is case-insensitive and an allowlist that is not
        // would be bypassed by `REGISTRY.NPMJS.ORG`.
        assert!(l.resolve_absolute("https://REGISTRY.NPMJS.ORG/express").is_ok());
    }

    #[test]
    fn a_different_port_or_scheme_is_a_different_upstream() {
        let l = list();
        assert!(l.resolve_absolute("https://registry.npmjs.org:8443/express").is_err());
        assert!(l.resolve_absolute("http://registry.npmjs.org/express").is_err());
        // …but the default port spelled out explicitly is the same origin.
        assert!(l.resolve_absolute("https://registry.npmjs.org:443/express").is_ok());
    }

    #[test]
    fn userinfo_is_refused_on_both_sides() {
        // In a base: a credential in a config string that gets logged. In a request: the job trying
        // to authenticate to the upstream itself, past the proxy where auth is supposed to terminate.
        assert!(matches!(
            Upstream::public("npm", "https://user:pw@registry.npmjs.org"),
            Err(AllowlistError::BadBase { .. })
        ));
        assert!(list().resolve_absolute("https://u:p@registry.npmjs.org/express").is_err());
    }

    #[test]
    fn absolute_form_respects_the_upstreams_path_prefix() {
        let l = list();
        assert!(l.resolve_absolute("https://art.example.test/artifactory/api/npm/internal/lodash").is_ok());
        // Same host, outside the configured repository.
        assert!(l.resolve_absolute("https://art.example.test/artifactory/api/npm/secret/x").is_err());
        assert!(l.resolve_absolute("https://art.example.test/").is_err());
    }

    #[test]
    fn only_reads_are_served() {
        // A `PUT` to an allowlisted host is an exfiltration channel out of a sandbox that has no
        // other egress at all.
        assert!(check_method("GET").is_ok() && check_method("HEAD").is_ok());
        for m in ["PUT", "POST", "DELETE", "PATCH", "CONNECT", "OPTIONS"] {
            assert!(matches!(check_method(m), Err(DenyReason::MethodNotAllowed(_))), "{m}");
        }
    }

    #[test]
    fn labels_and_bases_are_validated_at_configuration_time() {
        assert!(matches!(Upstream::public("Npm", "https://x.test"), Err(AllowlistError::BadLabel(_))));
        assert!(matches!(Upstream::public("a/b", "https://x.test"), Err(AllowlistError::BadLabel(_))));
        assert!(matches!(Upstream::public("", "https://x.test"), Err(AllowlistError::BadLabel(_))));
        assert!(matches!(Upstream::public("npm", "ftp://x.test"), Err(AllowlistError::BadBase { .. })));
        assert!(matches!(Upstream::public("npm", "not-a-url"), Err(AllowlistError::BadBase { .. })));
        assert!(matches!(
            Upstream::public("npm", "https://x.test/?a=1"),
            Err(AllowlistError::BadBase { .. })
        ));
    }

    #[test]
    fn a_duplicate_label_is_refused_rather_than_overwritten() {
        let dup = Allowlist::from_upstreams(vec![
            Upstream::public("npm", "https://a.test").unwrap(),
            Upstream::public("npm", "https://b.test").unwrap(),
        ]);
        assert!(matches!(dup, Err(AllowlistError::Duplicate(_))));
    }

    #[test]
    fn an_empty_allowlist_serves_nothing() {
        // The default posture: a proxy with no configured upstream is not an open proxy.
        let l = Allowlist::new();
        assert!(l.is_empty());
        assert!(l.resolve("npm", "express").is_err());
        assert!(l.resolve_absolute("https://registry.npmjs.org/express").is_err());
    }
}
