//! What the proxy fetched, and what it refused.
//!
//! Design D§7.5 lists "**Security telemetry** (new, because §14 is normative): seccomp denials,
//! egress-deny hits, metadata …" and says why: "an egress-deny hit is a job doing something it
//! shouldn't and is worth knowing about." The proxy is where the egress-deny hits are *visible* —
//! the sandbox's netns silently drops everything else, so a job reaching for an unallowlisted host
//! through the proxy is one of the few times hostile intent leaves a legible trace.
//!
//! Two records, kept separate because they answer different questions and have different retention
//! value: [`Fetch`] is "what did this build depend on" (a supply-chain question, and the input to any
//! future provenance attestation), and [`Refusal`] is "what did this job try that it was not allowed
//! to" (a security question).
//!
//! # What is deliberately not recorded
//!
//! The grant token, in any form. It appears in the request *path* — that is the cost of a
//! URL-carried bearer ([`crate::grant`]) — so [`redact_path`] strips it before anything is logged,
//! rather than trusting every call site to remember. Nor is any credential recorded: an audit record
//! names the upstream and the secret's *name*, never a value.

/// One successful (or attempted-and-answered) upstream fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetch {
    pub tenant: String,
    pub job_id: String,
    /// The allowlist label, not the hostname — an operator repointing `npm` at a mirror should not
    /// break their own log queries.
    pub upstream: String,
    /// Absolute upstream URL, with any grant token already stripped.
    pub url: String,
    pub method: String,
    pub status: u16,
    pub bytes: u64,
    /// Whether a tenant credential was spent. The *fact*, never the value — this is what tells an
    /// operator that a private registry was actually reached with auth rather than anonymously.
    pub authenticated: bool,
    /// How many redirects were followed to get here. Non-zero is worth noticing: each hop was
    /// re-checked against the allowlist, and a chain is an upstream behaving unusually.
    pub redirects: u8,
}

/// One refused request. The security-interesting record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// `None` when the grant itself did not authenticate — there is no job to attribute it to, which
    /// is itself the notable part.
    pub job_id: Option<String>,
    pub method: String,
    /// The job-facing path, token-redacted.
    pub path: String,
    /// The rule that refused it, from [`crate::allowlist::DenyReason`] or [`crate::grant::GrantError`].
    pub reason: String,
    pub status: u16,
}

/// Where audit records go.
///
/// A trait so the node/control plane can ship these into the same log pipeline as step output
/// (D§7.1) without this crate learning about it. The default implementation writes structured
/// `tracing` events, which is what a bring-up deployment has.
pub trait AuditSink: Send + Sync + std::fmt::Debug {
    fn fetched(&self, record: &Fetch);
    fn refused(&self, record: &Refusal);
}

/// Structured `tracing` events at `info` (fetches) and `warn` (refusals).
///
/// Refusals are `warn` rather than `info` deliberately: a job reaching for a host nobody allowlisted
/// is either a broken pipeline or an exfiltration attempt, and both are things an operator should see
/// without going looking.
#[derive(Debug, Default, Clone, Copy)]
pub struct TracingAudit;

impl AuditSink for TracingAudit {
    fn fetched(&self, r: &Fetch) {
        tracing::info!(
            target: "hull_ci_proxy::fetch",
            tenant = %r.tenant,
            job = %r.job_id,
            upstream = %r.upstream,
            method = %r.method,
            url = %r.url,
            status = r.status,
            bytes = r.bytes,
            authenticated = r.authenticated,
            redirects = r.redirects,
            "package fetch"
        );
    }

    fn refused(&self, r: &Refusal) {
        tracing::warn!(
            target: "hull_ci_proxy::refusal",
            job = r.job_id.as_deref().unwrap_or("<unauthenticated>"),
            method = %r.method,
            path = %r.path,
            reason = %r.reason,
            status = r.status,
            "package proxy refused a request"
        );
    }
}

/// Collects records in memory. For tests, and for the live probe that has to assert a fetch happened.
#[derive(Debug, Default)]
pub struct MemoryAudit {
    fetches: std::sync::Mutex<Vec<Fetch>>,
    refusals: std::sync::Mutex<Vec<Refusal>>,
}

impl MemoryAudit {
    pub fn new() -> Self {
        MemoryAudit::default()
    }

    pub fn fetches(&self) -> Vec<Fetch> {
        self.fetches.lock().expect("audit").clone()
    }

    pub fn refusals(&self) -> Vec<Refusal> {
        self.refusals.lock().expect("audit").clone()
    }
}

impl AuditSink for MemoryAudit {
    fn fetched(&self, r: &Fetch) {
        self.fetches.lock().expect("audit").push(r.clone());
    }

    fn refused(&self, r: &Refusal) {
        self.refusals.lock().expect("audit").push(r.clone());
    }
}

/// Strip a grant token out of a job-facing path before it is logged.
///
/// The token lives at `/j/<token>/...`, so this is a positional replacement rather than a pattern
/// match on the token's shape — a malformed token (the interesting case, since a *failed*
/// authentication is exactly what gets logged) must be redacted too, and by definition it does not
/// look like a token.
pub fn redact_path(path: &str) -> String {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    let mut parts = trimmed.splitn(3, '/');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("j"), Some(_token), rest) => format!("/j/<redacted>/{}", rest.unwrap_or("")),
        _ => path.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_grant_token_never_reaches_a_log_line() {
        // The cost of a URL-carried bearer, paid here once rather than at every call site.
        assert_eq!(
            redact_path("/j/hpkg_aabb.ccdd/u/npm/express"),
            "/j/<redacted>/u/npm/express"
        );
        // A *malformed* token is the case that matters most, because a failed authentication is
        // precisely what gets written to the refusal log.
        assert_eq!(redact_path("/j/garbage/u/npm/x"), "/j/<redacted>/u/npm/x");
        assert_eq!(redact_path("/j/hpkg_aabb.ccdd"), "/j/<redacted>/");
        // Paths that carry no token are left alone.
        assert_eq!(redact_path("/healthz"), "/healthz");
        assert_eq!(redact_path("/u/npm/express"), "/u/npm/express");
    }

    #[test]
    fn a_memory_sink_keeps_both_kinds_apart() {
        let audit = MemoryAudit::new();
        audit.fetched(&Fetch {
            tenant: "acme".into(),
            job_id: "job-1".into(),
            upstream: "npm".into(),
            url: "https://registry.npmjs.org/express".into(),
            method: "GET".into(),
            status: 200,
            bytes: 1234,
            authenticated: false,
            redirects: 0,
        });
        audit.refused(&Refusal {
            job_id: Some("job-1".into()),
            method: "GET".into(),
            path: "/j/<redacted>/u/pypi/x".into(),
            reason: "no upstream named `pypi` is allowlisted".into(),
            status: 403,
        });
        assert_eq!(audit.fetches().len(), 1);
        assert_eq!(audit.refusals().len(), 1);
        assert_eq!(audit.fetches()[0].bytes, 1234);
        assert!(audit.refusals()[0].reason.contains("pypi"));
    }

    #[test]
    fn a_fetch_record_names_the_credential_fact_and_never_a_value() {
        // The struct has no field a credential could go in; this test is the regression guard for
        // someone adding one.
        let r = Fetch {
            tenant: "acme".into(),
            job_id: "job-1".into(),
            upstream: "private".into(),
            url: "https://art.example.test/artifactory/api/npm/internal/lodash".into(),
            method: "GET".into(),
            status: 200,
            bytes: 10,
            authenticated: true,
            redirects: 0,
        };
        let rendered = format!("{r:?}");
        assert!(rendered.contains("authenticated: true"));
        assert!(!rendered.to_lowercase().contains("bearer"));
    }
}
