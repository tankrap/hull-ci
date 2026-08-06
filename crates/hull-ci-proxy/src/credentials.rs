//! Upstream credentials: held here, spent outbound, never handed to a job.
//!
//! D§7.4: "**Package auth still terminates at the proxy** where it can: the proxy holds upstream
//! registry credentials and authenticates outbound; the job talks to it over a per-job URL with a
//! per-job bearer." And: "This is also how **private base images and private package registries**
//! work: the pull/proxy credential is just a tenant secret, so the job gets its dependencies without
//! ever seeing it."
//!
//! So the credential is a *tenant* secret, resolved through the broker, and the whole value of this
//! module is that it flows in exactly one direction.
//!
//! # The three ways a credential leaks back into a job, and what stops each
//!
//! 1. **Reflected in the response.** An upstream that echoes `Authorization` into a body or a header
//!    would hand the job the token. Response headers are rebuilt from an allowlist
//!    ([`crate::server::response_headers`]) rather than copied, so an echo in a header is dropped.
//! 2. **Reflected in an error.** A 401 body from an upstream frequently quotes the credential it
//!    rejected. [`CredentialSet::masker`] registers every live value with
//!    [`hull_ci_secrets::Masker`], and error text the proxy generates goes through it.
//! 3. **Followed to somewhere else.** A `302` to an attacker-controlled host, with the
//!    `Authorization` header carried along, is the classic one — and it is why the proxy follows
//!    redirects itself, re-running the allowlist on each hop and re-deriving the credential from the
//!    *new* upstream rather than forwarding the old header ([`crate::server`]).
//!
//! What is **not** claimed: response *bodies* are streamed through unexamined. A tarball is not text,
//! masking it would corrupt it, and buffering hundreds of megabytes to scan it would defeat the
//! streaming. The mitigation is upstream of that — the job never sent the credential, so an upstream
//! has no honest reason to return it — and the residual risk is a hostile *upstream*, which is
//! already outside what an allowlist can help with.
//!
//! # Why a lookup carries the job, and why it used to not
//!
//! This module used to say: "Note what the trait does **not** take: a job id. A job's grant decides
//! which upstreams it may reach; it does not decide whose credential is spent. Threading a job id in
//! here would create the question *may this job use that tenant's token?* at a layer with no standing
//! to answer it."
//!
//! That was wrong, and wiring the real broker behind this seam is what showed it. The question is
//! not avoidable — it is the *only* question, and D§1's secret-bleed row already answers it: never
//! for an `outsider`-authored job. What the old wording got right is that this layer has no standing
//! to answer it, and that is exactly why the job travels: [`hull_ci_secrets::package`] mints a
//! capability bounded by the job, control decides at mint time whether the job may spend a tenant
//! credential at all, and this layer only *carries* the attribution to the layer that has standing.
//! A lookup with no job attached is one nobody can refuse.

use std::collections::BTreeMap;

use hull_ci_secrets::{Masker, SecretBytes};

use crate::allowlist::{AuthScheme, Upstream};
use crate::grant::Grant;

/// One credential lookup, attributed.
///
/// Every field is derived from an *authenticated* per-job grant ([`crate::grant`]) or from the
/// deployment allowlist — never from anything the job sent. A job cannot name a tenant, a job id or
/// a secret; it names an upstream label, and the label is resolved against a closed set.
#[derive(Debug, Clone, Copy)]
pub struct CredentialRequest<'a> {
    pub tenant: &'a str,
    /// The job whose grant authorised the request that needs this credential. This is what makes the
    /// disclosure attributable, and what a broker-backed source bounds its capability by.
    pub job_id: &'a str,
    /// The upstream label, for error text an operator will read.
    pub upstream: &'a str,
    /// The tenant secret's name, from the allowlist entry.
    pub secret: &'a str,
}

/// Where the proxy gets an upstream's credential.
///
/// A trait rather than a direct dependency on [`hull_ci_secrets::ProxyCredentialService`] for the
/// same reason the broker keeps its store behind one: the proxy needs a *value*, and how a
/// deployment custodies that value — a broker over a KMS, a static map in dev, nothing at all — is
/// not this crate's business. [`BrokeredCredentials`](crate::brokered::BrokeredCredentials) is the
/// real one; [`NoCredentials`] is the honest default.
///
/// The method returns a `Result` rather than an `Option` because the reasons a lookup comes back
/// empty are not interchangeable, and the proxy owes an operator the difference: a credential the
/// broker does not hold is a misconfiguration, a job with no authority to spend one is a policy
/// refusal, and a job the proxy was never told about is a wiring bug. An `Option` collapses all
/// three into "401 from the registry, good luck".
pub trait UpstreamCredentials: Send + Sync + std::fmt::Debug {
    /// The credential for one attributed lookup.
    fn credential(&self, req: &CredentialRequest<'_>) -> Result<SecretBytes, CredentialError>;

    /// Drop everything held for a finished job.
    ///
    /// Defaulted to a no-op because a source that holds nothing has nothing to drop, and because a
    /// source that *does* — the broker-backed one holds plaintext for the life of a job's grant —
    /// must be reachable from [`crate::server::PackageProxy::release_job`] without the server
    /// crate having to know which implementation it built. §14.1's "nothing survives into the next
    /// job", applied to the one piece of a job's state that does not live in a rootfs.
    fn release_job(&self, _job_id: &str) {}
}

/// The header one authenticated request carries.
///
/// A distinct type, rather than a `(String, String)`, so that the value is [`SecretBytes`]-derived
/// all the way to the point it is written onto the wire and cannot be `format!`ed into a log by
/// accident.
pub struct Injected {
    pub header: String,
    value: SecretBytes,
}

impl Injected {
    /// The header value. Named `expose` so every use site is greppable.
    pub fn expose(&self) -> &[u8] {
        self.value.expose()
    }
}

impl std::fmt::Debug for Injected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The header *name* is safe and useful (it says which scheme was used); the value never is.
        f.debug_struct("Injected").field("header", &self.header).field("value", &"<redacted>").finish()
    }
}

/// Build the outbound authentication header for one upstream, on behalf of one job.
///
/// Returns `Ok(None)` for a public upstream — the common case, which must stay unauthenticated. A
/// public registry that starts receiving an `Authorization` header because someone reused a config
/// block is a credential disclosure to a third party.
///
/// The `grant` is the *authenticated* per-job grant, so the tenant whose credential gets spent is
/// the tenant whose job is asking. There is no path here by which a request influences that: the
/// grant's tenant was fixed when control minted it.
pub fn inject(
    upstream: &Upstream,
    grant: &Grant,
    creds: &dyn UpstreamCredentials,
) -> Result<Option<Injected>, CredentialError> {
    let Some(name) = &upstream.credential else {
        return Ok(None);
    };
    let secret = creds.credential(&CredentialRequest {
        tenant: &grant.tenant,
        job_id: &grant.job_id,
        upstream: &upstream.name,
        secret: name,
    })?;
    let value = match &upstream.auth {
        AuthScheme::Bearer => {
            let token = secret.expose_str().ok_or(CredentialError::NotUtf8)?;
            SecretBytes::new(format!("Bearer {token}").into_bytes())
        }
        AuthScheme::Basic { user } => {
            let pass = secret.expose_str().ok_or(CredentialError::NotUtf8)?;
            SecretBytes::new(format!("Basic {}", base64(format!("{user}:{pass}").as_bytes())).into_bytes())
        }
        AuthScheme::Header { .. } => secret.clone(),
    };
    // Header values are ASCII-ish by protocol; a secret containing a newline would let a
    // misconfigured registry token split the outbound request into two.
    if value.expose().iter().any(|b| *b < 0x20 || *b == 0x7f) {
        return Err(CredentialError::NotHeaderSafe { upstream: upstream.name.clone() });
    }
    let header = match &upstream.auth {
        AuthScheme::Bearer | AuthScheme::Basic { .. } => "authorization".to_string(),
        AuthScheme::Header { name } => name.to_ascii_lowercase(),
    };
    Ok(Some(Injected { header, value }))
}

/// Why a credential could not be spent.
///
/// Every variant is a request the proxy **refused to make**. There is deliberately no variant that
/// means "carry on without one": a silent downgrade to an anonymous request surfaces as a confusing
/// 401 from the upstream instead of the condition it actually is, and — the part that matters — a
/// deployment that looks configured but is quietly unauthenticated is indistinguishable from a
/// working one until a private package fails to resolve.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    /// The upstream is configured to authenticate and the source has no such secret for this tenant.
    #[error("upstream `{upstream}` needs secret `{name}`, which this tenant does not have")]
    Missing { upstream: String, name: String },
    /// **The default posture.** No credential source is configured at all, and an authenticated
    /// upstream was asked for.
    ///
    /// A distinct variant from [`CredentialError::Missing`] because they call for different fixes:
    /// one deployment forgot to store a secret, the other never wired a broker. Both refuse.
    #[error(
        "upstream `{upstream}` needs secret `{name}` but this proxy has no credential source \
         configured; it will not make an unauthenticated request in its place"
    )]
    NoSource { upstream: String, name: String },
    /// Control registered this job and said it may spend no tenant credential — an
    /// `outsider`-authored job (D§1, D§7.4), or a deployment running with the broker off.
    ///
    /// A *policy* answer, not a failure: the job asked something it is not entitled to ask.
    #[error("job `{job_id}` may not spend a tenant credential for upstream `{upstream}`: {reason}")]
    NoAuthority { job_id: String, upstream: String, reason: String },
    /// The proxy was never told about this job, so it has no capability to redeem for it.
    ///
    /// Fails closed, and is a *wiring* bug rather than a job's problem: control minted a package
    /// grant without minting the matching credential capability. Named separately so it reads as the
    /// operator error it is instead of hiding inside "missing credential".
    #[error(
        "job `{job_id}` has no upstream-credential capability registered with this proxy; \
         control minted a package grant without one"
    )]
    Unregistered { job_id: String },
    /// The job's grant names one tenant and the capability the proxy holds for it names another.
    ///
    /// Unreachable through a correct control plane, and refused loudly rather than resolved in
    /// either direction: it is the shape a cross-tenant bug takes, and guessing which side is right
    /// would be guessing whose credential to spend.
    #[error("job `{job_id}` is registered under tenant `{registered}` but its grant says `{presented}`")]
    TenantMismatch { job_id: String, registered: String, presented: String },
    /// The credential source refused or could not answer. Carries the broker's own refusal text,
    /// which names *no* value — every [`hull_ci_secrets::SecretError`] is a policy or crypto answer.
    #[error("upstream credential for `{upstream}` could not be obtained: {detail}")]
    Unavailable { upstream: String, detail: String },
    #[error("credential is not valid UTF-8 and cannot be put in a header")]
    NotUtf8,
    /// A credential containing a control character would let a header value split the request.
    #[error("credential for upstream `{upstream}` contains bytes that are not header-safe")]
    NotHeaderSafe { upstream: String },
}

impl CredentialError {
    /// Whose problem this is: the job's, or the operator's.
    ///
    /// A named function with an exhaustive match rather than a `_ =>` arm, because the whole point of
    /// the variants above is that they are not interchangeable — and a wildcard would silently
    /// classify the next one added, which is how a policy refusal comes to look like an outage.
    pub fn is_policy_refusal(&self) -> bool {
        match self {
            // The job (or rather its author) asked for something it is not entitled to, and the
            // cross-tenant case is refused on the same footing because serving it would be a
            // disclosure.
            CredentialError::NoAuthority { .. } | CredentialError::TenantMismatch { .. } => true,
            // Everything else is a configuration or infrastructure condition. The job's request was
            // well-formed and the proxy could not complete it.
            CredentialError::Missing { .. }
            | CredentialError::NoSource { .. }
            | CredentialError::Unregistered { .. }
            | CredentialError::Unavailable { .. }
            | CredentialError::NotUtf8
            | CredentialError::NotHeaderSafe { .. } => false,
        }
    }
}

/// No credential source at all. **The default, and it refuses rather than downgrades.**
///
/// A deployment with public upstreams only wants exactly this: every request it serves is
/// unauthenticated *because none of its upstreams asks for authentication*, which is a different
/// state from "authenticated upstreams configured, credentials silently absent". This type keeps the
/// two distinguishable — a public upstream resolves normally, and an authenticated one is refused
/// with [`CredentialError::NoSource`] naming the secret nobody wired.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoCredentials;

impl UpstreamCredentials for NoCredentials {
    fn credential(&self, req: &CredentialRequest<'_>) -> Result<SecretBytes, CredentialError> {
        Err(CredentialError::NoSource {
            upstream: req.upstream.to_string(),
            name: req.secret.to_string(),
        })
    }
}

/// An in-memory credential source. **Development and test only** — it is exactly what
/// [`hull_ci_secrets::DevKeyManager`] is to the broker, and
/// [`BrokeredCredentials`](crate::brokered::BrokeredCredentials) is the real one.
///
/// Note what it ignores: the job. It answers on `(tenant, name)` alone, so it cannot refuse an
/// outsider-authored job and cannot bound a disclosure to the job that occasioned it. That is
/// precisely the gap the broker path exists to close, and the reason this type is dev-only is that
/// gap rather than where the bytes are stored.
#[derive(Debug, Default)]
pub struct StaticCredentials {
    by_tenant: BTreeMap<(String, String), Vec<u8>>,
}

impl StaticCredentials {
    pub fn new() -> Self {
        StaticCredentials::default()
    }

    pub fn with(mut self, tenant: &str, name: &str, value: &str) -> Self {
        self.by_tenant.insert((tenant.to_string(), name.to_string()), value.as_bytes().to_vec());
        self
    }
}

impl UpstreamCredentials for StaticCredentials {
    fn credential(&self, req: &CredentialRequest<'_>) -> Result<SecretBytes, CredentialError> {
        self.by_tenant
            .get(&(req.tenant.to_string(), req.secret.to_string()))
            .map(|v| SecretBytes::new(v.clone()))
            .ok_or_else(|| CredentialError::Missing {
                upstream: req.upstream.to_string(),
                name: req.secret.to_string(),
            })
    }
}

/// Every credential a set of upstreams could spend for one job, gathered so they can be registered
/// with a [`Masker`].
///
/// D§7.4 is explicit that masking "is a backstop, not a control" — it is exact-substring redaction
/// and falls to base64/split/transform. It is here for the accident (a proxy error message quoting an
/// upstream's 401 body), not for the adversary. The control is that the job never receives the value.
#[derive(Debug, Default)]
pub struct CredentialSet {
    values: Vec<SecretBytes>,
}

impl CredentialSet {
    /// Every credential the given upstreams could spend for this job.
    ///
    /// Silently skips an upstream whose credential is unavailable *for any reason*: this builds a
    /// **masker**, and a value that cannot be obtained cannot appear in output. The refusal belongs
    /// to [`inject`], on the request that actually needed it, where it can be a status code with a
    /// reason rather than a silent omission from a redaction list.
    pub fn gather<'a>(
        upstreams: impl IntoIterator<Item = &'a Upstream>,
        grant: &Grant,
        creds: &dyn UpstreamCredentials,
    ) -> Self {
        let mut set = CredentialSet::default();
        for u in upstreams {
            let Some(name) = u.credential.as_deref() else { continue };
            let req = CredentialRequest {
                tenant: &grant.tenant,
                job_id: &grant.job_id,
                upstream: &u.name,
                secret: name,
            };
            if let Ok(secret) = creds.credential(&req) {
                set.push(secret);
            }
        }
        set
    }

    pub fn push(&mut self, secret: SecretBytes) {
        self.values.push(secret);
    }

    pub fn masker(&self) -> Masker {
        let mut m = Masker::new();
        for v in &self.values {
            m.register(v.expose());
        }
        m
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// Standard base64, no padding omitted. Hand-rolled to avoid a dependency for 20 lines, and
/// deliberately not constant-time: the input is already a credential in memory and the output goes
/// straight onto a socket, so there is no secret-dependent branch a timing attacker could be on the
/// other side of.
fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratelimit::RateLimit;
    use std::collections::BTreeSet;

    fn creds() -> StaticCredentials {
        StaticCredentials::new()
            .with("acme", "NPM_TOKEN", "npm_s3cr3tvalue")
            .with("acme", "ART_USER_PW", "hunter2")
    }

    /// A grant is the only way a tenant reaches [`inject`], so the tests build one rather than
    /// passing a bare string — which is the property under test as much as anything below.
    fn grant(tenant: &str) -> Grant {
        let reg = crate::grant::GrantRegistry::new();
        let (_, grant) =
            reg.mint(tenant, "job-1", BTreeSet::new(), u64::MAX / 2, RateLimit::default());
        grant
    }

    #[test]
    fn a_public_upstream_is_never_given_a_credential() {
        // Sending a private token to a public registry is a disclosure to a third party, and the
        // easiest way to ship it is to reuse a config block.
        let u = Upstream::public("npm", "https://registry.npmjs.org").unwrap();
        assert!(inject(&u, &grant("acme"), &creds()).unwrap().is_none());
        // …including when there is no credential source at all: a public upstream must still work.
        assert!(inject(&u, &grant("acme"), &NoCredentials).unwrap().is_none());
    }

    #[test]
    fn a_bearer_upstream_gets_the_tenants_secret_in_an_authorization_header() {
        let u = Upstream::authenticated("npm", "https://r.test", "NPM_TOKEN", AuthScheme::Bearer).unwrap();
        let injected = inject(&u, &grant("acme"), &creds()).unwrap().unwrap();
        assert_eq!(injected.header, "authorization");
        assert_eq!(injected.expose(), b"Bearer npm_s3cr3tvalue");
    }

    #[test]
    fn a_basic_upstream_gets_the_user_and_secret_base64ed() {
        let u = Upstream::authenticated(
            "art",
            "https://a.test",
            "ART_USER_PW",
            AuthScheme::Basic { user: "ci".into() },
        )
        .unwrap();
        let injected = inject(&u, &grant("acme"), &creds()).unwrap().unwrap();
        // `ci:hunter2`
        assert_eq!(injected.expose(), b"Basic Y2k6aHVudGVyMg==");
    }

    #[test]
    fn a_custom_header_upstream_gets_the_raw_value_under_its_own_name() {
        let u = Upstream::authenticated(
            "art",
            "https://a.test",
            "NPM_TOKEN",
            AuthScheme::Header { name: "X-JFrog-Art-Api".into() },
        )
        .unwrap();
        let injected = inject(&u, &grant("acme"), &creds()).unwrap().unwrap();
        assert_eq!(injected.header, "x-jfrog-art-api", "header names are matched lowercased");
        assert_eq!(injected.expose(), b"npm_s3cr3tvalue");
    }

    #[test]
    fn a_missing_credential_is_refused_rather_than_downgraded_to_anonymous() {
        // A silent downgrade surfaces as a puzzling 401 from the upstream instead of the
        // configuration error it actually is.
        let u = Upstream::authenticated("npm", "https://r.test", "NO_SUCH", AuthScheme::Bearer).unwrap();
        assert_eq!(
            inject(&u, &grant("acme"), &creds()).unwrap_err(),
            CredentialError::Missing { upstream: "npm".into(), name: "NO_SUCH".into() }
        );
        // A different tenant is a different answer: the credential is the tenant's, not the proxy's.
        assert!(matches!(
            inject(
                &Upstream::authenticated("npm", "https://r.test", "NPM_TOKEN", AuthScheme::Bearer).unwrap(),
                &grant("other-tenant"),
                &creds()
            ),
            Err(CredentialError::Missing { .. })
        ));
    }

    #[test]
    fn with_no_credential_source_an_authenticated_upstream_is_refused_by_name() {
        // The honest-degradation rule: never silently unauthenticated in a way that looks
        // configured. The refusal names the secret nobody wired, so the fix is legible.
        let u = Upstream::authenticated("npm", "https://r.test", "NPM_TOKEN", AuthScheme::Bearer).unwrap();
        let err = inject(&u, &grant("acme"), &NoCredentials).unwrap_err();
        assert_eq!(err, CredentialError::NoSource { upstream: "npm".into(), name: "NPM_TOKEN".into() });
        assert!(err.to_string().contains("no credential source"));
        assert!(!err.is_policy_refusal(), "an unwired proxy is the operator's problem, not the job's");
    }

    #[test]
    fn a_credential_with_a_newline_cannot_split_the_outbound_request() {
        let creds = StaticCredentials::new().with("acme", "BAD", "abc\r\nX-Evil: 1");
        let u = Upstream::authenticated("npm", "https://r.test", "BAD", AuthScheme::Bearer).unwrap();
        assert!(matches!(
            inject(&u, &grant("acme"), &creds),
            Err(CredentialError::NotHeaderSafe { .. })
        ));
    }

    #[test]
    fn an_injected_value_is_redacted_in_debug() {
        let u = Upstream::authenticated("npm", "https://r.test", "NPM_TOKEN", AuthScheme::Bearer).unwrap();
        let injected = inject(&u, &grant("acme"), &creds()).unwrap().unwrap();
        let rendered = format!("{injected:?}");
        assert!(rendered.contains("authorization"), "the scheme is useful in a log");
        assert!(!rendered.contains("npm_s3cr3tvalue"), "the value never is: {rendered}");
    }

    #[test]
    fn a_lookup_carries_the_job_that_occasioned_it() {
        // The seam change this module's doc argues for: a source that must refuse an
        // outsider-authored job needs to know which job is asking, and nothing below `inject` can
        // reconstruct it.
        #[derive(Debug, Default)]
        struct Recording(std::sync::Mutex<Vec<(String, String, String)>>);
        impl UpstreamCredentials for Recording {
            fn credential(&self, req: &CredentialRequest<'_>) -> Result<SecretBytes, CredentialError> {
                self.0.lock().unwrap().push((
                    req.tenant.to_string(),
                    req.job_id.to_string(),
                    req.secret.to_string(),
                ));
                Ok(SecretBytes::new(b"v".to_vec()))
            }
        }
        let recording = Recording::default();
        let u = Upstream::authenticated("npm", "https://r.test", "NPM_TOKEN", AuthScheme::Bearer).unwrap();
        inject(&u, &grant("acme"), &recording).unwrap();
        assert_eq!(
            recording.0.lock().unwrap().as_slice(),
            [("acme".to_string(), "job-1".to_string(), "NPM_TOKEN".to_string())]
        );
    }

    #[test]
    fn every_refusal_is_classified_and_none_of_them_means_carry_on_anonymously() {
        // The exhaustive match in `is_policy_refusal` is what keeps a newly added variant from
        // being silently classified; this asserts the classification the server maps to statuses.
        let policy = [
            CredentialError::NoAuthority {
                job_id: "j".into(),
                upstream: "npm".into(),
                reason: "outsider".into(),
            },
            CredentialError::TenantMismatch {
                job_id: "j".into(),
                registered: "acme".into(),
                presented: "globex".into(),
            },
        ];
        let operator = [
            CredentialError::Missing { upstream: "npm".into(), name: "N".into() },
            CredentialError::NoSource { upstream: "npm".into(), name: "N".into() },
            CredentialError::Unregistered { job_id: "j".into() },
            CredentialError::Unavailable { upstream: "npm".into(), detail: "x".into() },
            CredentialError::NotUtf8,
            CredentialError::NotHeaderSafe { upstream: "npm".into() },
        ];
        assert!(policy.iter().all(CredentialError::is_policy_refusal));
        assert!(!operator.iter().any(CredentialError::is_policy_refusal));
    }

    #[test]
    fn a_credential_set_masks_its_values() {
        let mut set = CredentialSet::default();
        set.push(SecretBytes::new(b"npm_s3cr3tvalue".to_vec()));
        let masked = set.masker().mask("upstream said: npm_s3cr3tvalue is bad");
        assert!(!masked.contains("npm_s3cr3tvalue"), "{masked}");
    }

    #[test]
    fn gathering_for_a_masker_skips_what_it_cannot_obtain() {
        // A value that cannot be obtained cannot appear in output, so its absence from the masker is
        // not a gap. The refusal belongs to `inject`, on the request that needed it.
        let upstreams = [
            Upstream::authenticated("npm", "https://r.test", "NPM_TOKEN", AuthScheme::Bearer).unwrap(),
            Upstream::authenticated("art", "https://a.test", "NO_SUCH", AuthScheme::Bearer).unwrap(),
            Upstream::public("pypi", "https://p.test").unwrap(),
        ];
        let set = CredentialSet::gather(upstreams.iter(), &grant("acme"), &creds());
        assert!(!set.is_empty());
        let masked = set.masker().mask("npm_s3cr3tvalue");
        assert!(!masked.contains("npm_s3cr3tvalue"));
    }

    #[test]
    fn base64_matches_the_rfc() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }
}
