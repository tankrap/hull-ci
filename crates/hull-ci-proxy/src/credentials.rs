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

use std::collections::BTreeMap;

use hull_ci_secrets::{Masker, SecretBytes};

use crate::allowlist::{AuthScheme, Upstream};

/// Where the proxy gets an upstream's credential.
///
/// A trait rather than a direct dependency on [`hull_ci_secrets::SecretBroker`] for the same reason
/// the broker keeps its store behind one: the proxy needs a *value*, and how a deployment custodies
/// that value — a KMS-backed broker, a file in dev — is not this crate's business.
///
/// Note what the trait does **not** take: a job id. A job's grant decides which upstreams it may
/// reach; it does not decide whose credential is spent. Threading a job id in here would create the
/// question "may this job use that tenant's token?" at a layer with no standing to answer it.
pub trait UpstreamCredentials: Send + Sync + std::fmt::Debug {
    /// The secret named `name` for `tenant`, or `None` if there is not one.
    ///
    /// `None` is not an error: an upstream configured with a credential the broker does not hold is a
    /// misconfiguration an operator needs to see, and the caller turns it into a refusal with a
    /// readable message rather than silently making an unauthenticated request that will 401.
    fn credential(&self, tenant: &str, name: &str) -> Option<SecretBytes>;
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

/// Build the outbound authentication header for one upstream.
///
/// Returns `Ok(None)` for a public upstream — the common case, which must stay unauthenticated. A
/// public registry that starts receiving an `Authorization` header because someone reused a config
/// block is a credential disclosure to a third party.
pub fn inject(
    upstream: &Upstream,
    tenant: &str,
    creds: &dyn UpstreamCredentials,
) -> Result<Option<Injected>, CredentialError> {
    let Some(name) = &upstream.credential else {
        return Ok(None);
    };
    let secret = creds
        .credential(tenant, name)
        .ok_or_else(|| CredentialError::Missing { upstream: upstream.name.clone(), name: name.clone() })?;
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

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    /// The upstream is configured to authenticate and the broker has no such secret. Refused rather
    /// than downgraded to an anonymous request: a silent downgrade shows up as a confusing 401 from
    /// the upstream instead of the configuration error it is.
    #[error("upstream `{upstream}` needs secret `{name}`, which this tenant does not have")]
    Missing { upstream: String, name: String },
    #[error("credential is not valid UTF-8 and cannot be put in a header")]
    NotUtf8,
    /// A credential containing a control character would let a header value split the request.
    #[error("credential for upstream `{upstream}` contains bytes that are not header-safe")]
    NotHeaderSafe { upstream: String },
}

/// An in-memory credential source. **Development and test only** — it is exactly what
/// [`hull_ci_secrets::DevKeyManager`] is to the broker, and the trait above is where a real one goes.
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
    fn credential(&self, tenant: &str, name: &str) -> Option<SecretBytes> {
        self.by_tenant.get(&(tenant.to_string(), name.to_string())).map(|v| SecretBytes::new(v.clone()))
    }
}

/// Every credential a set of upstreams could spend for one tenant, gathered so they can be
/// registered with a [`Masker`].
///
/// D§7.4 is explicit that masking "is a backstop, not a control" — it is exact-substring redaction
/// and falls to base64/split/transform. It is here for the accident (a proxy error message quoting an
/// upstream's 401 body), not for the adversary. The control is that the job never receives the value.
#[derive(Debug, Default)]
pub struct CredentialSet {
    values: Vec<SecretBytes>,
}

impl CredentialSet {
    /// Every credential the given upstreams could spend for this tenant.
    ///
    /// Silently skips an upstream whose secret is absent: this builds a *masker*, and a credential
    /// that does not exist cannot appear in output. The refusal for a missing credential belongs to
    /// [`inject`], on the request that actually needed it.
    pub fn gather<'a>(
        upstreams: impl IntoIterator<Item = &'a Upstream>,
        tenant: &str,
        creds: &dyn UpstreamCredentials,
    ) -> Self {
        let mut set = CredentialSet::default();
        for u in upstreams {
            if let Some(secret) = u.credential.as_deref().and_then(|n| creds.credential(tenant, n)) {
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

    fn creds() -> StaticCredentials {
        StaticCredentials::new()
            .with("acme", "NPM_TOKEN", "npm_s3cr3tvalue")
            .with("acme", "ART_USER_PW", "hunter2")
    }

    #[test]
    fn a_public_upstream_is_never_given_a_credential() {
        // Sending a private token to a public registry is a disclosure to a third party, and the
        // easiest way to ship it is to reuse a config block.
        let u = Upstream::public("npm", "https://registry.npmjs.org").unwrap();
        assert!(inject(&u, "acme", &creds()).unwrap().is_none());
    }

    #[test]
    fn a_bearer_upstream_gets_the_tenants_secret_in_an_authorization_header() {
        let u = Upstream::authenticated("npm", "https://r.test", "NPM_TOKEN", AuthScheme::Bearer).unwrap();
        let injected = inject(&u, "acme", &creds()).unwrap().unwrap();
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
        let injected = inject(&u, "acme", &creds()).unwrap().unwrap();
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
        let injected = inject(&u, "acme", &creds()).unwrap().unwrap();
        assert_eq!(injected.header, "x-jfrog-art-api", "header names are matched lowercased");
        assert_eq!(injected.expose(), b"npm_s3cr3tvalue");
    }

    #[test]
    fn a_missing_credential_is_refused_rather_than_downgraded_to_anonymous() {
        // A silent downgrade surfaces as a puzzling 401 from the upstream instead of the
        // configuration error it actually is.
        let u = Upstream::authenticated("npm", "https://r.test", "NO_SUCH", AuthScheme::Bearer).unwrap();
        assert_eq!(
            inject(&u, "acme", &creds()).unwrap_err(),
            CredentialError::Missing { upstream: "npm".into(), name: "NO_SUCH".into() }
        );
        // A different tenant is a different answer: the credential is the tenant's, not the proxy's.
        assert!(matches!(
            inject(
                &Upstream::authenticated("npm", "https://r.test", "NPM_TOKEN", AuthScheme::Bearer).unwrap(),
                "other-tenant",
                &creds()
            ),
            Err(CredentialError::Missing { .. })
        ));
    }

    #[test]
    fn a_credential_with_a_newline_cannot_split_the_outbound_request() {
        let creds = StaticCredentials::new().with("acme", "BAD", "abc\r\nX-Evil: 1");
        let u = Upstream::authenticated("npm", "https://r.test", "BAD", AuthScheme::Bearer).unwrap();
        assert!(matches!(inject(&u, "acme", &creds), Err(CredentialError::NotHeaderSafe { .. })));
    }

    #[test]
    fn an_injected_value_is_redacted_in_debug() {
        let u = Upstream::authenticated("npm", "https://r.test", "NPM_TOKEN", AuthScheme::Bearer).unwrap();
        let injected = inject(&u, "acme", &creds()).unwrap().unwrap();
        let rendered = format!("{injected:?}");
        assert!(rendered.contains("authorization"), "the scheme is useful in a log");
        assert!(!rendered.contains("npm_s3cr3tvalue"), "the value never is: {rendered}");
    }

    #[test]
    fn a_credential_set_masks_its_values() {
        let mut set = CredentialSet::default();
        set.push(SecretBytes::new(b"npm_s3cr3tvalue".to_vec()));
        let masked = set.masker().mask("upstream said: npm_s3cr3tvalue is bad");
        assert!(!masked.contains("npm_s3cr3tvalue"), "{masked}");
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
