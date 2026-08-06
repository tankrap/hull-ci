//! The package proxy's access to a tenant's upstream registry credential.
//!
//! D§7.4 asks for two things that do not obviously fit together:
//!
//! > **Package auth still terminates at the proxy** where it can: the proxy holds upstream registry
//! > credentials and authenticates outbound; the job talks to it over a per-job URL with a per-job
//! > bearer that grants nothing but "resolve packages for this job, at this rate limit."
//!
//! and, three paragraphs earlier, that a tenant secret leaves this crate only as a **job-scoped,
//! single-use capability redeemed by an enrolled node at exec time**. The proxy is not a node, does
//! not run a job, and needs a *tenant's* credential on an inbound request that arrives whenever some
//! job of that tenant reaches for a package. Those two shapes are the design problem this module
//! exists to resolve.
//!
//! # The resolution: the job is the occasion, so the job is the scope
//!
//! The mismatch turns out to be illusory, and the sentence that made it look real was in this
//! codebase rather than in the design. [`crate::broker::SecretBroker`]'s delivery model is not
//! "secrets are for nodes"; it is "a tenant secret is disclosed only for a *named job*, only to a
//! *named principal*, only *once*, and only for a bounded window". Every one of those is available
//! to the proxy, because the proxy never handles a request that is not already attributed to a job:
//! a package request is authenticated by a per-job grant carrying `(tenant, job_id, upstreams)`
//! before any credential is looked up. So:
//!
//! * **The proxy is an enrolled principal.** It has its own Ed25519 enrolment keypair
//!   ([`ProxyIdentity`]) and its own enrolment table ([`ProxyRegistry`]), the same scheme D§7.4
//!   gives nodes ("the same scheme Hull already uses for actors"). A capability is bound to a
//!   `proxy_id` that the seam *derives from a verified signature*, never from a request field —
//!   exactly as [`crate::service::SecretService`] does for nodes, and for exactly the same reason.
//! * **Its authority is per-job, not standing.** When control mints a job's package grant it also
//!   mints a [`ProxyCapabilityRequest`] covering that job's authenticated upstreams and no others.
//!   The proxy's ability to spend `acme`'s registry token exists because `acme` has a job running
//!   that needs it, and expires with that job.
//!
//! # What was weighed and rejected
//!
//! * **A standing per-tenant capability for the proxy.** The proxy is an enrolled principal, so this
//!   is the shortest path — and it makes the proxy a principal that may spend *any* tenant's
//!   registry token at *any* time for *no stated reason*. There is then no answer to "which job
//!   occasioned this disclosure", which is both the audit question §14.3 wants and the authority
//!   question the author-class gate has to answer. Rejected.
//! * **Fetch once per tenant and cache with a TTL.** Simplest on the request path, and it decouples
//!   the credential's lifetime from any job: a tenant that was revoked or crypto-shredded keeps
//!   serving for up to one TTL, and the proxy holds credentials for tenants with nothing running.
//!   "Revocation stops proxy access" would become "revocation stops proxy access eventually", which
//!   is not the property D§7.4 claims. Rejected.
//!
//! # The outsider question, decided explicitly
//!
//! An `outsider`-authored job (D§1: a fork PR, an unknown contributor) gets **no** capability here,
//! by the same first-line refusal as [`crate::broker::SecretBroker::mint`]. The reasoning is worth
//! stating because the obvious objection is good: the job never *sees* the credential, so what is
//! there to leak?
//!
//! Use is authority. A fork PR that can make the proxy fetch `@acme/private-internal-lib` on the
//! tenant's token has pulled the tenant's private package into a build it controls, and can read it
//! out of its own workspace — without a token ever crossing the sandbox boundary. That is the
//! confused-deputy shape of the "pwn request" the gate exists to stop, and D§1's *secret bleed* row
//! names the control as "never to an `outsider`-authored job" without qualification. So the refusal
//! is here, at mint, before a name is validated or a store is touched.
//!
//! The cost is stated rather than hidden: an outsider's PR in a repo whose dependencies live behind
//! a private registry cannot resolve them. It is a *per-upstream* refusal, not a per-job one —
//! public upstreams in the same grant still serve, so an ordinary fork PR still builds.
//!
//! # What this module does not do
//!
//! It does not cache, hold plaintext, or decide when to redeem. Those are the proxy's, because they
//! are decisions about a process that is allowed to hold a plaintext credential in memory
//! (D§7.4) — this crate's contract is that plaintext leaves it only through a gate, and this module
//! is one more gate rather than a way around the existing one.

use std::collections::BTreeSet;
use std::sync::Arc;

use hull_ci_proto::AuthorClass;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::broker::{DeliveredSecrets, SecretBroker};
use crate::capability::{authenticates, mint_token, CapId, CapabilityToken};
use crate::identity::{NodeIdentity, NodePublicKey, NodeRegistry, NONCE_LEN, SIGNATURE_LEN};
use crate::{associated_data, Clock, SecretError, SystemClock};

/// What control asks for when it mints a job's package grant.
///
/// Deliberately parallel to [`crate::broker::CapabilityRequest`] and deliberately not the same type:
/// the principal is a proxy rather than a node, the names are upstream credentials rather than a
/// step's declared set, and the lifetime is the job's rather than the placement-to-exec gap. A
/// single struct serving both would make every field's meaning conditional on which path read it.
#[derive(Debug, Clone)]
pub struct ProxyCapabilityRequest {
    pub tenant: String,
    /// The job whose package grant occasioned this. The capability exists because this job does.
    pub job_id: String,
    /// The package proxy this capability will be redeemable from, and only this one.
    pub proxy_id: String,
    /// Names of the tenant secrets backing the authenticated upstreams *this job's grant covers* —
    /// so the capability is bounded by the same allowlist slice the job got, not by the deployment's.
    pub declared: Vec<String>,
    /// **Derived from the dispatch, never from the pipeline** (D§1). The gate.
    pub author_class: AuthorClass,
    /// Absolute expiry, which control sets to the job's package-grant expiry.
    ///
    /// Not a TTL constant like [`crate::DEFAULT_TTL_SECS`], and that is the one place this capability
    /// is weaker than a node's. Sixty seconds is right for placement→exec because that gap is short
    /// and known; package resolution happens at an unknown point inside a job, so a fixed short TTL
    /// would either expire before `npm install` ran or force the proxy to hold plaintext from the
    /// first instant of every job. The window is bounded by the job instead, and what compensates is
    /// that the token is useless to anyone but the enrolled proxy and is spent exactly once.
    pub expires_at: u64,
}

/// What a proxy credential capability authorises. Safe to log: ids and secret *names*, never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyCredentialGrant {
    pub cap_id: CapId,
    pub tenant: String,
    pub job_id: String,
    pub proxy_id: String,
    /// Fixed at mint. A redemption takes the whole set; there is no per-name request, because the
    /// proxy cannot know which upstream a job will reach for before the job reaches for it.
    pub names: BTreeSet<String>,
    /// Recorded so the gate can be re-checked at redemption — defence in depth behind the mint-time
    /// refusal, matching [`crate::capability::CapabilityGrant`].
    pub author_class: AuthorClass,
    pub expires_at: u64,
}

/// The registry's private record: the grant, the verifier, and the one-shot flags.
pub(crate) struct ProxyCapRecord {
    pub(crate) grant: ProxyCredentialGrant,
    digest: [u8; 32],
    pub(crate) consumed: bool,
    pub(crate) revoked: bool,
}

impl std::fmt::Debug for ProxyCapRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyCapRecord")
            .field("grant", &self.grant)
            // A verifier for a live bearer token answers no debugging question.
            .field("digest", &"<redacted>")
            .field("consumed", &self.consumed)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl ProxyCapRecord {
    /// Constant-time, through the same helper the node capability uses.
    pub(crate) fn authenticates(&self, presented: &[u8; 32]) -> bool {
        authenticates(&self.digest, presented)
    }
}

/// Mint a token and the record that will authenticate it.
///
/// Takes fields rather than a ready-made [`ProxyCredentialGrant`] for the reason
/// [`crate::capability::mint_record`] does: `cap_id` is not the caller's to choose, so a grant
/// addressed to an id no token was minted for cannot be constructed.
pub(crate) fn mint_proxy_record(
    tenant: String,
    job_id: String,
    proxy_id: String,
    names: BTreeSet<String>,
    author_class: AuthorClass,
    expires_at: u64,
) -> (CapabilityToken, CapId, ProxyCapRecord) {
    let (token, cap_id, digest) = mint_token();
    let grant =
        ProxyCredentialGrant { cap_id, tenant, job_id, proxy_id, names, author_class, expires_at };
    (token, cap_id, ProxyCapRecord { grant, digest, consumed: false, revoked: false })
}

// ── The proxy as a principal ─────────────────────────────────────────────────────────────────────

/// The package proxy's enrolment keypair. **Held only by the proxy process it identifies.**
///
/// A thin wrapper over [`NodeIdentity`] rather than a second Ed25519 implementation: D§7.4 says node
/// identity is "the same scheme Hull already uses for actors", and the proxy is another actor. The
/// wrapper exists so a `ProxyIdentity` cannot be enrolled in the *node* table by a type error — the
/// two principal families authorise entirely different things and the compiler should say so.
#[derive(Debug)]
pub struct ProxyIdentity {
    inner: NodeIdentity,
}

impl ProxyIdentity {
    pub fn generate() -> Self {
        ProxyIdentity { inner: NodeIdentity::generate() }
    }

    /// Rebuild from a stored 32-byte seed, for a proxy whose key was enrolled at provisioning.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        ProxyIdentity { inner: NodeIdentity::from_seed(seed) }
    }

    pub fn public(&self) -> NodePublicKey {
        self.inner.public()
    }

    /// Sign a redemption of `token` for `(tenant, job_id)`.
    ///
    /// `now` is passed in rather than read here so the caller owns its clock, matching
    /// [`NodeIdentity::sign`]. The fresh nonce does not carry the replay defence — the capability's
    /// single-use property does, checked under the broker's lock — but it makes two redemptions never
    /// byte-identical, so a captured signature is evidence of one attempt rather than a reusable
    /// artefact.
    pub fn sign(&self, token: &CapabilityToken, tenant: &str, job_id: &str, now: u64) -> SignedProxyRedemption {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let public_key = self.public();
        let payload = proxy_signing_payload(token, tenant, job_id, &nonce, now, &public_key);
        SignedProxyRedemption {
            token: token.clone(),
            tenant: tenant.to_string(),
            job_id: job_id.to_string(),
            nonce,
            issued_at: now,
            public_key,
            signature: self.inner.sign_raw(&payload),
        }
    }
}

/// A proxy's redemption as it goes over the proxy↔broker link.
///
/// Note what is **not** in here, for the same reason [`crate::identity::SignedRedemption`] omits it:
/// a `proxy_id`. The id is derived from `public_key` after the signature verifies, so there is no
/// field for a caller to put a lie in.
#[derive(Debug, Clone)]
pub struct SignedProxyRedemption {
    /// The bearer capability. Redacted in `Debug` by its own type.
    pub token: CapabilityToken,
    /// The tenant the proxy believes this job belongs to. Checked against the grant, so a proxy
    /// serving many tenants cannot redeem one tenant's capability while attributing it to another.
    pub tenant: String,
    /// The job the proxy is serving. Checked against the grant.
    pub job_id: String,
    pub nonce: [u8; NONCE_LEN],
    /// Unix seconds at the signer. Checked against [`crate::MAX_SKEW_SECS`].
    pub issued_at: u64,
    /// The **claimed** identity. Load-bearing only once the signature over it verifies.
    pub public_key: NodePublicKey,
    pub signature: [u8; SIGNATURE_LEN],
}

/// The exact bytes a proxy redemption's signature covers.
///
/// Its own domain string, so a proxy redemption can never be replayed as a node redemption over a
/// key that somehow ended up in both tables — and length-prefixed via [`associated_data`], so no two
/// different `(tenant, job)` pairs share an encoding. `("ac", "me-job")` and `("acme", "-job")`
/// producing the same signed bytes would be a cross-tenant confusion in the one field this whole
/// module is about.
fn proxy_signing_payload(
    token: &CapabilityToken,
    tenant: &str,
    job_id: &str,
    nonce: &[u8; NONCE_LEN],
    issued_at: u64,
    public_key: &NodePublicKey,
) -> Vec<u8> {
    let nonce_hex = hex::encode(nonce);
    let issued = issued_at.to_string();
    let key_hex = public_key.to_string();
    associated_data(
        "hull-ci/proxy-credential-redemption/v1",
        &[token.expose(), tenant, job_id, &nonce_hex, &issued, &key_hex],
    )
}

/// Which public keys belong to which package proxies.
///
/// A separate table from [`NodeRegistry`]'s contents even though it reuses its type: a key enrolled
/// as a node must not resolve as a proxy, because the two principal families authorise different
/// disclosures. Reusing the *implementation* buys the properties that took work to get right —
/// injective in both directions, replace-on-re-enrol, revocable — without a second copy of them to
/// keep in step.
#[derive(Debug, Default)]
pub struct ProxyRegistry {
    keys: NodeRegistry,
}

impl ProxyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enrol `key` as `proxy_id`, replacing whatever key that proxy had before.
    pub fn enrol(&self, proxy_id: impl Into<String>, key: NodePublicKey) -> Result<(), SecretError> {
        self.keys.enrol(proxy_id, key)
    }

    /// Withdraw a proxy's enrolment. After this its signatures still verify cryptographically and
    /// still refuse to resolve to an id: the key is not broken, it is no longer ours.
    pub fn revoke(&self, proxy_id: &str) -> bool {
        self.keys.revoke(proxy_id)
    }

    pub fn is_enrolled(&self, key: &NodePublicKey) -> bool {
        self.keys.is_enrolled(key)
    }

    /// Verify a redemption and return the proxy id **derived from the verified key**.
    ///
    /// Same order as [`NodeRegistry::verify`], for the same reasons: signature first (so nothing
    /// below is an oracle for someone without the private half), then freshness (so a stale request
    /// is refused before it can consume a capability), then enrolment (the only step that yields an
    /// id).
    pub fn verify(&self, req: &SignedProxyRedemption, now: u64) -> Result<String, SecretError> {
        let payload = proxy_signing_payload(
            &req.token,
            &req.tenant,
            &req.job_id,
            &req.nonce,
            req.issued_at,
            &req.public_key,
        );
        req.public_key.verify_raw(&payload, &req.signature)?;

        let skew = now.abs_diff(req.issued_at);
        if skew > crate::MAX_SKEW_SECS {
            return Err(SecretError::StaleRedemption { skew_secs: skew });
        }

        self.keys
            .resolve(&req.public_key)
            .ok_or_else(|| SecretError::UnenrolledProxy(req.public_key.to_string()))
    }
}

// ── The seam ─────────────────────────────────────────────────────────────────────────────────────

/// The broker plus the proxy enrolment table, wired in the order D§7.4 requires.
///
/// The sibling of [`crate::service::SecretService`], and thin for the same reason: it owns no policy,
/// and its whole contribution is the *order* — [`ProxyRegistry::verify`] first, and the proxy id it
/// returns is the only one [`SecretBroker::redeem_proxy_capability`] ever sees. There is no path
/// through this type by which a caller-supplied proxy id reaches the broker, which is what makes
/// [`SecretError::WrongProxy`] a control rather than a comment.
///
/// Minting stays on the control side and keeps its own entry point, because the actor whose authority
/// is checked there is the *job's author*, not the proxy.
#[derive(Debug)]
pub struct ProxyCredentialService {
    broker: Arc<SecretBroker>,
    proxies: Arc<ProxyRegistry>,
    clock: Arc<dyn Clock>,
}

impl ProxyCredentialService {
    pub fn new(broker: Arc<SecretBroker>, proxies: Arc<ProxyRegistry>) -> Self {
        ProxyCredentialService { broker, proxies, clock: Arc::new(SystemClock) }
    }

    /// Share the broker's clock. Two clocks that can disagree gives a deployment where a capability
    /// is live but every redemption of it looks stale — see [`crate::service::SecretService`].
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn broker(&self) -> &Arc<SecretBroker> {
        &self.broker
    }

    pub fn proxies(&self) -> &Arc<ProxyRegistry> {
        &self.proxies
    }

    /// Enrol a proxy's public key under an id, at provisioning.
    pub fn enrol_proxy(&self, proxy_id: impl Into<String>, key: NodePublicKey) -> Result<(), SecretError> {
        self.proxies.enrol(proxy_id, key)
    }

    /// Mint at placement, alongside the job's package grant. A pass-through to the broker, which owns
    /// the author-class gate.
    pub fn mint(
        &self,
        req: &ProxyCapabilityRequest,
    ) -> Result<(CapabilityToken, ProxyCredentialGrant), SecretError> {
        self.broker.mint_proxy_capability(req)
    }

    /// Redeem on behalf of whichever proxy actually signed the request.
    ///
    /// The tenant and job checks are here rather than in the broker for the same reason the node
    /// path's `WrongJob` check is in [`crate::service::SecretService`]: the broker takes an id it is
    /// handed, and the thing that knows what this redemption was *signed for* is the thing that just
    /// checked the signature.
    ///
    /// The tenant check is the one that matters most in this file. A package proxy is a single
    /// process serving every tenant on the fleet, so "the credential I just fetched belongs to the
    /// tenant whose job asked for it" is not a property of the deployment topology the way it is for
    /// a node — it has to be checked, and it is checked twice: here against the signed request, and
    /// structurally in the broker, which only ever opens `(grant.tenant, name)`.
    pub fn redeem(&self, req: &SignedProxyRedemption) -> Result<DeliveredSecrets, SecretError> {
        let proxy_id = self.proxies.verify(req, self.clock.now_secs())?;
        let delivered = self.broker.redeem_proxy_capability(&req.token, &proxy_id)?;
        if delivered.tenant != req.tenant {
            // The capability is already burnt by the time we get here, which is the right side to err
            // on: a mismatch is either a control-plane bug or an attempt, and neither should leave a
            // live capability behind.
            return Err(SecretError::WrongTenant {
                bound: delivered.tenant.clone(),
                presented: req.tenant.clone(),
            });
        }
        if delivered.job_id != req.job_id {
            return Err(SecretError::WrongJob {
                bound: delivered.job_id.clone(),
                presented: req.job_id.clone(),
            });
        }
        Ok(delivered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DevKeyManager;
    use crate::store::MemorySealedStore;
    use std::sync::Mutex;

    #[derive(Debug)]
    struct TestClock(Mutex<u64>);

    impl TestClock {
        fn new(t: u64) -> Arc<Self> {
            Arc::new(TestClock(Mutex::new(t)))
        }
        fn set(&self, t: u64) {
            *self.0.lock().unwrap() = t;
        }
    }

    impl Clock for TestClock {
        fn now_secs(&self) -> u64 {
            *self.0.lock().unwrap()
        }
    }

    struct Fixture {
        service: ProxyCredentialService,
        proxy: ProxyIdentity,
        clock: Arc<TestClock>,
    }

    /// Two tenants, each with a registry token of its own under the same *name*. The shared name is
    /// the point: if tenant scoping were nominal rather than structural, `acme` asking for
    /// `NPM_TOKEN` could plausibly return `globex`'s.
    fn fixture() -> Fixture {
        let clock = TestClock::new(1_000);
        let broker = Arc::new(
            SecretBroker::new(Arc::new(DevKeyManager::new()), Arc::new(MemorySealedStore::new()))
                .with_clock(clock.clone()),
        );
        for (tenant, value) in [("acme", b"acme-npm-token" as &[u8]), ("globex", b"globex-npm-token")] {
            broker.provision_tenant(tenant).unwrap();
            broker.put_secret(tenant, "NPM_TOKEN", value).unwrap();
        }
        broker.put_secret("acme", "DEPLOY_KEY", b"deploy-k3y-value").unwrap();

        let proxy = ProxyIdentity::generate();
        let service =
            ProxyCredentialService::new(broker, Arc::new(ProxyRegistry::new())).with_clock(clock.clone());
        service.enrol_proxy("proxy-a", proxy.public()).unwrap();
        Fixture { service, proxy, clock }
    }

    fn request(tenant: &str, class: AuthorClass) -> ProxyCapabilityRequest {
        ProxyCapabilityRequest {
            tenant: tenant.into(),
            job_id: format!("job-for-{tenant}"),
            proxy_id: "proxy-a".into(),
            declared: vec!["NPM_TOKEN".into()],
            author_class: class,
            expires_at: 2_000,
        }
    }

    #[test]
    fn the_enrolled_proxy_gets_the_tenants_upstream_credential() {
        let f = fixture();
        let (token, grant) = f.service.mint(&request("acme", AuthorClass::Member)).unwrap();
        assert_eq!(grant.proxy_id, "proxy-a");
        let signed = f.proxy.sign(&token, "acme", "job-for-acme", 1_000);
        let delivered = f.service.redeem(&signed).unwrap();
        assert_eq!(delivered.get("NPM_TOKEN").unwrap().expose(), b"acme-npm-token");
    }

    #[test]
    fn a_tenant_cannot_obtain_another_tenants_upstream_credential() {
        // The property this whole module is for. `globex` has a secret under the identical name; a
        // capability minted for `acme` resolves `acme`'s row under `acme`'s KEK and cannot be talked
        // into resolving anything else — the tenant is in the grant, and the grant is not in the
        // request.
        let f = fixture();
        let (token, _) = f.service.mint(&request("acme", AuthorClass::Member)).unwrap();
        let delivered = f.service.redeem(&f.proxy.sign(&token, "acme", "job-for-acme", 1_000)).unwrap();
        assert_eq!(delivered.tenant, "acme");
        assert_eq!(delivered.get("NPM_TOKEN").unwrap().expose(), b"acme-npm-token");
        assert_ne!(delivered.get("NPM_TOKEN").unwrap().expose(), b"globex-npm-token");
    }

    #[test]
    fn a_capability_redeemed_under_another_tenants_name_is_refused() {
        // The same attempt from the other side: the proxy holds `acme`'s capability and signs a
        // redemption attributing it to `globex`, which is what a cross-tenant bug in the proxy's own
        // bookkeeping would look like on the wire.
        let f = fixture();
        let (token, _) = f.service.mint(&request("acme", AuthorClass::Member)).unwrap();
        let signed = f.proxy.sign(&token, "globex", "job-for-acme", 1_000);
        assert_eq!(
            f.service.redeem(&signed).unwrap_err(),
            SecretError::WrongTenant { bound: "acme".into(), presented: "globex".into() }
        );
    }

    #[test]
    fn a_capability_redeemed_for_another_job_is_refused() {
        let f = fixture();
        let (token, _) = f.service.mint(&request("acme", AuthorClass::Member)).unwrap();
        let signed = f.proxy.sign(&token, "acme", "some-other-job", 1_000);
        assert!(matches!(f.service.redeem(&signed), Err(SecretError::WrongJob { .. })));
    }

    #[test]
    fn an_outsider_authored_job_gets_no_upstream_credential_capability() {
        // Decided in the module doc: the job never sees the value, but *use* is authority, and a
        // fork PR that can spend the tenant's registry token can pull the tenant's private packages
        // into a build it controls.
        let f = fixture();
        assert_eq!(
            f.service.mint(&request("acme", AuthorClass::Outsider)).unwrap_err(),
            SecretError::OutsiderRefused
        );
    }

    #[test]
    fn an_outsiders_refusal_is_not_an_existence_oracle() {
        // Identical to the node path: naming a real secret, a typo, and a malformed name must all
        // fail the same way, or the error enumerates the tenant's secrets to a fork PR.
        let f = fixture();
        for declared in [vec!["NPM_TOKEN"], vec!["NO_SUCH"], vec!["not a name"]] {
            let mut req = request("acme", AuthorClass::Outsider);
            req.declared = declared.iter().map(|s| s.to_string()).collect();
            assert_eq!(f.service.mint(&req).unwrap_err(), SecretError::OutsiderRefused);
        }
    }

    #[test]
    fn a_capability_is_single_use_and_cannot_be_replayed() {
        let f = fixture();
        let (token, _) = f.service.mint(&request("acme", AuthorClass::Member)).unwrap();
        assert!(f.service.redeem(&f.proxy.sign(&token, "acme", "job-for-acme", 1_000)).is_ok());
        // A fresh signature with a fresh nonce — the easy replay for whoever holds the key, and it
        // buys nothing, because the capability is spent rather than the signature.
        assert_eq!(
            f.service.redeem(&f.proxy.sign(&token, "acme", "job-for-acme", 1_000)).unwrap_err(),
            SecretError::CapabilityConsumed
        );
        // And the captured signature itself, re-presented byte-for-byte, is refused too.
        let signed = f.proxy.sign(&token, "acme", "job-for-acme", 1_000);
        assert!(f.service.redeem(&signed).is_err());
        assert_eq!(f.service.redeem(&signed).unwrap_err(), SecretError::CapabilityConsumed);
    }

    #[test]
    fn a_capability_expires_with_the_job_that_occasioned_it() {
        let f = fixture();
        let (token, grant) = f.service.mint(&request("acme", AuthorClass::Member)).unwrap();
        assert_eq!(grant.expires_at, 2_000, "the job's package-grant expiry, not a fixed TTL");

        f.clock.set(1_999);
        let (live, _) = f.service.mint(&request("acme", AuthorClass::Member)).unwrap();
        assert!(f.service.redeem(&f.proxy.sign(&live, "acme", "job-for-acme", 1_999)).is_ok());

        f.clock.set(2_000);
        assert_eq!(
            f.service.redeem(&f.proxy.sign(&token, "acme", "job-for-acme", 2_000)).unwrap_err(),
            SecretError::CapabilityExpired
        );
    }

    #[test]
    fn a_capability_already_past_its_expiry_is_never_minted() {
        // Control computing an expiry in the past is a bug, and minting the capability anyway would
        // move the failure into the proxy's request path where it reads as an outage.
        let f = fixture();
        let mut req = request("acme", AuthorClass::Member);
        req.expires_at = 999;
        assert_eq!(f.service.mint(&req).unwrap_err(), SecretError::CapabilityExpired);
    }

    #[test]
    fn a_capability_is_bound_to_one_proxy() {
        let f = fixture();
        let thief = ProxyIdentity::generate();
        f.service.enrol_proxy("proxy-b", thief.public()).unwrap();

        let (token, _) = f.service.mint(&request("acme", AuthorClass::Member)).unwrap();
        // The thief signs correctly with its own enrolled key and still cannot be `proxy-a`: it never
        // says which proxy it is, it proves it, and the proof resolves to `proxy-b`.
        assert_eq!(
            f.service.redeem(&thief.sign(&token, "acme", "job-for-acme", 1_000)).unwrap_err(),
            SecretError::WrongProxy
        );
        // And the legitimate proxy is not collateral damage.
        assert!(f.service.redeem(&f.proxy.sign(&token, "acme", "job-for-acme", 1_000)).is_ok());
    }

    #[test]
    fn an_unenrolled_proxy_never_reaches_the_broker() {
        let f = fixture();
        let stranger = ProxyIdentity::generate();
        let (token, _) = f.service.mint(&request("acme", AuthorClass::Member)).unwrap();

        assert!(matches!(
            f.service.redeem(&stranger.sign(&token, "acme", "job-for-acme", 1_000)),
            Err(SecretError::UnenrolledProxy(_))
        ));
        // The capability must survive an unauthenticated attempt, or anyone holding a token could
        // kill a healthy job's package resolution by presenting it badly.
        assert!(f.service.redeem(&f.proxy.sign(&token, "acme", "job-for-acme", 1_000)).is_ok());
    }

    #[test]
    fn a_tampered_redemption_does_not_verify() {
        let f = fixture();
        let (token, _) = f.service.mint(&request("acme", AuthorClass::Member)).unwrap();
        let base = f.proxy.sign(&token, "acme", "job-for-acme", 1_000);

        let mut wrong_tenant = base.clone();
        wrong_tenant.tenant = "globex".into();
        let mut wrong_job = base.clone();
        wrong_job.job_id = "job-2".into();
        let mut wrong_nonce = base.clone();
        wrong_nonce.nonce[0] ^= 0x01;
        let mut wrong_time = base.clone();
        wrong_time.issued_at = 1_001;
        let mut wrong_sig = base.clone();
        wrong_sig.signature[0] ^= 0x01;

        for (what, req) in [
            ("tenant", wrong_tenant),
            ("job_id", wrong_job),
            ("nonce", wrong_nonce),
            ("issued_at", wrong_time),
            ("signature", wrong_sig),
        ] {
            assert_eq!(
                f.service.redeem(&req).unwrap_err(),
                SecretError::BadNodeSignature,
                "tampering with {what} must invalidate the signature"
            );
        }
        // None of it burnt the capability.
        assert!(f.service.redeem(&base).is_ok());
    }

    #[test]
    fn a_stale_redemption_is_refused_before_it_can_burn_a_capability() {
        let f = fixture();
        let (token, _) = f.service.mint(&request("acme", AuthorClass::Member)).unwrap();
        let stale = f.proxy.sign(&token, "acme", "job-for-acme", 1_000 - crate::MAX_SKEW_SECS - 1);
        assert!(matches!(f.service.redeem(&stale), Err(SecretError::StaleRedemption { .. })));
        assert!(f.service.redeem(&f.proxy.sign(&token, "acme", "job-for-acme", 1_000)).is_ok());
    }

    #[test]
    fn a_node_key_does_not_resolve_as_a_proxy_and_a_node_payload_is_not_a_proxy_payload() {
        // The two principal families are separate tables over one key type. A key enrolled as a node
        // authorises a node's disclosures and no others.
        let f = fixture();
        let node = NodeIdentity::generate();
        let nodes = NodeRegistry::new();
        nodes.enrol("node-a", node.public()).unwrap();
        assert!(!f.service.proxies().is_enrolled(&node.public()));

        // And the domain separator means a signature over one payload family cannot be presented as
        // the other even if a key were in both tables.
        let (token, _) = f.service.mint(&request("acme", AuthorClass::Member)).unwrap();
        let node_signed = node.sign(&token, "job-for-acme", &[], 1_000);
        let smuggled = SignedProxyRedemption {
            token: node_signed.token.clone(),
            tenant: "acme".into(),
            job_id: node_signed.job_id.clone(),
            nonce: node_signed.nonce,
            issued_at: node_signed.issued_at,
            public_key: node_signed.public_key,
            signature: node_signed.signature,
        };
        assert_eq!(f.service.redeem(&smuggled).unwrap_err(), SecretError::BadNodeSignature);
    }

    #[test]
    fn revoking_a_tenant_stops_its_outstanding_proxy_capabilities() {
        let f = fixture();
        let (token, _) = f.service.mint(&request("acme", AuthorClass::Member)).unwrap();
        assert_eq!(f.service.broker().revoke_tenant("acme"), 1);
        assert_eq!(
            f.service.redeem(&f.proxy.sign(&token, "acme", "job-for-acme", 1_000)).unwrap_err(),
            SecretError::CapabilityRevoked
        );
    }

    #[test]
    fn crypto_shredding_a_tenant_stops_its_proxy_access_entirely() {
        // Three doors, all of which must shut: the outstanding capability, the ability to mint a new
        // one, and — even after a re-enrolment that restores key material — the old ciphertext.
        let f = fixture();
        let (token, _) = f.service.mint(&request("acme", AuthorClass::Member)).unwrap();

        f.service.broker().shred_tenant("acme").unwrap();

        assert_eq!(
            f.service.redeem(&f.proxy.sign(&token, "acme", "job-for-acme", 1_000)).unwrap_err(),
            SecretError::CapabilityRevoked
        );
        assert_eq!(
            f.service.mint(&request("acme", AuthorClass::Member)).unwrap_err(),
            SecretError::NoTenantKey("acme".into())
        );

        f.service.broker().provision_tenant("acme").unwrap();
        let (token2, _) = f.service.mint(&request("acme", AuthorClass::Member)).unwrap();
        assert!(matches!(
            f.service.redeem(&f.proxy.sign(&token2, "acme", "job-for-acme", 1_000)),
            Err(SecretError::NoKekVersion { .. })
        ));

        // And no other tenant was touched — the reason for one KEK per tenant.
        let (globex, _) = f.service.mint(&request("globex", AuthorClass::Member)).unwrap();
        let delivered =
            f.service.redeem(&f.proxy.sign(&globex, "globex", "job-for-globex", 1_000)).unwrap();
        assert_eq!(delivered.get("NPM_TOKEN").unwrap().expose(), b"globex-npm-token");
    }

    #[test]
    fn revoking_the_proxys_enrolment_stops_every_tenants_proxy_access() {
        // The break-glass for a compromised proxy: one call, and the process cannot spend anybody's
        // credential, without touching a single tenant's key material.
        let f = fixture();
        let (token, _) = f.service.mint(&request("acme", AuthorClass::Member)).unwrap();
        assert!(f.service.proxies().revoke("proxy-a"));
        assert!(matches!(
            f.service.redeem(&f.proxy.sign(&token, "acme", "job-for-acme", 1_000)),
            Err(SecretError::UnenrolledProxy(_))
        ));
    }

    #[test]
    fn a_capability_covers_only_the_names_control_declared() {
        // `DEPLOY_KEY` is a real `acme` secret that is not an upstream credential. The package
        // proxy's capability is bounded by the upstreams the job's grant covers, so it never reaches
        // the rest of the tenant's namespace.
        let f = fixture();
        let (token, grant) = f.service.mint(&request("acme", AuthorClass::Member)).unwrap();
        assert_eq!(grant.names.iter().cloned().collect::<Vec<_>>(), ["NPM_TOKEN"]);
        let delivered = f.service.redeem(&f.proxy.sign(&token, "acme", "job-for-acme", 1_000)).unwrap();
        assert_eq!(delivered.names(), ["NPM_TOKEN"]);
        assert!(delivered.get("DEPLOY_KEY").is_none());
    }

    #[test]
    fn a_name_the_tenant_does_not_have_is_refused_at_mint() {
        // At placement, where it is a legible configuration error, rather than inside a package
        // fetch where it looks like a registry outage.
        let f = fixture();
        let mut req = request("acme", AuthorClass::Member);
        req.declared = vec!["NO_SUCH".into()];
        assert!(matches!(f.service.mint(&req), Err(SecretError::UnknownSecret { .. })));
    }

    #[test]
    fn the_signed_payload_is_injective_across_field_boundaries() {
        // A collision here would let one signature stand for a different `(tenant, job)` pair, which
        // in this module is precisely a cross-tenant disclosure.
        let t = CapabilityToken::from_wire("hcap_aa.bb");
        let key = ProxyIdentity::generate().public();
        let n = [0u8; NONCE_LEN];
        assert_ne!(
            proxy_signing_payload(&t, "ac", "me-job", &n, 1, &key),
            proxy_signing_payload(&t, "acme", "-job", &n, 1, &key)
        );
    }

    #[test]
    fn the_token_and_the_record_are_redacted_in_debug() {
        let f = fixture();
        let (token, _) = f.service.mint(&request("acme", AuthorClass::Member)).unwrap();
        assert_eq!(format!("{token:?}"), "CapabilityToken(<redacted>)");
        let signed = f.proxy.sign(&token, "acme", "job-for-acme", 1_000);
        assert!(!format!("{signed:?}").contains(token.expose()));
    }
}
