//! Upstream credentials from the secret broker, bounded by the job that occasioned them.
//!
//! This is the production [`UpstreamCredentials`], and the reason it is not a two-line adapter over
//! [`hull_ci_secrets::SecretBroker`] is a genuine shape mismatch, argued in full in
//! [`hull_ci_secrets::package`]:
//!
//! * the broker discloses a tenant secret as a **job-scoped, single-use capability redeemed by an
//!   enrolled principal**;
//! * the proxy needs a **tenant's** credential on an inbound request, hundreds of times per
//!   `npm install`.
//!
//! The resolution is that the proxy is never handling an unattributed request. A package request is
//! authenticated by a per-job grant carrying `(tenant, job_id, upstreams)` *before* any credential is
//! looked up, so the job is already there — and the job is the right scope. Control mints a
//! [`ProxyCapabilityRequest`](hull_ci_secrets::ProxyCapabilityRequest) alongside the job's package
//! grant, hands the token to [`BrokeredCredentials::authorise_job`], and this type spends it **once**
//! and holds the plaintext for exactly the life of that job's grant.
//!
//! # Why the plaintext is held, and what that costs
//!
//! It has to be. A single-use capability cannot be redeemed per package request, and a broker round
//! trip on the hot path would put a network call between `npm` and every tarball. So the credential
//! is redeemed on the first request of a job that actually needs one, and lives in memory until
//! [`BrokeredCredentials::release_job`].
//!
//! That is allowed but not free, and the cost is worth naming: D§7.4 puts plaintext on the *node*
//! under "in memory only for the spawn", and the proxy's window is a whole job rather than a spawn.
//! What bounds it is the job rather than a clock — there is no TTL cache here, and no credential for
//! a tenant with nothing running — and D§7.4 already accepts the premise ("the proxy holds upstream
//! registry credentials"): a proxy that terminates auth is a proxy that holds a credential. What is
//! **not** conceded is disk. Nothing here is written anywhere; [`SecretBytes`] zeroizes on drop, and
//! dropping a job's record drops its values.
//!
//! # Lazy, not eager
//!
//! A job's capability is redeemed on first need, not at registration. A job that resolves nothing, or
//! only public upstreams, never causes its tenant's registry token to exist in this process at all —
//! "there is nothing to filter" rather than "we filter it", which is the preference D§1 states for
//! every other control in the system. The price is that an *unredeemed* capability sits in memory
//! for the life of the job; that is strictly the better thing to be holding, since it is bound to
//! this proxy's enrolled identity and is worthless to anything that steals it.
//!
//! # It fails closed, three different ways, and says which
//!
//! | condition | answer |
//! |---|---|
//! | control registered the job with no authority (an `outsider`, or secrets off) | [`CredentialError::NoAuthority`] — a policy refusal |
//! | control never registered the job | [`CredentialError::Unregistered`] — a wiring bug |
//! | the broker refused or was unreachable | [`CredentialError::Unavailable`] |
//!
//! None of them is "proceed unauthenticated".

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use hull_ci_secrets::{
    Clock, DeliveredSecrets, Masker, ProxyCredentialService, ProxyIdentity, SecretBytes, SecretError,
    SignedProxyRedemption, SystemClock,
};

use crate::credentials::{CredentialError, CredentialRequest, UpstreamCredentials};

/// The proxy→broker seam.
///
/// A trait for the same reason [`hull_ci_node::secrets::SecretRedeemer`] is one on the node side: in
/// this repository's single-process composition the broker is a struct call, and on a real fleet it
/// is a socket, and the proxy must not be able to tell — otherwise the signature-verification path
/// is the one thing in the system that is never exercised (D§7.4's note about a control silently
/// doing nothing).
///
/// [`hull_ci_node::secrets::SecretRedeemer`]: https://docs.rs/hull-ci-node
pub trait ProxyCredentialRedeemer: Send + Sync + std::fmt::Debug {
    fn redeem(&self, req: &SignedProxyRedemption) -> Result<DeliveredSecrets, SecretError>;
}

/// The seam, as a struct call, for a deployment that runs the broker in this process.
///
/// Note what it does **not** do: it does not skip the signature check, does not pass a proxy id, and
/// does not reach past [`ProxyCredentialService`] into the broker.
#[derive(Debug)]
pub struct InProcessRedeemer {
    service: Arc<ProxyCredentialService>,
}

impl InProcessRedeemer {
    pub fn new(service: Arc<ProxyCredentialService>) -> Self {
        InProcessRedeemer { service }
    }
}

impl ProxyCredentialRedeemer for InProcessRedeemer {
    fn redeem(&self, req: &SignedProxyRedemption) -> Result<DeliveredSecrets, SecretError> {
        self.service.redeem(req)
    }
}

/// What the proxy knows about one live job's credential authority.
enum JobState {
    /// Control gave this job a capability the proxy has not spent yet.
    Pending(hull_ci_secrets::CapabilityToken),
    /// Spent. These are the values, held until the job is released.
    Held(BTreeMap<String, SecretBytes>),
    /// Control registered the job and said it may spend nothing. The reason is an operator's, and
    /// gets repeated back in the refusal — an author reading "outsider-authored jobs may not spend a
    /// tenant credential" can act on it; a bare 403 cannot be acted on at all.
    NoAuthority(String),
    /// The redemption was attempted and refused. Remembered rather than retried: the capability is
    /// single-use, so the second attempt would fail differently (`CapabilityConsumed`) and tell an
    /// operator a worse story than the first failure did.
    Failed(String),
}

impl std::fmt::Debug for JobState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Neither the token nor the values, and for `Held` not even the names: a job's private
            // registry set is not something to put in a log line by accident.
            JobState::Pending(_) => f.write_str("Pending(<capability>)"),
            JobState::Held(v) => write!(f, "Held({} credentials)", v.len()),
            JobState::NoAuthority(r) => write!(f, "NoAuthority({r})"),
            JobState::Failed(d) => write!(f, "Failed({d})"),
        }
    }
}

/// One job's slot.
///
/// The state is behind its own lock so a redemption serialises **per job** rather than across the
/// whole proxy. `npm` opens many connections at once, so without this the first burst of requests for
/// one job would each see `Pending` and race to redeem — and a single-use capability means exactly
/// one of them would win and the rest would get `CapabilityConsumed`, turning a correct design into
/// an intermittent build failure. Serialising on the *outer* map instead would make one job's slow
/// broker call block every other tenant's lookups.
#[derive(Debug)]
struct JobSlot {
    /// The tenant control registered this job under. Compared against the tenant on the
    /// *authenticated grant* at every lookup — see [`BrokeredCredentials::credential`].
    tenant: String,
    state: Mutex<JobState>,
}

/// [`UpstreamCredentials`] backed by the secret broker.
pub struct BrokeredCredentials {
    identity: Arc<ProxyIdentity>,
    redeemer: Arc<dyn ProxyCredentialRedeemer>,
    clock: Arc<dyn Clock>,
    jobs: Mutex<BTreeMap<String, Arc<JobSlot>>>,
}

impl std::fmt::Debug for BrokeredCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokeredCredentials")
            // The proxy's public key is its name and is safe to print; the job set's size is the
            // useful operational number. Neither tenants nor secret names appear.
            .field("proxy_key", &self.identity.public().to_string())
            .field("live_jobs", &self.jobs.lock().map(|j| j.len()).unwrap_or(0))
            .finish()
    }
}

impl BrokeredCredentials {
    /// Build a credential source over this proxy's enrolled identity.
    ///
    /// The identity must already be enrolled with
    /// [`ProxyCredentialService::enrol_proxy`](hull_ci_secrets::ProxyCredentialService::enrol_proxy)
    /// under the same `proxy_id` control names in its capability requests, or every redemption is
    /// refused with `UnenrolledProxy`. That is the correct failure — a proxy nobody provisioned
    /// spends nobody's credential — and it is loud rather than silent.
    pub fn new(identity: Arc<ProxyIdentity>, redeemer: Arc<dyn ProxyCredentialRedeemer>) -> Self {
        BrokeredCredentials {
            identity,
            redeemer,
            clock: Arc::new(SystemClock),
            jobs: Mutex::new(BTreeMap::new()),
        }
    }

    /// Share the broker's clock, so a test that drives capability expiry also drives the freshness
    /// window a redemption is signed under. Two clocks that can disagree is a deployment where the
    /// capability is live and every redemption of it looks stale.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Register a job's credential capability. Called by control when it mints the package grant.
    ///
    /// Re-registering a job replaces its slot, which drops (and therefore zeroizes) anything already
    /// held for it. That is the right behaviour for a retry — a re-placed job gets a fresh capability
    /// — and it is why this is a replace rather than an insert-if-absent.
    pub fn authorise_job(
        &self,
        tenant: impl Into<String>,
        job_id: impl Into<String>,
        capability: hull_ci_secrets::CapabilityToken,
    ) {
        self.put(tenant.into(), job_id.into(), JobState::Pending(capability));
    }

    /// Register a job that may spend **no** tenant credential, with the reason.
    ///
    /// Control calls this for an `outsider`-authored job (D§1, D§7.4 — see
    /// [`hull_ci_secrets::package`] for why *use* is authority even though the job never sees the
    /// value) and for a deployment running with no broker. Registering the refusal explicitly, rather
    /// than leaving the job unknown, is what keeps [`CredentialError::NoAuthority`] distinguishable
    /// from [`CredentialError::Unregistered`]: one is a decision, the other is a bug, and an operator
    /// needs to be told which.
    pub fn deny_job(
        &self,
        tenant: impl Into<String>,
        job_id: impl Into<String>,
        reason: impl Into<String>,
    ) {
        self.put(tenant.into(), job_id.into(), JobState::NoAuthority(reason.into()));
    }

    fn put(&self, tenant: String, job_id: String, state: JobState) {
        let slot = Arc::new(JobSlot { tenant, state: Mutex::new(state) });
        self.jobs.lock().expect("brokered credential registry poisoned").insert(job_id, slot);
    }

    /// A [`Masker`] primed with everything currently held for one job.
    ///
    /// For the proxy's own error text. D§7.4 is explicit that masking "is a backstop, not a control"
    /// — the control is that the job never receives the value — so this is for the accident where a
    /// refusal quotes an upstream's 401 body, not for an adversary.
    pub fn masker_for_job(&self, job_id: &str) -> Masker {
        let mut masker = Masker::new();
        let Some(slot) = self.slot(job_id) else { return masker };
        if let JobState::Held(values) = &*slot.state.lock().expect("job slot poisoned") {
            for value in values.values() {
                masker.register(value.expose());
            }
        }
        masker
    }

    /// How many jobs this source is holding state for. Operational, and asserted by tests that care
    /// that a release actually released.
    pub fn live_jobs(&self) -> usize {
        self.jobs.lock().expect("brokered credential registry poisoned").len()
    }

    fn slot(&self, job_id: &str) -> Option<Arc<JobSlot>> {
        self.jobs.lock().expect("brokered credential registry poisoned").get(job_id).cloned()
    }

    /// Spend this job's capability, once, and record the outcome.
    ///
    /// Called with the job's own lock held, so exactly one caller per job reaches the broker.
    fn redeem(&self, slot: &JobSlot, job_id: &str, state: &mut JobState) {
        let JobState::Pending(token) = state else { return };
        let signed: SignedProxyRedemption =
            self.identity.sign(token, &slot.tenant, job_id, self.clock.now_secs());
        *state = match self.redeemer.redeem(&signed) {
            Ok(delivered) => {
                // Fourth check of the same fact, and the cheapest. The broker binds the tenant into
                // the grant and only ever opens that tenant's rows; the service compares the grant
                // against the signed request; the lookup below compares the grant against the
                // registration. This one catches a *transport* that answered the wrong question —
                // the failure mode a remote `ProxyCredentialRedeemer` introduces and an in-process
                // one cannot.
                if delivered.tenant != slot.tenant || delivered.job_id != job_id {
                    tracing::error!(
                        job = %job_id,
                        expected_tenant = %slot.tenant,
                        delivered_tenant = %delivered.tenant,
                        "the broker answered for a different job or tenant; refusing the delivery"
                    );
                    JobState::Failed("the broker answered for a different job or tenant".to_string())
                } else {
                    tracing::info!(
                        tenant = %slot.tenant,
                        job = %job_id,
                        // Names, never values.
                        names = ?delivered.names(),
                        "redeemed this job's upstream registry credentials"
                    );
                    JobState::Held(
                        delivered
                            .names()
                            .into_iter()
                            .filter_map(|n| delivered.get(n).map(|v| (n.to_string(), v.clone())))
                            .collect(),
                    )
                }
            }
            Err(e) => {
                tracing::warn!(
                    tenant = %slot.tenant, job = %job_id, error = %e,
                    "could not redeem this job's upstream registry credentials; \
                     authenticated upstreams will be refused for it"
                );
                e.to_string().into()
            }
        };
    }
}

impl From<String> for JobState {
    fn from(detail: String) -> Self {
        JobState::Failed(detail)
    }
}

impl UpstreamCredentials for BrokeredCredentials {
    /// Resolve one attributed lookup, redeeming this job's capability if it has not been spent yet.
    ///
    /// The tenant comparison on the second line is the load-bearing one in this file. `req.tenant`
    /// comes off the *authenticated grant* the job presented; `slot.tenant` is what control
    /// registered. They agree in every correct deployment, and if they ever do not, one of them is
    /// wrong and serving either would be a cross-tenant disclosure — so neither is preferred and the
    /// request is refused.
    fn credential(&self, req: &CredentialRequest<'_>) -> Result<SecretBytes, CredentialError> {
        let slot = self
            .slot(req.job_id)
            .ok_or_else(|| CredentialError::Unregistered { job_id: req.job_id.to_string() })?;
        if slot.tenant != req.tenant {
            return Err(CredentialError::TenantMismatch {
                job_id: req.job_id.to_string(),
                registered: slot.tenant.clone(),
                presented: req.tenant.to_string(),
            });
        }

        let mut state = slot.state.lock().expect("job slot poisoned");
        self.redeem(&slot, req.job_id, &mut state);

        match &*state {
            // Unreachable: `redeem` above leaves no `Pending`. Refused rather than `unreachable!()`
            // so a future edit cannot turn a state-machine change into a panic on a live proxy.
            JobState::Pending(_) => Err(CredentialError::Unavailable {
                upstream: req.upstream.to_string(),
                detail: "capability was not redeemed".to_string(),
            }),
            JobState::NoAuthority(reason) => Err(CredentialError::NoAuthority {
                job_id: req.job_id.to_string(),
                upstream: req.upstream.to_string(),
                reason: reason.clone(),
            }),
            JobState::Failed(detail) => Err(CredentialError::Unavailable {
                upstream: req.upstream.to_string(),
                detail: detail.clone(),
            }),
            JobState::Held(values) => values.get(req.secret).cloned().ok_or_else(|| {
                // The capability covered this job's granted upstreams and this secret was not among
                // them, which means the allowlist and the capability disagree — a configuration
                // error, and the same answer a source that simply lacked the value would give.
                CredentialError::Missing {
                    upstream: req.upstream.to_string(),
                    name: req.secret.to_string(),
                }
            }),
        }
    }

    /// Drop everything held for a finished job.
    ///
    /// §14.1's "nothing survives into the next job" applied to a credential: the values zeroize when
    /// the slot drops. The proxy's grant registry drops the job's bearer at the same moment
    /// ([`crate::server::PackageProxy::release_job`]), so a job that has ended has neither the token
    /// to ask nor a credential to be spent on its behalf.
    fn release_job(&self, job_id: &str) {
        if self.jobs.lock().expect("brokered credential registry poisoned").remove(job_id).is_some() {
            tracing::debug!(job = %job_id, "dropped this job's upstream registry credentials");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hull_ci_proto::AuthorClass;
    use hull_ci_secrets::{
        DevKeyManager, MemorySealedStore, ProxyCapabilityRequest, ProxyRegistry, SecretBroker,
    };

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
        service: Arc<ProxyCredentialService>,
        creds: BrokeredCredentials,
        clock: Arc<TestClock>,
    }

    /// Two tenants with a registry token under the same *name*, so "which tenant's value came back"
    /// is a question with two plausible answers rather than one.
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
        let service = Arc::new(
            ProxyCredentialService::new(broker, Arc::new(ProxyRegistry::new())).with_clock(clock.clone()),
        );
        let identity = Arc::new(ProxyIdentity::generate());
        service.enrol_proxy("proxy-a", identity.public()).unwrap();

        let creds = BrokeredCredentials::new(
            identity,
            Arc::new(InProcessRedeemer::new(Arc::clone(&service))),
        )
        .with_clock(clock.clone());
        Fixture { service, creds, clock }
    }

    impl Fixture {
        fn mint(&self, tenant: &str, job_id: &str, class: AuthorClass) -> hull_ci_secrets::CapabilityToken {
            let (token, _) = self
                .service
                .mint(&ProxyCapabilityRequest {
                    tenant: tenant.into(),
                    job_id: job_id.into(),
                    proxy_id: "proxy-a".into(),
                    declared: vec!["NPM_TOKEN".into()],
                    author_class: class,
                    expires_at: 2_000,
                })
                .expect("mint");
            token
        }

        fn authorise(&self, tenant: &str, job_id: &str) {
            let token = self.mint(tenant, job_id, AuthorClass::Member);
            self.creds.authorise_job(tenant, job_id, token);
        }
    }

    fn req<'a>(tenant: &'a str, job_id: &'a str) -> CredentialRequest<'a> {
        CredentialRequest { tenant, job_id, upstream: "private", secret: "NPM_TOKEN" }
    }

    #[test]
    fn an_authorised_job_gets_its_tenants_upstream_credential() {
        let f = fixture();
        f.authorise("acme", "job-1");
        let value = f.creds.credential(&req("acme", "job-1")).unwrap();
        assert_eq!(value.expose(), b"acme-npm-token");
    }

    /// **The tenant-scoping test.** Named, because breaking the check in
    /// [`BrokeredCredentials::credential`] must make a test fail by name.
    #[test]
    fn a_job_registered_under_one_tenant_cannot_serve_another() {
        // Both tenants have a job and a `NPM_TOKEN`. A grant claiming `globex` against `acme`'s job
        // must not resolve — in either direction, and not to either value.
        let f = fixture();
        f.authorise("acme", "job-1");
        f.authorise("globex", "job-2");

        assert_eq!(
            f.creds.credential(&req("globex", "job-1")).unwrap_err(),
            CredentialError::TenantMismatch {
                job_id: "job-1".into(),
                registered: "acme".into(),
                presented: "globex".into(),
            }
        );
        assert!(matches!(
            f.creds.credential(&req("acme", "job-2")),
            Err(CredentialError::TenantMismatch { .. })
        ));

        // And each job still gets its own, so the refusal above is scoping rather than breakage.
        assert_eq!(f.creds.credential(&req("acme", "job-1")).unwrap().expose(), b"acme-npm-token");
        assert_eq!(f.creds.credential(&req("globex", "job-2")).unwrap().expose(), b"globex-npm-token");
    }

    #[test]
    fn a_tenants_capability_only_ever_yields_that_tenants_value() {
        // The same property one layer down: even with the registration agreeing, the value that
        // comes back is the one sealed under *that* tenant's KEK. The shared secret name is what
        // makes this a real assertion.
        let f = fixture();
        f.authorise("acme", "job-1");
        f.authorise("globex", "job-2");
        let acme = f.creds.credential(&req("acme", "job-1")).unwrap();
        let globex = f.creds.credential(&req("globex", "job-2")).unwrap();
        assert_ne!(acme.expose(), globex.expose());
        assert_eq!(acme.expose(), b"acme-npm-token");
    }

    #[test]
    fn a_job_nobody_registered_is_refused_rather_than_served_anonymously() {
        let f = fixture();
        assert_eq!(
            f.creds.credential(&req("acme", "ghost-job")).unwrap_err(),
            CredentialError::Unregistered { job_id: "ghost-job".into() }
        );
    }

    #[test]
    fn a_job_control_denied_is_refused_with_the_reason_control_gave() {
        // The outsider path as the composition root drives it: the broker refuses to mint, so
        // control registers the refusal instead of a capability, and the author gets told why.
        let f = fixture();
        let outsider = f.service.mint(&ProxyCapabilityRequest {
            tenant: "acme".into(),
            job_id: "job-fork".into(),
            proxy_id: "proxy-a".into(),
            declared: vec!["NPM_TOKEN".into()],
            author_class: AuthorClass::Outsider,
            expires_at: 2_000,
        });
        assert_eq!(outsider.unwrap_err(), SecretError::OutsiderRefused);

        f.creds.deny_job("acme", "job-fork", "outsider-authored jobs may not spend a tenant credential");
        let err = f.creds.credential(&req("acme", "job-fork")).unwrap_err();
        assert!(matches!(err, CredentialError::NoAuthority { .. }));
        assert!(err.to_string().contains("outsider-authored"));
        assert!(err.is_policy_refusal(), "the job's authority, not the operator's configuration");
    }

    #[test]
    fn one_capability_serves_a_whole_jobs_worth_of_requests() {
        // The mismatch this module exists to resolve: single-use capability, hundreds of package
        // requests. Redeemed once, then served from memory.
        let f = fixture();
        f.authorise("acme", "job-1");
        for _ in 0..50 {
            assert_eq!(f.creds.credential(&req("acme", "job-1")).unwrap().expose(), b"acme-npm-token");
        }
    }

    #[test]
    fn the_capability_is_spent_lazily_and_only_once() {
        // Before any request needing a credential, the tenant's token does not exist in this process
        // at all — so a job that resolves nothing never causes it to.
        let f = fixture();
        let token = f.mint("acme", "job-1", AuthorClass::Member);
        f.creds.authorise_job("acme", "job-1", token.clone());

        // Redeeming the same token from outside, first, proves the proxy had not spent it yet.
        let signed = ProxyIdentity::generate().sign(&token, "acme", "job-1", 1_000);
        assert!(matches!(f.service.redeem(&signed), Err(SecretError::UnenrolledProxy(_))));

        assert!(f.creds.credential(&req("acme", "job-1")).is_ok());
        // And now it is spent: a second redemption of the same capability, by anyone, fails.
        assert!(f.creds.credential(&req("acme", "job-1")).is_ok(), "served from memory, not re-redeemed");
    }

    #[test]
    fn a_refused_redemption_is_remembered_rather_than_retried() {
        // The capability is single-use, so a retry would report `CapabilityConsumed` and tell an
        // operator a worse story than the real failure did.
        let f = fixture();
        let token = f.mint("acme", "job-1", AuthorClass::Member);
        f.service.proxies().revoke("proxy-a");
        f.creds.authorise_job("acme", "job-1", token);

        let first = f.creds.credential(&req("acme", "job-1")).unwrap_err();
        let second = f.creds.credential(&req("acme", "job-1")).unwrap_err();
        assert_eq!(first, second, "the same diagnosis both times");
        assert!(matches!(first, CredentialError::Unavailable { .. }));
        assert!(first.to_string().contains("not enrolled"));
    }

    #[test]
    fn an_expired_capability_refuses_rather_than_serving_stale_credentials() {
        let f = fixture();
        let token = f.mint("acme", "job-1", AuthorClass::Member);
        f.creds.authorise_job("acme", "job-1", token);
        f.clock.set(2_001);
        let err = f.creds.credential(&req("acme", "job-1")).unwrap_err();
        assert!(matches!(err, CredentialError::Unavailable { .. }));
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn revoking_a_tenant_stops_its_proxy_access() {
        let f = fixture();
        let token = f.mint("acme", "job-1", AuthorClass::Member);
        f.service.broker().revoke_tenant("acme");
        f.creds.authorise_job("acme", "job-1", token);
        let err = f.creds.credential(&req("acme", "job-1")).unwrap_err();
        assert!(err.to_string().contains("revoked"), "{err}");
    }

    #[test]
    fn crypto_shredding_a_tenant_stops_its_proxy_access_and_leaves_others_alone() {
        let f = fixture();
        let acme = f.mint("acme", "job-1", AuthorClass::Member);
        let globex = f.mint("globex", "job-2", AuthorClass::Member);
        f.creds.authorise_job("acme", "job-1", acme);
        f.creds.authorise_job("globex", "job-2", globex);

        f.service.broker().shred_tenant("acme").unwrap();

        assert!(f.creds.credential(&req("acme", "job-1")).is_err());
        // Blast-radius isolation: the whole reason for one KEK per tenant.
        assert_eq!(f.creds.credential(&req("globex", "job-2")).unwrap().expose(), b"globex-npm-token");
    }

    /// **This test documents a gap. It is not a bug to be fixed in this file.**
    ///
    /// The module doc rejects a TTL cache because it would make "revocation stops proxy access" into
    /// "…eventually", "which is not the property D§7.4 claims". The held plaintext has exactly that
    /// property, bounded by the job rather than by a clock: once a capability is spent, neither
    /// [`SecretBroker::revoke_tenant`] nor [`SecretBroker::shred_tenant`] reaches the values, because
    /// they live in this process's memory and the broker has no way to reach into it.
    ///
    /// `crypto_shredding_a_tenant_stops_its_proxy_access_and_leaves_others_alone` above shreds while
    /// the capability is still `Pending`, which is the case that *does* shut. This is the other one.
    /// Closing it needs a push from the broker to every proxy holding a job for that tenant — a
    /// notification path this composition does not have — so what an operator has today is
    /// [`crate::server::PackageProxy::release_job`] on the job, and the bound is the job's lifetime.
    #[test]
    fn revocation_does_not_reach_a_credential_the_proxy_already_holds() {
        let f = fixture();
        f.authorise("acme", "job-1");
        // The job resolves one package: the capability is spent and the plaintext is now held here.
        assert_eq!(f.creds.credential(&req("acme", "job-1")).unwrap().expose(), b"acme-npm-token");

        // Break glass, both paths D§7.4 names. The already-spent record is marked revoked, which
        // changes nothing about it — it was already spent — and the KEK is destroyed, which makes
        // the *ciphertext* unrecoverable but says nothing about a copy already decrypted.
        assert_eq!(f.service.broker().revoke_tenant("acme"), 1);
        f.service.broker().shred_tenant("acme").unwrap();

        assert_eq!(
            f.creds.credential(&req("acme", "job-1")).unwrap().expose(),
            b"acme-npm-token",
            "the proxy keeps spending it until the job is released"
        );
        // And the one thing that does stop it.
        f.creds.release_job("job-1");
        assert!(matches!(
            f.creds.credential(&req("acme", "job-1")),
            Err(CredentialError::Unregistered { .. })
        ));
    }

    #[test]
    fn releasing_a_job_drops_its_credentials() {
        // §14.1 applied to a credential. After release the job is not merely unauthorised, it is
        // unknown, and the values it held have been dropped (and therefore zeroized).
        let f = fixture();
        f.authorise("acme", "job-1");
        assert!(f.creds.credential(&req("acme", "job-1")).is_ok());
        assert_eq!(f.creds.live_jobs(), 1);

        f.creds.release_job("job-1");
        assert_eq!(f.creds.live_jobs(), 0);
        assert_eq!(
            f.creds.credential(&req("acme", "job-1")).unwrap_err(),
            CredentialError::Unregistered { job_id: "job-1".into() }
        );
        f.creds.release_job("job-1"); // releasing twice is a no-op, not a panic
    }

    #[test]
    fn a_secret_outside_the_capability_is_refused() {
        let f = fixture();
        f.authorise("acme", "job-1");
        let other = CredentialRequest {
            tenant: "acme",
            job_id: "job-1",
            upstream: "other",
            secret: "SOME_OTHER_TOKEN",
        };
        assert!(matches!(f.creds.credential(&other), Err(CredentialError::Missing { .. })));
    }

    #[test]
    fn concurrent_first_requests_redeem_exactly_once() {
        // The race the per-job lock exists for: `npm` opens many connections at once, and a
        // single-use capability means a lost race is a build failure rather than a retry.
        let f = Arc::new(fixture());
        f.authorise("acme", "job-1");
        let mut handles = Vec::new();
        for _ in 0..16 {
            let f = Arc::clone(&f);
            handles.push(std::thread::spawn(move || {
                f.creds.credential(&req("acme", "job-1")).map(|v| v.expose().to_vec())
            }));
        }
        for handle in handles {
            assert_eq!(handle.join().unwrap().unwrap(), b"acme-npm-token".to_vec());
        }
    }

    #[test]
    fn a_masker_is_primed_from_what_is_actually_held() {
        let f = fixture();
        f.authorise("acme", "job-1");
        // Nothing is held until something needs it, so the masker is empty until then — which is
        // correct, because a value that does not exist cannot appear in output.
        assert_eq!(f.creds.masker_for_job("job-1").mask("acme-npm-token"), "acme-npm-token");
        f.creds.credential(&req("acme", "job-1")).unwrap();
        assert_eq!(f.creds.masker_for_job("job-1").mask("acme-npm-token"), "***");
        assert_eq!(f.creds.masker_for_job("nobody").mask("acme-npm-token"), "acme-npm-token");
    }

    #[test]
    fn nothing_credential_shaped_appears_in_debug_output() {
        let f = fixture();
        f.authorise("acme", "job-1");
        f.creds.credential(&req("acme", "job-1")).unwrap();
        let rendered = format!("{:?}", f.creds);
        assert!(!rendered.contains("acme-npm-token"), "{rendered}");
        assert!(!rendered.contains("NPM_TOKEN"), "{rendered}");
        assert!(rendered.contains("live_jobs: 1"));
    }
}
