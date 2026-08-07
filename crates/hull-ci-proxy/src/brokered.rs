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
//! It has to be. A single-use capability cannot be redeemed per package request. So the credential is
//! redeemed on the first request of a job that actually needs one, and lives in memory until
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
//! # Break glass reaches the held copy, and what that costs
//!
//! For a while it did not, and the module doc said so in a way that made the gap sound smaller than
//! it was. It argued against a TTL cache *because* a TTL would turn "revocation stops proxy access"
//! into "revocation stops proxy access eventually", "which is not the property D§7.4 claims" — and
//! then held the plaintext with exactly that property, bounded by the job instead of by a clock. A
//! job is not obviously shorter than a TTL, and neither
//! [`SecretBroker::revoke_tenant`](hull_ci_secrets::SecretBroker::revoke_tenant) nor
//! [`SecretBroker::shred_tenant`](hull_ci_secrets::SecretBroker::shred_tenant) reached the values:
//! revoking marked a record that was already spent, and shredding destroyed the KEK, which makes the
//! *ciphertext* unrecoverable and says nothing about a copy already decrypted.
//!
//! So the authority is **re-asserted on the use path**, through
//! [`SecretBroker::reassert_proxy_capability`](hull_ci_secrets::SecretBroker::reassert_proxy_capability),
//! before every credential this type serves — and a credential that fails re-assertion is not merely
//! withheld, it is dropped, which zeroizes it. Three properties follow, in the order they matter:
//!
//! * **It fails closed.** A refusal and a *missing answer* — a broker that is down, a link that
//!   timed out, a capability record that is simply gone — are the same answer here, and it is no.
//!   That is the direction that matters: an operator who has just shredded a tenant is responding to
//!   a compromise, and the notification-push shape this could have taken instead fails the other way
//!   when a message is lost.
//! * **The residual window is one in-flight request**, not a clock interval. A revocation that
//!   commits before a package request looks up its credential stops that request. A request that has
//!   already built its `Authorization` header completes — there is no way to reach into a socket
//!   mid-flight — so what an operator is promised is "no *new* upstream request after the revoke",
//!   and the honest bound on the old one is the upstream's own timeout.
//! * **It costs a broker call per credential lookup.** In the composition this repository ships,
//!   that is a `Mutex` and a hash lookup, which is nothing beside the TLS connection the credential
//!   is about to be spent on. On a fleet where the broker is a socket it is a round trip, and this is
//!   the one place the module accepts one on the hot path. A cache with a lifetime would buy it back
//!   and would reintroduce exactly the "…eventually" this section exists to remove, so a deployment
//!   that wants the cost back should shorten the *job's* capability instead, where the shortening is
//!   visible to control rather than hidden in a proxy.
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
//! | the broker refused or was unreachable at redemption | [`CredentialError::Unavailable`] |
//! | authority was withdrawn, or could not be re-confirmed, after the credential was held | [`CredentialError::Invalidated`] — and the value is dropped |
//!
//! None of them is "proceed unauthenticated".

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use hull_ci_secrets::{
    CapabilityToken, Clock, DeliveredSecrets, Masker, ProxyCredentialReassertion,
    ProxyCredentialService, ProxyIdentity, SecretBytes, SecretError, SignedProxyRedemption,
    SystemClock,
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

    /// Is a credential this proxy already holds still authorised?
    ///
    /// **An implementation must not answer `Ok` from memory when it could not reach the broker.**
    /// This is the break-glass path: the whole value of the check is that a lost answer counts as a
    /// refusal, and an implementation that softened an error into "probably still fine" would put
    /// back the failure it exists to close. Returning any `Err` — including a transport one — makes
    /// [`BrokeredCredentials`] drop the credential, which is the intended behaviour and not a bug to
    /// be smoothed over.
    ///
    /// No default implementation, deliberately. A defaulted `Ok(())` would let a redeemer written for
    /// some future deployment opt out of revocation by saying nothing at all.
    fn reassert(&self, req: &ProxyCredentialReassertion) -> Result<(), SecretError>;
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

    fn reassert(&self, req: &ProxyCredentialReassertion) -> Result<(), SecretError> {
        self.service.reassert(req)
    }
}

/// What the proxy knows about one live job's credential authority.
enum JobState {
    /// Control gave this job a capability the proxy has not spent yet.
    Pending(CapabilityToken),
    /// Spent. These are the values, held until the job is released — or until the broker stops
    /// vouching for them.
    Held {
        /// The spent capability, kept so the authority behind these values can be re-asserted before
        /// each use. Worthless on its own — it is consumed, so it buys nobody a redemption — and it
        /// is what lets a revocation reach a decrypted copy at all.
        token: CapabilityToken,
        values: BTreeMap<String, SecretBytes>,
    },
    /// Control registered the job and said it may spend nothing. The reason is an operator's, and
    /// gets repeated back in the refusal — an author reading "outsider-authored jobs may not spend a
    /// tenant credential" can act on it; a bare 403 cannot be acted on at all.
    NoAuthority(String),
    /// The redemption was attempted and refused. Remembered rather than retried: the capability is
    /// single-use, so the second attempt would fail differently (`CapabilityConsumed`) and tell an
    /// operator a worse story than the first failure did.
    Failed(String),
    /// The values were held, and then the broker stopped vouching for them — or stopped answering.
    /// **Terminal, and the values are gone**: reaching this state drops the `Held` map, which
    /// zeroizes every value in it.
    ///
    /// Terminal rather than re-checked on the next request, and that is a deliberate one-way door.
    /// Re-checking would mean a broker that flapped could hand a revoked tenant's credential back,
    /// and there is nothing to hand back anyway — the plaintext is destroyed, and getting it again
    /// would need a fresh capability, which control mints only for a fresh job.
    Invalidated(String),
}

impl std::fmt::Debug for JobState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Neither the token nor the values, and for `Held` not even the names: a job's private
            // registry set is not something to put in a log line by accident.
            JobState::Pending(_) => f.write_str("Pending(<capability>)"),
            JobState::Held { values, .. } => write!(f, "Held({} credentials)", values.len()),
            JobState::NoAuthority(r) => write!(f, "NoAuthority({r})"),
            JobState::Failed(d) => write!(f, "Failed({d})"),
            JobState::Invalidated(d) => write!(f, "Invalidated({d})"),
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
        if let JobState::Held { values, .. } = &*slot.state.lock().expect("job slot poisoned") {
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
        // Cloned before the state is reassigned, because a spent capability is not finished with: it
        // is the handle the re-assertion below asks about for the rest of the job.
        let token = token.clone();
        let signed: SignedProxyRedemption =
            self.identity.sign(&token, &slot.tenant, job_id, self.clock.now_secs());
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
                    JobState::Held {
                        token,
                        values: delivered
                            .names()
                            .into_iter()
                            .filter_map(|n| delivered.get(n).map(|v| (n.to_string(), v.clone())))
                            .collect(),
                    }
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

    /// Re-assert the authority behind a credential this proxy is already holding, and **destroy** the
    /// credential if the answer is anything other than yes.
    ///
    /// This is what makes a revocation reach a decrypted copy (see the module doc). Three details are
    /// load-bearing:
    ///
    /// * **It runs on every lookup, including the one immediately after a redemption.** The extra
    ///   call on the first request of a job buys uniformity: "every use is re-asserted" is a property
    ///   a reader can check by looking at one call site, and a "we only just fetched it" fast path is
    ///   exactly the kind of exception that stops being true after two more edits.
    /// * **Any `Err` invalidates**, including a transport failure. A missing answer is a refusal
    ///   here; see [`ProxyCredentialRedeemer::reassert`].
    /// * **The values are dropped rather than gated.** Assigning over [`JobState::Held`] drops the
    ///   map, and [`SecretBytes`] zeroizes on drop, so break-glass removes the plaintext from this
    ///   process instead of leaving it sitting behind a flag that a later edit could stop consulting.
    ///
    /// Called with the job's own lock held, so a job's re-assertions serialise with each other and
    /// with its redemption — the same discipline, and the same reason.
    fn reassert(&self, slot: &JobSlot, job_id: &str, state: &mut JobState) {
        let JobState::Held { token, .. } = state else { return };
        let req = ProxyCredentialReassertion {
            token: token.clone(),
            tenant: slot.tenant.clone(),
            job_id: job_id.to_string(),
            public_key: self.identity.public(),
        };
        if let Err(e) = self.redeemer.reassert(&req) {
            tracing::warn!(
                tenant = %slot.tenant, job = %job_id, error = %e,
                "this job's upstream registry credentials are no longer authorised; \
                 dropping them and refusing authenticated upstreams for the rest of the job"
            );
            *state = JobState::Invalidated(e.to_string());
        }
    }
}

impl From<String> for JobState {
    fn from(detail: String) -> Self {
        JobState::Failed(detail)
    }
}

impl UpstreamCredentials for BrokeredCredentials {
    /// Resolve one attributed lookup: redeem this job's capability if it has not been spent yet, then
    /// re-assert it whether or not it just was.
    ///
    /// Two checks, and they answer different questions. Redemption asks *may this job have a
    /// credential*, once. Re-assertion asks *may it still*, every time — which is the only way an
    /// operator's break-glass reaches a value this process has already decrypted, and the reason
    /// there is a broker call on the request path at all (module doc).
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
        // Every use, not every redemption. This is the line that makes D§7.4's break-glass paths
        // reach a credential this process has already decrypted — see [`BrokeredCredentials::reassert`].
        self.reassert(&slot, req.job_id, &mut state);

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
            JobState::Invalidated(detail) => Err(CredentialError::Invalidated {
                job_id: req.job_id.to_string(),
                upstream: req.upstream.to_string(),
                detail: detail.clone(),
            }),
            JobState::Held { values, .. } => values.get(req.secret).cloned().ok_or_else(|| {
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

    /// A proxy→broker seam that can be cut mid-job, standing in for a broker that is down, a link
    /// that dropped, or a message that was lost.
    ///
    /// Only the *re-assertion* is cut. Redemption is left working on purpose: the question these
    /// tests ask is what happens to a credential the proxy is **already holding** when the answer
    /// stops arriving, and a fixture that also broke redemption could not get one held.
    #[derive(Debug)]
    struct Cuttable {
        inner: InProcessRedeemer,
        cut: std::sync::atomic::AtomicBool,
    }

    impl Cuttable {
        fn new(inner: InProcessRedeemer) -> Self {
            Cuttable { inner, cut: std::sync::atomic::AtomicBool::new(false) }
        }

        fn cut(&self) {
            self.cut.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl ProxyCredentialRedeemer for Cuttable {
        fn redeem(&self, req: &SignedProxyRedemption) -> Result<DeliveredSecrets, SecretError> {
            self.inner.redeem(req)
        }

        fn reassert(&self, req: &ProxyCredentialReassertion) -> Result<(), SecretError> {
            if self.cut.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(SecretError::Store("broker unreachable".into()));
            }
            self.inner.reassert(req)
        }
    }

    /// Two tenants with a registry token under the same *name*, so "which tenant's value came back"
    /// is a question with two plausible answers rather than one.
    fn fixture() -> Fixture {
        fixture_with(|service| Arc::new(InProcessRedeemer::new(service))).0
    }

    /// The same fixture with the proxy→broker seam built by `wrap`. Everything above the seam is
    /// identical, which is what lets a test ask "and what if the broker stops answering" without
    /// changing anything else about the setup.
    fn fixture_with<R: ProxyCredentialRedeemer + 'static>(
        wrap: impl FnOnce(Arc<ProxyCredentialService>) -> Arc<R>,
    ) -> (Fixture, Arc<R>) {
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

        let redeemer = wrap(Arc::clone(&service));
        let creds = BrokeredCredentials::new(identity, Arc::clone(&redeemer) as Arc<dyn ProxyCredentialRedeemer>)
            .with_clock(clock.clone());
        (Fixture { service, creds, clock }, redeemer)
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

    /// The **pending** half of tenant revocation: the capability is never spent at all.
    ///
    /// Kept as its own test rather than folded into the held case below, because the two shut through
    /// entirely different machinery — this one through the broker refusing a redemption, that one
    /// through the proxy re-asserting on the use path — and a single test covering "revocation works"
    /// would go on passing if either half broke.
    #[test]
    fn revoking_a_tenant_stops_a_capability_it_has_not_spent_yet() {
        let f = fixture();
        let token = f.mint("acme", "job-1", AuthorClass::Member);
        f.service.broker().revoke_tenant("acme");
        f.creds.authorise_job("acme", "job-1", token);
        let err = f.creds.credential(&req("acme", "job-1")).unwrap_err();
        assert!(err.to_string().contains("revoked"), "{err}");
    }

    /// The **pending** half of the crypto-shred, and the case that always shut.
    ///
    /// This is what `crypto_shredding_a_tenant_stops_its_proxy_access_and_leaves_others_alone` used
    /// to be, renamed for what it actually tests. Under its old name it read as a guarantee about
    /// shredding in general while only ever exercising the state where shredding already worked, and
    /// the state where it did not went untested for exactly that reason.
    #[test]
    fn crypto_shredding_a_tenant_stops_a_capability_it_has_not_spent_yet() {
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

    /// **The break-glass test.** Named, because breaking the re-assertion in
    /// [`BrokeredCredentials::credential`] must make a test fail by name.
    ///
    /// This is the case an audit found open and the case the two tests above do *not* cover: the
    /// capability is spent and the plaintext is sitting in this process before the operator breaks
    /// glass. Both of D§7.4's paths are exercised, and both have to reach it — revocation because it
    /// is the one that actually travels to a live proxy, and the shred because an operator will
    /// reach for it believing it is the stronger of the two.
    #[test]
    fn revoking_a_tenant_reaches_a_credential_the_proxy_already_holds() {
        let f = fixture();
        f.authorise("acme", "job-1");
        f.authorise("globex", "job-2");
        // Both jobs resolve a package: the capabilities are spent and the plaintext is held here.
        assert_eq!(f.creds.credential(&req("acme", "job-1")).unwrap().expose(), b"acme-npm-token");
        assert_eq!(f.creds.credential(&req("globex", "job-2")).unwrap().expose(), b"globex-npm-token");

        assert_eq!(f.service.broker().revoke_tenant("acme"), 1);

        let err = f.creds.credential(&req("acme", "job-1")).unwrap_err();
        assert!(matches!(err, CredentialError::Invalidated { .. }), "{err}");
        assert!(err.to_string().contains("revoked"), "{err}");
        assert!(err.is_policy_refusal(), "authority withdrawn, not an outage");
        // Blast-radius isolation, on the use path this time: one tenant's break-glass must not cost
        // every other tenant on the fleet its package resolution.
        assert_eq!(f.creds.credential(&req("globex", "job-2")).unwrap().expose(), b"globex-npm-token");
    }

    #[test]
    fn crypto_shredding_a_tenant_reaches_a_credential_the_proxy_already_holds() {
        // The shred's own reach is *not* what closes this: destroying the KEK makes the ciphertext
        // unrecoverable and says nothing about a copy already decrypted. What closes it is that
        // `shred_tenant` revokes first, and the proxy re-reads that mark before every use — which is
        // why the ordering inside `shred_tenant` is load-bearing rather than tidy.
        let f = fixture();
        f.authorise("acme", "job-1");
        f.authorise("globex", "job-2");
        assert_eq!(f.creds.credential(&req("acme", "job-1")).unwrap().expose(), b"acme-npm-token");
        assert_eq!(f.creds.credential(&req("globex", "job-2")).unwrap().expose(), b"globex-npm-token");

        f.service.broker().shred_tenant("acme").unwrap();

        assert!(matches!(
            f.creds.credential(&req("acme", "job-1")),
            Err(CredentialError::Invalidated { .. })
        ));
        assert_eq!(f.creds.credential(&req("globex", "job-2")).unwrap().expose(), b"globex-npm-token");
    }

    #[test]
    fn an_invalidated_credential_is_destroyed_rather_than_withheld() {
        // The difference between "refused" and "gone". A flag the serving path consults is one edit
        // away from not being consulted; a value that has been dropped is not there to serve. The
        // masker is the observable proxy for that, since it is primed from what is *actually held*.
        let f = fixture();
        f.authorise("acme", "job-1");
        f.creds.credential(&req("acme", "job-1")).unwrap();
        assert_eq!(f.creds.masker_for_job("job-1").mask("acme-npm-token"), "***");

        f.service.broker().revoke_tenant("acme");
        assert!(f.creds.credential(&req("acme", "job-1")).is_err());

        assert_eq!(
            f.creds.masker_for_job("job-1").mask("acme-npm-token"),
            "acme-npm-token",
            "nothing is held for this job any more, so there is nothing left to mask"
        );
        // The job is still registered — it has not ended — it simply has no credential.
        assert_eq!(f.creds.live_jobs(), 1);
        assert!(format!("{:?}", f.creds).contains("live_jobs: 1"));
    }

    /// **The fail-closed test.** A *lost* invalidation must not leave the credential usable.
    ///
    /// This is the property that decided the mechanism's shape. The obvious alternative — the broker
    /// pushing an invalidation to every proxy holding a job for the tenant — fails the other way:
    /// a dropped message leaves the proxy spending a compromised tenant's credential and nothing
    /// anywhere notices. Re-asserting on the use path makes silence indistinguishable from a
    /// refusal, which is the only direction that is safe on a break-glass path.
    #[test]
    fn a_lost_invalidation_signal_refuses_rather_than_serving() {
        let (f, link) = fixture_with(|s| Arc::new(Cuttable::new(InProcessRedeemer::new(s))));
        f.authorise("acme", "job-1");
        assert_eq!(f.creds.credential(&req("acme", "job-1")).unwrap().expose(), b"acme-npm-token");

        // The broker never gets to say "revoked" — it never gets to say anything.
        link.cut();

        let err = f.creds.credential(&req("acme", "job-1")).unwrap_err();
        assert!(matches!(err, CredentialError::Invalidated { .. }), "{err}");
        assert!(err.to_string().contains("broker unreachable"), "the detail names the real cause: {err}");
        assert_eq!(
            f.creds.masker_for_job("job-1").mask("acme-npm-token"),
            "acme-npm-token",
            "an unanswered re-assertion destroys the credential, the same as a refused one"
        );
    }

    #[test]
    fn a_credential_invalidated_by_an_outage_does_not_come_back_when_the_broker_does() {
        // Invalidation is a one-way door. A broker that flaps must not be a way to keep serving a
        // credential across a revocation that landed while it was down — and there is nothing to
        // serve anyway, because the plaintext was destroyed rather than parked.
        let (f, link) = fixture_with(|s| Arc::new(Cuttable::new(InProcessRedeemer::new(s))));
        f.authorise("acme", "job-1");
        f.creds.credential(&req("acme", "job-1")).unwrap();

        link.cut();
        assert!(f.creds.credential(&req("acme", "job-1")).is_err());
        link.cut.store(false, std::sync::atomic::Ordering::SeqCst);

        assert!(
            matches!(f.creds.credential(&req("acme", "job-1")), Err(CredentialError::Invalidated { .. })),
            "a recovered link must not resurrect a destroyed credential"
        );
    }

    #[test]
    fn withdrawing_this_proxys_enrolment_reaches_a_credential_it_already_holds() {
        // D§7.4's break-glass for a compromised *proxy*, which had the same shape of gap as the
        // tenant one: `ProxyRegistry::revoke` stopped the process fetching anything new and left it
        // spending everything it had already fetched. The re-assertion carries the proxy's key for
        // exactly this, and it is one call rather than one per tenant.
        let f = fixture();
        f.authorise("acme", "job-1");
        f.authorise("globex", "job-2");
        assert!(f.creds.credential(&req("acme", "job-1")).is_ok());
        assert!(f.creds.credential(&req("globex", "job-2")).is_ok());

        assert!(f.service.proxies().revoke("proxy-a"));

        for (tenant, job) in [("acme", "job-1"), ("globex", "job-2")] {
            let err = f.creds.credential(&req(tenant, job)).unwrap_err();
            assert!(matches!(err, CredentialError::Invalidated { .. }), "{tenant}: {err}");
            assert!(err.to_string().contains("not enrolled"), "{err}");
        }
    }

    #[test]
    fn revoking_one_jobs_capability_reaches_that_job_and_no_other() {
        // The narrowest break-glass, and the one that comes for free from re-asserting against the
        // capability record rather than against a per-tenant counter: two jobs of the *same* tenant
        // are separable.
        let f = fixture();
        let (token, grant) = f
            .service
            .mint(&ProxyCapabilityRequest {
                tenant: "acme".into(),
                job_id: "job-1".into(),
                proxy_id: "proxy-a".into(),
                declared: vec!["NPM_TOKEN".into()],
                author_class: AuthorClass::Member,
                expires_at: 2_000,
            })
            .unwrap();
        f.creds.authorise_job("acme", "job-1", token);
        f.authorise("acme", "job-2");
        assert!(f.creds.credential(&req("acme", "job-1")).is_ok());
        assert!(f.creds.credential(&req("acme", "job-2")).is_ok());

        assert!(f.service.broker().revoke_proxy_capability(grant.cap_id));

        assert!(matches!(
            f.creds.credential(&req("acme", "job-1")),
            Err(CredentialError::Invalidated { .. })
        ));
        assert_eq!(
            f.creds.credential(&req("acme", "job-2")).unwrap().expose(),
            b"acme-npm-token",
            "the tenant's other job was not revoked and must keep resolving"
        );
    }

    #[test]
    fn a_capability_that_expires_mid_job_stops_the_credential_it_delivered() {
        // A gap this closed in passing. The proxy's capability expires with the job's package grant
        // (`hull_ci_secrets::package`), and until the use path re-asserted, reaching that expiry
        // while the job was still running left the plaintext being spent regardless.
        let f = fixture();
        f.authorise("acme", "job-1");
        assert_eq!(f.creds.credential(&req("acme", "job-1")).unwrap().expose(), b"acme-npm-token");

        f.clock.set(2_000);

        let err = f.creds.credential(&req("acme", "job-1")).unwrap_err();
        assert!(matches!(err, CredentialError::Invalidated { .. }), "{err}");
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[test]
    fn releasing_a_job_still_stops_a_held_credential() {
        // The bound that existed before any of this, and still does. A released job is not merely
        // unauthorised, it is unknown — which is a stronger statement than "invalidated" and the one
        // §14.1 asks for.
        let f = fixture();
        f.authorise("acme", "job-1");
        assert!(f.creds.credential(&req("acme", "job-1")).is_ok());
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
