//! The broker: storage, the gate, and just-in-time delivery.
//!
//! D§7.4 describes "a fourth credential-scoped process, sibling to the fetch broker and package
//! proxy. Its job: store tenant secrets encrypted, and hand exactly one job's declared secrets to
//! exactly the node running that job, at exec time, for `member`-authored jobs only." This type is
//! that process's logic, minus the transport.
//!
//! **The one thing to get right is the gate.** [`SecretBroker::mint`] refuses
//! [`AuthorClass::Outsider`] before it does anything else — before it validates a name, before it
//! touches the store, before it learns whether the tenant has any secrets at all. The pipeline is
//! never consulted, because the pipeline is a file in the tree under test and the tree under test is
//! written by whoever authored the change. That asymmetry is the whole defence against the
//! "pwn request" class: a fork PR can edit `.hull/ci.star` to declare `secrets = ["PROD_TOKEN"]`,
//! and it changes nothing, because the broker derives author class from the dispatch's `author` and
//! repo membership (D§1) and the declaration only ever *narrows* what a capability covers.
//!
//! Spec §14.2 is untouched by any of this: no platform credential — the `X-Hull-CI-Secret`, cloud
//! keys, registry tokens, `source_url` auth — is reachable from here. The broker can only emit
//! values a tenant explicitly stored under its own KEK.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use hull_ci_proto::{Assignment, AuthorClass};
use zeroize::Zeroizing;

use crate::capability::{mint_record, parse_token, CapId, CapabilityGrant, CapabilityToken, DEFAULT_TTL_SECS};
use crate::keys::KeyManager;
use crate::mask::Masker;
use crate::package::{mint_proxy_record, ProxyCapRecord, ProxyCapabilityRequest, ProxyCredentialGrant};
use crate::seal::{SecretBytes, Vault};
use crate::store::SealedStore;
use crate::{validate_name, Clock, SecretError, SystemClock};

/// What the control plane asks for at placement.
#[derive(Debug, Clone)]
pub struct CapabilityRequest {
    pub tenant: String,
    pub job_id: String,
    /// The node this capability will be redeemable from, and only this one.
    pub node_id: String,
    /// Names the step declared. Narrows the capability; never widens the actor's authority.
    pub declared: Vec<String>,
    /// **Derived from the dispatch, never from the pipeline** (D§1).
    pub author_class: AuthorClass,
}

impl CapabilityRequest {
    /// Build a request from a leased [`Assignment`] plus the node it was placed on.
    ///
    /// The author class comes from the assignment — that is, from the control plane's own derivation
    /// — rather than from any argument this function could be handed wrong.
    pub fn for_assignment(assignment: &Assignment, node_id: impl Into<String>, declared: Vec<String>) -> Self {
        CapabilityRequest {
            tenant: assignment.tenant.clone(),
            job_id: assignment.job_id.clone(),
            node_id: node_id.into(),
            declared,
            author_class: assignment.author_class,
        }
    }
}

/// The values handed back on a successful redemption.
///
/// Held in memory "only for the spawn" (D§7.4) — every value zeroizes when this drops, so the node
/// should build the child's environment from it and let it fall out of scope immediately. It is
/// never written to disk and never sent anywhere.
#[derive(Debug)]
pub struct DeliveredSecrets {
    pub tenant: String,
    pub job_id: String,
    values: Vec<(String, SecretBytes)>,
}

impl DeliveredSecrets {
    pub fn names(&self) -> Vec<&str> {
        self.values.iter().map(|(n, _)| n.as_str()).collect()
    }

    pub fn get(&self, name: &str) -> Option<&SecretBytes> {
        self.values.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Environment entries for the sandbox.
    ///
    /// The values come back in [`Zeroizing`] so a caller that drops them mid-flight does not leave
    /// plaintext in the heap. A non-UTF-8 secret is skipped rather than lossily converted — an
    /// environment variable must be a string, and silently handing a job a mangled credential would
    /// produce a baffling failure far from its cause.
    ///
    /// Note for the integration step: hull-ci-node's `env::reject_forbidden` refuses
    /// credential-shaped names outright, which is correct for M1 (where the right number of secrets
    /// entering a sandbox is zero) and will need the node to distinguish *broker-delivered* entries
    /// from caller-supplied ones. That check is a backstop against a caller mistake, not the §14.2
    /// control, and weakening it for arbitrary callers would be the wrong fix.
    pub fn to_env_vars(&self) -> Vec<(String, Zeroizing<String>)> {
        self.values
            .iter()
            .filter_map(|(n, v)| v.expose_str().map(|s| (n.clone(), Zeroizing::new(s.to_string()))))
            .collect()
    }

    /// A [`Masker`] primed with every delivered value, for the log shipper and the summary
    /// constructor (D§7.4: "Every value registers with the log shipper (§7.1) and the summary
    /// constructor (§6.6)").
    ///
    /// Read [`crate::mask`] before assuming this protects anything: it is a backstop for an
    /// accidental `echo`, not a control.
    pub fn masker(&self) -> Masker {
        let mut m = Masker::new();
        for (_, v) in &self.values {
            m.register(v.expose());
        }
        m
    }
}

/// Store tenant secrets encrypted; hand one job's declared secrets to one node, once.
///
/// Two capability families live here, not one, and they live in the *same* type on purpose. A
/// package-proxy capability ([`crate::package`]) authorises a different principal over a different
/// set for a different lifetime, so it gets its own request, grant and registry — but it discloses
/// the same tenant plaintext, so it must be behind the same gate, the same tenant revocation and the
/// same crypto-shred. Putting the proxy registry in a sibling type would mean
/// [`SecretBroker::shred_tenant`] silently missed half the outstanding capabilities, and that is
/// exactly the kind of gap D§7.4's break-glass paths cannot afford.
#[derive(Debug)]
pub struct SecretBroker {
    vault: Vault,
    store: Arc<dyn SealedStore>,
    caps: Mutex<HashMap<CapId, crate::capability::CapRecord>>,
    /// Outstanding package-proxy capabilities. Separate map, same lock discipline, same lifecycle.
    proxy_caps: Mutex<HashMap<CapId, ProxyCapRecord>>,
    clock: Arc<dyn Clock>,
    ttl_secs: u64,
}

impl SecretBroker {
    pub fn new(keys: Arc<dyn KeyManager>, store: Arc<dyn SealedStore>) -> Self {
        SecretBroker {
            vault: Vault::new(keys),
            store,
            caps: Mutex::new(HashMap::new()),
            proxy_caps: Mutex::new(HashMap::new()),
            clock: Arc::new(SystemClock),
            ttl_secs: DEFAULT_TTL_SECS,
        }
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Override the capability lifetime. Shorter is safer; there is no upper bound enforced here
    /// because an operator with a slow fleet has a legitimate reason to raise it, and a bad value is
    /// visible in configuration rather than hidden in a refusal.
    pub fn with_ttl_secs(mut self, ttl_secs: u64) -> Self {
        self.ttl_secs = ttl_secs;
        self
    }

    /// Create the tenant's KEK. Explicit rather than lazy-on-first-write, so that a `put` against a
    /// crypto-shredded tenant fails loudly instead of quietly minting fresh key material and
    /// appearing to work while every pre-shred record stays unreadable.
    pub fn provision_tenant(&self, tenant: &str) -> Result<(), SecretError> {
        self.vault.keys().provision_tenant(tenant).map(|_| ())
    }

    // ── Storage ──────────────────────────────────────────────────────────────────────────────────

    /// Seal a value and store the ciphertext. The plaintext is not retained anywhere after this
    /// returns.
    pub fn put_secret(&self, tenant: &str, name: &str, value: &[u8]) -> Result<(), SecretError> {
        validate_name(name)?;
        let sealed = self.vault.seal(tenant, name, value)?;
        self.store.put(sealed)
    }

    pub fn delete_secret(&self, tenant: &str, name: &str) -> Result<bool, SecretError> {
        self.store.delete(tenant, name)
    }

    /// The names a tenant has stored. Names only — this is what an admin UI lists.
    pub fn list_names(&self, tenant: &str) -> Result<Vec<String>, SecretError> {
        Ok(self.store.list(tenant)?.into_iter().map(|s| s.name).collect())
    }

    // ── The gate ─────────────────────────────────────────────────────────────────────────────────

    /// Mint a short-TTL, single-use capability for one job on one node.
    ///
    /// **The outsider refusal comes first, deliberately.** Checking it before name validation and
    /// before any store lookup means an outsider-authored job cannot use the error it gets back as
    /// an oracle for which secrets a tenant has: every request from an outsider fails identically,
    /// whether it names a real secret, a typo, or something it guessed.
    ///
    /// Names are then validated and required to exist. Failing here rather than at redemption puts
    /// the error at placement time, where it is a legible configuration problem, instead of inside a
    /// sandbox spawn where it looks like an infrastructure flake.
    pub fn mint(&self, req: &CapabilityRequest) -> Result<(CapabilityToken, CapabilityGrant), SecretError> {
        // D§7.4: "the broker refuses to mint a capability for it." Not the pipeline's decision, not
        // the isolation tier's — the actor's class, and nothing else.
        if !req.author_class.may_receive_secrets() {
            return Err(SecretError::OutsiderRefused);
        }

        // Pre-flight the tenant's key material. A crypto-shredded tenant still has ciphertext rows
        // (shredding deliberately leaves them — see `shred_tenant`), so without this the broker
        // would happily mint a capability that can only ever fail inside a sandbox spawn, where the
        // failure reads as an infrastructure flake instead of "this tenant has no keys."
        self.vault.keys().current_version(&req.tenant)?;

        let mut names = BTreeSet::new();
        for name in &req.declared {
            validate_name(name)?;
            if self.store.get(&req.tenant, name)?.is_none() {
                return Err(SecretError::UnknownSecret { tenant: req.tenant.clone(), name: name.clone() });
            }
            names.insert(name.clone());
        }

        let now = self.clock.now_secs();
        let (token, id, record) = mint_record(
            req.tenant.clone(),
            req.job_id.clone(),
            req.node_id.clone(),
            names,
            req.author_class,
            now.saturating_add(self.ttl_secs),
        );
        let issued = record.grant.clone();

        let mut caps = self.caps.lock().expect("capability registry poisoned");
        // Opportunistic sweep, on expiry only. A *consumed* record is deliberately kept until it
        // expires: dropping it early would turn a replay into a generic "unknown capability"
        // instead of [`SecretError::CapabilityConsumed`], and that distinction is the alarm that
        // says someone else redeemed first.
        caps.retain(|_, r| r.grant.expires_at > now);
        caps.insert(id, record);
        Ok((token, issued))
    }

    /// Redeem a capability: authenticate it, burn it, and return the requested values.
    ///
    /// Check order is chosen for what each failure teaches an attacker:
    ///
    /// 1. **Parse and authenticate** (constant-time). Everything downstream is unreachable without a
    ///    valid token, so nothing below is an oracle for someone who does not hold one.
    /// 2. **Revoked / consumed / expired.** The break-glass and TTL paths from D§7.4.
    /// 3. **Node binding.** A capability redeemed from the wrong node fails *without* burning it —
    ///    otherwise a misrouted request would kill a healthy job, and an attacker holding the token
    ///    could burn it anyway by presenting the right node id, so the strictness would buy nothing.
    /// 4. **Burn.** Marked consumed here, before the name check, so a token cannot be used to probe
    ///    the declared set one name at a time.
    /// 5. **Author class, then names ⊆ declared.** The class re-check is defence in depth (an
    ///    outsider was already refused at mint); the subset check is what stops a compromised node
    ///    from widening a job's reach mid-flight.
    pub fn redeem(
        &self,
        token: &CapabilityToken,
        node_id: &str,
        requested: &[String],
    ) -> Result<DeliveredSecrets, SecretError> {
        let (id, digest) = parse_token(token)?;
        let now = self.clock.now_secs();

        // Everything that mutates the registry happens under this lock; decryption happens after it
        // is released, so a slow KMS call cannot stall every other job's redemption.
        let grant = {
            let mut caps = self.caps.lock().expect("capability registry poisoned");
            let record = caps.get_mut(&id).ok_or(SecretError::BadCapability)?;
            if !record.authenticates(&digest) {
                return Err(SecretError::BadCapability);
            }
            if record.revoked {
                return Err(SecretError::CapabilityRevoked);
            }
            if record.consumed {
                // Not merely a refusal — an alarm. The legitimate holder seeing this means someone
                // else redeemed first (see the `capability` module doc).
                return Err(SecretError::CapabilityConsumed);
            }
            if now >= record.grant.expires_at {
                return Err(SecretError::CapabilityExpired);
            }
            if record.grant.node_id != node_id {
                return Err(SecretError::WrongNode);
            }
            record.consumed = true;
            record.grant.clone()
        };

        if !grant.author_class.may_receive_secrets() {
            return Err(SecretError::OutsiderRefused);
        }

        // An empty request means "everything this job declared" — the ordinary case, since the node
        // asks for exactly what the step said it needs.
        let wanted: Vec<String> = if requested.is_empty() {
            grant.names.iter().cloned().collect()
        } else {
            for name in requested {
                if !grant.names.contains(name) {
                    return Err(SecretError::Undeclared(name.clone()));
                }
            }
            requested.to_vec()
        };

        let mut values = Vec::with_capacity(wanted.len());
        for name in wanted {
            let sealed = self
                .store
                .get(&grant.tenant, &name)?
                .ok_or_else(|| SecretError::UnknownSecret { tenant: grant.tenant.clone(), name: name.clone() })?;
            let plaintext = self.vault.open(&grant.tenant, &name, &sealed)?;
            values.push((name, plaintext));
        }

        tracing::debug!(
            cap_id = %grant.cap_id,
            job_id = %grant.job_id,
            node_id = %grant.node_id,
            count = values.len(),
            // Names, never values. This line is the audit trail for "which job got what, when".
            names = ?values.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            "delivered tenant secrets"
        );

        Ok(DeliveredSecrets { tenant: grant.tenant, job_id: grant.job_id, values })
    }

    // ── The package proxy's gate ─────────────────────────────────────────────────────────────────

    /// Mint a capability that lets the package proxy spend one job's upstream registry credentials.
    ///
    /// The argument for why the proxy gets a *job*-scoped capability rather than a standing
    /// per-tenant one is in [`crate::package`]; this method is the gate that makes it true. The
    /// order of checks is [`SecretBroker::mint`]'s, and for the same reasons:
    ///
    /// 1. **Outsider first**, before a name is validated or the store is touched, so an
    ///    outsider-authored job cannot use the error as an oracle for which credentials a tenant has.
    ///    D§7.4's gate is unqualified, and it applies here even though the job never receives the
    ///    value — see [`crate::package`] for why *use* is authority.
    /// 2. **Tenant key material**, so a crypto-shredded tenant fails at placement rather than inside
    ///    a package fetch, where it would read as a registry outage.
    /// 3. **Names validated and required to exist**, so a misconfigured upstream is a legible startup
    ///    error rather than a mid-build 502.
    /// 4. **Expiry sanity.** Control computing an expiry in the past is a bug; minting anyway moves
    ///    the failure to the request path.
    pub fn mint_proxy_capability(
        &self,
        req: &ProxyCapabilityRequest,
    ) -> Result<(CapabilityToken, ProxyCredentialGrant), SecretError> {
        if !req.author_class.may_receive_secrets() {
            return Err(SecretError::OutsiderRefused);
        }
        self.vault.keys().current_version(&req.tenant)?;

        let mut names = BTreeSet::new();
        for name in &req.declared {
            validate_name(name)?;
            if self.store.get(&req.tenant, name)?.is_none() {
                return Err(SecretError::UnknownSecret { tenant: req.tenant.clone(), name: name.clone() });
            }
            names.insert(name.clone());
        }

        let now = self.clock.now_secs();
        if req.expires_at <= now {
            return Err(SecretError::CapabilityExpired);
        }
        let (token, id, record) = mint_proxy_record(
            req.tenant.clone(),
            req.job_id.clone(),
            req.proxy_id.clone(),
            names,
            req.author_class,
            req.expires_at,
        );
        let issued = record.grant.clone();

        let mut caps = self.proxy_caps.lock().expect("proxy capability registry poisoned");
        // Same opportunistic sweep, and the same reason a *consumed* record is kept until it expires:
        // dropping it early turns a replay into a generic "unknown capability" instead of
        // [`SecretError::CapabilityConsumed`], which is the alarm that says someone redeemed first.
        caps.retain(|_, r| r.grant.expires_at > now);
        caps.insert(id, record);
        Ok((token, issued))
    }

    /// Redeem a package-proxy capability: authenticate it, burn it, and return the whole covered set.
    ///
    /// `proxy_id` must come from a verified signature — [`crate::package::ProxyCredentialService`] is
    /// the only thing that should call this, for the same reason
    /// [`crate::service::SecretService`] is the only thing that should call
    /// [`SecretBroker::redeem`]: reached directly, it compares a string the caller supplied against a
    /// string the caller could have supplied differently.
    ///
    /// Check order matches [`SecretBroker::redeem`] exactly. The one difference worth naming is that
    /// there is **no per-name request**: the proxy cannot know which upstream a job will reach for
    /// before it reaches for it, so it takes the covered set or nothing. That removes the
    /// probe-the-declared-set attack by removing the thing it probes rather than by burning on a
    /// wrong guess.
    pub fn redeem_proxy_capability(
        &self,
        token: &CapabilityToken,
        proxy_id: &str,
    ) -> Result<DeliveredSecrets, SecretError> {
        let (id, digest) = parse_token(token)?;
        let now = self.clock.now_secs();

        let grant = {
            let mut caps = self.proxy_caps.lock().expect("proxy capability registry poisoned");
            let record = caps.get_mut(&id).ok_or(SecretError::BadCapability)?;
            if !record.authenticates(&digest) {
                return Err(SecretError::BadCapability);
            }
            if record.revoked {
                return Err(SecretError::CapabilityRevoked);
            }
            if record.consumed {
                return Err(SecretError::CapabilityConsumed);
            }
            if now >= record.grant.expires_at {
                return Err(SecretError::CapabilityExpired);
            }
            // Checked *without* burning, matching the node path: a misrouted request must not kill a
            // healthy job, and an attacker holding the token could burn it anyway by presenting the
            // right id, so the strictness would buy nothing.
            if record.grant.proxy_id != proxy_id {
                return Err(SecretError::WrongProxy);
            }
            record.consumed = true;
            record.grant.clone()
        };

        if !grant.author_class.may_receive_secrets() {
            return Err(SecretError::OutsiderRefused);
        }

        // Note the tenant: it comes off the *grant*, never off the request. A cross-tenant read is
        // not refused here, it is unreachable — there is no expression in this loop that could name
        // another tenant's row, and the AAD would refuse it if there were.
        let mut values = Vec::with_capacity(grant.names.len());
        for name in &grant.names {
            let sealed = self.store.get(&grant.tenant, name)?.ok_or_else(|| SecretError::UnknownSecret {
                tenant: grant.tenant.clone(),
                name: name.clone(),
            })?;
            let plaintext = self.vault.open(&grant.tenant, name, &sealed)?;
            values.push((name.clone(), plaintext));
        }

        tracing::debug!(
            cap_id = %grant.cap_id,
            tenant = %grant.tenant,
            job_id = %grant.job_id,
            proxy_id = %grant.proxy_id,
            count = values.len(),
            // Names, never values. This line is the audit trail for "which job's packages, when".
            names = ?values.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            "delivered upstream registry credentials to the package proxy"
        );

        Ok(DeliveredSecrets { tenant: grant.tenant, job_id: grant.job_id, values })
    }

    /// Revoke one outstanding package-proxy capability. Returns whether it existed.
    pub fn revoke_proxy_capability(&self, cap_id: CapId) -> bool {
        let mut caps = self.proxy_caps.lock().expect("proxy capability registry poisoned");
        match caps.get_mut(&cap_id) {
            Some(record) => {
                record.revoked = true;
                true
            }
            None => false,
        }
    }

    /// Revoke every outstanding package-proxy capability for one job.
    ///
    /// The counterpart to the proxy dropping a job's grant when the job ends (§14.1's "nothing
    /// survives into the next job", applied to a credential): even if the proxy process never hears
    /// that the job finished, an unredeemed capability for it is dead.
    pub fn revoke_job_proxy_capabilities(&self, job_id: &str) -> usize {
        let mut caps = self.proxy_caps.lock().expect("proxy capability registry poisoned");
        let mut n = 0;
        for record in caps.values_mut().filter(|r| r.grant.job_id == job_id && !r.revoked) {
            record.revoked = true;
            n += 1;
        }
        n
    }

    // ── Break glass ──────────────────────────────────────────────────────────────────────────────

    /// Revoke one outstanding capability (D§7.4 break-glass path one). Returns whether it existed.
    ///
    /// Revoked rather than deleted: a later redemption then reports [`SecretError::CapabilityRevoked`]
    /// instead of a generic "no such capability", so an operator investigating an incident can tell
    /// "we killed this" from "this was never real".
    pub fn revoke(&self, cap_id: CapId) -> bool {
        let mut caps = self.caps.lock().expect("capability registry poisoned");
        match caps.get_mut(&cap_id) {
            Some(record) => {
                record.revoked = true;
                true
            }
            None => false,
        }
    }

    /// Revoke every outstanding capability for a tenant — **both** families.
    ///
    /// Both, because "revoke this tenant" that left the package proxy able to keep spending the
    /// tenant's registry token would be a revocation in name only. The two registries are separate
    /// maps precisely so this method has to name them both, where a reviewer can see it.
    pub fn revoke_tenant(&self, tenant: &str) -> usize {
        let mut n = 0;
        {
            let mut caps = self.caps.lock().expect("capability registry poisoned");
            for record in caps.values_mut().filter(|r| r.grant.tenant == tenant && !r.revoked) {
                record.revoked = true;
                n += 1;
            }
        }
        let mut proxy_caps = self.proxy_caps.lock().expect("proxy capability registry poisoned");
        for record in proxy_caps.values_mut().filter(|r| r.grant.tenant == tenant && !r.revoked) {
            record.revoked = true;
            n += 1;
        }
        n
    }

    /// **Crypto-shred a tenant** (D§7.4 break-glass path two): destroy its KEK, after which every
    /// secret it ever stored is unrecoverable — including any ciphertext already copied to a backup,
    /// a replica, or a snapshot nobody remembers taking. That reach is the reason to prefer this
    /// over `DELETE FROM secrets`.
    ///
    /// Outstanding capabilities are revoked first, so the window between "key gone" and "job fails"
    /// produces a clear refusal rather than a decryption error.
    ///
    /// Ciphertext rows are deliberately **left in place**: they are now inert, and an operator may
    /// want them for an audit. [`SealedStore::delete_tenant`] is the separate hygiene step.
    pub fn shred_tenant(&self, tenant: &str) -> Result<(), SecretError> {
        self.revoke_tenant(tenant);
        self.vault.keys().shred(tenant)
    }

    // ── Rotation ─────────────────────────────────────────────────────────────────────────────────

    /// Rotate a tenant's KEK and re-wrap every record's DEK under the new version.
    ///
    /// Cheap by construction (D§7.4): only the 32-byte DEKs move. The value ciphertexts are copied
    /// forward byte-identical, so rotating a tenant with ten thousand secrets is ten thousand tiny
    /// AEAD operations, not a bulk re-encrypt — and a rotation interrupted halfway leaves a mix of
    /// versions that both still open, because old KEK versions keep unwrapping.
    ///
    /// Returns how many records were re-wrapped.
    pub fn rotate_tenant(&self, tenant: &str) -> Result<usize, SecretError> {
        self.vault.keys().rotate(tenant)?;
        let mut rewrapped = 0;
        for sealed in self.store.list(tenant)? {
            if let Some(updated) = self.vault.rewrap(&sealed)? {
                self.store.put(updated)?;
                rewrapped += 1;
            }
        }
        Ok(rewrapped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DevKeyManager;
    use crate::store::MemorySealedStore;

    /// A clock the tests drive by hand: TTL behaviour is security behaviour, and a test that proves
    /// it by sleeping proves it slowly and flakily.
    #[derive(Debug)]
    struct TestClock(Mutex<u64>);

    impl TestClock {
        fn new(t: u64) -> Arc<Self> {
            Arc::new(TestClock(Mutex::new(t)))
        }
        fn advance(&self, secs: u64) {
            *self.0.lock().unwrap() += secs;
        }
    }

    impl Clock for TestClock {
        fn now_secs(&self) -> u64 {
            *self.0.lock().unwrap()
        }
    }

    struct Fixture {
        broker: SecretBroker,
        keys: Arc<DevKeyManager>,
        store: Arc<MemorySealedStore>,
        clock: Arc<TestClock>,
    }

    fn fixture() -> Fixture {
        let keys = Arc::new(DevKeyManager::new());
        let store = Arc::new(MemorySealedStore::new());
        let clock = TestClock::new(1_000);
        let broker = SecretBroker::new(keys.clone(), store.clone()).with_clock(clock.clone());
        broker.provision_tenant("acme").unwrap();
        broker.put_secret("acme", "NPM_TOKEN", b"npm_s3cr3tvalue").unwrap();
        broker.put_secret("acme", "DEPLOY_KEY", b"deploy-k3y-value").unwrap();
        Fixture { broker, keys, store, clock }
    }

    fn request(class: AuthorClass, declared: &[&str]) -> CapabilityRequest {
        CapabilityRequest {
            tenant: "acme".into(),
            job_id: "job-1".into(),
            node_id: "node-a".into(),
            declared: declared.iter().map(|s| s.to_string()).collect(),
            author_class: class,
        }
    }

    #[test]
    fn a_member_job_gets_exactly_its_declared_secrets() {
        let f = fixture();
        let (token, grant) = f.broker.mint(&request(AuthorClass::Member, &["NPM_TOKEN"])).unwrap();
        assert_eq!(grant.names.len(), 1);
        let delivered = f.broker.redeem(&token, "node-a", &[]).unwrap();
        assert_eq!(delivered.names(), ["NPM_TOKEN"]);
        assert_eq!(delivered.get("NPM_TOKEN").unwrap().expose(), b"npm_s3cr3tvalue");
        // DEPLOY_KEY exists for this tenant and was not declared, so it is not in the delivery.
        assert!(delivered.get("DEPLOY_KEY").is_none());
    }

    #[test]
    fn an_outsider_is_refused_even_when_the_pipeline_declares_the_names() {
        // The pwn-request defence (D§7.4). The declaration is identical to the member case above;
        // only the actor differs, and only the actor matters.
        let f = fixture();
        let err = f.broker.mint(&request(AuthorClass::Outsider, &["NPM_TOKEN"])).unwrap_err();
        assert_eq!(err, SecretError::OutsiderRefused);
    }

    #[test]
    fn an_outsiders_refusal_is_not_an_existence_oracle() {
        // Declaring a secret that exists, one that does not, and a malformed name must all fail the
        // same way for an outsider — otherwise the error message enumerates the tenant's secrets.
        let f = fixture();
        for declared in [vec!["NPM_TOKEN"], vec!["NO_SUCH_SECRET"], vec!["not a name"]] {
            assert_eq!(
                f.broker.mint(&request(AuthorClass::Outsider, &declared)).unwrap_err(),
                SecretError::OutsiderRefused
            );
        }
        // The same requests from a member are distinguishable, which is the point: members may know.
        assert!(matches!(
            f.broker.mint(&request(AuthorClass::Member, &["NO_SUCH_SECRET"])).unwrap_err(),
            SecretError::UnknownSecret { .. }
        ));
    }

    #[test]
    fn a_capability_is_single_use() {
        let f = fixture();
        let (token, _) = f.broker.mint(&request(AuthorClass::Member, &["NPM_TOKEN"])).unwrap();
        assert!(f.broker.redeem(&token, "node-a", &[]).is_ok());
        assert_eq!(f.broker.redeem(&token, "node-a", &[]).unwrap_err(), SecretError::CapabilityConsumed);
    }

    #[test]
    fn a_capability_expires() {
        let f = fixture();
        let (token, grant) = f.broker.mint(&request(AuthorClass::Member, &["NPM_TOKEN"])).unwrap();
        assert_eq!(grant.expires_at, 1_000 + DEFAULT_TTL_SECS);
        f.clock.advance(DEFAULT_TTL_SECS - 1);
        // Still inside the window: a scheduling hiccup must not cost the job its secrets.
        let (token2, _) = f.broker.mint(&request(AuthorClass::Member, &["NPM_TOKEN"])).unwrap();
        assert!(f.broker.redeem(&token2, "node-a", &[]).is_ok());
        f.clock.advance(2);
        assert_eq!(f.broker.redeem(&token, "node-a", &[]).unwrap_err(), SecretError::CapabilityExpired);
    }

    #[test]
    fn a_capability_is_bound_to_one_node() {
        let f = fixture();
        let (token, _) = f.broker.mint(&request(AuthorClass::Member, &["NPM_TOKEN"])).unwrap();
        assert_eq!(f.broker.redeem(&token, "node-b", &[]).unwrap_err(), SecretError::WrongNode);
        // And the legitimate node is not collateral damage: a stolen-token attempt from elsewhere
        // must not burn a healthy job's capability.
        assert!(f.broker.redeem(&token, "node-a", &[]).is_ok());
    }

    #[test]
    fn a_name_outside_the_declared_set_is_refused() {
        let f = fixture();
        let (token, _) = f.broker.mint(&request(AuthorClass::Member, &["NPM_TOKEN"])).unwrap();
        let err = f.broker.redeem(&token, "node-a", &["DEPLOY_KEY".into()]).unwrap_err();
        assert_eq!(err, SecretError::Undeclared("DEPLOY_KEY".into()));
    }

    #[test]
    fn probing_the_declared_set_burns_the_capability() {
        // A compromised node cannot walk the namespace one guess at a time: the first attempt, right
        // or wrong, is the only attempt.
        let f = fixture();
        let (token, _) = f.broker.mint(&request(AuthorClass::Member, &["NPM_TOKEN"])).unwrap();
        assert!(f.broker.redeem(&token, "node-a", &["DEPLOY_KEY".into()]).is_err());
        assert_eq!(f.broker.redeem(&token, "node-a", &[]).unwrap_err(), SecretError::CapabilityConsumed);
    }

    #[test]
    fn a_forged_or_unknown_token_is_refused() {
        let f = fixture();
        let (token, _) = f.broker.mint(&request(AuthorClass::Member, &["NPM_TOKEN"])).unwrap();
        // Right id, wrong authenticator.
        let (id, sep) = token.expose().split_at(token.expose().len() - 64);
        let forged = CapabilityToken::from_wire(format!("{id}{}", "0".repeat(sep.len())));
        assert_eq!(f.broker.redeem(&forged, "node-a", &[]).unwrap_err(), SecretError::BadCapability);
        assert_eq!(
            f.broker.redeem(&CapabilityToken::from_wire("garbage"), "node-a", &[]).unwrap_err(),
            SecretError::BadCapability
        );
        // The real token still works: the forgery did not burn it.
        assert!(f.broker.redeem(&token, "node-a", &[]).is_ok());
    }

    #[test]
    fn an_outstanding_capability_can_be_revoked() {
        let f = fixture();
        let (token, grant) = f.broker.mint(&request(AuthorClass::Member, &["NPM_TOKEN"])).unwrap();
        assert!(f.broker.revoke(grant.cap_id));
        assert_eq!(f.broker.redeem(&token, "node-a", &[]).unwrap_err(), SecretError::CapabilityRevoked);
    }

    #[test]
    fn crypto_shredding_a_tenant_makes_every_secret_unrecoverable() {
        let f = fixture();
        let (token, _) = f.broker.mint(&request(AuthorClass::Member, &["NPM_TOKEN"])).unwrap();

        f.broker.shred_tenant("acme").unwrap();

        // The ciphertext is still sitting in the store — and is now inert.
        assert_eq!(f.store.list("acme").unwrap().len(), 2);
        assert_eq!(f.broker.redeem(&token, "node-a", &[]).unwrap_err(), SecretError::CapabilityRevoked);
        assert_eq!(
            f.broker.mint(&request(AuthorClass::Member, &["NPM_TOKEN"])).unwrap_err(),
            SecretError::NoTenantKey("acme".into())
        );

        // Even re-enrolling the tenant does not bring the old values back: the key that could read
        // them no longer exists anywhere.
        f.broker.provision_tenant("acme").unwrap();
        let (token2, _) = f.broker.mint(&request(AuthorClass::Member, &["NPM_TOKEN"])).unwrap();
        assert!(matches!(
            f.broker.redeem(&token2, "node-a", &[]).unwrap_err(),
            SecretError::NoKekVersion { .. }
        ));
    }

    #[test]
    fn shredding_one_tenant_leaves_every_other_tenant_intact() {
        // Blast-radius isolation: the whole reason for one KEK per tenant.
        let f = fixture();
        f.broker.provision_tenant("globex").unwrap();
        f.broker.put_secret("globex", "NPM_TOKEN", b"globex-value").unwrap();

        f.broker.shred_tenant("acme").unwrap();

        let mut req = request(AuthorClass::Member, &["NPM_TOKEN"]);
        req.tenant = "globex".into();
        let (token, _) = f.broker.mint(&req).unwrap();
        assert_eq!(f.broker.redeem(&token, "node-a", &[]).unwrap().get("NPM_TOKEN").unwrap().expose(), b"globex-value");
    }

    #[test]
    fn rotation_keeps_old_ciphertext_readable_and_moves_new_writes_forward() {
        let f = fixture();
        let before = f.store.get("acme", "NPM_TOKEN").unwrap().unwrap();

        // A bare KEK rotation with no sweep: existing records are a version behind and must still
        // open, because old versions keep unwrapping (D§7.4).
        let v2 = f.keys.rotate("acme").unwrap();
        let (token, _) = f.broker.mint(&request(AuthorClass::Member, &["NPM_TOKEN"])).unwrap();
        assert_eq!(f.broker.redeem(&token, "node-a", &[]).unwrap().get("NPM_TOKEN").unwrap().expose(), b"npm_s3cr3tvalue");

        // New writes use the new version immediately.
        f.broker.put_secret("acme", "NEW_TOKEN", b"new-token-value").unwrap();
        assert_eq!(f.store.get("acme", "NEW_TOKEN").unwrap().unwrap().kek_version, v2);

        // The sweep re-wraps what is behind, and only what is behind.
        let rewrapped = f.broker.rotate_tenant("acme").unwrap();
        assert_eq!(rewrapped, 3, "every record was a version behind after the second rotation");
        let after = f.store.get("acme", "NPM_TOKEN").unwrap().unwrap();
        assert!(after.kek_version > before.kek_version);
        assert_eq!(after.ciphertext, before.ciphertext, "rotation must never re-encrypt the values");

        let (token, _) = f.broker.mint(&request(AuthorClass::Member, &["NPM_TOKEN"])).unwrap();
        assert_eq!(f.broker.redeem(&token, "node-a", &[]).unwrap().get("NPM_TOKEN").unwrap().expose(), b"npm_s3cr3tvalue");
    }

    #[test]
    fn delivered_secrets_produce_env_vars_and_a_primed_masker() {
        let f = fixture();
        let (token, _) = f.broker.mint(&request(AuthorClass::Member, &["NPM_TOKEN", "DEPLOY_KEY"])).unwrap();
        let delivered = f.broker.redeem(&token, "node-a", &[]).unwrap();

        let env = delivered.to_env_vars();
        assert_eq!(env.len(), 2);
        let npm = env.iter().find(|(n, _)| n == "NPM_TOKEN").unwrap();
        assert_eq!(npm.1.as_str(), "npm_s3cr3tvalue");

        let masker = delivered.masker();
        assert_eq!(masker.mask("leaked npm_s3cr3tvalue oops"), "leaked *** oops");
    }

    #[test]
    fn a_capability_for_one_job_cannot_reach_another_tenants_secrets() {
        // The capability carries the tenant; a matching secret *name* in another tenant is a
        // different row under a different KEK and is simply not reachable from here.
        let f = fixture();
        f.broker.provision_tenant("globex").unwrap();
        f.broker.put_secret("globex", "NPM_TOKEN", b"globex-value").unwrap();
        let (token, _) = f.broker.mint(&request(AuthorClass::Member, &["NPM_TOKEN"])).unwrap();
        let delivered = f.broker.redeem(&token, "node-a", &[]).unwrap();
        assert_eq!(delivered.tenant, "acme");
        assert_eq!(delivered.get("NPM_TOKEN").unwrap().expose(), b"npm_s3cr3tvalue");
    }

    #[test]
    fn a_reserved_or_malformed_name_cannot_be_stored_or_declared() {
        let f = fixture();
        assert!(matches!(f.broker.put_secret("acme", "PATH", b"/evil"), Err(SecretError::ReservedName(_))));
        assert!(matches!(f.broker.put_secret("acme", "lower", b"x"), Err(SecretError::InvalidName(_))));
        assert!(matches!(
            f.broker.mint(&request(AuthorClass::Member, &["PATH"])),
            Err(SecretError::ReservedName(_))
        ));
    }

    #[test]
    fn the_assignment_helper_takes_author_class_from_the_control_plane() {
        use hull_ci_proto::IsolationTier;
        let assignment = Assignment {
            job_id: "job-9".into(),
            step_id: "s1".into(),
            step_name: "test".into(),
            tenant: "acme".into(),
            repo: "acme/widget".into(),
            tree_id: "f7a2".into(),
            argv: vec!["true".into()],
            secrets: vec!["NPM_TOKEN".into()],
            image: "img".into(),
            tier: IsolationTier::MicroVm,
            author_class: AuthorClass::Outsider,
            timeout_secs: 60,
            lease_secs: 30,
        };
        let f = fixture();
        let req = CapabilityRequest::for_assignment(&assignment, "node-a", vec!["NPM_TOKEN".into()]);
        assert_eq!(req.author_class, AuthorClass::Outsider);
        // A microVM is a strong box, not a statement about authority (D§1): the tier is irrelevant
        // to this refusal.
        assert_eq!(f.broker.mint(&req).unwrap_err(), SecretError::OutsiderRefused);
    }
}
