//! The per-job grant: "resolve packages for this job, at this rate limit", and nothing else.
//!
//! D§7.4: "the job talks to it over a per-job URL with a per-job bearer that grants nothing but
//! 'resolve packages for this job, at this rate limit.'" This module is that bearer and its registry.
//!
//! The construction is deliberately the same as the secret broker's capability
//! ([`hull_ci_secrets::CapabilityToken`]): a public id plus a random authenticator, only a digest
//! retained, compared in constant time. Two credentials in one system that look alike and behave
//! differently is how a reviewer's intuition gets trained wrong, so where the properties are the same
//! the shape is the same.
//!
//! # Where it differs from a capability, and why
//!
//! | | secret capability | package grant |
//! |---|---|---|
//! | uses | **single**-use | many (a job resolves hundreds of packages) |
//! | TTL | ~60 s | the job's wall clock |
//! | holder | the node | **the job itself** |
//!
//! That last row is the one that matters. A grant is handed to untrusted code on purpose, so it is
//! designed on the assumption that the job will read it, log it, and try to use it for something
//! else. It therefore authorises no upstream outside its own list, no method but `GET`/`HEAD`
//! ([`crate::allowlist::ALLOWED_METHODS`]), and nothing at all after its job ends — and it is never
//! the thing that authenticates *to an upstream*. The upstream credential is a separate value the
//! job never receives (D§7.4: "the pull/proxy credential is just a tenant secret, so the job gets its
//! dependencies without ever seeing it").
//!
//! # Why the token travels in the URL path
//!
//! Because `npm`, `pip` and `cargo` take a registry *URL* and no separate credential hook that all
//! three share, so a token that cannot live in a URL cannot be used at all. That is a real cost — a
//! URL reaches logs, `package-lock.json`, and error messages more readily than a header does — and
//! it is affordable only because of the row above: the grant is job-scoped, read-only, expires with
//! the job, and unlocks nothing but packages the job was already going to fetch. A
//! `Proxy-Authorization: Bearer` header is accepted too, for clients that can send one.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use rand::rngs::OsRng;
use rand::RngCore;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ratelimit::{RateLimit, TokenBucket};

/// 128 bits of public id: unguessable, so a grant cannot even be enumerated.
const ID_LEN: usize = 16;
/// 256 bits of authenticator.
const SECRET_LEN: usize = 32;
/// Recognisable on sight in a log, and greppable in a leaked `package-lock.json`.
const TOKEN_PREFIX: &str = "hpkg_";

/// Public half of a grant token: safe to log, safe in a trace span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantId([u8; ID_LEN]);

impl std::fmt::Display for GrantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

/// The bearer the job holds: `hpkg_<id>.<secret>`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct GrantToken(String);

impl GrantToken {
    fn mint() -> (Self, GrantId, [u8; 32]) {
        let mut id = [0u8; ID_LEN];
        OsRng.fill_bytes(&mut id);
        let mut secret = [0u8; SECRET_LEN];
        OsRng.fill_bytes(&mut secret);
        let id = GrantId(id);
        let token = GrantToken(format!("{TOKEN_PREFIX}{id}.{}", hex::encode(secret)));
        let digest = *blake3::hash(&secret).as_bytes();
        secret.zeroize();
        (token, id, digest)
    }

    pub fn from_wire(s: impl Into<String>) -> Self {
        GrantToken(s.into())
    }

    /// Named `expose` so its use sites are greppable, matching [`hull_ci_secrets::SecretBytes`].
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Split into `(id, digest)`. Every malformed shape returns the same error, so a forger learns
    /// nothing about how far a guess got.
    fn parse(&self) -> Option<(GrantId, [u8; 32])> {
        let body = self.0.strip_prefix(TOKEN_PREFIX)?;
        let (id_hex, secret_hex) = body.split_once('.')?;
        let id: [u8; ID_LEN] = hex::decode(id_hex).ok()?.try_into().ok()?;
        let mut secret = hex::decode(secret_hex).ok()?;
        if secret.len() != SECRET_LEN {
            secret.zeroize();
            return None;
        }
        let digest = *blake3::hash(&secret).as_bytes();
        secret.zeroize();
        Some((GrantId(id), digest))
    }
}

impl std::fmt::Debug for GrantToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Weak as credentials go, but still a credential. It gets the same treatment.
        f.write_str("GrantToken(<redacted>)")
    }
}

/// What a grant authorises. Safe to log: it names a job, a tenant and some upstream *labels*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub grant_id: GrantId,
    pub tenant: String,
    pub job_id: String,
    /// Upstream labels this job may reach — a subset of the deployment allowlist, fixed at mint.
    /// A job cannot widen it, because the widening would have to happen here and nothing the job
    /// sends reaches this struct.
    pub upstreams: BTreeSet<String>,
    pub expires_at: u64,
    pub rate: RateLimit,
}

/// Why a presented grant was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    /// Malformed, unknown, or forged. Deliberately one variant: see [`GrantToken::parse`].
    #[error("package grant is not valid")]
    Invalid,
    #[error("package grant expired")]
    Expired,
    #[error("package grant was revoked")]
    Revoked,
    /// D§7.4's "at this rate limit", enforced.
    #[error("package grant is over its rate limit ({limit} requests/s, burst {burst})")]
    RateLimited { limit: u32, burst: u32 },
}

struct Record {
    grant: Grant,
    digest: [u8; 32],
    revoked: bool,
    bucket: TokenBucket,
}

impl Record {
    /// Constant-time. A byte-at-a-time `==` turns a 2^256 search into 32 sequential 2^8 searches.
    fn authenticates(&self, presented: &[u8; 32]) -> bool {
        self.digest.ct_eq(presented).into()
    }
}

/// Live grants, one per running job.
///
/// In-memory on purpose: a grant is worthless after its job ends, so surviving a proxy restart would
/// be a liability (a persisted bearer for a job nobody is running) rather than a feature. A restart
/// invalidates every grant, which fails closed — jobs get connection refusals, not somebody else's
/// packages.
#[derive(Debug, Default)]
pub struct GrantRegistry {
    records: Mutex<BTreeMap<GrantId, Record>>,
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Record")
            .field("grant", &self.grant)
            // A verifier for a live bearer token answers no debugging question.
            .field("digest", &"<redacted>")
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl GrantRegistry {
    pub fn new() -> Self {
        GrantRegistry::default()
    }

    /// Mint a grant for one job. Returns the token **once**; only its digest is kept.
    ///
    /// `upstreams` is intersected with nothing here — the caller is the control plane, which decides
    /// what this job's tenant may reach. What this type guarantees is that the set cannot grow
    /// afterwards.
    pub fn mint(
        &self,
        tenant: impl Into<String>,
        job_id: impl Into<String>,
        upstreams: BTreeSet<String>,
        expires_at: u64,
        rate: RateLimit,
    ) -> (GrantToken, Grant) {
        let (token, grant_id, digest) = GrantToken::mint();
        let grant = Grant {
            grant_id,
            tenant: tenant.into(),
            job_id: job_id.into(),
            upstreams,
            expires_at,
            rate,
        };
        let record = Record { grant: grant.clone(), digest, revoked: false, bucket: TokenBucket::new(rate) };
        self.records.lock().expect("grant registry").insert(grant_id, record);
        (token, grant)
    }

    /// Authenticate a presented token and charge it one request against its rate limit.
    ///
    /// Authentication and rate-charging are one call rather than two because the alternative — check,
    /// then charge — has a window in which a caller can forget the second half, and the half that
    /// gets forgotten is always the limit.
    pub fn authorise(&self, token: &GrantToken, now: u64) -> Result<Grant, GrantError> {
        let (id, digest) = token.parse().ok_or(GrantError::Invalid)?;
        let mut records = self.records.lock().expect("grant registry");
        let record = records.get_mut(&id).ok_or(GrantError::Invalid)?;
        // Authenticate *before* reporting expiry or revocation: otherwise an attacker with a
        // well-formed guess learns which ids exist by which error comes back.
        if !record.authenticates(&digest) {
            return Err(GrantError::Invalid);
        }
        if record.revoked {
            return Err(GrantError::Revoked);
        }
        if now >= record.grant.expires_at {
            return Err(GrantError::Expired);
        }
        if !record.bucket.take(now) {
            return Err(GrantError::RateLimited {
                limit: record.grant.rate.per_second,
                burst: record.grant.rate.burst,
            });
        }
        Ok(record.grant.clone())
    }

    /// Revoke one grant. The break-glass path; expiry is the primary one.
    pub fn revoke(&self, id: GrantId) -> bool {
        let mut records = self.records.lock().expect("grant registry");
        match records.get_mut(&id) {
            Some(r) if !r.revoked => {
                r.revoked = true;
                true
            }
            _ => false,
        }
    }

    /// Drop every grant for a job. Called when the job ends, so a token that outlives its sandbox is
    /// dead the moment the sandbox is (§14.1's "nothing survives into the next job", applied to a
    /// credential rather than a filesystem).
    pub fn revoke_job(&self, job_id: &str) -> usize {
        let mut records = self.records.lock().expect("grant registry");
        let ids: Vec<GrantId> =
            records.values().filter(|r| r.grant.job_id == job_id).map(|r| r.grant.grant_id).collect();
        for id in &ids {
            records.remove(id);
        }
        ids.len()
    }

    /// Forget expired records. Housekeeping, not a control — [`GrantRegistry::authorise`] already
    /// refuses an expired grant whether or not this ever runs.
    pub fn sweep(&self, now: u64) -> usize {
        let mut records = self.records.lock().expect("grant registry");
        let before = records.len();
        records.retain(|_, r| now < r.grant.expires_at);
        before - records.len()
    }

    pub fn len(&self) -> usize {
        self.records.lock().expect("grant registry").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstreams(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn registry() -> (GrantRegistry, GrantToken, Grant) {
        let reg = GrantRegistry::new();
        let (token, grant) =
            reg.mint("acme", "job-1", upstreams(&["npm"]), 1_000, RateLimit::new(100, 100));
        (reg, token, grant)
    }

    #[test]
    fn a_minted_grant_authorises_its_own_job_and_upstreams() {
        let (reg, token, grant) = registry();
        let got = reg.authorise(&token, 500).unwrap();
        assert_eq!(got.job_id, "job-1");
        assert_eq!(got.tenant, "acme");
        assert!(got.upstreams.contains("npm"));
        assert_eq!(got.grant_id, grant.grant_id);
    }

    #[test]
    fn a_grant_cannot_reach_an_upstream_it_was_not_minted_for() {
        // The per-job scoping D§7.4 asks for: the deployment allowlist is the ceiling, the grant is
        // this job's slice of it, and nothing the job sends can widen the slice.
        let (reg, token, _) = registry();
        let grant = reg.authorise(&token, 500).unwrap();
        assert!(!grant.upstreams.contains("private"), "an upstream outside the grant stays outside");
    }

    #[test]
    fn a_forged_or_unknown_token_fails_the_same_way_as_a_malformed_one() {
        let (reg, token, _) = registry();
        // Right id, wrong authenticator — the interesting forgery, since the id is public.
        let (id, _) = token.parse().unwrap();
        let forged = GrantToken::from_wire(format!("{TOKEN_PREFIX}{id}.{}", hex::encode([0u8; SECRET_LEN])));
        assert_eq!(reg.authorise(&forged, 500).unwrap_err(), GrantError::Invalid);

        for bad in ["", "nope", "hpkg_", "hpkg_zz.zz", "hcap_00.11"] {
            assert_eq!(
                reg.authorise(&GrantToken::from_wire(bad), 500).unwrap_err(),
                GrantError::Invalid,
                "{bad}"
            );
        }
        // A well-formed token for a grant that was never minted is also just `Invalid`: telling a
        // caller "that id does not exist" is an enumeration oracle.
        let unknown = GrantToken::from_wire(format!(
            "{TOKEN_PREFIX}{}.{}",
            hex::encode([9u8; ID_LEN]),
            hex::encode([9u8; SECRET_LEN])
        ));
        assert_eq!(reg.authorise(&unknown, 500).unwrap_err(), GrantError::Invalid);
    }

    #[test]
    fn a_grant_dies_with_its_job() {
        let (reg, token, _) = registry();
        assert!(reg.authorise(&token, 500).is_ok());
        assert_eq!(reg.revoke_job("job-1"), 1);
        assert_eq!(reg.authorise(&token, 500).unwrap_err(), GrantError::Invalid);
        assert!(reg.is_empty());
    }

    #[test]
    fn expiry_and_revocation_are_both_refusals() {
        let (reg, token, grant) = registry();
        assert_eq!(reg.authorise(&token, 1_000).unwrap_err(), GrantError::Expired);
        assert_eq!(reg.authorise(&token, 9_999).unwrap_err(), GrantError::Expired);

        let (reg2, token2, _) = registry();
        assert!(reg2.revoke(grant.grant_id) || reg2.authorise(&token2, 500).is_ok());
        let (reg3, token3, g3) = registry();
        assert!(reg3.revoke(g3.grant_id));
        assert_eq!(reg3.authorise(&token3, 500).unwrap_err(), GrantError::Revoked);
        assert!(!reg3.revoke(g3.grant_id), "revoking twice is not a second event");
    }

    #[test]
    fn the_rate_limit_is_charged_on_every_authorisation() {
        // Two requests of burst, then refusal — and the refusal names the limit so an operator
        // reading a failed job can tell a rate limit from an outage.
        let reg = GrantRegistry::new();
        let (token, _) = reg.mint("acme", "job-1", upstreams(&["npm"]), 1_000, RateLimit::new(1, 2));
        assert!(reg.authorise(&token, 100).is_ok());
        assert!(reg.authorise(&token, 100).is_ok());
        assert_eq!(
            reg.authorise(&token, 100).unwrap_err(),
            GrantError::RateLimited { limit: 1, burst: 2 }
        );
        // A second later, one token has refilled.
        assert!(reg.authorise(&token, 101).is_ok());
        assert!(reg.authorise(&token, 101).is_err());
    }

    #[test]
    fn one_jobs_rate_limit_is_not_anothers() {
        let reg = GrantRegistry::new();
        let (a, _) = reg.mint("acme", "job-a", upstreams(&["npm"]), 1_000, RateLimit::new(1, 1));
        let (b, _) = reg.mint("acme", "job-b", upstreams(&["npm"]), 1_000, RateLimit::new(1, 1));
        assert!(reg.authorise(&a, 100).is_ok());
        assert!(reg.authorise(&a, 100).is_err());
        assert!(reg.authorise(&b, 100).is_ok(), "job-b has its own bucket");
    }

    #[test]
    fn tokens_are_unique_and_redacted() {
        let reg = GrantRegistry::new();
        let (t1, _) = reg.mint("acme", "j1", upstreams(&["npm"]), 1, RateLimit::default());
        let (t2, _) = reg.mint("acme", "j2", upstreams(&["npm"]), 1, RateLimit::default());
        assert_ne!(t1.expose(), t2.expose());
        assert_eq!(t1.expose().len(), TOKEN_PREFIX.len() + ID_LEN * 2 + 1 + SECRET_LEN * 2);
        assert_eq!(format!("{t1:?}"), "GrantToken(<redacted>)");
    }

    #[test]
    fn sweeping_is_housekeeping_and_not_the_control() {
        let (reg, token, _) = registry();
        // Expiry is refused whether or not anyone swept.
        assert!(reg.authorise(&token, 2_000).is_err());
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.sweep(2_000), 1);
        assert!(reg.is_empty());
    }
}
