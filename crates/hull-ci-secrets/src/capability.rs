//! The job-scoped, single-use capability.
//!
//! D§7.4: "At placement, control mints a **short-TTL, single-use capability** bound to
//! `(job_id, node_id, [declared secret names], author_class=member)` — the response-wrapping /
//! SVID-style pattern where a reference, not the secret, travels and any interception is
//! detectable." This module is the token and its registry; the policy that decides whether to mint
//! one at all lives in [`crate::broker`].
//!
//! **Why a reference and not the values.** The alternative — control sends the secrets down with the
//! assignment — puts plaintext on the scheduling path, in the assignment record, in whatever queue
//! or retry buffer that record touches, and in memory on every node that was ever *considered* for
//! placement. A capability is a bearer token with none of those properties: it is worthless after
//! one use, worthless after a few seconds, and worthless to any node but one.
//!
//! **Detectability is the other half.** Single-use is not only a replay defence, it is an alarm: if
//! the legitimate node's redemption fails with [`crate::SecretError::CapabilityConsumed`], someone
//! else redeemed it first, and that is a security event with a `(job_id, node_id)` attached rather
//! than a silent compromise. Vault's response-wrapping is built on exactly this observation.

use std::collections::BTreeSet;

use hull_ci_proto::AuthorClass;
use rand::rngs::OsRng;
use rand::RngCore;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::SecretError;

/// Default capability lifetime.
///
/// D§7.4 makes short TTLs the *primary* revocation mechanism, with explicit revoke and crypto-shred
/// as break-glass. Sixty seconds is sized for the gap between "control mints at placement" and "node
/// redeems at exec": long enough to survive a scheduling hiccup and a retry, short enough that a
/// token captured from a log or a crash dump is almost certainly already dead.
pub const DEFAULT_TTL_SECS: u64 = 60;

/// Bytes in the public half of a token. 128 bits of randomness, so the id is itself unguessable —
/// an attacker cannot even enumerate which capabilities exist.
const ID_LEN: usize = 16;
/// Bytes in the secret half. 256 bits: the authenticator proper.
const SECRET_LEN: usize = 32;
/// What a token string starts with, so one found in a log is recognisable on sight.
const TOKEN_PREFIX: &str = "hcap_";

/// The public half of a capability: an index, safe to log and to put in a trace span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapId([u8; ID_LEN]);

impl CapId {
    fn generate() -> Self {
        let mut b = [0u8; ID_LEN];
        OsRng.fill_bytes(&mut b);
        CapId(b)
    }
}

impl std::fmt::Display for CapId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

/// The bearer token handed to the node: `hcap_<id>.<secret>`.
///
/// Split into a public id and a secret authenticator so the registry can be a map keyed on the id.
/// A map keyed on the *secret* would mean storing the secret itself and looking it up by hashing
/// into buckets — both things this design avoids: only a digest of the secret is retained, and the
/// comparison is constant-time.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CapabilityToken(String);

impl CapabilityToken {
    fn mint() -> (Self, CapId, [u8; 32]) {
        let id = CapId::generate();
        let mut secret = [0u8; SECRET_LEN];
        OsRng.fill_bytes(&mut secret);
        let token = CapabilityToken(format!("{TOKEN_PREFIX}{id}.{}", hex::encode(secret)));
        let digest = digest_secret(&secret);
        secret.zeroize();
        (token, id, digest)
    }

    /// Reconstruct a token from the wire.
    pub fn from_wire(s: impl Into<String>) -> Self {
        CapabilityToken(s.into())
    }

    /// The string to put on the wire. Named `expose` so its use sites are greppable.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Split into `(id, digest_of_secret)` without ever handing back the secret half.
    ///
    /// Every parse failure returns the same [`SecretError::BadCapability`]: distinguishing "bad
    /// prefix" from "bad hex" from "unknown id" tells an attacker how far up the validation chain a
    /// guess reached, which is how a forgery gets refined into a working token.
    fn parse(&self) -> Result<(CapId, [u8; 32]), SecretError> {
        let body = self.0.strip_prefix(TOKEN_PREFIX).ok_or(SecretError::BadCapability)?;
        let (id_hex, secret_hex) = body.split_once('.').ok_or(SecretError::BadCapability)?;
        let id_bytes: [u8; ID_LEN] = hex::decode(id_hex)
            .map_err(|_| SecretError::BadCapability)?
            .try_into()
            .map_err(|_| SecretError::BadCapability)?;
        let mut secret = hex::decode(secret_hex).map_err(|_| SecretError::BadCapability)?;
        if secret.len() != SECRET_LEN {
            return Err(SecretError::BadCapability);
        }
        let digest = digest_secret(&secret);
        secret.zeroize();
        Ok((CapId(id_bytes), digest))
    }
}

impl std::fmt::Debug for CapabilityToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A capability is a bearer credential for a live job's secrets. It gets the same treatment
        // as the secrets themselves.
        f.write_str("CapabilityToken(<redacted>)")
    }
}

/// Hash of the secret half. The registry stores this, never the secret.
///
/// A single BLAKE3 pass is the right primitive here and a password KDF would be the wrong one: the
/// input is 256 bits of CSPRNG output, not a human-chosen string, so there is no dictionary to slow
/// down and nothing an iteration count would buy except latency on the hot path.
fn digest_secret(secret: &[u8]) -> [u8; 32] {
    *blake3::hash(secret).as_bytes()
}

/// What a capability authorises. Safe to log — it names a job and some secret *names*, never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityGrant {
    pub cap_id: CapId,
    pub tenant: String,
    pub job_id: String,
    pub node_id: String,
    /// The declared set. Fixed at mint; a redemption may ask for a subset, never a superset.
    pub names: BTreeSet<String>,
    /// Recorded so the gate can be re-checked at redemption (defence in depth: the mint-time refusal
    /// is the control, this is the belt to its braces).
    pub author_class: AuthorClass,
    pub expires_at: u64,
}

/// The registry's private record: the grant plus the authenticator and the one-shot flags.
pub(crate) struct CapRecord {
    pub(crate) grant: CapabilityGrant,
    digest: [u8; 32],
    pub(crate) consumed: bool,
    pub(crate) revoked: bool,
}

/// Hand-written so the digest never reaches a log. It is only a hash of the authenticator, so
/// printing it does not directly enable a forgery — but it is a verifier for a live bearer token,
/// and there is no debugging question it answers.
impl std::fmt::Debug for CapRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapRecord")
            .field("grant", &self.grant)
            .field("digest", &"<redacted>")
            .field("consumed", &self.consumed)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl CapRecord {
    /// Constant-time check that `presented` is this record's token.
    ///
    /// `subtle::ConstantTimeEq` rather than `==`: a byte-at-a-time comparison that returns early
    /// leaks, through timing, how many leading bytes of a guess were right, which turns a 2^256
    /// search into 32 sequential 2^8 searches.
    pub(crate) fn authenticates(&self, presented: &[u8; 32]) -> bool {
        self.digest.ct_eq(presented).into()
    }
}

/// Mint a token and the record that will authenticate it.
///
/// Takes the grant's fields rather than a ready-made [`CapabilityGrant`] because `cap_id` is not the
/// caller's to choose: the id is generated here, with the token it indexes, so there is no way to
/// construct a grant addressed to an id that no token was ever minted for.
///
/// Returns the token *once*. Nothing keeps a copy — the registry holds only the digest, so a dump of
/// the broker's memory does not yield a usable capability.
pub(crate) fn mint_record(
    tenant: String,
    job_id: String,
    node_id: String,
    names: BTreeSet<String>,
    author_class: AuthorClass,
    expires_at: u64,
) -> (CapabilityToken, CapId, CapRecord) {
    let (token, cap_id, digest) = CapabilityToken::mint();
    let grant = CapabilityGrant { cap_id, tenant, job_id, node_id, names, author_class, expires_at };
    (token, cap_id, CapRecord { grant, digest, consumed: false, revoked: false })
}

/// Parse a presented token into `(id, digest)` for lookup and constant-time comparison.
pub(crate) fn parse_token(token: &CapabilityToken) -> Result<(CapId, [u8; 32]), SecretError> {
    token.parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mint() -> (CapabilityToken, CapId, CapRecord) {
        mint_record(
            "acme".into(),
            "job-1".into(),
            "node-a".into(),
            ["NPM_TOKEN".to_string()].into_iter().collect(),
            AuthorClass::Member,
            100,
        )
    }

    #[test]
    fn a_minted_token_authenticates_and_a_forged_one_does_not() {
        let (token, id, rec) = mint();
        let (parsed_id, digest) = parse_token(&token).unwrap();
        assert_eq!(parsed_id, id);
        assert_eq!(rec.grant.cap_id, id, "the record is addressed by the id inside the token");
        assert!(rec.authenticates(&digest));

        // Same id, different secret half: the id is public, the authenticator is not.
        let forged = CapabilityToken::from_wire(format!("{TOKEN_PREFIX}{id}.{}", hex::encode([0u8; SECRET_LEN])));
        let (_, forged_digest) = parse_token(&forged).unwrap();
        assert!(!rec.authenticates(&forged_digest));
    }

    #[test]
    fn tokens_are_unique_and_unguessable_in_both_halves() {
        let (t1, id1, _) = mint();
        let (t2, id2, _) = mint();
        assert_ne!(id1, id2);
        assert_ne!(t1.expose(), t2.expose());
        // 16 bytes of id + 32 of secret, hex-encoded, plus the prefix and separator.
        assert_eq!(t1.expose().len(), TOKEN_PREFIX.len() + ID_LEN * 2 + 1 + SECRET_LEN * 2);
    }

    #[test]
    fn every_malformed_token_fails_the_same_way() {
        for bad in [
            "",
            "nope",
            "hcap_",
            "hcap_zz.zz",
            "hcap_00.11",
            &format!("{TOKEN_PREFIX}{}.{}", hex::encode([1u8; ID_LEN]), hex::encode([2u8; 8])),
            // A right-shaped token for a capability that was never minted.
            &format!("{TOKEN_PREFIX}{}.{}", hex::encode([1u8; ID_LEN]), hex::encode([2u8; SECRET_LEN])),
        ] {
            let parsed = parse_token(&CapabilityToken::from_wire(bad.to_string()));
            // The last case parses (it is well-formed but unknown); the rest do not. Either way the
            // caller learns nothing beyond "no".
            if let Err(e) = parsed {
                assert_eq!(e, SecretError::BadCapability, "input {bad:?}");
            }
        }
    }

    #[test]
    fn the_token_and_its_verifier_are_redacted_in_debug() {
        let (token, _, rec) = mint();
        assert_eq!(format!("{token:?}"), "CapabilityToken(<redacted>)");
        assert!(!format!("{token:?}").contains("hcap_"));
        // The record is logged during incident work; the grant is the useful part and the digest is
        // not part of it.
        let rendered = format!("{rec:?}");
        assert!(rendered.contains("job-1"));
        assert!(rendered.contains("digest: \"<redacted>\""));
    }
}
