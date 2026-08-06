//! The secret broker (design D§7.4, milestone M3).
//!
//! Spec §14.2 is absolute about *platform* credentials: the `X-Hull-CI-Secret`, cloud keys, registry
//! tokens and `source_url` auth **MUST NOT** reach a job environment. Nothing in this crate weakens
//! that — it never sees a platform credential and has no way to emit one. What it adds is the other
//! half of D§2.2(c): a **tenant's own** declared secret (an integration-test API key, a private
//! registry token they chose to set) is a different kind of thing, and a CI system that cannot accept
//! one is a toy. This crate is the machinery that makes accepting one safe.
//!
//! Four properties, in the order they matter:
//!
//! 1. **The author-class gate is the control.** [`hull_ci_proto::AuthorClass::Outsider`] is refused a capability
//!    *here*, at the broker (see [`SecretBroker::mint`]) — never in the pipeline, which the author
//!    controls. Author class is derived from the dispatch's `author` and repo membership (D§1); it is
//!    a fact about the actor that no `.hull/ci.star` edit can raise. That is what makes GitHub's
//!    "pwn request" class ([GitHub Security Lab][pwn]) structurally impossible here rather than
//!    merely discouraged: hostile code never receives the value in the first place.
//! 2. **Envelope encryption under a per-tenant KEK** ([`keys`]). Every value gets a fresh DEK; the
//!    DEK is wrapped by that tenant's KEK; the KEK's root lives behind [`keys::KeyManager`] so a real
//!    KMS/HSM holds it and it never leaves. One KEK per tenant is the unit of tenancy: it buys
//!    single-call **crypto-shredding** ([`SecretBroker::shred_tenant`]) and hard blast-radius
//!    isolation.
//! 3. **Just-in-time delivery** ([`capability`]). A short-TTL, single-use capability bound to
//!    `(job_id, node_id, declared names, author_class)`. A reference travels, not the secret.
//! 4. **Node identity makes the node binding real** ([`identity`], [`service`]). A `node_id` in a
//!    request is a claim; an Ed25519 signature over the redemption, checked against an enrolment
//!    table, is a proof. [`service::SecretService`] verifies the signature and derives the node id
//!    from the verified key, so the id the broker binds against is never one the caller wrote.
//! 5. **Masking is a backstop, not a control** ([`mask`]) — exact-substring redaction, trivially
//!    defeated by base64/split/transform. It stops an accidental `echo`. It is not what protects a
//!    secret from hostile code; (1) is.
//!
//! Plaintext is never persisted and never crosses this crate's boundary except as
//! [`SecretBytes`], which zeroizes on drop and redacts itself in `Debug`.
//!
//! **Nothing here does I/O.** Persistence is behind [`store::SealedStore`] and key custody behind
//! [`keys::KeyManager`], so the control plane can back them with Postgres and AWS KMS without this
//! crate learning about either.
//!
//! # What a redemption does *not* prove
//!
//! Worth stating in the crate doc rather than a module doc, because these are the gaps an operator
//! would otherwise have to infer from an absence:
//!
//! * **Not lease-holding.** D§7.4 says "the broker verifies the node is the lease-holder"; it cannot.
//!   The lease table is the control plane's. What stands in for it here is *when* a capability is
//!   minted — at placement, by the same call that grants the lease — so a capability exists only for
//!   the node that was just leased the step. That is a property of the composition, not of this
//!   crate, and a different composition would not inherit it.
//! * **Not channel binding.** The signature covers the redemption, not the connection it arrives on.
//!   A network deployment must still carry it inside TLS; without that, an attacker who can replay a
//!   *whole* signed request within the freshness window is only stopped by the capability being
//!   single-use — which is why it is single-use.
//! * **Not attestation.** An enrolled key proves a machine was provisioned, not that it is running
//!   the software it was provisioned with. D§7.4's "so node attestations can ride it later" is the
//!   forward reference; nothing here implements one.
//!
//! [pwn]: https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/

pub mod broker;
pub mod capability;
pub mod identity;
pub mod keys;
pub mod mask;
pub mod package;
pub mod seal;
pub mod service;
pub mod store;

pub use broker::{CapabilityRequest, DeliveredSecrets, SecretBroker};
pub use capability::{CapId, CapabilityGrant, CapabilityToken, DEFAULT_TTL_SECS};
pub use identity::{NodeIdentity, NodePublicKey, NodeRegistry, SignedRedemption, MAX_SKEW_SECS};
pub use keys::{DevKeyManager, KekVersion, KeyManager};
pub use package::{
    ProxyCapabilityRequest, ProxyCredentialGrant, ProxyCredentialService, ProxyIdentity,
    ProxyRegistry, SignedProxyRedemption,
};
pub use mask::{Masker, MASK, MIN_MASKABLE_LEN};
pub use seal::{SealedSecret, SecretBytes, Vault};
pub use service::SecretService;
pub use store::{MemorySealedStore, SealedStore};

/// Everything that can go wrong, named for the attack or mistake it stops.
///
/// Note the deliberate coarseness of [`SecretError::Decrypt`]: a wrong tenant, a renamed record, a
/// substituted KEK version and a flipped bit all surface as one opaque authentication failure.
/// Distinguishing them would hand an attacker a decryption oracle that says *which* piece of context
/// was wrong. The refusals above it (`Outsider`, `Undeclared`, `WrongNode`) are policy decisions
/// about facts the caller already knows, so those stay specific — an operator debugging a broken
/// pipeline needs to be told why.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretError {
    /// Secret names become environment variables, so they must be shaped like one. Anything else
    /// would either be un-exportable or would smuggle shell syntax into the exec.
    #[error("`{0}` is not a valid secret name (expected `[A-Z_][A-Z0-9_]*`)")]
    InvalidName(String),
    /// A tenant secret named `PATH` would silently rewrite the job's toolchain lookup. The job
    /// environment's base variables (hull-ci-node `env::base_env`) are ours, not a namespace tenants
    /// may write into.
    #[error("`{0}` is reserved by the job environment and may not be used as a secret name")]
    ReservedName(String),
    /// Sealing an empty value is almost certainly a bug (a mis-read file, an unset variable), and an
    /// empty string is unmaskable anyway.
    #[error("secret value is empty")]
    EmptyValue,
    /// No KEK for this tenant: never provisioned, or crypto-shredded. Both are terminal for reads.
    #[error("no key material for tenant `{0}` (never provisioned, or crypto-shredded)")]
    NoTenantKey(String),
    /// A record references a KEK version this tenant no longer has — the shape a shredded tenant's
    /// ciphertext takes.
    #[error("tenant `{tenant}` has no KEK version {version}")]
    NoKekVersion { tenant: String, version: u32 },
    /// AEAD authentication failed. Intentionally says nothing about *why*.
    #[error("authenticated decryption failed")]
    Decrypt,
    /// The record's own labels disagree with the context the caller asked to open it under. The AEAD
    /// would refuse this anyway (the labels are in the AAD); catching it first turns a caller bug
    /// into a readable message instead of an opaque crypto failure.
    #[error("record is labelled `{found}` but was opened as `{expected}`")]
    ContextMismatch { expected: String, found: String },
    #[error("tenant `{tenant}` has no secret named `{name}`")]
    UnknownSecret { tenant: String, name: String },
    /// **The gate** (D§7.4). An outsider-authored job gets no capability, whatever the pipeline says.
    #[error("author class `outsider` may not receive tenant secrets")]
    OutsiderRefused,
    /// Malformed, unknown, or forged capability token.
    #[error("capability is not valid")]
    BadCapability,
    #[error("capability expired")]
    CapabilityExpired,
    /// Single-use means single-use: the replay is refused, not served.
    #[error("capability has already been redeemed")]
    CapabilityConsumed,
    #[error("capability was revoked")]
    CapabilityRevoked,
    /// Presented by a node other than the one the capability was minted for — a stolen token used
    /// from the wrong place.
    ///
    /// Only meaningful because [`service::SecretService`] derives the presenting node's id from a
    /// verified Ed25519 signature. Reached through [`SecretBroker::redeem`] directly, it compares a
    /// string the caller supplied against a string the caller could have supplied differently.
    #[error("capability is bound to another node")]
    WrongNode,
    /// Presented by a package proxy other than the one the capability was minted for.
    ///
    /// The proxy-side sibling of [`SecretError::WrongNode`], and load-bearing for the same reason:
    /// [`package::ProxyCredentialService`] derives the presenting proxy's id from a verified Ed25519
    /// signature, so this is a fact the caller cannot restate.
    #[error("capability is bound to another package proxy")]
    WrongProxy,
    /// The capability was minted for a different job than the node signed its redemption for.
    #[error("capability is bound to job `{bound}` but was presented for `{presented}`")]
    WrongJob { bound: String, presented: String },
    /// The capability was minted for a different tenant than the redemption was signed for.
    ///
    /// Only reachable on the package-proxy path, and it exists because that path has a property the
    /// node path does not: one proxy process serves every tenant on the fleet, so "the credential I
    /// just fetched belongs to the tenant whose job asked for it" is a claim that has to be checked
    /// rather than a consequence of the topology.
    #[error("capability is bound to tenant `{bound}` but was presented for `{presented}`")]
    WrongTenant { bound: String, presented: String },
    /// The redemption's Ed25519 signature does not verify — a forged, corrupted, or tampered-with
    /// request. Covers a malformed public key too: both mean "this was not signed by the key it
    /// claims", and there is no reason to help a caller tell them apart.
    #[error("node signature is not valid")]
    BadNodeSignature,
    /// A correctly signed redemption from a key no operator enrolled. Distinct from
    /// [`SecretError::BadNodeSignature`] on purpose: an operator whose node will not redeem needs to
    /// know whether the request was corrupt or the machine was never provisioned, and an attacker
    /// who cannot forge a signature learns nothing actionable from the difference.
    #[error("node public key `{0}` is not enrolled")]
    UnenrolledNode(String),
    /// A correctly signed proxy redemption from a key no operator enrolled as a package proxy.
    ///
    /// Distinct from [`SecretError::UnenrolledNode`] because the two enrolment tables are distinct:
    /// a key enrolled as a *node* must not resolve as a proxy, since the two principal families
    /// authorise different disclosures, and an operator debugging one needs to be told which table
    /// was consulted.
    #[error("package-proxy public key `{0}` is not enrolled")]
    UnenrolledProxy(String),
    /// The redemption's timestamp is further from ours than [`identity::MAX_SKEW_SECS`] — a replay,
    /// or a node whose clock is broken. Refused before it can consume a capability.
    #[error("redemption is {skew_secs}s away from this clock")]
    StaleRedemption { skew_secs: u64 },
    /// One public key may not be enrolled to two nodes: that would let one machine redeem as either.
    #[error("public key is already enrolled to node `{enrolled_to}` and may not also be `{requested}`")]
    KeyAlreadyEnrolled { enrolled_to: String, requested: String },
    /// The job asked for a name outside its declared set. The declared set is fixed at mint time, so
    /// a job cannot widen its own reach mid-flight.
    #[error("`{0}` is not in this job's declared secret set")]
    Undeclared(String),
    /// The backing store failed. Opaque on purpose — a DB error string is not something to render
    /// next to a secret.
    #[error("secret store failure: {0}")]
    Store(String),
}

/// A source of wall-clock seconds, injectable so TTL behaviour is testable without sleeping.
///
/// Capability expiry is the primary revocation mechanism (D§7.4), which makes "what time is it"
/// security-relevant rather than incidental — worth a seam that tests can drive to the second.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Seconds since the Unix epoch.
    fn now_secs(&self) -> u64;
}

/// The real clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            // A clock before the epoch is a broken host. Returning 0 makes every capability look
            // expired, which fails closed — no secret is delivered — rather than panicking a broker
            // that other tenants depend on.
            .unwrap_or(0)
    }
}

/// Names the job environment owns (hull-ci-node `env::base_env`). A tenant secret may not shadow one.
const RESERVED_NAMES: &[&str] = &["PATH", "HOME", "LANG", "CI", "TMPDIR", "IFS", "LD_PRELOAD", "LD_LIBRARY_PATH"];

/// Validate a secret name at the door, both when storing and when declaring.
///
/// Checked in two places rather than one because the two are different trust questions: a name being
/// *stored* comes from a tenant admin, a name being *declared* comes from a pipeline, and the
/// pipeline is written by whoever authored the change.
pub fn validate_name(name: &str) -> Result<(), SecretError> {
    let mut chars = name.chars();
    let ok = match chars.next() {
        Some(c) if c.is_ascii_uppercase() || c == '_' => {
            chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        }
        _ => false,
    };
    if !ok {
        return Err(SecretError::InvalidName(name.to_string()));
    }
    if RESERVED_NAMES.contains(&name) {
        return Err(SecretError::ReservedName(name.to_string()));
    }
    Ok(())
}

/// Build associated data: domain-separated and length-prefixed.
///
/// The length prefix is not decoration. Concatenating context naively makes `("ab", "c")` and
/// `("a", "bc")` the same AAD, and "tenant `ab` + secret `c`" colliding with "tenant `a` + secret
/// `bc`" is precisely the cross-tenant confusion the AAD exists to prevent. Prefixing each field
/// with its big-endian length makes the encoding injective, so distinct context is always distinct
/// bytes. The domain string keeps DEK-wrap ciphertexts and value ciphertexts from ever being
/// interchangeable even if the same key were somehow used for both.
pub(crate) fn associated_data(domain: &str, fields: &[&str]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + fields.iter().map(|f| f.len() + 4).sum::<usize>() + 4);
    for field in std::iter::once(domain).chain(fields.iter().copied()) {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_must_be_environment_shaped() {
        assert!(validate_name("NPM_TOKEN").is_ok());
        assert!(validate_name("_X9").is_ok());
        for bad in ["npm_token", "NPM-TOKEN", "9LIVES", "", "A B", "A;rm -rf /"] {
            assert!(matches!(validate_name(bad), Err(SecretError::InvalidName(_))), "{bad} must be refused");
        }
    }

    #[test]
    fn reserved_environment_names_are_refused() {
        // A secret named PATH would rewrite the job's toolchain lookup from inside the delivery path.
        for name in ["PATH", "HOME", "LD_PRELOAD"] {
            assert!(matches!(validate_name(name), Err(SecretError::ReservedName(_))), "{name}");
        }
    }

    #[test]
    fn associated_data_is_injective_across_field_boundaries() {
        // The whole point of length-prefixing: no two different contexts share an encoding.
        assert_ne!(associated_data("d", &["ab", "c"]), associated_data("d", &["a", "bc"]));
        assert_ne!(associated_data("d1", &["a"]), associated_data("d2", &["a"]));
        assert_eq!(associated_data("d", &["a", "b"]), associated_data("d", &["a", "b"]));
    }
}
