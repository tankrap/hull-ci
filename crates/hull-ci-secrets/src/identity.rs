//! Node identity: the Ed25519 enrolment keypair, and the thing that makes `WrongNode` mean something.
//!
//! D§7.4 closes with "Node identity to control is a per-node Ed25519 keypair enrolled at
//! provisioning", and — added after the first pass of this design met the code — is blunt about why
//! it matters to *this* crate:
//!
//! > **Node binding is only as strong as the thing that authenticates the node, and that is a
//! > separate component.** The broker binds a capability to a `node_id` and refuses a redemption
//! > presenting a different one — but a `node_id` is just a string in a request. Unless the transport
//! > has already proven *which node* is speaking, the field is self-asserted and the `WrongNode`
//! > refusal is decorative: an attacker who has the capability token can simply claim the right id.
//!
//! So this module exists to remove the string. [`SecretBroker::redeem`](crate::SecretBroker::redeem)
//! still takes a `node_id`, because it is the wrong layer to know about signatures — but nothing
//! outside a test calls it directly any more. The live path is
//! [`SecretService::redeem`](crate::service::SecretService::redeem), which takes a
//! [`SignedRedemption`], verifies the Ed25519 signature over it, looks the **verified public key** up
//! in the [`NodeRegistry`], and passes the *enrolled* node id — never the requester's claim — down to
//! the broker. A caller cannot name the node it wants to be, only prove which node it is.
//!
//! # One module owns the signed bytes
//!
//! Signer and verifier are in the same file on purpose. A signature scheme fails silently and
//! completely when the two sides disagree about the message by one byte, and the usual way that
//! happens is two modules each growing their own serializer. [`signing_payload`] is the only place
//! the message is built; [`NodeIdentity::sign`] and [`NodeRegistry::verify`] both call it.
//!
//! # What a verified signature does and does not prove
//!
//! It proves the sender holds the private half of a key some operator enrolled, and it binds that
//! proof to one capability, one job, one nonce and one instant. It does **not** prove the sender is
//! the lease-holder for that step — that requires the control plane's lease table, which D§7.4 now
//! says explicitly the broker cannot consult on its own — and it does not bind the redemption to a
//! transport channel, so on a network deployment it must ride inside TLS like any other bearer
//! exchange. See the crate docs' "what this does not prove" list before treating it as more.

use std::collections::HashMap;
use std::sync::Mutex;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::capability::CapabilityToken;
use crate::{associated_data, SecretError};

/// Bytes in an Ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Bytes in an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;
/// Bytes of freshness in a redemption.
pub const NONCE_LEN: usize = 16;

/// How far a redemption's `issued_at` may sit from the verifier's clock, in seconds.
///
/// Sized against the capability TTL ([`crate::DEFAULT_TTL_SECS`], 60s) rather than against network
/// latency: a redemption whose timestamp is further out than the capability could possibly live is
/// either a replay or a node whose clock is broken, and both should be refused rather than served.
/// Symmetric because clock skew has no preferred direction — a node that is fast is as suspicious as
/// one that is slow.
pub const MAX_SKEW_SECS: u64 = 60;

/// An enrolled node's public half. Safe to log — it *is* the node's public name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodePublicKey([u8; PUBLIC_KEY_LEN]);

impl NodePublicKey {
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Self {
        NodePublicKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }

    /// Parse the verifying key. Errors on a point that is not a valid Ed25519 public key, which is a
    /// forged or corrupt request rather than an enrolment we have never seen.
    fn verifying_key(&self) -> Result<VerifyingKey, SecretError> {
        VerifyingKey::from_bytes(&self.0).map_err(|_| SecretError::BadNodeSignature)
    }

    /// Check a signature over already-built, domain-separated bytes.
    ///
    /// `pub(crate)` and takes a finished payload, because the one way a signature scheme fails
    /// silently is two modules each growing their own serializer (see the module doc). A caller
    /// outside this crate has no business building the bytes; a caller inside it must build them in
    /// the module that also signs them.
    pub(crate) fn verify_raw(&self, payload: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Result<(), SecretError> {
        self.verifying_key()?
            .verify(payload, &Signature::from_bytes(signature))
            .map_err(|_| SecretError::BadNodeSignature)
    }
}

impl std::fmt::Display for NodePublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

/// A node's enrolment keypair. **Held only by the node it identifies.**
///
/// The signing half never leaves this type: there is no accessor for it and no `Debug` that renders
/// it. A node that could export its own key could be impersonated by anything that read one log line.
pub struct NodeIdentity {
    signing: SigningKey,
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The public half is the identity and is fine to print; the private half is the identity's
        // whole value and is not.
        f.debug_struct("NodeIdentity").field("public", &self.public().to_string()).finish()
    }
}

impl NodeIdentity {
    /// A fresh keypair from the operating system CSPRNG.
    ///
    /// Generated per process today, which is the honest shape for a node whose enrolment is also
    /// per-process (see [`NodeRegistry`]). A node that outlives its process needs its key persisted
    /// at provisioning time — that is a deployment concern, and deliberately not invented here.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        NodeIdentity { signing: SigningKey::from_bytes(&seed) }
    }

    /// Rebuild an identity from a stored 32-byte seed, for a node whose key was enrolled earlier.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        NodeIdentity { signing: SigningKey::from_bytes(&seed) }
    }

    pub fn public(&self) -> NodePublicKey {
        NodePublicKey(self.signing.verifying_key().to_bytes())
    }

    /// Sign already-built, domain-separated bytes.
    ///
    /// The counterpart to [`NodePublicKey::verify_raw`], and `pub(crate)` for the same reason: an
    /// enrolment keypair signs *this crate's* payloads, each of which is built in exactly one module
    /// alongside its verifier. Exposing a general-purpose signing oracle over an enrolled key would
    /// let any future payload be signed by a key whose meaning was fixed at provisioning.
    pub(crate) fn sign_raw(&self, payload: &[u8]) -> [u8; SIGNATURE_LEN] {
        let signature: Signature = self.signing.sign(payload);
        signature.to_bytes()
    }

    /// Sign a redemption of `token` for `job_id`, asking for `requested` names.
    ///
    /// `now` is passed in rather than read here so the caller owns its clock — the same reason
    /// [`crate::Clock`] exists. A fresh nonce is drawn per call: it does not carry the replay defence
    /// (the capability's single-use property does, and it is checked under the broker's lock), but it
    /// guarantees two redemptions are never byte-identical, so a captured signature is evidence of
    /// exactly one attempt rather than a reusable artefact.
    pub fn sign(
        &self,
        token: &CapabilityToken,
        job_id: &str,
        requested: &[String],
        now: u64,
    ) -> SignedRedemption {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let public_key = self.public();
        let payload = signing_payload(token, job_id, requested, &nonce, now, &public_key);
        let signature: Signature = self.signing.sign(&payload);
        SignedRedemption {
            token: token.clone(),
            job_id: job_id.to_string(),
            requested: requested.to_vec(),
            nonce,
            issued_at: now,
            public_key,
            signature: signature.to_bytes(),
        }
    }
}

/// A redemption request as it goes over the control↔broker link.
///
/// Everything the signature covers is in here, so a verifier needs nothing but this value and its own
/// clock. Note what is **not** in here: a `node_id`. That is the entire point — the id is derived
/// from `public_key` after verification (see the module docs), so there is no field for a caller to
/// put a lie in.
#[derive(Debug, Clone)]
pub struct SignedRedemption {
    /// The bearer capability. Redacted in `Debug` by its own type.
    pub token: CapabilityToken,
    /// The job the node believes it is running. Checked against the grant, so a node cannot redeem
    /// one job's capability while claiming another's.
    pub job_id: String,
    /// Names asked for; empty means "everything this job declared" (see [`crate::SecretBroker::redeem`]).
    pub requested: Vec<String>,
    pub nonce: [u8; NONCE_LEN],
    /// Unix seconds at the signer. Checked against [`MAX_SKEW_SECS`].
    pub issued_at: u64,
    /// The **claimed** identity. Load-bearing only once the signature over it verifies.
    pub public_key: NodePublicKey,
    pub signature: [u8; SIGNATURE_LEN],
}

/// The exact bytes a redemption's signature covers.
///
/// Built with [`associated_data`], so every field is length-prefixed and the whole thing is
/// domain-separated. That is not decoration here either: without length prefixes a node could move a
/// character between `job_id` and a secret name and produce the same signed bytes for a different
/// request, and the domain string keeps a redemption signature from ever being replayable as any
/// other signature this system might one day define over the same key.
///
/// The capability token is covered in full rather than by its public id. Binding the signature to the
/// exact bearer credential presented means a captured signature cannot be re-presented alongside a
/// *different* capability for the same job. Ed25519 signs a hash of the message and the signature
/// reveals nothing about it, so covering the secret half costs nothing.
fn signing_payload(
    token: &CapabilityToken,
    job_id: &str,
    requested: &[String],
    nonce: &[u8; NONCE_LEN],
    issued_at: u64,
    public_key: &NodePublicKey,
) -> Vec<u8> {
    let nonce_hex = hex::encode(nonce);
    let issued = issued_at.to_string();
    let key_hex = public_key.to_string();
    let mut fields: Vec<&str> = vec![token.expose(), job_id, &nonce_hex, &issued, &key_hex];
    fields.extend(requested.iter().map(String::as_str));
    associated_data("hull-ci/node-redemption/v1", &fields)
}

/// Which public keys belong to which nodes.
///
/// This is the enrolment table D§7.4 means by "enrolled at provisioning". It is the *only* place a
/// `node_id` is allowed to come from on the redemption path, which is what turns
/// [`SecretError::WrongNode`] from a comment into a control.
///
/// The mapping is enforced injective in both directions. One key must not name two nodes (that would
/// let one machine redeem another's capabilities), and one node must not have two keys registered at
/// once (a decommissioned key that still resolves is a key that was never really revoked — re-enrol
/// replaces, see [`NodeRegistry::enrol`]).
#[derive(Debug, Default)]
pub struct NodeRegistry {
    by_key: Mutex<HashMap<[u8; PUBLIC_KEY_LEN], String>>,
}

impl NodeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enrol `key` as `node_id`, replacing whatever key that node had before.
    ///
    /// Replacing rather than adding is the rotation story: a node that regenerates its keypair (a
    /// fresh process, a re-provision) enrols again and the old key stops resolving immediately. An
    /// additive registry would accumulate keys that are still accepted long after the machine that
    /// held them was destroyed.
    ///
    /// Errors if the key is already enrolled to a *different* node, because silently re-pointing one
    /// key at another node id is how a decommissioned machine keeps redeeming.
    pub fn enrol(&self, node_id: impl Into<String>, key: NodePublicKey) -> Result<(), SecretError> {
        let node_id = node_id.into();
        let mut by_key = self.by_key.lock().expect("node registry poisoned");
        if let Some(existing) = by_key.get(key.as_bytes()) {
            if *existing != node_id {
                return Err(SecretError::KeyAlreadyEnrolled {
                    enrolled_to: existing.clone(),
                    requested: node_id,
                });
            }
            return Ok(());
        }
        by_key.retain(|_, n| *n != node_id);
        by_key.insert(*key.as_bytes(), node_id);
        Ok(())
    }

    /// Withdraw a node's enrolment — decommissioning. Returns whether anything was removed.
    ///
    /// After this the node's signatures still verify cryptographically and still refuse to resolve to
    /// an id, which is the correct order of events: the key is not broken, it is no longer *ours*.
    pub fn revoke(&self, node_id: &str) -> bool {
        let mut by_key = self.by_key.lock().expect("node registry poisoned");
        let before = by_key.len();
        by_key.retain(|_, n| n != node_id);
        by_key.len() != before
    }

    pub fn is_enrolled(&self, key: &NodePublicKey) -> bool {
        self.by_key.lock().expect("node registry poisoned").contains_key(key.as_bytes())
    }

    /// The id `key` is enrolled under, if any.
    ///
    /// Exposed so a second principal family can reuse this table's properties (injective in both
    /// directions, replace-on-re-enrol, revocable) rather than growing a parallel copy of them — see
    /// [`crate::package::ProxyRegistry`]. It deliberately does **not** verify anything: a caller that
    /// resolves a key without first checking a signature over the request has learned nothing, which
    /// is why [`NodeRegistry::verify`] exists and this is not it.
    pub fn resolve(&self, key: &NodePublicKey) -> Option<String> {
        self.by_key.lock().expect("node registry poisoned").get(key.as_bytes()).cloned()
    }

    /// Verify a redemption and return the node id **derived from the verified key**.
    ///
    /// Order matters and is chosen for what each refusal teaches a caller who does not hold a key:
    ///
    /// 1. **Signature first.** Everything below is unreachable without the private half, so nothing
    ///    below can be used as an oracle by someone who is merely guessing.
    /// 2. **Freshness.** A stale or future-dated request is refused before it can consume a
    ///    capability.
    /// 3. **Enrolment.** Last, and the only step that yields the id the broker will bind against.
    ///
    /// The distinction between "signature does not verify" and "key is not enrolled" is deliberately
    /// preserved. It is not an oracle worth closing — an attacker who cannot forge a signature learns
    /// nothing actionable from either answer — and an operator whose node will not redeem needs to be
    /// told whether the problem is a corrupt request or a machine nobody provisioned.
    pub fn verify(&self, req: &SignedRedemption, now: u64) -> Result<String, SecretError> {
        let verifying = req.public_key.verifying_key()?;
        let signature = Signature::from_bytes(&req.signature);
        let payload = signing_payload(
            &req.token,
            &req.job_id,
            &req.requested,
            &req.nonce,
            req.issued_at,
            &req.public_key,
        );
        verifying.verify(&payload, &signature).map_err(|_| SecretError::BadNodeSignature)?;

        let skew = now.abs_diff(req.issued_at);
        if skew > MAX_SKEW_SECS {
            return Err(SecretError::StaleRedemption { skew_secs: skew });
        }

        self.by_key
            .lock()
            .expect("node registry poisoned")
            .get(req.public_key.as_bytes())
            .cloned()
            .ok_or_else(|| SecretError::UnenrolledNode(req.public_key.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> CapabilityToken {
        CapabilityToken::from_wire("hcap_00112233445566778899aabbccddeeff.".to_string() + &"11".repeat(32))
    }

    fn signed(id: &NodeIdentity, now: u64) -> SignedRedemption {
        id.sign(&token(), "job-1", &["NPM_TOKEN".to_string()], now)
    }

    #[test]
    fn an_enrolled_node_resolves_to_the_id_it_was_enrolled_under() {
        // The whole mechanism in one assertion: the id comes out of the registry, keyed by a public
        // key whose signature just verified — it is never read off the request.
        let registry = NodeRegistry::new();
        let node = NodeIdentity::generate();
        registry.enrol("node-a", node.public()).unwrap();
        assert_eq!(registry.verify(&signed(&node, 1_000), 1_000).unwrap(), "node-a");
    }

    #[test]
    fn a_node_that_was_never_enrolled_is_refused_however_well_it_signs() {
        // The signature is perfectly valid. That is the point: cryptographic validity is not
        // authority, enrolment is.
        let registry = NodeRegistry::new();
        let stranger = NodeIdentity::generate();
        let err = registry.verify(&signed(&stranger, 1_000), 1_000).unwrap_err();
        assert!(matches!(err, SecretError::UnenrolledNode(_)));
    }

    #[test]
    fn a_tampered_request_does_not_verify() {
        // Each field below is covered by the signature, so changing any one of them invalidates it.
        // Without this the "derive the id from the key" scheme would be defeated by editing the
        // request after signing.
        let registry = NodeRegistry::new();
        let node = NodeIdentity::generate();
        registry.enrol("node-a", node.public()).unwrap();

        let base = signed(&node, 1_000);
        let mut wrong_job = base.clone();
        wrong_job.job_id = "job-2".into();
        let mut wrong_names = base.clone();
        wrong_names.requested = vec!["DEPLOY_KEY".into()];
        let mut wrong_nonce = base.clone();
        wrong_nonce.nonce[0] ^= 0x01;
        let mut wrong_time = base.clone();
        wrong_time.issued_at = 1_001;
        let mut wrong_token = base.clone();
        wrong_token.token = CapabilityToken::from_wire("hcap_ff.".to_string() + &"22".repeat(32));
        let mut wrong_sig = base.clone();
        wrong_sig.signature[0] ^= 0x01;

        for (what, req) in [
            ("job_id", wrong_job),
            ("requested", wrong_names),
            ("nonce", wrong_nonce),
            ("issued_at", wrong_time),
            ("token", wrong_token),
            ("signature", wrong_sig),
        ] {
            assert!(
                matches!(registry.verify(&req, 1_000), Err(SecretError::BadNodeSignature)),
                "tampering with {what} must invalidate the signature"
            );
        }
    }

    #[test]
    fn one_node_cannot_present_anothers_public_key() {
        // The attack the derivation is for: a machine holding a stolen capability swaps in the
        // enrolled node's public key to be resolved as that node. It cannot sign for it.
        let registry = NodeRegistry::new();
        let real = NodeIdentity::generate();
        let attacker = NodeIdentity::generate();
        registry.enrol("node-a", real.public()).unwrap();

        let mut forged = signed(&attacker, 1_000);
        forged.public_key = real.public();
        assert!(matches!(registry.verify(&forged, 1_000), Err(SecretError::BadNodeSignature)));
    }

    #[test]
    fn a_stale_or_future_dated_redemption_is_refused() {
        let registry = NodeRegistry::new();
        let node = NodeIdentity::generate();
        registry.enrol("node-a", node.public()).unwrap();

        // Inside the window, in both directions.
        assert!(registry.verify(&signed(&node, 1_000), 1_000 + MAX_SKEW_SECS).is_ok());
        assert!(registry.verify(&signed(&node, 1_000 + MAX_SKEW_SECS), 1_000).is_ok());
        // Outside it, in both directions.
        for (signed_at, now) in [(1_000, 1_000 + MAX_SKEW_SECS + 1), (1_000 + MAX_SKEW_SECS + 1, 1_000)] {
            assert!(matches!(
                registry.verify(&signed(&node, signed_at), now),
                Err(SecretError::StaleRedemption { .. })
            ));
        }
    }

    #[test]
    fn re_enrolling_a_node_replaces_its_key_rather_than_adding_one() {
        // A decommissioned key that still resolves is a key that was never revoked.
        let registry = NodeRegistry::new();
        let old = NodeIdentity::generate();
        let new = NodeIdentity::generate();
        registry.enrol("node-a", old.public()).unwrap();
        registry.enrol("node-a", new.public()).unwrap();

        assert_eq!(registry.verify(&signed(&new, 1_000), 1_000).unwrap(), "node-a");
        assert!(matches!(
            registry.verify(&signed(&old, 1_000), 1_000),
            Err(SecretError::UnenrolledNode(_))
        ));
    }

    #[test]
    fn one_key_may_not_name_two_nodes() {
        let registry = NodeRegistry::new();
        let node = NodeIdentity::generate();
        registry.enrol("node-a", node.public()).unwrap();
        // Idempotent for the same node…
        registry.enrol("node-a", node.public()).unwrap();
        // …and refused for a different one, which would let one machine redeem as two.
        assert!(matches!(
            registry.enrol("node-b", node.public()),
            Err(SecretError::KeyAlreadyEnrolled { .. })
        ));
    }

    #[test]
    fn revoking_an_enrolment_stops_the_node_resolving() {
        let registry = NodeRegistry::new();
        let node = NodeIdentity::generate();
        registry.enrol("node-a", node.public()).unwrap();
        assert!(registry.revoke("node-a"));
        assert!(!registry.revoke("node-a"), "revoking twice is a no-op, not an error");
        assert!(matches!(
            registry.verify(&signed(&node, 1_000), 1_000),
            Err(SecretError::UnenrolledNode(_))
        ));
    }

    #[test]
    fn the_signing_key_never_appears_in_debug_output() {
        let node = NodeIdentity::generate();
        let rendered = format!("{node:?}");
        assert!(rendered.contains(&node.public().to_string()), "the public half is the node's name");
        assert!(!rendered.contains("signing"), "and the private half is not in there at all");
    }

    #[test]
    fn the_signed_payload_is_injective_across_field_boundaries() {
        // Same reasoning as `associated_data`'s own test, checked at this layer because a collision
        // here would let a node move a character between a job id and a secret name and reuse a
        // signature for a request it never made.
        let t = token();
        let key = NodeIdentity::generate().public();
        let n = [0u8; NONCE_LEN];
        assert_ne!(
            signing_payload(&t, "job", &["AB".into(), "C".into()], &n, 1, &key),
            signing_payload(&t, "job", &["A".into(), "BC".into()], &n, 1, &key)
        );
        assert_ne!(
            signing_payload(&t, "jobA", &["B".into()], &n, 1, &key),
            signing_payload(&t, "job", &["AB".into()], &n, 1, &key)
        );
    }
}
