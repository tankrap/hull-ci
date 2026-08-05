//! Sealing and opening a single secret value.
//!
//! D§7.4: "Ciphertext lives in the control-plane DB; **plaintext never touches Hull's request path
//! and never lands on a node's disk.**" This module is where that sentence is made true — it is the
//! only place a plaintext secret exists as bytes, and the only type it can leave in is
//! [`SecretBytes`], which wipes itself on drop and refuses to render in `Debug`.
//!
//! **The AAD is the load-bearing part.** A [`SealedSecret`] carries its tenant and name as plain
//! fields so a database row is legible, but those fields are *not* what the AEAD authenticates
//! against — [`Vault::open`] builds the associated data from the context the **caller** asks for.
//! The difference is the whole defence: if the record's own labels supplied the AAD, then moving
//! tenant A's ciphertext into tenant B's row (or renaming `STAGING_TOKEN` to `PROD_TOKEN`) would
//! decrypt cleanly, because the attacker edits the labels and the AAD follows. Binding to the
//! caller's expectation instead means a relabelled record simply fails to authenticate.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::keys::{aead_open, aead_seal, Dek, KekVersion, KeyManager};
use crate::{associated_data, SecretError};

/// Domain separator for the value ciphertext.
const DOMAIN_VALUE: &str = "hull-ci/secret-value/v1";
/// Domain separator for the wrapped DEK. Distinct from the value's, so the two ciphertext families
/// can never be swapped for one another even under a key-reuse mistake.
const DOMAIN_WRAP: &str = "hull-ci/dek-wrap/v1";

/// A secret's plaintext, in memory, briefly.
///
/// Wiped on drop and redacted in `Debug`, `Display` is deliberately not implemented: every path that
/// turns a secret into a string should be an explicit [`SecretBytes::expose`] call that a reviewer
/// can grep for, not an accidental `format!("{}", …)` inside a log line. `PartialEq` is likewise
/// absent — a derived equality is byte-at-a-time and early-exiting, which is a timing oracle on the
/// one type in this crate that must not have one.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretBytes(bytes)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// The value as a `str`, when it is valid UTF-8 (which an environment variable must be).
    pub fn expose_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Not even the length: value lengths distinguish a 40-char GitHub PAT from a 4-char PIN, and
        // an operator reading a log never needs to know.
        f.write_str("SecretBytes(<redacted>)")
    }
}

/// A secret at rest. Safe to persist, safe to log, useless without the tenant's KEK.
///
/// `tenant` and `name` are stored so an operator can read the table and so the broker can index it —
/// they are labels, **not** authenticators. See the module doc for why that distinction matters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSecret {
    pub tenant: String,
    pub name: String,
    /// Which KEK version wrapped [`SealedSecret::wrapped_dek`]. Rotation rewrites this field and
    /// that field only (plus the wrap); the value ciphertext below is never touched.
    pub kek_version: KekVersion,
    /// Opaque blob from [`KeyManager::wrap_dek`] — never parsed outside the key manager.
    #[serde(with = "hex_bytes")]
    pub wrapped_dek: Vec<u8>,
    /// `nonce || ciphertext || tag` for the value itself.
    #[serde(with = "hex_bytes")]
    pub ciphertext: Vec<u8>,
}

/// Hex rather than a JSON byte array: a `bytea`-shaped column in a DB is far easier to read, diff and
/// copy in an incident than 300 comma-separated integers, and the encoding is unambiguous.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Seals and opens values. Holds no key material of its own — that is the [`KeyManager`]'s job.
#[derive(Debug, Clone)]
pub struct Vault {
    keys: Arc<dyn KeyManager>,
}

impl Vault {
    pub fn new(keys: Arc<dyn KeyManager>) -> Self {
        Vault { keys }
    }

    pub fn keys(&self) -> &Arc<dyn KeyManager> {
        &self.keys
    }

    /// Seal one value for `(tenant, name)` under the tenant's current KEK version.
    ///
    /// Envelope encryption in three lines: fresh DEK, value sealed under the DEK, DEK wrapped by the
    /// KEK. The plaintext argument is borrowed and never copied anywhere that outlives the call.
    pub fn seal(&self, tenant: &str, name: &str, plaintext: &[u8]) -> Result<SealedSecret, SecretError> {
        if plaintext.is_empty() {
            return Err(SecretError::EmptyValue);
        }
        let version = self.keys.current_version(tenant)?;
        let dek = Dek::generate();
        let ciphertext = aead_seal(dek.expose(), plaintext, &value_aad(tenant, name))?;
        let wrapped_dek = self.keys.wrap_dek(tenant, version, &dek, &wrap_aad(tenant, name, version))?;
        Ok(SealedSecret { tenant: tenant.to_string(), name: name.to_string(), kek_version: version, wrapped_dek, ciphertext })
    }

    /// Open a sealed record **as** `(expect_tenant, expect_name)`.
    ///
    /// The caller states what it believes it is holding and the AEAD adjudicates. A record whose
    /// labels disagree is rejected before any key is touched (a caller bug, worth a clear message);
    /// a record whose labels were *edited* to agree still fails, because the AAD it was sealed under
    /// no longer matches — that is the cross-tenant and rename defence.
    pub fn open(&self, expect_tenant: &str, expect_name: &str, sealed: &SealedSecret) -> Result<SecretBytes, SecretError> {
        if sealed.tenant != expect_tenant || sealed.name != expect_name {
            return Err(SecretError::ContextMismatch {
                expected: format!("{expect_tenant}/{expect_name}"),
                found: format!("{}/{}", sealed.tenant, sealed.name),
            });
        }
        let dek = self.keys.unwrap_dek(
            expect_tenant,
            sealed.kek_version,
            &sealed.wrapped_dek,
            &wrap_aad(expect_tenant, expect_name, sealed.kek_version),
        )?;
        let plain = aead_open(dek.expose(), &sealed.ciphertext, &value_aad(expect_tenant, expect_name))?;
        Ok(SecretBytes::new(plain))
    }

    /// Re-wrap a record's DEK under the tenant's current KEK version (D§7.4 rotation).
    ///
    /// The value ciphertext is copied across untouched — that is the entire economy of envelope
    /// encryption: rotating a tenant costs one tiny AEAD operation per secret, not a bulk re-encrypt
    /// of every value. Returns `None` when the record is already current, so a rotation sweep can
    /// skip the write.
    pub fn rewrap(&self, sealed: &SealedSecret) -> Result<Option<SealedSecret>, SecretError> {
        let current = self.keys.current_version(&sealed.tenant)?;
        if current == sealed.kek_version {
            return Ok(None);
        }
        let dek = self.keys.unwrap_dek(
            &sealed.tenant,
            sealed.kek_version,
            &sealed.wrapped_dek,
            &wrap_aad(&sealed.tenant, &sealed.name, sealed.kek_version),
        )?;
        let wrapped_dek = self.keys.wrap_dek(&sealed.tenant, current, &dek, &wrap_aad(&sealed.tenant, &sealed.name, current))?;
        Ok(Some(SealedSecret { kek_version: current, wrapped_dek, ..sealed.clone() }))
    }
}

/// Context bound into the value ciphertext: tenant and name.
fn value_aad(tenant: &str, name: &str) -> Vec<u8> {
    associated_data(DOMAIN_VALUE, &[tenant, name])
}

/// Context bound into the wrapped DEK: tenant, name, and the KEK version that did the wrapping.
///
/// Including the version stops a downgrade shuffle — a wrapped DEK cannot be re-labelled as having
/// come from a different (perhaps compromised, perhaps deliberately weak) KEK version.
fn wrap_aad(tenant: &str, name: &str, version: KekVersion) -> Vec<u8> {
    associated_data(DOMAIN_WRAP, &[tenant, name, &version.0.to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DevKeyManager;

    fn vault() -> (Vault, Arc<DevKeyManager>) {
        let km = Arc::new(DevKeyManager::new());
        (Vault::new(km.clone()), km)
    }

    #[test]
    fn round_trip() {
        let (v, km) = vault();
        km.provision_tenant("acme").unwrap();
        let sealed = v.seal("acme", "NPM_TOKEN", b"npm_s3cr3t").unwrap();
        assert!(!sealed.ciphertext.windows(5).any(|w| w == b"npm_s"), "plaintext must not survive in the record");
        let opened = v.open("acme", "NPM_TOKEN", &sealed).unwrap();
        assert_eq!(opened.expose(), b"npm_s3cr3t");
    }

    #[test]
    fn cross_tenant_aad_confusion_is_refused() {
        // The attack: tenant A's ciphertext row is copied into tenant B's table under the same name.
        // Relabelling it is not enough — the AAD it was sealed under says `acme`, and B's open call
        // says `globex`.
        let (v, km) = vault();
        km.provision_tenant("acme").unwrap();
        km.provision_tenant("globex").unwrap();
        let sealed = v.seal("acme", "NPM_TOKEN", b"acme-only").unwrap();

        let relabelled = SealedSecret { tenant: "globex".into(), ..sealed.clone() };
        assert_eq!(v.open("globex", "NPM_TOKEN", &relabelled).unwrap_err(), SecretError::Decrypt);

        // And without relabelling, the mismatch is caught earlier still.
        assert!(matches!(v.open("globex", "NPM_TOKEN", &sealed), Err(SecretError::ContextMismatch { .. })));
    }

    #[test]
    fn renaming_a_secret_invalidates_its_ciphertext() {
        // A `STAGING_TOKEN` promoted to `PROD_TOKEN` by an UPDATE statement must not silently start
        // being handed out under the new name.
        let (v, km) = vault();
        km.provision_tenant("acme").unwrap();
        let sealed = v.seal("acme", "STAGING_TOKEN", b"staging-value").unwrap();
        let renamed = SealedSecret { name: "PROD_TOKEN".into(), ..sealed };
        assert_eq!(v.open("acme", "PROD_TOKEN", &renamed).unwrap_err(), SecretError::Decrypt);
    }

    #[test]
    fn a_wrapped_dek_cannot_be_swapped_between_records() {
        // Both records belong to the same tenant and the same KEK version; only the name differs. The
        // wrap AAD is what keeps their DEKs from being interchangeable.
        let (v, km) = vault();
        km.provision_tenant("acme").unwrap();
        let a = v.seal("acme", "A_TOKEN", b"value-a").unwrap();
        let b = v.seal("acme", "B_TOKEN", b"value-b").unwrap();
        let frankenstein = SealedSecret { wrapped_dek: b.wrapped_dek.clone(), ..a };
        assert_eq!(v.open("acme", "A_TOKEN", &frankenstein).unwrap_err(), SecretError::Decrypt);
    }

    #[test]
    fn empty_values_are_refused() {
        let (v, km) = vault();
        km.provision_tenant("acme").unwrap();
        assert_eq!(v.seal("acme", "X", b""), Err(SecretError::EmptyValue));
    }

    #[test]
    fn rewrap_moves_the_dek_and_leaves_the_value_ciphertext_alone() {
        let (v, km) = vault();
        km.provision_tenant("acme").unwrap();
        let old = v.seal("acme", "NPM_TOKEN", b"unchanged").unwrap();
        assert!(v.rewrap(&old).unwrap().is_none(), "already current");

        let v2 = km.rotate("acme").unwrap();
        let new = v.rewrap(&old).unwrap().expect("a version behind");
        assert_eq!(new.kek_version, v2);
        assert_eq!(new.ciphertext, old.ciphertext, "rotation must never re-encrypt the value itself");
        assert_ne!(new.wrapped_dek, old.wrapped_dek);
        assert_eq!(v.open("acme", "NPM_TOKEN", &new).unwrap().expose(), b"unchanged");
    }

    #[test]
    fn the_record_serializes_to_a_legible_hex_shape() {
        let (v, km) = vault();
        km.provision_tenant("acme").unwrap();
        let sealed = v.seal("acme", "NPM_TOKEN", b"value").unwrap();
        let json = serde_json::to_value(&sealed).unwrap();
        assert!(json["ciphertext"].as_str().unwrap().chars().all(|c| c.is_ascii_hexdigit()));
        let back: SealedSecret = serde_json::from_value(json).unwrap();
        assert_eq!(back, sealed);
    }

    #[test]
    fn plaintext_is_redacted_in_debug() {
        let s = SecretBytes::new(b"hunter2".to_vec());
        assert_eq!(format!("{s:?}"), "SecretBytes(<redacted>)");
    }
}
