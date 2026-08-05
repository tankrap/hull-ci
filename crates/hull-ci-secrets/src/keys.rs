//! Key custody: per-tenant KEKs, versioned, behind a trait a KMS can implement.
//!
//! D§7.4: "Each secret value is sealed with a fresh **DEK**; the DEK is wrapped by that **tenant's
//! KEK**; the KEK's root lives in a KMS/HSM (AWS KMS, GCP Cloud KMS, or Vault transit) and **never
//! leaves it**." That last clause is why [`KeyManager`] is a trait and not a struct holding key
//! bytes: `wrap_dek`/`unwrap_dek` are shaped exactly like a KMS `Encrypt`/`Decrypt` round trip
//! (including an AAD parameter, which AWS KMS calls the *encryption context*), so a production
//! implementation is a network call and this crate never holds the root at all.
//!
//! **One KEK per tenant is the unit of tenancy**, and it buys two things nothing else does:
//!
//! * **Crypto-shredding.** [`KeyManager::shred`] is one operation that makes every secret the tenant
//!   ever stored permanently unrecoverable, without touching a single ciphertext row. Deleting rows
//!   is a promise about a database; deleting the key is a fact about mathematics.
//! * **Blast-radius isolation.** A compromise of one tenant's key reaches exactly that tenant's
//!   secrets — the "secret bleed" row of the D§1 threat table.
//!
//! **Rotation is versioning, not re-encryption** (D§7.4, after [AWS KMS key rotation][rot]): a new
//! KEK version wraps new DEKs while old versions still unwrap existing ones. Re-keying therefore
//! re-wraps a handful of 32-byte DEKs and never re-encrypts the secrets themselves, so rotating a
//! tenant with a million secrets costs a million tiny AEAD operations instead of a bulk re-encrypt.
//!
//! [rot]: https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html

use std::collections::HashMap;
use std::sync::Mutex;

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::SecretError;

/// Which version of a tenant's KEK wrapped a given DEK.
///
/// Monotonic per tenant and **never reused, even across a shred**: a re-enrolled tenant's first KEK
/// is version *n+1*, so a surviving ciphertext row from before the shred can never be pointed at
/// fresh key material by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct KekVersion(pub u32);

impl std::fmt::Display for KekVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// The length of a data encryption key. 256 bits, as XChaCha20-Poly1305 requires.
pub const DEK_LEN: usize = 32;

/// A data encryption key: one per secret value, generated fresh, never persisted in the clear.
///
/// `ZeroizeOnDrop` matters more here than anywhere else in the crate. A DEK lives for microseconds
/// on a happy path, but a `Vec` that grew and reallocated leaves copies behind, so the key type is
/// a fixed-size array that is wiped in place.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Dek([u8; DEK_LEN]);

impl Dek {
    /// A fresh DEK from the operating system CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; DEK_LEN];
        OsRng.fill_bytes(&mut bytes);
        Dek(bytes)
    }

    /// Reconstruct from raw bytes. Only an unwrap path should call this.
    pub fn from_bytes(bytes: [u8; DEK_LEN]) -> Self {
        Dek(bytes)
    }

    pub fn expose(&self) -> &[u8; DEK_LEN] {
        &self.0
    }
}

/// Never print key material, not even truncated. A "first 4 bytes" preview in a log is a real
/// reduction in the search space and buys nothing an operator actually needs.
impl std::fmt::Debug for Dek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Dek(<redacted>)")
    }
}

/// Custody of tenant KEKs. Implemented in production by a KMS/HSM client.
///
/// The trait deliberately has no "give me the KEK" method. Every operation that needs the root
/// happens *inside* the implementation, which is what lets the root stay in a KMS: this crate can
/// seal and open secrets while being structurally incapable of exfiltrating a tenant's key.
///
/// `aad` is passed through to the AEAD (or to a KMS encryption context) so a wrapped DEK is bound to
/// the tenant, secret name and KEK version it was created for — see [`crate::associated_data`].
pub trait KeyManager: Send + Sync + std::fmt::Debug {
    /// The version new DEKs should be wrapped under. Errors if the tenant has no key material.
    fn current_version(&self, tenant: &str) -> Result<KekVersion, SecretError>;

    /// Wrap a DEK under a specific version of the tenant's KEK, returning an opaque blob.
    ///
    /// Opaque is the point: the format is the implementation's business (a KMS returns its own
    /// envelope), so nothing outside this trait may parse it.
    fn wrap_dek(&self, tenant: &str, version: KekVersion, dek: &Dek, aad: &[u8]) -> Result<Vec<u8>, SecretError>;

    /// Unwrap a DEK previously produced by [`KeyManager::wrap_dek`].
    fn unwrap_dek(&self, tenant: &str, version: KekVersion, wrapped: &[u8], aad: &[u8]) -> Result<Dek, SecretError>;

    /// Create the tenant's first KEK. Idempotent-ish: returns the current version if one exists.
    fn provision_tenant(&self, tenant: &str) -> Result<KekVersion, SecretError>;

    /// Add a new KEK version. Old versions remain usable for unwrapping (D§7.4).
    fn rotate(&self, tenant: &str) -> Result<KekVersion, SecretError>;

    /// **Crypto-shred**: destroy every version of this tenant's KEK. Irreversible by construction —
    /// after this, every DEK the tenant ever had is unrecoverable and so is every secret.
    fn shred(&self, tenant: &str) -> Result<(), SecretError>;
}

// ── Development implementation ───────────────────────────────────────────────────────────────────

/// Per-tenant key material, wiped when the entry is dropped or shredded.
#[derive(Zeroize, ZeroizeOnDrop)]
struct TenantKeys {
    /// version number → 32-byte KEK.
    versions: Vec<(u32, [u8; DEK_LEN])>,
    /// Next version to hand out. Survives a shred so versions are never reused.
    #[zeroize(skip)]
    next_version: u32,
}

/// **DEVELOPMENT AND TEST ONLY — this holds raw KEK bytes in this process's memory.**
///
/// Everything a real deployment gets from a KMS, this gives up: the root key is in the same address
/// space as the code that runs untrusted tenants' pipelines through the control plane, a core dump
/// contains it, and there is no audit log of a single unwrap. It exists so the broker's *logic* can
/// be tested end to end without a cloud dependency, and so a single-operator local stack can run.
///
/// Production wires a `KmsKeyManager` (AWS KMS / GCP KMS / Vault transit) into the same trait. The
/// broker cannot tell the difference, which is the entire reason the seam is a trait.
#[derive(Debug, Default)]
pub struct DevKeyManager {
    tenants: Mutex<HashMap<String, TenantKeys>>,
}

impl std::fmt::Debug for TenantKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantKeys")
            .field("versions", &self.versions.iter().map(|(v, _)| v).collect::<Vec<_>>())
            .field("next_version", &self.next_version)
            .finish()
    }
}

impl DevKeyManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run `f` with the KEK bytes for `(tenant, version)`, or fail if there is no such key.
    ///
    /// The closure shape keeps the key borrowed under the lock: it is never copied out, so there is
    /// no second live copy to forget to wipe.
    fn with_kek<T>(
        &self,
        tenant: &str,
        version: KekVersion,
        f: impl FnOnce(&[u8; DEK_LEN]) -> Result<T, SecretError>,
    ) -> Result<T, SecretError> {
        let guard = self.tenants.lock().expect("key map poisoned");
        let keys = guard.get(tenant).ok_or_else(|| SecretError::NoTenantKey(tenant.to_string()))?;
        let kek = keys
            .versions
            .iter()
            .find(|(v, _)| *v == version.0)
            .map(|(_, k)| k)
            .ok_or(SecretError::NoKekVersion { tenant: tenant.to_string(), version: version.0 })?;
        f(kek)
    }
}

impl KeyManager for DevKeyManager {
    fn current_version(&self, tenant: &str) -> Result<KekVersion, SecretError> {
        let guard = self.tenants.lock().expect("key map poisoned");
        guard
            .get(tenant)
            .and_then(|k| k.versions.last().map(|(v, _)| KekVersion(*v)))
            .ok_or_else(|| SecretError::NoTenantKey(tenant.to_string()))
    }

    fn wrap_dek(&self, tenant: &str, version: KekVersion, dek: &Dek, aad: &[u8]) -> Result<Vec<u8>, SecretError> {
        self.with_kek(tenant, version, |kek| aead_seal(kek, dek.expose(), aad))
    }

    fn unwrap_dek(&self, tenant: &str, version: KekVersion, wrapped: &[u8], aad: &[u8]) -> Result<Dek, SecretError> {
        self.with_kek(tenant, version, |kek| {
            let plain = aead_open(kek, wrapped, aad)?;
            let bytes: [u8; DEK_LEN] = plain.as_slice().try_into().map_err(|_| SecretError::Decrypt)?;
            Ok(Dek::from_bytes(bytes))
        })
    }

    fn provision_tenant(&self, tenant: &str) -> Result<KekVersion, SecretError> {
        let mut guard = self.tenants.lock().expect("key map poisoned");
        let entry = guard
            .entry(tenant.to_string())
            .or_insert_with(|| TenantKeys { versions: Vec::new(), next_version: 1 });
        if let Some((v, _)) = entry.versions.last() {
            return Ok(KekVersion(*v));
        }
        let version = entry.next_version;
        entry.next_version += 1;
        let mut kek = [0u8; DEK_LEN];
        OsRng.fill_bytes(&mut kek);
        entry.versions.push((version, kek));
        Ok(KekVersion(version))
    }

    fn rotate(&self, tenant: &str) -> Result<KekVersion, SecretError> {
        let mut guard = self.tenants.lock().expect("key map poisoned");
        let entry = guard.get_mut(tenant).ok_or_else(|| SecretError::NoTenantKey(tenant.to_string()))?;
        let version = entry.next_version;
        entry.next_version += 1;
        let mut kek = [0u8; DEK_LEN];
        OsRng.fill_bytes(&mut kek);
        // Appended, not replaced: old versions must keep unwrapping until every DEK is re-wrapped.
        entry.versions.push((version, kek));
        Ok(KekVersion(version))
    }

    fn shred(&self, tenant: &str) -> Result<(), SecretError> {
        let mut guard = self.tenants.lock().expect("key map poisoned");
        match guard.get_mut(tenant) {
            None => Err(SecretError::NoTenantKey(tenant.to_string())),
            Some(entry) => {
                // Wipe the bytes explicitly before dropping the entry. `Vec::clear` would leave the
                // key material sitting in the allocation until something else overwrote it.
                for (_, kek) in entry.versions.iter_mut() {
                    kek.zeroize();
                }
                entry.versions.clear();
                // `next_version` is deliberately left where it is, so a re-enrolled tenant never
                // reuses a version number a surviving ciphertext row might still reference.
                Ok(())
            }
        }
    }
}

// ── The AEAD ─────────────────────────────────────────────────────────────────────────────────────

/// Nonce length for XChaCha20-Poly1305.
pub(crate) const NONCE_LEN: usize = 24;

/// Seal `plaintext` under `key` with `aad`, returning `nonce || ciphertext || tag`.
///
/// **XChaCha20-Poly1305 with a random nonce.** The extended 192-bit nonce is the whole reason for
/// choosing the X variant over plain ChaCha20-Poly1305 or AES-GCM: with a 96-bit nonce, random
/// generation has a birthday bound that a busy multi-tenant broker could genuinely approach, and
/// nonce reuse under a shared key is catastrophic for both constructions. At 192 bits, random nonces
/// are safe essentially forever, which lets us avoid a counter — and a counter is state that has to
/// be persisted, replicated and never rolled back, which is exactly the kind of thing that fails
/// during a database restore.
///
/// The nonce is prepended rather than stored in its own column so that a ciphertext and its nonce
/// cannot be separated in transit or in a schema migration.
pub(crate) fn aead_seal(key: &[u8; DEK_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, SecretError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut out = nonce.to_vec();
    let ct = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        // The only realistic cause is an allocation failure; there is nothing useful to report and
        // nothing safe to log.
        .map_err(|_| SecretError::Decrypt)?;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a blob produced by [`aead_seal`]. Any failure — wrong key, wrong AAD, truncation, a flipped
/// bit — is one indistinguishable error.
pub(crate) fn aead_open(key: &[u8; DEK_LEN], blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, SecretError> {
    if blob.len() < NONCE_LEN {
        return Err(SecretError::Decrypt);
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| SecretError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::associated_data;

    fn aad() -> Vec<u8> {
        associated_data("test", &["tenant", "NAME"])
    }

    #[test]
    fn wrap_and_unwrap_round_trip() {
        let km = DevKeyManager::new();
        let v = km.provision_tenant("acme").unwrap();
        let dek = Dek::generate();
        let wrapped = km.wrap_dek("acme", v, &dek, &aad()).unwrap();
        let back = km.unwrap_dek("acme", v, &wrapped, &aad()).unwrap();
        assert_eq!(back.expose(), dek.expose());
    }

    #[test]
    fn another_tenants_kek_cannot_unwrap() {
        // Blast-radius isolation (D§1, secret-bleed row): tenant keys are independent by construction.
        let km = DevKeyManager::new();
        let va = km.provision_tenant("acme").unwrap();
        let vb = km.provision_tenant("globex").unwrap();
        let dek = Dek::generate();
        let wrapped = km.wrap_dek("acme", va, &dek, &aad()).unwrap();
        assert_eq!(km.unwrap_dek("globex", vb, &wrapped, &aad()).unwrap_err(), SecretError::Decrypt);
    }

    #[test]
    fn wrapped_dek_is_bound_to_its_associated_data() {
        let km = DevKeyManager::new();
        let v = km.provision_tenant("acme").unwrap();
        let dek = Dek::generate();
        let wrapped = km.wrap_dek("acme", v, &dek, &aad()).unwrap();
        let other = associated_data("test", &["tenant", "OTHER_NAME"]);
        assert_eq!(km.unwrap_dek("acme", v, &wrapped, &other).unwrap_err(), SecretError::Decrypt);
    }

    #[test]
    fn every_seal_uses_a_fresh_nonce() {
        // Two seals of identical plaintext under one key must not produce identical bytes; if they
        // do, the nonce is being reused and the keystream with it.
        let key = [7u8; DEK_LEN];
        let a = aead_seal(&key, b"same", &aad()).unwrap();
        let b = aead_seal(&key, b"same", &aad()).unwrap();
        assert_ne!(a, b, "nonce reuse under a shared key is catastrophic for XChaCha20-Poly1305");
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
    }

    #[test]
    fn truncated_or_tampered_ciphertext_is_refused() {
        let key = [7u8; DEK_LEN];
        let sealed = aead_seal(&key, b"value", &aad()).unwrap();
        assert_eq!(aead_open(&key, &sealed[..NONCE_LEN - 1], &aad()), Err(SecretError::Decrypt));
        let mut flipped = sealed.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x01;
        assert_eq!(aead_open(&key, &flipped, &aad()), Err(SecretError::Decrypt));
        // And the honest case still works, so the test above is not passing for a boring reason.
        assert_eq!(aead_open(&key, &sealed, &aad()).unwrap(), b"value");
    }

    #[test]
    fn rotation_adds_a_version_without_invalidating_the_old_one() {
        let km = DevKeyManager::new();
        let v1 = km.provision_tenant("acme").unwrap();
        let dek = Dek::generate();
        let wrapped_v1 = km.wrap_dek("acme", v1, &dek, &aad()).unwrap();

        let v2 = km.rotate("acme").unwrap();
        assert_ne!(v1, v2);
        assert_eq!(km.current_version("acme").unwrap(), v2, "new DEKs wrap under the new version");
        // D§7.4: "a new KEK version wraps new DEKs while old versions still unwrap existing ones."
        assert!(km.unwrap_dek("acme", v1, &wrapped_v1, &aad()).is_ok());
    }

    #[test]
    fn shred_destroys_every_version_and_never_reissues_a_version_number() {
        let km = DevKeyManager::new();
        let v1 = km.provision_tenant("acme").unwrap();
        km.rotate("acme").unwrap();
        let dek = Dek::generate();
        let wrapped = km.wrap_dek("acme", v1, &dek, &aad()).unwrap();

        km.shred("acme").unwrap();
        assert_eq!(km.current_version("acme"), Err(SecretError::NoTenantKey("acme".into())));

        // Re-enrolling the tenant must not resurrect the old ciphertext: the new key is different
        // material *and* carries a version number the old record never referenced.
        let v_new = km.provision_tenant("acme").unwrap();
        assert!(v_new.0 > v1.0 + 1, "version numbers must not be reused after a shred");
        assert_eq!(
            km.unwrap_dek("acme", v1, &wrapped, &aad()).unwrap_err(),
            SecretError::NoKekVersion { tenant: "acme".into(), version: v1.0 }
        );
    }

    #[test]
    fn key_material_never_appears_in_debug_output() {
        let dek = Dek::from_bytes([0xAB; DEK_LEN]);
        assert_eq!(format!("{dek:?}"), "Dek(<redacted>)");
        let km = DevKeyManager::new();
        km.provision_tenant("acme").unwrap();
        let rendered = format!("{km:?}");
        assert!(rendered.contains("versions"), "the shape is fine to log");
        assert!(!rendered.contains("171"), "but the bytes are not");
    }
}
