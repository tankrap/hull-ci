//! Where ciphertext lives.
//!
//! D§7.4 puts the sealed records in the control-plane DB. This crate does no I/O (see the crate
//! doc), so persistence is a trait the control plane implements over Postgres; the in-memory version
//! below is what the tests and a single-process dev stack use.
//!
//! The trait traffics only in [`SealedSecret`], never plaintext. That is deliberate and worth
//! keeping: a storage backend added later — a cache, a replica, an export job — cannot accidentally
//! be handed a decrypted value, because there is no method that could give it one.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::seal::SealedSecret;
use crate::SecretError;

/// Persistence for sealed secrets, keyed by `(tenant, name)`.
pub trait SealedStore: Send + Sync + std::fmt::Debug {
    /// Insert or replace. Replacing is how a rotated *value* is written (distinct from a rotated
    /// KEK, which only re-wraps).
    fn put(&self, sealed: SealedSecret) -> Result<(), SecretError>;

    fn get(&self, tenant: &str, name: &str) -> Result<Option<SealedSecret>, SecretError>;

    /// Returns whether a record was removed.
    fn delete(&self, tenant: &str, name: &str) -> Result<bool, SecretError>;

    /// Every sealed record for a tenant. Used by the rotation sweep, which needs to re-wrap all of
    /// them, and by the "which names exist" query behind capability minting.
    fn list(&self, tenant: &str) -> Result<Vec<SealedSecret>, SecretError>;

    /// Drop every record for a tenant, returning how many. **Hygiene, not the security control** —
    /// crypto-shredding the KEK is what makes the data unrecoverable; this just reclaims the rows.
    fn delete_tenant(&self, tenant: &str) -> Result<usize, SecretError>;
}

/// In-memory store for tests and the single-process dev stack.
///
/// A `BTreeMap` rather than a `HashMap` so [`SealedStore::list`] has a stable order — a rotation
/// sweep that reports "re-wrapped 4 of 7" is much easier to reason about when reruns agree on which
/// four.
#[derive(Debug, Default)]
pub struct MemorySealedStore {
    rows: Mutex<BTreeMap<(String, String), SealedSecret>>,
}

impl MemorySealedStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.rows.lock().expect("store poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl SealedStore for MemorySealedStore {
    fn put(&self, sealed: SealedSecret) -> Result<(), SecretError> {
        let mut rows = self.rows.lock().expect("store poisoned");
        rows.insert((sealed.tenant.clone(), sealed.name.clone()), sealed);
        Ok(())
    }

    fn get(&self, tenant: &str, name: &str) -> Result<Option<SealedSecret>, SecretError> {
        let rows = self.rows.lock().expect("store poisoned");
        Ok(rows.get(&(tenant.to_string(), name.to_string())).cloned())
    }

    fn delete(&self, tenant: &str, name: &str) -> Result<bool, SecretError> {
        let mut rows = self.rows.lock().expect("store poisoned");
        Ok(rows.remove(&(tenant.to_string(), name.to_string())).is_some())
    }

    fn list(&self, tenant: &str) -> Result<Vec<SealedSecret>, SecretError> {
        let rows = self.rows.lock().expect("store poisoned");
        Ok(rows.iter().filter(|((t, _), _)| t == tenant).map(|(_, s)| s.clone()).collect())
    }

    fn delete_tenant(&self, tenant: &str) -> Result<usize, SecretError> {
        let mut rows = self.rows.lock().expect("store poisoned");
        let before = rows.len();
        rows.retain(|(t, _), _| t != tenant);
        Ok(before - rows.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KekVersion;

    fn row(tenant: &str, name: &str) -> SealedSecret {
        SealedSecret {
            tenant: tenant.into(),
            name: name.into(),
            kek_version: KekVersion(1),
            wrapped_dek: vec![1, 2, 3],
            ciphertext: vec![4, 5, 6],
        }
    }

    #[test]
    fn rows_are_scoped_to_their_tenant() {
        let s = MemorySealedStore::new();
        s.put(row("acme", "T")).unwrap();
        s.put(row("globex", "T")).unwrap();
        // Same name, different tenants: two independent rows. A store that collapsed them would be
        // a cross-tenant leak before any crypto was involved.
        assert_eq!(s.list("acme").unwrap().len(), 1);
        assert_eq!(s.get("globex", "T").unwrap().unwrap().tenant, "globex");
        assert_eq!(s.delete_tenant("acme").unwrap(), 1);
        assert!(s.get("acme", "T").unwrap().is_none());
        assert!(s.get("globex", "T").unwrap().is_some());
    }

    #[test]
    fn delete_reports_whether_anything_was_there() {
        let s = MemorySealedStore::new();
        s.put(row("acme", "T")).unwrap();
        assert!(s.delete("acme", "T").unwrap());
        assert!(!s.delete("acme", "T").unwrap());
        assert!(s.is_empty());
    }
}
