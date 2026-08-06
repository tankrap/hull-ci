//! A [`KeyManager`] whose KEK roots live in Infisical KMS and never enter this process.
//!
//! D§7.4 says "the KEK's root lives in a KMS/HSM … and **never leaves it**". Until this module the
//! only shipping implementation was [`DevKeyManager`](crate::keys::DevKeyManager), which holds raw
//! KEK bytes in the control plane's address space — so the design described a *seam* as though it
//! were a product. This is the product: every wrap and unwrap is an HTTP round trip to Infisical's
//! `encrypt`/`decrypt` endpoints, key material is created and rotated inside Infisical, and this
//! crate is structurally incapable of holding a tenant KEK because it is never sent one.
//!
//! The Infisical surface used here (see <https://infisical.com/docs/api-reference/>):
//!
//! | Operation | Endpoint |
//! |---|---|
//! | wrap a DEK | `POST /api/v1/kms/keys/{keyId}/encrypt` |
//! | unwrap a DEK | `POST /api/v1/kms/keys/{keyId}/decrypt` |
//! | find a tenant's key, read its version | `GET /api/v1/kms/keys/key-name/{keyName}?projectId=…` |
//! | provision a tenant | `POST /api/v1/kms/keys` |
//! | rotate | `POST /api/v1/kms/keys/{keyId}/rotate` |
//! | crypto-shred | `DELETE /api/v1/kms/keys/{keyId}` |
//! | machine-identity login | `POST /api/v1/auth/universal-auth/login` |
//!
//! # The one real gap, and the construction that closes it
//!
//! **Infisical's encrypt/decrypt take no AAD.** AWS KMS calls it an encryption context, GCP calls it
//! additional authenticated data; Infisical's request body is `{"plaintext": …}` and nothing else.
//! That matters because the AAD is the load-bearing part of this crate's sealing story: [`seal`]
//! binds a wrapped DEK to `(domain, tenant, name, kek_version)`, and that binding is what stops a
//! wrapped DEK being moved between tenants, swapped between two secrets of one tenant, or relabelled
//! as having come from a different KEK version.
//!
//! [`seal`]: crate::seal
//!
//! Infisical only ever wraps the **DEK** — the secret *value* is sealed by our own
//! XChaCha20-Poly1305, whose AAD we fully control and which is unaffected by any of this. So the
//! binding is restored by **carrying the context inside the wrapped plaintext**:
//!
//! ```text
//! plaintext handed to Infisical =
//!     frame("hull-ci/infisical-dek-envelope/v1")   ← domain separator
//!     frame(tenant)                                ← from the trait argument
//!     frame(kek_version, decimal)                  ← from the trait argument
//!     frame(caller AAD)                            ← verbatim: (domain, tenant, name, version)
//!     dek                                          ← the 32 bytes, last, unframed
//! ```
//!
//! …where `frame(x)` is `be_u32(x.len()) || x`, so the encoding is injective for the same reason
//! `crate::associated_data` is. On unwrap the recovered prefix is compared against what the
//! **caller** expects, field by field, **before the DEK is returned**; any disagreement is
//! [`SecretError::Decrypt`], indistinguishable from a corrupt blob, exactly as elsewhere in the crate.
//!
//! **What this preserves.** Infisical's own AEAD authenticates the whole blob, so the prefix cannot
//! be edited by anyone who does not hold the tenant's KEK — which is nobody, including us. The prefix
//! check therefore gives back the full context binding: a blob wrapped for `(acme, NPM_TOKEN, v3)`
//! is refused when opened as `(globex, …)`, as `(acme, PROD_TOKEN, v3)`, or as `(acme, NPM_TOKEN,
//! v2)`. Cross-tenant movement is refused twice over, because a different tenant also resolves to a
//! different Infisical key id, and that key cannot decrypt this ciphertext at all.
//!
//! **What it does not preserve.** Three things, stated plainly because each is a real difference from
//! a KMS with a native encryption context:
//!
//! 1. **The check is ours, not the KMS's.** With AWS KMS the *service* refuses a mismatched context,
//!    so a bug in our client cannot bypass it. Here Infisical returns the plaintext and this process
//!    decides. The DEK is discarded on mismatch and never reaches the caller, but the boundary that
//!    enforces the binding has moved from the KMS into [`InfisicalKeyManager::unwrap_dek`].
//! 2. **It is not an audit-log control.** A wrong-context decrypt attempt is a *successful* decrypt in
//!    Infisical's audit log; only our refusal distinguishes it. An operator correlating a KMS audit
//!    trail must know that "decrypt succeeded" there does not mean a DEK was released here.
//! 3. **The recorded `kek_version` is our claim, not Infisical's.** Infisical always encrypts under
//!    the key's *latest* material and resolves the right version itself on decrypt; there is no way to
//!    ask it to encrypt under version *n-1*, and no version field on the ciphertext we can read back.
//!    So the version in the envelope is the version [`KeyManager::wrap_dek`] was asked for — which
//!    this implementation refuses unless it equals the current version at the moment of the call. The
//!    binding it buys is "this blob cannot be relabelled as another version", which is the downgrade
//!    defence. It is *not* proof of which key material actually wrapped it.
//!
//! # Fail closed
//!
//! Every path in this module ends in either a value or [`SecretError`]. There is no fallback key, no
//! cached plaintext, no "degrade to the dev manager" — an unreachable or slow Infisical means secret
//! delivery **refuses**, which is the only safe direction for a component whose job is to hand out
//! credentials. Timeouts are configured (default [`DEFAULT_TIMEOUT_MS`]) rather than left to the OS,
//! because "hangs forever" is how a fail-closed system becomes a fail-*open* one in practice: an
//! operator under pressure disables the check that hangs.
//!
//! # What is cached, and what is deliberately not
//!
//! * **Unwrapped DEKs: never.** Not for a job, not for a request, not for a microsecond longer than
//!   the [`Dek`] value the caller drops. An audit already found a credential outliving its revocation
//!   elsewhere in the stack; a DEK cache here would widen exactly that.
//! * **Tenant → Infisical key id: yes**, in memory. It is a UUID, not key material, and it saves a
//!   lookup per operation. Evicted on [`KeyManager::shred`] so a shredded tenant cannot keep hitting
//!   a deleted key id.
//! * **KEK version: never.** [`KeyManager::current_version`] and [`KeyManager::wrap_dek`] read it
//!   fresh, so a rotation that lands between two calls is observed rather than papered over.
//! * **The machine-identity access token: yes**, until shortly before it expires. It is a credential,
//!   so it lives in [`Redacted`], which zeroizes on drop and refuses to render in `Debug`.
//!
//! # Credentials never appear in an error, a log, or a `Debug`
//!
//! Errors from this module carry the operation and the HTTP status and **nothing from the response
//! body**. That is a deliberate loss of debuggability: Infisical's error bodies are genuinely useful,
//! but a body is attacker- and misconfiguration-influenced, an API that echoes an `Authorization`
//! header into its error message is a real thing that happens, and scrubbing a token out of a string
//! is exact-substring matching — the same backstop-not-a-control that [`crate::mask`] is careful to
//! say is not a security boundary. Not carrying the body is a boundary.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::keys::{Dek, KekVersion, KeyManager, DEK_LEN};
use crate::SecretError;

/// Domain separator for the plaintext envelope handed to Infisical.
///
/// Versioned in the string so a future envelope layout is a different domain rather than a silent
/// reinterpretation of existing blobs.
const ENVELOPE_DOMAIN: &str = "hull-ci/infisical-dek-envelope/v1";

/// Default per-request timeout. Five seconds is long enough for a cross-region KMS call and short
/// enough that a stuck secret delivery surfaces as an error inside one job's patience.
pub const DEFAULT_TIMEOUT_MS: u64 = 5_000;

/// How long before expiry a cached access token is considered stale.
///
/// A token that expires mid-flight fails the request it was attached to; renewing a minute early
/// costs one extra login per token lifetime and removes the race.
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// The longest an Infisical key name may be (`POST /api/v1/kms/keys` caps `name` at 32 characters).
const MAX_KEY_NAME_LEN: usize = 32;

/// Hex characters of tenant digest appended to a derived key name. See [`InfisicalConfig::key_name`].
const DIGEST_CHARS: usize = 8;

// ── Credentials ──────────────────────────────────────────────────────────────────────────────────

/// A string that must not be printed. Wiped on drop, redacted in `Debug`, no `Display`.
///
/// The same shape as [`crate::SecretBytes`], and here for the same reason: the compiler, not review
/// discipline, is what keeps a bearer token out of a log line.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Redacted(String);

impl Redacted {
    pub fn new(value: impl Into<String>) -> Self {
        Redacted(value.into())
    }

    /// The only way to read it. An explicit call a reviewer can grep for.
    fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Not even the length: token lengths distinguish a service token from a machine-identity
        // access token, which tells an attacker which login path to attack.
        f.write_str("<redacted>")
    }
}

/// How this process authenticates to Infisical.
///
/// Both variants are bearer credentials in the end; they differ in lifetime, and the difference is
/// worth an operator's attention rather than an implementation detail. A static token is one secret
/// that never rotates on its own — fine for a local stack, poor for production. A machine identity
/// issues short-lived access tokens from a client id/secret pair, which is what a fleet should use.
#[derive(Clone, Debug)]
pub enum InfisicalAuth {
    /// A pre-issued token, used verbatim as `Authorization: Bearer …`.
    Token(Redacted),
    /// Universal-auth machine identity: exchange `(clientId, clientSecret)` for a short-lived access
    /// token at `POST /api/v1/auth/universal-auth/login`, and re-exchange when it nears expiry.
    MachineIdentity { client_id: String, client_secret: Redacted },
}

// ── Configuration ────────────────────────────────────────────────────────────────────────────────

/// Where Infisical is, who we are to it, and how patient we are.
///
/// `Debug` is derived: every field that could carry a credential is a [`Redacted`], so the derive is
/// safe *by construction of the field types* rather than by a hand-written impl someone must
/// remember to update when a field is added.
#[derive(Clone, Debug)]
pub struct InfisicalConfig {
    /// Base URL, no trailing slash — `https://us.infisical.com`, `https://eu.infisical.com`, or a
    /// self-hosted origin.
    pub base_url: String,
    /// The Infisical project the tenant KEKs live in.
    pub project_id: String,
    /// Prefix for derived key names. See [`InfisicalConfig::key_name`].
    pub key_name_prefix: String,
    pub auth: InfisicalAuth,
    /// Per-request timeout. See the module doc on failing closed.
    pub timeout: Duration,
}

/// Configuration that is wrong in a way we can detect before any secret is at stake.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InfisicalConfigError {
    #[error("{0} is not set")]
    Missing(&'static str),
    #[error("{var} is invalid: {detail}")]
    Value { var: &'static str, detail: String },
}

impl InfisicalConfig {
    /// Read configuration from the environment.
    ///
    /// | Variable | Default | What it is |
    /// |---|---|---|
    /// | `HULL_CI_INFISICAL_URL` | *required* | base URL, e.g. `https://us.infisical.com` |
    /// | `HULL_CI_INFISICAL_PROJECT_ID` | *required* | project holding the tenant KEKs |
    /// | `HULL_CI_INFISICAL_TOKEN` | *none* | static bearer token |
    /// | `HULL_CI_INFISICAL_CLIENT_ID` | *none* | machine identity client id |
    /// | `HULL_CI_INFISICAL_CLIENT_SECRET` | *none* | machine identity client secret |
    /// | `HULL_CI_INFISICAL_KEY_PREFIX` | `hull-ci` | prefix for derived key names |
    /// | `HULL_CI_INFISICAL_TIMEOUT_MS` | [`DEFAULT_TIMEOUT_MS`] | per-request timeout |
    ///
    /// Exactly one auth method must be supplied. Accepting both and preferring one would mean a
    /// deployment that *thinks* it moved to a machine identity can still be running on a static token
    /// nobody has rotated, and the difference would be invisible.
    pub fn from_env() -> Result<Self, InfisicalConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// [`InfisicalConfig::from_env`] against an arbitrary lookup, so the parsing rules are testable
    /// without mutating the process environment (which is racy across parallel tests).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, InfisicalConfigError> {
        let required = |var: &'static str| -> Result<String, InfisicalConfigError> {
            get(var).filter(|v| !v.trim().is_empty()).ok_or(InfisicalConfigError::Missing(var))
        };
        let base_url = required("HULL_CI_INFISICAL_URL")?.trim_end_matches('/').to_string();
        let project_id = required("HULL_CI_INFISICAL_PROJECT_ID")?;

        let token = get("HULL_CI_INFISICAL_TOKEN").filter(|v| !v.trim().is_empty());
        let client_id = get("HULL_CI_INFISICAL_CLIENT_ID").filter(|v| !v.trim().is_empty());
        let client_secret = get("HULL_CI_INFISICAL_CLIENT_SECRET").filter(|v| !v.trim().is_empty());
        let auth = match (token, client_id, client_secret) {
            (Some(t), None, None) => InfisicalAuth::Token(Redacted::new(t)),
            (None, Some(id), Some(secret)) => {
                InfisicalAuth::MachineIdentity { client_id: id, client_secret: Redacted::new(secret) }
            }
            (None, None, None) => return Err(InfisicalConfigError::Missing("HULL_CI_INFISICAL_TOKEN")),
            (None, Some(_), None) | (None, None, Some(_)) => {
                return Err(InfisicalConfigError::Value {
                    var: "HULL_CI_INFISICAL_CLIENT_ID",
                    detail: "a machine identity needs both CLIENT_ID and CLIENT_SECRET".into(),
                })
            }
            (Some(_), _, _) => {
                return Err(InfisicalConfigError::Value {
                    var: "HULL_CI_INFISICAL_TOKEN",
                    detail: "set either TOKEN or CLIENT_ID/CLIENT_SECRET, not both".into(),
                })
            }
        };

        let key_name_prefix = get("HULL_CI_INFISICAL_KEY_PREFIX")
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "hull-ci".to_string());
        let timeout_ms = match get("HULL_CI_INFISICAL_TIMEOUT_MS") {
            None => DEFAULT_TIMEOUT_MS,
            Some(raw) => raw.trim().parse::<u64>().ok().filter(|ms| *ms > 0).ok_or_else(|| {
                InfisicalConfigError::Value {
                    var: "HULL_CI_INFISICAL_TIMEOUT_MS",
                    detail: format!("expected a positive integer, got `{raw}`"),
                }
            })?,
        };

        let cfg = InfisicalConfig {
            base_url,
            project_id,
            key_name_prefix,
            auth,
            timeout: Duration::from_millis(timeout_ms),
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Reject a prefix that cannot produce a legal key name, at construction rather than at the first
    /// `provision_tenant` — which would otherwise be discovered on a tenant's first secret.
    fn validate(&self) -> Result<(), InfisicalConfigError> {
        let bad = |detail: &str| InfisicalConfigError::Value {
            var: "HULL_CI_INFISICAL_KEY_PREFIX",
            detail: detail.to_string(),
        };
        let p = &self.key_name_prefix;
        if !p.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return Err(bad("expected lowercase letters, digits and dashes"));
        }
        if !p.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()) {
            return Err(bad("must start with a letter or digit"));
        }
        // Leave room for `-<slug>-<8 hex>`: at least four slug characters, or the name is all hash
        // and an operator reading the Infisical key list cannot tell tenants apart at a glance.
        if p.len() + 1 + 4 + 1 + DIGEST_CHARS > MAX_KEY_NAME_LEN {
            return Err(bad("too long to leave room for a tenant slug within Infisical's 32-character key names"));
        }
        Ok(())
    }

    /// The Infisical key name for a tenant: `{prefix}-{slug}-{digest}`.
    ///
    /// **A naming convention, not a stored mapping**, and that is the point: the control plane can be
    /// restored from a backup, or a second one stood up, and both resolve a tenant to the same key
    /// without a lookup table that could drift out of sync with Infisical and silently point a tenant
    /// at another tenant's KEK. Nothing outside this function decides which key a tenant gets.
    ///
    /// The name is derived rather than taken verbatim because Infisical requires slug-friendly names
    /// of at most 32 characters and a tenant id is neither. Slugging alone is not enough — it is
    /// lossy, so `acme/prod` and `acme-prod` would collide, which is a cross-tenant key share. The
    /// truncated BLAKE3 digest of the **full, unslugged** tenant id restores injectivity in practice:
    /// the slug is for humans reading the Infisical console, the digest is what makes the name unique.
    pub fn key_name(&self, tenant: &str) -> String {
        let digest = blake3::hash(tenant.as_bytes()).to_hex();
        let digest = &digest.as_str()[..DIGEST_CHARS];

        let budget = MAX_KEY_NAME_LEN - self.key_name_prefix.len() - 1 - 1 - DIGEST_CHARS;
        let mut slug = String::with_capacity(budget);
        let mut last_dash = false;
        for c in tenant.chars() {
            if slug.len() == budget {
                break;
            }
            if c.is_ascii_alphanumeric() {
                slug.push(c.to_ascii_lowercase());
                last_dash = false;
            } else if !last_dash && !slug.is_empty() {
                slug.push('-');
                last_dash = true;
            }
        }
        let slug = slug.trim_matches('-');
        if slug.is_empty() {
            // A tenant id with no alphanumerics at all is still a tenant. `t` keeps the name legal.
            format!("{}-t-{digest}", self.key_name_prefix)
        } else {
            format!("{}-{slug}-{digest}", self.key_name_prefix)
        }
    }
}

// ── The key manager ──────────────────────────────────────────────────────────────────────────────

/// A [`KeyManager`] backed by Infisical KMS.
///
/// See the module doc for the envelope construction, the caching policy, and what this preserves
/// relative to a KMS with a native encryption context.
pub struct InfisicalKeyManager {
    cfg: InfisicalConfig,
    http: Http,
    /// Cached machine-identity access token and the instant it should be replaced.
    token: Mutex<Option<(Redacted, Instant)>>,
    /// tenant → Infisical key uuid. A cache of identifiers, never of key material.
    key_ids: Mutex<HashMap<String, String>>,
}

/// Hand-written rather than derived so a future field carrying a credential cannot be added into a
/// derived `Debug` by accident. Nothing here is secret; nothing here could become secret unnoticed.
impl std::fmt::Debug for InfisicalKeyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InfisicalKeyManager")
            .field("base_url", &self.cfg.base_url)
            .field("project_id", &self.cfg.project_id)
            .field("key_name_prefix", &self.cfg.key_name_prefix)
            .field("timeout", &self.cfg.timeout)
            .field("auth", &match self.cfg.auth {
                InfisicalAuth::Token(_) => "token",
                InfisicalAuth::MachineIdentity { .. } => "machine-identity",
            })
            .field("cached_key_ids", &self.key_ids.lock().map(|m| m.len()).unwrap_or(0))
            .finish()
    }
}

impl InfisicalKeyManager {
    /// Build a manager. Does no I/O — a constructor that reached the network would make process
    /// startup depend on a KMS being up, which is a worse failure than the first operation erroring.
    pub fn new(cfg: InfisicalConfig) -> Result<Self, SecretError> {
        cfg.validate().map_err(|e| SecretError::KeyService(e.to_string()))?;
        let http = Http::new(cfg.timeout)?;
        Ok(InfisicalKeyManager { cfg, http, token: Mutex::new(None), key_ids: Mutex::new(HashMap::new()) })
    }

    /// A bearer token for the next request, logging in first if the cached one is missing or stale.
    fn bearer(&self) -> Result<Redacted, SecretError> {
        match &self.cfg.auth {
            InfisicalAuth::Token(t) => Ok(t.clone()),
            InfisicalAuth::MachineIdentity { client_id, client_secret } => {
                if let Some((token, until)) = self.token.lock().expect("token lock poisoned").as_ref() {
                    if Instant::now() < *until {
                        return Ok(token.clone());
                    }
                }
                let body = serde_json::json!({
                    "clientId": client_id,
                    "clientSecret": client_secret.expose(),
                });
                let url = format!("{}/api/v1/auth/universal-auth/login", self.cfg.base_url);
                let json = self.http.send(Method::Post, url, None, Some(body)).map_err(|e| e.into_error("login"))?;
                let access = json
                    .get("accessToken")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| SecretError::KeyService("login response has no accessToken".into()))?;
                // `expiresIn` is seconds. A missing or absurd value is treated as "expire it now",
                // which costs a login per request but never uses a token past its life.
                let ttl = json.get("expiresIn").and_then(|v| v.as_u64()).unwrap_or(0);
                let valid_for = Duration::from_secs(ttl).saturating_sub(TOKEN_REFRESH_MARGIN);
                let token = Redacted::new(access);
                *self.token.lock().expect("token lock poisoned") = Some((token.clone(), Instant::now() + valid_for));
                Ok(token)
            }
        }
    }

    fn get(&self, url: String) -> Result<serde_json::Value, ApiError> {
        let bearer = self.bearer().map_err(ApiError::Refused)?;
        self.http.send(Method::Get, url, Some(bearer.expose()), None)
    }

    fn post(&self, url: String, body: Option<serde_json::Value>) -> Result<serde_json::Value, ApiError> {
        let bearer = self.bearer().map_err(ApiError::Refused)?;
        self.http.send(Method::Post, url, Some(bearer.expose()), body)
    }

    fn delete(&self, url: String) -> Result<serde_json::Value, ApiError> {
        let bearer = self.bearer().map_err(ApiError::Refused)?;
        self.http.send(Method::Delete, url, Some(bearer.expose()), None)
    }

    /// Look the tenant's key up by its derived name, returning `(key id, current version)`.
    ///
    /// **Fails closed when the key does not exist.** A 404 becomes [`SecretError::NoTenantKey`], the
    /// same terminal error a shredded tenant produces — never a create-on-demand and never a fall back
    /// to a local key. A tenant whose KEK is missing is a tenant whose secrets are unreadable, and
    /// quietly minting fresh key material would turn "your data is gone" into "your data is gone and
    /// new writes look fine", which is strictly worse.
    fn lookup_key(&self, tenant: &str) -> Result<(String, KekVersion), SecretError> {
        let name = self.cfg.key_name(tenant);
        let url = format!(
            "{}/api/v1/kms/keys/key-name/{name}?projectId={}",
            self.cfg.base_url, self.cfg.project_id
        );
        let json = match self.get(url) {
            Ok(json) => json,
            Err(ApiError::Status(404)) => return Err(SecretError::NoTenantKey(tenant.to_string())),
            Err(e) => return Err(e.into_error("key lookup")),
        };
        let (id, version) = parse_key(&json)?;
        self.key_ids.lock().expect("key id cache poisoned").insert(tenant.to_string(), id.clone());
        Ok((id, version))
    }

    /// The tenant's key id, from cache when possible.
    ///
    /// Only used on paths where the *version* is not needed. Anything that has to reason about
    /// versions calls `lookup_key`, which never reads a cache.
    fn key_id(&self, tenant: &str) -> Result<String, SecretError> {
        if let Some(id) = self.key_ids.lock().expect("key id cache poisoned").get(tenant) {
            return Ok(id.clone());
        }
        self.lookup_key(tenant).map(|(id, _)| id)
    }
}

/// Pull `(id, version)` out of a `{"key": {...}}` response.
///
/// `version` is documented with a default of 1 and is not in the schema's `required` list, so a
/// missing field is read as version 1 rather than as an error — that is what an Infisical old enough
/// to predate versioning means, and refusing would strand a working deployment.
fn parse_key(json: &serde_json::Value) -> Result<(String, KekVersion), SecretError> {
    let key = json.get("key").ok_or_else(|| SecretError::KeyService("response has no `key` object".into()))?;
    let id = key
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SecretError::KeyService("key object has no `id`".into()))?;
    let version = key.get("version").and_then(|v| v.as_u64()).unwrap_or(1);
    let version = u32::try_from(version)
        .map_err(|_| SecretError::KeyService("key version does not fit in 32 bits".into()))?;
    Ok((id.to_string(), KekVersion(version)))
}

impl KeyManager for InfisicalKeyManager {
    fn current_version(&self, tenant: &str) -> Result<KekVersion, SecretError> {
        self.lookup_key(tenant).map(|(_, v)| v)
    }

    /// Wrap a DEK under the tenant's KEK, with the caller's context carried inside the plaintext.
    ///
    /// **Refuses any version but the current one.** Infisical always encrypts under the key's latest
    /// material and offers no way to select an older version, so honouring a request for version
    /// *n-1* is impossible; claiming to have honoured it would put a false version in the record and
    /// break the downgrade binding the envelope exists to provide. In practice nothing asks for one —
    /// [`Vault::seal`](crate::seal::Vault::seal) and [`Vault::rewrap`](crate::seal::Vault::rewrap)
    /// both wrap under `current_version` — so this is a guard against a future caller, not a
    /// limitation anything hits today.
    fn wrap_dek(&self, tenant: &str, version: KekVersion, dek: &Dek, aad: &[u8]) -> Result<Vec<u8>, SecretError> {
        let (key_id, current) = self.lookup_key(tenant)?;
        if version != current {
            return Err(SecretError::NoKekVersion { tenant: tenant.to_string(), version: version.0 });
        }
        let mut envelope = seal_envelope(tenant, version, aad, dek);
        let plaintext = base64::engine::general_purpose::STANDARD.encode(&envelope);
        // The envelope contains the DEK. Wipe it as soon as it is encoded rather than waiting for the
        // scope to end, so the window in which two copies exist is as short as it can be.
        envelope.zeroize();

        let url = format!("{}/api/v1/kms/keys/{key_id}/encrypt", self.cfg.base_url);
        let json = self
            .post(url, Some(serde_json::json!({ "plaintext": plaintext })))
            .map_err(|e| e.into_error("wrap"))?;
        let ciphertext = json
            .get("ciphertext")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SecretError::KeyService("encrypt response has no ciphertext".into()))?;
        // Stored as the exact bytes of Infisical's ciphertext string. The trait calls this blob
        // opaque and means it: we do not decode, validate or reshape it, so an Infisical that changes
        // its envelope format round-trips unchanged.
        Ok(ciphertext.as_bytes().to_vec())
    }

    fn unwrap_dek(&self, tenant: &str, version: KekVersion, wrapped: &[u8], aad: &[u8]) -> Result<Dek, SecretError> {
        let key_id = self.key_id(tenant)?;
        // A blob that is not valid UTF-8 was not produced by `wrap_dek`. Same opaque error as a
        // failed authentication — a caller learns "this did not open", never why.
        let ciphertext = std::str::from_utf8(wrapped).map_err(|_| SecretError::Decrypt)?;

        let url = format!("{}/api/v1/kms/keys/{key_id}/decrypt", self.cfg.base_url);
        let json = match self.post(url, Some(serde_json::json!({ "ciphertext": ciphertext }))) {
            Ok(json) => json,
            // Infisical rejects a ciphertext this key cannot open with a 4xx. That is an
            // authentication failure, not an outage, and must not be reported as one — a broker that
            // said "KMS unavailable" every time an attacker presented a foreign blob would page an
            // operator for a working refusal.
            Err(ApiError::Status(s)) if (400..500).contains(&s) => return Err(SecretError::Decrypt),
            Err(e) => return Err(e.into_error("unwrap")),
        };
        let b64 = json
            .get("plaintext")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SecretError::KeyService("decrypt response has no plaintext".into()))?;
        let mut envelope = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| SecretError::Decrypt)?;
        let dek = open_envelope(tenant, version, aad, &envelope);
        envelope.zeroize();
        dek
    }

    /// Create the tenant's KEK in Infisical, or return the version of the one already there.
    ///
    /// **Create-on-provision, not create-on-first-use.** The key comes into existence at the moment a
    /// tenant is enrolled, by an explicit call an operator can see in an audit log — not as a side
    /// effect of a secret being written. The difference matters when something goes wrong: with
    /// create-on-first-use, a lookup failure and a genuinely new tenant are indistinguishable, so the
    /// safe response to "no key found" (refuse) and the necessary response (create) are the same
    /// event. Here they are different calls, and `lookup_key` can fail closed.
    ///
    /// `isExportable: false` is the clause that makes D§7.4's "never leaves it" true rather than
    /// aspirational: Infisical will not hand the raw key material back even to a caller holding this
    /// process's credentials, so a compromise of the control plane does not become a compromise of
    /// every tenant's KEK.
    fn provision_tenant(&self, tenant: &str) -> Result<KekVersion, SecretError> {
        match self.lookup_key(tenant) {
            Ok((_, version)) => return Ok(version),
            Err(SecretError::NoTenantKey(_)) => {}
            Err(e) => return Err(e),
        }
        let body = serde_json::json!({
            "projectId": self.cfg.project_id,
            "name": self.cfg.key_name(tenant),
            "description": format!("hull-ci tenant KEK for `{tenant}` (D§7.4)"),
            "keyUsage": "encrypt-decrypt",
            "isExportable": false,
        });
        let url = format!("{}/api/v1/kms/keys", self.cfg.base_url);
        let json = match self.post(url, Some(body)) {
            Ok(json) => json,
            // Two provisions racing: the loser sees a name conflict. Re-reading is correct and
            // idempotent — the trait promises "returns the current version if one exists".
            //
            // A 400 is ambiguous: Infisical answers it both for a duplicate name and for a request it
            // simply did not like (a bad project id, say). So the re-read decides, and if it finds
            // nothing the *original* refusal is reported rather than `NoTenantKey` — an operator
            // whose project id is wrong must not be told the tenant has no key material.
            Err(ApiError::Status(s)) if s == 409 || s == 400 => {
                return match self.lookup_key(tenant) {
                    Ok((_, version)) => Ok(version),
                    Err(SecretError::NoTenantKey(_)) => Err(ApiError::Status(s).into_error("provision")),
                    Err(e) => Err(e),
                }
            }
            Err(e) => return Err(e.into_error("provision")),
        };
        let (id, version) = parse_key(&json)?;
        self.key_ids.lock().expect("key id cache poisoned").insert(tenant.to_string(), id);
        Ok(version)
    }

    fn rotate(&self, tenant: &str) -> Result<KekVersion, SecretError> {
        let key_id = self.key_id(tenant)?;
        let url = format!("{}/api/v1/kms/keys/{key_id}/rotate", self.cfg.base_url);
        let json = self.post(url, None).map_err(|e| e.into_error("rotate"))?;
        let (_, version) = parse_key(&json)?;
        Ok(version)
    }

    /// Delete the tenant's key.
    ///
    /// # This claim is **unverified**
    ///
    /// Crypto-shredding requires that deletion *destroys the key material*, not that it hides the key
    /// from the API. Infisical's documentation for `DELETE /api/v1/kms/keys/{keyId}` says only
    /// "Delete KMS key" and describes the 200 response; it states nothing about whether the row is
    /// soft-deleted, whether the material is retained for a recovery window (as AWS KMS deliberately
    /// does — `ScheduleKeyDeletion` has a mandatory 7-to-30-day waiting period), or whether an
    /// operator with database access could restore it. **Do not tell a tenant their data has been
    /// crypto-shredded on the strength of this call succeeding.**
    ///
    /// What would settle it, in increasing order of strength:
    ///
    /// 1. A statement in Infisical's own documentation or changelog that deletion destroys material.
    /// 2. Reading `Infisical/infisical`'s `kms-key-dal`/`kms-service` source for the deployed version:
    ///    a hard `DELETE FROM kms_keys` plus cascade to `kms_key_versions` would establish it; an
    ///    `isDeleted`/`deletedAt` column would refute it.
    /// 3. On a self-hosted instance an operator controls: create a key, encrypt a marker, delete the
    ///    key, then confirm the row is absent from Postgres (not merely flagged) **and** that the
    ///    marker cannot be decrypted after a restart. That last step matters because a cached key in
    ///    process memory would otherwise mask a soft delete.
    /// 4. For a hosted deployment, deletion of the *external* CMEK when Infisical is chained to
    ///    AWS/GCP KMS — that shreds the root regardless of what Infisical's own row does, and is the
    ///    configuration a tenant-facing shredding promise should actually rest on.
    ///
    /// Until one of those is done, treat this as *revocation* — the key is unusable through the API,
    /// which stops delivery — and treat the deletion of ciphertext rows
    /// ([`SealedStore::delete_tenant`](crate::store::SealedStore::delete_tenant)) as the other half.
    fn shred(&self, tenant: &str) -> Result<(), SecretError> {
        let key_id = self.key_id(tenant)?;
        let url = format!("{}/api/v1/kms/keys/{key_id}", self.cfg.base_url);
        let result = self.delete(url);
        // Evict before inspecting the result: if the delete half-succeeded, a cached id pointing at a
        // key that may be gone is worse than a lookup.
        self.key_ids.lock().expect("key id cache poisoned").remove(tenant);
        match result {
            Ok(_) => Ok(()),
            // Already gone is the state the caller asked for.
            Err(ApiError::Status(404)) => Ok(()),
            Err(e) => Err(e.into_error("shred")),
        }
    }
}

// ── The envelope: AAD carried inside the wrapped plaintext ───────────────────────────────────────

/// `be_u32(len) || bytes`, appended to `out`.
///
/// Length-prefixed for the reason `crate::associated_data` is: without it, `("ab", "c")` and
/// `("a", "bc")` encode identically, and a tenant/name pair colliding with another tenant/name pair
/// is precisely the cross-tenant confusion this envelope exists to prevent.
fn frame(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Build the plaintext handed to Infisical: framed context, then the DEK.
///
/// The DEK goes **last and unframed** so the parser can take "everything after the prefix" — a length
/// field in front of the key would be one more attacker-influenced number to get wrong, and there is
/// nothing after it that needs delimiting.
fn seal_envelope(tenant: &str, version: KekVersion, aad: &[u8], dek: &Dek) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + tenant.len() + aad.len() + DEK_LEN);
    frame(&mut out, ENVELOPE_DOMAIN.as_bytes());
    frame(&mut out, tenant.as_bytes());
    frame(&mut out, version.0.to_string().as_bytes());
    frame(&mut out, aad);
    out.extend_from_slice(dek.expose());
    out
}

/// Recover the DEK **only if** every field of the carried context equals what the caller expects.
///
/// This is the check that replaces the encryption context Infisical does not offer. Every failure —
/// wrong tenant, wrong secret name (which lives inside `aad`), wrong KEK version, a truncated blob,
/// an envelope from a future format — returns the same [`SecretError::Decrypt`] the AEAD paths do, so
/// a caller probing with mutated context learns nothing about which field it got wrong.
///
/// The comparisons are ordinary equality, not constant-time. That is deliberate: every value compared
/// here — a tenant id, a secret name, a version number — is context an attacker mounting this attack
/// already knows, because it is what they chose to present. Constant-time comparison protects key
/// material, and no key material is compared.
fn open_envelope(tenant: &str, version: KekVersion, aad: &[u8], envelope: &[u8]) -> Result<Dek, SecretError> {
    let mut rest = envelope;
    let mut take = || -> Option<&[u8]> {
        let (len, tail) = rest.split_first_chunk::<4>()?;
        let len = u32::from_be_bytes(*len) as usize;
        if tail.len() < len {
            return None;
        }
        let (field, tail) = tail.split_at(len);
        rest = tail;
        Some(field)
    };
    let (domain, got_tenant, got_version, got_aad) = match (take(), take(), take(), take()) {
        (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
        _ => return Err(SecretError::Decrypt),
    };

    let expected_version = version.0.to_string();
    let bound = domain == ENVELOPE_DOMAIN.as_bytes()
        && got_tenant == tenant.as_bytes()
        && got_version == expected_version.as_bytes()
        && got_aad == aad;
    if !bound {
        return Err(SecretError::Decrypt);
    }

    let bytes: [u8; DEK_LEN] = rest.try_into().map_err(|_| SecretError::Decrypt)?;
    Ok(Dek::from_bytes(bytes))
}

// ── HTTP ─────────────────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum Method {
    Get,
    Post,
    Delete,
}

/// A failed call, in the only two shapes a caller needs to tell apart.
///
/// Note what is *not* here: the response body. See the module doc — a body is influenced by the far
/// end and by an attacker, and a component whose job is to not leak credentials should not be in the
/// business of forwarding strings it did not write.
#[derive(Debug)]
enum ApiError {
    /// A well-formed HTTP response with a non-2xx status.
    Status(u16),
    /// Nothing usable came back: connection refused, TLS failure, timeout, unparseable body.
    Transport(&'static str),
    /// A [`SecretError`] raised before the request went out — a failed login, for instance.
    Refused(SecretError),
}

impl ApiError {
    /// Turn into the error an operator sees, naming the operation so a log line is actionable.
    fn into_error(self, op: &str) -> SecretError {
        match self {
            ApiError::Refused(e) => e,
            ApiError::Status(status) => {
                tracing::warn!(op, status, "infisical KMS refused a request; failing closed");
                SecretError::KeyService(format!("infisical {op} returned HTTP {status}"))
            }
            ApiError::Transport(what) => {
                tracing::warn!(op, reason = what, "infisical KMS is unreachable; failing closed");
                SecretError::KeyService(format!("infisical {op} failed: {what}"))
            }
        }
    }
}

/// The HTTP client, and the runtime that drives it.
///
/// [`KeyManager`] is synchronous and has to stay synchronous — it is called from `Vault::seal`, which
/// is called from ordinary non-async code. `reqwest::blocking` cannot be used to bridge that gap
/// because it **panics** when invoked from inside a Tokio runtime, and the control plane is a Tokio
/// application: a broker that works in tests and panics in production is worse than no broker. So
/// this owns a small runtime of its own, hands each request to it, and blocks the calling thread on
/// the result. Callers on an async thread should still wrap these calls in `spawn_blocking` — this
/// makes blocking *safe*, not free.
struct Http {
    client: reqwest::Client,
    /// `Option` only so [`Drop`] can take it. See the impl.
    rt: Option<tokio::runtime::Runtime>,
    timeout: Duration,
}

impl Http {
    fn new(timeout: Duration) -> Result<Self, SecretError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            // A KMS is not a redirect-following API. Refusing redirects means a compromised or
            // misconfigured endpoint cannot bounce a request carrying our bearer token elsewhere.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| SecretError::KeyService("could not build an HTTP client".into()))?;
        // One worker: KMS calls are I/O-bound and few, and a single thread keeps the footprint of an
        // optional backend small. Concurrency still works — the worker multiplexes futures.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("hull-ci-infisical")
            .enable_all()
            .build()
            .map_err(|_| SecretError::KeyService("could not start the KMS client runtime".into()))?;
        Ok(Http { client, rt: Some(rt), timeout })
    }

    /// Send a request and parse a JSON response, blocking the calling thread.
    fn send(
        &self,
        method: Method,
        url: String,
        bearer: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ApiError> {
        let method = match method {
            Method::Get => reqwest::Method::GET,
            Method::Post => reqwest::Method::POST,
            Method::Delete => reqwest::Method::DELETE,
        };
        let mut req = self.client.request(method, url);
        if let Some(token) = bearer {
            req = req.bearer_auth(token);
        }
        if let Some(body) = body {
            req = req.json(&body);
        }
        let req = req.build().map_err(|_| ApiError::Transport("request could not be built"))?;

        let client = self.client.clone();
        let rt = self.rt.as_ref().expect("runtime dropped while still in use");
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        rt.spawn(async move {
            let outcome = match client.execute(req).await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    match resp.bytes().await {
                        Ok(bytes) => Ok((status, bytes)),
                        Err(_) => Err(ApiError::Transport("response body could not be read")),
                    }
                }
                Err(e) if e.is_timeout() => Err(ApiError::Transport("timed out")),
                Err(e) if e.is_connect() => Err(ApiError::Transport("could not connect")),
                // Anything else — TLS, DNS, a malformed URL. `reqwest`'s message can contain the URL
                // and, on some error kinds, header content; the kind is all an operator needs.
                Err(_) => Err(ApiError::Transport("request failed")),
            };
            let _ = tx.send(outcome);
        });

        // A backstop on top of the client's own timeout: if the runtime worker were wedged, the
        // client timeout would never fire and this call would block a broker thread forever. Failing
        // closed means bounded, not eventual.
        let (status, bytes) = rx
            .recv_timeout(self.timeout + Duration::from_secs(1))
            .map_err(|_| ApiError::Transport("timed out"))??;

        if !(200..300).contains(&status) {
            return Err(ApiError::Status(status));
        }
        // An empty 2xx body is legal for a DELETE. `null` parses and every caller that needs a field
        // checks for it, so this stays permissive here and strict at the field level.
        if bytes.is_empty() {
            return Ok(serde_json::Value::Null);
        }
        serde_json::from_slice(&bytes).map_err(|_| ApiError::Transport("response was not JSON"))
    }
}

/// Shut the runtime down **without blocking**.
///
/// A multi-threaded Tokio runtime's ordinary `Drop` blocks until its workers stop, and blocking in a
/// destructor that might run on an async thread panics. `shutdown_background` is the non-blocking
/// form, so dropping a key manager can never take down the process that held it.
impl Drop for Http {
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    // ── A hand-rolled HTTP/1.1 stub ──────────────────────────────────────────────────────────────
    //
    // A real socket rather than a mocked client type, and no new dependency for it. The point of
    // these tests is the wire contract with Infisical — paths, headers, bodies, status codes — and a
    // faked client trait would let all four drift while the tests stayed green.

    struct Request {
        method: String,
        path: String,
        auth: Option<String>,
        body: serde_json::Value,
    }

    struct Response {
        status: u16,
        body: String,
    }

    impl Response {
        fn json(value: serde_json::Value) -> Self {
            Response { status: 200, body: value.to_string() }
        }
    }

    /// What the stub observed on the wire, so a test can assert the request and not just the answer.
    #[derive(Clone)]
    struct Seen {
        method: String,
        path: String,
        auth: Option<String>,
    }

    struct Stub {
        addr: std::net::SocketAddr,
        stop: Arc<AtomicBool>,
        seen: Arc<Mutex<Vec<Seen>>>,
    }

    impl Stub {
        fn start(handler: impl Fn(&Request) -> Response + Send + Sync + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.set_nonblocking(true).expect("nonblocking");
            let addr = listener.local_addr().expect("addr");
            let stop = Arc::new(AtomicBool::new(false));
            let seen = Arc::new(Mutex::new(Vec::new()));
            let (stop_t, seen_t) = (stop.clone(), seen.clone());
            std::thread::spawn(move || {
                while !stop_t.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((sock, _)) => {
                            // On BSD-derived platforms (macOS included) an accepted socket inherits
                            // the listener's non-blocking flag, so this must be undone or the first
                            // read races the client's bytes and returns `WouldBlock`.
                            sock.set_nonblocking(false).expect("blocking");
                            if let Some(req) = read_request(&sock) {
                                seen_t.lock().expect("seen").push(Seen {
                                    method: req.method.clone(),
                                    path: req.path.clone(),
                                    auth: req.auth.clone(),
                                });
                                write_response(sock, handler(&req));
                            }
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => break,
                    }
                }
            });
            Stub { addr, stop, seen }
        }

        fn url(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn paths(&self) -> Vec<String> {
            self.seen.lock().expect("seen").iter().map(|s| format!("{} {}", s.method, s.path)).collect()
        }

        fn auth_headers(&self) -> Vec<Option<String>> {
            self.seen.lock().expect("seen").iter().map(|s| s.auth.clone()).collect()
        }
    }

    impl Drop for Stub {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    fn read_request(mut sock: &TcpStream) -> Option<Request> {
        sock.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        // Read until the headers are complete, then until Content-Length bytes of body have arrived.
        loop {
            let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n");
            if let Some(end) = head_end {
                let head = String::from_utf8_lossy(&buf[..end]).to_string();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_string()))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                if buf.len() >= end + 4 + len {
                    let mut lines = head.lines();
                    let start = lines.next()?;
                    let mut parts = start.split_whitespace();
                    let method = parts.next()?.to_string();
                    let path = parts.next()?.to_string();
                    let auth = head.lines().find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("authorization:")
                            .map(|_| l[l.find(':').unwrap() + 1..].trim().to_string())
                    });
                    let raw = &buf[end + 4..end + 4 + len];
                    let body = serde_json::from_slice(raw).unwrap_or(serde_json::Value::Null);
                    return Some(Request { method, path, auth, body });
                }
            }
            let n = sock.read(&mut chunk).ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    fn write_response(mut sock: TcpStream, resp: Response) {
        let out = format!(
            "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            resp.status,
            resp.body.len(),
            resp.body
        );
        let _ = sock.write_all(out.as_bytes());
        let _ = sock.flush();
    }

    // ── A stand-in for Infisical's crypto ────────────────────────────────────────────────────────

    /// The stub "encrypts" by base64-ing the plaintext it was given and "decrypts" by reversing it.
    ///
    /// Deliberately **no** authentication and **no** context binding — that is the whole point. This
    /// models the property the module has to compensate for: a KMS that will happily return the
    /// plaintext for any ciphertext it is shown, under any key, with no notion of an AAD. Every
    /// wrong-context test below therefore fails at *our* prefix check or not at all.
    fn kms_stub(key_version: u64) -> impl Fn(&Request) -> Response + Send + Sync + 'static {
        move |req: &Request| {
            if req.path.contains("/encrypt") {
                let pt = req.body["plaintext"].as_str().unwrap_or_default();
                Response::json(serde_json::json!({ "ciphertext": format!("ct:{pt}") }))
            } else if req.path.contains("/decrypt") {
                let ct = req.body["ciphertext"].as_str().unwrap_or_default();
                match ct.strip_prefix("ct:") {
                    Some(pt) => Response::json(serde_json::json!({ "plaintext": pt })),
                    None => Response { status: 400, body: "{}".into() },
                }
            } else if req.path.contains("/key-name/") {
                Response::json(serde_json::json!({
                    "key": { "id": "11111111-2222-3333-4444-555555555555", "version": key_version }
                }))
            } else {
                Response { status: 404, body: "{}".into() }
            }
        }
    }

    fn config(base_url: String) -> InfisicalConfig {
        InfisicalConfig {
            base_url,
            project_id: "proj-1".into(),
            key_name_prefix: "hull-ci".into(),
            auth: InfisicalAuth::Token(Redacted::new("test-token")),
            timeout: Duration::from_millis(500),
        }
    }

    fn aad(tenant: &str, name: &str, version: u32) -> Vec<u8> {
        crate::associated_data("hull-ci/dek-wrap/v1", &[tenant, name, &version.to_string()])
    }

    // ── The envelope construction ────────────────────────────────────────────────────────────────

    #[test]
    fn a_dek_round_trips_through_a_kms_that_has_no_aad() {
        let stub = Stub::start(kms_stub(1));
        let km = InfisicalKeyManager::new(config(stub.url())).unwrap();
        let dek = Dek::generate();
        let a = aad("acme", "NPM_TOKEN", 1);

        let wrapped = km.wrap_dek("acme", KekVersion(1), &dek, &a).unwrap();
        let back = km.unwrap_dek("acme", KekVersion(1), &wrapped, &a).unwrap();
        assert_eq!(back.expose(), dek.expose());

        // The wire contract, not just the outcome.
        assert!(stub.paths().iter().any(|p| p.contains("/api/v1/kms/keys/key-name/hull-ci-acme-")));
        assert!(stub.paths().iter().any(|p| p.ends_with("/encrypt")));
        assert!(stub.paths().iter().any(|p| p.ends_with("/decrypt")));
    }

    #[test]
    fn a_blob_wrapped_for_one_tenant_is_refused_for_another() {
        // The attack the carried prefix exists to stop. Infisical has no encryption context, so the
        // stub returns the plaintext for anyone who asks; only the prefix check refuses. Note that
        // the *same* key id is used for both tenants here — that is the stub being maximally
        // unhelpful, which is exactly the condition under which this check must still hold.
        let stub = Stub::start(kms_stub(1));
        let km = InfisicalKeyManager::new(config(stub.url())).unwrap();
        let dek = Dek::generate();
        let wrapped = km.wrap_dek("acme", KekVersion(1), &dek, &aad("acme", "NPM_TOKEN", 1)).unwrap();

        let err = km
            .unwrap_dek("globex", KekVersion(1), &wrapped, &aad("globex", "NPM_TOKEN", 1))
            .unwrap_err();
        assert_eq!(err, SecretError::Decrypt);
    }

    #[test]
    fn a_blob_wrapped_for_one_secret_name_is_refused_for_another() {
        // Same tenant, same KEK version, different name: a `STAGING_TOKEN` record whose wrapped DEK
        // is spliced into a `PROD_TOKEN` row.
        let stub = Stub::start(kms_stub(1));
        let km = InfisicalKeyManager::new(config(stub.url())).unwrap();
        let dek = Dek::generate();
        let wrapped = km.wrap_dek("acme", KekVersion(1), &dek, &aad("acme", "STAGING_TOKEN", 1)).unwrap();

        let err = km
            .unwrap_dek("acme", KekVersion(1), &wrapped, &aad("acme", "PROD_TOKEN", 1))
            .unwrap_err();
        assert_eq!(err, SecretError::Decrypt);
    }

    #[test]
    fn a_blob_cannot_be_relabelled_as_another_kek_version() {
        // The downgrade shuffle: a record's `kek_version` column is edited so the blob appears to have
        // come from a different (perhaps deliberately weak) KEK version.
        let stub = Stub::start(kms_stub(3));
        let km = InfisicalKeyManager::new(config(stub.url())).unwrap();
        let dek = Dek::generate();
        let wrapped = km.wrap_dek("acme", KekVersion(3), &dek, &aad("acme", "NPM_TOKEN", 3)).unwrap();

        // Both halves of the claim are moved together, as an attacker editing a row would.
        let err = km
            .unwrap_dek("acme", KekVersion(2), &wrapped, &aad("acme", "NPM_TOKEN", 2))
            .unwrap_err();
        assert_eq!(err, SecretError::Decrypt);
    }

    #[test]
    fn wrapping_under_a_stale_version_is_refused_rather_than_silently_upgraded() {
        // Infisical can only encrypt under the latest material. Wrapping "under v1" while the key is
        // at v4 would record a version the blob was not wrapped with, which is precisely the lie the
        // version binding exists to prevent — so it is refused instead.
        let stub = Stub::start(kms_stub(4));
        let km = InfisicalKeyManager::new(config(stub.url())).unwrap();
        let err = km.wrap_dek("acme", KekVersion(1), &Dek::generate(), &aad("acme", "T", 1)).unwrap_err();
        assert_eq!(err, SecretError::NoKekVersion { tenant: "acme".into(), version: 1 });
    }

    #[test]
    fn a_truncated_or_reshaped_envelope_is_refused() {
        let dek = Dek::generate();
        let a = aad("acme", "T", 1);
        let env = seal_envelope("acme", KekVersion(1), &a, &dek);
        assert_eq!(open_envelope("acme", KekVersion(1), &a, &env).unwrap().expose(), dek.expose());

        for cut in [0, 4, env.len() - 1, env.len() - DEK_LEN] {
            assert_eq!(
                open_envelope("acme", KekVersion(1), &a, &env[..cut]).unwrap_err(),
                SecretError::Decrypt,
                "a {cut}-byte envelope must not open"
            );
        }
        // Extra trailing bytes must not be tolerated either: the DEK is "the rest", so a longer rest
        // is a different message.
        let mut long = env.clone();
        long.push(0);
        assert_eq!(open_envelope("acme", KekVersion(1), &a, &long).unwrap_err(), SecretError::Decrypt);
    }

    #[test]
    fn the_envelope_domain_separator_is_checked() {
        // An envelope from some other length-prefixed format must not be reinterpreted as this one.
        let dek = Dek::generate();
        let a = aad("acme", "T", 1);
        let mut forged = Vec::new();
        frame(&mut forged, b"hull-ci/some-other-envelope/v1");
        frame(&mut forged, b"acme");
        frame(&mut forged, b"1");
        frame(&mut forged, &a);
        forged.extend_from_slice(dek.expose());
        assert_eq!(open_envelope("acme", KekVersion(1), &a, &forged).unwrap_err(), SecretError::Decrypt);
    }

    // ── Failing closed ───────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_unreachable_kms_refuses_rather_than_degrading() {
        // Port 1 rather than a bound-then-dropped ephemeral port: a released ephemeral port can be
        // handed straight back to another test's stub, which would make this test pass or fail on a
        // race. Nothing listens on tcpmux, and connecting to a low port needs no privilege.
        let km = InfisicalKeyManager::new(config("http://127.0.0.1:1".into())).unwrap();

        // Every entry point, because "fails closed" has to be true of all of them, not the one that
        // happened to get a test.
        let e = km.current_version("acme").unwrap_err();
        assert!(matches!(e, SecretError::KeyService(_)), "got {e:?}");
        assert!(matches!(km.provision_tenant("acme"), Err(SecretError::KeyService(_))));
        assert!(matches!(km.rotate("acme"), Err(SecretError::KeyService(_))));
        assert!(matches!(km.shred("acme"), Err(SecretError::KeyService(_))));
        assert!(matches!(
            km.wrap_dek("acme", KekVersion(1), &Dek::generate(), &aad("acme", "T", 1)),
            Err(SecretError::KeyService(_))
        ));
        assert!(matches!(
            km.unwrap_dek("acme", KekVersion(1), b"ct:x", &aad("acme", "T", 1)),
            Err(SecretError::KeyService(_))
        ));
    }

    #[test]
    fn a_slow_kms_times_out_rather_than_hanging_a_broker_thread() {
        let stub = Stub::start(|_req: &Request| {
            std::thread::sleep(Duration::from_secs(30));
            Response::json(serde_json::json!({}))
        });
        let mut cfg = config(stub.url());
        cfg.timeout = Duration::from_millis(150);
        let km = InfisicalKeyManager::new(cfg).unwrap();

        let started = Instant::now();
        let err = km.current_version("acme").unwrap_err();
        assert!(matches!(err, SecretError::KeyService(_)), "got {err:?}");
        assert!(started.elapsed() < Duration::from_secs(5), "a timeout must be bounded by the configured one");
    }

    #[test]
    fn a_missing_key_is_terminal_and_never_creates_one() {
        // 404 from the lookup: the tenant was never provisioned, or was shredded. Both must refuse.
        // A key manager that created a key here would turn a lost KEK into a working write path and
        // an unreadable history.
        let stub = Stub::start(|_req: &Request| Response { status: 404, body: "{}".into() });
        let km = InfisicalKeyManager::new(config(stub.url())).unwrap();
        assert_eq!(km.current_version("acme").unwrap_err(), SecretError::NoTenantKey("acme".into()));
        assert_eq!(
            km.wrap_dek("acme", KekVersion(1), &Dek::generate(), &aad("acme", "T", 1)).unwrap_err(),
            SecretError::NoTenantKey("acme".into())
        );
        // No key was created on the way past.
        assert!(stub.paths().iter().all(|p| !p.starts_with("POST /api/v1/kms/keys ")));
    }

    #[test]
    fn a_rejected_ciphertext_is_an_authentication_failure_not_an_outage() {
        // Infisical answers 400 for a ciphertext this key cannot open. Reporting that as
        // `KeyService` would page an operator every time an attacker presented a foreign blob.
        let stub = Stub::start(|req: &Request| {
            if req.path.contains("/key-name/") {
                Response::json(serde_json::json!({ "key": { "id": "k-1", "version": 1 } }))
            } else {
                Response { status: 400, body: "{}".into() }
            }
        });
        let km = InfisicalKeyManager::new(config(stub.url())).unwrap();
        assert_eq!(
            km.unwrap_dek("acme", KekVersion(1), b"ct:garbage", &aad("acme", "T", 1)).unwrap_err(),
            SecretError::Decrypt
        );
    }

    // ── Credentials ──────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_bearer_token_never_reaches_an_error_a_log_or_a_debug() {
        const TOKEN: &str = "st.deadbeef.super-secret-do-not-print";
        // An API that echoes the Authorization header back in its error body. This is not a
        // hypothetical: it is why errors from this module carry no body at all.
        let stub = Stub::start(|req: &Request| Response {
            status: 500,
            body: serde_json::json!({ "message": format!("bad credential: {:?}", req.auth) }).to_string(),
        });
        let mut cfg = config(stub.url());
        cfg.auth = InfisicalAuth::Token(Redacted::new(TOKEN));
        let km = InfisicalKeyManager::new(cfg.clone()).unwrap();

        let err = km.current_version("acme").unwrap_err();
        for rendered in [format!("{err}"), format!("{err:?}"), format!("{km:?}"), format!("{cfg:?}")] {
            assert!(!rendered.contains(TOKEN), "a credential leaked into `{rendered}`");
            assert!(!rendered.contains("deadbeef"), "a credential leaked into `{rendered}`");
        }
        // …and the token really was sent, so the assertion above is not passing because nothing
        // authenticated in the first place.
        assert_eq!(stub.auth_headers(), vec![Some(format!("Bearer {TOKEN}"))]);
        // The status still reaches the operator: refusing to forward a body is not refusing to say
        // anything.
        assert!(format!("{err}").contains("500"), "got {err}");
    }

    #[test]
    fn a_redacted_string_renders_nothing_and_holds_no_display() {
        let r = Redacted::new("hunter2");
        assert_eq!(format!("{r:?}"), "<redacted>");
        // The length is not rendered either — token lengths identify the credential family.
        assert!(!format!("{r:?}").contains('7'));
        assert_eq!(
            format!("{:?}", InfisicalAuth::MachineIdentity {
                client_id: "id-1".into(),
                client_secret: Redacted::new("shh"),
            }),
            "MachineIdentity { client_id: \"id-1\", client_secret: <redacted> }"
        );
    }

    #[test]
    fn a_machine_identity_logs_in_once_and_reuses_the_token() {
        let stub = Stub::start(|req: &Request| {
            if req.path.contains("/auth/universal-auth/login") {
                Response::json(serde_json::json!({
                    "accessToken": "issued-token", "expiresIn": 7200,
                    "accessTokenMaxTTL": 7200, "tokenType": "Bearer"
                }))
            } else {
                kms_stub(1)(req)
            }
        });
        let mut cfg = config(stub.url());
        cfg.auth = InfisicalAuth::MachineIdentity {
            client_id: "id-1".into(),
            client_secret: Redacted::new("secret-1"),
        };
        let km = InfisicalKeyManager::new(cfg).unwrap();
        km.current_version("acme").unwrap();
        km.current_version("acme").unwrap();

        let logins = stub.paths().iter().filter(|p| p.contains("login")).count();
        assert_eq!(logins, 1, "a valid token must be reused, not re-minted per call");
        // The login itself carries no bearer header — it is the thing that produces one.
        assert_eq!(stub.auth_headers()[0], None);
        assert_eq!(stub.auth_headers()[1], Some("Bearer issued-token".into()));
    }

    // ── Lifecycle ────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn provisioning_creates_a_non_exportable_key_and_is_idempotent() {
        let created = Arc::new(AtomicBool::new(false));
        let seen_body = Arc::new(Mutex::new(serde_json::Value::Null));
        let (c, b) = (created.clone(), seen_body.clone());
        let stub = Stub::start(move |req: &Request| {
            if req.path.contains("/key-name/") {
                if c.load(Ordering::Relaxed) {
                    Response::json(serde_json::json!({ "key": { "id": "k-1", "version": 1 } }))
                } else {
                    Response { status: 404, body: "{}".into() }
                }
            } else if req.method == "POST" {
                *b.lock().unwrap() = req.body.clone();
                c.store(true, Ordering::Relaxed);
                Response::json(serde_json::json!({ "key": { "id": "k-1", "version": 1 } }))
            } else {
                Response { status: 404, body: "{}".into() }
            }
        });
        let km = InfisicalKeyManager::new(config(stub.url())).unwrap();
        assert_eq!(km.provision_tenant("acme").unwrap(), KekVersion(1));

        let body = seen_body.lock().unwrap().clone();
        // D§7.4's "never leaves it" is this field. Without it, Infisical would export the raw KEK to
        // anyone holding this process's credentials.
        assert_eq!(body["isExportable"], serde_json::json!(false));
        assert_eq!(body["keyUsage"], serde_json::json!("encrypt-decrypt"));
        assert_eq!(body["projectId"], serde_json::json!("proj-1"));

        // Second call finds the existing key and creates nothing.
        let creates_before = stub.paths().iter().filter(|p| p == &"POST /api/v1/kms/keys").count();
        assert_eq!(km.provision_tenant("acme").unwrap(), KekVersion(1));
        let creates_after = stub.paths().iter().filter(|p| p == &"POST /api/v1/kms/keys").count();
        assert_eq!(creates_before, creates_after, "provisioning must be idempotent");
    }

    #[test]
    fn a_rejected_provisioning_is_reported_as_a_refusal_not_as_a_missing_key() {
        // Infisical answers 400 both for "that name is taken" and for "your request was wrong". When
        // the follow-up lookup finds nothing, the operator gets the refusal — telling them the tenant
        // has no key material would send them looking for a shred that never happened.
        let stub = Stub::start(|req: &Request| {
            if req.path.contains("/key-name/") {
                Response { status: 404, body: "{}".into() }
            } else {
                Response { status: 400, body: r#"{"message":"projectId not found"}"#.into() }
            }
        });
        let km = InfisicalKeyManager::new(config(stub.url())).unwrap();
        let err = km.provision_tenant("acme").unwrap_err();
        assert!(matches!(err, SecretError::KeyService(_)), "got {err:?}");
        assert!(format!("{err}").contains("400"), "got {err}");
    }

    #[test]
    fn shredding_deletes_the_key_and_forgets_its_id() {
        // Both the lookup and the delete answer with the key object, as Infisical does.
        let stub = Stub::start(|_req: &Request| {
            Response::json(serde_json::json!({ "key": { "id": "k-doomed", "version": 2 } }))
        });
        let km = InfisicalKeyManager::new(config(stub.url())).unwrap();
        km.shred("acme").unwrap();
        assert!(stub.paths().contains(&"DELETE /api/v1/kms/keys/k-doomed".to_string()));
        // The cache must not survive the shred: a cached id for a deleted key would keep aiming
        // operations at a key that may be gone.
        assert!(km.key_ids.lock().unwrap().is_empty());
    }

    #[test]
    fn rotation_reports_the_new_version() {
        let stub = Stub::start(|req: &Request| {
            if req.path.contains("/rotate") {
                Response::json(serde_json::json!({ "key": { "id": "k-1", "version": 7 } }))
            } else {
                Response::json(serde_json::json!({ "key": { "id": "k-1", "version": 6 } }))
            }
        });
        let km = InfisicalKeyManager::new(config(stub.url())).unwrap();
        assert_eq!(km.rotate("acme").unwrap(), KekVersion(7));
        assert!(stub.paths().contains(&"POST /api/v1/kms/keys/k-1/rotate".to_string()));
    }

    // ── Naming and configuration ─────────────────────────────────────────────────────────────────

    #[test]
    fn key_names_are_legal_slugs_and_never_collide_after_slugging() {
        let cfg = config("http://x".into());
        // Slugging is lossy, so these two would be the same name without the digest — and the same
        // name is the same KEK, which is a cross-tenant key share.
        assert_ne!(cfg.key_name("acme/prod"), cfg.key_name("acme-prod"));
        assert_ne!(cfg.key_name("ACME"), cfg.key_name("acme_"));

        for tenant in ["acme", "acme/prod", "a-very-long-tenant-identifier-indeed", "🙂", "", "_"] {
            let name = cfg.key_name(tenant);
            assert!(name.len() <= MAX_KEY_NAME_LEN, "`{name}` is {} chars", name.len());
            assert!(
                name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "`{name}` is not slug-friendly"
            );
            assert!(!name.starts_with('-') && !name.ends_with('-'), "`{name}`");
            assert!(!name.contains("--"), "`{name}`");
            // Deterministic: two control planes must resolve a tenant to the same key with no shared
            // lookup table.
            assert_eq!(name, cfg.key_name(tenant));
        }
    }

    #[test]
    fn configuration_demands_exactly_one_auth_method() {
        let base = |extra: &[(&str, &str)]| {
            let mut vars = vec![
                ("HULL_CI_INFISICAL_URL", "https://kms.example/"),
                ("HULL_CI_INFISICAL_PROJECT_ID", "p1"),
            ];
            vars.extend_from_slice(extra);
            let owned: Vec<(String, String)> =
                vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            InfisicalConfig::from_lookup(move |k| {
                owned.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone())
            })
        };

        let ok = base(&[("HULL_CI_INFISICAL_TOKEN", "t")]).unwrap();
        assert!(matches!(ok.auth, InfisicalAuth::Token(_)));
        // The trailing slash is trimmed, or every URL would contain `//`.
        assert_eq!(ok.base_url, "https://kms.example");
        assert_eq!(ok.timeout, Duration::from_millis(DEFAULT_TIMEOUT_MS));

        assert!(matches!(
            base(&[("HULL_CI_INFISICAL_CLIENT_ID", "i"), ("HULL_CI_INFISICAL_CLIENT_SECRET", "s")])
                .unwrap()
                .auth,
            InfisicalAuth::MachineIdentity { .. }
        ));

        // Both set: refused rather than silently preferred, so a deployment that believes it moved to
        // a machine identity cannot still be running on a static token.
        assert!(matches!(
            base(&[("HULL_CI_INFISICAL_TOKEN", "t"), ("HULL_CI_INFISICAL_CLIENT_ID", "i")]),
            Err(InfisicalConfigError::Value { .. })
        ));
        // Half a machine identity is not a machine identity.
        assert!(matches!(
            base(&[("HULL_CI_INFISICAL_CLIENT_ID", "i")]),
            Err(InfisicalConfigError::Value { .. })
        ));
        // None at all.
        assert!(matches!(base(&[]), Err(InfisicalConfigError::Missing(_))));
        // And a URL is not optional.
        assert!(matches!(
            InfisicalConfig::from_lookup(|_| None),
            Err(InfisicalConfigError::Missing("HULL_CI_INFISICAL_URL"))
        ));
    }

    #[test]
    fn a_prefix_that_could_not_produce_a_legal_key_name_is_refused_at_construction() {
        let mut cfg = config("http://x".into());
        cfg.key_name_prefix = "a-prefix-so-long-it-leaves-no-room".into();
        assert!(InfisicalKeyManager::new(cfg.clone()).is_err());
        cfg.key_name_prefix = "Not_A_Slug".into();
        assert!(InfisicalKeyManager::new(cfg).is_err());
    }
}
