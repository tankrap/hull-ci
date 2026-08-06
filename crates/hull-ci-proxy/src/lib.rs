//! The package proxy — the single destination a sandbox is permitted to reach (spec §14.3, D§7.3/7.4).
//!
//! Spec §14.3 is the whole brief:
//!
//! > Default **egress-deny**. A job **SHOULD** run with no outbound network. Where dependency
//! > resolution needs it, restrict egress to an allowlisted, authenticated **package proxy** — never
//! > the open internet, never Hull's internal network.
//!
//! Which exists because of an awkward fact: with `--network none` a job has no network at all, so
//! `npm install`, `cargo fetch` and `pip install` cannot work. This crate is what lets real CI run
//! *without* opening egress — and it is only worth having if the sandbox genuinely cannot reach
//! anything else, which is a property of [`hull_ci_node::container`]'s network posture, not of this
//! crate. **This crate is one half of a control.** The other half is the netns, and neither is worth
//! anything alone.
//!
//! # The five properties, in the order they matter
//!
//! 1. **Deny by default** ([`allowlist`]). An upstream nobody configured is refused, not proxied.
//!    Hosts match exactly — never by suffix, which would allow `evil-npmjs.org` — and only `GET`
//!    and `HEAD` are served, because a `PUT` to an allowlisted host is a ready-made exfiltration
//!    channel out of a sandbox with no other egress.
//! 2. **Auth terminates here** ([`credentials`], D§7.4). The proxy holds the upstream registry
//!    credential as a *tenant secret* and spends it outbound; the job never receives it, and cannot,
//!    because the response headers a job sees are rebuilt from an allowlist rather than copied.
//! 3. **Per-job scope** ([`grant`]). A job gets a URL carrying a bearer that authorises exactly
//!    "resolve packages, for this job, from these upstreams, at this rate, until this job ends".
//!    It is handed to untrusted code on purpose, and is designed on that assumption.
//! 4. **Rate limited** ([`ratelimit`]). The proxy is the only channel a job has, which makes it the
//!    only place a job can hammer an upstream from Hull's IP or drip data out slowly.
//! 5. **Audited** ([`audit`]). What was fetched, and — the security-interesting half — what was
//!    refused. A job reaching for an unallowlisted host is one of the few times hostile intent leaves
//!    a legible trace, because everything else it might try is silently dropped by the netns.
//!
//! # It is a terminating mirror, not a `CONNECT` tunnel
//!
//! The single most consequential design decision here, argued in full in [`server`]: a `CONNECT`
//! proxy cannot authenticate outbound (the TLS session belongs to the job) and cannot see what was
//! fetched (an allowlisted host becomes a general-purpose tunnel). So `CONNECT` is refused, the job
//! speaks plain HTTP to the proxy over the isolated sandbox network, and the proxy speaks
//! authenticated HTTPS to the upstream.
//!
//! # What this crate does not do
//!
//! * **It does not cache.** D§7 calls the proxy "a legitimate shared cross-tenant cache" and it would
//!   be one, but a cache is a shared surface and D§1's rule ("no shared surface ever crosses a tenant
//!   or trust-tier boundary") makes that a design question with its own answer, not an optimisation
//!   to add quietly. Every request goes upstream.
//! * **It does not verify what it serves.** Package signatures, checksum pinning and any
//!   dependency-confusion defence are the ecosystem's (`npm` lockfile integrity hashes, `cargo`'s
//!   `Cargo.lock`). The proxy narrows *where* bytes may come from; it does not vouch for them.
//! * **It holds no key material.** Credentials are resolved through
//!   [`credentials::UpstreamCredentials`], which a deployment backs with the secret broker
//!   ([`brokered::BrokeredCredentials`]). The proxy holds a *value* in memory for the life of a job
//!   and never on disk (D§7.4); it holds no KEK, implements no `KeyManager`, and cannot decrypt
//!   anything itself.
//!
//! # The one credential the proxy does hold, and how it gets it
//!
//! D§7.4 calls the upstream registry credential "just a tenant secret", which makes the broker its
//! only legitimate source — and the broker delivers tenant secrets as job-scoped, single-use
//! capabilities redeemed by an *enrolled principal*. So the proxy is one: it has its own Ed25519
//! enrolment keypair, and control mints it a capability alongside each job's package grant, bounded
//! by that job and that job's upstreams. [`brokered`] is that machinery and
//! [`hull_ci_secrets::package`] is the argument for it, including why an `outsider`-authored job
//! gets none even though it never sees the value.

pub mod allowlist;
pub mod audit;
pub mod brokered;
pub mod config;
pub mod credentials;
pub mod grant;
pub mod jobenv;
pub mod ratelimit;
pub mod server;

pub use allowlist::{Allowlist, AllowlistError, AuthScheme, DenyReason, Upstream, ALLOWED_METHODS};
pub use audit::{AuditSink, Fetch, MemoryAudit, Refusal, TracingAudit};
pub use brokered::{BrokeredCredentials, InProcessRedeemer, ProxyCredentialRedeemer};
pub use config::{ProxyConfig, ProxyMode};
pub use credentials::{
    CredentialError, CredentialRequest, NoCredentials, StaticCredentials, UpstreamCredentials,
};
pub use grant::{Grant, GrantError, GrantId, GrantRegistry, GrantToken};
pub use jobenv::JobProxyEndpoint;
pub use ratelimit::RateLimit;
pub use server::PackageProxy;
