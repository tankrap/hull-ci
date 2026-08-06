//! Wiring the secret broker into this process (design D§7.4, milestone M3).
//!
//! `hull-ci-secrets` is deliberately I/O-free and has no opinion about deployment. This module is
//! where a running server acquires one: it decides whether there is a broker at all, what holds the
//! key material, and — the part that matters — it **enrols the node's public key before the node can
//! ever redeem**, so the id the broker binds capabilities against is one an operator provisioned
//! rather than one a request asserted.
//!
//! # Why there is an `off` mode and why it is the default
//!
//! A deployment that never stores a tenant secret should not carry a broker, a key manager, or a node
//! keypair. `HULL_CI_SECRETS=off` is not a degraded mode: no capability is ever minted, `secrets` in
//! a pipeline goes undelivered with a warning at plan time, and the sandbox's credential-shaped-name
//! refusal keeps its M1 meaning exactly. That is the same behaviour this runner had before M3, which
//! is what makes it a safe default.
//!
//! # Why the dev mode is only a dev mode
//!
//! [`hull_ci_secrets::DevKeyManager`] holds raw KEK bytes in this process's memory. Everything a real
//! deployment gets from a KMS it gives up: a core dump contains the root key, there is no audit log
//! of an unwrap, and the key lives in the same address space as the control plane. The
//! [`KeyManager`](hull_ci_secrets::KeyManager) trait is the seam a `KmsKeyManager` implements — this
//! module deliberately does **not** invent one, because a half-written KMS client that looked
//! production-shaped would be worse than an absence nobody can mistake for one.

use std::sync::Arc;

use hull_ci_node::secrets::{SecretRedeemer, SecretsClient};
use hull_ci_node::sandbox::BoxFuture;
use hull_ci_secrets::{
    DeliveredSecrets, DevKeyManager, MemorySealedStore, NodeIdentity, NodeRegistry, SecretBroker,
    SecretError, SecretService, SignedRedemption,
};

use crate::config::{Config, SecretsMode};

/// Everything a running server needs to deliver a tenant secret, or `None` in `off` mode.
pub struct SecretPlane {
    pub service: Arc<SecretService>,
    /// The node's half: its identity, and the route back to [`SecretPlane::service`].
    pub client: Arc<SecretsClient>,
}

/// Build the secret plane for this configuration, enrolling `node_id`'s fresh keypair.
///
/// Enrolment happens here, at assembly, because it is the only moment at which this process both
/// knows the node's id and holds its public key. On a real fleet this is a provisioning step against
/// a durable registry and the node's key outlives its process; in this single-process runner the node
/// is created here, so its enrolment is too — and the *check* is identical either way, which is the
/// property worth preserving. There is no path where the in-process node skips verification.
pub fn assemble(config: &Config) -> Option<SecretPlane> {
    match config.secrets {
        SecretsMode::Off => None,
        SecretsMode::Infisical => assemble_infisical(config),
        SecretsMode::Dev => {
            tracing::warn!(
                "HULL_CI_SECRETS=dev: tenant secrets are sealed under keys held IN THIS PROCESS'S \
                 MEMORY (hull_ci_secrets::DevKeyManager). A core dump contains every tenant KEK, no \
                 unwrap is audited, and the ciphertext is in RAM and dies with the process. \
                 Development and test only — production needs a KMS behind the KeyManager trait."
            );

            Some(build_plane(config, Arc::new(DevKeyManager::new())))
        }
    }
}

/// Assemble the plane around whichever [`KeyManager`] the mode chose.
///
/// Shared by every mode on purpose: the enrolment, the node identity and the redemption path must be
/// **identical** whatever holds the KEKs. If the KMS mode built its own plane, the signature check
/// that makes `WrongNode` a control rather than a comment would be a second implementation, and the
/// one that gets exercised least is the one that would rot.
///
/// [`KeyManager`]: hull_ci_secrets::KeyManager
fn build_plane(config: &Config, keys: Arc<dyn hull_ci_secrets::KeyManager>) -> SecretPlane {
    let broker = Arc::new(SecretBroker::new(keys, Arc::new(MemorySealedStore::new())));
    let service = Arc::new(SecretService::new(broker, Arc::new(NodeRegistry::new())));

    let identity = Arc::new(NodeIdentity::generate());
    // An `Err` here means this key is already enrolled to a different node, which cannot happen for
    // a key generated one line above. Logged rather than propagated so a startup path stays free of
    // an impossible error case.
    if let Err(e) = service.enrol_node(config.node_id.clone(), identity.public()) {
        tracing::error!(error = %e, "could not enrol this node's identity; it will redeem nothing");
    }
    tracing::info!(
        node_id = %config.node_id,
        public_key = %identity.public(),
        "enrolled this node's Ed25519 identity (D§7.4); redemptions are verified against it"
    );

    let client = Arc::new(SecretsClient::new(
        identity,
        Arc::new(InProcessRedeemer { service: Arc::clone(&service) }),
    ));
    SecretPlane { service, client }
}

/// The node→broker seam, as a struct call in this one-process runner.
///
/// The point of it being a trait object is that the node cannot tell this from the socket that
/// replaces it on a real fleet. Note what this does *not* do: it does not shortcut the signature
/// check, does not pass a node id, and does not reach past [`SecretService`] into the broker. An
/// in-process caller that skipped any of those would make the verification path the one thing in the
/// system that is never exercised — see D§7.4's note about the control silently doing nothing.
#[derive(Debug)]
struct InProcessRedeemer {
    service: Arc<SecretService>,
}

impl SecretRedeemer for InProcessRedeemer {
    fn redeem<'a>(
        &'a self,
        req: &'a SignedRedemption,
    ) -> BoxFuture<'a, Result<DeliveredSecrets, SecretError>> {
        Box::pin(async move { self.service.redeem(req) })
    }
}

/// Seed the dev broker from `HULL_CI_DEV_SECRETS` (`tenant/NAME=value`, comma-separated).
///
/// **Dev only, and it puts plaintext in this process's environment**, which is precisely the shape
/// §14.2 spends its time keeping out of a *job*. It is defensible here and nowhere else: the values
/// never enter a sandbox except through a redemption, the dev key manager already holds the KEKs in
/// the same memory, and a dev mode with no way to put a secret in is a mode that cannot be tried. A
/// real deployment writes ciphertext to the control-plane DB through
/// [`SecretBroker::put_secret`](hull_ci_secrets::SecretBroker::put_secret) and never has a plaintext
/// value in an environment at all.
///
/// A malformed entry is logged and skipped rather than fatal: this is a development convenience, and
/// refusing to start over a typo in it would be a poor trade.
pub fn seed_dev_secrets(plane: &SecretPlane, raw: &str) {
    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let Some((qualified, value)) = entry.split_once('=') else {
            tracing::warn!("HULL_CI_DEV_SECRETS entry is not `tenant/NAME=value`; skipped");
            continue;
        };
        let Some((tenant, name)) = qualified.trim().split_once('/') else {
            tracing::warn!("HULL_CI_DEV_SECRETS entry has no `tenant/` prefix; skipped");
            continue;
        };
        let broker = plane.service.broker();
        if let Err(e) = broker.provision_tenant(tenant) {
            tracing::warn!(tenant, error = %e, "could not provision a tenant KEK");
            continue;
        }
        match broker.put_secret(tenant, name, value.as_bytes()) {
            // The name, never the value — this line goes to an operator's log.
            Ok(()) => tracing::info!(tenant, name, "stored a development tenant secret"),
            Err(e) => tracing::warn!(tenant, name, error = %e, "could not store a development secret"),
        }
    }
}

/// Build the plane with KEKs in Infisical KMS (design D§7.4).
///
/// Two arms compiled by feature, and the `else` arm is the point of the whole shape: a binary built
/// without `hull-ci-secrets/infisical` **refuses to start** in this mode rather than falling back.
/// Falling back to `Dev` would move every tenant KEK into this process's memory while the operator
/// believed they were in a KMS — a silent downgrade of the one property §7.4 exists to state, on a
/// deployment that had explicitly asked for the strong thing. The error names the missing feature,
/// so the remedy is "rebuild", never "use something weaker".
#[cfg(feature = "infisical")]
fn assemble_infisical(config: &Config) -> Option<SecretPlane> {
    use hull_ci_secrets::{InfisicalConfig, InfisicalKeyManager};

    let built = InfisicalConfig::from_env()
        .map_err(|e| e.to_string())
        .and_then(|cfg| InfisicalKeyManager::new(cfg).map_err(|e| e.to_string()));
    let kms = match built {
        Ok(k) => k,
        Err(e) => {
            // Fail the startup rather than the first job: a misconfigured KMS discovered at
            // dispatch time is an outage wearing an infrastructure error, and it would be
            // indistinguishable from Infisical being down.
            tracing::error!(alert = true, error = %e, "HULL_CI_SECRETS=infisical: could not reach or configure Infisical KMS");
            return None;
        }
    };
    tracing::info!(
        "HULL_CI_SECRETS=infisical: tenant KEKs live in Infisical KMS and are not extractable from          it. This process holds no KEK material; every unwrap is a round trip, and a KMS outage          refuses secret delivery rather than degrading it."
    );
    Some(build_plane(config, Arc::new(kms)))
}

#[cfg(not(feature = "infisical"))]
fn assemble_infisical(_config: &Config) -> Option<SecretPlane> {
    tracing::error!(
        alert = true,
        "HULL_CI_SECRETS=infisical, but this binary was built without the `infisical` feature.          Refusing to start the broker: falling back to the dev key manager would put every tenant          KEK in this process's memory while the operator believes they are in a KMS. Rebuild with          `--features hull-ci-secrets/infisical`."
    );
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use hull_ci_proto::AuthorClass;
    use hull_ci_secrets::CapabilityRequest;

    fn dev_config() -> Config {
        Config { secrets: SecretsMode::Dev, node_id: "node-x".into(), ..Config::default() }
    }

    #[test]
    fn off_is_the_default_and_builds_nothing() {
        assert_eq!(Config::default().secrets, SecretsMode::Off);
        assert!(assemble(&Config::default()).is_none());
    }

    #[tokio::test]
    async fn the_in_process_node_is_enrolled_and_goes_through_the_same_verification() {
        // The claim D§7.4 says is invisible when it is false: the node in this process is not a
        // special case. It redeems by signing, and the id the broker binds against comes out of the
        // enrolment table.
        let config = dev_config();
        let plane = assemble(&config).unwrap();
        let broker = plane.service.broker();
        broker.provision_tenant("acme").unwrap();
        broker.put_secret("acme", "NPM_TOKEN", b"npm_s3cr3tvalue").unwrap();

        let (token, _) = plane
            .service
            .mint(&CapabilityRequest {
                tenant: "acme".into(),
                job_id: "job-1".into(),
                node_id: "node-x".into(),
                declared: vec!["NPM_TOKEN".into()],
                author_class: AuthorClass::Member,
            })
            .unwrap();

        let signed = plane.client.identity().sign(&token, "job-1", &[], now());
        let delivered = plane.service.redeem(&signed).unwrap();
        assert_eq!(delivered.get("NPM_TOKEN").unwrap().expose(), b"npm_s3cr3tvalue");
    }

    #[test]
    fn a_foreign_identity_is_refused_by_the_same_service_the_node_uses() {
        let config = dev_config();
        let plane = assemble(&config).unwrap();
        let broker = plane.service.broker();
        broker.provision_tenant("acme").unwrap();
        broker.put_secret("acme", "NPM_TOKEN", b"npm_s3cr3tvalue").unwrap();

        let (token, _) = plane
            .service
            .mint(&CapabilityRequest {
                tenant: "acme".into(),
                job_id: "job-1".into(),
                node_id: "node-x".into(),
                declared: vec!["NPM_TOKEN".into()],
                author_class: AuthorClass::Member,
            })
            .unwrap();

        let stranger = NodeIdentity::generate();
        let signed = stranger.sign(&token, "job-1", &[], now());
        assert!(matches!(plane.service.redeem(&signed), Err(SecretError::UnenrolledNode(_))));
    }

    #[test]
    fn dev_seeding_stores_names_it_can_later_mint_for() {
        let config = dev_config();
        let plane = assemble(&config).unwrap();
        seed_dev_secrets(&plane, "acme/NPM_TOKEN=abc123xyz, acme/DEPLOY_KEY=k3yvalue, nonsense");
        let mut names = plane.service.broker().list_names("acme").unwrap();
        names.sort();
        assert_eq!(names, ["DEPLOY_KEY", "NPM_TOKEN"]);
        // The malformed entry was skipped, not fatal, and did not create a tenant.
        assert!(plane.service.broker().list_names("nonsense").unwrap().is_empty());
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}
