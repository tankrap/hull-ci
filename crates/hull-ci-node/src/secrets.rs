//! The node's half of the secret broker: hold an identity, redeem at exec time, forget immediately.
//!
//! D§7.4: "The node presents it plus its own Ed25519 node identity […] The node injects them as env
//! vars into the single-use sandbox and holds them in memory **only for the spawn** — never written
//! to disk, gone when the microVM is destroyed."
//!
//! Two things this module is careful about, both of which are easy to get wrong in a way that still
//! looks correct:
//!
//! * **The node signs, and nothing else may.** [`NodeIdentity`] lives here, on the node, because a
//!   signature produced anywhere else proves nothing about which machine is speaking. That is the
//!   whole reason this crate now depends on `hull-ci-secrets` — see the crate doc's revised note on
//!   what the node holds.
//! * **The redeemer is a seam, not a call.** [`SecretRedeemer`] is a trait for the same reason
//!   `NodeSink` is: in a single-process bring-up it is a struct reaching into the broker, and on a
//!   real fleet it is a socket to the credential-scoped process of D§7.4. The node's behaviour must
//!   not change between the two, and the only way to be sure of that is for the node to be unable to
//!   tell them apart.
//!
//! **The node holds no tenant credential at rest.** What it holds is its own enrolment key, which
//! authenticates it and authorises nothing on its own, plus — for the duration of one spawn — the
//! values one member-authored job declared. A sandbox escape during that window reaches that job's
//! own secrets, which is a real and unavoidable consequence of delivering a secret to a job at all;
//! it reaches no other job's and no platform credential, because there are none here to reach.

use std::sync::Arc;

use hull_ci_proto::Assignment;
use hull_ci_secrets::{CapabilityToken, DeliveredSecrets, NodeIdentity, SecretError, SignedRedemption};

use crate::sandbox::BoxFuture;

/// Where a node sends a signed redemption.
///
/// Fallible and async on purpose: on a real fleet this is a network call to a separate,
/// credential-scoped process, and a seam that could not fail or block would be one no transport could
/// implement without lying about it.
pub trait SecretRedeemer: Send + Sync + std::fmt::Debug {
    fn redeem<'a>(
        &'a self,
        req: &'a SignedRedemption,
    ) -> BoxFuture<'a, Result<DeliveredSecrets, SecretError>>;
}

/// A source of wall-clock seconds for the redemption's freshness stamp.
///
/// Its own tiny trait rather than a direct `SystemTime` call so a test can prove the node refuses to
/// run a step whose redemption was rejected for skew — behaviour that is otherwise only reachable by
/// changing the host clock.
pub trait NodeClock: Send + Sync + std::fmt::Debug {
    fn now_secs(&self) -> u64;
}

/// The real clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemNodeClock;

impl NodeClock for SystemNodeClock {
    fn now_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            // A clock before the epoch makes every redemption look stale, so the node runs no step
            // that declared a secret. Failing closed on a broken host is the right direction: the
            // alternative is delivering a secret with an unverifiable freshness stamp.
            .unwrap_or(0)
    }
}

/// Everything the node needs to obtain its declared secrets: who it is, and where to ask.
#[derive(Debug)]
pub struct SecretsClient {
    identity: Arc<NodeIdentity>,
    redeemer: Arc<dyn SecretRedeemer>,
    clock: Arc<dyn NodeClock>,
}

impl SecretsClient {
    pub fn new(identity: Arc<NodeIdentity>, redeemer: Arc<dyn SecretRedeemer>) -> Self {
        SecretsClient { identity, redeemer, clock: Arc::new(SystemNodeClock) }
    }

    pub fn with_clock(mut self, clock: Arc<dyn NodeClock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn identity(&self) -> &Arc<NodeIdentity> {
        &self.identity
    }

    /// Sign a redemption for this assignment and present it.
    ///
    /// The requested set is left **empty**, which the broker reads as "everything this job declared"
    /// — deliberately, because the declared set was fixed at mint time from the same plan this
    /// assignment came from. Asking for a subset would only create a way for the two to disagree, and
    /// asking for a superset is refused anyway (and burns the capability doing it).
    pub async fn redeem(
        &self,
        assignment: &Assignment,
        capability: &CapabilityToken,
    ) -> Result<DeliveredSecrets, SecretError> {
        let signed =
            self.identity.sign(capability, &assignment.job_id, &[], self.clock.now_secs());
        self.redeemer.redeem(&signed).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hull_ci_secrets::{
        DevKeyManager, MemorySealedStore, NodeRegistry, SecretBroker, SecretService,
    };
    use hull_ci_proto::{AuthorClass, IsolationTier};

    /// The in-process redeemer, which is also exactly what the server wires: the seam is a struct
    /// here and a socket later, and the node cannot tell.
    #[derive(Debug)]
    struct DirectRedeemer(Arc<SecretService>);

    impl SecretRedeemer for DirectRedeemer {
        fn redeem<'a>(
            &'a self,
            req: &'a SignedRedemption,
        ) -> BoxFuture<'a, Result<DeliveredSecrets, SecretError>> {
            Box::pin(async move { self.0.redeem(req) })
        }
    }

    fn assignment() -> Assignment {
        Assignment {
            job_id: "job-1".into(),
            step_id: "step-1".into(),
            step_name: "test".into(),
            tenant: "acme".into(),
            repo: "acme/widget".into(),
            tree_id: "tree-1".into(),
            argv: vec!["/bin/true".into()],
            secrets: vec!["NPM_TOKEN".into()],
            image: "n/a".into(),
            tier: IsolationTier::Container,
            author_class: AuthorClass::Member,
            timeout_secs: 30,
            lease_secs: 30,
        }
    }

    fn service() -> Arc<SecretService> {
        let broker =
            Arc::new(SecretBroker::new(Arc::new(DevKeyManager::new()), Arc::new(MemorySealedStore::new())));
        broker.provision_tenant("acme").unwrap();
        broker.put_secret("acme", "NPM_TOKEN", b"npm_s3cr3tvalue").unwrap();
        Arc::new(SecretService::new(broker, Arc::new(NodeRegistry::new())))
    }

    fn request(job: &str) -> hull_ci_secrets::CapabilityRequest {
        hull_ci_secrets::CapabilityRequest {
            tenant: "acme".into(),
            job_id: job.into(),
            node_id: "node-a".into(),
            declared: vec!["NPM_TOKEN".into()],
            author_class: AuthorClass::Member,
        }
    }

    #[tokio::test]
    async fn an_enrolled_node_redeems_its_own_capability() {
        let service = service();
        let identity = Arc::new(NodeIdentity::generate());
        service.enrol_node("node-a", identity.public()).unwrap();
        let client = SecretsClient::new(identity, Arc::new(DirectRedeemer(service.clone())));

        let (token, _) = service.mint(&request("job-1")).unwrap();
        let delivered = client.redeem(&assignment(), &token).await.unwrap();
        assert_eq!(delivered.get("NPM_TOKEN").unwrap().expose(), b"npm_s3cr3tvalue");
    }

    #[tokio::test]
    async fn a_node_whose_key_is_not_enrolled_gets_nothing() {
        // No special case for the in-process path: this node signs correctly and is still refused,
        // because authority comes from the enrolment table and not from being in the same process.
        let service = service();
        let client =
            SecretsClient::new(Arc::new(NodeIdentity::generate()), Arc::new(DirectRedeemer(service.clone())));
        let (token, _) = service.mint(&request("job-1")).unwrap();
        assert!(matches!(
            client.redeem(&assignment(), &token).await,
            Err(SecretError::UnenrolledNode(_))
        ));
    }

    #[tokio::test]
    async fn the_node_signs_for_the_job_it_was_assigned() {
        // A capability minted for another job is refused even though this node is the enrolled one,
        // because the signature covers the job id the node believes it is running.
        let service = service();
        let identity = Arc::new(NodeIdentity::generate());
        service.enrol_node("node-a", identity.public()).unwrap();
        let client = SecretsClient::new(identity, Arc::new(DirectRedeemer(service.clone())));

        let (token, _) = service.mint(&request("job-other")).unwrap();
        assert!(matches!(
            client.redeem(&assignment(), &token).await,
            Err(SecretError::WrongJob { .. })
        ));
    }
}
