//! The seam: authenticate the node, *then* ask the broker.
//!
//! D§7.4's node-binding note says where these two checks belong:
//!
//! > So the binding is load-bearing **only** when the server seam verifies the node's Ed25519
//! > identity (§7.4's enrolment keypair) on the connection carrying the redemption, and derives
//! > `node_id` from that verified identity rather than from the request body. […] Both checks belong
//! > at the seam where identity is already established, and the design should not imply the broker
//! > can do them alone.
//!
//! This type is that seam. It is deliberately thin — it owns no policy of its own — and its whole
//! contribution is the *order*: [`NodeRegistry::verify`] first, and the node id it returns is the
//! only one [`SecretBroker::redeem`] ever sees. There is no path through this type by which a
//! caller-supplied node id reaches the broker, which is what makes [`SecretError::WrongNode`] a
//! control rather than a comment.
//!
//! Minting stays on the control side and keeps its own entry point ([`SecretService::mint`]), because
//! the actor whose authority is being checked there is the *job's author*, not the node — the author
//! class gate is the broker's and this type must not appear to duplicate it.

use std::sync::Arc;

use crate::broker::{CapabilityRequest, DeliveredSecrets, SecretBroker};
use crate::capability::{CapabilityGrant, CapabilityToken};
use crate::identity::{NodePublicKey, NodeRegistry, SignedRedemption};
use crate::{Clock, SecretError, SystemClock};

/// The broker plus the enrolment table, wired in the order D§7.4 requires.
#[derive(Debug)]
pub struct SecretService {
    broker: Arc<SecretBroker>,
    nodes: Arc<NodeRegistry>,
    clock: Arc<dyn Clock>,
}

impl SecretService {
    pub fn new(broker: Arc<SecretBroker>, nodes: Arc<NodeRegistry>) -> Self {
        SecretService { broker, nodes, clock: Arc::new(SystemClock) }
    }

    /// Share the broker's clock, so a test that drives capability expiry also drives redemption
    /// freshness. Two clocks that can disagree is a source of test flakes and, worse, of a real
    /// deployment where a capability is live but every redemption of it looks stale.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn broker(&self) -> &Arc<SecretBroker> {
        &self.broker
    }

    pub fn nodes(&self) -> &Arc<NodeRegistry> {
        &self.nodes
    }

    /// Enrol a node's public key under an id (D§7.4: "enrolled at provisioning").
    pub fn enrol_node(&self, node_id: impl Into<String>, key: NodePublicKey) -> Result<(), SecretError> {
        self.nodes.enrol(node_id, key)
    }

    /// Mint at placement. A pass-through to the broker, which owns the author-class gate.
    pub fn mint(&self, req: &CapabilityRequest) -> Result<(CapabilityToken, CapabilityGrant), SecretError> {
        self.broker.mint(req)
    }

    /// Redeem at exec time, on behalf of whichever node actually signed the request.
    ///
    /// The `node_id` handed to the broker is [`NodeRegistry::verify`]'s return value — derived from a
    /// public key whose signature over this exact request just verified — so a node presenting a
    /// stolen capability is refused with [`SecretError::WrongNode`] on a fact it cannot restate.
    ///
    /// The `job_id` check is here rather than in the broker for the same reason: the broker takes a
    /// node id it is handed, and the thing that knows the redemption was *signed* for this job is the
    /// thing that just checked the signature.
    pub fn redeem(&self, req: &SignedRedemption) -> Result<DeliveredSecrets, SecretError> {
        let node_id = self.nodes.verify(req, self.clock.now_secs())?;
        let delivered = self.broker.redeem(&req.token, &node_id, &req.requested)?;
        if delivered.job_id != req.job_id {
            // Only reachable with a capability minted for a different job than the node signed for.
            // The capability is already burnt by the time we get here, which is the right side to err
            // on: a mismatch is either a control-plane bug or an attempt, and neither should leave a
            // live capability behind.
            return Err(SecretError::WrongJob {
                bound: delivered.job_id.clone(),
                presented: req.job_id.clone(),
            });
        }
        Ok(delivered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use crate::keys::DevKeyManager;
    use crate::store::MemorySealedStore;
    use hull_ci_proto::AuthorClass;
    use std::sync::Mutex;

    #[derive(Debug)]
    struct TestClock(Mutex<u64>);

    impl Clock for TestClock {
        fn now_secs(&self) -> u64 {
            *self.0.lock().unwrap()
        }
    }

    struct Fixture {
        service: SecretService,
        node: NodeIdentity,
        clock: Arc<TestClock>,
    }

    fn fixture() -> Fixture {
        let clock = Arc::new(TestClock(Mutex::new(1_000)));
        let broker = Arc::new(
            SecretBroker::new(Arc::new(DevKeyManager::new()), Arc::new(MemorySealedStore::new()))
                .with_clock(clock.clone()),
        );
        broker.provision_tenant("acme").unwrap();
        broker.put_secret("acme", "NPM_TOKEN", b"npm_s3cr3tvalue").unwrap();

        let node = NodeIdentity::generate();
        let service = SecretService::new(broker, Arc::new(NodeRegistry::new())).with_clock(clock.clone());
        service.enrol_node("node-a", node.public()).unwrap();
        Fixture { service, node, clock }
    }

    fn request() -> CapabilityRequest {
        CapabilityRequest {
            tenant: "acme".into(),
            job_id: "job-1".into(),
            node_id: "node-a".into(),
            declared: vec!["NPM_TOKEN".into()],
            author_class: AuthorClass::Member,
        }
    }

    #[test]
    fn the_enrolled_node_gets_its_secret() {
        let f = fixture();
        let (token, _) = f.service.mint(&request()).unwrap();
        let signed = f.node.sign(&token, "job-1", &[], 1_000);
        let delivered = f.service.redeem(&signed).unwrap();
        assert_eq!(delivered.get("NPM_TOKEN").unwrap().expose(), b"npm_s3cr3tvalue");
    }

    #[test]
    fn a_capability_stolen_by_another_node_is_refused_on_the_derived_id() {
        // The refusal D§7.4 says is decorative without this file. The thief holds the token, signs
        // correctly with its own enrolled key, and still cannot be `node-a` — because it never says
        // which node it is, it proves it, and the proof resolves to `node-b`.
        let f = fixture();
        let thief = NodeIdentity::generate();
        f.service.enrol_node("node-b", thief.public()).unwrap();

        let (token, _) = f.service.mint(&request()).unwrap();
        let signed = thief.sign(&token, "job-1", &[], 1_000);
        assert_eq!(f.service.redeem(&signed).unwrap_err(), SecretError::WrongNode);

        // And the legitimate node is not collateral damage: the attempt did not burn the capability.
        let honest = f.node.sign(&token, "job-1", &[], 1_000);
        assert!(f.service.redeem(&honest).is_ok());
    }

    #[test]
    fn an_unenrolled_node_never_reaches_the_broker() {
        // The capability must survive an unauthenticated attempt, or anyone holding a token could
        // burn a healthy job's secrets by presenting it badly.
        let f = fixture();
        let stranger = NodeIdentity::generate();
        let (token, _) = f.service.mint(&request()).unwrap();

        let signed = stranger.sign(&token, "job-1", &[], 1_000);
        assert!(matches!(f.service.redeem(&signed), Err(SecretError::UnenrolledNode(_))));

        let honest = f.node.sign(&token, "job-1", &[], 1_000);
        assert!(f.service.redeem(&honest).is_ok(), "an unauthenticated attempt must not burn it");
    }

    #[test]
    fn a_capability_is_still_single_use_through_the_seam() {
        let f = fixture();
        let (token, _) = f.service.mint(&request()).unwrap();
        assert!(f.service.redeem(&f.node.sign(&token, "job-1", &[], 1_000)).is_ok());
        // A fresh signature with a fresh nonce, which is exactly the replay the capability stops:
        // signing again is easy for the node that holds the key, and buys nothing.
        assert_eq!(
            f.service.redeem(&f.node.sign(&token, "job-1", &[], 1_000)).unwrap_err(),
            SecretError::CapabilityConsumed
        );
    }

    #[test]
    fn a_redemption_signed_for_another_job_is_refused() {
        let f = fixture();
        let (token, _) = f.service.mint(&request()).unwrap();
        let signed = f.node.sign(&token, "job-2", &[], 1_000);
        assert!(matches!(f.service.redeem(&signed), Err(SecretError::WrongJob { .. })));
    }

    #[test]
    fn an_outsiders_job_gets_no_capability_to_present_in_the_first_place() {
        // Nothing in this file weakens the gate: it is refused at mint, before a node is involved.
        let f = fixture();
        let outsider = CapabilityRequest { author_class: AuthorClass::Outsider, ..request() };
        assert_eq!(f.service.mint(&outsider).unwrap_err(), SecretError::OutsiderRefused);
    }

    #[test]
    fn one_clock_drives_both_expiry_and_freshness() {
        // The failure this guards against: a capability that is live by the broker's clock but whose
        // every redemption looks stale by the registry's.
        let f = fixture();
        let (token, _) = f.service.mint(&request()).unwrap();
        *f.clock.0.lock().unwrap() = 1_030;
        let signed = f.node.sign(&token, "job-1", &[], 1_030);
        assert!(f.service.redeem(&signed).is_ok(), "half a TTL in is well inside both windows");
    }
}
