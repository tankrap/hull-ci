//! Adversarial tests for the secret broker.
//!
//! The unit tests next to the code check that each rule does what it says. This file checks the
//! harder claims — the ones design D§7.4 actually makes to a tenant — told as attacks, through the
//! public API only, with no access to internals a real attacker would not have either:
//!
//! * A fork PR cannot obtain a secret **no matter what the pipeline declares**.
//! * A stolen database gives up nothing.
//! * A compromised node cannot widen its reach, redeem twice, or redeem for anyone else.
//! * Deleting one tenant's key is a fact about that tenant and nobody else.
//!
//! Two habits run through it, borrowed from the dialect suite:
//!
//! * **Same setup, one variable.** Every gate test runs the *identical* request twice and changes
//!   exactly the thing under test, so a pass cannot be an accident of a differently-shaped fixture.
//! * **Prove the positive too.** Each refusal is paired with the case that must still work.
//!   A broker that refuses everything is trivially secure and useless.

use std::sync::Arc;

use hull_ci_proto::AuthorClass;
use hull_ci_secrets::{
    CapabilityRequest, CapabilityToken, DevKeyManager, KeyManager, MemorySealedStore, NodeIdentity,
    NodeRegistry, SealedSecret, SealedStore, SecretBroker, SecretError, SecretService, Vault,
};

/// The declared set a hostile fork would write into `.hull/ci.star`. Identical in every test that
/// uses it — the point being that the *declaration* is never what decides anything.
const DECLARED: &[&str] = &["NPM_TOKEN", "DEPLOY_KEY"];

struct Stack {
    broker: SecretBroker,
    keys: Arc<DevKeyManager>,
    store: Arc<MemorySealedStore>,
}

fn stack() -> Stack {
    let keys = Arc::new(DevKeyManager::new());
    let store = Arc::new(MemorySealedStore::new());
    let broker = SecretBroker::new(keys.clone(), store.clone());
    broker.provision_tenant("acme").unwrap();
    broker.put_secret("acme", "NPM_TOKEN", b"npm_live_s3cr3t_value").unwrap();
    broker.put_secret("acme", "DEPLOY_KEY", b"deploy-key-material-here").unwrap();
    Stack { broker, keys, store }
}

fn request(class: AuthorClass, job: &str, node: &str) -> CapabilityRequest {
    CapabilityRequest {
        tenant: "acme".into(),
        job_id: job.into(),
        node_id: node.into(),
        declared: DECLARED.iter().map(|s| s.to_string()).collect(),
        author_class: class,
    }
}

/// The headline claim: the "pwn request" is structurally impossible, not merely discouraged.
///
/// Both halves run the same repo, the same tenant, the same declared names, the same node. The only
/// difference is the author class, which D§1 derives from the dispatch's `author` and repo
/// membership and which no edit to the tree under test can raise.
#[test]
fn a_fork_pr_cannot_get_a_secret_however_it_declares_it() {
    let s = stack();

    let member = s.broker.mint(&request(AuthorClass::Member, "job-member", "node-a")).unwrap();
    let delivered = s.broker.redeem(&member.0, "node-a", &[]).unwrap();
    assert_eq!(delivered.len(), 2, "a member's job gets what it declared");

    let refused = s.broker.mint(&request(AuthorClass::Outsider, "job-fork", "node-a")).unwrap_err();
    assert_eq!(refused, SecretError::OutsiderRefused);
}

/// The refusal must not double as a reconnaissance channel.
///
/// If the message differed between "that secret exists" and "that secret does not", a fork PR could
/// enumerate a tenant's secret names — which are frequently enough to identify its vendors, its
/// cloud, and where to aim the next attempt.
#[test]
fn an_outsider_learns_nothing_from_the_refusal() {
    let s = stack();
    let mut errors = Vec::new();
    for declared in [
        vec!["NPM_TOKEN"],          // exists
        vec!["NO_SUCH_THING"],      // does not
        vec!["PATH"],               // reserved
        vec!["not a valid name"],   // malformed
        vec![],                     // nothing at all
    ] {
        let mut req = request(AuthorClass::Outsider, "job-fork", "node-a");
        req.declared = declared.iter().map(|s| s.to_string()).collect();
        errors.push(s.broker.mint(&req).unwrap_err());
    }
    assert!(errors.iter().all(|e| *e == SecretError::OutsiderRefused), "{errors:?}");

    // A member asking the same questions gets useful, distinguishable answers — members are allowed
    // to know what their own tenant holds.
    let mut req = request(AuthorClass::Member, "job-member", "node-a");
    req.declared = vec!["NO_SUCH_THING".into()];
    assert!(matches!(s.broker.mint(&req).unwrap_err(), SecretError::UnknownSecret { .. }));
}

/// A full database dump is worth nothing without the KEK, which lives in a KMS this crate never
/// holds. The attacker here has more than a real one usually does: every ciphertext row, and a
/// working broker of their own.
#[test]
fn a_stolen_ciphertext_row_is_inert() {
    let s = stack();
    let stolen: Vec<SealedSecret> = s.store.list("acme").unwrap();
    assert_eq!(stolen.len(), 2);
    for row in &stolen {
        assert!(
            !row.ciphertext.windows(4).any(|w| w == b"npm_" || w == b"depl"),
            "no plaintext fragment may survive into the record"
        );
    }

    // Attacker's own stack, with their own keys and the victim's rows loaded into it.
    let attacker_keys = Arc::new(DevKeyManager::new());
    let attacker_store = Arc::new(MemorySealedStore::new());
    for row in stolen.clone() {
        attacker_store.put(row).unwrap();
    }
    let attacker = SecretBroker::new(attacker_keys.clone(), attacker_store.clone());

    // Without key material for `acme` there is nothing to try.
    let err = attacker.mint(&request(AuthorClass::Member, "job-x", "node-x")).unwrap_err();
    assert_eq!(err, SecretError::NoTenantKey("acme".into()));

    // Provisioning a *fresh* `acme` KEK in the attacker's own KMS does not help: it is different key
    // material under a version the stolen rows never referenced.
    attacker.provision_tenant("acme").unwrap();
    let (token, _) = attacker.mint(&request(AuthorClass::Member, "job-x", "node-x")).unwrap();
    assert!(matches!(
        attacker.redeem(&token, "node-x", &[]).unwrap_err(),
        SecretError::NoKekVersion { .. } | SecretError::Decrypt
    ));
}

/// Tenant B is fully compromised — the attacker holds B's KEK. A's rows must still be unreadable,
/// including after relabelling them as B's, which is the obvious next move once row-level access is
/// assumed.
#[test]
fn compromising_one_tenants_key_does_not_reach_another_tenants_secrets() {
    let s = stack();
    s.broker.provision_tenant("globex").unwrap();
    s.broker.put_secret("globex", "NPM_TOKEN", b"globex-own-value").unwrap();

    let acme_row = s.store.get("acme", "NPM_TOKEN").unwrap().unwrap();
    let vault = Vault::new(s.keys.clone());

    // Straight attempt: the labels disagree with the context.
    assert!(matches!(
        vault.open("globex", "NPM_TOKEN", &acme_row).unwrap_err(),
        SecretError::ContextMismatch { .. }
    ));

    // Relabelled to agree — the AAD, not the labels, is what authenticates.
    let relabelled = SealedSecret { tenant: "globex".into(), ..acme_row.clone() };
    assert_eq!(vault.open("globex", "NPM_TOKEN", &relabelled).unwrap_err(), SecretError::Decrypt);

    // Renamed within the same tenant — a `STAGING_TOKEN` promoted by an UPDATE statement.
    let renamed = SealedSecret { name: "DEPLOY_KEY".into(), ..acme_row };
    assert_eq!(vault.open("acme", "DEPLOY_KEY", &renamed).unwrap_err(), SecretError::Decrypt);
}

/// A capability is bound to one node and one use. Every way of stretching it is refused.
#[test]
fn a_capability_cannot_be_stretched() {
    let s = stack();

    // Bound to its node — but note what this line is and is not. Called straight against the broker,
    // `node-b` is a string this test chose, so all it proves is that the comparison happens. The
    // attack it stands for is `a_stolen_capability_is_useless_on_the_attackers_machine` below, which
    // goes through `SecretService` and makes the node prove which node it is. D§7.4 is explicit that
    // the difference is invisible from the code, so it is spelled out here instead.
    let (token, grant) = s.broker.mint(&request(AuthorClass::Member, "job-1", "node-a")).unwrap();
    assert_eq!(s.broker.redeem(&token, "node-b", &[]).unwrap_err(), SecretError::WrongNode);

    // Bound to its declared set. `DEPLOY_KEY` is declared here, so narrow the grant first to have
    // something outside it.
    let mut narrow = request(AuthorClass::Member, "job-2", "node-a");
    narrow.declared = vec!["NPM_TOKEN".into()];
    let (narrow_token, _) = s.broker.mint(&narrow).unwrap();
    assert_eq!(
        s.broker.redeem(&narrow_token, "node-a", &["DEPLOY_KEY".into()]).unwrap_err(),
        SecretError::Undeclared("DEPLOY_KEY".into())
    );

    // Bound to one use.
    assert!(s.broker.redeem(&token, "node-a", &[]).is_ok());
    assert_eq!(s.broker.redeem(&token, "node-a", &[]).unwrap_err(), SecretError::CapabilityConsumed);

    // And revocable while outstanding.
    let (fresh, fresh_grant) = s.broker.mint(&request(AuthorClass::Member, "job-3", "node-a")).unwrap();
    assert!(s.broker.revoke(fresh_grant.cap_id));
    assert_eq!(s.broker.redeem(&fresh, "node-a", &[]).unwrap_err(), SecretError::CapabilityRevoked);
    assert_ne!(grant.cap_id, fresh_grant.cap_id);
}

/// Single-use has to hold under a race, not just in sequence. Twelve threads redeem the same token
/// at once; exactly one may win, and every loser must see `CapabilityConsumed` rather than a
/// partially-delivered result.
///
/// A broker that checked "consumed" and then set it would pass the sequential test above and fail
/// this one, delivering the same job's secrets to every racer.
#[test]
fn concurrent_redemption_of_one_capability_has_exactly_one_winner() {
    let s = stack();
    let (token, _) = s.broker.mint(&request(AuthorClass::Member, "job-race", "node-a")).unwrap();
    let token: &CapabilityToken = &token;
    let broker = &s.broker;

    let outcomes: Vec<Result<usize, SecretError>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..12)
            .map(|_| scope.spawn(move || broker.redeem(token, "node-a", &[]).map(|d| d.len())))
            .collect();
        handles.into_iter().map(|h| h.join().expect("no thread may panic")).collect()
    });

    let winners: Vec<_> = outcomes.iter().filter(|o| o.is_ok()).collect();
    assert_eq!(winners.len(), 1, "single-use means exactly one redemption: {outcomes:?}");
    assert_eq!(*winners[0].as_ref().unwrap(), 2);
    assert!(
        outcomes.iter().filter(|o| o.is_err()).all(|o| o.as_ref().unwrap_err() == &SecretError::CapabilityConsumed),
        "every loser must be told the capability was already redeemed: {outcomes:?}"
    );
}

/// Rotation is an operational event, not an outage. A capability minted before a KEK rotation must
/// still redeem afterwards, because old KEK versions keep unwrapping (D§7.4) — otherwise every
/// rotation would fail whichever jobs happened to be in flight.
#[test]
fn a_rotation_mid_flight_does_not_break_a_live_job() {
    let s = stack();
    let (token, _) = s.broker.mint(&request(AuthorClass::Member, "job-inflight", "node-a")).unwrap();

    let rewrapped = s.broker.rotate_tenant("acme").unwrap();
    assert_eq!(rewrapped, 2);

    let delivered = s.broker.redeem(&token, "node-a", &[]).unwrap();
    assert_eq!(delivered.get("NPM_TOKEN").unwrap().expose(), b"npm_live_s3cr3t_value");

    // And a rotation interrupted halfway leaves a mix of versions that all still open.
    s.broker.put_secret("acme", "THIRD_TOKEN", b"third-token-value").unwrap();
    s.keys.rotate("acme").unwrap();
    s.broker.put_secret("acme", "FOURTH_TOKEN", b"fourth-token-value").unwrap();
    let mut mixed = request(AuthorClass::Member, "job-mixed", "node-a");
    mixed.declared = vec!["NPM_TOKEN".into(), "THIRD_TOKEN".into(), "FOURTH_TOKEN".into()];
    let (token, _) = s.broker.mint(&mixed).unwrap();
    assert_eq!(s.broker.redeem(&token, "node-a", &[]).unwrap().len(), 3);
}

/// **This test documents a gap. It is not a bug to be fixed in `keys.rs`.**
///
/// D§7.4 puts rotation under the heading "Rotation & revocation", which reads as though rotating is
/// a *recovery* from a compromised KEK. It is not, here or in the pattern it cites: rotation adds a
/// version and re-wraps, and [`KeyManager`] has no operation that retires the old one. So after a
/// full sweep, KEK v1 is still in the key manager and still unwraps every DEK it ever wrapped — and
/// an attacker holding v1 plus a pre-rotation backup row reads the secret.
///
/// This is the correct behaviour for the *operational* rotation the design describes (an interrupted
/// sweep must leave a mix of versions that all still open — see
/// `a_rotation_mid_flight_does_not_break_a_live_job`), and it is why crypto-shredding, not rotation,
/// is the answer to a compromise. Written down because the two readings are one word apart.
#[test]
fn rotating_a_kek_does_not_retire_the_old_version() {
    let s = stack();
    let pre_rotation_backup = s.store.get("acme", "NPM_TOKEN").unwrap().unwrap();
    assert_eq!(pre_rotation_backup.kek_version.0, 1);

    assert_eq!(s.broker.rotate_tenant("acme").unwrap(), 2);
    assert_eq!(s.store.get("acme", "NPM_TOKEN").unwrap().unwrap().kek_version.0, 2);

    // The row that was rotated away from still opens, because the key it names still exists.
    let vault = Vault::new(s.keys.clone());
    assert_eq!(
        vault.open("acme", "NPM_TOKEN", &pre_rotation_backup).unwrap().expose(),
        b"npm_live_s3cr3t_value"
    );
    assert_eq!(s.keys.current_version("acme").unwrap().0, 2);
}

/// **This test documents a gap.**
///
/// The AAD binds `(tenant, name)` and the wrap binds `(tenant, name, kek_version)`. Neither binds a
/// *generation*, so two ciphertexts for one `(tenant, name)` are interchangeable and the broker
/// serves whichever row it finds. A tenant that rotates a leaked value therefore has that rotation
/// undone, silently, by any restore of an older snapshot — a lagging replica, a point-in-time
/// recovery, a botched migration — and the next job gets the compromised value with no signal.
///
/// The AEAD cannot fix this on its own (a rollback restores a row that *was* authentic), but a
/// monotonic generation in the AAD plus a high-water mark outside the row would make the stale row
/// fail to open rather than open cleanly. Stated here because "the AAD stops a substituted row" is
/// true for a *foreign* row and false for a *previous* one, and the difference is not obvious.
#[test]
fn a_restored_backup_row_reinstates_a_rotated_out_secret_value() {
    let s = stack();
    let before_rotation = s.store.get("acme", "NPM_TOKEN").unwrap().unwrap();

    // The tenant rotates the value itself after a leak.
    s.broker.put_secret("acme", "NPM_TOKEN", b"fresh-value-after-the-leak").unwrap();
    let (token, _) = s.broker.mint(&request(AuthorClass::Member, "job-1", "node-a")).unwrap();
    assert_eq!(
        s.broker.redeem(&token, "node-a", &[]).unwrap().get("NPM_TOKEN").unwrap().expose(),
        b"fresh-value-after-the-leak"
    );

    // A restore puts the old row back. It authenticates, because it always did.
    s.store.put(before_rotation).unwrap();
    let (token, _) = s.broker.mint(&request(AuthorClass::Member, "job-2", "node-a")).unwrap();
    assert_eq!(
        s.broker.redeem(&token, "node-a", &[]).unwrap().get("NPM_TOKEN").unwrap().expose(),
        b"npm_live_s3cr3t_value",
        "the compromised value is served again, with nothing to distinguish it"
    );
}

/// **This test documents a gap.**
///
/// [`Masker::register`] returns `false` for a value below `MIN_MASKABLE_LEN`, and its doc says why
/// that is a refusal rather than a silent no-op: "a caller who registers a short value and sees no
/// error would reasonably assume it was covered." Every caller in this workspace discards the
/// answer, so a short tenant secret is delivered and then never masked, with no warning anywhere.
///
/// Masking is a backstop and not a control (see `mask`'s module doc), so this is not a hole in the
/// gate — but it is the *stated* contract of `register` being dropped by its own callers, and the
/// honest `echo` it exists to catch goes uncaught.
#[test]
fn a_secret_too_short_to_mask_is_delivered_anyway_and_never_masked() {
    let s = stack();
    s.broker.put_secret("acme", "PIN", b"a1b2c").unwrap(); // 5 bytes, below MIN_MASKABLE_LEN
    let mut req = request(AuthorClass::Member, "job-1", "node-a");
    req.declared = vec!["PIN".into()];

    let (token, _) = s.broker.mint(&req).unwrap();
    let delivered = s.broker.redeem(&token, "node-a", &[]).unwrap();
    assert_eq!(delivered.get("PIN").unwrap().expose(), b"a1b2c");

    let masker = delivered.masker();
    assert!(masker.is_empty(), "the registration was refused and the refusal discarded");
    assert_eq!(masker.mask("PIN=a1b2c"), "PIN=a1b2c");
}

/// Crypto-shredding is total for its tenant and inert for everyone else. This is the property that
/// makes "delete my data" a one-call operation rather than a hunt through backups.
#[test]
fn shredding_a_tenant_is_total_and_local() {
    let s = stack();
    s.broker.provision_tenant("globex").unwrap();
    s.broker.put_secret("globex", "NPM_TOKEN", b"globex-own-value").unwrap();
    let (inflight, _) = s.broker.mint(&request(AuthorClass::Member, "job-doomed", "node-a")).unwrap();

    s.broker.shred_tenant("acme").unwrap();

    // Total: in-flight capability dead, no new capability, rows present but unreadable.
    assert_eq!(s.broker.redeem(&inflight, "node-a", &[]).unwrap_err(), SecretError::CapabilityRevoked);
    assert_eq!(
        s.broker.mint(&request(AuthorClass::Member, "job-after", "node-a")).unwrap_err(),
        SecretError::NoTenantKey("acme".into())
    );
    assert_eq!(s.store.list("acme").unwrap().len(), 2, "rows are left in place deliberately");
    let vault = Vault::new(s.keys.clone());
    let row = s.store.get("acme", "NPM_TOKEN").unwrap().unwrap();
    assert!(vault.open("acme", "NPM_TOKEN", &row).is_err());

    // Local: globex never noticed.
    let mut req = request(AuthorClass::Member, "job-globex", "node-a");
    req.tenant = "globex".into();
    req.declared = vec!["NPM_TOKEN".into()];
    let (token, _) = s.broker.mint(&req).unwrap();
    assert_eq!(s.broker.redeem(&token, "node-a", &[]).unwrap().get("NPM_TOKEN").unwrap().expose(), b"globex-own-value");
}

/// The delivery-to-sandbox seam: names and values come out shaped for an environment, and the
/// masker that goes to the log shipper is primed with the same values.
#[test]
fn delivery_produces_an_environment_and_a_primed_masker() {
    let s = stack();
    let (token, _) = s.broker.mint(&request(AuthorClass::Member, "job-1", "node-a")).unwrap();
    let delivered = s.broker.redeem(&token, "node-a", &[]).unwrap();

    let mut env = delivered.to_env_vars();
    env.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(env.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), ["DEPLOY_KEY", "NPM_TOKEN"]);
    assert_eq!(env[1].1.as_str(), "npm_live_s3cr3t_value");

    let masker = delivered.masker();
    assert_eq!(masker.mask("npm ERR! using npm_live_s3cr3t_value"), "npm ERR! using ***");
    // And the honest disclaimer, asserted rather than merely written down: the same value, encoded,
    // sails straight through. The gate above is what protects it from hostile code.
    assert_eq!(masker.mask(&hex::encode("npm_live_s3cr3t_value")), hex::encode("npm_live_s3cr3t_value"));
}

/// **The attack the node binding actually exists for**, told end to end through the seam that makes
/// it real.
///
/// An attacker gets a live capability token — off a crash dump, a stray log line, a compromised
/// second node. Every other property still stands in their way, but the one under test here is the
/// node binding, and D§7.4 says it is worthless unless the *transport* proves who is speaking:
///
/// > a `node_id` is just a string in a request. Unless the transport has already proven *which node*
/// > is speaking, the field is self-asserted and the `WrongNode` refusal is decorative: an attacker
/// > who has the capability token can simply claim the right id.
///
/// So the attacker is given every advantage short of the honest node's private key: a real keypair,
/// a real enrolment of their own, and a correctly signed request naming the right job. There is no
/// field left in which to claim to be `node-honest`, because the id is derived from the key that
/// signed — and the refusal follows from a fact the attacker cannot restate.
#[test]
fn a_stolen_capability_is_useless_on_the_attackers_machine() {
    let s = stack();
    let broker = Arc::new(s.broker);
    let nodes = Arc::new(NodeRegistry::new());
    let service = SecretService::new(Arc::clone(&broker), Arc::clone(&nodes));

    let honest = NodeIdentity::generate();
    let attacker = NodeIdentity::generate();
    service.enrol_node("node-honest", honest.public()).unwrap();
    service.enrol_node("node-attacker", attacker.public()).unwrap();

    let (stolen, _) = service.mint(&request(AuthorClass::Member, "job-1", "node-honest")).unwrap();
    // Real wall-clock seconds, because this stack runs on the real clock and a redemption stamped
    // outside `MAX_SKEW_SECS` is refused for freshness before the node binding is ever reached — a
    // useful thing to have discovered while writing this, and a reason not to hand-pick a timestamp.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap();

    // 1. Signed correctly, by an enrolled key, for the right job — and still refused, because the
    //    key resolves to `node-attacker`.
    assert_eq!(
        service.redeem(&attacker.sign(&stolen, "job-1", &[], now)).unwrap_err(),
        SecretError::WrongNode
    );

    // 2. Copying the honest node's public key into the request does not help: the signature is over
    //    that key too, and the attacker cannot produce one for a key they do not hold.
    let mut impersonation = attacker.sign(&stolen, "job-1", &[], now);
    impersonation.public_key = honest.public();
    assert_eq!(service.redeem(&impersonation).unwrap_err(), SecretError::BadNodeSignature);

    // 3. Neither does an unenrolled key, however well-formed the rest of the request is.
    let anonymous = NodeIdentity::generate();
    assert!(matches!(
        service.redeem(&anonymous.sign(&stolen, "job-1", &[], now)),
        Err(SecretError::UnenrolledNode(_))
    ));

    // Prove the positive: none of those attempts burned the capability, and the node the capability
    // was actually minted for still gets its secrets. A binding that also killed the honest job
    // would hand an attacker a denial of service in place of a theft.
    let delivered = service.redeem(&honest.sign(&stolen, "job-1", &[], now)).unwrap();
    assert_eq!(delivered.get("NPM_TOKEN").unwrap().expose(), b"npm_live_s3cr3t_value");
}
