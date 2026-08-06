//! Layer 2 of design D§6.1, wired: the step memo and the digester that keys it.
//!
//! Everything here is assembly. The digest lives in `hull-ci-fetch` (it walks the extracted tree with
//! the same code that verified it), the key and the store live in `hull-ci-control`, and this module
//! decides only whether this deployment has them at all.
//!
//! # Off by default, and that is not timidity
//!
//! A memo that returns a wrong answer is worse than no memo: it reports a verdict about code nobody
//! ran, and Hull memoizes `green`/`red` by `tree_id` permanently (spec §7), so a bad hit is not
//! something a re-check dislodges. The failure is also silent — a wrongly-cached pass looks exactly
//! like a fast one. So it is opt-in per deployment, and the default stays the behaviour that has been
//! conformance-tested since M1.
//!
//! # What makes a step cacheable
//!
//! Only a step that **declares `inputs`**. The control plane refuses a key to a step with no inputs,
//! and refuses one whose globs select nothing — both fold an identical digest over every tree in
//! existence, which is not a cache key but a constant. Autodetected steps therefore never cache:
//! `AutodetectPlanner` names a command, not the files it depends on, and inventing globs on its
//! behalf would be guessing at exactly the point where guessing is unsound.

use std::sync::Arc;

use hull_ci_control::memo::{
    DigestError, InMemoryStepMemo, InputDigest, MemoConfig, SubtreeDigest,
};
use hull_ci_control::seams::VerifiedTree;
use hull_ci_fetch::{KeelTreeVerifier, TreeDigester};

use crate::config::Config;

/// Adapts `hull-ci-fetch`'s digester to the control plane's seam.
///
/// The composition root owns this rather than either crate, for the same reason it owns
/// [`crate::fetch::BrokerFetcher`]: the control plane must not depend on the broker, and the broker
/// must not know what a step is.
struct FetchDigester(TreeDigester);

impl SubtreeDigest for FetchDigester {
    fn digest(
        &self,
        tenant: &str,
        tree: &VerifiedTree,
        glob: &str,
    ) -> Result<InputDigest, DigestError> {
        self.0
            .digest(tenant, &tree.tree_id, &tree.path, glob)
            .map(|d| InputDigest { digest: d.digest, selected: d.selected })
            // The glob is author text from `.hull/ci.star`, so it travels in the error; the detail is
            // ours. Neither is interpolated anywhere but a log and a step detail, both of which
            // sanitize (spec §14.5).
            .map_err(|e| DigestError::Failed { glob: glob.into(), detail: e.to_string() })
    }
}

/// Build the memo configuration for this deployment, or the inert default.
///
/// The inert default is a real [`MemoConfig`] whose digester refuses every glob, not an `Option`:
/// the control plane then takes one code path in both cases, so "memo off" is exercised by every
/// existing test rather than being a branch nobody runs.
pub fn assemble(config: &Config) -> MemoConfig {
    if !config.memo {
        tracing::info!("step memo off (HULL_CI_MEMO=on to enable); every step runs");
        return MemoConfig::default();
    }

    tracing::info!(
        "step memo ON: steps declaring `inputs` may resolve from a previous identical run. \
         Only `passed` is cached long-lived; a remembered failure is served as `failed`, never \
         `cached`; `errored` is never cached at all (design D§6.1)."
    );
    MemoConfig {
        digest: Arc::new(FetchDigester(TreeDigester::new(
            KeelTreeVerifier::default(),
            Default::default(),
        ))),
        store: Arc::new(InMemoryStepMemo::default()),
        // Bumped whenever anything changes what a step *definition means* without changing the
        // definition — the evaluator's semantics, the argv construction, the image policy. Tying it
        // to the crate version makes that automatic for releases; a deliberate mid-version change to
        // any of those still has to bump it by hand, and forgetting is how a memo serves an answer
        // computed under rules that no longer apply.
        pipeline_version: format!("hull-ci/{}", env!("CARGO_PKG_VERSION")),
    }
}
