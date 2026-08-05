//! The [`Fetcher`] seam, backed by `hull-ci-fetch`'s broker.
//!
//! This is a thin adapter and is meant to stay one. Everything that makes the fetch safe — the byte
//! and entry caps, the hardened tar reader, the mandatory re-hash against `tree_id`, the tenant-scoped
//! store, the sensitive handling of `fetch_token` — lives in the broker (design D§4.2, spec §6/§14.2).
//! What this file adds is the translation between the control plane's vocabulary and the broker's, and
//! the mapping of a broker failure onto a control-plane failure.
//!
//! Note what is *not* here: no retry. A fetch failure is `errored`, Hull does not memoize `errored`
//! (spec §7), and a re-check re-dispatches — so a failed fetch costs one re-check, while a retry loop
//! inside the fetch phase would eat the fetch clock and turn a fast, honest `errored` into a slow one.

use hull_ci_control::callback::BoxFuture;
use hull_ci_control::seams::{FetchError, FetchRequest, Fetcher, VerifiedTree};
use hull_ci_fetch::{FetchBroker, FetchError as BrokerError, VerifyError};

/// Adapts [`FetchBroker`] to the control plane's [`Fetcher`] seam.
pub struct BrokerFetcher {
    broker: FetchBroker,
}

impl BrokerFetcher {
    pub fn new(broker: FetchBroker) -> Self {
        BrokerFetcher { broker }
    }

    pub fn broker(&self) -> &FetchBroker {
        &self.broker
    }
}

impl Fetcher for BrokerFetcher {
    fn fetch<'a>(&'a self, req: &'a FetchRequest) -> BoxFuture<'a, Result<VerifiedTree, FetchError>> {
        Box::pin(async move {
            let stored = self
                .broker
                .ensure_tree(&req.tenant, &req.tree_id, &req.source_url, req.fetch_token.as_deref())
                .await
                .map_err(to_seam_error)?;
            tracing::info!(
                tenant = %req.tenant,
                tree_id = %stored.tree_id,
                cached = stored.cached,
                "tree ready"
            );
            Ok(VerifiedTree { tree_id: stored.tree_id, path: stored.path, cached: stored.cached })
        })
    }
}

/// Map a broker failure onto the seam's error.
///
/// The mismatch case is called out separately because it is the one failure that is *about the
/// archive* rather than about the transfer: the source served bytes that are not the tree it named.
/// It is still not `red` — we never ran anything, so we have no statement about the code — but an
/// operator reading `errored` needs to be able to tell "Hull sent us the wrong bytes" apart from
/// "the connection dropped", and the seam has a variant for exactly that.
fn to_seam_error(e: BrokerError) -> FetchError {
    match e {
        BrokerError::Verify(VerifyError::Mismatch { .. }) => FetchError::TreeMismatch,
        other => FetchError::Failed(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mismatched_archive_is_its_own_failure_not_a_generic_one() {
        let mismatch = BrokerError::Verify(VerifyError::Mismatch {
            expected: "a".repeat(64),
            actual: "b".repeat(64),
        });
        assert!(matches!(to_seam_error(mismatch), FetchError::TreeMismatch));

        let http = BrokerError::Http { status: 502, url: "https://hull.example/tar".into() };
        match to_seam_error(http) {
            FetchError::Failed(detail) => assert!(detail.contains("502")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
