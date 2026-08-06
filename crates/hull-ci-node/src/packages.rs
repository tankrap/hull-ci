//! The node's seam to the package proxy (§14.3, D§7.3/7.4).
//!
//! # Why this is a trait and not a dependency
//!
//! The node's relationship to the package proxy is deliberately thin: it puts a sandbox on a network
//! where the proxy is reachable, and it tells the job's tools where to look. It does not talk to the
//! proxy, hold its allowlist, or know an upstream credential exists. Design D§7.1 is emphatic about
//! what a node must not hold — "there is nothing in its memory a successful sandbox escape would want
//! except the ability to be a node" — and the proxy holds *tenant registry credentials*, which is
//! exactly the sort of thing that sentence is about.
//!
//! So the proxy lives in its own crate and its own process, and this trait is the whole of the node's
//! knowledge of it: mint a grant for a job, hand back some environment variables, revoke the grant
//! when the job ends. A node that escapes with a grant in memory has stolen the right to resolve
//! packages for one job that is already running.
//!
//! # Why the grant is released when the step ends
//!
//! §14.1's rule is that nothing survives a job — "a planted binary, a poisoned cache, a lingering
//! process". A live bearer token for a sandbox that no longer exists is the same category of thing,
//! and it is the one piece of a job's state that does **not** live inside the rootfs the runtime
//! destroys. So [`PackageAccess::release`] is called on every exit path, including the failing ones.

use std::time::Duration;

use crate::env::EnvVar;

/// A job's package-proxy access: minted at spawn, released when the step ends.
pub trait PackageAccess: Send + Sync + std::fmt::Debug {
    /// Mint a grant for one job and return the environment variables that point its package managers
    /// at the proxy.
    ///
    /// Returning the environment rather than a token is the point: the node never has to know the
    /// grant's shape, which URL scheme the proxy serves, or which ecosystems are configured. An empty
    /// vector is a valid answer and means "this job gets no package access", which is what a
    /// deployment with an empty allowlist should produce.
    ///
    /// `lifetime` is the step's wall clock. The grant expires with it, so D§7.4's "short TTL as the
    /// primary revocation mechanism" holds even if [`release`](Self::release) never runs — a node
    /// that crashes mid-step leaves a token that is already dying.
    fn grant(&self, tenant: &str, job_id: &str, lifetime: Duration) -> Vec<EnvVar>;

    /// Drop every grant for this job. Called on all exit paths.
    fn release(&self, job_id: &str);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct Recorder {
        granted: Mutex<Vec<String>>,
        released: Mutex<Vec<String>>,
    }

    impl PackageAccess for Recorder {
        fn grant(&self, _tenant: &str, job_id: &str, _lifetime: Duration) -> Vec<EnvVar> {
            self.granted.lock().unwrap().push(job_id.to_string());
            vec![("npm_config_registry".into(), format!("http://p/j/tok-{job_id}/u/npm/"))]
        }

        fn release(&self, job_id: &str) {
            self.released.lock().unwrap().push(job_id.to_string());
        }
    }

    #[test]
    fn the_seam_hands_back_an_environment_and_nothing_else() {
        // The property that keeps the node ignorant: what comes back is variables, so the node never
        // learns what a grant looks like or that an upstream credential exists at all.
        let r = Recorder::default();
        let env = r.grant("acme", "job-1", Duration::from_secs(60));
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].0, "npm_config_registry");
        // Nothing credential-shaped by name, so §14.2's backstop lets it into a sandbox.
        assert!(!crate::env::is_forbidden_name(&env[0].0));
        r.release("job-1");
        assert_eq!(&*r.released.lock().unwrap(), &["job-1"]);
    }

    #[test]
    fn no_package_access_means_an_empty_environment_not_a_failure() {
        // A deployment with the proxy off, or with an empty allowlist, produces no variables — and a
        // job that then cannot resolve anything is the correct outcome under egress-deny, not an
        // error the node should invent.
        #[derive(Debug)]
        struct None_;
        impl PackageAccess for None_ {
            fn grant(&self, _: &str, _: &str, _: Duration) -> Vec<EnvVar> {
                Vec::new()
            }
            fn release(&self, _: &str) {}
        }
        assert!(None_.grant("acme", "job-1", Duration::from_secs(1)).is_empty());
    }
}
