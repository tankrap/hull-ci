//! Wiring the package proxy into the composition root (spec §14.3, D§7.3/7.4).
//!
//! This module is where the two independently-enforced halves of §14.3's exception meet:
//!
//! * **The proxy process** — an allowlist, tenant credentials, per-job grants. Started here when
//!   `HULL_CI_PROXY=on`.
//! * **The sandbox network** — the thing that makes the proxy the *only* reachable destination.
//!   Configured here, but **verified by the node** ([`hull_ci_node::probe_network_posture`]), which
//!   is the only component in a position to find out by trying.
//!
//! Keeping them independent is deliberate. Neither can talk the other into a claim: a proxy with a
//! perfect allowlist on a wide-open network reports `egress_deny: false`, and a locked-down network
//! with no proxy on it reports `egress_deny: true` and simply runs jobs that cannot resolve anything.
//! Both are safe. The dangerous state — a job with a network and a backend that says it has none —
//! is unreachable, because the backend's answer comes from a probe rather than from this file.
//!
//! # An operator has to opt in twice, and that is not an accident
//!
//! `HULL_CI_PROXY=on` starts the proxy; `HULL_CI_PROXY_NETWORK` moves jobs off `--network none`.
//! Setting one without the other gets a warning and a safe outcome (a proxy nobody can reach, or jobs
//! with no network). §14.3 makes egress-deny the default and the proxy the exception, so the
//! exception is spelled out in full or it does not happen.

use std::sync::Arc;
use std::time::Duration;

use hull_ci_node::env::EnvVar;
use hull_ci_node::{NetworkMode, PackageAccess, ProxyNetwork};
use hull_ci_proxy::credentials::UpstreamCredentials;
use hull_ci_proxy::{JobProxyEndpoint, PackageProxy, ProxyConfig, ProxyMode, RateLimit};

/// A running package proxy, and the node-facing handle that mints its per-job grants.
pub struct PackagePlane {
    pub proxy: Arc<PackageProxy>,
    /// The sandbox network the node should attach jobs to, when one is configured.
    pub network: Option<ProxyNetwork>,
    /// What jobs are told to talk to.
    endpoint: Option<JobProxyEndpoint>,
    labels: Vec<String>,
    rate: RateLimit,
}

impl std::fmt::Debug for PackagePlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PackagePlane")
            .field("upstreams", &self.labels)
            .field("network", &self.network.as_ref().map(|n| &n.network))
            .finish()
    }
}

/// Build the proxy, or don't.
///
/// Returns `None` in [`ProxyMode::Off`] — and `None` means the node is never given a
/// [`PackageAccess`], so no job ever receives a grant, and the sandbox network is never configured,
/// so every job stays on `--network none`. The default path through this function changes nothing
/// about the runner at all.
pub fn assemble(config: &ProxyConfig, credentials: Arc<dyn UpstreamCredentials>) -> Option<PackagePlane> {
    if config.mode == ProxyMode::Off {
        return None;
    }
    let labels: Vec<String> = config.allowlist.labels().iter().map(|s| s.to_string()).collect();
    let proxy = Arc::new(PackageProxy::new(config.allowlist.clone(), credentials));

    let network = match (&config.network, &config.endpoint) {
        (Some(network), Some(endpoint)) => Some(ProxyNetwork::new(network, endpoint)),
        // A network with no endpoint would put jobs somewhere with nothing to talk to; an endpoint
        // with no network names an address no sandbox can reach. Both are refused as a *pairing*
        // rather than half-applied.
        _ => None,
    };
    let endpoint = config
        .endpoint
        .as_ref()
        .map(|e| JobProxyEndpoint::new(format!("http://{e}"), String::new()));

    Some(PackagePlane { proxy, network, endpoint, labels, rate: config.rate })
}

impl PackagePlane {
    /// The node-facing seam. `None` when there is no endpoint for a job to be pointed at, because a
    /// grant whose URL nobody can reach is worse than no grant: the job's tools would try the proxy,
    /// fail to connect, and report a build error rather than a configuration one.
    pub fn access(&self) -> Option<Arc<dyn PackageAccess>> {
        let endpoint = self.endpoint.as_ref()?;
        Some(Arc::new(ProxyAccess {
            proxy: Arc::clone(&self.proxy),
            base_url: endpoint.base_url.clone(),
            labels: self.labels.clone(),
            rate: self.rate,
        }))
    }

    /// The sandbox network mode this deployment implies, for the container backend.
    ///
    /// `--network none` whenever a network was not fully configured — which is the same answer the
    /// backend's default gives, so a half-configured proxy costs a warning rather than a job's
    /// isolation.
    pub fn network_mode(&self) -> NetworkMode {
        match &self.network {
            Some(n) => NetworkMode::ProxyOnly(n.clone()),
            None => NetworkMode::None,
        }
    }

    pub fn upstreams(&self) -> &[String] {
        &self.labels
    }

    /// Serve the proxy until the process ends.
    pub async fn serve(&self, listener: tokio::net::TcpListener) -> std::io::Result<()> {
        self.proxy.serve(listener).await
    }
}

/// [`PackageAccess`] over a live [`PackageProxy`].
struct ProxyAccess {
    proxy: Arc<PackageProxy>,
    base_url: String,
    labels: Vec<String>,
    rate: RateLimit,
}

impl std::fmt::Debug for ProxyAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyAccess").field("base_url", &self.base_url).finish()
    }
}

impl PackageAccess for ProxyAccess {
    fn grant(&self, tenant: &str, job_id: &str, lifetime: Duration) -> Vec<EnvVar> {
        if self.labels.is_empty() {
            // An allowlist with nothing on it serves nothing, so a grant against it would authorise
            // nothing. Handing a job registry URLs that will 403 on every request is a worse failure
            // than handing it none.
            return Vec::new();
        }
        let upstreams = self.labels.iter().cloned().collect();
        // A grace margin over the step's wall clock: a grant that expires at the same instant the
        // step is killed would turn an ordinary slow build into an authentication failure partway
        // through resolution, which reads like a proxy outage.
        let expires_at = now_secs() + lifetime.as_secs() + GRANT_GRACE_SECS;
        let (token, grant) = self.proxy.grants().mint(tenant, job_id, upstreams, expires_at, self.rate);
        tracing::info!(
            tenant = %tenant, job = %job_id, grant = %grant.grant_id, upstreams = ?self.labels,
            "minted a package-proxy grant"
        );
        JobProxyEndpoint::new(&self.base_url, token.expose()).env_vars(&self.labels)
    }

    fn release(&self, job_id: &str) {
        let dropped = self.proxy.grants().revoke_job(job_id);
        if dropped > 0 {
            tracing::info!(job = %job_id, dropped, "released package-proxy grants with the job");
        }
    }
}

/// How long a grant outlives its step's wall clock. See [`ProxyAccess::grant`].
const GRANT_GRACE_SECS: u64 = 60;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        // A clock before the epoch makes every grant look expired, which fails closed: jobs get
        // refusals rather than a token that never dies.
        .unwrap_or(0)
}

/// Build the proxy's credential source from `HULL_CI_DEV_SECRETS`.
///
/// **Development only**, and the same seam and the same warning as
/// [`crate::secrets::seed_dev_secrets`]: D§7.4 says "the pull/proxy credential is just a tenant
/// secret", and the production answer is therefore the broker, reached through
/// [`UpstreamCredentials`] — which is a trait for exactly this reason.
///
/// It is not the broker *yet* because the broker's delivery model is a job-scoped, single-use
/// capability redeemed by a node at exec time (D§7.4), and the proxy needs a tenant's credential on
/// an arbitrary request from an arbitrary job. Bridging those two is a design decision about who
/// mints the proxy's own capability and how often, not a wiring detail — so rather than quietly
/// adding a plaintext read path to the broker and calling it done, this stays an explicitly
/// dev-only source and the seam stays where the real one goes.
pub fn dev_credentials(raw: Option<&str>) -> Arc<dyn UpstreamCredentials> {
    let mut creds = hull_ci_proxy::StaticCredentials::new();
    for entry in raw.unwrap_or_default().split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let Some((qualified, value)) = entry.split_once('=') else { continue };
        let Some((tenant, name)) = qualified.trim().split_once('/') else { continue };
        // The name, never the value.
        tracing::info!(tenant, name, "package proxy holds a development upstream credential");
        creds = creds.with(tenant, name, value);
    }
    Arc::new(creds)
}

/// Say, at startup, exactly what the package-proxy configuration does and does not buy.
pub fn announce(plane: Option<&PackagePlane>, config: &ProxyConfig) {
    let Some(plane) = plane else {
        tracing::info!(
            "package proxy disabled (HULL_CI_PROXY=off): every job runs with `--network none` and \
             no outbound network at all (§14.3's default)"
        );
        return;
    };

    if !config.serves_anything() {
        tracing::warn!(
            "HULL_CI_PROXY=on with an empty HULL_CI_PROXY_UPSTREAMS: the proxy is listening and will \
             refuse every request. Jobs will not be able to resolve anything."
        );
    }

    match (&plane.network, plane.access().is_some()) {
        (Some(network), true) => tracing::warn!(
            network = %network.network,
            endpoint = %network.endpoint,
            upstreams = ?plane.upstreams(),
            "package proxy ENABLED: jobs no longer run with `--network none`. Whether this network \
             actually denies egress is decided by the node's live posture probe, NOT by this \
             configuration — check the `egress_deny` capability the backend reports (§14.3)."
        ),
        _ => tracing::warn!(
            "HULL_CI_PROXY=on but HULL_CI_PROXY_NETWORK/HULL_CI_PROXY_ENDPOINT are not both set: \
             jobs stay on `--network none` and cannot reach the proxy. Set both, or set \
             HULL_CI_PROXY=off."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hull_ci_proxy::config::parse_upstreams;
    use hull_ci_proxy::StaticCredentials;

    fn creds() -> Arc<dyn UpstreamCredentials> {
        Arc::new(StaticCredentials::new().with("acme", "NPM_TOKEN", "s3cret"))
    }

    fn on(network: Option<&str>, endpoint: Option<&str>) -> ProxyConfig {
        ProxyConfig {
            mode: ProxyMode::On,
            allowlist: parse_upstreams("npm=https://registry.npmjs.org").unwrap(),
            network: network.map(str::to_string),
            endpoint: endpoint.map(str::to_string),
            ..ProxyConfig::default()
        }
    }

    #[test]
    fn the_default_configuration_builds_no_proxy_at_all() {
        // The whole default path: no proxy, therefore no `PackageAccess`, therefore no grant, and
        // `network_mode` never gets asked. §14.3's default is what an unconfigured deployment gets.
        assert!(assemble(&ProxyConfig::default(), creds()).is_none());
    }

    #[test]
    fn a_proxy_without_a_network_leaves_every_job_on_network_none() {
        // The half-configured case. Safe, and loud — never a job with a network and a backend that
        // does not know it.
        let plane = assemble(&on(None, None), creds()).expect("a proxy");
        assert_eq!(plane.network_mode(), NetworkMode::None);
        assert!(plane.access().is_none(), "no endpoint means no grant to hand out");
    }

    #[test]
    fn a_network_without_an_endpoint_is_refused_as_a_pairing() {
        // A network with nothing to talk to on it is strictly worse than no network: the job has a
        // netns it cannot use and no diagnosis.
        let plane = assemble(&on(Some("sandbox"), None), creds()).expect("a proxy");
        assert_eq!(plane.network_mode(), NetworkMode::None);
        let plane = assemble(&on(None, Some("10.0.0.1:3128")), creds()).expect("a proxy");
        assert_eq!(plane.network_mode(), NetworkMode::None);
    }

    #[test]
    fn a_fully_configured_proxy_hands_the_node_an_unprobed_network() {
        // The critical handoff: the composition root supplies the *configuration*, and the posture
        // is deliberately absent — only the node's live probe can fill it in, so nothing here can
        // cause a capability to be claimed.
        let plane = assemble(&on(Some("sandbox"), Some("172.18.0.1:3128")), creds()).expect("a proxy");
        match plane.network_mode() {
            NetworkMode::ProxyOnly(n) => {
                assert_eq!(n.network, "sandbox");
                assert_eq!(n.endpoint, "172.18.0.1:3128");
                assert!(n.posture.is_none(), "the composition root must not assert a posture");
            }
            other => panic!("expected a proxy network, got {other:?}"),
        }
        assert!(plane.access().is_some());
    }

    #[test]
    fn a_grant_produces_registry_urls_that_point_at_the_proxy_and_carry_the_token() {
        let plane = assemble(&on(Some("sandbox"), Some("172.18.0.1:3128")), creds()).expect("a proxy");
        let access = plane.access().expect("access");
        let env = access.grant("acme", "job-1", Duration::from_secs(600));

        assert!(!env.is_empty());
        let registry = env.iter().find(|(n, _)| n == "npm_config_registry").expect("npm registry");
        assert!(registry.1.starts_with("http://172.18.0.1:3128/j/hpkg_"), "{}", registry.1);
        assert!(registry.1.ends_with("/u/npm/"), "{}", registry.1);
        // Nothing credential-shaped by name, so §14.2's backstop admits it into a sandbox.
        for (name, _) in &env {
            assert!(!hull_ci_node::env::is_forbidden_name(name), "{name}");
        }
        assert_eq!(plane.proxy.grants().len(), 1);
    }

    #[test]
    fn releasing_a_job_kills_its_grant() {
        // §14.1 applied to a credential: nothing survives the job, including the one piece of its
        // state that does not live in the rootfs the runtime destroys.
        let plane = assemble(&on(Some("sandbox"), Some("172.18.0.1:3128")), creds()).expect("a proxy");
        let access = plane.access().expect("access");
        access.grant("acme", "job-1", Duration::from_secs(600));
        access.grant("acme", "job-2", Duration::from_secs(600));
        assert_eq!(plane.proxy.grants().len(), 2);

        access.release("job-1");
        assert_eq!(plane.proxy.grants().len(), 1, "and only that job's");
        access.release("job-2");
        assert!(plane.proxy.grants().is_empty());
    }

    #[test]
    fn an_empty_allowlist_grants_nothing_rather_than_urls_that_403() {
        let config = ProxyConfig {
            mode: ProxyMode::On,
            network: Some("sandbox".into()),
            endpoint: Some("172.18.0.1:3128".into()),
            ..ProxyConfig::default()
        };
        let plane = assemble(&config, creds()).expect("a proxy");
        let env = plane.access().expect("access").grant("acme", "job-1", Duration::from_secs(60));
        assert!(env.is_empty(), "no upstreams means no registry URLs, not URLs that fail");
        assert!(plane.proxy.grants().is_empty(), "and no grant was minted");
    }

    #[test]
    fn a_grant_expires_with_its_step_plus_a_grace_margin() {
        // D§7.4's "short TTLs that auto-expire" as the primary revocation path: even if `release`
        // never runs — a node that crashed, a process killed mid-step — the token is dying on its
        // own. Asserted through `sweep`, which drops exactly the records that are past expiry.
        let plane = assemble(&on(Some("sandbox"), Some("172.18.0.1:3128")), creds()).expect("a proxy");
        let step = Duration::from_secs(600);
        plane.access().expect("access").grant("acme", "job-1", step);
        let minted_at = now_secs();

        // Still live while the step could still be running.
        assert_eq!(plane.proxy.grants().sweep(minted_at + step.as_secs()), 0);
        assert_eq!(plane.proxy.grants().len(), 1);

        // And gone once the step's wall clock plus the margin has passed.
        assert_eq!(plane.proxy.grants().sweep(minted_at + step.as_secs() + GRANT_GRACE_SECS + 1), 1);
        assert!(plane.proxy.grants().is_empty(), "no grant outlives its job by more than the margin");
    }
}
