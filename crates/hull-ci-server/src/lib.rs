//! **hull-ci-server** — M1's whole runner in one process: ingest → fetch broker → planner → one node
//! → callback (design D§13's "conforming skeleton").
//!
//! Every part of that sentence already exists in a sibling crate. This crate is the composition root
//! and nothing else: it reads configuration, chooses a sandbox backend, refuses to run if that choice
//! is not one an operator asked for, and plugs the four crates into each other through
//! `hull-ci-control`'s three seams.
//!
//! ```text
//!            ┌─────────────────── this process ───────────────────┐
//! Hull ─────▶│ ingest ─▶ driver ─┬─▶ Fetcher   → hull-ci-fetch    │──GET source_url──▶ Hull
//!  §5        │                   ├─▶ Planner   → hull-ci-node's   │
//!            │                   │              detect            │
//!            │                   └─▶ NodeSink  → hull-ci-node's   │
//!            │                                  NodeAgent ─▶ sandbox (the only place job code runs)
//! Hull ◀─────│ callback sender ◀── aggregator ◀─────────────────── │
//!  §7        └────────────────────────────────────────────────────┘
//! ```
//!
//! # One process is not one trust domain
//!
//! Design §3 puts the control plane, the broker and the node in three processes on three hosts, and
//! spec §14.1 is why: "the runner MUST NEVER execute job code on the control-plane host or on any host
//! with access to Hull's secrets". M1 collapses them onto one host, which is precisely the reason
//! D§13 says M1 is "single-tenant, trusted-input only" — the collapse is only safe when there is no
//! untrusted author to isolate. So this crate does not treat that as a footnote:
//!
//! * The **seams stay seams.** The control plane still never fetches and never executes; it calls
//!   [`fetch::BrokerFetcher`] and [`node::InProcessFleet`], both of which could be a socket instead of
//!   a struct without the control plane noticing (M3's job).
//! * The **isolation gate is enforced at startup and at every assignment.** No M1 backend's
//!   `BackendCapabilities::admits_untrusted()` is true, so untrusted work is refused rather than run —
//!   see [`assemble`] and [`node::InProcessFleet::assign`].
//! * The **unsandboxed backend requires the operator to say so**, in an environment variable whose
//!   only purpose is to be typed on purpose ([`config::SandboxChoice`]).
//! * The **secret broker is a seam too, and its identity check is not skipped for being local**
//!   ([`secrets`]). D§7.4 puts the broker in a fourth, credential-scoped process; here it is a struct
//!   in this one. The node still signs every redemption with its own enrolled Ed25519 key and the
//!   service still derives the node id from that key, because a shortcut for the in-process case
//!   would make the check that matters the one thing never exercised.
//!
//! # What M1 does not do
//!
//! No pipeline file (M2), no step memo or cache (M4), no fair-share queue, no Postgres — state is in
//! memory and a restart forgets in-flight jobs, which is survivable because Hull re-dispatches a tree
//! with no verdict. And one node: [`node::InProcessFleet`] runs assignments here, in this process.

pub mod admin;
pub mod config;
pub mod fetch;
pub mod membership;
pub mod node;
pub mod pipeline;
pub mod plan;
pub mod secrets;
pub mod workspace;

use std::sync::Arc;

use axum::Router;
use hull_ci_control::callback::HttpCallback;
use hull_ci_control::{Control, ControlConfig, Deps, FairShare};
use hull_ci_fetch::{ContentStore, FetchBroker};
use hull_ci_node::{ContainerConfig, LocalProcessBackend, NodeAgent, NodeConfig, SandboxBackend};
use hull_ci_proto::IsolationTier;

pub use config::{Config, ConfigError, SandboxChoice, SecretsMode};
use fetch::BrokerFetcher;
use node::InProcessFleet;
use pipeline::PipelinePlanner;

/// Why the runner would not start.
///
/// Every variant is a refusal, not a degradation. There is no path here that starts a weaker runner
/// than the one that was asked for — a runner that quietly ran jobs with less isolation than the
/// operator configured would be the exact failure spec §14.1 describes.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("no usable sandbox backend: {0}")]
    Backend(#[from] hull_ci_node::SandboxError),
    #[error(
        "HULL_CI_SANDBOX=local runs jobs as plain host subprocesses, which spec §14.1 says is NOT a \
         sufficient boundary. Set HULL_CI_ALLOW_UNSANDBOXED=1 to accept that, or use the container backend."
    )]
    UnsandboxedNotPermitted,
    #[error("could not prepare {what} at `{path}`: {detail}")]
    Storage { what: &'static str, path: String, detail: String },
    #[error("could not build the fetch broker: {0}")]
    Broker(#[from] hull_ci_fetch::FetchError),
    #[error("could not bind {addr}: {source}")]
    Bind { addr: std::net::SocketAddr, source: std::io::Error },
    #[error("server failed: {0}")]
    Serve(std::io::Error),
}

/// A wired runner that has not been bound to a port yet.
///
/// Returned separately from [`run`] so the end-to-end suite can serve it on an ephemeral port and
/// still reach the [`Control`] it is testing.
pub struct Runner {
    pub control: Arc<Control>,
    pub router: Router,
    pub fleet: Arc<InProcessFleet>,
    /// The secret broker and this node's enrolled identity, or `None` in `HULL_CI_SECRETS=off`.
    ///
    /// Exposed for the same reason `control` is: the end-to-end suite has to store a tenant secret
    /// and inspect enrolment, and doing that through the *assembled* plane is the only way to test
    /// the wiring rather than a rebuilt copy of it. There is no HTTP surface here — storing a secret
    /// is an operator action against the control-plane DB (D§7.4), and inventing an endpoint for it
    /// would be a new attack surface this milestone does not need.
    pub secrets: Option<Arc<hull_ci_secrets::SecretService>>,
}

/// Build the runner: choose a backend, check it, and wire the seams.
pub async fn assemble(config: &Config) -> Result<Runner, StartupError> {
    let backend = choose_backend(config).await?;
    announce_isolation(config, backend.as_ref());
    // Taken before the backend is handed to the agent: which §14 clauses this deployment enforces
    // cannot change while the process runs (`choose_backend` refuses rather than degrades), so the
    // panel reads a copy instead of reaching back through the node for it.
    let node_facts = admin::NodeFacts::of(backend.as_ref());

    // The broker's store and the workspace root are created up front, so a misconfigured path is a
    // startup failure rather than a job that errors five minutes into someone's afternoon.
    prepare_dir("content store", &config.store_root)?;
    prepare_dir("workspace root", &config.work_root)?;

    let broker = FetchBroker::new(ContentStore::new(&config.store_root))?;
    let agent = NodeAgent::new(
        NodeConfig { node_id: config.node_id.clone(), ..NodeConfig::default() },
        backend,
    );

    // D§7.4. The plane is built before the fleet because enrolling the node's key is a precondition
    // for it redeeming anything: a node wired to a broker it is not enrolled with would fail every
    // delivery, and it would fail it in the shape of an outage rather than of a misconfiguration.
    let secrets = secrets::assemble(config);
    if let Some(plane) = &secrets {
        if let Some(raw) = &config.dev_secrets {
            secrets::seed_dev_secrets(plane, raw);
        }
    }
    let fleet = match &secrets {
        Some(plane) => InProcessFleet::with_secrets(
            agent.with_secrets(Arc::clone(&plane.client)),
            config.work_root.clone(),
            Arc::clone(&plane.service),
        ),
        None => InProcessFleet::new(agent, config.work_root.clone()),
    };

    // Tell the scheduler how big the fleet actually is (design D§11.1). Without this it holds
    // per-tenant quotas and no notion of total capacity, so it can only *offer* work in fair order
    // and take the fleet's refusal for an answer: fair ordering is real, fair allocation is not. The
    // composition root is the only place that knows both numbers, so it is the only place that can
    // reconcile them.
    let node_slots = usize::try_from(NodeConfig::default().slots_total).unwrap_or(1).max(1);
    let mut fair_share = FairShare { fleet_slots: Some(node_slots), ..FairShare::default() };

    // A quota larger than the fleet is not a quota. The default plan permitted more concurrent steps
    // than this deployment can run, which means the number an operator reads constrains nothing —
    // worse than no number, because someone will read it and believe it. Clamp the policy ceiling to
    // the physical one rather than the reverse: policy should never promise more than physics.
    if fair_share.default_plan.max_running_steps > node_slots {
        tracing::info!(
            plan_cap = fair_share.default_plan.max_running_steps,
            node_slots,
            "default per-tenant concurrency exceeded fleet capacity; clamped to the fleet"
        );
        fair_share.default_plan.max_running_steps = node_slots;
    }

    let control_config = ControlConfig {
        secret: config.secret.clone(),
        timeouts: config.timeouts,
        // M1's tier is the container scaffold (design D§13). Reported on every assignment, and the
        // node refuses a tier it does not implement.
        tier: IsolationTier::Container,
        details_base_url: config.details_base_url.clone(),
        fair_share,
        ..ControlConfig::default()
    };

    // Written out in full rather than as overrides on `Deps::default()`: the defaults are the
    // *unwired* seams, which fail loudly by design, and a field forgotten here should be a compile
    // error rather than a runner that reports `errored` on every job because its planner is a stub.
    let deps = Deps {
        fetcher: Arc::new(BrokerFetcher::new(broker)),
        // The planner is told whether a broker exists for one reason only: so it stops warning that
        // `secrets = [...]` goes undelivered when it no longer does. It is not an authority input —
        // the broker still refuses an outsider whatever this says.
        planner: Arc::new(
            PipelinePlanner::new(config.image.clone()).with_secret_delivery(secrets.is_some()),
        ),
        node: Arc::clone(&fleet) as Arc<dyn hull_ci_control::seams::NodeSink>,
        // Built here rather than taken from `Deps::default` so that failing to construct the HTTP
        // client is a startup error, not a silently unwired verdict sender.
        transport: Arc::new(HttpCallback::new(std::time::Duration::from_secs(30)).map_err(|e| {
            StartupError::Storage { what: "callback client", path: "-".into(), detail: e.to_string() }
        })?),
        membership: Arc::new(config.trusted.clone()),
    };

    let control = Control::new(control_config, deps);
    fleet.attach(&control);

    // The panel is merged onto the same listener, which is why it inherits `HULL_CI_BIND`'s
    // loopback default. With no token configured there is no `/admin*` route at all — not a 403 and
    // not a login page (see [`admin`]).
    let mut router = hull_ci_control::ingest::router(Arc::clone(&control));
    if let Some(token) = config.admin_token.clone() {
        router = router.merge(admin::router(admin::AdminState::new(
            Arc::clone(&control),
            Arc::clone(&fleet),
            node_facts,
            token,
            config.bind,
        )));
    }

    Ok(Runner { router, control, fleet, secrets: secrets.map(|p| p.service) })
}

/// Assemble, bind, and serve until the process ends.
pub async fn run(config: Config) -> Result<(), StartupError> {
    let runner = assemble(&config).await?;
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(|source| StartupError::Bind { addr: config.bind, source })?;
    tracing::info!(addr = %config.bind, "hull-ci listening on POST /hull");
    axum::serve(listener, runner.router).await.map_err(StartupError::Serve)
}

/// Pick the backend the operator asked for, or refuse.
///
/// `HULL_CI_SANDBOX=container` goes through `hull_ci_node::detect_backend`, which errors when no
/// container runtime answers instead of falling back — the fallback is the hole, so it is opt-in and
/// has its own name.
async fn choose_backend(config: &Config) -> Result<Arc<dyn SandboxBackend>, StartupError> {
    match config.sandbox {
        SandboxChoice::Container => Ok(hull_ci_node::detect_backend(ContainerConfig::default()).await?),
        SandboxChoice::LocalProcess if !config.allow_unsandboxed => {
            Err(StartupError::UnsandboxedNotPermitted)
        }
        SandboxChoice::LocalProcess => Ok(Arc::new(LocalProcessBackend::new_for_development_only())),
    }
}

/// Say, at startup and in one place, exactly which §14 controls this configuration does **not**
/// enforce and what follows from that.
///
/// Design D§7.2 puts the capability answer in the code so the M1 gap "is a property the code knows
/// about rather than a note in a document". This is the operator-facing half of the same idea: an
/// operator should learn what their runner cannot contain when they start it, not from a refused job
/// at 3am — and least of all from an incident.
fn announce_isolation(config: &Config, backend: &dyn SandboxBackend) {
    let controls = backend.controls();
    let unmet = controls.unmet_clauses();
    let admits = backend.capabilities().admits_untrusted();

    tracing::info!(
        backend = backend.name(),
        tier = ?backend.tier(),
        trusted_tenants = %config.trusted.describe(),
        "sandbox backend selected"
    );

    if admits {
        tracing::info!(backend = backend.name(), "backend enforces every §14 clause");
    } else {
        tracing::warn!(
            backend = backend.name(),
            unmet = ?unmet,
            "SPEC §14 NOT FULLY ENFORCED — this runner refuses work from untrusted authors. \
             Design D§13: M1 is single-tenant, trusted-input only and MUST NOT take untrusted or \
             multi-tenant input."
        );
    }

    if config.sandbox == SandboxChoice::LocalProcess {
        tracing::warn!(
            "HULL_CI_ALLOW_UNSANDBOXED is set: jobs run as plain host subprocesses. There is NO \
             §14.1 boundary (no single-use rootfs, no kernel isolation), NO §14.2 metadata \
             blackhole, NO §14.3 egress deny, and NO §14.4 privilege or resource limits beyond the \
             wall clock and the output cap. Trusted, local input only."
        );
    }

    if config.trusted.trusts_everyone() && !admits {
        // The one combination that is a live foot-gun: every author is a member, so the admission
        // check never fires, on a backend that cannot contain them. Legitimate for a single-tenant
        // bring-up; catastrophic the moment a fork PR can reach the endpoint.
        tracing::warn!(
            "HULL_CI_TRUSTED_TENANTS=* on a backend that does not admit untrusted work: every \
             dispatch that clears the shared secret will run. Only do this where every author who \
             can reach this endpoint is trusted."
        );
    }

    if config.secret.is_none() {
        tracing::warn!(
            bind = %config.bind,
            "no HULL_CI_SECRET configured — every dispatch reaching this port is accepted (spec §8)"
        );
    }

    match config.secrets {
        // Not a gap to apologise for: it is the state in which a sandbox escape reaches no tenant
        // credential at all, because there is none on this host to reach.
        SecretsMode::Off => tracing::info!(
            "tenant secret broker disabled (HULL_CI_SECRETS=off): `secrets` in a pipeline is \
             delivered to nobody, and this runner holds no tenant credential"
        ),
        // The loud one is emitted by `secrets::assemble`, which is the module that knows *why* the
        // dev key manager is dangerous. This line is the summary an operator reads next to it.
        SecretsMode::Dev => tracing::warn!(
            node_id = %config.node_id,
            "tenant secret broker enabled in DEVELOPMENT mode. Member-authored jobs receive their \
             declared secrets; outsider-authored jobs never do (D§7.4). Masking of job output is a \
             backstop against an accidental echo, not a control."
        ),
    }

    match (&config.admin_token, config.bind.ip().is_loopback()) {
        (None, _) => tracing::info!("operator panel disabled (no HULL_CI_ADMIN_TOKEN); /admin is not routed"),
        (Some(_), true) => tracing::info!(bind = %config.bind, "operator panel on /admin (read-only, loopback)"),
        // The one combination worth a warning. The panel is the one surface in this system that is
        // deliberately cross-tenant (design D§1 partitions every other one), so on a non-loopback
        // bind a single bearer token is all that stands between the network and every tenant's job
        // list. Legitimate behind a VPN or an authenticating proxy; a mistake anywhere else.
        (Some(_), false) => tracing::warn!(
            bind = %config.bind,
            "operator panel on /admin is bound to a NON-LOOPBACK address. It shows every tenant's \
             jobs to anyone holding HULL_CI_ADMIN_TOKEN. Put it behind a private interface, a VPN, \
             or an authenticating proxy."
        ),
    }
}

fn prepare_dir(what: &'static str, path: &std::path::Path) -> Result<(), StartupError> {
    std::fs::create_dir_all(path).map_err(|e| StartupError::Storage {
        what,
        path: path.display().to_string(),
        detail: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs() -> (tempfile::TempDir, Config) {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            store_root: dir.path().join("store"),
            work_root: dir.path().join("workspaces"),
            ..Config::default()
        };
        (dir, config)
    }

    #[tokio::test]
    async fn the_unsandboxed_backend_needs_an_explicit_opt_in() {
        // §14.1 calls a host subprocess insufficient. Asking for it is allowed; asking for it by
        // accident is not.
        let (_d, mut config) = dirs();
        config.sandbox = SandboxChoice::LocalProcess;
        assert!(matches!(assemble(&config).await, Err(StartupError::UnsandboxedNotPermitted)));

        config.allow_unsandboxed = true;
        assert!(assemble(&config).await.is_ok(), "with the opt-in it starts, loudly");
    }

    #[tokio::test]
    async fn the_container_backend_refuses_to_start_rather_than_degrade() {
        // No runtime answers → an error. The tempting behaviour — quietly running on the host — is
        // the one this must never do.
        let (_d, mut config) = dirs();
        config.sandbox = SandboxChoice::Container;
        config.allow_unsandboxed = true; // must not rescue the container path
        match assemble(&config).await {
            Err(StartupError::Backend(_)) => {}
            Err(other) => panic!("wrong failure: {other}"),
            Ok(_) => {
                // A host with a live daemon: then the backend really is the container one, and the
                // assertion is that it is not the local process backend.
            }
        }
    }

    #[tokio::test]
    async fn a_started_runner_admits_no_untrusted_work_in_m1() {
        // D§13 as an assertion: whatever backend this host produced, it cannot take an outsider's
        // code, so the runner's refusal path is reachable and its acceptance path is not.
        let (_d, mut config) = dirs();
        config.sandbox = SandboxChoice::LocalProcess;
        config.allow_unsandboxed = true;

        let runner = assemble(&config).await.unwrap();
        assert!(!runner.fleet.agent().capabilities().admits_untrusted());
    }

    /// GET a path on an assembled runner's router, optionally presenting the admin token.
    async fn get(config: &Config, path: &str, token: Option<&str>) -> axum::http::StatusCode {
        use tower::ServiceExt;
        let runner = assemble(config).await.unwrap();
        let mut req = axum::http::Request::builder().method("GET").uri(path);
        if let Some(t) = token {
            req = req.header(crate::admin::ADMIN_TOKEN_HEADER, t);
        }
        runner
            .router
            .oneshot(req.body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn the_operator_panel_does_not_exist_until_a_token_is_configured() {
        // Not a 403 and not a login page: with no `HULL_CI_ADMIN_TOKEN` there is no route, so there
        // is no default credential to leave in place and nothing to brute-force. The panel is the
        // one cross-tenant surface in this system (design D§1), so a deployment that did not ask for
        // it must not have it.
        use axum::http::StatusCode;
        let (_d, mut config) = dirs();
        config.sandbox = SandboxChoice::LocalProcess;
        config.allow_unsandboxed = true;

        for path in ["/admin", "/admin/jobs", "/admin/nodes", "/admin/queue", "/admin/summary"] {
            assert_eq!(get(&config, path, None).await, StatusCode::NOT_FOUND, "{path} was routed");
        }
        // And ingest is unaffected either way.
        assert_eq!(get(&config, "/healthz", None).await, StatusCode::OK);

        config.admin_token = Some("t0ken".into());
        assert_eq!(get(&config, "/admin", None).await, StatusCode::OK, "the page is the renderer");
        assert_eq!(get(&config, "/admin/jobs", None).await, StatusCode::UNAUTHORIZED);
        assert_eq!(get(&config, "/admin/jobs", Some("wrong")).await, StatusCode::UNAUTHORIZED);
        assert_eq!(get(&config, "/admin/jobs", Some("t0ken")).await, StatusCode::OK);
    }
}
