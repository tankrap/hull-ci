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
//! No pipeline file (M2), no step memo or cache (M4), no fair-share queue. And one node:
//! [`node::InProcessFleet`] runs assignments here, in this process.
//!
//! Postgres is now optional rather than absent, and only for the two things a second replica cannot
//! decide alone — the `(repo, tree_id)` claim and the step claim ([`claims`], M5 phase 1). The job
//! record itself is still this process's. Off unless `HULL_CI_POSTGRES_URL` says otherwise, and the
//! default build does not link a driver.
//!
//! What a restart forgets is now a **choice**, not a fact. The line above used to end "…and a restart
//! forgets in-flight jobs, which is survivable because Hull re-dispatches a tree with no verdict",
//! and that second clause was simply wrong: spec §10 says Hull neither polls us nor times a dispatched
//! job out, and it clears its in-flight set only when a callback arrives, so a forgotten job leaves a
//! tree wedged until a human forces a rerun. [`journal`] is the write-ahead outbox that closes it —
//! off by default for compatibility, and drained at startup by [`journal::recover`] when it is on.

pub mod admin;
pub mod claims;
pub mod config;
pub mod fetch;
pub mod journal;
pub mod membership;
pub mod memo;
pub mod node;
pub mod pipeline;
pub mod proxy;
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
    /// The write-ahead journal was asked for and could not be opened.
    ///
    /// A refusal, like every other variant here, and for the sharpest version of the usual reason: a
    /// runner that started without the journal an operator configured would accept dispatches it
    /// cannot answer after a restart, while the operator believes otherwise. Degrading here does not
    /// lose a feature, it loses jobs.
    #[error("could not open the write-ahead journal: {0}")]
    Journal(#[from] hull_ci_control::JournalError),
    /// The shared claim store was asked for and could not be had — see [`claims::assemble`].
    ///
    /// The refusal *is* the feature. Every other way of handling a misconfigured claim store ends
    /// with two replicas that each believe they are the only one: every tree dispatched twice, every
    /// step run twice, two verdicts racing to one `callback_url`, and nothing in the logs to say so.
    /// A runner that will not start is loud, immediate, and fixable.
    #[error("could not set up the shared claim store: {0}")]
    Claims(String),
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
    /// The assembled fetch seam, and through it the broker and its content store.
    ///
    /// Exposed for the same reason `control` and `fleet` are: the properties worth asserting about a
    /// broker are properties of the *assembled* one. The store's reclamation policy in particular is
    /// wired by exactly one line here, and a line that quietly stops being called leaves a runner
    /// whose store grows forever while every test about the store still passes — the store is simply
    /// correct and full.
    pub fetch: Arc<BrokerFetcher>,
    /// The secret broker and this node's enrolled identity, or `None` in `HULL_CI_SECRETS=off`.
    ///
    /// Exposed for the same reason `control` is: the end-to-end suite has to store a tenant secret
    /// and inspect enrolment, and doing that through the *assembled* plane is the only way to test
    /// the wiring rather than a rebuilt copy of it. There is no HTTP surface here — storing a secret
    /// is an operator action against the control-plane DB (D§7.4), and inventing an endpoint for it
    /// would be a new attack surface this milestone does not need.
    pub secrets: Option<Arc<hull_ci_secrets::SecretService>>,
    /// The package proxy, or `None` in `HULL_CI_PROXY=off` (§14.3's default).
    ///
    /// Handed back rather than served inside [`assemble`] for the same reason `router` is: it needs
    /// its **own listener** on its **own address**, because the two are reached from different places
    /// — `HULL_CI_BIND` is where the control plane accepts dispatches, and `HULL_CI_PROXY_BIND` is
    /// what a sandbox network's gateway can route to. Binding them together would either expose the
    /// dispatch endpoint to every job on the fleet or make the proxy unreachable.
    pub packages: Option<proxy::PackagePlane>,
}

/// Build the runner: choose a backend, check it, and wire the seams.
pub async fn assemble(config: &Config) -> Result<Runner, StartupError> {
    // §14.3. Built before the backend, because it is what decides whether the backend is asked for a
    // network at all — and `None` here means every job keeps `--network none`, which is the default
    // and the safe answer.
    let packages = proxy::assemble(&config.proxy, proxy::dev_credentials(config.dev_secrets.as_deref()));
    proxy::announce(packages.as_ref(), &config.proxy);
    let network = packages.as_ref().map(|p| p.network_mode()).unwrap_or(hull_ci_node::NetworkMode::None);

    let backend = choose_backend(config, network).await?;
    announce_isolation(config, backend.as_ref());
    // Taken before the backend is handed to the agent: which §14 clauses this deployment enforces
    // cannot change while the process runs (`choose_backend` refuses rather than degrades), so the
    // panel reads a copy instead of reaching back through the node for it.
    let node_facts = admin::NodeFacts::of(backend.as_ref());

    // The broker's store and the workspace root are created up front, so a misconfigured path is a
    // startup failure rather than a job that errors five minutes into someone's afternoon.
    prepare_dir("content store", &config.store_root)?;
    prepare_dir("workspace root", &config.work_root)?;

    // The broker owns the store, so it is also what bounds it: a commit that publishes a tree is
    // where reclamation is amortized from (design D§4.2's GC, which until now had no caller). The
    // policy is read here, in the one place that reads an operator's configuration, and announced
    // there — see `fetch::reclaim`.
    let broker = FetchBroker::new(ContentStore::new(&config.store_root))?.with_reclaim(fetch::reclaim(config));
    // `slots_total` is named here rather than left to `NodeConfig::default()` — which is `1`, the
    // conservative default a library type has to have when it cannot see the host it will run on.
    // This is the one place that reads an operator's configuration, so it is the one place that can
    // know the real number (design D§7.1's executor slots; see `config::default_node_slots`).
    let mut agent = NodeAgent::new(
        NodeConfig {
            node_id: config.node_id.clone(),
            slots_total: config.node_slots,
            ..NodeConfig::default()
        },
        backend,
    );
    if let Some(access) = packages.as_ref().and_then(|p| p.access()) {
        agent = agent.with_package_access(access);
    }

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

    let fair_share = fleet_capacity(config.node_slots, FairShare::default());

    let control_config = ControlConfig {
        secret: config.secret.clone(),
        timeouts: config.timeouts,
        // M1's tier is the container scaffold (design D§13). Reported on every assignment, and the
        // node refuses a tier it does not implement.
        tier: IsolationTier::Container,
        details_base_url: config.details_base_url.clone(),
        fair_share,
        // Layer 2 of D§6.1, or an inert placeholder that refuses every glob. Never an `Option`: the
        // driver takes one path either way, so "memo off" is the configuration every existing test
        // already exercises rather than a branch nobody runs.
        memo: memo::assemble(config),
        ..ControlConfig::default()
    };

    // Built here rather than taken from `Deps::default` so that failing to construct the HTTP client
    // is a startup error, not a silently unwired verdict sender. Held as its own binding because the
    // journal recovery pass below needs the *same* transport the runner will use — recovering over a
    // second, differently-configured client would test a path production never takes.
    let transport: Arc<dyn hull_ci_control::callback::CallbackTransport> =
        Arc::new(HttpCallback::new(std::time::Duration::from_secs(30)).map_err(|e| {
            StartupError::Storage { what: "callback client", path: "-".into(), detail: e.to_string() }
        })?);

    // Design D§4.1's durable outbox, or the one that remembers nothing. Opened before the control
    // plane exists, because `Control::accept` refuses a dispatch it cannot journal — a runner whose
    // journal is broken must fail to start rather than 503 every dispatch it is given.
    let journal = journal::assemble(config)?;

    // Written out in full rather than as overrides on `Deps::default()`: the defaults are the
    // *unwired* seams, which fail loudly by design, and a field forgotten here should be a compile
    // error rather than a runner that reports `errored` on every job because its planner is a stub.
    let fetch = Arc::new(BrokerFetcher::new(broker));
    let deps = Deps {
        fetcher: Arc::clone(&fetch) as Arc<dyn hull_ci_control::seams::Fetcher>,
        // The planner is told whether a broker exists for one reason only: so it stops warning that
        // `secrets = [...]` goes undelivered when it no longer does. It is not an authority input —
        // the broker still refuses an outsider whatever this says.
        planner: Arc::new(
            PipelinePlanner::new(config.image.clone()).with_secret_delivery(secrets.is_some()),
        ),
        node: Arc::clone(&fleet) as Arc<dyn hull_ci_control::seams::NodeSink>,
        transport: Arc::clone(&transport),
        membership: Arc::new(config.trusted.clone()),
        journal: Arc::clone(&journal),
        // The `(repo, tree_id)` index and the step claims — process-local unless this deployment has
        // told us there is a second replica (design D§4.5, [`claims`]).
        claims: claims::assemble(config)?,
    };

    // **Answer last run's debts before taking this run's work.** Spec §10: Hull does not poll us and
    // does not time a dispatched job out, so a job we accepted and never answered leaves its tree
    // marked in-flight forever — a normal re-check comes back `Pending` and only a human forcing a
    // rerun recovers it. Draining the journal here is what turns "the runner restarted" from a wedged
    // tree into an `errored` verdict Hull does not memoize (spec §7) and a re-check clears.
    //
    // Before `Control` is built and before the router is served, so recovery can never race a fresh
    // dispatch for one of the same trees. It does not block startup on failure — see `recover`.
    journal::recover(
        &*journal,
        &*transport,
        config.secret.as_deref(),
        &journal::recovery_retry(),
    )
    .await;

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

    Ok(Runner { router, control, fleet, fetch, secrets: secrets.map(|p| p.service), packages })
}

/// Assemble, bind, and serve until the process ends.
pub async fn run(config: Config) -> Result<(), StartupError> {
    let runner = assemble(&config).await?;

    // §14.3's package proxy, on its own listener. Bound *before* the dispatch endpoint so a runner
    // that cannot serve packages never accepts a job that will need them: with the sandbox network
    // already configured, jobs would otherwise start on a network whose only destination is a socket
    // nobody is listening on, and fail as broken builds rather than as a broken deployment.
    if let Some(packages) = runner.packages {
        let addr = config.proxy.bind;
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|source| StartupError::Bind { addr, source })?;
        tracing::info!(%addr, upstreams = ?packages.upstreams(), "package proxy listening (§14.3)");
        tokio::spawn(async move {
            if let Err(e) = packages.serve(listener).await {
                tracing::error!(error = %e, "the package proxy stopped serving; jobs can no longer resolve");
            }
        });
    }

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
async fn choose_backend(
    config: &Config,
    network: hull_ci_node::NetworkMode,
) -> Result<Arc<dyn SandboxBackend>, StartupError> {
    match config.sandbox {
        SandboxChoice::Container => {
            // The one place the sandbox's network posture is chosen. `detect_backend` runs the live
            // posture probe for a proxy network and derives `egress_deny` from what it found, so a
            // misconfigured network costs a capability rather than a job's isolation (§14.3).
            //
            // `runner_id` comes from the node id for the reason `ContainerConfig::runner_id`
            // documents: the orphan reaper must recognise this runner's own containers across a
            // restart and never another runner's, and `node_id` is the identity the scheduler's
            // roster already requires to be unique per node (D§5.1). Deriving it from anything
            // process-local — a pid, a boot nonce — would leave the reaper unable to find the
            // containers it exists to remove.
            Ok(hull_ci_node::detect_backend(ContainerConfig {
                network,
                runner_id: config.node_id.clone(),
                pool: warm_pool(config),
                // The composition root is the only place that knows what `HULL_CI_IMAGE` resolved
                // to, and a create failure cannot give the right advice without it: "build it
                // locally" and "pull it from a registry" are opposite instructions, and D§6 has
                // pipelines naming their own images, so both kinds reach that message in normal use.
                default_image: Some(config.image.clone()),
                ..ContainerConfig::default()
            })
            .await?)
        }
        SandboxChoice::LocalProcess if !config.allow_unsandboxed => {
            Err(StartupError::UnsandboxedNotPermitted)
        }
        SandboxChoice::LocalProcess => Ok(Arc::new(LocalProcessBackend::new_for_development_only())),
    }
}

/// Tell the scheduler how big the fleet actually is (design D§11.1), and announce it.
///
/// Without `fleet_slots` the scheduler holds per-tenant quotas and no notion of total capacity, so it
/// can only *offer* work in fair order and take the fleet's refusal for an answer: fair ordering is
/// real, fair allocation is not. The composition root is the only place that knows both the node's
/// slot count and the policy plan, so it is the only place that can reconcile them.
///
/// # The clamp, and why raising the slots does not defeat it
///
/// **A quota larger than the fleet is not a quota.** A default plan permitting more concurrent steps
/// than the deployment can run means the number an operator reads constrains nothing — worse than no
/// number, because someone will read it and believe it. So the *policy* ceiling is clamped to the
/// *physical* one and never the reverse: policy should never promise more than physics.
///
/// Making the slot count configurable does not weaken that. The clamp is a comparison between two
/// live numbers, not a statement about the old default of `1`: with `HULL_CI_NODE_SLOTS` at or above
/// the plan's 16 the comparison simply does not fire, and the moment an operator sets fewer slots
/// than the plan permits — which is most deployments, since the derived default is 1–8 — it fires
/// exactly as before. What changed is that a deployment can now be on the other side of it, which is
/// the side D§6.5's parallel branches need.
///
/// A parameter rather than a read of [`FairShare::default`] inside, so the rule can be tested at both
/// sides of that comparison without a `Config` or a running node.
fn fleet_capacity(node_slots: u32, mut fair_share: FairShare) -> FairShare {
    // `HULL_CI_NODE_SLOTS=0` is refused at parse time ([`config::node_slots`]), but `Config`'s fields
    // are public — the end-to-end suite builds one directly rather than mutating the process
    // environment — so a zero can still arrive here. A fleet advertised as zero-capacity schedules
    // *nothing*, silently and forever, which is the one outcome worse than being slow.
    let node_slots = usize::try_from(node_slots).unwrap_or(usize::MAX).max(1);

    tracing::info!(
        node_slots,
        "node executor slots (HULL_CI_NODE_SLOTS): this node runs at most this many steps at once. \
         Each one is a live sandbox holding its configured CPU and memory for the length of a step \
         (design D§7.1), so this number times the per-job memory is what a busy node wants resident."
    );

    fair_share.fleet_slots = Some(node_slots);
    if fair_share.default_plan.max_running_steps > node_slots {
        tracing::info!(
            plan_cap = fair_share.default_plan.max_running_steps,
            node_slots,
            "default per-tenant concurrency exceeded fleet capacity; clamped to the fleet"
        );
        fair_share.default_plan.max_running_steps = node_slots;
    }
    fair_share
}

/// This deployment's warm sandbox pool (design D§6.4), announced.
///
/// Announced for the reason reclamation is (`crate::fetch::reclaim`): what an operator must be able
/// to tell apart is *"the pool is on and every job is hitting it"* from *"the pool is on and has
/// never warmed a single member"*, and from the outside — jobs that work, at some latency nobody is
/// measuring — those are the same picture. This line is the first half; `hull_ci_node::PoolStats` is
/// the second.
///
/// **The root is inside the work root, and that is not cosmetic.** Claiming a member moves the job's
/// workspace into the member's mount directory, and `rename(2)` refuses to cross filesystems — so a
/// pool root somewhere else is a pool that warms perfectly and never hits. Deriving it from
/// `HULL_CI_WORK_ROOT` makes the two share a filesystem by construction rather than by an operator
/// remembering to line up two paths.
///
/// # `HULL_CI_POOL_TOTAL` and `HULL_CI_NODE_SLOTS` count different containers, and both cost memory
///
/// The two numbers are independent and are **deliberately not coupled here**, but they add up on the
/// same host, so an operator who reads one without the other will size their box wrong:
///
/// * `HULL_CI_NODE_SLOTS` bounds sandboxes that are **running a step** — each holds its configured
///   memory (4 GB by default) for the length of that step.
/// * `HULL_CI_POOL_TOTAL` bounds sandboxes that are **idle, pre-created and holding memory anyway**,
///   across all keys. `SandboxPool::claim` *removes* a member as it hands it over, so a claimed
///   member stops being one of these and becomes one of the above.
///
/// Worst case resident is therefore `node_slots + pool_total` containers, not the larger of the two.
/// On the defaults that is a handful; raising slots on a host already carrying a deep pool is how a
/// node ends up over-committed, and the OOM killer's answer to that is an `errored` verdict on
/// whichever step was unluckiest — a flake, not a configuration error. **Nothing in this process
/// refuses that combination**, because only the operator can see the RAM budget it has to fit in
/// (the same reasoning D§6.4 gives for not deriving pool depth), so it is announced instead.
///
/// The other direction wastes nothing and starves nobody, but it is worth saying out loud: with
/// `pool_total` below `node_slots`, a node running flat out has more concurrent starts than the pool
/// can ever have members for, so at least `node_slots - pool_total` of them are cold *by
/// construction* — and since refill is amortized one member per teardown, the hit rate is worst
/// exactly when the fleet is busiest. That is a latency trade, never a correctness one: a miss is a
/// cold create, never a queue.
fn warm_pool(config: &Config) -> hull_ci_node::PoolConfig {
    let default = hull_ci_node::PoolConfig::default();
    let pool = hull_ci_node::PoolConfig {
        depth: config.pool_depth,
        total: config.pool_total,
        root: config.work_root.join("pool"),
        ..default
    };
    if !pool.enabled() {
        tracing::info!(
            "warm sandbox pools are OFF (HULL_CI_POOL_DEPTH=0): every job creates and boots its own \
             container, which design D§6.4 puts at ~200 ms against ~40 ms warm. Nothing about a \
             job's isolation changes either way."
        );
        return pool;
    }
    tracing::info!(
        depth = pool.depth,
        total = pool.total,
        root = %pool.root.display(),
        idle = %pool.idle_argv.join(" "),
        "warm sandbox pools on: this node pre-creates sandboxes per hot configuration. Each is handed \
         to exactly one job and destroyed afterwards — pre-boot, not reuse (D§6.4, §14.1). A member \
         is only ever given to a job whose image, network posture, limits and privilege settings are \
         identical to the ones it was created with. A key with nothing warm falls back to a cold \
         create; no job ever waits for a refill."
    );
    // The one line that puts the two independent bounds next to each other. An operator sizing a host
    // from `HULL_CI_POOL_TOTAL` alone under-counts by a whole fleet's worth of running sandboxes, and
    // one from `HULL_CI_NODE_SLOTS` alone under-counts by the pool — see this function's docs.
    tracing::info!(
        node_slots = config.node_slots,
        pool_total = pool.total,
        peak_containers = u64::from(config.node_slots) + pool.total as u64,
        "warm pool and executor slots are bounded separately and add up on this host: at peak this \
         node holds up to `node_slots` sandboxes running a step plus `pool_total` idle ones, each \
         holding its configured memory. A pool smaller than the slot count is a supported trade — \
         the extra concurrent starts are cold, never queued."
    );
    pool
}

/// Say, at startup and in one place, exactly which §14 controls this configuration does **not**
/// enforce and what follows from that.
///
/// Design D§7.2 puts the capability answer in the code so the M1 gap "is a property the code knows
/// about rather than a note in a document". This is the operator-facing half of the same idea: an
/// operator should learn what their runner cannot contain when they start it, not from a refused job
/// at 3am — and least of all from an incident.
fn announce_isolation(config: &Config, backend: &dyn SandboxBackend) {
    let caps = backend.capabilities();
    let unmet = caps.unmet_clauses();
    // Three different questions, reported as three, because collapsing them is how an operator ends
    // up believing a backend enforces §14 in full when it merely enforces enough to be trusted with
    // untrusted work. `admits_untrusted()` waives the in-sandbox hardening clauses on purpose (see
    // `hull_ci_proto::Clause::required_for_untrusted`); `fully_conforming()` waives nothing.
    let admits = caps.admits_untrusted();
    let conforming = caps.fully_conforming();

    tracing::info!(
        backend = backend.name(),
        tier = ?backend.tier(),
        trusted_tenants = %config.trusted.describe(),
        "sandbox backend selected"
    );

    match (conforming, admits) {
        (true, _) => tracing::info!(backend = backend.name(), "backend enforces every §14 clause"),
        // The case the gate exists to allow: a real boundary with a gap that is defence in depth
        // rather than an escape. Worth a warning — it is still a gap — but not a refusal.
        (false, true) => tracing::warn!(
            backend = backend.name(),
            unmet = ?unmet,
            "SPEC §14 NOT FULLY ENFORCED, but every clause required to admit untrusted work is: \
             the gaps above are in-sandbox hardening, contained by the kernel boundary, the \
             single-use rootfs and egress-deny that this backend does enforce."
        ),
        (false, false) => tracing::warn!(
            backend = backend.name(),
            unmet = ?unmet,
            blocking = ?caps.unmet_for_untrusted(),
            "SPEC §14 NOT FULLY ENFORCED — this runner refuses work from untrusted authors. The \
             `blocking` clauses are the ones that would have to change. Design D§13: M1 is \
             single-tenant, trusted-input only and MUST NOT take untrusted or multi-tenant input."
        ),
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
        SecretsMode::Infisical => tracing::info!(
            node_id = %config.node_id,
            "tenant secret broker enabled with KEKs in Infisical KMS (D§7.4). This process holds no \
             KEK material and every unwrap is a round trip, so a KMS outage refuses secret delivery \
             rather than degrading it. Masking of job output remains a backstop, not a control."
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

    #[test]
    fn the_warm_pool_lives_inside_the_work_root_so_a_claim_can_rename_into_it() {
        // Not cosmetic. Claiming a member moves the job's workspace into the member's mount
        // directory, and `rename(2)` refuses to cross filesystems — so a pool root anywhere else is a
        // pool that warms members perfectly and hits none of them, which from the outside is
        // indistinguishable from no pool at all. Deriving the path from `HULL_CI_WORK_ROOT` makes the
        // two share a filesystem by construction rather than by an operator lining up two settings.
        let (_dir, mut config) = dirs();
        config.pool_depth = 2;
        let pool = warm_pool(&config);
        assert!(pool.enabled());
        assert_eq!(pool.depth, 2);
        assert!(
            pool.root.starts_with(&config.work_root),
            "the pool root must be under the work root, not {}",
            pool.root.display()
        );

        // …and the default is a pool that does not exist, so a deployment that configured nothing
        // gets no idle containers holding its memory (D§6.4).
        let (_dir, config) = dirs();
        assert!(!warm_pool(&config).enabled());
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

    /// The operator's reclamation setting has to reach the broker that owns the store, and one line
    /// in [`assemble`] is the whole of that journey.
    ///
    /// Worth its own test because of how this fails: a broker built without the policy still fetches,
    /// still verifies, still stores, and still passes every test in this repository — it just never
    /// sweeps, and the symptom arrives weeks later as a full disk on a runner whose configuration
    /// says otherwise. Asserted on the *assembled* runner rather than on a broker built here, since a
    /// rebuilt copy would prove only that `with_reclaim` works.
    #[tokio::test]
    async fn the_operators_reclamation_setting_reaches_the_store_that_grows() {
        let (_d, mut config) = dirs();
        config.sandbox = SandboxChoice::LocalProcess;
        config.allow_unsandboxed = true;
        config.reclaim_retention = std::time::Duration::from_secs(3 * 24 * 60 * 60);

        let on = assemble(&config).await.unwrap();
        let policy = *on.fetch.broker().reclaim_config();
        assert!(policy.enabled, "reclamation is on unless an operator turns it off");
        assert_eq!(policy.tree_retention, config.reclaim_retention, "the configured retention, not a default");
        assert!(!policy.cooldown.is_zero(), "a burst of commits must not become a burst of walks");

        config.reclaim = false;
        let off = assemble(&config).await.unwrap();
        assert!(
            !off.fetch.broker().reclaim_config().enabled,
            "HULL_CI_RECLAIM=off must reach the broker: an operator who turned the reaper off and \
             got one anyway is worse served than one who never had it"
        );
    }

    /// The operator's slot count has to arrive at **both** things that can act on it, and one line
    /// each in [`assemble`] is the whole of those two journeys.
    ///
    /// Worth asserting on the assembled runner rather than on a `NodeConfig` built here, for the
    /// reason the reclamation test above gives: a number parsed, logged and then dropped leaves a
    /// runner that reads back as configured and behaves exactly as it did before. The two ends are
    /// different failures, too. Lost on the way to the **node** and the heartbeat under-reports this
    /// node's capacity, so D§5.1's roster would place against a fleet size that is not real. Lost on
    /// the way to the **scheduler** and `fleet_slots` stays at the old default, so the fleet is idle
    /// while steps sit `ready` and nothing anywhere says why.
    #[tokio::test]
    async fn the_operators_slot_count_reaches_the_node_and_the_scheduler() {
        let (_d, mut config) = dirs();
        config.sandbox = SandboxChoice::LocalProcess;
        config.allow_unsandboxed = true;
        config.node_slots = 3;

        let runner = assemble(&config).await.unwrap();
        let state = runner.fleet.agent().state();
        assert_eq!(state.slots_total, 3, "the node must heartbeat the configured capacity, not a default");
        assert_eq!(state.slots_free, 3, "and start with all of them free");
        assert_eq!(
            runner.control.config().fair_share.fleet_slots,
            Some(3),
            "the scheduler must be told the same number, or it schedules against a fleet that is not this one"
        );
    }

    /// The clamp of `fleet_capacity` still fires — through the whole composition root, not just in
    /// the function — when an operator asks for fewer slots than the default plan permits.
    ///
    /// This is the property that making slots configurable could most easily have destroyed: raising
    /// the default so the comparison stops firing on *this* machine reads exactly like the clamp
    /// working, right up until someone sets a small number and finds their per-tenant quota promising
    /// 16 concurrent steps on a fleet of two.
    #[tokio::test]
    async fn the_policy_clamp_still_fires_on_a_fleet_smaller_than_the_plan() {
        let (_d, mut config) = dirs();
        config.sandbox = SandboxChoice::LocalProcess;
        config.allow_unsandboxed = true;
        config.node_slots = 2;

        let runner = assemble(&config).await.unwrap();
        let fair = &runner.control.config().fair_share;
        assert_eq!(fair.fleet_slots, Some(2));
        assert_eq!(
            fair.default_plan.max_running_steps, 2,
            "a quota larger than the fleet is not a quota: policy must not promise more than physics"
        );
    }

    /// The reconciliation rule itself, at both sides of the comparison and at the edge.
    #[test]
    fn a_fleet_bigger_than_the_plan_is_not_clamped_and_does_not_raise_the_quota() {
        let plan_cap = FairShare::default().default_plan.max_running_steps;

        let roomy = fleet_capacity(64, FairShare::default());
        assert_eq!(roomy.fleet_slots, Some(64), "the scheduler is told the fleet's real size");
        assert_eq!(
            roomy.default_plan.max_running_steps, plan_cap,
            "the clamp lowers a promise to fit physics; it must never raise one to fill it"
        );

        // The edge: equal is not "exceeds", so nothing moves.
        let exact = fleet_capacity(plan_cap as u32, FairShare::default());
        assert_eq!(exact.default_plan.max_running_steps, plan_cap);

        // Zero cannot come from the environment (`config::node_slots` refuses it) but can from a
        // hand-built `Config`, and a fleet of zero schedules nothing at all, forever and silently.
        assert_eq!(fleet_capacity(0, FairShare::default()).fleet_slots, Some(1));
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

/// What the slot count *does*, rather than where it is stored.
///
/// The wiring tests above prove the number arrives; they would all still pass on a deployment that
/// ran every step one after another, because "configured for four" and "runs four at once" are
/// different claims and only the second one is design D§6.5's. So these tests assert **overlap** —
/// two steps of one job in flight at the same time, and the same two refusing to overlap on a
/// one-slot fleet.
///
/// **Nothing here is asserted on wall clock**, deliberately: this repository already has one flaky
/// timing test and does not need a second. Two devices replace it. The stub node *never reports*, so
/// a step stays in flight until a test answers for it and "both are in flight" is a fact about
/// recorded state rather than about how fast the machine is; and the real-sandbox case makes the two
/// steps **rendezvous**, so each one can only exit `0` if the other was genuinely running beside it —
/// a proof by deadlock-or-pass rather than by stopwatch.
///
/// The control plane's own fakes are `#[cfg(test)]`-private to its crate (as [`crate::admin`]'s tests
/// note), so the seams are stubbed again here: enough to get real steps through a real driver, and
/// nothing more.
#[cfg(test)]
mod concurrency_tests {
    use super::*;

    use std::sync::Mutex;
    use std::time::Duration;

    use hull_ci_control::callback::{
        BoxFuture, CallbackRequest, CallbackResponse, CallbackTransport, TransportError,
    };
    use hull_ci_control::model::{StepSpec, StepState};
    use hull_ci_control::seams::{
        FetchError, FetchRequest, Fetcher, Membership, NodeError, NodeSink, PlanError, Planner,
        VerifiedTree,
    };
    use hull_ci_control::{ControlConfig, Deps};
    use hull_ci_node::{LocalProcessBackend, NodeConfig};
    use hull_ci_proto::{Assignment, AuthorClass, Dispatch, StepOutcome, StepReport};

    const NODE: &str = "node-slots-test";
    const TENANT: &str = "acme";

    /// Reports a tree at a path that really exists, because the node under test materializes it.
    struct DirFetcher {
        path: std::path::PathBuf,
    }

    impl Fetcher for DirFetcher {
        fn fetch<'a>(&'a self, req: &'a FetchRequest) -> BoxFuture<'a, Result<VerifiedTree, FetchError>> {
            let (path, tree_id) = (self.path.clone(), req.tree_id.clone());
            Box::pin(async move { Ok(VerifiedTree { tree_id, path, cached: false, keep_alive: None }) })
        }
    }

    /// Steps with **no `needs` edges**, so every one of them is ready at once and capacity is the
    /// only thing left that can decide whether they overlap. That is the whole fixture: a planner
    /// that emitted a chain would prove nothing about slots.
    struct ParallelPlanner {
        steps: Vec<StepSpec>,
    }

    impl Planner for ParallelPlanner {
        fn plan<'a>(&'a self, _t: &'a VerifiedTree) -> BoxFuture<'a, Result<Vec<StepSpec>, PlanError>> {
            let steps = self.steps.clone();
            Box::pin(async move { Ok(steps) })
        }
    }

    /// Accepts every assignment, records it, and **never reports**.
    ///
    /// The silence is the instrument. A step this node holds stays in flight until the test records a
    /// report on its behalf, so "two steps were in flight together" is read off recorded state at a
    /// moment the test chose, instead of being inferred from two timestamps being close.
    #[derive(Default)]
    struct RecordingNode {
        assigned: Mutex<Vec<(String, String)>>,
    }

    impl RecordingNode {
        fn assigned(&self) -> Vec<(String, String)> {
            self.assigned.lock().unwrap().clone()
        }
    }

    impl NodeSink for RecordingNode {
        fn assign(&self, a: &Assignment, _t: &VerifiedTree) -> Result<String, NodeError> {
            self.assigned.lock().unwrap().push((a.step_id.clone(), a.step_name.clone()));
            Ok(NODE.into())
        }
        fn cancel(&self, _job_id: &str, _step_id: &str) {}
    }

    struct SilentTransport;

    impl CallbackTransport for SilentTransport {
        fn post<'a>(&'a self, _r: &'a CallbackRequest) -> BoxFuture<'a, Result<CallbackResponse, TransportError>> {
            Box::pin(async { Ok(CallbackResponse { status: 200 }) })
        }
    }

    struct Everyone;

    impl Membership for Everyone {
        fn classify(&self, _repo: &str, _author: &str) -> AuthorClass {
            AuthorClass::Member
        }
    }

    fn dispatch() -> Dispatch {
        Dispatch {
            repo: format!("{TENANT}/widget"),
            change: "c0ffee".into(),
            tree_id: "tree1".into(),
            intent: "two independent steps".into(),
            author: "someone".into(),
            source_url: "https://hull.example/tree/tree1/tar".into(),
            callback_url: "https://hull.example/ci-result".into(),
            fetch_token: None,
        }
    }

    /// A control plane sized for `node_slots`, wired to the seams a capacity test needs.
    ///
    /// The `FairShare` comes from [`fleet_capacity`] — the same function `assemble` calls — rather
    /// than from a hand-set `fleet_slots`, so what these tests exercise is the composition root's
    /// reconciliation and not a second copy of it.
    fn control_with(
        node_slots: u32,
        tree: std::path::PathBuf,
        steps: Vec<StepSpec>,
        node: Arc<dyn NodeSink>,
    ) -> Arc<Control> {
        let config = ControlConfig {
            fair_share: fleet_capacity(node_slots, FairShare::default()),
            ..ControlConfig::default()
        };
        let deps = Deps {
            fetcher: Arc::new(DirFetcher { path: tree }),
            planner: Arc::new(ParallelPlanner { steps }),
            node,
            transport: Arc::new(SilentTransport),
            membership: Arc::new(Everyone),
            claims: Arc::new(hull_ci_control::LocalClaims::new()),
            journal: Arc::new(hull_ci_control::NoJournal),
        };
        Control::new(config, deps)
    }

    /// Two steps that need nothing and can therefore both be ready at once.
    fn two_steps() -> Vec<StepSpec> {
        vec![
            StepSpec::new("left", vec!["/bin/true".into()], "n/a"),
            StepSpec::new("right", vec!["/bin/true".into()], "n/a"),
        ]
    }

    /// Poll until a condition holds, or give up.
    ///
    /// The budget is a **bound on giving up**, not a measurement: every assertion below is about
    /// which states were observed, and a generous budget only decides how long a genuine failure
    /// takes to be reported. Two seconds against work that finishes in tens of milliseconds.
    async fn wait_until(f: impl FnMut() -> bool) -> bool {
        wait_up_to(400, f).await
    }

    async fn wait_up_to(rounds: usize, mut f: impl FnMut() -> bool) -> bool {
        for _ in 0..rounds {
            if f() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        false
    }

    fn passed(job_id: &str, step_id: &str) -> StepReport {
        StepReport {
            job_id: job_id.into(),
            step_id: step_id.into(),
            outcome: StepOutcome::Passed,
            reason: None,
            exit_code: Some(0),
            log_key: None,
            detail: String::new(),
        }
    }

    /// How many of this job's steps are occupying the fleet right now.
    fn in_flight(control: &Control) -> usize {
        control.snapshot_jobs()[0]
            .steps
            .iter()
            .filter(|s| matches!(s.state, StepState::Leased | StepState::Running))
            .count()
    }

    #[tokio::test]
    async fn two_independent_steps_are_in_flight_together_when_the_slots_allow() {
        // D§6.5's promise, as a fact about state: with two slots, both branches of a fan-out are on
        // the fleet at the same instant. Neither has reported, so this is not "one finished quickly
        // and the other started" — it is two steps held simultaneously.
        let dir = tempfile::tempdir().unwrap();
        let node = Arc::new(RecordingNode::default());
        let control = control_with(2, dir.path().to_path_buf(), two_steps(), Arc::clone(&node) as Arc<dyn NodeSink>);
        control.accept(dispatch()).unwrap();

        let n = Arc::clone(&node);
        assert!(wait_until(move || n.assigned().len() == 2).await, "both steps must be placed");
        assert_eq!(in_flight(&control), 2, "and held at the same time, not one after the other");
        assert_eq!(control.queue_depth(TENANT).running, 2, "the tenant is using both slots");
    }

    #[tokio::test]
    async fn one_slot_holds_the_second_step_until_the_first_has_answered() {
        // The other half, and the one that would have caught a `fleet_slots` left at a default: a
        // one-slot fleet must place exactly one of the two ready steps, and place the second only
        // once the first has given its slot back. The assertion is on *ordering* — what is placed
        // before and after a report this test controls — never on how long anything took.
        let dir = tempfile::tempdir().unwrap();
        let node = Arc::new(RecordingNode::default());
        let control = control_with(1, dir.path().to_path_buf(), two_steps(), Arc::clone(&node) as Arc<dyn NodeSink>);
        let job = control.accept(dispatch()).unwrap().job_id;

        let n = Arc::clone(&node);
        assert!(wait_until(move || n.assigned().len() == 1).await, "the first step is placed");

        let n = Arc::clone(&node);
        assert!(
            !wait_until(move || n.assigned().len() > 1).await,
            "a one-slot fleet must not hold two steps at once, however long it is given"
        );
        assert_eq!(in_flight(&control), 1);

        // The slot comes back, and only then does the second step go out.
        let first = node.assigned()[0].0.clone();
        control.record_step_report(&passed(&job, &first), NODE).unwrap();

        let n = Arc::clone(&node);
        assert!(
            wait_until(move || n.assigned().len() == 2).await,
            "the second step must be placed once the first releases its slot"
        );
        let names: Vec<String> = node.assigned().into_iter().map(|(_, name)| name).collect();
        assert_eq!(names.len(), 2, "each step is placed exactly once: {names:?}");
    }

    #[tokio::test]
    async fn two_steps_really_run_at_the_same_time_on_the_node() {
        // The end of the wire: the real [`InProcessFleet`] over the real local backend, running two
        // real processes. The two steps **rendezvous** — each creates its own file and blocks until
        // it sees the other's — so a `passed` from both is only reachable if the node genuinely had
        // two steps executing simultaneously. Run serially they cannot both pass: the first would
        // block on a file the second cannot create until the first is done, and the step clock below
        // ends it as `errored`.
        //
        // A rendezvous rather than a stopwatch on purpose. "Both finished within N ms of each other"
        // is a machine-speed assertion; "both observed each other" is a causal one.
        let work = tempfile::tempdir().unwrap();
        let tree = tempfile::tempdir().unwrap();
        let meet = tempfile::tempdir().unwrap();
        let meet = meet.path().display().to_string();

        let rendezvous = |mine: &str, theirs: &str| {
            StepSpec {
                // A short clock so the serial case fails as a bounded `errored` rather than by
                // hanging: nothing waits on this in the passing case.
                timeout: Some(Duration::from_secs(20)),
                ..StepSpec::new(
                    mine,
                    vec![
                        "/bin/sh".into(),
                        "-c".into(),
                        format!("touch {meet}/{mine}; while [ ! -f {meet}/{theirs} ]; do sleep 0.05; done"),
                    ],
                    "n/a",
                )
            }
        };

        let agent = NodeAgent::new(
            NodeConfig { node_id: NODE.into(), slots_total: 2, ..NodeConfig::default() },
            Arc::new(LocalProcessBackend::new_for_development_only()),
        );
        let fleet = InProcessFleet::new(agent, work.path().to_path_buf());
        let control = control_with(
            2,
            tree.path().to_path_buf(),
            vec![rendezvous("left", "right"), rendezvous("right", "left")],
            Arc::clone(&fleet) as Arc<dyn NodeSink>,
        );
        fleet.attach(&control);
        control.accept(dispatch()).unwrap();

        // A longer budget than the other two tests use, because this one waits on two real processes
        // through a real workspace materialization rather than on a stub. It is still only a bound on
        // how long a failure takes to report: the passing path here is tens of milliseconds.
        let ctrl = Arc::clone(&control);
        let met = wait_up_to(1200, move || {
            let steps = &ctrl.snapshot_jobs()[0].steps;
            steps.len() == 2 && steps.iter().all(|s| s.state.is_terminal())
        })
        .await;
        let states: Vec<StepState> = control.snapshot_jobs()[0].steps.iter().map(|s| s.state).collect();
        assert!(met, "neither step ever finished; states were {states:?}");
        assert!(
            states.iter().all(|s| *s == StepState::Passed),
            "each step only exits 0 if it saw the other running beside it; states were {states:?}"
        );
    }
}
