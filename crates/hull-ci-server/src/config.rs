//! Configuration, from the environment.
//!
//! Every setting here is read once at startup and then owned by the process; nothing is re-read, and
//! nothing is settable over HTTP. Two of them are safety switches rather than preferences
//! ([`Config::sandbox`] and [`Config::allow_unsandboxed`]), and those are written so that the unsafe
//! choice is the one you have to spell out — see [`SandboxChoice`].
//!
//! | Variable | Default | What it is |
//! |---|---|---|
//! | `HULL_CI_BIND` | `127.0.0.1:8080` | listen address for `POST /hull` (spec §4) |
//! | `HULL_CI_SECRET` | *none* | the shared secret (spec §8), checked on dispatch and echoed on the callback |
//! | `HULL_CI_STORE_ROOT` | `$TMPDIR/hull-ci/store` | root of the broker's content store (design D§4.2) |
//! | `HULL_CI_WORK_ROOT` | `$TMPDIR/hull-ci/workspaces` | where per-job workspaces are materialized (D§6.2) |
//! | `HULL_CI_SANDBOX` | `container` | `container` \| `local` — the §14.1 boundary, or the absence of one |
//! | `HULL_CI_ALLOW_UNSANDBOXED` | unset | required to start with `HULL_CI_SANDBOX=local` |
//! | `HULL_CI_TRUSTED_TENANTS` | *empty* | tenants whose authors count as members (design D§1); `*` for all |
//! | `HULL_CI_NODE_ID` | `node-0` | this node's id, as it appears in leases and log keys |
//! | `HULL_CI_NODE_SLOTS` | *derived from the host's cores*, 1–8 | how many steps this node runs **at once** (design D§7.1); see [`default_node_slots`] |
//! | `HULL_CI_IMAGE` | `hull-ci/m1:latest` | image the planner names for its step |
//! | `HULL_CI_DETAILS_BASE_URL` | *none* | base for the verdict's `details_url` (design G4) |
//! | `HULL_CI_ADMIN_TOKEN` | *none* | bearer token for the read-only operator panel; **unset disables it entirely** |
//! | `HULL_CI_SECRETS` | `off` | `off` \| `dev` — the tenant secret broker (design D§7.4) |
//! | `HULL_CI_DEV_SECRETS` | *none* | `tenant/NAME=value,…` seed for `HULL_CI_SECRETS=dev`; **dev only** |
//! | `HULL_CI_PROXY` | `off` | `off` \| `on` — the package proxy (spec §14.3); see [`hull_ci_proxy::config`] for the rest of the `HULL_CI_PROXY_*` family |
//! | `HULL_CI_JOURNAL` | **`on`** | `on` \| `off` — the write-ahead journal under `HULL_CI_STORE_ROOT/journal` ([`crate::journal`]). One of two switches here that default **on**: off means a restart strands every in-flight job |
//! | `HULL_CI_RECLAIM` | **`on`** | `on` \| `off` — content-store reclamation, amortized over commits ([`crate::fetch::reclaim`]). The other default-**on** switch: off means the store grows until the disk does not |
//! | `HULL_CI_RECLAIM_RETENTION_DAYS` | `14` | how long a stored tree survives after its last *use*. Longer keeps more cache hits and more disk |
//! | `HULL_CI_POOL_DEPTH` | `0` (off) | warm sandboxes kept **per hot configuration** (design D§6.4, [`hull_ci_node::pool`]). Pre-boot, not reuse: a member has never run a job, is handed to exactly one, and is destroyed afterwards (§14.1) |
//! | `HULL_CI_POOL_TOTAL` | `8` | warm sandboxes kept across **all** configurations. The other half of the bound |
//! | `HULL_CI_POSTGRES_URL` | *none* | the **shared claim store** two or more replicas contend on ([`crate::claims`]). Needs a binary built with `--features postgres`, and `HULL_CI_REPLICA_ID`; without either the runner refuses to start rather than becoming a second replica that believes it is alone |
//! | `HULL_CI_REPLICA_ID` | *none* | this replica's identity on every claim it holds. **No default**: two replicas sharing an id would take each other's leases |
//!
//! `HULL_CI_SECRET` deserves its own note: spec §8 makes configuring one a SHOULD, and this process
//! treats a missing one as a loud warning rather than a refusal, because a loopback bring-up run
//! genuinely does not need it. The moment `HULL_CI_BIND` is not loopback that reasoning stops
//! holding, and the warning says so.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use hull_ci_control::Timeouts;

use crate::membership::TrustedTenants;

/// Which sandbox backend to run jobs in.
///
/// There is no `Auto` that silently degrades. Spec §14.1 calls a plain host subprocess "NOT
/// sufficient" and design D§13 makes the container the M1 backend, so falling back from one to the
/// other on a host where the daemon happens to be down would turn an operator's isolation
/// expectation into a coin flip decided by `docker`'s uptime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxChoice {
    /// The M1 bring-up backend: a locked-down container (design D§7.2, D§13).
    Container,
    /// A host subprocess. **Not a sandbox.** Requires `HULL_CI_ALLOW_UNSANDBOXED`.
    LocalProcess,
}

impl SandboxChoice {
    fn parse(raw: &str) -> Result<SandboxChoice, ConfigError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "container" | "docker" => Ok(SandboxChoice::Container),
            "local" | "local-process" => Ok(SandboxChoice::LocalProcess),
            other => Err(ConfigError::Value {
                var: "HULL_CI_SANDBOX",
                detail: format!("expected `container` or `local`, got `{other}`"),
            }),
        }
    }
}

/// Whether this deployment can deliver a tenant secret, and what holds the keys (design D§7.4).
///
/// There is no `auto`. Whether a runner can hand a job a credential is not something to infer from
/// the environment: it changes what a sandbox escape reaches, so it is a choice an operator makes in
/// one place and can read back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretsMode {
    /// **The default.** No broker, no node keypair, no capability ever minted. A pipeline's
    /// `secrets = [...]` is warned about at plan time and delivered to nobody, and the sandbox's
    /// credential-shaped-name refusal keeps its pre-M3 meaning exactly.
    Off,
    /// A broker whose key material lives in this process's memory
    /// ([`hull_ci_secrets::DevKeyManager`]), announced loudly at startup. Development and test only;
    /// the [`KeyManager`](hull_ci_secrets::KeyManager) trait is where a KMS goes.
    Dev,
    /// A broker whose KEKs live in **Infisical KMS** and are never extractable from it
    /// ([`hull_ci_secrets::InfisicalKeyManager`]) — design D§7.4's "the KEK's root lives in a
    /// KMS/HSM and never leaves it", which until now described a seam rather than a product.
    ///
    /// Recognised in **every** build, but only *usable* in one compiled with
    /// `--features hull-ci-secrets/infisical`. That is deliberate: an operator who sets
    /// `HULL_CI_SECRETS=infisical` on a binary without the feature gets a startup error naming the
    /// missing feature, rather than "expected `off` or `dev`" — which reads as though the mode does
    /// not exist and invites a downgrade to `dev`, i.e. to keys in process memory. The failure has
    /// to say *rebuild*, never *use something weaker*.
    Infisical,
}

impl SecretsMode {
    fn parse(raw: &str) -> Result<SecretsMode, ConfigError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "disabled" => Ok(SecretsMode::Off),
            "dev" | "development" => Ok(SecretsMode::Dev),
            "infisical" | "kms" => Ok(SecretsMode::Infisical),
            other => Err(ConfigError::Value {
                var: "HULL_CI_SECRETS",
                // No fuzzy matching, for the same reason `SandboxChoice` has none: a typo must not
                // resolve to a mode that hands out credentials.
                detail: format!("expected `off`, `dev` or `infisical`, got `{other}`"),
            }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{var} is invalid: {detail}")]
    Value { var: &'static str, detail: String },
}

/// Everything this process is configured with.
///
/// Public fields on purpose: the end-to-end suite builds one directly rather than mutating the
/// process environment, which is global state that test threads would race on.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub secret: Option<String>,
    pub store_root: PathBuf,
    pub work_root: PathBuf,
    pub sandbox: SandboxChoice,
    /// The operator's explicit acknowledgement that [`SandboxChoice::LocalProcess`] enforces almost
    /// nothing. Without it, that choice refuses to start.
    pub allow_unsandboxed: bool,
    pub trusted: TrustedTenants,
    pub node_id: String,
    /// Image the planner names for its step. Ignored by the local backend, which has no images.
    pub image: String,
    /// How many steps this node runs **at once** — design D§7.1's executor slots.
    ///
    /// This is the number that decides whether parallelism exists at all. The control plane's
    /// scheduler is told it as `FairShare::fleet_slots` and will not select more steps than the fleet
    /// can hold, so a runner configured with one slot runs a pipeline's independent branches strictly
    /// one after another however the pipeline is written — design D§6.5's "a 4-step pipeline with one
    /// dependency edge is 2 steps deep in wall clock, not 4" is simply false on such a deployment,
    /// and nothing in a verdict says so.
    ///
    /// **Not free, which is why it is not just "lots".** A slot is one concurrent sandbox holding
    /// [`ResourceLimits`](hull_ci_node::ResourceLimits)' memory (4 GB by default) and CPU for as long
    /// as a step runs, so this number multiplied by that one is the memory a busy node wants. See
    /// [`default_node_slots`] for what the unconfigured deployment gets and why.
    ///
    /// **Zero is not a setting** — see [`node_slots`]. Unlike [`Self::pool_depth`], where `0` means
    /// "no pre-created containers" and every job simply starts cold, a node with no slots is a runner
    /// that accepts dispatches and runs nothing: spec §10 has Hull neither polling nor timing a job
    /// out, so every tree it accepts wedges until a human forces a rerun. The way to run nothing is
    /// to not start the process.
    pub node_slots: u32,
    pub details_base_url: Option<String>,
    pub timeouts: Timeouts,
    /// Bearer token for the operator panel ([`crate::admin`]).
    ///
    /// `None` means the panel does not exist: no route is mounted, so there is nothing to
    /// misconfigure, nothing to brute-force, and no default credential. That is deliberate rather
    /// than cautious — the panel is **cross-tenant by nature** (design D§1: every other shared
    /// surface in this system is partitioned by tenant, and this one is not), so a deployment that
    /// did not ask for it must not get it.
    pub admin_token: Option<String>,
    /// Whether tenant secrets can be delivered at all (design D§7.4). See [`SecretsMode`].
    pub secrets: SecretsMode,
    /// The package proxy (spec §14.3, design D§7.3/7.4), read from `HULL_CI_PROXY*`.
    ///
    /// Its own type from its own crate rather than fields inlined here, because it configures a
    /// *separate process concern* — an allowlist, upstream credentials, a listen address — and the
    /// one setting that touches this runner (the sandbox network) is enforced by the node's live
    /// probe rather than by anything in this struct. Keeping it whole makes that separation visible.
    pub proxy: hull_ci_proxy::ProxyConfig,
    /// `tenant/NAME=value,…` seeded into a [`SecretsMode::Dev`] broker at startup.
    ///
    /// Ignored in [`SecretsMode::Off`], and documented dev-only where it is read
    /// ([`crate::secrets::seed_dev_secrets`]) — it is the one place in this configuration that holds
    /// a plaintext credential, and it exists so a dev stack can be tried at all.
    pub dev_secrets: Option<String>,
    /// Whether layer 2 of the design's memoization is on (design D§6.1, [`crate::memo`]).
    ///
    /// Off by default. A memo that answers wrongly reports a verdict about code nobody ran, and Hull
    /// memoizes `green`/`red` by `tree_id` permanently (spec §7) — so a bad hit is not something a
    /// re-check dislodges, and it is silent, because a wrongly-cached pass looks exactly like a fast
    /// one. Opting in is the operator saying they want that trade.
    pub memo: bool,
    /// Whether accepted dispatches are recorded durably, so a restart still answers them
    /// (design D§4.1, [`crate::journal`]).
    ///
    /// **Off by default**, which is the behaviour every deployment already had: state is in memory and
    /// a restart strands in-flight jobs. That default is a statement about compatibility, not about
    /// what is right — spec §10 leaves the timeout and the recovery entirely to us, and Hull's
    /// in-flight set is cleared only by our callback, so an unanswered job wedges its tree until a
    /// human forces a rerun. Turning this on is the operator accepting the one cost it has: the
    /// journal directory has to be writable, on storage that outlives the process, or **every**
    /// dispatch is refused with a 503 rather than acked and lost.
    pub journal: bool,
    /// Whether the content store collects its own garbage (design D§4.2, [`hull_ci_fetch::ReclaimConfig`]).
    ///
    /// **On by default**, which it shares with only [`Self::journal`], and for a related reason: what
    /// it prevents is not a missing feature but a runner that eventually stops working. Every fetch
    /// that misses adds a tree and never removes one, so an unswept store is bounded by nothing but
    /// the disk — and a full disk fails *every* job on the box, as `errored`, which spec §7 does not
    /// memoize, so Hull keeps re-dispatching into it.
    ///
    /// Turning it off is the operator saying they will bound the store some other way. The cost of on
    /// is a directory walk per tenant per cooldown, on a blocking worker, off the path to any verdict.
    pub reclaim: bool,
    /// How long a stored tree survives after its last **use** (not its commit — see
    /// [`hull_ci_fetch::ReclaimPolicy::tree_retention`]).
    ///
    /// The one number an operator genuinely has to size, because it is the trade between disk and
    /// cache hits, and only they know their disk. The cooldown between sweeps is deliberately *not*
    /// configurable: it is a rate limit on our own housekeeping rather than a policy, and an operator
    /// whose store is too big wants a shorter retention, never a busier reaper.
    pub reclaim_retention: Duration,
    /// How many sandboxes this node keeps pre-created **per hot configuration** (design D§6.4,
    /// [`hull_ci_node::PoolConfig`]).
    ///
    /// **`0` — off — is the default.** A pool member is a container holding its configured memory
    /// resident before any job exists to want it, and D§6.4 sizes the real cap as
    /// `free_RAM / guest_RAM_per_job`; only the operator knows that number. Turning it on changes
    /// latency and nothing else: a job that finds no member creates one the cold way, and a pool that
    /// cannot warm at all costs an `error` line rather than a verdict.
    ///
    /// It is emphatically **not** sandbox reuse (§14.1): a member has never run a job, is handed to
    /// exactly one, and is destroyed afterwards.
    pub pool_depth: usize,
    /// How many pre-created sandboxes this node keeps **in total**, across all configurations.
    ///
    /// The second half of "bounded". [`Self::pool_depth`] alone bounds one configuration, and a node
    /// that sees several images would otherwise hold `depth × images` idle containers.
    pub pool_total: usize,
    /// Where the **shared claim store** lives, if this deployment has more than one replica
    /// ([`hull_ci_control::claims`], design D§4.5).
    ///
    /// `None` — the default — keeps the process-local `(repo, tree_id)` index the job store has
    /// always used. That is not a degraded mode; it is the single-replica behaviour, unchanged.
    ///
    /// Setting it is the operator saying "there is more than one of me", and it is checked hard at
    /// startup: without the `postgres` feature, and without [`Self::replica_id`], the runner refuses
    /// to start rather than becoming a second replica that believes it is alone. See
    /// [`crate::claims::assemble`].
    pub postgres_url: Option<String>,
    /// This replica's identity, as recorded on every claim it holds.
    ///
    /// Required exactly when [`Self::postgres_url`] is set, and with no default on purpose. Two
    /// replicas sharing an id could renew each other's leases and release each other's step claims —
    /// a split brain that looks like correct bookkeeping — and there is no value this process can
    /// derive that is guaranteed distinct from another container's.
    pub replica_id: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        let base = std::env::temp_dir().join("hull-ci");
        Config {
            // Loopback: this endpoint holds the CI shared secret and queues work on a fleet, so
            // exposing it is a deliberate act (mirrors `hull_ci_control::Opts`).
            bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            secret: None,
            store_root: base.join("store"),
            work_root: base.join("workspaces"),
            sandbox: SandboxChoice::Container,
            allow_unsandboxed: false,
            // Empty: every author is an outsider until an operator says otherwise, and no M1 backend
            // admits outsider work. A misconfigured deployment therefore refuses jobs rather than
            // running them unprotected (design D§1, D§13).
            trusted: TrustedTenants::none(),
            node_id: "node-0".into(),
            image: "hull-ci/m1:latest".into(),
            // Derived from the host, and it must stay in step with `from_env`'s default for the
            // reason the journal switch does: two spellings of one default is how a setting comes to
            // mean different things depending on which door you came in through.
            node_slots: default_node_slots(),
            details_base_url: None,
            timeouts: Timeouts::default(),
            // Off. See the field's doc: an operator surface that shows every tenant's jobs is opt-in.
            admin_token: None,
            // Off: a runner nobody asked to hold credentials holds none, so there is nothing for a
            // sandbox escape to reach and nothing for a misconfiguration to hand out.
            secrets: SecretsMode::Off,
            // Off: §14.3's default is that a job has no outbound network at all, and the switch that
            // changes that is never implicit.
            proxy: hull_ci_proxy::ProxyConfig::default(),
            dev_secrets: None,
            memo: false,
            // On, and it must stay in step with `from_env`'s default. Two spellings of one default
            // is how a switch comes to mean different things depending on which door you came in
            // through, and this one decides whether a dispatch is ever answered.
            journal: true,
            // On, for the same reason and with the same obligation to stay in step. See the field.
            reclaim: true,
            // A fortnight, which is `hull_ci_fetch::ReclaimConfig`'s own default and is justified
            // there. Named again here rather than reached for through that type, because this is the
            // number an operator reads back out of their configuration and it should not depend on a
            // default two crates away.
            reclaim_retention: Duration::from_secs(14 * 24 * 60 * 60),
            // Off. Idle containers cost memory whether or not a job ever arrives; see the field.
            pool_depth: 0,
            pool_total: 8,
            // Off: one replica, and the `(repo, tree_id)` index in this process's memory — exactly
            // what this runner has always done. Scale-out is opt-in and it has prerequisites; see
            // `crate::claims::assemble`.
            postgres_url: None,
            replica_id: None,
        }
    }
}

impl Config {
    /// Read the environment. Absent variables take the documented default; present-but-unparseable
    /// ones are an error, never a silent default — a typo'd bind address that quietly listens
    /// somewhere else is worse than a process that will not start.
    pub fn from_env() -> Result<Config, ConfigError> {
        let d = Config::default();
        Ok(Config {
            bind: match var("HULL_CI_BIND") {
                Some(v) => v.parse().map_err(|e| ConfigError::Value {
                    var: "HULL_CI_BIND",
                    detail: format!("{e} (expected `host:port`)"),
                })?,
                None => d.bind,
            },
            secret: var("HULL_CI_SECRET"),
            store_root: var("HULL_CI_STORE_ROOT").map(PathBuf::from).unwrap_or(d.store_root),
            work_root: var("HULL_CI_WORK_ROOT").map(PathBuf::from).unwrap_or(d.work_root),
            sandbox: match var("HULL_CI_SANDBOX") {
                Some(v) => SandboxChoice::parse(&v)?,
                None => d.sandbox,
            },
            allow_unsandboxed: var("HULL_CI_ALLOW_UNSANDBOXED").as_deref().is_some_and(is_truthy),
            trusted: var("HULL_CI_TRUSTED_TENANTS").map(|v| TrustedTenants::parse(&v)).unwrap_or(d.trusted),
            node_id: var("HULL_CI_NODE_ID").unwrap_or(d.node_id),
            image: var("HULL_CI_IMAGE").unwrap_or(d.image),
            node_slots: node_slots(var("HULL_CI_NODE_SLOTS").as_deref())?,
            details_base_url: var("HULL_CI_DETAILS_BASE_URL"),
            timeouts: d.timeouts,
            // `var` treats an empty value as unset, which matters more here than anywhere else:
            // `HULL_CI_ADMIN_TOKEN=` must disable the panel, never authenticate the empty string.
            admin_token: var("HULL_CI_ADMIN_TOKEN"),
            secrets: match var("HULL_CI_SECRETS") {
                Some(v) => SecretsMode::parse(&v)?,
                None => d.secrets,
            },
            proxy: hull_ci_proxy::ProxyConfig::from_env()
                .map_err(|e| ConfigError::Value { var: "HULL_CI_PROXY", detail: e.to_string() })?,
            dev_secrets: var("HULL_CI_DEV_SECRETS"),
            memo: var("HULL_CI_MEMO").as_deref().is_some_and(is_truthy),
            // On unless explicitly turned off, which is the opposite of every other switch here.
            //
            // The others gate a *capability* — a memo, a proxy, a secret broker — and a deployment
            // that never asked for one is simply a deployment without it. This one gates whether an
            // accepted dispatch is ever answered, and what it prevents is not a missing feature:
            // spec §10 has Hull neither polling nor timing a job out, and clearing its in-flight
            // mark only when a callback arrives, so a dispatch this process forgets leaves that tree
            // wedged until a human forces a rerun. Verified end to end — with this off, a `kill -9`
            // between accept and verdict produces no callback, ever.
            //
            // Defaulting off would ship that as what an operator gets for doing nothing, which is
            // the wrong direction to be wrong in for a runner whose stated posture is to refuse
            // rather than degrade. The cost of on is one small fsync per dispatch, into a store root
            // this process already requires and already writes.
            journal: journal_enabled(var("HULL_CI_JOURNAL").as_deref())?,
            // On unless explicitly turned off, like the journal above and unlike everything else
            // here. A deployment that configures nothing gets a store that stays bounded; see the
            // field's doc for why the two ways of being wrong about this are not symmetrical.
            reclaim: reclaim_enabled(var("HULL_CI_RECLAIM").as_deref())?,
            reclaim_retention: reclaim_retention(var("HULL_CI_RECLAIM_RETENTION_DAYS").as_deref())?,
            pool_depth: whole_number("HULL_CI_POOL_DEPTH", var("HULL_CI_POOL_DEPTH").as_deref(), d.pool_depth)?,
            pool_total: whole_number("HULL_CI_POOL_TOTAL", var("HULL_CI_POOL_TOTAL").as_deref(), d.pool_total)?,
            postgres_url: var("HULL_CI_POSTGRES_URL"),
            replica_id: var("HULL_CI_REPLICA_ID"),
        })
    }
}

/// A count from the environment. Absent takes the default; **anything that is not a whole number
/// refuses to start**.
///
/// The same rule [`reclaim_retention`] applies, and for the same reason: a number silently defaulted
/// after a typo is a runner whose behaviour is not what its configuration says. `HULL_CI_POOL_DEPTH=on`
/// is somebody trying to turn warm pools on and getting a node with no pool at all, which is exactly
/// the failure the counters in `hull_ci_node::PoolStats` exist to make visible — better to refuse at
/// startup, where it is cheap to notice.
fn whole_number(name: &'static str, raw: Option<&str>, default: usize) -> Result<usize, ConfigError> {
    let Some(raw) = raw else { return Ok(default) };
    raw.trim().parse().map_err(|_| ConfigError::Value {
        // An operator's own text out of this process's environment, never a byte from a dispatch, so
        // echoing it is safe and is what makes the mistake findable.
        var: name,
        detail: format!("expected a whole number, got `{raw}`"),
    })
}

/// The most slots this file will derive on its own. An operator who wants more says the number.
///
/// Eight slots is 32 GB of guest memory resident when the node is busy
/// ([`ResourceLimits`](hull_ci_node::ResourceLimits) defaults to 4 GB a job), and **memory, not
/// cores, is what a runner runs out of** — design D§6.4 sizes the warm pool the same way, as
/// `free_RAM / guest_RAM_per_job`, precisely because this process cannot see the operator's RAM
/// budget. Deriving further up a 64- or 128-core host would be this file sizing a machine it can
/// only see one dimension of, and being wrong there costs the OOM killer taking whichever step was
/// unluckiest — which arrives as a flaky `errored` verdict, not as a configuration error.
const MAX_DERIVED_NODE_SLOTS: u32 = 8;

/// How many steps run at once when nobody said. Design D§7.1's slot, sized by this host.
///
/// **Why this is derived and not a constant.** D§7.1 defines the unit — "one slot per CPU group
/// (default 2 cores + 4 GB)" — so the honest default is *how many of those groups this host has*,
/// and the group size is read from [`ResourceLimits::default`](hull_ci_node::ResourceLimits) rather
/// than restated here: the two numbers describe one thing, and a second spelling of `2` is how they
/// come apart the first time somebody tunes one.
///
/// **Why not `1`.** It was `1`, and it made a milestone unreachable rather than conservative: D§6.5
/// ships parallel DAG branches and fan-out, and one slot runs them serially whatever the pipeline
/// says. The evidence was in the startup log of every boot — the default plan permits 16 concurrent
/// steps per tenant and the composition root clamped it to `node_slots=1` on the way past, i.e. the
/// rest of the system was already asking for capacity this default refused to have.
///
/// **Why not "as many as there are cores".** A slot is a *concurrent sandbox*, holding its memory
/// and CPU for the length of a step; oversubscribing cores would also oversubscribe RAM, and see
/// [`MAX_DERIVED_NODE_SLOTS`] for what that costs. Dividing by the slot's own CPU share is the
/// derivation that keeps the promise the slot shape makes.
///
/// **A one-core machine still works.** The floor is 1, so a single-core host (and a two-core one)
/// gets exactly the behaviour it had before this was configurable.
///
/// **When the host will not say.** [`std::thread::available_parallelism`] fails on a platform that
/// does not report it, and on a container whose cgroup limits are unreadable; there is no number to
/// guess at then, so this falls back to `1` — slow, and correct. Guessing high would put a sandbox
/// per imaginary core on a host that may have one. The effective value is logged at startup either
/// way (see `hull_ci_server::assemble`), which is where a `1` on a large box announces itself.
fn default_node_slots() -> u32 {
    slots_for_cores(std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
}

/// [`default_node_slots`]' arithmetic, as a function of a core count — so the rule can be tested at
/// one core, at a hundred, and at the value a failed [`std::thread::available_parallelism`] produces,
/// on whatever machine happens to be running the suite. A test that could only assert what *this*
/// host derives would assert nothing.
fn slots_for_cores(cores: usize) -> u32 {
    // `max(1.0)` so a future edit to the slot's CPU share cannot divide by zero into a slot count of
    // infinity; the clamp below would catch it, but not before the cast.
    let per_slot = hull_ci_node::ResourceLimits::default().cpus.max(1.0);
    let derived = (cores as f32 / per_slot).floor().max(1.0);
    (derived as u32).clamp(1, MAX_DERIVED_NODE_SLOTS)
}

/// How many steps this node runs at once. `HULL_CI_NODE_SLOTS`, as a function of the raw value.
///
/// A named rule rather than an expression inside `from_env`, for the reason [`journal_enabled`] is
/// one: `from_env` reads the real process environment, so testing a rule written inline there means
/// mutating global state from a test — racy under a parallel harness, and `unsafe` besides.
///
/// **Zero refuses to start**, which is the one place this differs from [`whole_number`]. `0` is a
/// legitimate pool depth — no pre-created containers, every job starts cold — but a node with zero
/// slots accepts every dispatch and runs none of them, and spec §10 has Hull neither polling us nor
/// timing a job out, so each of those trees stays in-flight until a human forces a rerun. There is no
/// reading of `HULL_CI_NODE_SLOTS=0` that means something an operator wants; the way to run nothing
/// is to not start the process.
///
/// Anything that is not a whole number refuses too — including a negative one, which `u32` rejects
/// on its own — because a slot count silently defaulted after a typo is a runner whose concurrency
/// is not what its configuration says, and the symptom is a fleet that is mysteriously slow rather
/// than an error anybody can find.
fn node_slots(raw: Option<&str>) -> Result<u32, ConfigError> {
    let Some(raw) = raw else { return Ok(default_node_slots()) };
    let slots: u32 = raw.trim().parse().map_err(|_| ConfigError::Value {
        // An operator's own text out of this process's environment, never a byte from a dispatch, so
        // echoing it is safe and is what makes the mistake findable.
        var: "HULL_CI_NODE_SLOTS",
        detail: format!("expected a whole number of slots, got `{raw}`"),
    })?;
    if slots == 0 {
        return Err(ConfigError::Value {
            var: "HULL_CI_NODE_SLOTS",
            detail: "a node with no slots accepts dispatches and runs nothing, and spec §10 leaves \
                     every such tree in-flight until a human forces a rerun. To run nothing, do not \
                     start the runner"
                .into(),
        });
    }
    Ok(slots)
}

/// Is the write-ahead journal on? The `HULL_CI_JOURNAL` rule, as a function of the raw value.
///
/// A named predicate rather than an expression inside `from_env`, for the same reason the rest of
/// this crate names its gates: `from_env` reads the real process environment, so the only way to
/// test the rule inside it is to mutate global state from a test — which is racy under a parallel
/// harness and `unsafe` besides. Taking `Option<&str>` makes the decision an ordinary pure function,
/// and the thing that decides whether a dispatch is ever answered is worth being able to test
/// directly.
///
/// Unset means **on**. See the call site for why this switch defaults the opposite way to every
/// other one here.
fn journal_enabled(raw: Option<&str>) -> Result<bool, ConfigError> {
    match raw.map(|v| v.trim().to_ascii_lowercase()) {
        // Unset is on. An operator who configured nothing gets a runner that answers.
        None => Ok(true),
        Some(v) => match v.as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            // Refuse rather than guess, exactly as `SandboxChoice` and `SecretsMode` do, and for
            // the same reason: this is a safety switch, and the two ways to be wrong about it are
            // not equally bad. Reading an unrecognised value as *on* would ignore an operator who
            // is trying to turn it off; reading it as *off* would let a typo silently disarm the
            // thing that answers dispatches, which is the failure the default exists to prevent.
            // Neither is worth guessing at when the variable is right there to be spelled properly.
            other => Err(ConfigError::Value {
                var: "HULL_CI_JOURNAL",
                detail: format!("expected `on` or `off`, got `{other}`"),
            }),
        },
    }
}

/// Is content-store reclamation on? The `HULL_CI_RECLAIM` rule, as a function of the raw value.
///
/// A named predicate for the reason [`journal_enabled`] is one: `from_env` reads the real process
/// environment, so the only way to test a rule written inline there is to mutate global state from a
/// test — racy under a parallel harness, and `unsafe` besides.
///
/// The rule is deliberately identical to the journal's, spelled out rather than shared, because the
/// two switches are independent settings that happen to agree today: unset means **on**, `off` and
/// its synonyms mean off, and **anything else refuses to start**. That last clause is the one that
/// matters here. Reading an unrecognised value as *on* ignores an operator trying to turn reclamation
/// off — perhaps because they bound the store some other way and do not want a reaper touching it —
/// and reading it as *off* lets a typo silently disarm the only thing keeping the disk from filling,
/// which is the failure the default exists to prevent. Neither is worth guessing at.
fn reclaim_enabled(raw: Option<&str>) -> Result<bool, ConfigError> {
    match raw.map(|v| v.trim().to_ascii_lowercase()) {
        None => Ok(true),
        Some(v) => match v.as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => Err(ConfigError::Value {
                var: "HULL_CI_RECLAIM",
                detail: format!("expected `on` or `off`, got `{other}`"),
            }),
        },
    }
}

/// How long a tree survives its last use. `HULL_CI_RECLAIM_RETENTION_DAYS`, as a function of the raw
/// value.
///
/// **Days, not seconds**, because the unit is where this kind of variable goes wrong: an operator who
/// means a fortnight and types `14` into a seconds-valued variable gets a store that keeps nothing,
/// and finds out as a fleet-wide collapse in cache hits rather than as an error. Days makes the
/// plausible typo — an order of magnitude — cost disk instead of every hit.
///
/// Zero is accepted and means "reclaim every tree the moment nothing holds it". It is a legitimate
/// setting for a disk-starved runner, it loses no data (the tree is re-fetched from `source_url`),
/// and refusing it would be this file inventing a policy the operator did not ask for. The chosen
/// value is logged at startup, which is where a mistyped `0` announces itself.
///
/// Anything that is not a number refuses to start, exactly as an unrecognised switch value does: a
/// retention silently defaulted after a typo is a runner whose disk behaviour is not what its
/// configuration says.
fn reclaim_retention(raw: Option<&str>) -> Result<Duration, ConfigError> {
    let Some(raw) = raw else { return Ok(Config::default().reclaim_retention) };
    let days: u32 = raw.trim().parse().map_err(|_| ConfigError::Value {
        var: "HULL_CI_RECLAIM_RETENTION_DAYS",
        // The raw value is an operator's own text from this process's environment, never a byte from
        // a dispatch, so echoing it is safe and is what makes the mistake findable.
        detail: format!("expected a whole number of days, got `{raw}`"),
    })?;
    Ok(Duration::from_secs(u64::from(days) * 24 * 60 * 60))
}

/// A set variable that is empty or whitespace reads as unset. `HULL_CI_SECRET=` is a mistake, and
/// treating it as "no secret configured" is friendlier than authenticating against the empty string.
fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn is_truthy(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_the_safe_one() {
        let d = Config::default();
        assert_eq!(d.sandbox, SandboxChoice::Container, "the sandboxed backend is the default");
        assert!(!d.allow_unsandboxed, "running without a sandbox is never implicit");
        assert!(d.bind.ip().is_loopback());
        assert!(
            !d.trusted.is_trusted("acme"),
            "least privilege: an unconfigured deployment has no trusted tenant, so it runs nothing"
        );
        assert!(d.admin_token.is_none(), "the cross-tenant operator panel is off unless asked for");
        assert_eq!(
            d.proxy.mode,
            hull_ci_proxy::ProxyMode::Off,
            "§14.3: an unconfigured deployment runs every job with no outbound network"
        );
        assert!(d.proxy.network.is_none(), "and therefore on `--network none`");
        assert_eq!(
            d.secrets,
            SecretsMode::Off,
            "a runner nobody asked to hold tenant credentials holds none (D§7.4)"
        );
    }

    #[test]
    fn the_secrets_mode_refuses_anything_it_does_not_recognise() {
        // Same reasoning as the sandbox choice: a typo must not resolve to the mode that hands out
        // credentials, so there is no fuzzy match and no fallback.
        assert_eq!(SecretsMode::parse("off").unwrap(), SecretsMode::Off);
        assert_eq!(SecretsMode::parse(" DEV ").unwrap(), SecretsMode::Dev);
        // The KMS mode now exists and parses in *every* build, feature or not. That is deliberate:
        // a binary without the feature must fail at startup naming the missing feature, rather than
        // rejecting the value as unknown — an "unknown mode" error reads as though the mode is not a
        // thing, and the obvious next move is to set `dev`, which puts every tenant KEK in this
        // process's memory. The failure has to say *rebuild*, never *use something weaker*.
        assert_eq!(SecretsMode::parse("infisical").unwrap(), SecretsMode::Infisical);
        assert_eq!(SecretsMode::parse("kms").unwrap(), SecretsMode::Infisical);
        assert!(SecretsMode::parse("").is_err());
        assert!(SecretsMode::parse("infisicl").is_err(), "still no fuzzy matching");
    }

    #[test]
    fn the_sandbox_choice_refuses_anything_it_does_not_recognise() {
        // A typo must not resolve to a weaker backend, so there is no fuzzy match and no fallback.
        assert_eq!(SandboxChoice::parse("container").unwrap(), SandboxChoice::Container);
        assert_eq!(SandboxChoice::parse(" LOCAL ").unwrap(), SandboxChoice::LocalProcess);
        assert!(SandboxChoice::parse("none").is_err());
        assert!(SandboxChoice::parse("").is_err());
    }

    #[test]
    fn truthiness_is_explicit() {
        for yes in ["1", "true", "YES", " on "] {
            assert!(is_truthy(yes));
        }
        for no in ["0", "false", "", "maybe"] {
            assert!(!is_truthy(no));
        }
    }
}
#[cfg(test)]
mod journal_switch_tests {
    use super::journal_enabled;

    #[test]
    fn an_operator_who_configures_nothing_gets_the_journal() {
        assert!(journal_enabled(None).unwrap(), "silence must not be how a runner stops answering (spec §10)");
    }

    #[test]
    fn off_is_the_one_spelling_that_turns_a_safety_property_off() {
        for raw in ["off", "0", "false", "no", "OFF", "False"] {
            assert!(!journal_enabled(Some(raw)).unwrap(), "{raw:?} should turn the journal off");
        }
    }

    #[test]
    fn turning_it_on_explicitly_still_works() {
        for raw in ["on", "1", "true", "yes", "ON"] {
            assert!(journal_enabled(Some(raw)).unwrap(), "{raw:?} should leave the journal on");
        }
    }

    #[test]
    fn a_value_nobody_recognises_refuses_to_start() {
        // `HULL_CI_JOURNAL=maybe` must not resolve to either answer. Reading it as *on* ignores an
        // operator trying to turn the journal off; reading it as *off* lets a typo silently disarm
        // the thing that answers dispatches. The variable is right there to be spelled properly, so
        // this refuses at startup where it is cheap to notice.
        for raw in ["maybe", "onn", "disabled", "enabled", "y"] {
            let err = journal_enabled(Some(raw)).expect_err("{raw:?} must not be guessed at");
            assert!(err.to_string().contains("HULL_CI_JOURNAL"), "the error must name the variable");
        }
    }
}

/// The slot count, as a pure rule — see [`super::node_slots`] for why it is a function rather than
/// an expression inside `from_env`.
#[cfg(test)]
mod node_slot_tests {
    use super::{default_node_slots, node_slots, slots_for_cores, Config, MAX_DERIVED_NODE_SLOTS};

    #[test]
    fn an_operator_who_configures_nothing_gets_more_than_a_single_step_at_a_time() {
        // The default that was `1` made design D§6.5 unreachable: parallel branches and fan-out ran
        // serially however the pipeline was written, and the only evidence was a startup log saying
        // the plan's 16 had been clamped to one. The derivation is CPU groups (D§7.1: "one slot per
        // CPU group (default 2 cores + 4 GB)"), so on anything with four cores or more it is at least
        // two — and this assertion is written so it still holds on a single-core box.
        assert_eq!(slots_for_cores(4), 2, "four cores is two of D§7.1's 2-core slots");
        assert_eq!(slots_for_cores(16), 8);
        assert!(
            slots_for_cores(8) > 1,
            "an eight-core host must not run a fan-out one step at a time"
        );
    }

    #[test]
    fn a_machine_with_one_core_still_works_and_nothing_derives_past_the_cap() {
        // The two ends of the derivation. Below: a floor of one, because a runner that cannot run a
        // step is not a smaller runner, it is a broken one — and `0` is what plain division gives on
        // a single-core host.
        assert_eq!(slots_for_cores(1), 1);
        assert_eq!(slots_for_cores(2), 1);
        // `available_parallelism` failing is reported to this function as one core (see
        // `default_node_slots`), and it must land on the old, safe behaviour rather than a guess.
        assert_eq!(slots_for_cores(0), 1, "no answer from the host means one slot, never a guess");

        // Above: memory is what a runner runs out of, and this file cannot see the operator's RAM.
        assert_eq!(slots_for_cores(128), MAX_DERIVED_NODE_SLOTS);
        assert_eq!(slots_for_cores(usize::MAX), MAX_DERIVED_NODE_SLOTS);
        assert!(
            (1..=MAX_DERIVED_NODE_SLOTS).contains(&default_node_slots()),
            "whatever host this suite runs on, the derived default stays inside the bound"
        );
    }

    #[test]
    fn the_default_here_matches_the_default_a_config_is_built_with() {
        // Two spellings of one default is how a setting comes to mean different things depending on
        // which door you came in through — `Config::default()` for the end-to-end suite, `from_env`
        // for the binary.
        assert_eq!(Config::default().node_slots, node_slots(None).unwrap());
    }

    #[test]
    fn an_operator_may_ask_for_more_than_this_file_would_ever_derive() {
        // The cap bounds what is *guessed*, not what is *asked for*: someone who knows their box has
        // 256 GB says so, and this must not quietly clamp them back to eight.
        assert_eq!(node_slots(Some("2")).unwrap(), 2);
        assert_eq!(node_slots(Some(" 16 ")).unwrap(), 16);
        // …and 64 really is past what the derivation would ever produce, so that last line is the
        // property and not a coincidence.
        assert_eq!(node_slots(Some("64")).unwrap().min(MAX_DERIVED_NODE_SLOTS), MAX_DERIVED_NODE_SLOTS);
    }

    #[test]
    fn zero_slots_refuses_to_start() {
        // `0` is a legitimate `HULL_CI_POOL_DEPTH` — no pre-created containers, every job starts cold
        // — and it is *not* a legitimate slot count. A node with no slots accepts dispatches and runs
        // none of them, and spec §10 has Hull neither polling nor timing a job out, so every one of
        // those trees stays in-flight until a human forces a rerun. Refusing at startup costs an
        // error message; guessing costs a wedged repository.
        let err = node_slots(Some("0")).expect_err("a fleet of zero must not start");
        assert!(err.to_string().contains("HULL_CI_NODE_SLOTS"), "the error must name the variable: {err}");
    }

    #[test]
    fn a_slot_count_that_is_not_a_number_refuses_to_start() {
        // The rule the retention and the pool sizes follow, for the same reason: a count silently
        // defaulted after a typo is a runner whose concurrency is not what its configuration says,
        // and it announces itself as "the fleet feels slow" rather than as an error anyone can find.
        // `-1` is in here because it is the plausible typo that a signed parse would have accepted.
        for raw in ["", "on", "true", "-1", "1.5", "many", "4 slots", "1e3"] {
            let err = node_slots(Some(raw)).expect_err("must not be guessed at");
            assert!(
                err.to_string().contains("HULL_CI_NODE_SLOTS"),
                "the error must name the variable: {err}"
            );
        }
    }
}

/// The reclamation switch and its retention, as pure rules — see [`super::reclaim_enabled`] for why
/// they are functions rather than expressions inside `from_env`.
#[cfg(test)]
mod reclaim_switch_tests {
    use super::{reclaim_enabled, reclaim_retention, whole_number, Config};
    use std::time::Duration;

    const DAY: u64 = 24 * 60 * 60;

    #[test]
    fn an_operator_who_configures_nothing_gets_a_bounded_store() {
        assert!(
            reclaim_enabled(None).unwrap(),
            "doing nothing must not be how a runner fills its disk and fails every job on it"
        );
        assert_eq!(
            reclaim_retention(None).unwrap(),
            Duration::from_secs(14 * DAY),
            "a fortnight: long enough that a repo built weekly survives a holiday, short enough to bound the store"
        );
    }

    #[test]
    fn the_default_here_matches_the_default_a_config_is_built_with() {
        // Two spellings of one default is how a switch comes to mean different things depending on
        // which door you came in through — `Config::default()` for the end-to-end suite, `from_env`
        // for the binary.
        let d = Config::default();
        assert_eq!(d.reclaim, reclaim_enabled(None).unwrap());
        assert_eq!(d.reclaim_retention, reclaim_retention(None).unwrap());
        assert_eq!(d.pool_depth, whole_number("HULL_CI_POOL_DEPTH", None, d.pool_depth).unwrap());
    }

    #[test]
    fn the_warm_pool_is_off_until_an_operator_asks_for_it() {
        // Design §6.4 sizes a pool as `free_RAM / guest_RAM_per_job`, and this process cannot see the
        // operator's RAM budget. An idle member holds its configured memory whether or not a job ever
        // arrives, so a deployment that configured nothing gets no idle containers.
        assert_eq!(Config::default().pool_depth, 0);
        assert!(!hull_ci_node::PoolConfig { depth: 0, ..Default::default() }.enabled());
    }

    #[test]
    fn a_pool_size_that_is_not_a_number_refuses_to_start() {
        // The same rule the retention follows, and for the same reason: `HULL_CI_POOL_DEPTH=on` is
        // somebody trying to turn warm pools on and silently getting a node with no pool at all —
        // which is exactly the failure that is invisible from the outside, since every job would
        // still run, just cold.
        assert_eq!(whole_number("HULL_CI_POOL_DEPTH", Some("2"), 0).unwrap(), 2);
        assert_eq!(whole_number("HULL_CI_POOL_DEPTH", Some(" 4 "), 0).unwrap(), 4);
        // Zero is a legitimate setting and means off, which is why it is not refused.
        assert_eq!(whole_number("HULL_CI_POOL_DEPTH", Some("0"), 3).unwrap(), 0);
        for raw in ["on", "true", "-1", "1.5", "many"] {
            let err = whole_number("HULL_CI_POOL_DEPTH", Some(raw), 0).expect_err("must not be guessed at");
            assert!(err.to_string().contains("HULL_CI_POOL_DEPTH"), "must name the variable: {err}");
        }
    }

    #[test]
    fn off_is_the_one_spelling_that_stops_the_store_being_swept() {
        for raw in ["off", "0", "false", "no", "OFF", "False"] {
            assert!(!reclaim_enabled(Some(raw)).unwrap(), "{raw:?} should turn reclamation off");
        }
        for raw in ["on", "1", "true", "yes", "ON"] {
            assert!(reclaim_enabled(Some(raw)).unwrap(), "{raw:?} should leave reclamation on");
        }
    }

    #[test]
    fn a_value_nobody_recognises_refuses_to_start() {
        for raw in ["maybe", "onn", "disabled", "enabled", "y"] {
            let err = reclaim_enabled(Some(raw)).expect_err("must not be guessed at");
            assert!(err.to_string().contains("HULL_CI_RECLAIM"), "the error must name the variable");
        }
    }

    #[test]
    fn a_retention_is_days_and_refuses_anything_that_is_not_a_number() {
        assert_eq!(reclaim_retention(Some("1")).unwrap(), Duration::from_secs(DAY));
        assert_eq!(reclaim_retention(Some(" 30 ")).unwrap(), Duration::from_secs(30 * DAY));
        // Accepted, and it means what it says: nothing survives a sweep it is not pinned through.
        // Not data loss — the tree is re-fetched — so this is the operator's call to make.
        assert_eq!(reclaim_retention(Some("0")).unwrap(), Duration::ZERO);

        for raw in ["", "14d", "two weeks", "-1", "1.5", "1e3"] {
            let err = reclaim_retention(Some(raw)).expect_err("{raw:?} must not silently become a default");
            let msg = err.to_string();
            assert!(msg.contains("HULL_CI_RECLAIM_RETENTION_DAYS"), "the error must name the variable: {msg}");
        }
    }
}
