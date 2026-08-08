//! Warm sandbox pools for the container backend (D§6.4).
//!
//! Each node keeps a few pre-created, already-started sandboxes per *hot configuration*, so starting
//! a job is "materialize the workspace and exec" rather than "create a container and boot one".
//! D§1's latency table puts that at **40 ms warm against 200 ms cold**, and D§6.4 is explicit about
//! the shape: "containers unpacked … workspace mount point empty and waiting. Starting a job is then
//! *bind the workspace and exec*, not *pull an image and boot*."
//!
//! # This is not sandbox reuse, and it must never become it
//!
//! §14.1: "A sandbox **MUST NOT** be reused across jobs. Destroy the whole microVM/rootfs after each
//! job." Every clause of that still holds here, and it holds *by construction* rather than by
//! intention:
//!
//! * A pool member has **never run a job**. Between creation and claim it runs one process: the idle
//!   argv ([`PoolConfig::idle_argv`], a `sleep` out of the image itself), with an **empty** mount
//!   directory, no job environment, and no delivered secret.
//! * A member is handed to **exactly one** job. [`SandboxPool::claim`] *removes* it from the pool as
//!   it hands it over — there is no borrow, no return path, and no API that gives the same
//!   [`PoolMember`] out twice.
//! * It is **destroyed afterwards**, by the same `rm --force --volumes` every cold sandbox gets, plus
//!   the removal of its mount directory. The single-use state machine
//!   ([`UseGuard`](crate::sandbox::UseGuard)) is unchanged and still admits one `exec`.
//!
//! D§6.4 puts it best: "pre-warming is to sandbox lifetime what pre-heating an oven is to cooking two
//! meals in it." The §14 conformance table agrees in one line — "warm pools are pre-boot, not reuse
//! (§6.4)". What would turn this into the thing §14.1 forbids is *returning* a member to the pool
//! after a job, and there is deliberately no function in this module that could: [`PoolMember`] is
//! consumed by the sandbox that owns it and the pool never sees it again.
//!
//! # The mount problem, and the shape that solves it
//!
//! A docker container's bind mounts are fixed at `create` time and the workspace path is per-job, so
//! "pre-create, then bind the workspace" cannot be done literally — there is no API that adds a mount
//! to an existing container. Verified against docker 28.0.4, the shape that *does* work:
//!
//! 1. Each member is created with **its own fixed host directory**, empty, bind-mounted at the job's
//!    `workdir`. Only the empty mount *point* is prepared in advance.
//! 2. At claim, the job's workspace is **moved into that directory** ([`adopt_workspace`]). A bind
//!    mount is of a directory, so entries that appear inside it after the container started are
//!    visible to the container — confirmed live before any of this was built.
//! 3. The job's argv runs through `docker exec`, which shares the container's namespaces, cgroup,
//!    user, capability set and seccomp filter. Also confirmed live rather than assumed: inside an
//!    exec of a member created with this crate's flags, `id -u` is `65534`, `CapEff`/`CapBnd` are
//!    zero, `NoNewPrivs` is `1`, `/` is read-only, `--network none` still denies egress, and
//!    `memory.max`/`pids.max` are the container's ceilings.
//!
//! The move is O(number of top-level entries) rather than O(tree), which is what keeps the pool worth
//! having: a byte copy of the tree would cost far more than the container boot it saves. It is a
//! *move* and not a copy because the node's workspace is per (job, step) and is dropped at teardown
//! anyway (D§6.2, "teardown = drop the snapshot") — relocating a per-job snapshot is not observable
//! to anyone.
//!
//! # The property that makes a member safe to hand over
//!
//! A member must **never** be given to a job whose required posture differs from the one it was
//! created with. Handing a job that needs `--network none` a member created on the package-proxy
//! network is a silent egress escape: the job gets a network §14.3 says it must not have, and the
//! posture probe that would have caught it ([`crate::container::probe_network_posture`]) ran at
//! *creation* against a different sandbox.
//!
//! So [`PoolKey`] is not a summary of a member — **it is the complete recipe a member is created
//! from**. `warm_one` builds the container from `key.container_config()` and
//! `key.shape_spec()` and from nothing else, and [`SandboxPool::claim`] can only reach a member
//! stored under an equal key. "Created with these properties" and "matched on these properties" are
//! therefore the same value, not two values somebody has to keep in step. Both directions of the
//! network translation are **exhaustive matches**, so a new [`NetworkMode`] variant is a compile
//! error here rather than a silent inheritance of whatever the previous arm computed — the same
//! discipline `container::network_facts` is held to, for the same reason.
//!
//! # Bounded, and refilled without a background task
//!
//! [`PoolConfig::depth`] caps members per key and [`PoolConfig::total`] caps them across all keys.
//! Refill is **amortized onto teardown**, in the style `hull-ci-fetch`'s reclamation is amortized
//! onto commit and the memo's eviction onto accept: `destroy()` tops its own key back up by at most
//! one member. There is no timer to own, supervise or shut down, and no job ever waits for a refill —
//! an empty pool is a [`PoolStats::misses`] and a cold create, never a queue.
//!
//! Two consequences are stated rather than hidden. Depth *N* is reached after *N* jobs of a key, not
//! at node start; and a key that stops being used keeps its idle members until the total cap makes
//! room for a different key (see `warm_one`'s eviction).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use hull_ci_proto::AuthorClass;

use crate::container::{
    control_command, create_argv, short_id, ContainerConfig, NetworkMode, NetworkPosture,
    ProxyNetwork,
};
use crate::sandbox::{ExecStatus, ResourceLimits, SandboxError, SandboxSpec};

/// How many members a node keeps warm, and where their mount directories live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolConfig {
    /// Members kept per [`PoolKey`]. **`0` turns the pool off entirely**, which is the default: a
    /// deployment that did not ask for pre-created containers does not get idle containers holding
    /// its RAM. D§6.4 sizes the real cap in memory — "pool depth ≈ `free_RAM / guest_RAM_per_job`" —
    /// and this crate cannot see the operator's RAM budget, so the number is theirs.
    pub depth: usize,
    /// Members kept across **all** keys. The second half of "bounded": `depth` alone bounds one
    /// configuration, and a node that sees many images would otherwise hold `depth × images`
    /// containers resident.
    pub total: usize,
    /// Where member mount directories are created.
    ///
    /// **Must be on the same filesystem as the job workspaces**, or [`adopt_workspace`]'s move is an
    /// `EXDEV` and every claim falls back to a cold create. The composition root points it inside the
    /// work root for exactly that reason; a pool that silently never hits is the failure mode this
    /// whole module's counters exist to make visible.
    pub root: PathBuf,
    /// What a member runs while it waits.
    ///
    /// It has to be something that does not exit — a container that exits is removed by `--rm`
    /// (AutoRemove), which would leave the pool holding a name the daemon no longer has. It also has
    /// to exist *in the job's image*, and there is no command every image is guaranteed to carry, so
    /// this is configuration: an image without it simply fails to warm ([`PoolStats::warm_failures`])
    /// and its jobs take the cold path. That is the correct failure — a pool that cannot warm must
    /// cost latency, never correctness.
    pub idle_argv: Vec<String>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        PoolConfig {
            // Off. Idle containers cost resident memory whether or not a job ever arrives, and D§6.4
            // is explicit that the cap is a memory budget only the operator knows.
            depth: 0,
            total: 8,
            root: std::env::temp_dir().join("hull-ci-pool"),
            // Busybox and coreutils both have it, and `2147483647` seconds is longer than any node
            // stays up. Not `sleep infinity`, which is a GNU extension busybox does not take.
            idle_argv: vec!["/bin/sleep".into(), "2147483647".into()],
        }
    }
}

impl PoolConfig {
    /// The pool, switched off. Named rather than spelled out, because a member's *own* configuration
    /// must carry it: a pool member is not itself allowed to have a pool.
    pub fn off() -> Self {
        PoolConfig { depth: 0, ..PoolConfig::default() }
    }

    pub fn enabled(&self) -> bool {
        self.depth > 0 && self.total > 0
    }
}

/// The network a sandbox was created on, in a form that can be compared.
///
/// Built from [`NetworkMode`] by an exhaustive match and turned back into one by another, so the
/// network a member was created on and the network a claim asks for are the same value rather than
/// two descriptions of it.
///
/// The `ProxyOnly` arm carries the **measured posture**, not just the network's name. Two backends
/// can name the same docker network and disagree about what a container on it could reach — one
/// probed it and one did not, or the network's rules changed between two node starts — and a member
/// created under the posture that certified egress-deny must not be handed to a backend that could
/// not certify it. Carrying the whole [`NetworkPosture`] makes that a value comparison instead of a
/// judgement call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkIdentity {
    None,
    Named(String),
    ProxyOnly { network: String, endpoint: String, posture: Option<NetworkPosture> },
}

/// The resource ceilings a container was created with, as the daemon reads them.
///
/// `cpus` is kept as the rendered string rather than the `f32`, for two reasons that both matter:
/// `f32` is not `Eq`, and `--cpus` is passed as `{:.2}`, so `1.0` and `1.004` are *the same
/// container* to the daemon. Comparing the rendered value is comparing what was actually enforced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitsKey {
    cpus: String,
    memory_bytes: u64,
    pids: u32,
    tmpfs_bytes: u64,
}

impl LimitsKey {
    fn of(limits: &ResourceLimits) -> Self {
        LimitsKey {
            // Exactly the string `create_argv` passes.
            cpus: format!("{:.2}", limits.cpus),
            memory_bytes: limits.memory_bytes,
            pids: limits.pids,
            tmpfs_bytes: limits.tmpfs_bytes,
        }
    }

    fn to_limits(&self) -> ResourceLimits {
        ResourceLimits {
            cpus: self.cpus.parse().unwrap_or(0.0),
            memory_bytes: self.memory_bytes,
            pids: self.pids,
            tmpfs_bytes: self.tmpfs_bytes,
            // Not a create-time property on this backend: §14.4's disk clause is unmet here and
            // `create_argv` passes no `--storage-opt`, so it cannot make two sandboxes differ.
            disk_bytes: 0,
        }
    }
}

/// Everything that must be identical for two sandboxes to be interchangeable — **and the complete
/// recipe one is created from**.
///
/// Those two sentences describe one value on purpose. If the key were a *summary* of a member, then
/// "what this member was created with" and "what a claim matches on" would be two pieces of state,
/// and the way that goes wrong is the worst failure this module has: a job that needed no network
/// handed a member sitting on the package-proxy network, with the posture probe that would have
/// caught it having run at creation against some other container. Making the key the recipe means
/// there is no second piece of state to drift.
///
/// Every field is something `create_argv` reads:
///
/// | field | flag it decides | why a mismatch matters |
/// |---|---|---|
/// | `network` | `--network` | §14.3 egress. **The dangerous one** — see the module docs. |
/// | `image` | the image argument | a job would run on someone else's rootfs |
/// | `workdir` | `--mount target=`, `--workdir` | the workspace would not be where the job looks |
/// | `limits` | `--cpus`/`--memory`/`--pids-limit`/`--tmpfs` | §14.4 ceilings, fixed at create |
/// | `user` | `--user` | §14.4 non-root |
/// | `seccomp_profile` | `--security-opt seccomp=` | §14.4 default-deny syscall filter |
/// | `runtime`, `runner_id` | which daemon, and the reaper's label | a member another runner reaps |
///
/// `the_pool_key_covers_every_property_a_create_derives_from_the_job`, below, is the guard against
/// this list falling behind [`create_argv`]: it diffs a member's create argv against a job's and
/// fails if anything outside the job-varying set differs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolKey {
    runtime: String,
    runner_id: String,
    user: String,
    seccomp_profile: Option<PathBuf>,
    network: NetworkIdentity,
    image: String,
    workdir: String,
    limits: LimitsKey,
}

impl PoolKey {
    /// The key a job needs — which is also the recipe a member for it is built from.
    pub fn for_job(config: &ContainerConfig, spec: &SandboxSpec) -> PoolKey {
        PoolKey {
            runtime: config.runtime.clone(),
            runner_id: config.runner_id.clone(),
            user: config.user.clone(),
            seccomp_profile: config.seccomp_profile.clone(),
            // Exhaustive on purpose: a new `NetworkMode` variant must not be able to reach this
            // function and come out as one of the existing identities. Adding one breaks the build
            // here and in `network_mode` below, which is the only way a network posture can be kept
            // from silently joining an existing pool.
            network: match &config.network {
                NetworkMode::None => NetworkIdentity::None,
                NetworkMode::Named(n) => NetworkIdentity::Named(n.clone()),
                NetworkMode::ProxyOnly(proxy) => NetworkIdentity::ProxyOnly {
                    network: proxy.network.clone(),
                    endpoint: proxy.endpoint.clone(),
                    posture: proxy.posture.clone(),
                },
            },
            image: spec.image.clone(),
            workdir: spec.workdir.clone(),
            limits: LimitsKey::of(&spec.limits),
        }
    }

    /// The network a member for this key is created on. The other half of the exhaustive pair.
    fn network_mode(&self) -> NetworkMode {
        match &self.network {
            NetworkIdentity::None => NetworkMode::None,
            NetworkIdentity::Named(n) => NetworkMode::Named(n.clone()),
            NetworkIdentity::ProxyOnly { network, endpoint, posture } => {
                let mut proxy = ProxyNetwork::new(network.clone(), endpoint.clone());
                // `ProxyNetwork::new` deliberately has no posture parameter, so this is the one
                // place a posture is carried across — and it is carried, never invented: what goes
                // back is exactly what `for_job` observed on the backend that asked.
                proxy.posture = posture.clone();
                NetworkMode::ProxyOnly(proxy)
            }
        }
    }

    /// The configuration a member for this key is created with.
    ///
    /// **Reconstructed from the key, never borrowed from the caller.** A member built from the
    /// backend's `ContainerConfig` while being *filed* under a key would be two facts that could
    /// disagree; built from the key, "created on this network" and "claimed for this network" are the
    /// same field read twice.
    fn container_config(&self, control_timeout: Duration) -> ContainerConfig {
        ContainerConfig {
            runtime: self.runtime.clone(),
            network: self.network_mode(),
            user: self.user.clone(),
            seccomp_profile: self.seccomp_profile.clone(),
            // The only value not from the key, and the only one that cannot make two sandboxes
            // differ: it bounds how long *we* wait on the CLI, and nothing about the container.
            control_timeout,
            runner_id: self.runner_id.clone(),
            // A pool member does not get a pool of its own.
            pool: PoolConfig::off(),
        }
    }

    /// The spec a member is created from: this key's shape, and a job-shaped hole where the job goes.
    ///
    /// The environment and the delivered secrets are **empty**, and that is a security property
    /// rather than an omission: a member exists before any job is assigned to it, so there is nothing
    /// of anyone's to bake in. The job's own environment arrives at `docker exec`, under the same
    /// rules `create_argv` applies — allowlisted values as `NAME=VALUE`, broker-delivered ones by
    /// name only.
    fn shape_spec(&self, mount_dir: &Path) -> SandboxSpec {
        SandboxSpec {
            // Not a job id. It lands in `--label hull-ci.job=`, and a member that has never run a job
            // must not claim one — an operator listing containers should see `warm-pool` there and
            // know this container is holding nobody's work. Docker cannot relabel a running
            // container, so the label stays `warm-pool` for the member's whole life; the sandbox id
            // in the node's logs is the container's *name*, which is unique per member.
            job_id: "warm-pool".into(),
            step_id: "unclaimed".into(),
            image: self.image.clone(),
            workspace: mount_dir.to_path_buf(),
            workdir: self.workdir.clone(),
            limits: self.limits.to_limits(),
            env: Vec::new(),
            author_class: AuthorClass::Outsider,
            broker_authorised: Vec::new(),
            secret_env: Vec::new(),
        }
    }

    /// The image this key's members run. For logs.
    pub fn image(&self) -> &str {
        &self.image
    }
}

/// A sandbox created before the job that will use it, and handed to exactly one.
///
/// Deliberately not `Clone` and deliberately without a "return to pool" constructor: the only way to
/// obtain one is [`SandboxPool::claim`], which removes it from the pool, and the only thing that can
/// be done with it afterwards is run one job and destroy it (§14.1).
#[derive(Debug)]
pub struct PoolMember {
    name: String,
    mount_dir: PathBuf,
    key: PoolKey,
    config: ContainerConfig,
}

impl PoolMember {
    /// The container's name, which is also the sandbox id the node logs.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The host directory bind-mounted at the job's `workdir`, empty until this member is claimed.
    pub fn mount_dir(&self) -> &Path {
        &self.mount_dir
    }

    pub fn key(&self) -> &PoolKey {
        &self.key
    }

    /// The configuration this member was **created with** — rebuilt from its key, so it is not a
    /// second opinion about the network the container is on.
    pub fn config(&self) -> &ContainerConfig {
        &self.config
    }
}

/// What the pool has actually done, as counters rather than as an inference.
///
/// This exists because of a specific way a warm pool fails: **a pool that silently never warms passes
/// every functional test.** Every job takes the cold path, every job works, and the only symptom is
/// latency nobody is measuring in a test. So the hit is an asserted fact — `hits` went up, and the
/// container the job ran in is one that existed before the job did — and never an inference from a
/// stopwatch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PoolStats {
    /// Members created and started successfully.
    pub warmed: u64,
    /// Claims that found a member. The number that says the pool is doing anything at all.
    pub hits: u64,
    /// Claims that found nothing and sent the job down the cold path. Not a failure — this is what
    /// exhaustion is *supposed* to look like.
    pub misses: u64,
    /// Members destroyed without ever running a job: evicted to make room, or dropped because the
    /// daemon no longer had them.
    pub retired: u64,
    /// Warms that could not be created or started. The image has no idle command, the daemon
    /// refused, the mount root is not writable.
    pub warm_failures: u64,
    /// Members that were claimed and then could not be handed over — the container had stopped, or
    /// the workspace could not be moved into its mount directory. The job takes the cold path.
    pub claim_failures: u64,
    /// Members found filed under a key that is not their own. Structurally impossible; counted
    /// because "impossible" is a claim about code that can be edited, and the failure it would cause
    /// is a job running under someone else's network posture.
    pub key_mismatches: u64,
}

/// One idle member, plus the sequence number that orders eviction.
#[derive(Debug)]
struct Idle {
    key: PoolKey,
    member: PoolMember,
    /// Monotonic **counter**, not a clock. Ordering is all that is wanted, and a clock would make
    /// eviction depend on wall time — which this repo does not test against and should not depend on.
    seq: u64,
}

/// A node's warm sandboxes (D§6.4).
#[derive(Debug)]
pub struct SandboxPool {
    config: PoolConfig,
    control_timeout: Duration,
    /// A `Vec` rather than a map, because the number of hot keys on one node is a handful of images
    /// and a linear scan over it is nothing next to the `docker` round trip it saves. It also spares
    /// [`PoolKey`] a `Hash` impl over [`NetworkPosture`], which would be a second definition of
    /// "these two sandboxes are the same" and therefore a second thing to keep in step.
    idle: Mutex<Vec<Idle>>,
    stats: Mutex<PoolStats>,
    seq: AtomicU64,
}

impl SandboxPool {
    pub fn new(config: PoolConfig, control_timeout: Duration) -> SandboxPool {
        SandboxPool {
            config,
            control_timeout,
            idle: Mutex::new(Vec::new()),
            stats: Mutex::new(PoolStats::default()),
            seq: AtomicU64::new(0),
        }
    }

    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    pub fn stats(&self) -> PoolStats {
        *self.stats.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn count(&self, f: impl FnOnce(&mut PoolStats)) {
        f(&mut self.stats.lock().unwrap_or_else(|e| e.into_inner()));
    }

    /// Take a member for this key, or `None`.
    ///
    /// `None` is an ordinary answer, not an error: the caller creates a container the cold way. **No
    /// job ever waits for a refill** — queueing work behind housekeeping is how a pool turns a
    /// latency optimization into a latency problem.
    pub async fn claim(&self, key: &PoolKey) -> Option<PoolMember> {
        if !self.config.enabled() {
            return None;
        }
        loop {
            let Some(idle) = self.take_matching(key) else {
                self.count(|s| s.misses += 1);
                return None;
            };
            // Structurally impossible: `take_matching` compares the stored key. Checked anyway,
            // because the consequence of being wrong is a job running with a network posture it was
            // never cleared for, and "impossible" is a statement about code somebody can edit. A
            // mismatch is destroyed rather than handed over, and the loop tries the next member.
            if idle.member.key != *key {
                tracing::error!(
                    container = %idle.member.name,
                    "a warm sandbox was filed under a key that is not its own; destroying it rather \
                     than running a job in it (§14.1, §14.3)"
                );
                self.count(|s| s.key_mismatches += 1);
                self.discard(idle.member).await;
                continue;
            }
            // A member the daemon no longer has, or one whose idle process died, would fail the job
            // at `exec` — after the workspace has already been moved into it. Ask before that point,
            // so the answer is a cold create rather than an `errored` verdict.
            if !self.still_running(&idle.member).await {
                tracing::warn!(
                    container = %idle.member.name,
                    "a warm sandbox was no longer running when it was claimed; taking the cold path"
                );
                self.count(|s| s.claim_failures += 1);
                self.discard(idle.member).await;
                continue;
            }
            self.count(|s| s.hits += 1);
            return Some(idle.member);
        }
    }

    /// Remove the first idle member filed under an **equal** key.
    ///
    /// The whole security property of this module is one `==` in this function: there is no "closest
    /// match", no fallback to a compatible-looking member, and no way for a caller to ask for
    /// anything other than exact equality, because [`PoolKey`] has no public field to relax.
    fn take_matching(&self, key: &PoolKey) -> Option<Idle> {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        let at = idle.iter().position(|i| i.key == *key)?;
        Some(idle.remove(at))
    }

    /// Top this key back up, by at most one member. Called from teardown (§6.4, D§4.2's style).
    ///
    /// One member per call is what makes this *amortized* rather than a burst: a key reaches
    /// [`PoolConfig::depth`] after `depth` jobs, so the steady state of a busy key is one warm create
    /// per job — off the path to any verdict, since teardown runs after the output has been
    /// collected.
    ///
    /// Never returns an error and never panics. D§6.4 buys latency; a pool that could fail a job
    /// would be trading a verdict for it.
    pub async fn refill(&self, key: &PoolKey) {
        if !self.config.enabled() {
            return;
        }
        if self.idle_for(key) >= self.config.depth {
            return;
        }
        if let Err(e) = self.warm_one(key).await {
            self.count(|s| s.warm_failures += 1);
            // `error`, because the operator asked for a pool and is not getting one, and the symptom
            // — every job quietly taking the cold path — is invisible from the outside.
            tracing::error!(
                image = %key.image,
                error = %e,
                "could not warm a sandbox; jobs for this configuration will take the cold path (D§6.4)"
            );
        }
    }

    fn idle_for(&self, key: &PoolKey) -> usize {
        let idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        idle.iter().filter(|i| i.key == *key).count()
    }

    /// Create and start one member for `key`.
    ///
    /// The container is built from `key.container_config()` and `key.shape_spec()` — the key and
    /// nothing else — which is what makes "this member's posture" and "the posture it is filed under"
    /// the same fact.
    async fn warm_one(&self, key: &PoolKey) -> Result<(), SandboxError> {
        self.make_room(key).await?;

        let config = key.container_config(self.control_timeout);
        let mount_dir = self.config.root.join(format!("warm-{}", short_id()));
        std::fs::create_dir_all(&mount_dir)?;
        let name = format!("hull-ci-warm-{}", short_id());
        let member = PoolMember { name, mount_dir, key: key.clone(), config };

        let create = create_argv(
            &member.config,
            &key.shape_spec(&member.mount_dir),
            &member.name,
            &self.config.idle_argv,
        );
        let (status, out) = control_command(&member.config, create, &[]).await?;
        if status != ExecStatus::Exited(0) {
            // Remove the directory, but not the container: a `create` we did not hear back from may
            // have completed on the daemon's side, and the runner label is what collects that one at
            // the next node start (§14.1) — the same reasoning `ContainerInstance::exec` documents.
            let _ = std::fs::remove_dir_all(&member.mount_dir);
            return Err(SandboxError::Runtime(format!("warm create failed ({status:?}): {out}")));
        }

        let start = vec![member.config.runtime.clone(), "start".into(), member.name.clone()];
        let (status, out) = control_command(&member.config, start, &[]).await?;
        if status != ExecStatus::Exited(0) {
            self.discard(member).await;
            return Err(SandboxError::Runtime(format!("warm start failed ({status:?}): {out}")));
        }
        // An idle argv the image does not have starts and exits immediately, and `--rm` then removes
        // the container — leaving the pool holding a name the daemon does not have. Checking here
        // turns "this image cannot be pooled" into a warm failure the operator is told about, rather
        // than into a claim failure on somebody's job.
        if !self.still_running(&member).await {
            self.discard(member).await;
            return Err(SandboxError::Runtime(format!(
                "a warm sandbox exited immediately; `{}` is probably not present in the image",
                self.config.idle_argv.join(" ")
            )));
        }

        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        self.idle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Idle { key: key.clone(), member, seq });
        self.count(|s| s.warmed += 1);
        Ok(())
    }

    /// Make room under [`PoolConfig::total`] for one more member of `key`.
    ///
    /// Eviction takes the **oldest idle member of some other key**, which is the only shape that is
    /// both bounded and self-correcting without a timer: a node whose workload moves from one image
    /// to another gives the old image's members up as the new one asks for room, and a node with one
    /// hot key never evicts anything. A pool that is full of the key being warmed is left alone —
    /// there is nothing useful to trade.
    async fn make_room(&self, key: &PoolKey) -> Result<(), SandboxError> {
        let victim = {
            let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
            if idle.len() < self.config.total {
                return Ok(());
            }
            let at = idle
                .iter()
                .enumerate()
                .filter(|(_, i)| i.key != *key)
                .min_by_key(|(_, i)| i.seq)
                .map(|(at, _)| at);
            match at {
                Some(at) => idle.remove(at),
                None => {
                    return Err(SandboxError::Runtime(format!(
                        "the warm pool is at its cap of {} and holds only members of this \
                         configuration, so there is nothing to evict",
                        self.config.total
                    )))
                }
            }
        };
        self.discard(victim.member).await;
        Ok(())
    }

    /// Is this member's container still there and still running?
    async fn still_running(&self, member: &PoolMember) -> bool {
        let argv = vec![
            member.config.runtime.clone(),
            "inspect".into(),
            member.name.clone(),
            "--format".into(),
            "{{.State.Running}}".into(),
        ];
        matches!(
            control_command(&member.config, argv, &[]).await,
            Ok((ExecStatus::Exited(0), out)) if out.trim() == "true"
        )
    }

    /// Destroy a member that never ran a job.
    ///
    /// The same teardown a used sandbox gets, for the same §14.1 reason: an idle member is a
    /// container with a host directory bind-mounted into it, and one left behind is exactly the
    /// orphan [`crate::container::reap_orphans`] exists to collect.
    async fn discard(&self, member: PoolMember) {
        remove_container(&member.config, &member.name).await;
        remove_mount_dir(&member.mount_dir);
        self.count(|s| s.retired += 1);
    }

    /// Destroy a member that was claimed and then could not be handed over.
    ///
    /// Public because the failure it covers is the backend's to notice, not the pool's: the claim
    /// succeeded and the *workspace move* did not. The member is destroyed rather than put back —
    /// there is no put-back — and the job takes the cold path.
    pub async fn discard_claimed(&self, member: PoolMember) {
        self.count(|s| s.claim_failures += 1);
        self.discard(member).await;
    }

    /// Destroy every idle member. For a node that is shutting down cleanly.
    ///
    /// Not the guarantee — [`crate::container::reap_orphans`] at the next node start is, exactly as
    /// it is for job containers, because a `SIGKILL` runs no shutdown code. Every member carries the
    /// runner label ([`create_argv`] writes it on everything), so the reaper finds them.
    pub async fn drain(&self) {
        let members: Vec<Idle> =
            std::mem::take(&mut *self.idle.lock().unwrap_or_else(|e| e.into_inner()));
        for idle in members {
            self.discard(idle.member).await;
        }
    }
}

impl Drop for SandboxPool {
    /// Best-effort removal of whatever is still idle, on the same terms as
    /// `ContainerInstance`'s `Drop`: **spawned, never blocked on**.
    ///
    /// A destructor that blocked on a daemon socket would stall a Tokio worker for
    /// `control_timeout` per member, on the runtime's own threads, possibly against the very daemon
    /// that has stopped answering. So this schedules the removals and returns, and says so when
    /// there is no runtime to schedule them onto. The guarantee remains the reaper at next start.
    fn drop(&mut self) {
        let members: Vec<Idle> =
            std::mem::take(&mut *self.idle.lock().unwrap_or_else(|e| e.into_inner()));
        if members.is_empty() {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::error!(
                idle = members.len(),
                "the warm pool was dropped outside a Tokio runtime, so its members could not be \
                 removed; they will be reaped at next node start (§14.1)"
            );
            return;
        };
        handle.spawn(async move {
            for idle in members {
                remove_container(&idle.member.config, &idle.member.name).await;
                remove_mount_dir(&idle.member.mount_dir);
            }
        });
    }
}

/// `rm --force --volumes`, the same teardown a used sandbox gets (§14.1).
pub(crate) async fn remove_container(config: &ContainerConfig, name: &str) {
    let argv = vec![
        config.runtime.clone(),
        "rm".into(),
        "--force".into(),
        "--volumes".into(),
        name.to_string(),
    ];
    match control_command(config, argv, &[]).await {
        Ok((ExecStatus::Exited(0), _)) => {}
        Ok((status, out)) => tracing::error!(
            container = %name, ?status, %out,
            "could not remove a warm sandbox; it will be reaped at next node start (§14.1)"
        ),
        Err(e) => tracing::error!(
            container = %name, error = %e,
            "could not remove a warm sandbox; it will be reaped at next node start (§14.1)"
        ),
    }
}

/// Remove a member's mount directory — which, after a claim, holds the job's whole workspace.
///
/// This is D§6.2's "teardown = drop the snapshot" for the pooled path. It runs after the container
/// is gone, so nothing is reading it.
pub(crate) fn remove_mount_dir(dir: &Path) {
    if let Err(e) = std::fs::remove_dir_all(dir) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(path = %dir.display(), error = %e, "could not remove a warm sandbox's mount directory");
        }
    }
}

/// Move a job's workspace into a member's mount directory.
///
/// This is the step D§6.4 calls "bind the workspace", done the only way docker allows: the mount was
/// fixed at `create`, so the *contents* move rather than the mount point. A bind mount is of a
/// directory, and entries that appear in it afterwards are visible inside the container — verified
/// against docker 28.0.4 before anything here was built.
///
/// # Why a move and not a copy
///
/// A copy would cost O(tree) and buy a saving of ~160 ms (D§1), which for any real checkout is a
/// straight loss — a pool that made jobs slower would be worse than no pool. A rename is O(1) per
/// top-level entry. It is safe to move because the workspace is per (job, step), is built for this
/// one step, and is dropped at teardown (D§6.2): the caller's directory is left empty and is then
/// removed by whoever created it, and the files themselves are destroyed with the member.
///
/// # Why the probe
///
/// `rename(2)` refuses to cross filesystems (`EXDEV`), and a pool root on a different filesystem from
/// the work root is an easy misconfiguration. Probing with one throwaway file finds that out **before
/// anything has moved**, which is what keeps the failure a clean "take the cold path" rather than a
/// half-moved workspace. If a later rename fails anyway the moved entries are put back, and only a
/// filesystem that has started failing renames in both directions can get past that — at which point
/// an `errored` verdict is the honest answer, because a job run against a workspace missing half its
/// files would report `red` about code that is fine.
pub fn adopt_workspace(from: &Path, into: &Path) -> std::io::Result<()> {
    // A member has never run a job, so its mount directory is empty. If it is not, something is very
    // wrong and the job must not inherit whatever is in there (§14.1).
    if std::fs::read_dir(into)?.next().is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("warm sandbox mount directory `{}` is not empty", into.display()),
        ));
    }
    // Wrapped, and the wrapping is load-bearing rather than decorative. A rename that fails inside
    // the loop below and a rename that fails here produce the same `io::Error`, so without a message
    // only this path can produce, "the probe ran" and "the probe was deleted and the first entry
    // failed instead" are indistinguishable — to an operator reading a log and to a test. The text
    // also happens to be the one an operator needs: the two paths, and the fact that nothing moved.
    probe_rename(from, into).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "`{}` and `{}` cannot be renamed between — different filesystems, or a destination \
                 that refuses a rename ({e}); nothing has been moved",
                from.display(),
                into.display()
            ),
        )
    })?;
    // The job's workspace was created by `fs::create_dir`; the member's by `create_dir_all`. Match
    // the mode so a pooled job sees the same permissions on its workdir as a cold one.
    if let Ok(meta) = std::fs::metadata(from) {
        let _ = std::fs::set_permissions(into, meta.permissions());
    }

    let mut moved: Vec<std::ffi::OsString> = Vec::new();
    for entry in std::fs::read_dir(from)? {
        let name = entry?.file_name();
        if let Err(e) = std::fs::rename(from.join(&name), into.join(&name)) {
            for done in &moved {
                // Best effort, and the failure is reported rather than swallowed: the caller turns
                // it into an `errored` verdict, which is the right answer for a workspace we can no
                // longer vouch for.
                if let Err(back) = std::fs::rename(into.join(done), from.join(done)) {
                    return Err(std::io::Error::other(format!(
                        "could not move the workspace into the warm sandbox ({e}), and could not \
                         move `{}` back ({back}); the workspace is now split across two directories",
                        done.to_string_lossy()
                    )));
                }
            }
            return Err(e);
        }
        moved.push(name);
    }
    Ok(())
}

/// Find out whether these two directories are on one filesystem, by renaming something between them.
///
/// Asking the filesystem directly (`st_dev`) would answer a subtly different question — bind mounts
/// and `overlayfs` can share a device number and still refuse a rename — so the probe *does the
/// thing*, which is the standard the rest of this crate's probes are held to.
fn probe_rename(from: &Path, into: &Path) -> std::io::Result<()> {
    let name = format!(".hull-ci-pool-probe-{}", short_id());
    let src = from.join(&name);
    let dst = into.join(&name);
    std::fs::write(&src, b"")?;
    let result = std::fs::rename(&src, &dst);
    // Whichever side it ended on.
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::{DockerProbe, RUNNER_LABEL};
    use std::path::Path;

    fn spec(ws: &Path) -> SandboxSpec {
        SandboxSpec {
            job_id: "job-1".into(),
            step_id: "step-1".into(),
            image: "hull-ci/base:1".into(),
            workspace: ws.to_path_buf(),
            workdir: "/workspace".into(),
            limits: Default::default(),
            env: crate::env::base_env("/tmp"),
            author_class: AuthorClass::Member,
            broker_authorised: Vec::new(),
            secret_env: Vec::new(),
        }
    }

    fn proxy_config(posture: Option<NetworkPosture>) -> ContainerConfig {
        let mut proxy = ProxyNetwork::new("hull-ci-sandbox", "172.18.0.1:3128");
        proxy.posture = posture;
        ContainerConfig { network: NetworkMode::ProxyOnly(proxy), ..ContainerConfig::default() }
    }

    fn proven_posture() -> NetworkPosture {
        NetworkPosture {
            declared_internal: true,
            no_default_route: true,
            public_ip_unreachable: true,
            public_dns_unresolvable: true,
            metadata_unreachable: true,
            proxy_reachable: true,
            peer_unreachable: true,
            cannot_add_route: true,
            gateway_ports_open: Vec::new(),
            failure: None,
        }
    }

    #[test]
    fn a_member_created_for_one_network_can_never_be_claimed_for_the_other() {
        // **The test this module exists for.** Handing a `--network none` job a member created on the
        // package-proxy network is a silent egress escape: §14.3's guarantee is gone, and the posture
        // probe that would have caught it ran at creation against a different container.
        let t = tempfile::tempdir().unwrap();
        let no_network = ContainerConfig::default();
        let proxied = proxy_config(Some(proven_posture()));

        let cold = PoolKey::for_job(&no_network, &spec(t.path()));
        let warm = PoolKey::for_job(&proxied, &spec(t.path()));
        assert_ne!(cold, warm, "two network postures are never one pool");

        // …and the same network with a posture nobody measured is a third key again, because a
        // backend that could not certify egress-deny must not inherit a member from one that could.
        let unproven = PoolKey::for_job(&proxy_config(None), &spec(t.path()));
        assert_ne!(warm, unproven, "an unmeasured posture is not the measured one");

        // A named bridge is neither.
        let named = ContainerConfig { network: NetworkMode::Named("ci".into()), ..Default::default() };
        let named = PoolKey::for_job(&named, &spec(t.path()));
        assert_ne!(named, cold);
        assert_ne!(named, warm);

        // And the round trip is the identity, so a member really is created on the network its key
        // names rather than on the backend's.
        assert_eq!(cold.container_config(Duration::from_secs(1)).network, NetworkMode::None);
        match warm.container_config(Duration::from_secs(1)).network {
            NetworkMode::ProxyOnly(p) => {
                assert_eq!(p.network, "hull-ci-sandbox");
                assert_eq!(p.posture, Some(proven_posture()), "the measured posture travels with it");
            }
            other => panic!("the proxy posture did not survive the key: {other:?}"),
        }
    }

    #[test]
    fn every_property_that_changes_the_container_changes_the_key() {
        // Anything a job can vary that reaches `create` has to partition the pool, or a job gets a
        // container built for different rules. Each case below is one such property.
        let t = tempfile::tempdir().unwrap();
        let base_config = ContainerConfig::default();
        let base = PoolKey::for_job(&base_config, &spec(t.path()));

        let mut other_image = spec(t.path());
        other_image.image = "alpine:3".into();
        assert_ne!(base, PoolKey::for_job(&base_config, &other_image), "image");

        let mut other_workdir = spec(t.path());
        other_workdir.workdir = "/src".into();
        assert_ne!(base, PoolKey::for_job(&base_config, &other_workdir), "workdir");

        for (why, limits) in [
            ("cpus", ResourceLimits { cpus: 1.0, ..Default::default() }),
            ("memory", ResourceLimits { memory_bytes: 1 << 20, ..Default::default() }),
            ("pids", ResourceLimits { pids: 7, ..Default::default() }),
            ("tmpfs", ResourceLimits { tmpfs_bytes: 1 << 20, ..Default::default() }),
        ] {
            let mut s = spec(t.path());
            s.limits = limits;
            assert_ne!(base, PoolKey::for_job(&base_config, &s), "{why}");
        }

        for (why, config) in [
            ("user", ContainerConfig { user: "1000:1000".into(), ..Default::default() }),
            (
                "seccomp",
                ContainerConfig { seccomp_profile: Some("/etc/p.json".into()), ..Default::default() },
            ),
            ("runtime", ContainerConfig { runtime: "podman".into(), ..Default::default() }),
            // The runner label is what `reap_orphans` matches on, so a member carrying another
            // runner's label is one that runner will delete out from under a live job.
            ("runner_id", ContainerConfig { runner_id: "node-9".into(), ..Default::default() }),
        ] {
            assert_ne!(base, PoolKey::for_job(&config, &spec(t.path())), "{why}");
        }

        // …and two jobs that differ only in the things a member cannot carry — the job's identity,
        // its environment, its workspace path — share one key, which is the entire point.
        let mut sibling = spec(t.path());
        sibling.job_id = "job-2".into();
        sibling.step_id = "step-9".into();
        sibling.workspace = t.path().join("elsewhere");
        sibling.env.push(("EXTRA".into(), "1".into()));
        assert_eq!(base, PoolKey::for_job(&base_config, &sibling));
    }

    #[test]
    fn a_cpu_limit_the_daemon_reads_identically_is_one_key() {
        // `--cpus` is passed as `{:.2}`, so these are the same container to the daemon. Keying on the
        // `f32` would split the pool on a difference that does not exist — and `f32` is not `Eq`.
        let t = tempfile::tempdir().unwrap();
        let config = ContainerConfig::default();
        let mut a = spec(t.path());
        a.limits = ResourceLimits { cpus: 2.0, ..Default::default() };
        let mut b = spec(t.path());
        b.limits = ResourceLimits { cpus: 2.001, ..Default::default() };
        assert_eq!(PoolKey::for_job(&config, &a), PoolKey::for_job(&config, &b));
    }

    /// The elements of a create argv that legitimately differ between a member and the job that
    /// claims it. Everything else must match, which is what the next test asserts.
    fn strip_job_varying(argv: &[String]) -> Vec<String> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                // The image and the command come after the flag terminator, and both are the job's.
                "--" => break,
                // The container's own name, the workspace path, the job environment, the job
                // labels and the job's own argv[0] are the things a member cannot know in advance.
                "--name" | "--env" | "--mount" | "--entrypoint" => i += 2,
                "--label" if argv[i + 1].starts_with("hull-ci.job=") => i += 2,
                "--label" if argv[i + 1].starts_with("hull-ci.step=") => i += 2,
                other => {
                    out.push(other.to_string());
                    i += 1;
                }
            }
        }
        out
    }

    #[test]
    fn the_pool_key_covers_every_property_a_create_derives_from_the_job() {
        // The guard against this module falling behind `create_argv`. A new security flag driven by
        // something the key does not carry — a `--device`, a `--storage-opt`, a second
        // `--security-opt` — would let a member be handed to a job it was not built for, and the
        // mismatch would be invisible because both containers would still *run*.
        //
        // So the two argvs are diffed. If they stop agreeing, either the key gained the property or
        // this test fails; there is no third outcome in which the pool silently starts lying.
        let t = tempfile::tempdir().unwrap();
        let config = proxy_config(Some(proven_posture()));
        let job = spec(t.path());
        let key = PoolKey::for_job(&config, &job);

        let job_argv = create_argv(&config, &job, "hull-ci-job", &["cargo".into(), "test".into()]);
        let member_dir = t.path().join("warm-1");
        let member_argv = create_argv(
            &key.container_config(config.control_timeout),
            &key.shape_spec(&member_dir),
            "hull-ci-warm",
            &["/bin/sleep".into(), "1".into()],
        );

        assert_eq!(
            strip_job_varying(&member_argv),
            strip_job_varying(&job_argv),
            "a member is not created with the same rules as the job that will claim it"
        );
        // And the parts that *do* differ differ the way they are supposed to.
        assert!(member_argv.windows(2).any(|w| w[0] == "--mount"
            && w[1].contains(&member_dir.display().to_string())
            && w[1].contains("target=/workspace")));
        assert!(
            !member_argv.iter().any(|a| a.contains("CI=true")),
            "a member carries no job environment: {member_argv:?}"
        );
        assert!(member_argv
            .windows(2)
            .any(|w| w[0] == "--label" && w[1] == "hull-ci.job=warm-pool"));
    }

    #[test]
    fn a_member_carries_the_label_the_reaper_matches_and_the_daemons_auto_remove() {
        // Requirement, not decoration: an idle member is a container with a host directory mounted
        // into it, and a node that is `SIGKILL`ed leaves it running forever. `reap_orphans` at the
        // next node start is what collects it, and it matches on an exact key/value.
        let t = tempfile::tempdir().unwrap();
        let config = ContainerConfig { runner_id: "node-7".into(), ..Default::default() };
        let key = PoolKey::for_job(&config, &spec(t.path()));
        let argv = create_argv(
            &key.container_config(config.control_timeout),
            &key.shape_spec(&t.path().join("warm-1")),
            "hull-ci-warm-1",
            &["/bin/sleep".into(), "1".into()],
        );
        assert!(
            argv.windows(2).any(|w| w[0] == "--label" && w[1] == config.runner_label()),
            "a member without the runner label is an orphan nothing collects: {argv:?}"
        );
        assert_eq!(config.runner_label(), format!("{RUNNER_LABEL}=node-7"));
        assert!(argv.iter().any(|a| a == "--rm"));
    }

    #[test]
    fn a_pool_nobody_switched_on_holds_nothing_and_claims_nothing() {
        let t = tempfile::tempdir().unwrap();
        let pool = SandboxPool::new(
            PoolConfig { root: t.path().to_path_buf(), ..PoolConfig::off() },
            Duration::from_secs(1),
        );
        let key = PoolKey::for_job(&ContainerConfig::default(), &spec(t.path()));
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            assert!(pool.claim(&key).await.is_none());
            pool.refill(&key).await;
        });
        // Not even a miss: a pool that is off is not a pool that missed, and an operator reading
        // these counters should not see traffic against a feature they did not turn on.
        assert_eq!(pool.stats(), PoolStats::default());
    }

    /// A member that exists only in the pool's bookkeeping, for the branches that must be tested
    /// without a daemon. `runtime` is a binary that does not exist, so any command against it fails —
    /// which is the correct behaviour for these tests: nothing here should reach a daemon.
    fn phantom(key: &PoolKey, name: &str, dir: &Path) -> PoolMember {
        PoolMember {
            name: name.to_string(),
            mount_dir: dir.to_path_buf(),
            key: key.clone(),
            config: key.container_config(Duration::from_millis(200)),
        }
    }

    #[tokio::test]
    async fn a_member_filed_under_the_wrong_key_is_destroyed_rather_than_handed_over() {
        // The guard that cannot happen — and the reason it is a guard rather than a comment. The
        // consequence of a member reaching a job it was not built for is §14.3 silently not holding,
        // so the branch is written, counted, and tested by putting the pool into the state directly.
        let t = tempfile::tempdir().unwrap();
        let unreachable = ContainerConfig { runtime: "not-a-runtime".into(), ..Default::default() };
        let wanted = PoolKey::for_job(&unreachable, &spec(t.path()));
        let other = PoolKey::for_job(&proxy_config(Some(proven_posture())), &spec(t.path()));

        let pool = SandboxPool::new(
            PoolConfig { depth: 1, total: 4, root: t.path().to_path_buf(), ..Default::default() },
            Duration::from_millis(200),
        );
        // Filed under `wanted`, but built for `other`.
        pool.idle.lock().unwrap().push(Idle {
            key: wanted.clone(),
            member: phantom(&other, "hull-ci-warm-liar", &t.path().join("liar")),
            seq: 0,
        });

        assert!(pool.claim(&wanted).await.is_none(), "a mismatched member must never be handed over");
        assert_eq!(pool.stats().key_mismatches, 1);
        assert_eq!(pool.stats().hits, 0);
        assert_eq!(pool.stats().misses, 1, "and the job goes down the cold path");
    }

    #[tokio::test]
    async fn a_claim_against_a_daemon_that_no_longer_has_the_member_falls_back_rather_than_failing() {
        // Exhaustion is not the only way a claim comes up empty: a member the daemon lost is one
        // too, and finding out at `exec` — after the workspace has already been moved into it —
        // would turn it into an `errored` verdict instead of a cold create.
        let t = tempfile::tempdir().unwrap();
        let unreachable = ContainerConfig { runtime: "not-a-runtime".into(), ..Default::default() };
        let key = PoolKey::for_job(&unreachable, &spec(t.path()));
        let pool = SandboxPool::new(
            PoolConfig { depth: 1, total: 4, root: t.path().to_path_buf(), ..Default::default() },
            Duration::from_millis(200),
        );
        pool.idle.lock().unwrap().push(Idle {
            key: key.clone(),
            member: phantom(&key, "hull-ci-warm-gone", &t.path().join("gone")),
            seq: 0,
        });

        assert!(pool.claim(&key).await.is_none());
        assert_eq!(pool.stats().claim_failures, 1);
        assert_eq!(pool.stats().misses, 1);
        assert_eq!(pool.stats().hits, 0);
    }

    #[tokio::test]
    async fn the_total_cap_evicts_another_key_and_never_the_one_being_warmed() {
        // Both halves of "bounded", checked on the bookkeeping alone: the total cap is what stops a
        // node that sees many images from holding `depth × images` containers, and evicting the key
        // we are warming would be a pool that trades with itself forever.
        let t = tempfile::tempdir().unwrap();
        let unreachable = ContainerConfig { runtime: "not-a-runtime".into(), ..Default::default() };
        let mut hot = spec(t.path());
        hot.image = "hot:1".into();
        let hot = PoolKey::for_job(&unreachable, &hot);
        let mut cold = spec(t.path());
        cold.image = "cold:1".into();
        let cold = PoolKey::for_job(&unreachable, &cold);

        let pool = SandboxPool::new(
            PoolConfig { depth: 2, total: 2, root: t.path().to_path_buf(), ..Default::default() },
            Duration::from_millis(200),
        );
        for (n, key) in [(0, &cold), (1, &hot)] {
            pool.idle.lock().unwrap().push(Idle {
                key: key.clone(),
                member: phantom(key, &format!("warm-{n}"), &t.path().join(format!("m{n}"))),
                seq: n,
            });
        }

        // Room for `hot`: the oldest member of the *other* key goes.
        pool.make_room(&hot).await.expect("there was something to evict");
        let left: Vec<PoolKey> =
            pool.idle.lock().unwrap().iter().map(|i| i.key.clone()).collect();
        assert_eq!(left, vec![hot.clone()], "the wrong member was evicted");
        assert_eq!(pool.stats().retired, 1);

        // A pool that is full of the key being warmed has nothing to trade, and says so rather than
        // evicting the member it is about to replace.
        pool.idle.lock().unwrap().push(Idle {
            key: hot.clone(),
            member: phantom(&hot, "warm-2", &t.path().join("m2")),
            seq: 2,
        });
        assert!(pool.make_room(&hot).await.is_err());
        assert_eq!(pool.idle.lock().unwrap().len(), 2, "and nothing was removed");
    }

    #[tokio::test]
    async fn refill_stops_at_the_depth_and_never_fails_a_caller() {
        // A pool at its depth does no work at all — no daemon call, no counter — and a pool that
        // cannot warm reports the failure without propagating it. `refill` is called from teardown,
        // where a `?` would turn housekeeping into a verdict.
        let t = tempfile::tempdir().unwrap();
        let unreachable = ContainerConfig { runtime: "not-a-runtime".into(), ..Default::default() };
        let key = PoolKey::for_job(&unreachable, &spec(t.path()));
        let pool = SandboxPool::new(
            PoolConfig { depth: 1, total: 4, root: t.path().to_path_buf(), ..Default::default() },
            Duration::from_millis(200),
        );
        pool.idle.lock().unwrap().push(Idle {
            key: key.clone(),
            member: phantom(&key, "warm-full", &t.path().join("full")),
            seq: 0,
        });
        pool.refill(&key).await;
        assert_eq!(pool.stats(), PoolStats::default(), "a full key is not touched");

        // Now empty, and the runtime does not exist: a warm failure, counted, not returned.
        pool.idle.lock().unwrap().clear();
        pool.refill(&key).await;
        assert_eq!(pool.stats().warm_failures, 1);
        assert_eq!(pool.stats().warmed, 0);
    }

    #[test]
    fn adopting_a_workspace_moves_it_whole_and_leaves_the_source_empty() {
        let t = tempfile::tempdir().unwrap();
        let from = t.path().join("workspace");
        let into = t.path().join("member");
        std::fs::create_dir_all(from.join("src")).unwrap();
        std::fs::create_dir(&into).unwrap();
        std::fs::write(from.join("Cargo.toml"), b"[package]").unwrap();
        std::fs::write(from.join("src/main.rs"), b"fn main() {}").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("Cargo.toml", from.join("link")).unwrap();

        adopt_workspace(&from, &into).expect("same filesystem");

        assert_eq!(std::fs::read(into.join("Cargo.toml")).unwrap(), b"[package]");
        assert_eq!(std::fs::read(into.join("src/main.rs")).unwrap(), b"fn main() {}");
        #[cfg(unix)]
        assert!(std::fs::symlink_metadata(into.join("link")).unwrap().is_symlink(), "a link stays a link");
        assert_eq!(std::fs::read_dir(&from).unwrap().count(), 0, "the source is left empty");
        assert!(from.is_dir(), "…but still a directory, so the caller's own teardown still works");
        // The probe leaves nothing behind on either side.
        assert!(!std::fs::read_dir(&into)
            .unwrap()
            .any(|e| e.unwrap().file_name().to_string_lossy().starts_with(".hull-ci-pool-probe")));
    }

    #[test]
    fn a_member_whose_mount_directory_is_not_empty_never_receives_a_workspace() {
        // A member has never run a job, so its directory is empty. Anything in there is somebody
        // else's, and §14.1's whole point is that a job does not inherit it.
        let t = tempfile::tempdir().unwrap();
        let from = t.path().join("workspace");
        let into = t.path().join("member");
        std::fs::create_dir(&from).unwrap();
        std::fs::create_dir(&into).unwrap();
        std::fs::write(into.join("planted"), b"from a previous job").unwrap();
        std::fs::write(from.join("Cargo.toml"), b"[package]").unwrap();

        let err = adopt_workspace(&from, &into).expect_err("a dirty member must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(from.join("Cargo.toml").exists(), "and nothing moved");
    }

    #[cfg(unix)]
    #[test]
    fn a_pool_root_on_another_filesystem_is_found_before_anything_moves() {
        // `rename(2)` refuses to cross filesystems, and a pool root outside the work root is an easy
        // misconfiguration. The probe finds it with one throwaway file, so the failure is a clean
        // "take the cold path" rather than a workspace half in each directory.
        //
        // **The assertion is on the probe's own message, not just on "it failed".** A destination
        // that refuses a rename would make the *first entry's* rename fail too, so a test that only
        // checked for an error would pass just as happily with the probe deleted — which is this
        // repo's favourite way for a test to be worthless. Only this path produces "nothing has been
        // moved", so only this path can satisfy the test.
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let from = t.path().join("workspace");
        let into = t.path().join("member");
        std::fs::create_dir(&from).unwrap();
        std::fs::create_dir(&into).unwrap();
        std::fs::write(from.join("Cargo.toml"), b"[package]").unwrap();
        std::fs::write(from.join("README.md"), b"#").unwrap();
        // A real, readable, empty directory that nevertheless refuses a rename. It stands in for the
        // cross-device case, which cannot be produced portably — what matters is that it gets past
        // the empty-directory check so that the *probe* is the thing that answers.
        std::fs::set_permissions(&into, std::fs::Permissions::from_mode(0o555)).unwrap();
        assert!(
            std::fs::write(into.join("precondition"), b"").is_err(),
            "this test needs a destination that refuses writes, and root ignores the mode; run it \
             as an ordinary user"
        );

        let err = adopt_workspace(&from, &into).expect_err("a destination like this must be refused");
        assert!(
            err.to_string().contains("nothing has been moved"),
            "the refusal must come from the probe, before any entry moved: {err}"
        );
        assert!(err.to_string().contains("member"), "and it must name the paths: {err}");
        assert!(from.join("Cargo.toml").exists() && from.join("README.md").exists(), "untouched");
        std::fs::set_permissions(&into, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn the_probe_answers_the_rename_question_by_asking_it_and_cleans_up_after_itself() {
        // `st_dev` would answer a subtly different question — bind mounts and overlayfs can share a
        // device number and still refuse a rename — so the probe does the thing. It must also leave
        // nothing behind on either side, or a member would start its one job with a stray file in
        // its workspace.
        let t = tempfile::tempdir().unwrap();
        let (a, b) = (t.path().join("a"), t.path().join("b"));
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();

        probe_rename(&a, &b).expect("two directories under one tempdir are one filesystem");
        assert_eq!(std::fs::read_dir(&a).unwrap().count(), 0, "nothing left in the source");
        assert_eq!(std::fs::read_dir(&b).unwrap().count(), 0, "nor in the destination");

        // …and the control: a destination it cannot rename into comes out the other way, so the
        // success above is a measurement rather than a function that always returns `Ok`.
        let file = t.path().join("file");
        std::fs::write(&file, b"").unwrap();
        assert!(probe_rename(&a, &file).is_err());
        assert_eq!(std::fs::read_dir(&a).unwrap().count(), 0, "and still nothing left behind");
    }

    #[test]
    fn a_pool_member_is_never_told_to_keep_a_pool_of_its_own() {
        let t = tempfile::tempdir().unwrap();
        let config = ContainerConfig {
            pool: PoolConfig { depth: 4, ..Default::default() },
            ..Default::default()
        };
        let key = PoolKey::for_job(&config, &spec(t.path()));
        assert!(!key.container_config(Duration::from_secs(1)).pool.enabled());
    }

    #[test]
    fn a_backend_with_no_pool_configured_has_no_pool() {
        // The composition-root default, asserted where it is read rather than where it is written.
        assert!(!ContainerConfig::default().pool.enabled());
        assert!(!PoolConfig { depth: 4, total: 0, ..Default::default() }.enabled());
        assert!(PoolConfig { depth: 1, total: 1, ..Default::default() }.enabled());
        // A probe-built backend is unaffected by any of this.
        let _ = DockerProbe::default();
    }
}
