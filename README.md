# hull-ci

A high-performance, multi-tenant CI runner service for [Hull](https://github.com/tankrap/hull).

Hull is a dispatcher, not a scheduler: it POSTs a job and waits for a verdict. Everything behind that
contract — queueing, scheduling, caching, isolation, scale — is this repository's problem. hull-ci
speaks Hull's [CI Integration Standard](https://github.com/tankrap/hull/blob/main/CI-SPEC.md)
(contract v1) and implements a **central orchestrator + fleet of execution nodes** behind it.

**Status: pre-alpha.** M1 and M2 are done, M3 is most of the way there, and M4 has started. It runs
real pipelines end to end and scores 27/27 on the contract's conformance suite against a live
container backend.

It is **not safe for multi-tenant or untrusted input**, and that is enforced rather than asked for:
no sandbox backend here reports `admits_untrusted()`, so the scheduler refuses to place work from an
author it cannot vouch for, and the server names every unenforced §14 clause at startup instead of
burying it in a footnote. Lifting the gate needs the Firecracker tier, which needs a Linux host with
KVM. There is a [Known gaps](#known-gaps) section below, kept deliberately close to the claims.

## The idea

CI latency is dominated by work you already did and by bytes you already have. Hull memoizes whole
trees by content address; hull-ci's job is to memoize *below* that granularity and to schedule so the
bytes are already on the machine that runs the job.

- **Three layers of "don't run it again"** — Hull's tree memo, then a step-level memo keyed on keel
  subtree digests, then a tool-level action cache. A README-only change gets a fresh tree id (so Hull
  must dispatch it) yet resolves without touching a node.
- **Affinity scheduling** — nodes advertise what they hold; placement scores tree and blob overlap
  above load, because cold-versus-warm is the difference between 300 ms and 5 s.
- **Hostile by default** — every job is untrusted relative to the platform *and* to every other
  tenant. Single-use microVMs, no credentials near a job, egress denied.

## Architecture

```
Hull ──dispatch──▶ ingest ─▶ queue ─▶ fetch broker ─▶ planner ─▶ scheduler ══lease══▶ node agent
                                          │                                              │
                                          ▼                                       single-use sandbox
                                   content store ────────────LAN pull─────────────────▶  (job runs here)
                                                                                              │
Hull ◀──verdict─── callback sender ◀─ aggregator ◀────────────────────────────────────────────┘
```

The control plane never executes job code, never clones a repo, and holds every credential the job
must never see. The **fetch broker** is deliberately a third place — neither the sandbox nor the
credential-holding host — so `source_url` can be fetched and verified without either handing auth to
untrusted code or parsing attacker-controlled archives next to the secrets.

## Crates

| Crate | What it is |
|---|---|
| `hull-ci-proto` | The contract v1 types (dispatch, verdict) **and** the internal control↔node protocol, in one crate so no component can drift from another. Also the tenancy axes. |
| `hull-ci-fetch` | The fetch broker: GET `source_url`, verify the archive re-hashes to `tree_id`, extract with a hardened tar reader, store content-addressed. |
| `hull-ci-control` | Ingest, job/step state, scheduling, aggregation, idempotent verdict delivery. |
| `hull-ci-node` | The node agent and its sandbox backends. All job execution happens here. |
| `hull-ci-plan` | `.hull/ci.star` → a validated, acyclic DAG. Hermetic Starlark, with the *parser* bounded before it ever sees the source and evaluation bounded inside a child process. Ships a second binary, **`hull-ci-plan-eval`**, which must be installed next to `hull-ci-server`: it is where the memory ceiling is enforced, and planning fails closed without it. |
| `hull-ci-secrets` | The secret broker: tenant secrets under per-tenant KEKs, delivered just-in-time to one job on one enrolled node, never to an outsider. Infisical KMS behind the `KeyManager` seam. |
| `hull-ci-proxy` | The package proxy — §14.3's one permitted hole in egress-deny. Allowlisted upstreams, per-job grants, upstream credentials that the job never sees. |
| `hull-ci-server` | The binary: the composition root that wires the other crates into one running service, plus the read-only operator panel. |

## Two axes that are not the same axis

A recurring source of confusion, so it is encoded in the type system (`hull-ci-proto`):

- **Isolation tier** (`MicroVm` / `Container`) — *how strong is the box?* A property of the sandbox,
  set by platform policy, never by a pipeline. Always `MicroVm` on a multi-tenant instance.
- **Author class** (`Member` / `Outsider`) — *whose authority does this code carry?* Derived from the
  dispatch's author and repo membership. Gates shared-cache writes and tenant secrets.

They are independent. A member's job on the hosted fleet runs in a microVM **and** may write the
shared cache and receive secrets; a fork PR runs in an identically strong box with neither. Collapsing
them makes both unreachable on the exact configuration the product ships as.

## Tenancy

The tenant is the hard boundary, with no opt-in to cross it: caches, blob dedup, log keys, memo keys,
and fair-share accounting are all tenant-scoped. Cache *sharing* happens **within** a tenant via
opt-in named scopes, so repos under one org can share a warmed dependency cache, with write access an
admin grant rather than a string a pipeline can claim.

## Milestones

- **M1 — conforming skeleton. ✅ Done.** Ingest → fetch broker → one node → single-use sandbox →
  callback. Single-tenant, trusted input only. Passes the spec's §11 checklist — the black-box
  conformance suite scores **27/27** against the running service, including two STRICT cases the
  spec's own reference CI fails.
- **M2 — pipelines. ✅ Done.** `.hull/ci.star` (hermetic Starlark) → DAG, parallel branches,
  cascading skips, fail-fast cancel. A tree without a pipeline still autodetects exactly as M1 did,
  so pointing an existing repo here does not change what its CI does.
- **M3 — the multi-tenant untrusted core. Mostly done; the gate has not lifted.** Built and tested:
  weighted fair queueing with per-tenant admission, the secret broker (per-tenant KEKs, Ed25519 node
  identity, author-class gate), the package proxy, egress-deny verified by live probes, and Infisical
  KMS behind the key seam. **Not done: Firecracker**, which needs a Linux host with KVM — so no
  backend here reports `admits_untrusted()`, and **one instance still must not serve many tenants.**
  That is enforced in code, not remembered: the scheduler refuses to place untrusted work on a
  backend whose capabilities say it cannot contain it.
- **M4 — the performance layer. Started.** The step memo (layer 2 of §6.1) is built and wired,
  keyed on keel subtree digests, off by default behind `HULL_CI_MEMO=on`. **CoW workspaces** are in:
  a step's workspace is a reflink clone of the store's tree (`clonefile` on APFS, `FICLONE` on
  btrfs/XFS), so materializing costs metadata rather than bytes, and a filesystem that cannot clone —
  or a store root and work root on different filesystems — falls back to a byte copy rather than
  failing the job. The clone is emphatically **not** a hard link: a job writes, and a second name for
  a file whose path is a content address would corrupt that tree for every later job.
  **Within-tenant content dedup** is in: each of a tenant's files is stored once, and every tree of
  that tenant that holds it is a hard link to that single copy, so a second commit costs the files it
  actually changed rather than a second whole checkout. Two trees overlapping by 90% measure **1.10x**
  of one tree's bytes, where storing both whole is 2.00x. Here a hard link is right for the same
  reason it is wrong in a workspace: a stored tree's path *is* a content address and nothing ever
  writes to one. A blob is keyed on `(content, mode)` and never on content alone — a hard link shares
  an inode and an inode carries the mode, so a content-only key would flip the executable bit of a
  file whose executable bit keel *addresses*, and that tree would stop hashing to the id it is filed
  under. Cross-tenant sharing stays impossible rather than merely off: the blob store lives inside the
  tenant scope, so identical bytes in two tenants are two inodes. **Reclamation** is built and
  wired: trees go once their last recorded *use* is older than the retention, then any blob with
  `st_nlink == 1` goes too, and a pin carried from the store through the fetch seam to the last read
  means a queued job never loses its tree. It runs where the store grows — a commit that publishes a
  tree sweeps that tenant, at most once per cooldown, on a blocking worker rather than on the fetch
  that triggered it, so no job ever waits on housekeeping and there is no timer or background task to
  own. On by default with a 14-day retention (`HULL_CI_RECLAIM=off`,
  `HULL_CI_RECLAIM_RETENTION_DAYS`).
  **Warm sandbox pools** are in: a node keeps a few containers pre-created and started per hot
  configuration, so starting a job is "move the workspace in and exec" rather than "create a
  container and boot" — design §6.4 puts that at ~40 ms against ~200 ms. **This is not sandbox reuse
  and cannot become it**: a member has never run a job, is handed to exactly one, and is destroyed
  afterwards, so §14.1's prohibition on reuse *across jobs* is untouched — which is what the
  conformance table means by "warm pools are pre-boot, not reuse". Docker fixes a container's mounts
  at create time, so each member is created with its own empty host directory bind-mounted at the
  workdir, and the job's workspace is *moved* into it when the member is claimed — O(top-level
  entries) rather than O(tree), because a byte copy would cost more than the boot it saves. A member
  is only ever given to a job whose image, network posture, resource ceilings, user, seccomp profile
  and workdir are identical to the ones it was created with, and that is structural rather than
  checked: the pool key **is** the recipe a member is built from, so "created on this network" and
  "claimed for this network" are one value read twice, and both directions of the network
  translation are exhaustive matches that a new mode breaks at compile time. Handing a no-egress job
  a member sitting on the package-proxy network would be a silent §14.3 escape, and it is the
  mismatch the whole design is shaped around. Live tests assert that a pooled sandbox is
  control-for-control identical to a cold one from the inside — uid, read-only rootfs, dropped
  capabilities, `NoNewPrivs`, cgroup ceilings, no egress, no metadata endpoint, nothing surviving
  into the next job — and that the hit was real, from a counter and from the daemon's own container
  listing taken before the job existed, never from a stopwatch. Exhaustion is a cold create and
  never a queue; the pool is bounded per key and in total; refill is amortized onto teardown, the
  way reclamation is amortized onto commit, so there is no timer to own; and every member carries
  the runner label, so the reaper that collects a crashed node's job containers collects its idle
  members too. Off by default (`HULL_CI_POOL_DEPTH`, `HULL_CI_POOL_TOTAL`) — an idle member holds
  its configured memory whether or not a job ever arrives.
  Still to come: affinity scheduling.
- **M5 — scale-out.** Multi-replica control, autoscaling with cache-aware drain, sharding by history.
  Two pieces are here. The first is the part a restart made unsafe rather than merely slow: every
  accepted dispatch is written to a durable outbox before it is acked, because the thing that has to
  survive is the **obligation to answer**, not the work. A forgotten job is not a lost job; it is a
  tree Hull holds in-flight forever, since spec §10 has Hull neither polling nor timing out, and
  clearing that mark only on a callback. Reporting *something* unwedges it, so the outbox drains from
  both ends — at startup, and again whenever a later dispatch arrives — re-sending a recorded verdict
  when there is one and `errored` when there is not. On by default; `HULL_CI_JOURNAL=off` turns it off.

  The second is the **shared claim**, and it is deliberately narrower than "the job store on
  Postgres". Only two decisions genuinely cannot be made in one process's memory: *one tree, one job*
  (spec §9's `(repo, tree_id)` idempotency) and *one replica, one step* (nothing may run twice). Both
  are now single `INSERT … ON CONFLICT` statements against a shared table, with a fence that stops a
  superseded replica dispatching anything, and every dispatcher's `callback_url` recorded on the claim
  itself — so two replicas produce one job and *both* callers still get the verdict, from whichever
  replica computed it. The job **record** stays process-local on purpose: `Control` mutates it through
  ~39 read-modify-write call sites, and a trait handing out `&mut Job` over a network is a lost update
  wearing a seam's clothes. Off by default and the default build needs no database
  (`HULL_CI_POSTGRES_URL` + `HULL_CI_REPLICA_ID`, `--features postgres`); setting the URL without
  either prerequisite refuses to start rather than quietly running as a replica that thinks it is
  alone. **What still prevents a second replica:** the fair-share clocks are per replica, so two are
  fair each but not fair together; a dead replica's tree is released after one lease TTL but only when
  the next dispatch arrives, and nothing re-runs its work; and the outbox is still per-replica disk.

The ordering is deliberate: multi-tenancy is the product, so isolation precedes the performance
layer rather than following it.

## Known gaps

Kept here rather than in a tracker, because a runner's honest limits belong next to its claims:

- **Orphaned containers outlive a crash until the next start.** Killing a node mid-step leaves a
  live container, because §14.1's teardown is async code that a `SIGKILL` skips. Three things hold
  the clause and none of them closes the window: the reaper removes every container carrying this
  runner's label at node start, `--rm` collects any that exit on their own, and `Drop` covers the
  cases where the node survives. So `single_use` is never violated — nothing is ever *reused* — but
  a node that crashes and does not come back leaves a job's process running with its workspace still
  mounted, and no other node will clean it up, because the label is deliberately scoped so one
  runner cannot reap another's.

  **Warm pool members widen that window rather than opening a new one.** An idle member is the one
  container `--rm` can never help with, because AutoRemove fires when a container *exits* and a
  member is deliberately one that does not — so a crash with the pool on leaves up to
  `HULL_CI_POOL_TOTAL` idle containers, plus their (empty) mount directories, until this runner
  starts again. They hold no job's work and are on the same network every job of their shape would
  have been on, so what is leaked is memory and disk rather than isolation; the reaper removes them
  all at the next start, and a live test asserts exactly that.

- **A warm pool learns its hot configurations from what just ran, and never forgets on its own.**
  Design §6.4 sizes a pool by predicting demand from the last hour's image mix with a floor of 1 for
  anything seen in 24 h. What is here instead is "warm what just finished": the first job of a shape
  misses and takes the cold path, and its teardown warms one member for the next. That needs no
  history, no persistence and no clock, and it reaches the configured depth after that many jobs —
  but it means a node coming back from a restart is cold for one job per shape, and a *fleet* that
  scales out is cold on every new node's first job. The other half of the same simplification: a
  configuration that stops being used keeps its idle members until the total cap needs the room for
  a different one. That eviction is what bounds it — the oldest member of some other key goes, so a
  node whose workload shifts converges — but nothing reclaims idle members on a node that has simply
  gone quiet, exactly as nothing sweeps the content store on a node that has stopped fetching.

- **Pooling is a latency trade that depends on one path being configured correctly, and it fails
  quietly in the direction of "no pool".** Claiming a member moves the job's workspace into the
  member's mount directory, and `rename(2)` refuses to cross filesystems — so a pool root on a
  different filesystem from the work root warms members perfectly and never hits a single one. The
  composition root derives the pool root from `HULL_CI_WORK_ROOT` so the two share a filesystem by
  construction, and a failed move is reported at `error` with both paths, but an operator who sets
  the paths some other way gets a runner that is slightly *slower* than one with no pool at all.
  That is why `hull_ci_node::PoolStats` counts hits, misses, warms and every kind of failure
  separately: a pool that silently never warms is otherwise indistinguishable, from the outside,
  from one that is working.
- **The content store reclaims disk, but only while trees are being committed to it.**
  `ContentStore::reclaim` removes trees whose last recorded *use* is older than the retention, and
  then any blob with `st_nlink == 1`, because one name means no tree references it — a property of
  the layout, so there is no index to build or to get wrong. "Last used" is a stamp the store writes
  at every cache hit, not the filesystem's `atime`, which `relatime`/`noatime` make either a no-op
  or a reaper that deletes the hottest trees. What it did is reported (trees and blobs removed,
  bytes actually returned, and what was skipped and why) because a reclaimer that silently reclaims
  nothing leaves a store that is perfectly correct and still full.

  **It is called from the one place the store grows** — a commit that publishes a tree — rather than
  from a timer, so there is no background task to own, supervise or shut down. That is the residual:
  the sweep is amortized onto growth, so **a runner that goes idle keeps whatever it was holding**
  until the next tree is published. An idle store is bounded by exactly what it already holds, which
  is why this is the shape of the control rather than a hole in it, but a runner parked at 90% full
  will stay there. The rate limit is the other half: at most one sweep per tenant per cooldown, so a
  12-way sharded fan-out costs one walk and not twelve, and a burst therefore *delays* collection
  rather than multiplying it. Reclaiming is not deleting data — a reclaimed tree is re-fetched from
  `source_url` on the next dispatch that wants it — so being wrong here costs a cache miss, where
  being wrong the other way costs a full disk on which every job fails.

  A tree that is *in use* is safe, which is what makes the sweep safe to run at all. A job can sit
  queued between its fetch and its first step, and "retention > queue wait" is a comparison nothing
  enforces, so a tree in use is protected by an explicit RAII pin rather than by a generous
  retention. The pin travels into the control plane's `VerifiedTree` as an **opaque** keep-alive — no
  `hull-ci-fetch` type crosses the seam; the control plane holds an `Arc<dyn Any + Send + Sync>` it
  never inspects and whose only contract is not to drop it — is held for the whole life of the job,
  and is owned by each placement's run down to the blocking materialize that actually reads the tree
  (an abort cannot stop blocking work, so that read can outlive its job). The pin is in-memory and
  per-process: a statement about this runner, not about a second process sweeping the same root.
  Smaller and separately: a `staging/` or `reclaiming/` directory orphaned by a `SIGKILL`
  mid-operation is still reclaimed by nothing.

  One residual is not closable and is stated rather than argued away: a blob can gain a link between
  the sweep's `stat` and its unlink. The sweep narrows the window — it renames a candidate out of
  circulation, re-checks it, and links it back if a commit won — and a commit whose blob vanishes
  retries as the creator, so what is left costs *dedup* on one file, never data: the commit's tree
  entry is a second name for the same inode, so the bytes and the tree survive intact.
- **Revocation reaches a credential the package proxy already holds, but not one already on the
  wire.** The proxy re-asserts the job's capability with the broker before every use, so a revoke or
  a crypto-shred stops the *next* package request and destroys the decrypted copy; an upstream
  request whose `Authorization` header is already built runs to completion, bounded by that request's
  own timeout rather than by anything Hull controls. A missing answer counts as a refusal, so an
  unreachable broker stops the proxy instead of being taken for consent.
- **On `HULL_CI_TRUSTED_TENANTS=*`, the dispatch chooses both the tenant and the author class**, and
  dispatching needs one deployment-wide secret rather than a per-tenant credential. The default
  (`empty`) fails closed; the `*` configuration trusts Hull completely.
- **Crypto-shredding via Infisical is unverified** — the delete endpoint exists; whether it destroys
  key material or soft-deletes is not documented, so it ships described as revocation.
- **An undelivered verdict can still be dropped under memory pressure.** The outbox never lets the
  retention clock forget a job Hull has not acknowledged, but the hard `max_jobs` ceiling can, once
  every delivered job has already been evicted — loudly, naming the job. Its journal entry survives
  on disk, so a restart answers it; nothing else in the running process will. The alternative, an
  absolute exemption, turns a Hull that refuses every callback while still dispatching into an
  unbounded store.
- **Tenant names are case-sensitive**, so `HULL_CI_TRUSTED_TENANTS` must spell a tenant the way Hull
  spells it. Getting it wrong is quiet in the right direction — every job runs as an outsider and
  comes back `errored` — but the reason is in the verdict, not in the startup banner. This is
  deliberate: folding case would decide that two accounts Hull holds as distinct are one principal,
  which fails open and no config repairs.


## Running it

Build the sandbox image first — it is built locally by design and published to no registry, so
nothing pulls it for you:

```bash
docker build -t hull-ci/m1:latest images/m1
```

```bash
HULL_CI_SECRET=…                  # spec §8 — checked on dispatch, echoed on the callback
HULL_CI_TRUSTED_TENANTS=acme      # whose authors count as members; empty means nobody, so nothing runs
HULL_CI_SANDBOX=container         # the default. `local` additionally needs HULL_CI_ALLOW_UNSANDBOXED=1

# Sized from this host if you say nothing, because "unconfigured" must not mean "no parallelism".
HULL_CI_NODE_SLOTS=4              # steps this node runs at once (design §7.1). Default: one slot per CPU
                                  # group of 2 cores, floored at 1, capped at 8. `0` refuses to start

# Optional, all off by default — each turns on a subsystem, none degrades if misconfigured.
HULL_CI_ADMIN_TOKEN=…             # read-only operator panel on /admin; unset means the route does not exist
HULL_CI_MEMO=on                   # step memo (design §6.1): steps declaring `inputs` may resolve from a previous run
HULL_CI_PROXY=on                  # package proxy — the only egress a sandbox gets (§14.3)
HULL_CI_SECRETS=infisical         # tenant secrets with KEKs in Infisical KMS; needs --features hull-ci-server/infisical
HULL_CI_POOL_DEPTH=1              # warm sandbox pool (design §6.4): containers kept pre-created per hot configuration
HULL_CI_POOL_TOTAL=8              # …and across all of them. Each idle member holds its configured memory resident.

# On unless you turn them off — each one is a thing the runner needs to keep working, not a feature.
HULL_CI_JOURNAL=off               # stop recording dispatches durably; a restart then strands in-flight jobs
HULL_CI_RECLAIM=off               # stop reclaiming the content store; it then grows until the disk does not
HULL_CI_RECLAIM_RETENTION_DAYS=14 # how long an unused tree is kept. Shorter frees disk and costs cache hits
cargo run -p hull-ci-server
```

Point Hull's `ci-config` at `POST http://<host>/hull` — the path is `/hull`, and the server logs the
route it bound at startup. Full variable reference in the crate's docs
(`cargo doc -p hull-ci-server --open`).

**`HULL_CI_NODE_SLOTS` and `HULL_CI_POOL_TOTAL` bound different containers and add up on the same
host.** A slot is a sandbox *running a step*; a pool member is one sitting *idle*, pre-created. A
claim moves a member out of the pool and into a slot, so the worst case a host has to hold is
`node_slots + pool_total` containers, each with its configured memory (4 GB by default) — not the
larger of the two. Nothing refuses a combination that does not fit, because only you can see the RAM
budget it has to fit into; both numbers are printed at startup so the arithmetic is in front of you.
Setting the pool smaller than the slot count is a supported trade and not a mistake: at full
occupancy the extra concurrent starts are cold, never queued.

**Hull and hull-ci share the `HULL_CI_*` prefix, and two of those names mean different things on
each side.** Hull reads `HULL_CI_MEMO` as the *path* to its tree-memo JSON (default
`~/.hull/ci-memo.json`) while this runner reads it as `on`/`off`; Hull reads `HULL_CI_SANDBOX` as
`on`/`off`/`enforce` while this runner reads it as `container`/`local`. Only `HULL_CI_SECRET` means
the same thing to both, and is meant to match. So exporting this runner's settings into a shell that
later starts `hull-server` misconfigures Hull — `HULL_CI_MEMO=on` makes it load its memo from a file
literally named `on`, which loses memoization without erroring. Keep the runner's environment in its
own process (a systemd unit, a `docker run --env-file`, or a start script that sources its own file)
rather than in a shell profile both share.

**`HULL_CI_WORK_ROOT` must be a directory your container runtime is allowed to bind-mount.** It is
the only host path that ever enters a sandbox: the store is read by the server and never mounted, so
it can live anywhere. On Docker Desktop for Mac that means the work root has to sit under a path in
Settings → Resources → File sharing — which does **not** necessarily include `/Users`, even though it
is the default. Get this wrong and the runtime refuses the mount at *create*, so every job comes back
`errored` with `container create failed` while a plain `docker run` with no volume works fine and the
image, the network and the daemon all look healthy. Two lines that tell you in seconds:

```bash
mkdir -p "$HULL_CI_WORK_ROOT" && docker run --rm -v "$HULL_CI_WORK_ROOT:/w" hull-ci/m1:latest true \
  && echo "work root is mountable"
```

**M1 refuses rather than degrades.** No sandbox backend in this milestone can contain untrusted code
(`BackendCapabilities::admits_untrusted()` is `false` for all of them), so work from an author who is
not a member of a configured tenant comes back `errored` instead of running, and the container
backend fails to start rather than falling back to the host when no runtime answers. Both are
deliberate: see §14.1 of the spec.

## Development

```bash
cargo test --workspace
```

The **27/27 conformance score is a black-box run against a live service**, not part of `cargo test`,
and it needs its own setup — the endpoint's full path, keel addressing, the `keel` feature, and a
built sandbox image. [`tests/README.md`](./tests/README.md) has the exact invocation. Getting any of
it wrong does not fail loudly: point the suite at a bare host with no path and every case answers
404, at which point the refusal-shaped tests *pass* — a non-2xx is what they assert — and the score
looks like a partial rather than a miss.

## License

Apache-2.0. See [LICENSE](./LICENSE).
