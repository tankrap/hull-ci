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
  `HULL_CI_RECLAIM_RETENTION_DAYS`). Still to come: affinity scheduling, warm pools.
- **M5 — scale-out.** Multi-replica control, autoscaling with cache-aware drain, sharding by history.
  Mostly not here, and **state is still in memory**, which is why there is no horizontal scaling: the
  fair-share clocks and the job store are process-local. What *is* here is the part a restart made
  unsafe rather than merely slow. Every accepted dispatch is written to a durable outbox before it is
  acked, because the thing that has to survive is the **obligation to answer**, not the work. A
  forgotten job is not a lost job; it is a tree Hull holds in-flight forever, since spec §10 has Hull
  neither polling nor timing out, and clearing that mark only on a callback. Reporting *something*
  unwedges it, so the outbox drains from both ends — at startup, and again whenever a later dispatch
  arrives — re-sending a recorded verdict when there is one and `errored` when there is not. On by
  default; `HULL_CI_JOURNAL=off` turns it off.

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

# Optional, all off by default — each turns on a subsystem, none degrades if misconfigured.
HULL_CI_ADMIN_TOKEN=…             # read-only operator panel on /admin; unset means the route does not exist
HULL_CI_MEMO=on                   # step memo (design §6.1): steps declaring `inputs` may resolve from a previous run
HULL_CI_PROXY=on                  # package proxy — the only egress a sandbox gets (§14.3)
HULL_CI_SECRETS=infisical         # tenant secrets with KEKs in Infisical KMS; needs --features hull-ci-server/infisical

# On unless you turn them off — each one is a thing the runner needs to keep working, not a feature.
HULL_CI_JOURNAL=off               # stop recording dispatches durably; a restart then strands in-flight jobs
HULL_CI_RECLAIM=off               # stop reclaiming the content store; it then grows until the disk does not
HULL_CI_RECLAIM_RETENTION_DAYS=14 # how long an unused tree is kept. Shorter frees disk and costs cache hits
cargo run -p hull-ci-server
```

Point Hull's `ci-config` at `POST http://<host>/hull`. Full variable reference in the crate's docs
(`cargo doc -p hull-ci-server --open`).

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
