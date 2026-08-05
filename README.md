# hull-ci

A high-performance, multi-tenant CI runner service for [Hull](https://github.com/tankrap/hull).

Hull is a dispatcher, not a scheduler: it POSTs a job and waits for a verdict. Everything behind that
contract — queueing, scheduling, caching, isolation, scale — is this repository's problem. hull-ci
speaks Hull's [CI Integration Standard](https://github.com/tankrap/hull/blob/main/CI-SPEC.md)
(contract v1) and implements a **central orchestrator + fleet of execution nodes** behind it.

**Status: pre-alpha.** The contract crate is real; the rest is being built out. Not usable yet, and
**not safe for multi-tenant or untrusted input** until the isolation milestone lands (see below).

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
| `hull-ci-server` | The M1 binary: the composition root that wires the four crates into one running service. |

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

- **M1 — conforming skeleton.** Ingest → fetch broker → one node → single-use container → callback.
  Single-tenant, trusted input only. Passes the spec's §11 checklist.
- **M2 — pipelines.** `.hull/ci.star` (hermetic Starlark) → DAG, parallel steps, fail-fast.
- **M3 — the multi-tenant untrusted core.** Firecracker default tier, node partitioning, fair-share +
  admission control, egress-deny, package proxy, secret broker. **One instance safely serves many
  tenants only after M3.**
- **M4 — the performance layer.** Step cache keys, content store with within-tenant dedup, affinity
  scheduling, CoW workspaces, warm pools.
- **M5 — scale-out.** Multi-replica control, autoscaling with cache-aware drain, sharding by history.

The ordering is deliberate: multi-tenancy is the product, so isolation precedes the performance layer
rather than following it.

## Running it (M1)

```bash
HULL_CI_SECRET=…                  # spec §8 — checked on dispatch, echoed on the callback
HULL_CI_TRUSTED_TENANTS=acme      # whose authors count as members; empty means nobody, so nothing runs
HULL_CI_SANDBOX=container         # the default. `local` additionally needs HULL_CI_ALLOW_UNSANDBOXED=1
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
cargo test
```

## License

Apache-2.0. See [LICENSE](./LICENSE).
