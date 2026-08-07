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
  keyed on keel subtree digests, off by default behind `HULL_CI_MEMO=on`. Still to come: the internal
  content store with within-tenant dedup, affinity scheduling, CoW workspaces, warm pools.
- **M5 — scale-out.** Multi-replica control, autoscaling with cache-aware drain, sharding by history.
  Nothing here yet, and note what that means today: **state is in memory**, so a restart forgets
  in-flight jobs. Survivable because Hull re-dispatches a tree with no verdict, but it is why there
  is no horizontal scaling — the fair-share clocks and the job store are process-local.

The ordering is deliberate: multi-tenancy is the product, so isolation precedes the performance
layer rather than following it.

## Known gaps

Kept here rather than in a tracker, because a runner's honest limits belong next to its claims:

- **Orphaned containers.** Killing a node mid-step can leave a container running, so `single_use` is
  true in the ordinary path and not across a crash.
- **Revocation does not reach a credential the package proxy already holds** — shredding a tenant
  makes the ciphertext unrecoverable and says nothing about a copy already decrypted for a live job.
- **On `HULL_CI_TRUSTED_TENANTS=*`, the dispatch chooses both the tenant and the author class**, and
  dispatching needs one deployment-wide secret rather than a per-tenant credential. The default
  (`empty`) fails closed; the `*` configuration trusts Hull completely.
- **Crypto-shredding via Infisical is unverified** — the delete endpoint exists; whether it destroys
  key material or soft-deletes is not documented, so it ships described as revocation.


## Running it

```bash
HULL_CI_SECRET=…                  # spec §8 — checked on dispatch, echoed on the callback
HULL_CI_TRUSTED_TENANTS=acme      # whose authors count as members; empty means nobody, so nothing runs
HULL_CI_SANDBOX=container         # the default. `local` additionally needs HULL_CI_ALLOW_UNSANDBOXED=1

# Optional, all off by default — each turns on a subsystem, none degrades if misconfigured.
HULL_CI_ADMIN_TOKEN=…             # read-only operator panel on /admin; unset means the route does not exist
HULL_CI_MEMO=on                   # step memo (design §6.1): steps declaring `inputs` may resolve from a previous run
HULL_CI_PROXY=on                  # package proxy — the only egress a sandbox gets (§14.3)
HULL_CI_SECRETS=infisical         # tenant secrets with KEKs in Infisical KMS; needs --features hull-ci-server/infisical
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
