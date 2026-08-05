# Contract conformance suite

A **black-box HTTP suite** that judges any CI endpoint against the [Hull CI Integration
Standard](../../hull/CI-SPEC.md) — §11's checklist line by line, plus the adversarial cases from the
runner design's §14 ("How we prove it").

It talks to the endpoint over HTTP and nothing else: it knows a URL and a shared secret, and it
imports nothing from `hull-ci`. That is what lets it exist *before* the service does — the crates
under `../crates` are still scaffolding, and this suite is the fixed point they get built towards.
It also means the suite cannot be satisfied by our code agreeing with our own test: the header names
and JSON shapes here are transcribed from the spec, so if `hull-ci-proto` ever drifts from the
document, this is what notices.

The suite is a **standalone crate, deliberately not a workspace member** (the empty `[workspace]`
table in `Cargo.toml` detaches it). Nothing here touches `../Cargo.toml` or `../crates`.

```
tests/
  src/hull.rs         the stub Hull — sends dispatches (§5), serves source_url (§6),
                      receives and records callbacks (§7/§8)
  src/tree.rs         synthetic keel trees, their tar serialisation, their content address
  src/http.rs         a small HTTP/1.1 client + server over std::net (no async, no shared stack
                      with the subject)
  src/config.rs       the environment knobs
  tests/conformance.rs   CI-SPEC §11, one test per checklist line
  tests/adversarial.rs   design D§14: wrong secrets both ways, unknown contract major,
                         corrupted archive, hostile job output
  reference/strict-ci.py a strictly conforming reference CI (see "Is the suite satisfiable?")
```

There is **no real Hull anywhere in the loop, and no network access**. Each test starts its own stub
Hull on an ephemeral loopback port; it serves the `source_url` tar itself, so the fixture trees are
generated in-process and are byte-identical run to run.

---

## Running it

### (a) Against `fake-ci.py` — the reference stand-in

```sh
# terminal 1 — the CI under test
python3 ../../hull/scripts/fake-ci.py 9099 green conformance-secret

# terminal 2 — the suite
cd hull-ci/tests
cargo test --no-fail-fast
```

`9099` and `conformance-secret` are the suite's defaults, so no environment is needed. Use
`--no-fail-fast`: without it cargo stops after the first failing *binary* and you never see the other
half of the results.

**`fake-ci.py` does not pass.** That is a finding about the reference, not a broken harness — see
[Baseline](#baseline-what-fake-cipy-actually-does) below.

### (b) Against our service, later

```sh
cd hull-ci/tests
HULL_CI_ENDPOINT=http://127.0.0.1:8080/dispatch \
HULL_CI_SECRET=$(pass hull/ci-secret) \
cargo test --no-fail-fast
```

The only requirements on the service are that it listens on plain HTTP at that URL (the harness is
loopback-only, by design — put a TLS terminator in front if you must) and that it is configured with
the same shared secret. Everything else the suite provides for itself.

### Knobs

| Variable | Default | Meaning |
|---|---|---|
| `HULL_CI_ENDPOINT` | `http://127.0.0.1:9099` | the CI endpoint under test (spec §4) |
| `HULL_CI_SECRET` | `conformance-secret` | the shared secret the endpoint is configured with (§8) |
| `HULL_CI_CALLBACK_TIMEOUT_MS` | `20000` | how long a job may take from dispatch to callback |
| `HULL_CI_SETTLE_MS` | `1500` | how long to wait before concluding something that must *not* happen has not happened |
| `HULL_CI_SUMMARY_MAX_CHARS` | `200` | the cap a `summary` must respect (`hull_ci_proto::SUMMARY_MAX_CHARS`) |
| `HULL_CI_SKIP_STRICT` | unset | turn off the three checks that are stricter than the letter of the spec |

The secret is not optional. §11.2 ("verifies `X-Hull-CI-Secret` on dispatch") cannot be asserted
against an endpoint that has no secret, and a suite that silently skipped that line would be
reporting a green baseline it had not earned — so an endpoint without one fails
`spec_11_2_rejects_dispatch_carrying_a_wrong_secret` rather than quietly passing.

### Strict checks

Three tests enforce a spec **MAY**/**SHOULD** that our own design (D§4.2, D§14) promotes to a MUST
for `hull-ci`:

* `adversarial_corrupt_archive_must_fail_the_tree_id_rehash_rather_than_run` — §6 says a runner
  **MAY** re-hash; D§4.2 says "we make it mandatory".
* `adversarial_dispatch_with_an_unknown_major_version_is_refused` — §13 puts version negotiation on
  Hull's side, so tolerating an unknown major is not itself a violation.
* `adversarial_hostile_job_output_never_reaches_hull_as_control_characters` — §14.5 is normative for
  runners accepting untrusted authors, which a single-tenant CI may not be.

`HULL_CI_SKIP_STRICT=1` turns them off when judging a conforming third party. They are on by default
because the primary subject of this suite is `hull-ci`, which is held to the stricter bar. A skipped
strict check prints a `SKIPPED (…)` line; cargo hides test output unless you add `-- --nocapture`, so
pass that when you want the skips visible.

### Is the suite satisfiable?

A conformance suite that only ever goes red is indistinguishable from a broken one, so
`reference/strict-ci.py` is kept alongside it: the same contract as `fake-ci.py` plus exactly the
clauses `fake-ci.py` omits. The suite is **22/22 green** against it in about three seconds.

```sh
python3 reference/strict-ci.py 9098 conformance-secret
HULL_CI_ENDPOINT=http://127.0.0.1:9098 cargo test --no-fail-fast
```

It is a fixture, not a runner: it executes the fetched tree's test script as a plain host
subprocess, which spec §14.1 explicitly rules out. Never point it at a real Hull.

---

## Baseline: what `fake-ci.py` actually does

Measured, not assumed (macOS, Python 3.14, `fake-ci.py 9099 green conformance-secret`):

| | result |
|---|---|
| `conformance.rs` (§11 checklist) | **12 passed, 1 failed** |
| `adversarial.rs` (D§14) | **4 passed, 3 failed** |

It handles the happy path correctly: 2xx ack, secret verified on dispatch, `source_url` fetched
verbatim with no git, verdict POSTed to the exact `callback_url` with the secret echoed, unknown
fields ignored, duplicate dispatch safe and self-consistent. The four failures:

1. **`spec_11_5_reports_errored_not_red_when_the_source_cannot_be_fetched`** — when `source_url`
   answers 500, `urlopen` raises inside `do_POST`, the handler thread dies, and **no callback is ever
   sent**. §7 requires `errored`; silence leaves the tree unverified with nothing to explain it, and
   §10 says a human then has to chase it. The reference's own §12 pseudocode has the same shape, so
   this is worth fixing in the illustration: `errored` is exactly the case an example should model.
2. **`adversarial_unextractable_archive_reports_errored_not_a_verdict_about_the_code`** — same
   defect via `tarfile.ReadError`: a non-tar body kills the handler instead of producing `errored`.
3. **`adversarial_corrupt_archive_must_fail_the_tree_id_rehash_rather_than_run`** *(strict)* — served
   the bytes of a different tree under the advertised `tree_id`, `fake-ci.py` runs it and reports
   **`green`**. Hull memoises green by `tree_id`, so that writes a verdict about substituted content
   against the real tree's address. §6 only says a runner **MAY** re-hash, so this is conforming to
   the letter — but it is the failure mode content addressing exists to prevent, and D§4.2 makes the
   re-hash mandatory for us.
4. **`adversarial_dispatch_with_an_unknown_major_version_is_refused`** *(strict)* — `fake-ci.py`
   reads `X-Hull-CI-Version` only to print it, and acks `202` to a `v2` dispatch. Again conforming to
   the letter of §13 (negotiation is Hull's job), and again not what we want our runner doing.

(1) and (2) are the same one-line bug — an unguarded `run_checks` — and are genuine spec violations
of §7/§11.5 rather than strictness disagreements. With `HULL_CI_SKIP_STRICT=1`, `fake-ci.py` scores
**18 passed, 2 failed**, both of them that bug.

---

## What a black-box suite cannot see

Stated here rather than encoded as tests that always pass:

* **Isolation — §14.1–§14.4.** Whether the job ran in a single-use microVM, as a non-root user, with
  egress denied, `169.254.169.254` blackholed and the environment scrubbed, is invisible from the far
  end of an HTTP callback. Those clauses are provable only from *inside* the runner, where the
  sandbox can be inspected and a job can be told to try to escape — they belong in `hull-ci`'s own
  integration tests (design D§14's security and cross-tenant lists), not here.
* **"No git" in general — §11.3.** The suite proves the runner fetched `source_url` verbatim and made
  no git-shaped request to Hull, which is the only host the dispatch names. It cannot prove the
  runner did not clone from somewhere else; no observer at Hull's end can. That needs a watch on the
  runner's own egress.
* **"In isolation" as a phrase in §11.3** — same reason.
* **How many callbacks a duplicate dispatch produces.** One (the runner de-duplicated on `tree_id`)
  and two (it ran both) are equally conforming — §9 puts de-duplication in Hull. The suite asserts
  the invariant that actually matters: they never disagree.
* **Callback retry after a Hull outage — §10.** Inducing it means breaking the very endpoint the
  assertion reads from. `spec_11_7_is_safe_under_duplicate_callback` instead replays the runner's own
  callback byte for byte, which is the message a retrying runner would send.
* **Sanitisation in a runner that runs nothing.** A CI that never executes the tree has no hostile
  output to leak, so it passes the §14.5 test trivially, and the two cases are indistinguishable from
  Hull's end. (The test does bite when a runner *does* execute: it was verified against a
  deliberately unsanitised build of `reference/strict-ci.py`, which it catches.)

## Notes

* `src/tree.rs` computes `tree_id` with a documented SHA-256 canonicalisation of the tree — a
  stand-in, because the contract deliberately never puts keel's hash on the wire (§5 calls `tree_id`
  opaque). It is written out in the doc comment so any language can reproduce it, and it is the
  single place to change when `hull-ci-fetch` lands the real one. The corrupted-archive case does not
  depend on the choice: bytes that are not the bytes that were hashed fail under any canonicalisation.
* Tests are safe to run in parallel — each holds its own stub Hull and correlates traffic by a token
  that appears in both URLs. Against a single-threaded endpoint, `-- --test-threads=1` is gentler.
