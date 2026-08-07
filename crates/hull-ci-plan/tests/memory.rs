//! The memory bound: that it exists, that it fires, and what it costs.
//!
//! **The finding these tests come from.** `Limits::max_heap_bytes` is 64 MiB and its own
//! documentation named the string-doubling trick as the thing it was for. It did not stop it,
//! because starlark-rust checks the heap once every thousand bytecode instructions and thirty-one
//! doublings are about a hundred and fifty. Measured, release build, at the default limits:
//!
//! | `.hull/ci.star` | source | before | peak RSS before |
//! |---|---|---|---|
//! | `s = "A"`; `for i in range(31): s = s + s` | 58 B | **succeeded** | 4 420 MB |
//! | the same at `range(32)` | 58 B | panicked (`len overflow`) | 4 304 MB |
//! | `x = "A" * 500000000` | 41 B | correct error | 1 008 MB |
//! | `x = [0] * 100000000` | 41 B | correct error | 1 608 MB |
//! | `t = s + s + … + s`, 400 terms, one statement | 1.6 KB | correct error, after 16 s | 4 901 MB |
//!
//! Rows three and four are why "it returns the right error" was never the test to write: the error
//! was right and the gigabyte was still spent. Every one of these is a file any tenant can commit,
//! and the planner runs on the control plane for every job (spec §14.1).
//!
//! **What is asserted here.** Not that an error comes back — the old tests did exactly that, and
//! passed, while the process took 4 GB. Every bomb below is asserted against **resident memory**,
//! read from `getrusage`, because that is the quantity a control plane dies of:
//!
//! * `RUSAGE_SELF` — this process must not have spent it. This is the assertion that fails the
//!   moment evaluation moves back into the address space that matters, whatever error it returns.
//! * `RUSAGE_CHILDREN` — nor did the child; it was refused, not merely survived.
//!
//! `the_bound_is_load_bearing_and_not_decoration` closes the loop by running the same source
//! through the unbounded path and showing that it *is* unbounded, so the ceiling is demonstrably
//! the only thing holding these numbers down.

use std::time::{Duration, Instant};

use hull_ci_plan::error::Bound;
use hull_ci_plan::sandbox::{self, WORKER_ENV};
use hull_ci_plan::{BUILTIN_ACTIONS, Limits, PlanErrorKind, evaluate, evaluate_measured};

/// The audit's bomb, verbatim. Fifty-eight bytes.
const DOUBLING_BOMB: &str = r#"s = "A"
for i in range(31):
    s = s + s
step("x", run = s)
"#;

/// One more doubling — the input that reaches starlark-rust's `len overflow` panic.
const DOUBLING_BOMB_PANIC: &str = r#"s = "A"
for i in range(32):
    s = s + s
step("x", run = s)
"#;

/// A ceiling generous enough that a normal pipeline never sees it, and mean enough that a bomb
/// cannot hide 4 GB underneath it. The process ceiling derived from it is this plus 16 MiB.
const TIGHT: usize = 48 * 1024 * 1024;

fn tight() -> Limits {
    Limits { max_heap_bytes: TIGHT, ..Limits::default() }
}

/// The two numbers every bomb here is judged on: what this process spent, and what its children
/// spent. Both are high-water marks, so they can only over-state — the safe direction.
fn peak_mb() -> (f64, f64) {
    (
        sandbox::peak_rss_bytes() as f64 / 1e6,
        sandbox::children_peak_rss_bytes() as f64 / 1e6,
    )
}

/// Headroom over the ceiling: the test binary and its threads, the helper binary and its runtime,
/// and the one allocation that crossed the line and was refused. Generous enough not to flake, and
/// an order of magnitude below every "before" number in the table above — which is the only
/// property that matters, because that is the gap the bound has to cover.
const RSS_ALLOWANCE_MB: f64 = 400.0;

/// Assert the two numbers, and say what they used to be if they are wrong.
fn assert_bounded(what: &str, was: &str) {
    let (mine, childrens) = peak_mb();
    assert!(
        mine < RSS_ALLOWANCE_MB,
        "{what}: this process reached {mine:.0} MB. That is the control plane, and this file used \
         to take it to {was}. A bound enforced after the allocation is not a bound."
    );
    assert!(
        childrens < RSS_ALLOWANCE_MB,
        "{what}: the evaluation child reached {childrens:.0} MB against a ceiling well under that; \
         it was survived, not refused (it used to reach {was})."
    );
}

// ── The bombs ────────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_fifty_eight_byte_bomb_is_refused_and_the_memory_is_not_spent() {
    let (result, cost) = evaluate_measured(DOUBLING_BOMB, &tight(), BUILTIN_ACTIONS);
    let err = result.expect_err("58 bytes that allocate 4 GB must not be a valid pipeline");
    assert!(
        matches!(err.kind, PlanErrorKind::Exhausted(Bound::Memory { .. })),
        "the refusal must name the rule it broke, got {err}"
    );

    assert_bounded("the 58-byte bomb", "4 420 MB");
    assert!(
        cost.peak_bytes >= TIGHT as u64,
        "the reported cost must not under-state what was actually spent"
    );
}

#[test]
fn a_starlark_panic_is_reported_as_a_bound_not_an_abort() {
    // One doubling further is where starlark-rust panics with `len overflow` instead of erroring.
    // With the ceiling in the way the process never gets there, which is the better outcome and is
    // what the first assertion checks. The second is the one that matters for containment: the
    // *process running this test* is still alive and still evaluating, which is not something a
    // caught panic and an abort can both claim.
    let (result, _) = evaluate_measured(DOUBLING_BOMB_PANIC, &tight(), BUILTIN_ACTIONS);
    let err = result.expect_err("a pipeline that panics the evaluator is not a valid pipeline");
    assert!(
        matches!(err.kind, PlanErrorKind::Exhausted(Bound::Memory { .. })),
        "got {err}"
    );

    assert_bounded("the len-overflow bomb", "4 304 MB");

    // Alive, and unbothered.
    assert_eq!(evaluate("step(\"x\", run = \"true\")").unwrap().steps.len(), 1);
}

/// The shapes no cooperative check can see, because each spends its gigabyte inside a single
/// operation or a single statement — between two of starlark's periodic checks, and between two of
/// any finer check we could have written ourselves.
#[test]
fn one_operation_and_one_statement_are_bounded_too() {
    for (name, source, was) in [
        ("a single string repeat", r#"x = "A" * 500000000"#, "1 008 MB"),
        ("a single list repeat", r#"x = [0] * 100000000"#, "1 608 MB"),
        ("a chained repeat", r#"x = "A" * 20000 * 20000"#, "808 MB"),
        (
            "400 concatenations in one statement",
            // Legal, 1.6 KB, and inside `max_statement_weight`. A per-statement memory check —
            // the obvious in-process fix — reads the heap once before this line and once after.
            &format!("s = \"A\" * 1000000\nt = {}\n", vec!["s"; 400].join(" + ")),
            "4 901 MB",
        ),
    ] {
        let (result, _) = evaluate_measured(source, &tight(), BUILTIN_ACTIONS);
        let err = result.err().unwrap_or_else(|| panic!("{name} must be refused"));
        assert!(
            matches!(err.kind, PlanErrorKind::Exhausted(Bound::Memory { .. })),
            "{name}: got {err}"
        );
        assert_bounded(name, was);
    }
}

/// **The test that proves the bound is doing the work.**
///
/// Everything above would also pass if some *other* rule happened to refuse these files. So this
/// one runs the audit's own source through `evaluate_in_process` — the same evaluation the child
/// runs, with no ceiling around it, which is precisely what removing the fix would leave — and
/// shows that it runs to completion.
///
/// The reason it runs to completion is worth stating, because it is not the one the old comments
/// assumed. starlark-rust's periodic heap check *does* eventually notice a doubling loop, but
/// `eval::classify` prefers our own typed failure to starlark's, and in this file our own failure
/// arrives first: `run` is 16 MB, so `StringTooLong` wins and the heap verdict is discarded. The
/// bytes were spent either way. That is the shape of the bug — a bound that reports rather than
/// prevents can be routed around by an error that is merely *more specific*.
///
/// Deliberately a small bomb. At `range(24)` the unbounded path allocates ~74 MB here, which is
/// enough to be unambiguous and cheap enough to run on every commit; the identical file at
/// `range(31)` measured **4 094 MB**, in this process, in a debug build, with a 48 MiB heap limit
/// configured and consulted.
#[test]
fn the_bound_is_load_bearing_and_not_decoration() {
    const SMALL_BOMB: &str = "s = \"A\"\nfor i in range(24):\n    s = s + s\nstep(\"x\", run = s)\n";

    let unbounded = hull_ci_plan::eval::evaluate_in_process(
        SMALL_BOMB,
        &tight().clamped(),
        BUILTIN_ACTIONS.iter().map(|a| a.to_string()).collect(),
    );
    let err = unbounded.expect_err("`run` is 16 MB, so the length rule refuses the step");
    assert!(
        !matches!(err.kind, PlanErrorKind::Exhausted(Bound::Memory { .. })),
        "the unbounded path is supposed to be unbounded — if the configured heap limit stopped \
         this, the premise of this whole module is wrong. Got {err}"
    );

    // The same file, through the front door, is stopped by the ceiling instead — before it can
    // finish, which is the difference between the two paths.
    let (result, _) = evaluate_measured(SMALL_BOMB, &tight(), BUILTIN_ACTIONS);
    let err = result.expect_err("bounded");
    assert!(
        matches!(err.kind, PlanErrorKind::Exhausted(Bound::Memory { .. })),
        "got {err}"
    );
}

// ── Fail closed ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn without_the_helper_evaluation_fails_rather_than_running_here() {
    // The failure mode a bound like this dies of is a fallback: "if the child cannot be spawned,
    // evaluate in-process". That is a memory bound that is not there, on exactly the deployments
    // where nobody noticed the helper was missing. So it is an error, and this pins it.
    //
    // Serialised against the rest of the file by running in its own process (`--test-threads` does
    // not help: the environment is process-wide), which is why this is a spawn of the test binary
    // rather than an ordinary `#[test]` body.
    let exe = std::env::current_exe().expect("test binary");
    let output = std::process::Command::new(exe)
        .args(["--exact", "--nocapture", "helper_missing_child"])
        .env("HULL_CI_PLAN_TEST_CHILD", "1")
        .env(WORKER_ENV, "/nonexistent/hull-ci-plan-eval")
        .output()
        .expect("re-run this test binary");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("fails closed"),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn helper_missing_child() {
    if std::env::var_os("HULL_CI_PLAN_TEST_CHILD").is_none() {
        return; // The parent case above is the real test; this body only runs under it.
    }
    let err = evaluate("step(\"x\", run = \"true\")").expect_err("no helper, no evaluation");
    assert_eq!(err.kind, PlanErrorKind::Internal);
    println!("fails closed: {err}");
}

#[test]
fn a_child_that_does_not_finish_in_time_is_killed_and_reported() {
    // The wall clock, exercised the only way that is deterministic: a budget no spawn can meet.
    // What is under test is the machinery — that the parent stops waiting, kills the child, reaps
    // it, and returns a *named* bound — not that any particular pipeline is slow. `max_ticks`
    // remains the bound that catches a slow pipeline, and it has a far better message; this one is
    // for the cases where the thing being consumed is not work.
    let limits = Limits { eval_timeout_ms: 1, ..Limits::default() };
    let err = hull_ci_plan::evaluate_with("step(\"x\", run = \"true\")", &limits, BUILTIN_ACTIONS)
        .expect_err("a one-millisecond budget cannot cover a process spawn");
    assert!(
        matches!(err.kind, PlanErrorKind::Exhausted(Bound::Time { limit_ms: 1 })),
        "got {err}"
    );

    // The killed child was reaped, not left behind. Planning runs for every job, so a zombie here
    // would be a zombie per job.
    assert_eq!(evaluate("step(\"x\", run = \"true\")").unwrap().steps.len(), 1);
}

// ── What it costs ────────────────────────────────────────────────────────────────────────────────

/// Design D§4.4's own example, plus the `for`-generated fan-out that is the format's headline.
const DESIGN_EXAMPLE: &str = r#"
image("rust:1.83")
trust("trusted")
cache_scope("acme-rust")

rust = ["crates/**", "Cargo.toml", "Cargo.lock"]

step("fmt",   run = "cargo fmt --check", inputs = ["**/*.rs", "rustfmt.toml"])
build = step("build", run = "cargo build --workspace --all-targets",
             inputs = rust, cache = ["target/", "~/.cargo/registry"])
step("test",  run = "cargo test --workspace", needs = [build],
             inputs = rust, shard = "auto", timeout = "20m",
             secrets = ["TEST_DB_URL"])
action("scan", uses = "hull/secret-scan")

for c in ["core", "fetch", "node"]:
    step("clippy-" + c, run = "cargo clippy -p hull-ci-" + c, needs = [build], inputs = rust)
"#;

/// A `for`-generated matrix: 3 × 3 × 4 plus a base step. The ergonomic case the format exists for,
/// and the one that does the most work per byte of source.
const MATRIX: &str = r#"
image("rust:1.83")
rust = ["crates/**", "Cargo.toml", "Cargo.lock"]
base = step("build", run = "cargo build", inputs = rust, cache = ["target/"])
for os in ["linux", "macos", "windows"]:
    for tc in ["stable", "beta", "nightly"]:
        for c in ["core", "fetch", "node", "plan"]:
            step("test-" + os + "-" + tc + "-" + c,
                 run = "cargo test -p hull-ci-" + c + " --target " + os,
                 needs = [base], inputs = rust, timeout = "20m")
"#;

#[test]
fn a_real_pipeline_still_evaluates_and_the_cost_is_a_number_we_state() {
    // Reported, not asserted tightly: a wall-clock threshold in a test is a flake on a loaded CI
    // box. What is asserted is the shape of the claim — that a plan is *milliseconds*, not the tens
    // or hundreds a sandbox spawn would cost, and nowhere near design D§4.4's sub-second budget.
    //
    // Measured, release build, 300 iterations:
    //
    //   design D§4.4's example    in-process 123 µs  ->  bounded child 3.55 ms   (+3.4 ms)
    //   37-step generated matrix  in-process 103 µs  ->  bounded child 3.60 ms   (+3.5 ms)
    //   a one-step pipeline                          ->  bounded child 3.40 ms
    //
    // The third line is the interesting one: the cost is fixed (exec, dynamic linking, and building
    // the Starlark globals once in a cold address space), not proportional to the pipeline. For
    // scale, design D§6.1 measures one `**/*.rs` glob on a 100k-file tree at 23.9 ms on this same
    // plan path — so the bound costs about 15% of one glob.
    for (name, source, steps) in
        [("design D§4.4 example", DESIGN_EXAMPLE, 7), ("generated matrix", MATRIX, 37)]
    {
        let reps = 20;
        let start = Instant::now();
        let mut last = None;
        for _ in 0..reps {
            last = Some(evaluate(source).unwrap_or_else(|e| panic!("{name} must evaluate: {e}")));
        }
        let each = start.elapsed() / reps;
        assert_eq!(last.unwrap().steps.len(), steps);
        println!("{name}: {each:?} per plan");
        assert!(
            each < Duration::from_millis(250),
            "{name} took {each:?} per plan, which is not the trade this design made"
        );
    }
}

#[test]
fn a_real_pipeline_runs_nowhere_near_the_ceiling() {
    // The number starlark-rust's own documentation asks a user of a heap limit to watch, so that
    // the limit is tuned against reality before it starts refusing an honest pipeline. Nothing
    // measured it until there was a process to measure.
    let (pipeline, cost) = evaluate_measured(MATRIX, &Limits::default(), BUILTIN_ACTIONS);
    assert_eq!(pipeline.unwrap().steps.len(), 37);
    println!("a 37-step matrix peaks at {} KB", cost.peak_bytes / 1024);
    assert!(
        cost.peak_bytes * 10 < Limits::default().hard_memory_bytes() as u64,
        "a real pipeline should not be within an order of magnitude of the ceiling, \
         but this one peaked at {} bytes",
        cost.peak_bytes
    );
}
