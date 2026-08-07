//! Adversarial tests for the pipeline dialect.
//!
//! This file exists because the pipeline is the only attacker-controlled input that is *evaluated*
//! outside a sandbox (design D§4.4, spec §14.1). The unit tests next to the code check that the
//! rules do what they say; these check the harder claim — that the dialect cannot be talked into
//! doing something it has no business doing, that a hostile-but-valid module cannot hold the
//! planner, and that what comes back to the author is safe to show them.
//!
//! Two habits run through it:
//!
//! * **Absence, not rejection.** Where design D§4.4 says a capability "does not exist", the test
//!   asserts on the *global environment* — the complete list of names the dialect defines — rather
//!   than on an error message. An error proves something said no; an inventory proves there was
//!   never anything to say no to.
//! * **Termination, not tolerance.** The recursion and budget tests would *hang* rather than fail
//!   if the bounds were missing, which is exactly the failure mode they are protecting against, so
//!   each one is written to complete or blow up quickly.

use std::time::Duration;

use hull_ci_plan::error::Bound;
use hull_ci_plan::{
    BUILTIN_ACTIONS, Invalid, Limits, PlanErrorKind, Shard, StepKind, Trust, evaluate,
    evaluate_with,
};
use hull_ci_proto::IsolationTier;

/// The example from design D§4.4, verbatim, plus the `for`-generated fan-out the prototype proved
/// out. This is the spec's own headline artefact; if it does not evaluate, nothing else matters.
const DESIGN_EXAMPLE: &str = r#"
image("rust:1.83")            # OCI ref, resolved to a digest at plan time
trust("trusted")              # "trusted" | "untrusted" -> isolation tier
cache_scope("acme-rust")      # share this tenant's cache across repos

rust = ["crates/**", "Cargo.toml", "Cargo.lock"]

step("fmt",   run = "cargo fmt --check", inputs = ["**/*.rs", "rustfmt.toml"])
build = step("build", run = "cargo build --workspace --all-targets",
             inputs = rust, cache = ["target/", "~/.cargo/registry"])
step("test",  run = "cargo test --workspace", needs = [build],
             inputs = rust, shard = "auto", timeout = "20m",
             secrets = ["TEST_DB_URL"])
action("scan", uses = "hull/secret-scan")

# The code-as-config win: one matrix, expressed once.
for c in ["core", "fetch", "node"]:
    step("clippy-" + c, run = "cargo clippy -p hull-ci-" + c, needs = [build], inputs = rust)
"#;

// ── The example, and the DAG it must produce ─────────────────────────────────────────────────────

#[test]
fn the_design_example_evaluates_to_the_expected_dag() {
    let p = evaluate(DESIGN_EXAMPLE).expect("design D§4.4's own example must evaluate");

    assert_eq!(p.image.as_deref(), Some("rust:1.83"));
    assert_eq!(p.trust, Some(Trust::Trusted));
    assert_eq!(p.cache_scope.as_deref(), Some("acme-rust"));

    // Seven nodes: fmt, build, test, scan, and three `for`-generated clippy steps.
    let names: Vec<&str> = p.steps.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        ["fmt", "build", "test", "scan", "clippy-core", "clippy-fetch", "clippy-node"]
    );

    let build = p.step("build").unwrap();
    assert_eq!(build.inputs, ["crates/**", "Cargo.toml", "Cargo.lock"]);
    assert_eq!(build.cache, ["target/", "~/.cargo/registry"]);
    assert!(build.needs.is_empty());

    let test = p.step("test").unwrap();
    assert_eq!(test.needs, ["build"], "`needs = [build]` is data flow through the handle");
    assert_eq!(test.shard, Some(Shard::Auto));
    assert_eq!(test.timeout, Some(Duration::from_secs(20 * 60)));
    assert_eq!(test.secrets, ["TEST_DB_URL"]);

    // An action carries no user shell — that is the whole point of the second builtin.
    assert_eq!(p.step("scan").unwrap().kind, StepKind::Action("hull/secret-scan".into()));

    // The generated steps are ordinary steps, each depending on the handle captured outside the loop.
    for c in ["core", "fetch", "node"] {
        let s = p.step(&format!("clippy-{c}")).unwrap();
        assert_eq!(s.needs, ["build"]);
        assert_eq!(s.kind, StepKind::Run(format!("cargo clippy -p hull-ci-{c}")));
    }

    assert_eq!(p.depth(), 2, "fmt/build at depth 1, everything downstream of build at 2");
}

#[test]
fn a_run_string_survives_verbatim_and_is_never_split() {
    // The control plane must not have an opinion about shell syntax (spec §14.1). Quoting,
    // pipelines, `&&`, and `$VAR` all arrive at the sandbox exactly as written.
    let run = r#"sh -c 'echo "a  b" | tee $OUT && exit 0'"#;
    let p = evaluate(&format!("step(\"s\", run = {run:?})")).unwrap();
    assert_eq!(p.steps[0].kind, StepKind::Run(run.to_string()));
}

#[test]
fn top_level_for_is_the_flag_the_headline_ergonomics_need() {
    // The prototype's one finding (design D§4.4): standard Starlark refuses `for` at module scope,
    // so `enable_top_level_stmt` is load-bearing rather than cosmetic. If this regresses, "express
    // a matrix once" silently stops working — hence a test on the feature, not just on the example.
    let p = evaluate(
        r#"
for arch in ["amd64", "arm64"]:
    if arch == "amd64":
        step("build-" + arch, run = "make " + arch)
    else:
        step("build-" + arch, run = "make cross-" + arch)
"#,
    )
    .expect("`for`/`if` at module scope must be accepted");
    assert_eq!(p.steps.len(), 2);
    assert_eq!(p.steps[1].kind, StepKind::Run("make cross-arm64".into()));
}

#[test]
fn helper_functions_and_comprehensions_work_because_this_is_a_language() {
    let p = evaluate(
        r#"
def unit(name, deps = []):
    return step("test-" + name, run = "pytest " + name, needs = deps, inputs = ["**/*.py"])

a = unit("a")
[unit(n, deps = [a]) for n in ["b", "c"]]
"#,
    )
    .unwrap();
    assert_eq!(p.steps.len(), 3);
    assert_eq!(p.steps[2].needs, ["test-a"]);
}

// ── Hermeticity: the capabilities that do not exist ──────────────────────────────────────────────

#[test]
fn the_global_environment_is_exactly_the_standard_library_plus_five_builtins() {
    // The strongest form of the D§4.4 claim "no file/URL fetch and no open/network/clock builtins
    // exist in the dialect": an inventory. This is a golden test on purpose — if a future starlark
    // release adds a global, or someone reaches for `GlobalsBuilder::extended()` to get `print` or
    // `json`, this fails and a human decides, instead of the surface growing quietly.
    let globals = hull_ci_plan::eval::globals();
    let mut names: Vec<String> = globals.names().map(|n| n.as_str().to_string()).collect();
    names.sort();

    let expected = [
        // ours (design D§4.4's five)
        "action",
        "cache_scope",
        "image",
        "step",
        "trust",
        // the Starlark standard environment — values, types, and pure functions only
        "None",
        "True",
        "False",
        "abs",
        "all",
        "any",
        "bool",
        "dict",
        "dir",
        "enumerate",
        "fail",
        "float",
        "getattr",
        "hasattr",
        "hash",
        "bytes",
        "chr",
        "int",
        "len",
        "list",
        "max",
        "min",
        "ord",
        "range",
        "repr",
        "reversed",
        "sorted",
        "str",
        "tuple",
        "type",
        "zip",
    ];
    let mut expected: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
    expected.sort();
    assert_eq!(names, expected, "the dialect's surface changed — is the new global hermetic?");
}

#[test]
fn there_is_no_io_clock_or_network_to_reach_for() {
    // Not "blocked" — absent. Each of these is an *undefined name*, the same error you would get
    // for a typo, because nothing under these names was ever defined.
    for expr in [
        "open(\"/etc/passwd\")",
        "fetch(\"https://example.com\")",
        "time.now()",
        "print(\"x\")",
        "getattr(struct, \"anything\")",
        "json.encode({})",
        "os.environ",
        "exec(\"x\")",
        "eval(\"x\")",
        "__builtins__",
        "breakpoint()",
        "debug(1)",
    ] {
        let err = evaluate(expr).unwrap_err();
        assert!(
            matches!(err.kind, PlanErrorKind::Language(_)),
            "{expr} should be an undefined name, got {err:?}"
        );
    }
}

#[test]
fn load_is_off_at_the_grammar_level() {
    // `load()` is the one Starlark feature that reaches outside the file — the remote-reference
    // class design D§4.4 says must be absent. With `enable_load: false` it is a *parse* error, so
    // there is no resolver to misconfigure and no file path to canonicalise.
    let err = evaluate(r#"load("//other:defs.bzl", "helper")"#).unwrap_err();
    assert!(matches!(err.kind, PlanErrorKind::Language(_)));
    // Even the name is not callable as a function, so no "did you mean" path exists either.
    assert!(evaluate(r#"x = load"#).is_err());
}

#[test]
fn while_is_not_in_the_language() {
    // The guarantee that makes evaluation safe on the control plane is *termination*, and `while`
    // is the only unbounded loop Starlark's syntax could have had. It is a parse error.
    let err = evaluate("while True:\n    step(\"x\", run = \"y\")").unwrap_err();
    assert!(matches!(err.kind, PlanErrorKind::Language(_)));
}

#[test]
fn evaluation_records_a_dag_and_nothing_else() {
    // No side effect a pipeline could observe or cause: the same source evaluated twice gives an
    // identical result, and a failing evaluation leaves nothing behind for the next one.
    let first = evaluate(DESIGN_EXAMPLE).unwrap();
    assert!(evaluate("step(\"bad name\", run = \"x\")").is_err());
    let second = evaluate(DESIGN_EXAMPLE).unwrap();
    assert_eq!(first, second, "evaluation is deterministic and carries no state between runs");
}

// ── Bounds: a pathological module cannot wedge the planner ───────────────────────────────────────

#[test]
fn unbounded_recursion_terminates_via_the_stack_cap() {
    // Would hang or blow the host stack if `set_max_callstack_size` were missing. It returns.
    let err = evaluate(
        r#"
def forever(n):
    return forever(n + 1)
forever(0)
"#,
    )
    .unwrap_err();
    assert!(
        matches!(err.kind, PlanErrorKind::Exhausted(Bound::CallStack { .. })),
        "expected the call-stack cap, got {err}"
    );
}

#[test]
fn mutual_recursion_terminates_too() {
    let err = evaluate(
        r#"
def ping(n):
    return pong(n + 1)
def pong(n):
    return ping(n + 1)
ping(0)
"#,
    )
    .unwrap_err();
    assert!(matches!(err.kind, PlanErrorKind::Exhausted(Bound::CallStack { .. })));
}

#[test]
fn the_step_budget_trips() {
    let limits = Limits { max_steps: 10, ..Limits::default() };
    let err = evaluate_with(
        "for i in range(1000):\n    step(\"s\" + str(i), run = \"x\")",
        &limits,
        BUILTIN_ACTIONS,
    )
    .unwrap_err();
    assert_eq!(err.kind, PlanErrorKind::Exhausted(Bound::Steps { limit: 10 }));
    assert!(err.line.is_some(), "an author needs to know which line stopped emitting");
}

#[test]
fn the_depth_cap_trips_on_a_long_chain() {
    let limits = Limits { max_depth: 8, ..Limits::default() };
    let err = evaluate_with(
        r#"
prev = step("s0", run = "x")
for i in range(100):
    prev = step("s" + str(i + 1), run = "x", needs = [prev])
"#,
        &limits,
        BUILTIN_ACTIONS,
    )
    .unwrap_err();
    assert_eq!(err.kind, PlanErrorKind::Exhausted(Bound::Depth { limit: 8 }));
}

#[test]
fn a_wide_dag_is_not_a_deep_one() {
    // The depth cap must bound chains, not fan-out: 500 steps hanging off one root is depth 2.
    let limits = Limits { max_depth: 4, max_steps: 1000, ..Limits::default() };
    let p = evaluate_with(
        r#"
root = step("root", run = "x")
for i in range(500):
    step("leaf" + str(i), run = "x", needs = [root])
"#,
        &limits,
        BUILTIN_ACTIONS,
    )
    .unwrap();
    assert_eq!(p.steps.len(), 501);
    assert_eq!(p.depth(), 2);
}

#[test]
fn a_legal_but_enormous_computation_is_bounded_by_the_work_budget() {
    // No I/O, no recursion, no `while` — perfectly hermetic, perfectly terminating, and would still
    // hold a planner thread for a very long time. This is exactly the "pathological but valid"
    // module design D§4.4 asks the tick budget to stop.
    let limits = Limits { max_ticks: 200_000, ..Limits::default() };
    let err = evaluate_with(
        r#"
total = 0
for a in range(1000):
    for b in range(1000):
        total = total + b
"#,
        &limits,
        BUILTIN_ACTIONS,
    )
    .unwrap_err();
    assert_eq!(err.kind, PlanErrorKind::Exhausted(Bound::Work { limit: 200_000 }));
}

#[test]
fn huge_literals_are_bounded_by_the_heap_budget() {
    // Six lines that build a hundred megabytes, spread over many loop iterations — which is the one
    // shape starlark-rust's own periodic heap check *does* catch, and it catches it with a line
    // number, which is why the check is still worth having.
    //
    // Every other shape is caught by the child's allocation ceiling instead. `memory.rs` is that
    // story, including the 58-byte file this check used to let through at 4 420 MB.
    let limits = Limits { max_heap_bytes: 8 * 1024 * 1024, ..Limits::default() };
    let err = evaluate_with(
        r#"
s = "x"
for i in range(20000):
    s = s + "y" * 1000
"#,
        &limits,
        BUILTIN_ACTIONS,
    )
    .unwrap_err();
    assert!(
        matches!(
            err.kind,
            PlanErrorKind::Exhausted(Bound::Memory { .. } | Bound::Work { .. })
        ),
        "a memory bomb must trip a bound, got {err}"
    );
}

#[test]
fn a_panic_inside_starlark_is_contained_rather_than_taken_out_on_the_control_plane() {
    // Doubling a string past starlark-rust's internal length limit panics (`len overflow` in
    // `str_type.rs`) rather than returning an error. A panic on the control plane, from an untrusted
    // file, is a denial of service.
    //
    // This test used to assert that the panic came back as `Internal` — contained by the evaluation
    // thread's `join`, but only *after* 4 304 MB had been allocated reaching it. It is now the
    // memory ceiling that answers first, so the assertion is stronger: a **named bound**, not a
    // caught panic. The containment underneath is still real and still tested — see
    // `memory.rs::a_starlark_panic_is_reported_as_a_bound_not_an_abort`, which reaches the panic
    // with the ceiling raised out of the way.
    let err = evaluate(
        r#"
s = "x" * 1024
for i in range(40):
    s = s + s
"#,
    )
    .unwrap_err();
    assert!(
        matches!(err.kind, PlanErrorKind::Exhausted(Bound::Memory { .. })),
        "got {err}"
    );

    // And the process is still healthy afterwards.
    assert_eq!(evaluate(DESIGN_EXAMPLE).unwrap().steps.len(), 7);
}

#[test]
fn an_oversized_file_is_refused_before_the_parser_sees_it() {
    let limits = Limits { max_source_bytes: 1024, ..Limits::default() };
    let source = format!("# {}\n", "a".repeat(4096));
    let err = evaluate_with(&source, &limits, BUILTIN_ACTIONS).unwrap_err();
    assert_eq!(err.kind, PlanErrorKind::Exhausted(Bound::SourceBytes { limit: 1024 }));
    assert!(err.line.is_none(), "there is no line to point at when nothing was parsed");
}

/// **This test is why `hull_ci_plan::shape` exists.** Before that module, every one of these inputs
/// aborted the process — a stack overflow inside `AstModule::parse`, hit before a single one of
/// design D§4.4's evaluation bounds had anything to check. A `SIGABRT` on the control plane, from a
/// file in an untrusted tree, is the worst outcome this crate can have, so the cases are kept
/// together and each one is small enough to be an obvious thing for someone to try.
///
/// If this test ever *crashes the test binary* rather than failing, that is the bug back.
#[test]
fn nesting_that_would_overflow_the_parser_is_refused_before_parsing() {
    let cases = [
        // Brackets, parens, braces, calls — the direct route.
        format!("x = {}{}\n", "[".repeat(10_000), "]".repeat(10_000)),
        format!("x = {}1{}\n", "(".repeat(5_000), ")".repeat(5_000)),
        format!("x = {}{}\n", "{".repeat(5_000), "}".repeat(5_000)),
        format!("x = {}1{}\n", "int(".repeat(4_000), ")".repeat(4_000)),
        // Unbracketed: the same AST depth with no bracket for a nesting cap to count.
        format!("x = {}1\n", "-".repeat(20_000)),
        format!("x = {}True\n", "not ".repeat(5_000)),
        format!("x = 1{}\n", "+1".repeat(10_000)),
        // Multi-line inside one bracket pair: nesting 1, and it defeats any per-line cap.
        format!("x = (1{})\n", "\n+1".repeat(8_000)),
        // Indentation.
        {
            let mut s = String::new();
            for i in 0..400 {
                s.push_str(&" ".repeat(i));
                s.push_str("if True:\n");
            }
            s.push_str(&" ".repeat(400));
            s.push_str("x = 1\n");
            s
        },
    ];
    for source in cases {
        let err = evaluate(&source).unwrap_err();
        assert!(
            matches!(
                err.kind,
                PlanErrorKind::Exhausted(
                    Bound::Nesting { .. }
                        | Bound::StatementSize { .. }
                        | Bound::Indent { .. }
                        | Bound::SourceBytes { .. }
                )
            ),
            "must be refused by a shape bound, got {err}"
        );
    }
}

#[test]
fn the_worst_input_the_bounds_admit_still_evaluates() {
    // The other half of the previous test: the guards have to be loose enough that everything they
    // *do* accept survives the parser on the stack we give it. These sit just under each cap.
    let l = Limits::default();
    let admitted = [
        format!("x = {}1\n", "-".repeat(l.max_statement_weight - 8)),
        format!("x = {}True\n", "not ".repeat(l.max_statement_weight - 8)),
        format!("x = 1{}\n", "+1".repeat((l.max_statement_weight - 8) / 2)),
        format!("x = {}{}\n", "[".repeat(l.max_nesting), "]".repeat(l.max_nesting)).repeat(400),
        format!(
            "x = {}{}{}\n",
            "[".repeat(l.max_nesting),
            "1,".repeat(l.max_statement_weight / 2 - l.max_nesting - 8),
            "]".repeat(l.max_nesting)
        ),
    ];
    for source in admitted {
        assert!(source.len() <= l.max_source_bytes, "test case must be inside the source cap");
        assert!(evaluate(&source).is_ok(), "a bound is tighter than it needs to be");
    }
}

#[test]
fn a_long_run_string_is_not_what_the_statement_bound_is_for() {
    // The bound counts tokens, so a 6 KB shell script in `run =` is one of them. If this regresses,
    // the cap silently becomes a rule about how long your build command may be.
    let script = "echo step && ".repeat(500);
    let p = evaluate(&format!("step(\"s\", run = \"{script}\")")).unwrap();
    assert_eq!(p.steps[0].kind, StepKind::Run(script));
}

// ── Validation: design D§4.4's table, rule by rule ───────────────────────────────────────────────

#[test]
fn duplicate_names_are_refused() {
    let err = evaluate("step(\"test\", run = \"a\")\nstep(\"test\", run = \"b\")").unwrap_err();
    assert_eq!(err.kind, Invalid::DuplicateName { name: "test".into() }.into());
    assert_eq!(err.line, Some(2));
}

#[test]
fn a_needs_target_must_already_exist_which_is_why_cycles_cannot_be_written() {
    // Dangling forward reference: the only shape a cycle could start as.
    let err = evaluate(r#"step("a", run = "x", needs = ["b"])"#).unwrap_err();
    assert_eq!(
        err.kind,
        Invalid::DanglingNeeds { name: "a".into(), missing: "b".into() }.into()
    );

    // A self-edge is the degenerate cycle, and it is the same error: the name is not in the index
    // until after the step is recorded.
    let err = evaluate(r#"step("a", run = "x", needs = ["a"])"#).unwrap_err();
    assert!(matches!(err.kind, PlanErrorKind::Invalid(Invalid::DanglingNeeds { .. })));

    // And there is no way to reach back and mutate an existing step, so a two-node cycle cannot be
    // assembled after the fact either — the handle is a plain string, not a mutable node.
    let err = evaluate(
        r#"
a = step("a", run = "x")
b = step("b", run = "x", needs = [a])
step("c", run = "x", needs = [b, "d"])
"#,
    )
    .unwrap_err();
    assert!(matches!(err.kind, PlanErrorKind::Invalid(Invalid::DanglingNeeds { .. })));
}

#[test]
fn every_emitted_dag_is_topologically_ordered() {
    // The structural claim, asserted directly: each step's `needs` name only steps before it.
    let p = evaluate(DESIGN_EXAMPLE).unwrap();
    let mut seen: Vec<&str> = Vec::new();
    for step in &p.steps {
        for need in &step.needs {
            assert!(seen.contains(&need.as_str()), "`{need}` must be declared before `{}`", step.name);
        }
        seen.push(&step.name);
    }
}

#[test]
fn bad_trust_tiers_are_refused() {
    for bad in ["Trusted", "root", "", "untrusted "] {
        let err = evaluate(&format!("trust({bad:?})")).unwrap_err();
        assert!(
            matches!(err.kind, PlanErrorKind::Invalid(Invalid::Tier { .. })),
            "{bad:?} must not be a tier"
        );
    }
    assert_eq!(evaluate("trust(\"untrusted\")").unwrap().trust, Some(Trust::Untrusted));
}

#[test]
fn trust_is_a_request_that_policy_clamps_upward_only() {
    // Design D§4.4: `effective tier = max(policy_floor(author_class), request)`. On the fleet the
    // floor is a microVM, so `trust("trusted")` — the strongest thing a pipeline can ask for — is
    // inert. This is the anti-privilege-escalation property, so it gets an assertion of its own.
    let p = evaluate("trust(\"trusted\")").unwrap();
    let requested = p.trust.unwrap();
    assert_eq!(requested.requested_tier(), IsolationTier::Container);
    assert_eq!(
        requested.effective_tier(IsolationTier::MicroVm),
        IsolationTier::MicroVm,
        "a pipeline may not talk its way down to a container on a multi-tenant floor"
    );
    assert_eq!(requested.effective_tier(IsolationTier::Container), IsolationTier::Container);
    // And the other direction still clamps up.
    assert_eq!(
        Trust::Untrusted.effective_tier(IsolationTier::Container),
        IsolationTier::MicroVm
    );
}

#[test]
fn shard_is_auto_or_one_to_two_hundred_and_fifty_six() {
    assert_eq!(evaluate(r#"step("s", run="x", shard="auto")"#).unwrap().steps[0].shard, Some(Shard::Auto));
    assert_eq!(evaluate(r#"step("s", run="x", shard=256)"#).unwrap().steps[0].shard, Some(Shard::Fixed(256)));
    assert_eq!(evaluate(r#"step("s", run="x", shard=1)"#).unwrap().steps[0].shard, Some(Shard::Fixed(1)));
    for bad in ["0", "-1", "257", "\"AUTO\"", "\"\"", "True", "1.5", "[1]"] {
        let err = evaluate(&format!("step(\"s\", run=\"x\", shard={bad})")).unwrap_err();
        assert!(
            matches!(err.kind, PlanErrorKind::Invalid(Invalid::Shard { .. })),
            "shard={bad} must be refused, got {err}"
        );
    }
}

#[test]
fn names_are_bounded_and_narrow() {
    let long = "a".repeat(65);
    let err = evaluate(&format!("step({long:?}, run = \"x\")")).unwrap_err();
    assert!(matches!(err.kind, PlanErrorKind::Invalid(Invalid::NameLength { .. })));

    // Written as raw source rather than through `{:?}`, so the bidi override and the accented
    // character reach the *dialect* as literal UTF-8 — which is how they would arrive in a repo.
    for bad in ["a b", "a;rm -rf /", "../../etc", "a\u{202e}b", "", "naïve", "a\u{200b}b"] {
        let err = evaluate(&format!("step(\"{bad}\", run = \"x\")")).unwrap_err();
        assert!(
            matches!(
                err.kind,
                PlanErrorKind::Invalid(Invalid::NameCharset { .. } | Invalid::NameLength { .. })
            ),
            "{bad:?} must not be a step name, got {err}"
        );
    }
}

#[test]
fn cache_scope_and_image_are_bounded() {
    assert!(evaluate("cache_scope(\"acme-rust\")").is_ok());
    let err = evaluate("cache_scope(\"../other-tenant\")").unwrap_err();
    assert!(matches!(err.kind, PlanErrorKind::Invalid(Invalid::CacheScope { .. })));

    let err = evaluate(&format!("image({:?})", "r".repeat(513))).unwrap_err();
    assert!(matches!(err.kind, PlanErrorKind::Invalid(Invalid::ImageRef { .. })));
}

#[test]
fn setting_a_module_level_value_twice_is_an_error_not_a_race() {
    // Last-wins would make the pipeline's meaning depend on evaluation order inside a `for`, which
    // is exactly the kind of ambiguity an author should never have to reason about.
    for src in [
        "image(\"a\")\nimage(\"b\")",
        "trust(\"trusted\")\ntrust(\"untrusted\")",
        "cache_scope(\"a\")\ncache_scope(\"b\")",
    ] {
        let err = evaluate(src).unwrap_err();
        assert!(matches!(err.kind, PlanErrorKind::Invalid(Invalid::Redeclared { .. })), "{src}");
    }
}

#[test]
fn uses_must_name_a_registered_action() {
    let err = evaluate(r#"action("scan", uses = "hull/rm-rf")"#).unwrap_err();
    assert_eq!(err.kind, Invalid::UnknownAction { got: "hull/rm-rf".into() }.into());

    // The registry is the server's, so a deployment with a newer node binary can widen it — but a
    // pipeline still cannot.
    let p = evaluate_with(
        r#"action("lint", uses = "hull/lint")"#,
        &Limits::default(),
        &["hull/lint"],
    )
    .unwrap();
    assert_eq!(p.steps[0].kind, StepKind::Action("hull/lint".into()));
}

#[test]
fn a_step_with_nothing_to_run_is_refused() {
    let err = evaluate(r#"step("s")"#).unwrap_err();
    assert_eq!(err.kind, Invalid::NothingToRun { name: "s".into() }.into());
}

#[test]
fn bad_timeouts_are_refused_at_plan_time_not_at_dispatch() {
    for bad in ["\"20\"", "\"20 m\"", "\"1d\"", "\"0s\"", "\"-5m\"", "\"\""] {
        let err = evaluate(&format!("step(\"s\", run=\"x\", timeout={bad})")).unwrap_err();
        assert!(
            matches!(err.kind, PlanErrorKind::Invalid(Invalid::TimeoutSyntax { .. })),
            "timeout={bad} must be refused, got {err}"
        );
    }
    let err = evaluate(r#"step("s", run="x", timeout="48h")"#).unwrap_err();
    assert!(matches!(err.kind, PlanErrorKind::Invalid(Invalid::TimeoutTooLong { .. })));
}

#[test]
fn control_characters_cannot_ride_in_on_a_glob_or_a_command() {
    let err = evaluate("step(\"s\", run = \"echo\\u0000rm\")").unwrap_err();
    assert!(matches!(err.kind, PlanErrorKind::Invalid(Invalid::ControlCharacters { .. })));

    let err = evaluate("step(\"s\", run = \"x\", inputs = [\"a\\u001b[2Kb\"])").unwrap_err();
    assert!(matches!(err.kind, PlanErrorKind::Invalid(Invalid::ControlCharacters { .. })));
}

#[test]
fn list_fields_are_bounded() {
    let limits = Limits::default();
    let err = evaluate_with(
        r#"step("s", run = "x", inputs = ["g" for i in range(2000)])"#,
        &limits,
        BUILTIN_ACTIONS,
    )
    .unwrap_err();
    assert!(matches!(err.kind, PlanErrorKind::Invalid(Invalid::ListTooLong { .. })));
}

// ── Error reporting: safe to show an untrusted author ────────────────────────────────────────────

#[test]
fn no_error_leaks_a_host_path_a_stack_or_our_source() {
    // Every one of these is rendered into a review comment on a change whose author may be an
    // outsider (design D§1). Nothing about the machine that evaluated it may travel back.
    let hostile = [
        "step(\"a\", run = \"x\"",                  // syntax error
        "load(\"x\", \"y\")",                        // absent feature
        "open(\"/etc/shadow\")",                     // absent builtin
        "while True:\n    pass",                     // absent statement
        "step(\"a\", run = 1)",                      // wrong argument type
        "step(\"a\", nonsense = 1, run = \"x\")",    // unknown keyword
        "step(\"dup\", run=\"x\")\nstep(\"dup\", run=\"y\")",
        "def f():\n    return f()\nf()",             // stack cap
        "fail(\"a message from the pipeline\")",     // author-triggered
    ];
    for src in hostile {
        let rendered = evaluate(src).unwrap_err().to_string();
        assert!(!rendered.contains("/Users/"), "leaked a host path: {rendered}");
        assert!(!rendered.contains(".cargo"), "leaked our toolchain: {rendered}");
        assert!(!rendered.contains(".rs:"), "leaked a Rust source location: {rendered}");
        assert!(!rendered.to_lowercase().contains("backtrace"), "leaked a backtrace: {rendered}");
        assert!(!rendered.contains('\n'), "multi-line output is where a stack hides: {rendered}");
        assert!(rendered.len() < 400, "an error is a message, not a dump: {rendered}");
        assert!(
            rendered.starts_with(".hull/ci.star"),
            "an author needs to know which file: {rendered}"
        );
    }
}

#[test]
fn an_attackers_string_cannot_use_an_error_as_a_display_surface() {
    // A 100 KB "tier" would otherwise be echoed verbatim into a review comment.
    let flood = "z".repeat(100_000);
    let rendered = evaluate(&format!("trust({flood:?})")).unwrap_err().to_string();
    assert!(rendered.len() < 200, "error must truncate the offending value: {} bytes", rendered.len());
}

#[test]
fn a_syntax_error_still_points_at_a_line() {
    let err = evaluate("image(\"ok\")\n\nstep(\"a\", run = \"x\"\n").unwrap_err();
    assert!(matches!(err.kind, PlanErrorKind::Language(_)));
    assert!(err.to_string().starts_with(".hull/ci.star"));
}

// ── Degenerate but legal inputs ──────────────────────────────────────────────────────────────────

#[test]
fn an_empty_pipeline_is_a_pipeline() {
    // Not this crate's job to decide that zero steps means `no_tests`; that is a verdict, and
    // verdicts belong to the server (design D§4.4 fallback, spec §7).
    let p = evaluate("").unwrap();
    assert!(p.steps.is_empty());
    assert_eq!(p.image, None);
    assert_eq!(p.trust, None);
    assert_eq!(p.cache_scope, None);
    assert_eq!(p.depth(), 0);
    assert_eq!(evaluate("# just a comment\n").unwrap(), p);
}

#[test]
fn a_per_step_image_overrides_the_default() {
    let p = evaluate(
        r#"
image("rust:1.83")
step("a", run = "x")
step("b", run = "y", image = "node:22")
"#,
    )
    .unwrap();
    assert_eq!(p.step("a").unwrap().effective_image(&p), Some("rust:1.83"));
    assert_eq!(p.step("b").unwrap().effective_image(&p), Some("node:22"));
}

#[test]
fn continue_on_error_round_trips() {
    let p = evaluate(r#"step("flaky", run = "x", continue_on_error = True)"#).unwrap();
    assert!(p.steps[0].continue_on_error);
    assert!(!evaluate(r#"step("s", run = "x")"#).unwrap().steps[0].continue_on_error);
}


/// The fourth route to a deep AST, found by security audit: an `elif` chain nests the parser's
/// recursion once per branch while adding no brackets, no indentation and no single large statement.
/// Every other shape measure reads flat at any depth, so before this bound the only thing between a
/// pipeline and a `SIGABRT` was `max_source_bytes` — a knob that reads as unrelated to stack safety,
/// and which left a margin of about 1.5× rather than the ~4× the measured shapes are sized for.
#[test]
fn an_elif_chain_is_bounded_like_every_other_route_to_a_deep_ast() {
    let limits = hull_ci_plan::Limits::default();

    // A ladder past the bound is refused, and refused by *name* — the author is told which rule.
    let long = (0..limits.max_block_chain + 50)
        .map(|i| format!("elif x == {i}:\n    pass\n"))
        .collect::<String>();
    let src = format!("x = 1\nif x == -1:\n    pass\n{long}else:\n    pass\n");
    let err = hull_ci_plan::evaluate(&src).expect_err("a chain past the bound must be refused");
    let msg = err.to_string();
    assert!(msg.contains("conditional chain"), "the rule should name itself: {msg}");

    // And an ordinary ladder still evaluates — a bound that refuses real pipelines is not a bound,
    // it is an outage.
    let ok = "\n".to_string()
        + &(0..20).map(|i| format!("if False:\n    pass\nelif {i} == -1:\n    pass\n")).collect::<String>()
        + "step(\"build\", run = \"true\", inputs = [\"src/**\"])\n";
    let p = hull_ci_plan::evaluate(&ok).expect("twenty separate short ladders are ordinary");
    assert_eq!(p.steps.len(), 1);
}

/// Separate ladders must not add together: it is the depth of *one* chain that costs stack, and a
/// file of many short `if`/`elif` pairs is a normal pipeline, not an attack.
#[test]
fn separate_conditional_chains_are_not_summed() {
    let src = (0..300)
        .map(|i| format!("if {i} == -1:\n    pass\nelif {i} == -2:\n    pass\n"))
        .collect::<String>()
        + "step(\"b\", run = \"true\", inputs = [\"src/**\"])\n";
    let p = hull_ci_plan::evaluate(&src).expect("300 two-branch ladders are not one 600-branch chain");
    assert_eq!(p.steps.len(), 1);
}
