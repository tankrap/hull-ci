//! `.hull/ci.star` → a validated, acyclic step DAG (design D§4.4).
//!
//! The pipeline format is **Starlark, not YAML** (design D§12/D5). Starlark reads like Python —
//! functions, `for` loops, computed values — so a build matrix is expressed once instead of
//! copy-pasted. That is the ergonomic argument. The security argument is the one that decided it:
//!
//! > The pipeline file is **attacker-controlled input** — it lives in the tree under test, written
//! > by whoever authored the change — and it is **evaluated on the control plane**, which spec
//! > §14.1 forbids running job code on. Those two facts are only compatible because the dialect is
//! > hermetic. Its hermeticity is the boundary, not a convenience.
//!
//! So this crate is closer in spirit to `hull-ci-fetch`'s tar reader than to a config loader: both
//! parse hostile bytes outside a sandbox, and both are written on the assumption that they will be
//! attacked. The properties that make that safe are structural rather than defensive:
//!
//! * **No I/O exists in the dialect.** Not filtered — absent. The globals are the Starlark standard
//!   environment plus five functions; there is no `open`, no `fetch`, no clock, no `print`, and
//!   `load()` is off at the grammar level. The billion-laughs / remote-reference class a YAML
//!   parser has to fence out has no analogue to fence.
//! * **Evaluation has no side effects.** Each builtin appends to a recording. A `run` string is
//!   copied verbatim and is *never* executed, split into argv, or interpolated here — word
//!   splitting is the sandbox's job (spec §14.1).
//! * **Cycles are unrepresentable.** `step`/`action` return the step's name as a handle, and a
//!   `needs` target must already have been declared, so every edge points backwards. [`Pipeline`]'s
//!   `steps` are topologically ordered by construction; there is no cycle for a detector to find.
//! * **Termination is bounded twice.** The language terminates by design (no `while`, no unbounded
//!   recursion), and on top of that [`Limits`] caps emitted steps, DAG depth, source size, heap,
//!   total work, and call-stack frames — because "terminates by design" is not what you want the
//!   control plane's availability to rest on when the input is hostile.
//! * **The parser is bounded too, before it runs.** Design D§4.4's bounds are all bounds on
//!   *evaluation*, and measurement showed that is too late: recursive-descent parsing of nested
//!   brackets overflows the stack and **aborts the process** while every one of those bounds is
//!   still unchecked. [`shape`] measures nesting first, and evaluation runs on a dedicated thread
//!   with a stack sized against [`Limits::max_source_bytes`]. See that module for the numbers.
//! * **Errors are safe to show.** They carry a rule and a line, never a host path or a stack —
//!   they are rendered back to the author, who on a multi-tenant instance is an outsider.
//!
//! What this crate does **not** do: resolve an image ref to a digest, decide a tier, grant a cache
//! scope, or hand out secrets. Each of those is policy, adjudicated by the server against the
//! *actor* (design D§1); a pipeline can only ever *ask*. Nor does it autodetect: when there is no
//! `.hull/ci.star` at all, the server falls back to its own detector. Given the file's contents,
//! this crate produces a [`Pipeline`] or a precise [`PlanError`], and nothing else.
//!
//! ```
//! # use hull_ci_plan::{evaluate, StepKind};
//! let pipeline = evaluate(r#"
//! image("rust:1.83")
//! build = step("build", run = "cargo build", inputs = ["**/*.rs"])
//! for crate_name in ["a", "b"]:
//!     step("clippy-" + crate_name, run = "cargo clippy -p " + crate_name, needs = [build])
//! "#).unwrap();
//! assert_eq!(pipeline.steps.len(), 3);
//! assert_eq!(pipeline.steps[2].needs, vec!["build"]);
//! assert!(matches!(&pipeline.steps[0].kind, StepKind::Run(r) if r == "cargo build"));
//! ```

pub mod error;
pub mod eval;
pub mod pipeline;
pub mod shape;
pub mod validate;

pub use error::{Bound, PlanError, PlanErrorKind};
pub use pipeline::{PlanStep, Pipeline, Shard, StepKind, Trust};
pub use validate::{BUILTIN_ACTIONS, Invalid};

/// Where the pipeline lives in a tree, and the logical name errors are reported against.
///
/// Repo-relative on purpose: it is the only "path" that ever appears in a message crossing back to
/// an untrusted author, and it is one they already have.
pub const PIPELINE_PATH: &str = ".hull/ci.star";

/// The evaluation bounds of design D§4.4.
///
/// Defence in depth, all of it. The dialect terminates by design, so a legitimate pipeline is
/// nowhere near any of these; they are what stops a pathological-but-valid module from wedging the
/// planner, and the planner runs on the control plane for *every* job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Emitted nodes. A repo with more than this many steps has a problem the planner cannot fix.
    pub max_steps: usize,
    /// Longest `needs` chain. Depth is what turns a DAG walk into a stack, downstream and here.
    pub max_depth: usize,
    /// Bytes of source we will hand to the parser at all. 32 KiB is ~800 lines, and a pipeline that
    /// wants more steps than that should be writing a `for` loop, which is the point of the format.
    pub max_source_bytes: usize,
    /// Maximum bracket nesting in code (see [`shape`]). **Not one of design D§4.4's bounds** — it
    /// has to exist because nesting overflows the parser's stack *before* any of them is reached,
    /// and a stack overflow aborts the process rather than returning an error.
    pub max_nesting: usize,
    /// Maximum bracket nesting counting string literals too — the backstop that a bug in the
    /// scanner's string skipping cannot lower. Generous, because it can only fire on absurd input.
    pub max_raw_nesting: usize,
    /// Maximum size of one statement, in tokens ([`shape::Shape::statement_weight`]). Bounds the
    /// *unbracketed* route to a deep AST — `x = ------…-1`, `x = 1+1+1+…` — which no bracket cap
    /// can see. A whole string literal counts as one token, so a long `run =` script is unaffected.
    pub max_statement_weight: usize,
    /// Maximum leading indentation, in columns. Bounds block nesting, the third route.
    pub max_indent_columns: usize,
    /// Stack for the evaluation thread. The worst input the other bounds admit needs under 32 MiB
    /// in a debug build (see [`shape`]), so the default is a 4× margin. Address space, not memory:
    /// a real pipeline touches a few pages of it.
    pub stack_bytes: usize,
    /// starlark-rust's own call-stack cap — what makes unbounded recursion *terminate* instead of
    /// exhausting the host's stack.
    pub max_callstack: usize,
    /// Total "ticks" (function calls + loop backedges). Bounds a legal-but-enormous computation:
    /// a triple-nested loop over a computed range does no I/O and never recurses, and would still
    /// hold a planner thread for as long as it liked.
    pub max_ticks: u64,
    /// Starlark heap ceiling. Bounds huge literals and the string-doubling trick that builds a
    /// gigabyte from ten lines.
    pub max_heap_bytes: usize,
}

impl Default for Limits {
    /// Chosen to be an order of magnitude above anything a real pipeline does, so tripping one is
    /// evidence of abuse or a mistake rather than of an ambitious repo.
    fn default() -> Self {
        Limits {
            max_steps: 1_000,
            max_depth: 64,
            max_source_bytes: 32 * 1024,
            max_nesting: 32,
            max_raw_nesting: 512,
            max_statement_weight: 1_024,
            max_indent_columns: 256,
            stack_bytes: 128 * 1024 * 1024,
            max_callstack: 64,
            max_ticks: 10_000_000,
            max_heap_bytes: 64 * 1024 * 1024,
        }
    }
}

impl Limits {
    /// Every field at least 1.
    ///
    /// starlark-rust rejects a zero limit with an error rather than treating it as "unbounded", and
    /// a caller who passes `0` almost certainly meant "no work at all", not "no bound". Clamping
    /// makes the setters in [`eval::evaluate_with`] infallible, which is why they may `expect`.
    pub fn clamped(&self) -> Limits {
        Limits {
            max_steps: self.max_steps.max(1),
            max_depth: self.max_depth.max(1),
            max_source_bytes: self.max_source_bytes.max(1),
            max_nesting: self.max_nesting.max(1),
            max_raw_nesting: self.max_raw_nesting.max(self.max_nesting.max(1)),
            max_statement_weight: self.max_statement_weight.max(1),
            max_indent_columns: self.max_indent_columns.max(1),
            // Below a megabyte a thread cannot do useful work; a caller who passes something tiny
            // meant "small", not "let the parser run out of stack".
            stack_bytes: self.stack_bytes.max(1024 * 1024),
            max_callstack: self.max_callstack.max(1),
            max_ticks: self.max_ticks.max(1),
            max_heap_bytes: self.max_heap_bytes.max(1),
        }
    }
}

/// Evaluate a pipeline with the default [`Limits`] and the built-in action registry.
pub fn evaluate(source: &str) -> Result<Pipeline, PlanError> {
    evaluate_with(source, &Limits::default(), BUILTIN_ACTIONS)
}

/// Evaluate a pipeline with explicit bounds and an explicit action registry.
///
/// The registry is a parameter rather than a constant because `uses` must name an action the
/// *node binary* implements, and only the server knows which build of it is deployed.
pub fn evaluate_with(
    source: &str,
    limits: &Limits,
    actions: &[&str],
) -> Result<Pipeline, PlanError> {
    eval::evaluate_with(source, &limits.clamped(), actions)
}
