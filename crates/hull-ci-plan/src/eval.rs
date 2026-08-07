//! The dialect: five builtins, a recorder, and the bounds around them.
//!
//! **Why this file is a security boundary and not a config parser.** The pipeline is
//! attacker-controlled — it is a file in the tree under test, written by whoever authored the
//! change — and it is evaluated **on the control plane**, which spec §14.1 forbids running job code
//! on. Those two facts are only compatible because the language is hermetic: the dialect has no
//! filesystem, no network, no clock, no `while`, and no unbounded recursion, so "evaluating" it
//! cannot be a way to *do* anything. A general-purpose SDK in the same slot would be
//! straight-line RCE on a host holding Hull's secrets (design D§12/D5).
//!
//! **Hermeticity here is structural, not filtered.** We do not maintain a blocklist of dangerous
//! builtins. The globals are [`GlobalsBuilder::standard`] — the Starlark standard environment,
//! which has no I/O in it at all — plus exactly the five functions below. `open`, `fetch`,
//! `time.now`, `print`, and `load` are not rejected; they do not exist, which is the difference
//! between a fence and a vacuum, and the reason the billion-laughs / remote-reference class that
//! plagues YAML has no analogue here (design D§4.4).
//!
//! **Evaluating a file records a DAG and has no side effects.** Each builtin appends to a
//! [`Recorder`]; nothing is executed, opened, resolved, or fetched. A `run` string is copied
//! verbatim into [`StepKind::Run`] — never split into argv, never interpolated, never inspected for
//! meaning. Word splitting happens inside the sandbox, because a control plane that had parsed a
//! shell command line is one refactor away from having run one.
//!
//! **Cycles are unrepresentable, not detected.** `step`/`action` return the step's name as a
//! handle, and a `needs` entry must name a step *already recorded*. An edge can therefore only ever
//! point at an earlier index, so the emitted `steps` vector is topologically ordered by
//! construction and there is no cycle for a detector to find. Downstream (design D§4.3's step
//! model) can rely on that instead of re-checking it.

use std::cell::RefCell;
use std::collections::HashMap;

use starlark::environment::{Globals, GlobalsBuilder, Module};
use starlark::eval::Evaluator;
use starlark::syntax::{AstModule, Dialect, DialectTypes};
use starlark::values::Value;
use starlark::values::list::UnpackList;
use starlark::values::none::{NoneOr, NoneType};
use starlark::{ErrorKind, starlark_module};

use crate::error::{Bound, PlanError, PlanErrorKind, sanitize_message};
use crate::pipeline::{PlanStep, Pipeline, Shard, StepKind, Trust};
use crate::validate::{self, Invalid};
use crate::{Limits, PIPELINE_PATH};

/// The language we accept.
///
/// Two flags carry the weight:
///
/// * `enable_load: false` — `load()` is the one Starlark feature that reaches outside the file. It
///   is the reference-expansion hole design D§4.4 says must be *absent*, so it is off at the
///   grammar level: `load("x", "y")` is a parse error, not a resolver that returns nothing.
/// * `enable_top_level_stmt: true` — **the prototype's finding**. Standard Starlark forbids `for`
///   and `if` at module scope (`for cannot be used outside def`), which would make the headline
///   ergonomics of design D§4.4 — "express a matrix once" — impossible: the example's three
///   `clippy-*` steps come from a top-level `for`. Enabling it changes nothing about hermeticity or
///   termination (a `for` iterates a finite value; there is still no `while`), it only lets the
///   fan-out live where an author would write it.
///
/// Everything else is off or standard. `enable_types` stays `Disable` because runtime type
/// annotations would be a second, richer surface to get wrong for no authoring benefit;
/// `enable_f_strings` stays off because string interpolation in a file whose strings are commands
/// is a footgun we do not need to hand anyone.
pub fn dialect() -> Dialect {
    Dialect {
        enable_def: true,
        enable_lambda: true,
        enable_load: false,
        enable_keyword_only_arguments: false,
        enable_positional_only_arguments: false,
        enable_types: DialectTypes::Disable,
        enable_load_reexport: false,
        enable_top_level_stmt: true,
        enable_f_strings: false,
        _non_exhaustive: (),
    }
}

/// The complete global environment of the dialect: the Starlark standard library plus five
/// functions. Built once per evaluation; cheap enough that caching it would be premature.
pub fn globals() -> Globals {
    GlobalsBuilder::standard().with(pipeline_builtins).build()
}

// ── The recorder ─────────────────────────────────────────────────────────────────────────────────

/// Mutable state threaded through [`Evaluator::extra`]. `RefCell` rather than `extra_mut` because
/// every builtin wants the same short `&mut`, and a shared reference with interior mutability keeps
/// the borrow local to one method instead of held across a call.
#[derive(Debug, starlark::any::ProvidesStaticType)]
pub struct Recorder(RefCell<State>);

#[derive(Debug)]
struct State {
    limits: Limits,
    actions: Vec<String>,
    image: Option<String>,
    trust: Option<Trust>,
    cache_scope: Option<String>,
    steps: Vec<PlanStep>,
    /// Longest path ending at the step of the same index. Maintained incrementally, which is only
    /// possible *because* edges point backwards — the same property that kills cycles.
    depths: Vec<usize>,
    index: HashMap<String, usize>,
    /// The first typed failure. Kept so the caller can report *our* precise error rather than
    /// whatever starlark made of the `anyhow` we threw to unwind evaluation.
    failure: Option<PlanErrorKind>,
}

impl Recorder {
    pub fn new(limits: Limits, actions: Vec<String>) -> Self {
        Recorder(RefCell::new(State {
            limits,
            actions,
            image: None,
            trust: None,
            cache_scope: None,
            steps: Vec::new(),
            depths: Vec::new(),
            index: HashMap::new(),
            failure: None,
        }))
    }

    /// Consume the recording. Only called after a successful evaluation.
    pub fn into_pipeline(self) -> Pipeline {
        let state = self.0.into_inner();
        Pipeline {
            image: state.image,
            trust: state.trust,
            cache_scope: state.cache_scope,
            steps: state.steps,
        }
    }

    pub fn take_failure(&self) -> Option<PlanErrorKind> {
        self.0.borrow_mut().failure.take()
    }

    /// Record a typed failure and produce the error that unwinds the evaluation.
    ///
    /// The `anyhow` message is a duplicate of the typed one — it exists so that a starlark error we
    /// somehow fail to correlate still says something true, never so that anyone parses it back.
    fn fail(&self, kind: impl Into<PlanErrorKind>) -> anyhow::Error {
        let kind = kind.into();
        let message = kind.to_string();
        let mut state = self.0.borrow_mut();
        if state.failure.is_none() {
            state.failure = Some(kind);
        }
        anyhow::Error::msg(message)
    }
}

impl State {
    fn set_image(&mut self, reference: &str) -> Result<(), PlanErrorKind> {
        if self.image.is_some() {
            return Err(Invalid::Redeclared { builtin: "image".into() }.into());
        }
        validate::check_image_ref(reference)?;
        self.image = Some(reference.to_string());
        Ok(())
    }

    fn set_trust(&mut self, tier: &str) -> Result<(), PlanErrorKind> {
        if self.trust.is_some() {
            return Err(Invalid::Redeclared { builtin: "trust".into() }.into());
        }
        self.trust = Some(match tier {
            "trusted" => Trust::Trusted,
            "untrusted" => Trust::Untrusted,
            other => return Err(Invalid::Tier { got: truncate(other) }.into()),
        });
        Ok(())
    }

    fn set_cache_scope(&mut self, name: &str) -> Result<(), PlanErrorKind> {
        if self.cache_scope.is_some() {
            return Err(Invalid::Redeclared { builtin: "cache_scope".into() }.into());
        }
        validate::check_cache_scope(name)?;
        self.cache_scope = Some(name.to_string());
        Ok(())
    }

    /// The one place a node joins the DAG. Everything the table in design D§4.4 promises about a
    /// step is checked here, in the order an author would want to hear about it.
    fn push(&mut self, step: PlanStep) -> Result<String, PlanErrorKind> {
        validate::check_step_name(&step.name)?;
        if self.index.contains_key(&step.name) {
            return Err(Invalid::DuplicateName { name: step.name }.into());
        }
        if self.steps.len() >= self.limits.max_steps {
            return Err(Bound::Steps { limit: self.limits.max_steps }.into());
        }

        match &step.kind {
            StepKind::Run(run) => validate::check_run(&step.name, run)?,
            StepKind::Action(uses) => {
                let registry: Vec<&str> = self.actions.iter().map(String::as_str).collect();
                validate::check_action(uses, &registry)?;
            }
        }
        for (field, list) in [
            ("inputs", &step.inputs),
            ("cache", &step.cache),
            ("secrets", &step.secrets),
            ("needs", &step.needs),
        ] {
            if list.len() > validate::MAX_LIST_LEN {
                return Err(Invalid::ListTooLong {
                    field: field.into(),
                    name: step.name.clone(),
                    limit: validate::MAX_LIST_LEN,
                }
                .into());
            }
            for item in list {
                validate::check_list_item(field, &step.name, item)?;
            }
        }
        if let Some(reference) = &step.image {
            validate::check_image_ref(reference)?;
        }

        // The acyclicity argument, in three lines: a `needs` target is looked up in `index`, which
        // only ever holds steps already pushed, so an edge cannot reach a step declared later — and
        // a step cannot need itself, because its own name is inserted after this loop.
        let mut depth = 1;
        for need in &step.needs {
            let Some(&i) = self.index.get(need) else {
                return Err(Invalid::DanglingNeeds {
                    name: step.name.clone(),
                    missing: truncate(need),
                }
                .into());
            };
            depth = depth.max(self.depths[i] + 1);
        }
        if depth > self.limits.max_depth {
            return Err(Bound::Depth { limit: self.limits.max_depth }.into());
        }

        let handle = step.name.clone();
        self.index.insert(handle.clone(), self.steps.len());
        self.depths.push(depth);
        self.steps.push(step);
        Ok(handle)
    }
}

/// Keep an attacker's string out of an error message at full length. An error is rendered into a
/// review comment; 32 characters is enough to recognise your own typo and not enough to use the
/// error as a display surface.
fn truncate(s: &str) -> String {
    let mut out: String = s.chars().take(32).collect();
    if out.chars().count() < s.chars().count() {
        out.push('…');
    }
    out
}

// ── The five builtins (design D§4.4's table) ─────────────────────────────────────────────────────

/// Fetch the recorder for the current evaluation.
///
/// An error rather than a panic: this can only fail if [`crate::evaluate_with`] forgot to install
/// it, and a control-plane panic on a code path fed by untrusted input is a denial of service even
/// when the panic itself is our bug.
fn recorder<'a>(eval: &Evaluator<'_, 'a, '_>) -> anyhow::Result<&'a Recorder> {
    eval.extra
        .and_then(|extra| extra.downcast_ref::<Recorder>())
        .ok_or_else(|| anyhow::Error::msg("pipeline evaluator was not initialised"))
}

/// `shard = "auto"` | `shard = <int 1..=256>` (design D§4.4).
fn unpack_shard(value: Value) -> Result<Shard, Invalid> {
    let bad = |v: Value| Invalid::Shard { got: truncate(&v.to_repr()), max: validate::MAX_SHARD };
    if let Some(s) = value.unpack_str() {
        return if s == "auto" { Ok(Shard::Auto) } else { Err(bad(value)) };
    }
    // `unpack_bool` first: in Starlark `True` is not an `int`, and a pipeline that reads
    // `shard = True` deserves the shard error rather than a silent `Fixed(1)`.
    if value.unpack_bool().is_some() {
        return Err(bad(value));
    }
    match value.unpack_i32() {
        Some(n) if (1..=validate::MAX_SHARD as i32).contains(&n) => Ok(Shard::Fixed(n as u32)),
        _ => Err(bad(value)),
    }
}

#[starlark_module]
fn pipeline_builtins(builder: &mut GlobalsBuilder) {
    /// `image(ref)` — the default OCI ref, resolved to a digest at plan time by the server.
    fn image(
        #[starlark(require = pos)] reference: &str,
        eval: &mut Evaluator,
    ) -> anyhow::Result<NoneType> {
        let rec = recorder(eval)?;
        let outcome = rec.0.borrow_mut().set_image(reference);
        outcome.map_err(|e| rec.fail(e)).map(|()| NoneType)
    }

    /// `trust(tier)` — *requests* an isolation tier. Clamped upward by policy, never downward, and
    /// it cannot touch author class (design D§1), so no pipeline can grant itself cache-write or
    /// secrets by editing this line.
    fn trust(
        #[starlark(require = pos)] tier: &str,
        eval: &mut Evaluator,
    ) -> anyhow::Result<NoneType> {
        let rec = recorder(eval)?;
        let outcome = rec.0.borrow_mut().set_trust(tier);
        outcome.map_err(|e| rec.fail(e)).map(|()| NoneType)
    }

    /// `cache_scope(name)` — names a cache scope **within this tenant** (design D§6.3). Naming a
    /// scope this repo may not write yields read-only access, not an error: write access is an
    /// admin grant on the tenant, and this is a string in an untrusted file.
    fn cache_scope(
        #[starlark(require = pos)] name: &str,
        eval: &mut Evaluator,
    ) -> anyhow::Result<NoneType> {
        let rec = recorder(eval)?;
        let outcome = rec.0.borrow_mut().set_cache_scope(name);
        outcome.map_err(|e| rec.fail(e)).map(|()| NoneType)
    }

    /// `step(name, run=None, inputs=[], cache=[], secrets=[], needs=[], shard=None, timeout=None,
    /// image=None, continue_on_error=False)` → the step's name, as a handle.
    #[allow(clippy::too_many_arguments)]
    fn step(
        #[starlark(require = pos)] name: &str,
        #[starlark(require = named, default = NoneOr::None)] run: NoneOr<&str>,
        #[starlark(require = named, default = UnpackList::default())] inputs: UnpackList<String>,
        #[starlark(require = named, default = UnpackList::default())] cache: UnpackList<String>,
        #[starlark(require = named, default = UnpackList::default())] secrets: UnpackList<String>,
        #[starlark(require = named, default = UnpackList::default())] needs: UnpackList<String>,
        #[starlark(require = named, default = NoneOr::None)] shard: NoneOr<Value>,
        #[starlark(require = named, default = NoneOr::None)] timeout: NoneOr<&str>,
        #[starlark(require = named, default = NoneOr::None)] image: NoneOr<&str>,
        #[starlark(require = named, default = false)] continue_on_error: bool,
        eval: &mut Evaluator,
    ) -> anyhow::Result<String> {
        let rec = recorder(eval)?;
        // A step with no `run` has nothing to do. Design D§4.4 gives `run` a `None` default but
        // never says what a run-less, uses-less step means; treating it as a no-op node would put
        // an empty argv in front of a node agent, so it is refused here where the author can see it.
        let Some(run) = run.into_option() else {
            return Err(rec.fail(Invalid::NothingToRun { name: truncate(name) }));
        };
        let step = build_step(
            rec,
            name,
            StepKind::Run(run.to_string()),
            inputs,
            cache,
            secrets,
            needs,
            shard,
            timeout,
            image,
            continue_on_error,
        )?;
        let outcome = rec.0.borrow_mut().push(step);
        outcome.map_err(|e| rec.fail(e))
    }

    /// `action(name, uses, needs=[])` — a built-in action implemented in the node binary, with **no
    /// user shell**. `uses` must name a registered action, checked here rather than at dispatch so
    /// a typo is a pipeline error with a line number.
    fn action(
        #[starlark(require = pos)] name: &str,
        uses: &str,
        #[starlark(require = named, default = UnpackList::default())] needs: UnpackList<String>,
        #[starlark(require = named, default = NoneOr::None)] timeout: NoneOr<&str>,
        #[starlark(require = named, default = false)] continue_on_error: bool,
        eval: &mut Evaluator,
    ) -> anyhow::Result<String> {
        let rec = recorder(eval)?;
        let step = build_step(
            rec,
            name,
            StepKind::Action(uses.to_string()),
            UnpackList::default(),
            UnpackList::default(),
            UnpackList::default(),
            needs,
            NoneOr::None,
            timeout,
            NoneOr::None,
            continue_on_error,
        )?;
        let outcome = rec.0.borrow_mut().push(step);
        outcome.map_err(|e| rec.fail(e))
    }
}

/// Turn one call's arguments into an unvalidated [`PlanStep`]. Shared by `step` and `action` so the
/// two cannot drift on the fields they have in common — the difference between them is
/// [`StepKind`], and it should be nothing else.
#[allow(clippy::too_many_arguments)]
fn build_step(
    rec: &Recorder,
    name: &str,
    kind: StepKind,
    inputs: UnpackList<String>,
    cache: UnpackList<String>,
    secrets: UnpackList<String>,
    needs: UnpackList<String>,
    shard: NoneOr<Value>,
    timeout: NoneOr<&str>,
    image: NoneOr<&str>,
    continue_on_error: bool,
) -> anyhow::Result<PlanStep> {
    let shard = match shard.into_option() {
        Some(v) => Some(unpack_shard(v).map_err(|e| rec.fail(e))?),
        None => None,
    };
    let timeout = match timeout.into_option() {
        Some(raw) => Some(validate::parse_timeout(raw).map_err(|e| rec.fail(e))?),
        None => None,
    };
    Ok(PlanStep {
        name: name.to_string(),
        kind,
        inputs: inputs.items,
        cache: cache.items,
        secrets: secrets.items,
        needs: needs.items,
        shard,
        timeout,
        image: image.into_option().map(str::to_string),
        continue_on_error,
    })
}

// ── The driver ───────────────────────────────────────────────────────────────────────────────────

/// Evaluate a pipeline file into a DAG **in this process**, with no bound on memory.
///
/// The name is the warning. The work here is complete and correct, but every resource bound it
/// installs is one starlark-rust checks *periodically* — so the memory an evaluation actually
/// consumes is not among them. Measured: a 58-byte file reached **4 420 MB** resident and returned
/// `Ok` (the table is in [`crate::alloc`]). The only legitimate caller is the `hull-ci-plan-eval`
/// binary, which runs this inside a process whose allocator has a ceiling and whose death is an
/// expected outcome. Everything else wants [`crate::evaluate_with`].
///
/// `actions` is the built-in action registry `uses` is checked against — passed in rather than read
/// from a global so the server owns what its node binary can actually run.
///
/// Runs on a **dedicated thread with an explicit stack size**, for two reasons that survive the move
/// into a child. The parser and the bytecode compiler are both recursive over the AST, so their
/// depth is a function of hostile input; pinning the stack means the margin is a number this crate
/// chose and tested against [`Limits::max_source_bytes`] rather than whatever the caller's runtime
/// happened to provide. And a stack overflow is still an *abort*, so keeping [`crate::shape`]'s
/// bounds honest is worth doing even where an abort is survivable.
pub fn evaluate_in_process(
    source: &str,
    limits: &Limits,
    actions: Vec<String>,
) -> Result<Pipeline, PlanError> {
    let source = source.to_owned();
    let limits = limits.clone();
    let stack_bytes = limits.stack_bytes;

    std::thread::Builder::new()
        .name("hull-ci-plan".to_string())
        .stack_size(stack_bytes)
        .spawn(move || evaluate_on_this_stack(&source, &limits, actions))
        .map_err(|_| PlanError::new(PlanErrorKind::Internal))?
        .join()
        // A panic here is our bug. It must not become a control-plane panic, because the input that
        // provoked it is attacker-chosen and a crash loop is a denial of service (spec §14.1).
        .unwrap_or_else(|_| Err(PlanError::new(PlanErrorKind::Internal)))
}

fn evaluate_on_this_stack(
    source: &str,
    limits: &Limits,
    actions: Vec<String>,
) -> Result<Pipeline, PlanError> {
    // Refuse the file before the parser sees it. A parser is a fine place to hide a quadratic, and
    // this check costs a comparison (design D§4.4, evaluation bounds).
    if source.len() > limits.max_source_bytes {
        return Err(PlanError::new(Bound::SourceBytes { limit: limits.max_source_bytes }));
    }
    // And refuse *nested* source before the parser sees it, because recursive descent on hostile
    // nesting aborts the process rather than returning an error — see [`crate::shape`].
    let shape = crate::shape::measure(source);
    if shape.code_nesting > limits.max_nesting || shape.raw_nesting > limits.max_raw_nesting {
        return Err(PlanError::new(Bound::Nesting { limit: limits.max_nesting }));
    }
    if shape.statement_weight > limits.max_statement_weight {
        return Err(PlanError::new(Bound::StatementSize { limit: limits.max_statement_weight }));
    }
    if shape.block_chain > limits.max_block_chain {
        return Err(PlanError::new(Bound::BlockChain { limit: limits.max_block_chain }));
    }
    if shape.indent_columns > limits.max_indent_columns {
        return Err(PlanError::new(Bound::Indent { limit: limits.max_indent_columns }));
    }

    // The filename is a fixed, repo-relative logical name — never a host path — because it ends up
    // in error messages that cross back to an untrusted author (see [`crate::error`]).
    let ast = AstModule::parse(PIPELINE_PATH, source.to_owned(), &dialect())
        .map_err(|e| language_error(&e))?;

    let globals = globals();
    let recorder = Recorder::new(limits.clone(), actions);

    let outcome = Module::with_temp_heap(|module| {
        let mut eval = Evaluator::new(&module);
        // All three are set once, on a fresh evaluator, with non-zero values guaranteed by
        // `Limits::clamped`, so the only documented failure modes are unreachable.
        eval.set_max_callstack_size(limits.max_callstack).expect("fresh evaluator, non-zero limit");
        eval.set_max_tick_count(limits.max_ticks).expect("fresh evaluator, non-zero limit");
        eval.set_max_heap_size(limits.max_heap_bytes).expect("fresh evaluator, non-zero limit");
        eval.extra = Some(&recorder);

        match eval.eval_module(ast, &globals) {
            Ok(_) => Ok(()),
            Err(e) => Err(classify(&mut eval, &e, &recorder, limits)),
        }
    });
    outcome?;

    Ok(recorder.into_pipeline())
}

/// Decide what actually went wrong, preferring our own typed failure to starlark's prose.
fn classify(
    eval: &mut Evaluator,
    err: &starlark::Error,
    recorder: &Recorder,
    limits: &Limits,
) -> PlanError {
    // `+ 1` because starlark resolves to 0-based lines and humans do not.
    let line = err.span().map(|s| s.resolve_span().begin.line as u32 + 1);

    // A validation rule or an emitted-node budget: we wrote the message, it names the rule, and it
    // is the one worth showing.
    if let Some(kind) = recorder.take_failure() {
        return PlanError::at(line, kind);
    }
    if matches!(err.kind(), ErrorKind::StackOverflow(_)) {
        return PlanError::at(line, Bound::CallStack { limit: limits.max_callstack });
    }
    // starlark-rust reports both of these as an opaque `Other` error whose only distinguishing
    // feature is its English message, and `ResourceCheckResult` is not exported, so we re-derive
    // the answer from the counters instead of pattern-matching on prose. Both checks reproduce
    // starlark's own comparison exactly, so they agree with whatever actually tripped.
    let heap_used = eval.heap().peak_allocated_bytes() + eval.frozen_heap().allocated_bytes();
    if heap_used > limits.max_heap_bytes {
        return PlanError::at(line, Bound::Memory { limit: limits.max_heap_bytes });
    }
    if eval.get_total_tick_count() > limits.max_ticks {
        return PlanError::at(line, Bound::Work { limit: limits.max_ticks });
    }
    language_error(err).with_line(line)
}

/// A language-level rejection: syntax, an undefined name, a wrong argument shape.
fn language_error(err: &starlark::Error) -> PlanError {
    PlanError::new(PlanErrorKind::Language(sanitize_message(
        &err.without_diagnostic().to_string(),
    )))
}

impl PlanError {
    fn with_line(mut self, line: Option<u32>) -> Self {
        self.line = line;
        self
    }
}
