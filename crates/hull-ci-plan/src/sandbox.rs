//! Evaluation in a bounded child process — the only place a memory ceiling can actually be
//! enforced.
//!
//! **Why a process, when design D§4.4 argued against one.** The design chose Starlark over a
//! general-purpose SDK partly because "evaluating an SDK in a sandbox would drag a spawn into the
//! plan step of *every* job, forfeiting the sub-second cached verdict the design exists for". That
//! argument is about a **sandbox** spawn — a container or a microVM, hundreds of milliseconds — and
//! it still holds against one. It is not an argument about `posix_spawn` of a helper binary, which
//! is two orders of magnitude cheaper. Measured, release build, macOS, 300 iterations:
//!
//! | | in-process | in a bounded child | delta |
//! |---|---|---|---|
//! | design D§4.4's own example (7 steps, 668 B) | 123 µs | 3.55 ms | **+3.4 ms** |
//! | a `for`-generated 37-step matrix (475 B) | 103 µs | 3.60 ms | **+3.5 ms** |
//! | a one-step pipeline (24 B) | — | 3.40 ms | — |
//!
//! The third row is the useful one: the cost is **fixed**, not proportional. Of the 3.4 ms, 1.6 ms
//! is `exec` plus dynamic linking plus Rust runtime start-up, and the remaining ~1.8 ms is
//! cold-start — faulting in the pages of a 9 MB binary and building the Starlark global environment
//! once in a fresh address space. Evaluating 37 steps instead of 1 costs nothing measurable on top.
//!
//! Next to the other costs already on this path, that is not the expensive part: design D§6.1
//! measures a single pattern glob (`**/*.rs`, 100k entries) at **23.9 ms**, and a pipeline normally
//! declares several. The spawn is ~15% of one glob and ~0.35% of the "sub-second" budget it is
//! charged against. That is the trade, in numbers: **3.5 ms per plan buys a memory bound that
//! exists**, replacing bounds that measured 1–4.9 GB of resident memory for a 41-byte file
//! ([`crate::alloc`]).
//!
//! **If 3.5 ms ever stops being affordable**, the next step is a pool of pre-spawned helpers reading
//! one request each, which trades the 3.4 ms for an IPC round trip (~100 µs) at the cost of process
//! supervision, restart-after-kill, and a worker per concurrent plan. It is deliberately not built:
//! the measurement above says it would be complexity bought with no headroom problem to spend it on.
//!
//! **What the child buys beyond memory.** It is the containment for every way starlark-rust can
//! end a process rather than return an error, present and future:
//!
//! * the allocation ceiling ([`crate::alloc`]) — the reason it exists;
//! * `len overflow`, the panic `s = s + s` reaches at 2³², which used to be caught only by the
//!   evaluation thread's `join` — *after* the memory had been spent;
//! * a stack overflow the pre-parse bounds in [`crate::shape`] failed to predict, which is an abort
//!   no `join` can catch;
//! * a wall-clock hang, which [`Limits::eval_timeout`](crate::Limits::eval_timeout) turns into
//!   `SIGKILL` and an ordinary error.
//!
//! The evaluation thread with its measured stack still exists — it just lives *inside* the child
//! now, so the shape bounds and the child are two independent defences rather than one.
//!
//! **Deploying it.** The helper is `hull-ci-plan-eval`, a second binary target of this crate. Ship
//! it **next to the binary that links this crate** — that is the first thing [`worker_path`] looks
//! for — or name it explicitly with [`WORKER_ENV`]. It reads a request on stdin and writes a reply
//! on stdout; it holds no configuration, opens no files, and needs no privileges.
//!
//! **What is still not bounded, stated so nobody has to rediscover it.** The ceiling is per
//! *evaluation*, not per host: *n* plans running concurrently can hold *n* ×
//! [`Limits::hard_memory_bytes`] between them. That is the correct place to draw the line — this
//! crate is handed one file and knows nothing about fleet load — but it means the aggregate is
//! somebody else's bound, and design D§4.5's admission control is where it belongs. Two smaller
//! residuals: memory a future dependency takes by `mmap` rather than through Rust's allocator is
//! covered only by the `RLIMIT_AS` backstop the child sets, which Darwin does not reliably honour;
//! and the evaluation thread's stack is address space, deliberately uncounted, because a real
//! pipeline touches a few pages of it.
//!
//! **Fail closed.** If the helper cannot be found, evaluation fails. It does not quietly fall back
//! to running in this process: that would be a bound that reads as a fix and is not, which is the
//! exact failure this module was written to remove. The cost of that choice is that forgetting to
//! deploy the helper breaks planning loudly, which is the correct direction — the alternative is a
//! fleet that has silently lost its memory bound and no way to tell.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Bound, PlanError, PlanErrorKind};
use crate::pipeline::Pipeline;
use crate::{Limits, alloc};

/// The helper binary. A separate target of this crate, deployed next to whatever links it.
pub const WORKER_NAME: &str = "hull-ci-plan-eval";

/// Overrides the search below. The deployment escape hatch, and how a test names a helper that is
/// not where the search would look.
pub const WORKER_ENV: &str = "HULL_CI_PLAN_EVAL";

/// Cap on what we will read back from our own child. The child is ours and its output is bounded by
/// [`Limits::max_steps`], but a parent that trusts a child's length prefix has just moved the
/// denial of service one process along.
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// What the parent hands the child. Nothing here is host state — the source is the tenant's bytes,
/// and the rest is configuration the parent already holds.
#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub source: String,
    pub limits: Limits,
    pub actions: Vec<String>,
}

/// What the child hands back: the outcome, and what producing it cost.
#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub result: Result<Pipeline, PlanError>,
    pub peak_bytes: u64,
}

/// What one evaluation cost, whatever its outcome.
///
/// starlark-rust's own documentation asks users of a heap limit to watch how close real evaluations
/// run to it, so that the limit is tuned before it starts refusing honest pipelines. This is that
/// number, and the server logs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cost {
    /// High-water mark of live bytes in the child, from [`alloc::Bounded`].
    ///
    /// When the ceiling is what stopped the evaluation the child is gone before it can report, so
    /// this is the ceiling itself — a floor on the truth, never an over-statement.
    pub peak_bytes: u64,
}

/// Evaluate `source` in a child bounded by `limits`.
pub fn evaluate_with(
    source: &str,
    limits: &Limits,
    actions: &[&str],
) -> Result<Pipeline, PlanError> {
    evaluate_measured(source, limits, actions).0
}

/// [`evaluate_with`], plus what it cost.
pub fn evaluate_measured(
    source: &str,
    limits: &Limits,
    actions: &[&str],
) -> (Result<Pipeline, PlanError>, Cost) {
    let ceiling = limits.hard_memory_bytes() as u64;
    match run(source, limits, actions) {
        Ok(response) => (response.result, Cost { peak_bytes: response.peak_bytes }),
        Err(kind) => (Err(PlanError::new(kind)), Cost { peak_bytes: ceiling }),
    }
}

/// Spawn, converse, and reap. Every failure of *ours* — no helper, no spawn, a mangled reply — is
/// [`PlanErrorKind::Internal`], because it says nothing true about the author's pipeline.
fn run(source: &str, limits: &Limits, actions: &[&str]) -> Result<Response, PlanErrorKind> {
    let worker = worker_path().ok_or(PlanErrorKind::Internal)?;
    let request = Request {
        source: source.to_owned(),
        limits: limits.clone(),
        actions: actions.iter().map(|a| a.to_string()).collect(),
    };
    let request = serde_json::to_vec(&request).map_err(|_| PlanErrorKind::Internal)?;

    let mut child = Command::new(&worker)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // The child's stderr is a panic message about *our* source, in a process whose whole job is
        // to die noisily. It is not evidence about the pipeline and it is not for the author.
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| PlanErrorKind::Internal)?;

    let mut stdin = child.stdin.take().ok_or(PlanErrorKind::Internal)?;
    let stdout = child.stdout.take().ok_or(PlanErrorKind::Internal)?;

    // Both halves of the conversation on one thread, so the wall-clock guard below covers the whole
    // of it. Doing the write here and the read there would leave a window — a child that read half
    // the request and stopped — that the timeout could not see.
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let io = std::thread::Builder::new()
        .name("hull-ci-plan-io".to_string())
        .spawn(move || {
            // A dead child makes this `EPIPE`, which is not an error worth reporting: the exit
            // status is about to say something far more specific.
            let _ = stdin.write_all(&request);
            drop(stdin);
            let mut buf = Vec::new();
            let _ = stdout.take(MAX_RESPONSE_BYTES).read_to_end(&mut buf);
            let _ = done_tx.send(());
            buf
        })
        .map_err(|_| PlanErrorKind::Internal)?;

    let timed_out = done_rx.recv_timeout(limits.eval_timeout()).is_err();
    if timed_out {
        // `kill` also unblocks the io thread, whichever half of the conversation it is stuck in.
        let _ = child.kill();
    }
    // Joined and reaped *before* either result is unwrapped, so no early return can leave a zombie
    // on the control plane. Planning runs for every job; a leak here is a leak per job.
    let reply = io.join();
    let status = child.wait();
    let reply = reply.map_err(|_| PlanErrorKind::Internal)?;
    let status = status.map_err(|_| PlanErrorKind::Internal)?;

    if timed_out {
        return Err(Bound::Time { limit_ms: limits.eval_timeout_ms }.into());
    }
    if status.code() == Some(alloc::EXIT_OVER_BUDGET) {
        // The ceiling refused an allocation. This is the bound design D§4.4 asked for, finally
        // enforced somewhere it can be: see [`crate::alloc`].
        return Err(Bound::Memory { limit: limits.hard_memory_bytes() }.into());
    }
    if !status.success() {
        // A panic, a signal, a stack overflow: contained here rather than on the control plane, and
        // deliberately not described to the author (see [`crate::error`]).
        return Err(PlanErrorKind::Internal);
    }
    serde_json::from_slice(&reply).map_err(|_| PlanErrorKind::Internal)
}

/// Find the helper.
///
/// In order: an explicit override, then next to the binary that is running, then one directory up
/// from it — which is what a Cargo test binary in `target/debug/deps/` needs to reach
/// `target/debug/`. Nothing here searches `PATH`: the helper is a component of this crate, not a
/// tool the operator supplies, and resolving it through a mutable, inherited search path would be a
/// way to choose what the control plane executes.
pub fn worker_path() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os(WORKER_ENV) {
        let path = PathBuf::from(explicit);
        return path.is_file().then_some(path);
    }
    let exe = std::env::current_exe().ok()?;
    let here = exe.parent()?;
    if let Some(found) = beside(here) {
        return Some(found);
    }
    if let Some(found) = here.parent().and_then(beside) {
        return Some(found);
    }
    from_cargo_layout()
}

fn beside(dir: &Path) -> Option<PathBuf> {
    let candidate = dir.join(WORKER_NAME);
    candidate.is_file().then_some(candidate)
}

/// The last resort: a Cargo target directory, for processes **Cargo itself launched**.
///
/// This exists for one caller — a documentation test. `rustdoc` runs each example from a binary in a
/// temporary directory, so neither rule above can reach the helper, and the alternative is a crate
/// whose headline example is marked `no_run`.
///
/// Two things keep it from being a way to choose what a control plane executes. It is gated on
/// `CARGO` being present in the environment, which is true of `cargo test`/`cargo run` and false of
/// anything deployed. And it searches upward from `CARGO_MANIFEST_DIR` — a path Cargo computed from
/// the manifest — rather than from the working directory, which is attacker-influenceable in a way a
/// manifest path is not. `cfg(debug_assertions)` was the first gate tried and is worse on both
/// counts: it is on in a debug deployment and off in `cargo test --release`, i.e. exactly inverted.
fn from_cargo_layout() -> Option<PathBuf> {
    std::env::var_os("CARGO")?;
    if let Some(explicit) = std::env::var_os("CARGO_TARGET_DIR") {
        if let Some(found) = in_target(Path::new(&explicit)) {
            return Some(found);
        }
    }
    let mut dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR")?);
    loop {
        if let Some(found) = in_target(&dir.join("target")) {
            return Some(found);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn in_target(target: &Path) -> Option<PathBuf> {
    ["debug", "release"].into_iter().find_map(|profile| beside(&target.join(profile)))
}

/// Peak resident memory, in bytes, of **this** process.
///
/// Public for the same reason as [`children_peak_rss_bytes`], and it is the stricter of the two
/// claims: the bug this module closes was a pipeline file spending gigabytes *here*, on the control
/// plane. A test that reads this number fails the moment evaluation moves back into this address
/// space, which no assertion about an error type can do.
pub fn peak_rss_bytes() -> u64 {
    rss(libc::RUSAGE_SELF)
}

/// Peak resident memory, in bytes, of every child this process has reaped so far.
///
/// Public because it is how the claim in [`crate::alloc`] is *checked* rather than asserted: the
/// bound is about resident memory, so the test that proves it has to read resident memory. It is
/// also the number to put on a dashboard — the honest one, since the allocator's own count cannot
/// see pages faulted in outside the Rust heap.
///
/// A high-water mark over all reaped children, so it never decreases and can only over-state, which
/// is the safe direction for a ceiling.
pub fn children_peak_rss_bytes() -> u64 {
    rss(libc::RUSAGE_CHILDREN)
}

fn rss(who: libc::c_int) -> u64 {
    // SAFETY: `getrusage` writes a plain struct through the pointer we hand it and reads nothing
    // else. Both `who` values are defined on every Unix this runs on.
    let usage = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        if libc::getrusage(who, &mut usage) != 0 {
            return 0;
        }
        usage
    };
    // Darwin reports `ru_maxrss` in bytes; every other Unix reports kilobytes.
    if cfg!(target_os = "macos") {
        usage.ru_maxrss as u64
    } else {
        (usage.ru_maxrss as u64).saturating_mul(1024)
    }
}

impl Limits {
    /// The ceiling [`alloc::Bounded`] is armed with in the child.
    ///
    /// [`Limits::max_heap_bytes`] is the budget for the *pipeline's* values, and it is the number an
    /// author is told about. The child also has to hold the source, the AST, the compiled bytecode
    /// and the recorded DAG, none of which are on starlark's heap — so the process ceiling is that
    /// budget plus a fixed allowance for them. The allowance is fixed rather than proportional
    /// because all four are already bounded: [`Limits::max_source_bytes`] caps the first three and
    /// [`Limits::max_steps`] the fourth.
    pub fn hard_memory_bytes(&self) -> usize {
        const NON_VALUE_ALLOWANCE: usize = 16 * 1024 * 1024;
        self.max_heap_bytes.saturating_add(NON_VALUE_ALLOWANCE)
    }

    /// Wall-clock ceiling on one evaluation.
    ///
    /// [`Limits::max_ticks`] already bounds *work*, and it is the bound that produces a good error.
    /// This is the one that holds when work is not the thing being consumed — a child wedged in the
    /// kernel, a machine thrashing — and it is only reachable now that there is a process to kill.
    pub fn eval_timeout(&self) -> Duration {
        Duration::from_millis(self.eval_timeout_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_process_ceiling_sits_above_the_heap_budget_it_is_derived_from() {
        let limits = Limits::default();
        assert!(limits.hard_memory_bytes() > limits.max_heap_bytes);
        // And it cannot be talked into wrapping by an absurd setting.
        let absurd = Limits { max_heap_bytes: usize::MAX, ..Limits::default() };
        assert_eq!(absurd.hard_memory_bytes(), usize::MAX);
    }

    #[test]
    fn the_helper_is_findable_from_a_test_binary() {
        // The search has to work from `target/{debug,release}/deps/`, where every test binary in
        // this workspace lives, or the bound is untestable — and an untested bound is the thing
        // this module replaced. A missing helper is covered from the other side by
        // `tests/memory.rs::without_the_helper_evaluation_fails_rather_than_running_here`.
        let found = worker_path().expect("the helper must be findable from a test binary");
        assert!(found.is_file());
        assert_eq!(found.file_name().and_then(|n| n.to_str()), Some(WORKER_NAME));
    }
}
