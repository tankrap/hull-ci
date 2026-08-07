//! A global allocator with a hard ceiling — and the reason it can only live in a child process.
//!
//! **The gap this closes.** Design D§4.4 asks for a memory bound, and
//! [`Limits::max_heap_bytes`](crate::Limits::max_heap_bytes) was it. starlark-rust's own words
//! about that knob (`Evaluator::set_max_heap_size`) are worth quoting, because they are the whole
//! finding:
//!
//! > this check in particular is best-effort and should absolutely not be treated as a way to
//! > guarantee bounded memory use of an evaluation. Use OS-level APIs in a subprocess if you want
//! > that. […] This limit is not enforced on allocation, but instead checked once every so often
//! > during evaluation.
//!
//! "Once every so often" is every 1 000 bytecode instructions. Measured against `starlark` 0.14.2,
//! release build, that leaves the bound decorative at a 64 MiB setting:
//!
//! | `.hull/ci.star` | source | outcome | peak RSS |
//! |---|---|---|---|
//! | `s = "A"` then `for i in range(31): s = s + s` | **58 B** | *succeeded* | **4 420 MB** |
//! | the same at `range(32)` | 58 B | panicked (`len overflow`) | 4 304 MB |
//! | `x = "A" * 500000000` | 41 B | correct error | 1 008 MB |
//! | `x = [0] * 100000000` | 41 B | correct error | 1 608 MB |
//! | `t = s + s + … + s` (400 terms, one statement) | 1.6 KB | correct error, 16 s | 4 901 MB |
//!
//! The third and fourth rows are the point: *returning the right error is not the same as not
//! spending the memory*. Every one of these is a file any tenant can commit, and the planner runs
//! on the control plane for every job (spec §14.1).
//!
//! **Why the ceiling cannot be enforced in-process.** There is exactly one place that sees every
//! byte before it is committed — the global allocator — and a `GlobalAlloc` implementation may not
//! unwind, so it cannot turn "over budget" into a Rust error. Its only options are to return null
//! (which sends the caller to `handle_alloc_error`, i.e. `abort`) or to terminate. Neither is
//! survivable in the control-plane process. Nor can a thread be killed from outside in Rust, so a
//! watchdog has nothing to act on. Cooperative checks — starlark's, or a finer one of our own at
//! every statement — are always *after* the fact, and a single operation (`"A" * 500000000`) spends
//! a gigabyte between two of them.
//!
//! So the ceiling is enforced where terminating is the *correct* answer: inside the short-lived
//! child process that [`crate::sandbox`] spawns for each evaluation. There, refusal is
//! [`libc::_exit`] with [`EXIT_OVER_BUDGET`], which the parent reads back as
//! [`Bound::Memory`](crate::Bound::Memory).
//!
//! **Cost.** Two relaxed atomics on allocation and one on free, uncontended (the child is one
//! evaluation thread). It does not measurably move the numbers in [`crate::sandbox`]'s table.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

/// The child's exit code when [`Bounded`] refused an allocation.
///
/// A distinct code, not a signal, so the parent can tell "this pipeline wanted too much memory"
/// (the author's problem, [`Bound::Memory`](crate::Bound::Memory)) from "the evaluator fell over"
/// (ours, [`PlanErrorKind::Internal`](crate::PlanErrorKind::Internal)). Kept out of the range libc
/// and the shell use for their own meanings.
pub const EXIT_OVER_BUDGET: i32 = 20;

/// Sentinel for "no ceiling set yet" — the child's own startup is not what the budget is about.
const UNARMED: usize = usize::MAX;

/// A [`System`] allocator that counts live bytes and terminates the process past a ceiling.
///
/// Install it in a binary that exists to be killed:
///
/// ```ignore
/// #[global_allocator]
/// static ALLOC: hull_ci_plan::alloc::Bounded = hull_ci_plan::alloc::Bounded::new();
/// ```
///
/// It counts **live** bytes (allocated minus freed), not cumulative traffic, because live bytes are
/// what a resident-set number is made of and what actually threatens the host. A pipeline that
/// churns a megabyte a million times is bounded by
/// [`max_ticks`](crate::Limits::max_ticks), which is the budget for that shape of abuse.
pub struct Bounded {
    live: AtomicUsize,
    peak: AtomicUsize,
    ceiling: AtomicUsize,
}

impl Bounded {
    pub const fn new() -> Self {
        Bounded {
            live: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            ceiling: AtomicUsize::new(UNARMED),
        }
    }

    /// Arm the ceiling at `budget` bytes **above what is already live**.
    ///
    /// Relative, so the budget is about the evaluation rather than about how large the request that
    /// carried it happened to be. Call it once, after the request is decoded and before the
    /// evaluator runs.
    pub fn arm(&self, budget: usize) {
        let base = self.live.load(Ordering::Relaxed);
        self.ceiling.store(base.saturating_add(budget), Ordering::Relaxed);
    }

    /// The high-water mark of live bytes so far. Reported back to the parent so an operator can see
    /// how close real pipelines run to the bound before it ever fires (starlark's own docs
    /// recommend exactly this).
    pub fn peak_bytes(&self) -> u64 {
        self.peak.load(Ordering::Relaxed) as u64
    }

    /// Account `size` new bytes and terminate if that crosses the ceiling.
    ///
    /// `_exit` rather than `abort`: no unwinding (forbidden here), no signal for the parent to
    /// guess at, no atexit handler that might allocate.
    #[inline]
    fn charge(&self, size: usize) {
        let now = self.live.fetch_add(size, Ordering::Relaxed) + size;
        if now > self.ceiling.load(Ordering::Relaxed) {
            // SAFETY: `_exit` does not return, allocate, or unwind, which is the entire set of
            // things a `GlobalAlloc` method is not allowed to do.
            unsafe { libc::_exit(EXIT_OVER_BUDGET) }
        }
        self.peak.fetch_max(now, Ordering::Relaxed);
    }

    #[inline]
    fn refund(&self, size: usize) {
        self.live.fetch_sub(size, Ordering::Relaxed);
    }
}

impl Default for Bounded {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: every method forwards to `System` after accounting, and the accounting itself only
// touches relaxed atomics and `_exit`. Nothing here allocates or unwinds.
unsafe impl GlobalAlloc for Bounded {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.charge(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.charge(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.refund(layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }

    /// Charged on the *growth only*, and charged **before** the copy — a realloc that doubles a
    /// gigabyte string is the string-doubling bomb, and it must be refused while it is still a
    /// request rather than after the bytes have been touched.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size > layout.size() {
            self.charge(new_size - layout.size());
        } else {
            self.refund(layout.size() - new_size);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The accounting, without the half that ends the process. `charge`/`refund` are what make the
    /// ceiling meaningful, so they are worth a test that does not need a subprocess to run.
    #[test]
    fn live_bytes_track_allocation_and_free_and_peak_only_rises() {
        let b = Bounded::new();
        b.arm(1 << 30);
        b.charge(1000);
        b.charge(500);
        assert_eq!(b.peak_bytes(), 1500);
        b.refund(1400);
        assert_eq!(b.live.load(Ordering::Relaxed), 100);
        assert_eq!(b.peak_bytes(), 1500, "peak is a high-water mark, not a gauge");
        b.charge(200);
        assert_eq!(b.peak_bytes(), 1500);
        b.charge(2000);
        assert_eq!(b.peak_bytes(), 2300);
    }

    #[test]
    fn arming_is_relative_to_what_is_already_live() {
        let b = Bounded::new();
        b.charge(4096); // the request we were handed, before the budget is about anything
        b.arm(1024);
        assert_eq!(b.ceiling.load(Ordering::Relaxed), 4096 + 1024);
    }
}
