//! The bounded evaluator: one pipeline in, one DAG out, and a process that may be killed.
//!
//! This binary exists so that "over budget" has somewhere to be enforced. A `GlobalAlloc` may not
//! unwind, so the only refusal it can express is to end the process — which is unacceptable in the
//! control plane and exactly right here. See [`hull_ci_plan::alloc`] for the measurements that made
//! it necessary and [`hull_ci_plan::sandbox`] for what it costs.
//!
//! It reads a JSON request on stdin, writes a JSON response on stdout, and says nothing else. It
//! opens no files, reads no environment, and makes no network call: the parent has already read the
//! pipeline out of the verified tree (design D§4.4), so this process needs no ambient authority to
//! do its job — and holding none is the property that makes it safe to point at hostile input.

use std::io::{Read, Write};
use std::process::ExitCode;

use hull_ci_plan::alloc::Bounded;
use hull_ci_plan::sandbox::{Request, Response};

/// The ceiling this binary exists to enforce. Armed once the request has been decoded, so the
/// budget is about the evaluation and not about the request that carried it.
#[global_allocator]
static ALLOC: Bounded = Bounded::new();

/// Refused before decoding. The parent sends at most `max_source_bytes` (32 KiB by default) plus a
/// little JSON, so a megabyte is generous — and the request arrives on a pipe, which is exactly the
/// kind of unbounded `read_to_end` this crate exists to be careful about.
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;

/// Our own failures. The parent renders every non-zero code that is not
/// [`EXIT_OVER_BUDGET`](hull_ci_plan::alloc::EXIT_OVER_BUDGET) as "the evaluator failed", so these
/// are for a human reading a core file, not for the protocol.
const EXIT_BAD_REQUEST: u8 = 2;
const EXIT_BAD_REPLY: u8 = 3;

fn main() -> ExitCode {
    let mut raw = Vec::new();
    if std::io::stdin().take(MAX_REQUEST_BYTES).read_to_end(&mut raw).is_err() {
        return ExitCode::from(EXIT_BAD_REQUEST);
    }
    let Ok(request) = serde_json::from_slice::<Request>(&raw) else {
        return ExitCode::from(EXIT_BAD_REQUEST);
    };
    let limits = request.limits.clamped();

    ALLOC.arm(limits.hard_memory_bytes());
    cap_address_space(&limits);

    // The dedicated, measured stack still applies — it is what keeps the *parser* inside the bounds
    // `hull_ci_plan::shape` measured (design D§4.4's correction). Being in a child makes a stack
    // overflow survivable for the control plane; it does not make it a good outcome here.
    let result = hull_ci_plan::eval::evaluate_in_process(&request.source, &limits, request.actions);

    let response = Response { result, peak_bytes: ALLOC.peak_bytes() };
    let Ok(encoded) = serde_json::to_vec(&response) else {
        return ExitCode::from(EXIT_BAD_REPLY);
    };
    if std::io::stdout().write_all(&encoded).is_err() {
        return ExitCode::from(EXIT_BAD_REPLY);
    }
    ExitCode::SUCCESS
}

/// A second, coarser ceiling from the kernel.
///
/// [`Bounded`] counts what goes through Rust's global allocator, which is everything starlark-rust
/// does today. `RLIMIT_AS` covers what it would miss — a direct `mmap` from a future dependency, an
/// allocator that bypasses the hook — and it is one syscall. It is set deliberately loose so that
/// the precise bound is always the one that fires: the address space a healthy child reserves is
/// dominated by the evaluation thread's stack, which is address space rather than memory
/// ([`Limits::stack_bytes`](hull_ci_plan::Limits::stack_bytes)), plus mapped binaries and allocator
/// arenas.
///
/// Best-effort by design: Darwin does not reliably honour `RLIMIT_AS`, and a failure here must not
/// stop an evaluation the real bound would have allowed. It is the backstop, not the bound.
fn cap_address_space(limits: &hull_ci_plan::Limits) {
    const MAPPING_SLACK: usize = 512 * 1024 * 1024;
    let bytes = limits
        .hard_memory_bytes()
        .saturating_add(limits.stack_bytes)
        .saturating_add(MAPPING_SLACK);
    let limit = libc::rlimit { rlim_cur: bytes as libc::rlim_t, rlim_max: bytes as libc::rlim_t };
    // SAFETY: `setrlimit` reads the struct we hand it and touches nothing else. Lowering our own
    // limit cannot fail in a way that matters, and the return value is checked only to keep clippy
    // and the reader honest about it being best-effort.
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_AS, &limit) };
}
