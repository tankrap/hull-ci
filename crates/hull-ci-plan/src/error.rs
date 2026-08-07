//! What the author sees when a pipeline does not evaluate.
//!
//! Two properties matter more than the taxonomy, and both are enforced by [`sanitize_message`] plus
//! the fact that we choose the "filename" ourselves:
//!
//! 1. **No host detail escapes.** The error is rendered into a review comment on the change that
//!    introduced the pipeline, so it is read by whoever wrote the pipeline — on a multi-tenant
//!    instance, an outsider (design D§1). A Rust backtrace, a starlark call stack, or an absolute
//!    path on the control plane would each be a small, free piece of reconnaissance about a host
//!    §14.1 says job authors must never reach. We therefore render `starlark::Error` through
//!    [`without_diagnostic`], which is its message *without* the snippet and the call stack, and we
//!    parse under the fixed logical name [`crate::PIPELINE_PATH`] so any span that does leak names a
//!    repo-relative file the author already has.
//! 2. **It is actionable.** A line number and the rule that was broken, because "your pipeline is
//!    invalid" turns a 30-second fix into a support ticket.
//!
//! [`without_diagnostic`]: starlark::Error::without_diagnostic

use serde::{Deserialize, Serialize};

use crate::validate::Invalid;

/// An evaluation bound tripped (design D§4.4, "Evaluation bounds").
///
/// These are *defence in depth*: the dialect terminates by design — no `while`, no unbounded
/// recursion that the stack cap won't stop — so in principle none of them can fire. They exist
/// because "in principle" is not a property you want the control plane's availability to rest on
/// when the input is written by an attacker.
///
/// Serialisable because evaluation now happens in a child process ([`crate::sandbox`]), so this is
/// what one process tells another. A typed error that could not cross the pipe would have to be
/// re-derived from prose on the parent side, which is precisely the mistake `eval::classify`
/// already exists to avoid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Bound {
    #[error("pipeline emits more than {limit} steps")]
    Steps { limit: usize },
    #[error("dependency chain is deeper than {limit} steps")]
    Depth { limit: usize },
    #[error("pipeline file is larger than {limit} bytes")]
    SourceBytes { limit: usize },
    /// Brackets nested deeper than the parser is safe at — see [`crate::shape`]. Not one of design
    /// D§4.4's three bounds; it has to exist because the other three are checked too late.
    #[error("brackets nested more than {limit} deep")]
    Nesting { limit: usize },
    /// One statement builds too large an expression — the unbracketed way to the same overflow.
    #[error("a single statement is more than {limit} tokens long")]
    StatementSize { limit: usize },
    /// Indentation deeper than the parser is safe at.
    #[error("indented more than {limit} columns")]
    Indent { limit: usize },
    #[error("a conditional chain is longer than the {limit}-branch limit")]
    BlockChain { limit: usize },
    #[error("evaluation exceeded its work budget of {limit} operations")]
    Work { limit: u64 },
    /// The memory ceiling. Since the audit, two different things trip this: starlark-rust's own
    /// periodic heap check, which is where the *line number* comes from, and the child's allocation
    /// ceiling ([`crate::alloc`]), which is the one that is actually a bound. The author is told the
    /// same thing either way, because from their side it is the same rule.
    #[error("evaluation exceeded its memory budget of {limit} bytes")]
    Memory { limit: usize },
    #[error("recursion exceeded the {limit}-frame call stack")]
    CallStack { limit: usize },
    /// The wall clock. [`Bound::Work`] bounds *work* and produces a better message; this one holds
    /// when the thing being consumed is not work, and it only became enforceable when evaluation
    /// moved into a process that can be killed ([`crate::sandbox`]).
    #[error("evaluation did not finish within {limit_ms} ms")]
    Time { limit_ms: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum PlanErrorKind {
    /// The dialect refused it: a syntax error, an undefined name (`load`, `open`, `time` — none of
    /// which exist here), or a builtin called with the wrong argument shape.
    #[error("{0}")]
    Language(String),
    /// A rule from design D§4.4's builtin table.
    #[error("{0}")]
    Invalid(#[from] Invalid),
    /// An evaluation bound.
    #[error("{0}")]
    Exhausted(#[from] Bound),
    /// The evaluator itself failed — a panic, a signal, or a child that never started. Our bug, not
    /// the author's, and deliberately detail-free: whatever it said is about our source, not theirs.
    ///
    /// It is also the fail-closed answer when the evaluation helper cannot be found
    /// ([`crate::sandbox::worker_path`]). Falling back to evaluating in this process would be worse
    /// than an error: it would be a memory bound that is not there.
    #[error("the pipeline evaluator failed unexpectedly")]
    Internal,
}

/// A pipeline that did not produce a DAG.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[error("{}: {kind}", location(*line))]
pub struct PlanError {
    /// 1-based line in `.hull/ci.star`, when the failure has a location at all. A budget that trips
    /// mid-loop does; a file-size rejection does not.
    pub line: Option<u32>,
    pub kind: PlanErrorKind,
}

fn location(line: Option<u32>) -> String {
    match line {
        Some(l) => format!("{}:{l}", crate::PIPELINE_PATH),
        None => crate::PIPELINE_PATH.to_string(),
    }
}

impl PlanError {
    pub fn new(kind: impl Into<PlanErrorKind>) -> Self {
        PlanError { line: None, kind: kind.into() }
    }

    pub fn at(line: Option<u32>, kind: impl Into<PlanErrorKind>) -> Self {
        PlanError { line, kind: kind.into() }
    }
}

/// Make a `starlark::Error` message safe to show to the pipeline's author.
///
/// starlark's own messages are developer-facing English about the *language*, which is exactly what
/// an author needs ("`while` is not supported", "Variable `open` not found"). What they must not
/// carry across the trust boundary is anything about *us*: a path, a backtrace, or a call stack.
/// The caller has already dropped the diagnostic; this is the belt to that pair of braces —
/// newlines collapse (a multi-line message is where a backtrace would hide), anything that looks
/// like an absolute host path is elided, and the whole thing is capped.
pub fn sanitize_message(raw: &str) -> String {
    const MAX: usize = 300;
    let mut out = String::with_capacity(raw.len().min(MAX));
    let mut last_space = false;
    for token in raw.split_whitespace() {
        // A token beginning with `/` or containing a Windows-style root is a filesystem path far
        // more often than it is prose, and no message we want to show needs one.
        let token = if token.starts_with('/') || token.contains(":\\") { "<path>" } else { token };
        if !out.is_empty() && !last_space {
            out.push(' ');
        }
        out.push_str(token);
        last_space = false;
        if out.chars().count() >= MAX {
            break;
        }
    }
    let cleaned: String = out.chars().filter(|c| !c.is_control()).take(MAX).collect();
    cleaned.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_never_carries_a_host_path_or_a_stack() {
        let hostile = "error at /Users/someone/hull-ci/crates/x.rs:12\n\
                       stack backtrace:\n   0: core::panicking\n   1: whatever";
        let clean = sanitize_message(hostile);
        assert!(!clean.contains("/Users/"), "an author must not learn our filesystem layout");
        assert!(!clean.contains('\n'), "one line, so a stack cannot render as one");
        assert!(clean.contains("<path>"));
    }

    #[test]
    fn a_message_is_capped() {
        assert!(sanitize_message(&"word ".repeat(5000)).chars().count() <= 300);
    }

    #[test]
    fn an_error_names_the_pipeline_file_and_the_line() {
        let e = PlanError::at(Some(7), Invalid::DuplicateName { name: "test".into() });
        assert_eq!(e.to_string(), ".hull/ci.star:7: duplicate step name `test`");
        let e = PlanError::new(Bound::SourceBytes { limit: 10 });
        assert_eq!(e.to_string(), ".hull/ci.star: pipeline file is larger than 10 bytes");
    }
}
