//! A pre-parse bound on how *nested* the source is, and why one is necessary.
//!
//! **This is not in design D§4.4, and it should be.** The design lists three evaluation bounds — a
//! step budget, a DAG depth cap, and starlark-rust's call-stack cap — and all three are bounds on
//! *evaluation*. Measured against `starlark` 0.14.2, none of them is reached by the cheapest attack
//! on this crate:
//!
//! ```text
//! x = [[[[[[ … ]]]]]]        # ~800 deep, ~1.6 KB of source
//! ```
//!
//! `AstModule::parse` is recursive descent, so nesting like that exhausts the thread's stack
//! **during parsing**, before a single builtin has run. A Rust stack overflow is not an error — it
//! hits the guard page and aborts the process. On the control plane that is a remote crash, from a
//! file in an untrusted tree, triggered before any of design D§4.4's bounds exist to be checked.
//! Raising the stack does not fix it either: bracket frames are expensive enough that 64 KiB of
//! source still overflows a 128 MiB stack. The bound has to come *before* the parser, which is what
//! this module is.
//!
//! It is deliberately **not a parser** — a second parser is a second thing to get wrong, and this
//! one runs before the real one on input we already distrust. It is a byte scan producing three
//! upper bounds, one per way of building a deep AST, plus a backstop:
//!
//! * [`Shape::code_nesting`] — bracket depth outside comments and string literals. The nesting an
//!   author actually wrote, and the rule they are told about.
//! * [`Shape::statement_weight`] — tokens in one statement. Brackets are not the only route: `x =
//!   ------…-1` and `x = 1+1+1+…` build the same depth with none, and `x = (1\n+1\n+1…)` slips past
//!   any per-*line* cap. AST depth is at most token count, so bounding tokens bounds depth.
//! * [`Shape::indent_columns`] — leading whitespace, which over-estimates block nesting.
//! * [`Shape::raw_nesting`] — every bracket byte in the file, string literals included. It has no
//!   string handling to get wrong, so a bug in the string skipping above (which could only make
//!   `code_nesting` too *low*) cannot get past it. Its limit is high enough that no honest pipeline
//!   reaches it and low enough that the parser survives.
//!
//! Two single passes over bytes. Every delimiter is ASCII and UTF-8 continuation bytes are all
//! ≥ 0x80, so scanning bytes cannot mistake part of a multi-byte character for a bracket.
//!
//! **The limits are measured, not guessed.** Against `starlark` 0.14.2 in a *debug* build (the
//! expensive one, and the one a developer runs the control plane in), the worst input these
//! defaults admit — a 1 024-token unary chain, 32-deep brackets, 32 KiB of either — parses,
//! compiles and evaluates in **under 32 MiB** of stack; the evaluation thread is given 128 MiB
//! ([`stack_bytes`](crate::Limits::stack_bytes)), a 4× margin. Halve `max_statement_weight` and the
//! requirement roughly halves with it, which is the knob to turn if that margin ever looks thin.

/// How nested a pipeline file is.
///
/// Three numbers, because there are three independent ways to build a deep AST and only the first
/// of them involves brackets:
///
/// | shape | example | bounded by |
/// |---|---|---|
/// | brackets | `x = [[[[…]]]]` | [`Shape::code_nesting`] |
/// | one enormous expression | `x = ----------…-1`, `x = 1+1+1+…` | [`Shape::statement_weight`] |
/// | indentation | 200 nested `if True:` | [`Shape::indent_columns`] |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    /// Maximum bracket depth outside comments and string literals.
    pub code_nesting: usize,
    /// Maximum bracket depth counting every byte in the file. Always ≥ [`Shape::code_nesting`].
    pub raw_nesting: usize,
    /// The largest single *statement*, weighed in code bytes.
    ///
    /// A statement, not a line: a newline inside brackets continues the statement, which is how
    /// `x = (1\n+1\n+1…)` would otherwise slip past a per-line cap. Whitespace and comments do not
    /// count, and **a whole string literal counts as one** — a 2 KB `run =` script is one token to
    /// the parser and must not be what trips a bound aimed at operator chains.
    pub statement_weight: usize,
    /// The deepest leading indentation, in columns. A cheap over-estimate of block nesting: each
    /// nested suite costs at least one column, so columns bound depth.
    pub indent_columns: usize,
    /// The longest run of `elif` branches at one indentation level.
    ///
    /// **The fourth way to build a deep AST, and the one the other three cannot see.** An `elif`
    /// chain nests the parser's recursion once per branch while adding no brackets, no indentation
    /// and no single large statement — so `code_nesting`, `indent_columns` and `statement_weight` all
    /// read flat at any depth. Found by audit: at a 1 MiB stack, fifty branches in 559 bytes aborted
    /// the process, and even at the default stack the only thing bounding it was `max_source_bytes`,
    /// a knob that reads as unrelated to stack safety.
    ///
    /// Counted per indentation column so that separate `if`/`elif` ladders elsewhere in the file do
    /// not add together — it is the depth of one chain that costs stack, not the total in the file.
    pub block_chain: usize,
}

/// Measure a pipeline file. Never fails: an unterminated string or an unbalanced bracket is the
/// parser's business to report, and this pass only needs an upper bound.
pub fn measure(source: &str) -> Shape {
    let bytes = source.as_bytes();
    let mut shape = scan(bytes);
    shape.raw_nesting = raw_nesting(bytes);
    shape
}

/// The backstop pass: every bracket byte in the file counts, strings and comments included. A bug
/// in [`skip_string`] can only make [`scan`] under-count, and this pass has no string handling to
/// get wrong.
fn raw_nesting(bytes: &[u8]) -> usize {
    let (mut depth, mut max) = (0usize, 0usize);
    for &b in bytes {
        match b {
            b'(' | b'[' | b'{' => {
                depth += 1;
                max = max.max(depth);
            }
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    max
}

fn scan(bytes: &[u8]) -> Shape {
    let mut shape =
        Shape { code_nesting: 0, raw_nesting: 0, statement_weight: 0, indent_columns: 0, block_chain: 0 };
    // Longest `elif` run seen at each indentation column, and the run currently open there.
    let mut chain_at: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    let mut depth: usize = 0;
    let mut weight: usize = 0;
    let mut at_line_start = true;
    let mut indent: usize = 0;
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];

        // Leading whitespace is measured, not weighed.
        if at_line_start && (b == b' ' || b == b'\t') {
            indent += 1;
            i += 1;
            continue;
        }
        // The first non-blank byte settles that line's indentation. A blank line has none to
        // record, hence the `\n` exclusion.
        if at_line_start && b != b'\n' {
            shape.indent_columns = shape.indent_columns.max(indent);
            // A keyword at column `indent` either extends the chain open there or starts a new one.
            // Anything else at that column ends it: the ladder is over.
            let rest = &bytes[i..];
            let entry = chain_at.entry(indent).or_insert(0);
            if rest.starts_with(b"elif") {
                *entry += 1;
                shape.block_chain = shape.block_chain.max(*entry);
            } else if rest.starts_with(b"if ") || rest.starts_with(b"if(") {
                *entry = 1;
                shape.block_chain = shape.block_chain.max(*entry);
            } else if !rest.starts_with(b"else") {
                *entry = 0;
            }
            at_line_start = false;
        }

        match b {
            b'#' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'"' | b'\'' => {
                // One literal, one unit of weight, however long it is.
                weight += 1;
                i = skip_string(bytes, i);
            }
            b'(' | b'[' | b'{' => {
                depth += 1;
                shape.code_nesting = shape.code_nesting.max(depth);
                weight += 1;
                i += 1;
            }
            b')' | b']' | b'}' => {
                depth = depth.saturating_sub(1);
                weight += 1;
                i += 1;
            }
            // A statement ends at a top-level newline or `;`. Inside brackets a newline is just
            // whitespace, so the statement — and its weight — carries on.
            b'\n' | b';' => {
                if depth == 0 && !(b == b'\n' && i > 0 && bytes[i - 1] == b'\\') {
                    shape.statement_weight = shape.statement_weight.max(weight);
                    weight = 0;
                }
                if b == b'\n' {
                    at_line_start = true;
                    indent = 0;
                }
                i += 1;
            }
            b' ' | b'\t' | b'\r' => i += 1,
            // A run of identifier/number bytes is one token, so `continue_on_error` weighs the same
            // as `x`. The bound is about how many *nodes* a statement can build, and a long name
            // builds one; charging per byte would make the cap a rule about naming style.
            b if b.is_ascii_alphanumeric() || b == b'_' || b == b'.' => {
                weight += 1;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'.')
                {
                    i += 1;
                }
            }
            _ => {
                weight += 1;
                i += 1;
            }
        }
    }
    shape.statement_weight = shape.statement_weight.max(weight);
    shape
}

/// Advance past the string literal starting at `start`. Returns the index just after it, or the end
/// of the input for an unterminated literal.
///
/// Handles triple quotes and backslash escapes. Raw strings (`r"…"`) are treated as escaped too: in
/// Starlark, as in Python, a backslash in a raw string still prevents the next quote from closing
/// it, so the *termination* rule is the same and that is all this scan needs.
fn skip_string(bytes: &[u8], start: usize) -> usize {
    let quote = bytes[start];
    let triple = bytes[start..].starts_with(&[quote, quote, quote]);
    let delim_len = if triple { 3 } else { 1 };
    let mut i = start + delim_len;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            // A single-quoted literal cannot span a line; stopping here keeps an unterminated
            // string from swallowing the rest of the file and hiding real nesting from the scan.
            b'\n' if !triple => return i,
            b if b == quote => {
                if !triple {
                    return i + 1;
                }
                if bytes[i..].starts_with(&[quote, quote, quote]) {
                    return i + 3;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_nesting_is_counted() {
        assert_eq!(measure("x = [[[1]]]").code_nesting, 3);
        assert_eq!(measure("f(g(h(1)))").code_nesting, 3);
        assert_eq!(measure("x = {'a': [1, {'b': 2}]}").code_nesting, 3);
        assert_eq!(measure("").code_nesting, 0);
        // Sequential, not nested.
        assert_eq!(measure("f(1)\ng(2)\nh(3)").code_nesting, 1);
    }

    #[test]
    fn brackets_inside_strings_and_comments_are_not_code_nesting() {
        let src = r#"
# [[[[[[[[
step("s", run = "find . -name '*.[ch]' | xargs grep '[[[['")
"#;
        assert_eq!(measure(src).code_nesting, 1, "only the `step(` call nests");
        assert!(measure(src).raw_nesting > 1, "the raw backstop still counts them");
    }

    #[test]
    fn triple_quoted_strings_are_skipped_whole() {
        let src = "x = \"\"\"\n[[[[[[\n'not a quote'\n\"\"\"\ny = [1]";
        assert_eq!(measure(src).code_nesting, 1);
    }

    #[test]
    fn escapes_do_not_end_a_string_early() {
        // If the `\"` were treated as a terminator, the `[[[` after it would count as code.
        assert_eq!(measure(r#"x = "a\"[[[b" "#).code_nesting, 0);
    }

    #[test]
    fn an_unterminated_string_cannot_hide_the_rest_of_the_file() {
        // The pathological case for a string-skipping scan: an attacker opens a quote and never
        // closes it, hoping the scanner swallows the payload. A single-quoted literal ends at the
        // newline, so it does not.
        let src = "x = \"oops\ny = [[[[[[[[1]]]]]]]]";
        assert_eq!(measure(src).code_nesting, 8);
    }

    #[test]
    fn the_raw_backstop_is_never_lower_than_the_code_count() {
        for src in ["", "[[[]]]", "# [[[", "\"[[[\"", "x = [1, [2, [3]]]", "'''[[['''"] {
            let s = measure(src);
            assert!(s.raw_nesting >= s.code_nesting, "{src:?}: {s:?}");
        }
    }

    #[test]
    fn unbalanced_closers_do_not_underflow() {
        assert_eq!(measure("]]]]]]]]]]]] [1]").code_nesting, 1);
    }

    #[test]
    fn statement_weight_counts_operators_not_prose() {
        // Each `-` is one AST level, and that is what the weight is a proxy for.
        assert_eq!(measure(&format!("x = {}1", "-".repeat(500))).statement_weight, 503);
        // Separate statements do not accumulate: they are siblings, not nested.
        assert_eq!(measure(&"x = 1\n".repeat(1000)).statement_weight, 3);
        // A long name is one token, not thirty. The bound is about AST nodes, not typing.
        assert_eq!(
            measure("continue_on_error = a_very_long_identifier_name").statement_weight,
            3
        );
        assert_eq!(measure("x = not not not True").statement_weight, 6);
    }

    #[test]
    fn a_long_run_string_is_one_token_not_two_thousand() {
        // The bound aims at operator chains. A legitimately long shell script in `run =` must sail
        // through it, or the cap would be a rule about how big your build command may be.
        let script = "echo hello && ".repeat(500);
        let src = format!("step(\"s\", run = \"{script}\")");
        assert!(src.len() > 7000);
        assert!(measure(&src).statement_weight < 20, "{:?}", measure(&src));

        // And a realistic pipeline statement is nowhere near the cap either.
        let real = r#"step("test-" + name, run = "cargo test --workspace", needs = [build], inputs = rust, shard = "auto", timeout = "20m", secrets = ["TEST_DB_URL"], continue_on_error = False)"#;
        assert!(measure(real).statement_weight < 50, "{:?}", measure(real));
    }

    #[test]
    fn a_newline_inside_brackets_does_not_end_the_statement() {
        // The obvious way round a per-line cap. One statement, ~1000 operators.
        let src = format!("x = (1{})", "\n+1".repeat(1000));
        assert!(measure(&src).statement_weight > 1000);
        // ...and the same characters split into real statements weigh nothing.
        let src = "x = 1\n".repeat(1000);
        assert!(measure(&src).statement_weight < 10);
    }

    #[test]
    fn backslash_continuation_does_not_end_the_statement_either() {
        let src = format!("x = 1{}", " \\\n+1".repeat(500));
        assert!(measure(&src).statement_weight > 500);
    }

    #[test]
    fn indentation_is_measured() {
        let mut src = String::new();
        for i in 0..50 {
            src.push_str(&"  ".repeat(i));
            src.push_str("if True:\n");
        }
        assert_eq!(measure(&src).indent_columns, 98);
        assert_eq!(measure("x = 1\ny = 2\n").indent_columns, 0);
    }
}
