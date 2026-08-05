//! Bounded capture of job output.
//!
//! Spec §14.4: "Cap captured output so a job can't OOM the runner by flooding logs." Design D§7.1
//! fixes the numbers — 50 MB / 500k lines per step, "beyond it, truncate with a marker and keep the
//! tail. A job must not be able to OOM or bankrupt us by printing."
//!
//! Two decisions worth stating, because both are security properties rather than ergonomics:
//!
//! - **We keep the tail, not the head.** A failing suite prints its verdict last, and an attacker who
//!   wanted to bury it would flood *before* the interesting bytes. Keeping the tail costs nothing and
//!   defeats that; a marker records exactly how much we dropped so the truncation is never silent.
//! - **We hold bytes, not `String`.** Job output is untrusted data (§14.5) and is not required to be
//!   UTF-8. Decoding happens at the edge ([`CapturedOutput::text`]), lossily, and anything destined
//!   for a summary goes through `hull_ci_proto::sanitize_summary` on top of that.
//!
//! Memory is bounded by `max_bytes + slack` at all times: we trim on a slack overshoot rather than on
//! every write, which keeps trimming amortised O(1) per byte without ever letting the buffer grow
//! proportional to what the job printed.

/// Design D§7.1 default byte cap for one step's captured output.
pub const DEFAULT_MAX_BYTES: usize = 50 * 1024 * 1024;

/// Design D§7.1 default line cap for one step's captured output.
pub const DEFAULT_MAX_LINES: usize = 500_000;

/// The per-step output budget (§14.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputCaps {
    pub max_bytes: usize,
    pub max_lines: usize,
}

impl Default for OutputCaps {
    fn default() -> Self {
        OutputCaps { max_bytes: DEFAULT_MAX_BYTES, max_lines: DEFAULT_MAX_LINES }
    }
}

impl OutputCaps {
    pub fn new(max_bytes: usize, max_lines: usize) -> Self {
        OutputCaps { max_bytes, max_lines }
    }

    /// How far over the cap we let the buffer run before trimming.
    ///
    /// Trimming drops from the front of a `Vec`, which is O(n); trimming only once per slack-sized
    /// overshoot makes the amortised cost O(1) per byte while capping peak memory at
    /// `max_bytes + slack`.
    fn byte_slack(&self) -> usize {
        (self.max_bytes / 8).max(64 * 1024)
    }

    fn line_slack(&self) -> usize {
        (self.max_lines / 8).max(1024)
    }
}

/// A write sink that never grows past its budget.
#[derive(Debug)]
pub struct OutputCapture {
    caps: OutputCaps,
    buf: Vec<u8>,
    /// `\n` count currently in `buf`. A trailing unterminated line is not counted; it becomes a line
    /// only once it is terminated, which keeps the count monotone under chunked writes.
    lines: usize,
    dropped_bytes: u64,
    dropped_lines: u64,
}

impl OutputCapture {
    pub fn new(caps: OutputCaps) -> Self {
        OutputCapture { caps, buf: Vec::new(), lines: 0, dropped_bytes: 0, dropped_lines: 0 }
    }

    pub fn caps(&self) -> OutputCaps {
        self.caps
    }

    /// Append a chunk read from the job. Never fails and never allocates unboundedly.
    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
        self.lines += count_newlines(chunk);
        if self.buf.len() > self.caps.max_bytes.saturating_add(self.caps.byte_slack())
            || self.lines > self.caps.max_lines.saturating_add(self.caps.line_slack())
        {
            self.trim();
        }
    }

    /// Bytes currently retained. Exposed for tests and for progress reporting.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Drop from the front until both caps hold, always cutting on a line boundary so we never emit
    /// half a line (a half-line is exactly the shape that makes truncated logs misread).
    fn trim(&mut self) {
        let mut cut = 0usize;

        if self.buf.len() > self.caps.max_bytes {
            cut = self.buf.len() - self.caps.max_bytes;
            cut = match self.buf[cut..].iter().position(|b| *b == b'\n') {
                Some(off) => cut + off + 1,
                // No line boundary in the retained window: the job is printing one enormous line, so
                // the honest thing is to drop all of it rather than keep a meaningless fragment.
                None => self.buf.len(),
            };
        }

        let lines_after = count_newlines(&self.buf[cut..]);
        if lines_after > self.caps.max_lines {
            let mut excess = lines_after - self.caps.max_lines;
            for (i, b) in self.buf[cut..].iter().enumerate() {
                if *b == b'\n' {
                    excess -= 1;
                    if excess == 0 {
                        cut += i + 1;
                        break;
                    }
                }
            }
        }

        if cut == 0 {
            return;
        }
        let dropped_lines = count_newlines(&self.buf[..cut]);
        self.dropped_bytes += cut as u64;
        self.dropped_lines += dropped_lines as u64;
        self.lines -= dropped_lines;
        self.buf.drain(..cut);
    }

    /// Seal the capture, enforcing the caps exactly (the running buffer is allowed slack; the result
    /// is not).
    pub fn finish(mut self) -> CapturedOutput {
        self.trim();
        CapturedOutput {
            bytes: self.buf,
            dropped_bytes: self.dropped_bytes,
            dropped_lines: self.dropped_lines,
            caps: self.caps,
        }
    }
}

fn count_newlines(b: &[u8]) -> usize {
    b.iter().filter(|c| **c == b'\n').count()
}

/// A sealed, capped capture. Everything in `bytes` is untrusted job output (§14.5).
#[derive(Debug, Clone)]
pub struct CapturedOutput {
    bytes: Vec<u8>,
    dropped_bytes: u64,
    dropped_lines: u64,
    caps: OutputCaps,
}

impl CapturedOutput {
    /// An empty capture, for the paths where a sandbox died before producing anything.
    pub fn empty(caps: OutputCaps) -> Self {
        CapturedOutput { bytes: Vec::new(), dropped_bytes: 0, dropped_lines: 0, caps }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn truncated(&self) -> bool {
        self.dropped_bytes > 0
    }

    pub fn dropped_bytes(&self) -> u64 {
        self.dropped_bytes
    }

    pub fn dropped_lines(&self) -> u64 {
        self.dropped_lines
    }

    /// The marker that makes truncation visible rather than silent (§14.4, D§7.1).
    pub fn marker(&self) -> Option<String> {
        if !self.truncated() {
            return None;
        }
        Some(format!(
            "[hull-ci] output truncated: dropped {} bytes / {} lines to stay under the {} byte / {} line cap (spec §14.4); the tail follows.",
            self.dropped_bytes, self.dropped_lines, self.caps.max_bytes, self.caps.max_lines
        ))
    }

    /// The capture as text, marker first. Lossy by construction: job output need not be UTF-8, and
    /// refusing to decode it would just mean losing the log.
    pub fn text(&self) -> String {
        let body = String::from_utf8_lossy(&self.bytes);
        match self.marker() {
            Some(m) => format!("{m}\n{body}"),
            None => body.into_owned(),
        }
    }

    /// The last `max_chars` characters, for building a one-line summary. Still untrusted — the caller
    /// must run this through `hull_ci_proto::sanitize_summary` before it reaches a `Verdict`.
    pub fn tail_text(&self, max_chars: usize) -> String {
        let body = String::from_utf8_lossy(&self.bytes);
        let n = body.chars().count();
        if n <= max_chars {
            return body.into_owned();
        }
        body.chars().skip(n - max_chars).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_under_the_cap_is_verbatim() {
        let mut c = OutputCapture::new(OutputCaps::new(1024, 100));
        c.push(b"hello\nworld\n");
        let out = c.finish();
        assert!(!out.truncated());
        assert_eq!(out.bytes(), b"hello\nworld\n");
        assert!(out.marker().is_none());
    }

    #[test]
    fn byte_cap_truncates_and_keeps_the_tail() {
        // §14.4: a job must not be able to OOM us by printing.
        let caps = OutputCaps::new(256, 1_000_000);
        let mut c = OutputCapture::new(caps);
        for i in 0..10_000 {
            c.push(format!("line {i}\n").as_bytes());
        }
        assert!(
            c.len() <= caps.max_bytes + caps.byte_slack(),
            "running buffer must stay bounded, not grow with what the job printed"
        );
        let out = c.finish();
        assert!(out.truncated());
        assert!(out.bytes().len() <= 256);
        let text = String::from_utf8_lossy(out.bytes()).into_owned();
        assert!(text.contains("line 9999\n"), "the tail is what we keep");
        assert!(!text.contains("line 0\n"), "the head is what we drop");
        assert!(text.starts_with("line "), "we always cut on a line boundary");
        assert!(out.marker().unwrap().contains("truncated"));
        assert!(out.text().starts_with("[hull-ci] output truncated"));
    }

    #[test]
    fn line_cap_truncates_independently_of_the_byte_cap() {
        // Tiny lines: the byte cap would never fire, so only the line cap protects the log shipper.
        let mut c = OutputCapture::new(OutputCaps::new(usize::MAX / 2, 10));
        for _ in 0..5_000 {
            c.push(b"x\n");
        }
        let out = c.finish();
        assert!(out.truncated());
        assert_eq!(out.bytes().iter().filter(|b| **b == b'\n').count(), 10);
        assert_eq!(out.dropped_lines(), 4_990);
    }

    #[test]
    fn one_enormous_line_cannot_defeat_the_cap() {
        // A job that prints 10 MB with no newline: there is no line boundary to cut on, so the
        // fallback must still bound memory rather than keeping the whole blob.
        let mut c = OutputCapture::new(OutputCaps::new(1024, 100));
        c.push(&vec![b'A'; 10 * 1024 * 1024]);
        let out = c.finish();
        assert!(out.bytes().len() <= 1024);
        assert!(out.truncated());
    }

    #[test]
    fn chunk_boundaries_do_not_change_the_result() {
        let mut whole = OutputCapture::new(OutputCaps::new(64, 100));
        whole.push(b"aaaa\nbbbb\ncccc\ndddd\neeee\nffff\ngggg\nhhhh\niiii\njjjj\n");
        let mut split = OutputCapture::new(OutputCaps::new(64, 100));
        for b in b"aaaa\nbbbb\ncccc\ndddd\neeee\nffff\ngggg\nhhhh\niiii\njjjj\n" {
            split.push(&[*b]);
        }
        assert_eq!(whole.finish().bytes(), split.finish().bytes());
    }

    #[test]
    fn tail_text_bounds_the_summary_source() {
        let mut c = OutputCapture::new(OutputCaps::default());
        c.push("z".repeat(5_000).as_bytes());
        let out = c.finish();
        assert_eq!(out.tail_text(200).chars().count(), 200);
    }

    #[test]
    fn non_utf8_output_does_not_lose_the_log() {
        let mut c = OutputCapture::new(OutputCaps::default());
        c.push(&[0xff, 0xfe, b'o', b'k']);
        let out = c.finish();
        assert!(out.text().contains("ok"));
    }
}
