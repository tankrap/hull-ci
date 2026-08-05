//! Output masking — **a backstop, not a control**.
//!
//! Read this before relying on anything in this module.
//!
//! D§7.4 is blunt about it: "log masking is exact-substring redaction and is **trivially evaded** by
//! base64/split/transform — GitHub says as much: redaction 'relies on finding an exact match' and
//! structured/encoded secrets slip through ([GitHub secure-use][gh]). So masking stops an accidental
//! `echo`; it is *not* what protects a secret from hostile code."
//!
//! Everything below is a byte-for-byte substring search. A job that wants its own secret in a log
//! defeats it in one line — `echo $TOKEN | base64`, `echo ${TOKEN:0:10}; echo ${TOKEN:10}`, `tr a-z
//! A-Z`, gzip it, XOR it, print it one character per line. There is no version of this module that
//! fixes that, because the job holds the plaintext and controls the encoding. Adding base64 and hex
//! variants (as GitHub does) raises the bar by one line of shell and is not a different kind of
//! defence; it is not implemented here precisely so that nobody reads a long list of encodings and
//! concludes the problem is handled.
//!
//! **What actually protects a secret from hostile code is that hostile code never receives it** —
//! the author-class gate in [`crate::broker::SecretBroker::mint`]. Masking exists for the honest
//! case: a member's own pipeline that prints its environment while debugging, a test harness that
//! dumps config on failure, a stack trace with a URL in it. That case is common, and catching it is
//! worth doing. It is just not a security boundary, and no operator should be told it is one.
//!
//! [gh]: https://docs.github.com/en/actions/reference/security/secure-use

use zeroize::Zeroizing;

/// What a redacted value is replaced with.
pub const MASK: &str = "***";

/// Values shorter than this are refused registration.
///
/// Masking a 2-character value would redact those two characters everywhere they occur, turning the
/// log into confetti and destroying far more information than it protects — and a 2-character secret
/// has no meaningful entropy to protect in the first place. Refusing is better than silently not
/// masking, because a caller who registers a short value and sees no error would reasonably assume
/// it was covered.
pub const MIN_MASKABLE_LEN: usize = 6;

/// Redacts known secret values from captured output.
///
/// Values are held in a [`Zeroizing`] buffer and wiped when the masker drops — a masker outlives the
/// step whose output it filters, so it is one of the longer-lived plaintext copies in the system.
#[derive(Default)]
pub struct Masker {
    /// Sorted longest-first. Order matters: if one secret is a substring of another (a base URL and
    /// the same URL with a token appended, say), masking the short one first would leave the long
    /// one partially visible and unmatched.
    values: Vec<Zeroizing<Vec<u8>>>,
}

/// Hand-written, because a derived `Debug` over the value list would print every registered secret
/// in full — turning the type whose entire job is keeping secrets out of logs into the thing that
/// puts them there.
impl std::fmt::Debug for Masker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Masker({} value(s), <redacted>)", self.values.len())
    }
}

impl Masker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a value. Returns `false` if it was too short to mask safely (see
    /// [`MIN_MASKABLE_LEN`]) — the caller decides whether that is worth a warning.
    pub fn register(&mut self, value: &[u8]) -> bool {
        if value.len() < MIN_MASKABLE_LEN {
            return false;
        }
        if self.values.iter().any(|v| v.as_slice() == value) {
            return true;
        }
        self.values.push(Zeroizing::new(value.to_vec()));
        self.values.sort_by_key(|v| std::cmp::Reverse(v.len()));
        true
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// The longest registered value.
    ///
    /// A streaming log shipper needs this: it must keep the last `longest_value() - 1` bytes of each
    /// chunk as overlap, or a secret straddling a chunk boundary passes through unmasked. That is a
    /// *different* failure from the encoding bypass above — it is one this module's callers can and
    /// should fix.
    pub fn longest_value(&self) -> usize {
        self.values.first().map(|v| v.len()).unwrap_or(0)
    }

    /// Redact every registered value from `bytes`.
    pub fn mask_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        let mut current = bytes.to_vec();
        for value in &self.values {
            current = replace_all(&current, value, MASK.as_bytes());
        }
        current
    }

    /// Redact every registered value from `text`.
    ///
    /// UTF-8 is self-synchronising, so a valid UTF-8 needle can only ever match at a character
    /// boundary of a valid UTF-8 haystack — the byte-level replacement below therefore cannot split
    /// a character, and the result is always valid UTF-8.
    pub fn mask(&self, text: &str) -> String {
        String::from_utf8(self.mask_bytes(text.as_bytes()))
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
    }
}

/// Byte-level search and replace. Deliberately the simplest thing that works: this runs over every
/// byte of every log line, and a clever matcher would be a new place for a bug that leaks output.
fn replace_all(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if i + needle.len() <= haystack.len() && &haystack[i..i + needle.len()] == needle {
            out.extend_from_slice(replacement);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masker(values: &[&str]) -> Masker {
        let mut m = Masker::new();
        for v in values {
            assert!(m.register(v.as_bytes()), "{v} should be maskable");
        }
        m
    }

    #[test]
    fn a_known_value_is_redacted() {
        let m = masker(&["npm_s3cr3tvalue"]);
        assert_eq!(m.mask("token is npm_s3cr3tvalue here"), "token is *** here");
        // Every occurrence, not just the first.
        assert_eq!(m.mask("npm_s3cr3tvalue npm_s3cr3tvalue"), "*** ***");
    }

    #[test]
    fn overlapping_values_mask_longest_first() {
        // `https://registry/` and `https://registry/?token=abcdef` — masking the shorter one first
        // would leave `***?token=abcdef` with the token intact.
        let m = masker(&["https://registry/", "https://registry/?token=abcdef"]);
        assert_eq!(m.mask("GET https://registry/?token=abcdef"), "GET ***");
    }

    #[test]
    fn short_values_are_refused_rather_than_silently_unmasked() {
        let mut m = Masker::new();
        assert!(!m.register(b"ab"), "a 2-byte value would redact the whole log");
        assert!(m.is_empty());
        assert_eq!(m.mask("ab ab ab"), "ab ab ab");
    }

    #[test]
    fn masking_is_byte_exact_and_binary_safe() {
        let m = masker(&["s3cr3tvalue"]);
        let mut log = b"prefix\x00\xff".to_vec();
        log.extend_from_slice(b"s3cr3tvalue");
        let masked = m.mask_bytes(&log);
        assert!(!masked.windows(11).any(|w| w == b"s3cr3tvalue"));
        assert!(masked.starts_with(b"prefix\x00\xff"), "non-UTF-8 bytes must survive untouched");
    }

    /// **This test documents a bypass. It is not a bug to be fixed here.**
    ///
    /// Every case below is a one-line transform any job can apply to a value it already holds in its
    /// own environment. They pass through masking untouched, and that is exactly the point of
    /// D§7.4's "masking is a backstop, not a control": the control that stops these is the
    /// author-class gate, which never gave hostile code the value to transform.
    #[test]
    fn masking_is_trivially_defeated_by_encoding_and_splitting() {
        let secret = "npm_s3cr3tvalue";
        let m = masker(&[secret]);

        // 1. Split across two prints (`echo ${T:0:7}; echo ${T:7}`).
        let split = format!("{} {}", &secret[..7], &secret[7..]);
        assert!(m.mask(&split).contains("npm_s3c"), "a split value is not matched");

        // 2. Case transform (`tr a-z A-Z`).
        assert_eq!(m.mask(&secret.to_uppercase()), secret.to_uppercase());

        // 3. Any encoding at all — hex stands in for base64, gzip, or a XOR the job invents.
        let encoded = hex::encode(secret);
        assert_eq!(m.mask(&encoded), encoded, "an encoded value is not matched");

        // 4. One character per line.
        let spelled: String = secret.chars().map(|c| format!("{c}\n")).collect();
        assert!(m.mask(&spelled).contains('n'), "a spelled-out value is not matched");

        // The honest case — the one masking is actually for — still works.
        assert_eq!(m.mask(&format!("NPM_TOKEN={secret}")), "NPM_TOKEN=***");
    }

    #[test]
    fn a_streaming_caller_is_told_how_much_overlap_it_needs() {
        let m = masker(&["npm_s3cr3tvalue"]);
        assert_eq!(m.longest_value(), 15);
        // The failure the accessor exists to prevent: chunked output splits the value and neither
        // half matches.
        let (a, b) = ("...npm_s3c", "r3tvalue...");
        assert_eq!(format!("{}{}", m.mask(a), m.mask(b)), "...npm_s3cr3tvalue...");
        // With the overlap the caller is told to keep, the whole value is in one buffer and matches.
        assert_eq!(m.mask(&format!("{a}{b}")), "...***...");
    }

    #[test]
    fn the_masker_does_not_leak_its_values_through_debug() {
        let m = masker(&["npm_s3cr3tvalue"]);
        let rendered = format!("{m:?}");
        assert!(!rendered.contains("npm_s3cr3tvalue"));
        assert_eq!(rendered, "Masker(1 value(s), <redacted>)");
    }

    #[test]
    fn registering_the_same_value_twice_is_a_no_op() {
        let mut m = Masker::new();
        assert!(m.register(b"s3cr3tvalue"));
        assert!(m.register(b"s3cr3tvalue"));
        assert_eq!(m.mask("s3cr3tvalue"), "***", "not `******`");
    }
}
