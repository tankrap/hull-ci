//! The filesystem write-ahead journal, and the recovery pass that drains it at startup.
//!
//! [`hull_ci_control::Journal`] is the seam; this is the one real implementation. It lives here
//! rather than in the control plane for the reason that crate's own docs give: the control plane
//! parses JSON and nothing else, because it holds the CI shared secret and spec §14.1 forbids job code
//! anywhere near it. Opening files is this crate's business.
//!
//! # What is on disk
//!
//! One small JSON file per outstanding job, under `{HULL_CI_STORE_ROOT}/journal/`, named
//! `{job_id}.json`. No index, no log, no compaction: the set of files *is* the set of debts, so
//! "which jobs do we owe an answer for" is a directory listing and "this one is paid" is an unlink.
//! There is nothing to replay in order and nothing that can disagree with itself.
//!
//! # The two properties that make it worth having
//!
//! **Writes are atomic.** Write to a temp file in the *same directory*, fsync it, then rename over the
//! target. `rename(2)` within a directory is atomic on every filesystem this runs on, so a reader
//! sees either the previous entry or the new one and never a half-written one. Same directory
//! matters: a rename across filesystems is a copy, which is not atomic and would reintroduce exactly
//! the torn read the fsync was for.
//!
//! **A corrupt entry costs one job, not the recovery.** [`FileJournal::outstanding`] skips anything it
//! cannot read or parse, with a warning naming the file. See the comment there for why that is the
//! right trade rather than the lenient one.
//!
//! # The recovery pass
//!
//! [`recover`] runs once at startup, before the process serves, and answers every entry. It is what
//! turns a durable record into an unwedged tree — see [`hull_ci_control::journal`] for why anything at
//! all is better than silence, and spec §10 for Hull's half of it.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hull_ci_control::callback::{deliver, CallbackRequest, CallbackTransport, RetryPolicy};
use hull_ci_control::{JobIntent, Journal, JournalError};
use hull_ci_proto::{sanitize_summary, Reason, Verdict, SUMMARY_MAX_CHARS};

/// The subdirectory of `HULL_CI_STORE_ROOT` the journal owns.
///
/// A directory of its own rather than files beside the content store's, because the two have opposite
/// lifetimes: the content store is a cache whose entries may be dropped whenever space is wanted, and
/// every file here is an unanswered dispatch. Anything that sweeps one must not be able to reach the
/// other by accident.
pub const JOURNAL_DIR: &str = "journal";

/// One JSON file per outstanding job, under a directory of its own.
pub struct FileJournal {
    dir: PathBuf,
    /// Makes temp-file names unique within this process, so two threads recording two jobs at the
    /// same instant cannot pick the same scratch path and have one rename the other's half-written
    /// bytes into place.
    seq: AtomicU64,
}

impl FileJournal {
    /// Open (creating if needed) the journal under `store_root`.
    ///
    /// Fails rather than degrading to a no-op journal: a runner configured for durability that
    /// silently ran without it would be the worst of both worlds — the operator believes in-flight
    /// jobs survive a restart, and they do not.
    pub fn open(store_root: &Path) -> Result<FileJournal, JournalError> {
        let dir = store_root.join(JOURNAL_DIR);
        std::fs::create_dir_all(&dir).map_err(|e| JournalError::Write {
            job_id: "-".into(),
            detail: format!("could not create {}: {e}", dir.display()),
        })?;
        Ok(FileJournal { dir, seq: AtomicU64::new(0) })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The path one job's entry lives at, or an error if `job_id` is not a name.
    ///
    /// **`job_id` is validated before it becomes a path component.** It is minted by
    /// [`hull_ci_control::ids`] as hex today, so nothing hostile can reach here now — but a filename
    /// derived from a string is a path whatever the string's provenance, and the check that stops
    /// `../../etc/cron.d/x` from being an "entry" costs one call. [`check_path_segment`] is the rule
    /// this codebase already uses for exactly this (`repo`, `log_key`), and reusing it is the point:
    /// a traversal one caller refuses and another permits is a traversal.
    ///
    /// [`check_path_segment`]: hull_ci_proto::check_path_segment
    fn entry_path(&self, job_id: &str) -> Result<PathBuf, JournalError> {
        hull_ci_proto::check_path_segment(job_id).map_err(|why| JournalError::Write {
            job_id: sanitize_summary(job_id, 80),
            detail: format!("not a usable file name: {why}"),
        })?;
        Ok(self.dir.join(format!("{job_id}.json")))
    }

    /// Write `bytes` to `target` so that a reader sees all of it or none of it.
    ///
    /// Temp file in the same directory → fsync the file → rename. The fsync is before the rename, not
    /// after: rename is what publishes the name, so publishing before the bytes are durable is exactly
    /// the window where a power loss leaves a present-but-empty entry — which
    /// [`FileJournal::outstanding`] would then skip as corrupt, turning a job we promised to answer
    /// into one we silently forgot.
    fn write_atomically(&self, target: &Path, bytes: &[u8], job_id: &str) -> Result<(), JournalError> {
        use std::io::Write;

        let fail = |detail: String| JournalError::Write { job_id: job_id.to_string(), detail };
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let tmp = self.dir.join(format!(".{job_id}.{}.{n}.tmp", std::process::id()));

        let mut file = std::fs::File::create(&tmp).map_err(|e| fail(e.to_string()))?;
        let written = file
            .write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| fail(e.to_string()));
        drop(file);
        if let Err(e) = written {
            // Leaving scratch behind would accumulate one file per failed write forever. It is not an
            // entry — the dot prefix and the `.tmp` suffix keep it out of `outstanding` either way —
            // but a directory that only grows is its own outage.
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }

        std::fs::rename(&tmp, target).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            fail(format!("could not publish {}: {e}", target.display()))
        })
    }
}

impl Journal for FileJournal {
    fn record(&self, intent: &JobIntent) -> Result<(), JournalError> {
        let path = self.entry_path(&intent.job_id)?;
        let bytes = serde_json::to_vec(intent).map_err(|e| JournalError::Write {
            job_id: intent.job_id.clone(),
            detail: e.to_string(),
        })?;
        self.write_atomically(&path, &bytes, &intent.job_id)
    }

    fn forget(&self, job_id: &str) {
        // Infallible by contract (see the trait). A failed unlink leaves a stale entry, which costs
        // one duplicate callback on the next start — and spec §10 makes the callback idempotent, so
        // that is a log line rather than a problem. A missing file is not even that: `forget` is
        // reached on every delivered job, including ones whose entry never existed because the
        // deployment runs `NoJournal`-era state.
        let Ok(path) = self.entry_path(job_id) else {
            tracing::warn!(job_id = %sanitize_summary(job_id, 80), "refusing to unlink an unusable journal name");
            return;
        };
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(
                %job_id, error = %e,
                "could not drop a paid journal entry; the next start will re-send its verdict once"
            ),
        }
    }

    fn outstanding(&self) -> Result<Vec<JobIntent>, JournalError> {
        let entries = std::fs::read_dir(&self.dir).map_err(|e| JournalError::Read {
            detail: format!("could not list {}: {e}", self.dir.display()),
        })?;

        let mut out = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                // One unreadable directory entry, skipped for the same reason a corrupt file is: this
                // is the startup path, and every entry we fail to read is a tree that stays wedged.
                Err(e) => {
                    tracing::warn!(error = %e, "skipping an unreadable journal directory entry");
                    continue;
                }
            };
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                // Scratch from an interrupted `write_atomically`, or something an operator dropped in
                // here. Not an entry, and never was — the rename is what makes an entry.
                continue;
            }
            // **A corrupt or partial file is skipped, not fatal**, and this is the load-bearing
            // decision in the whole module. `outstanding` runs once, at startup, over every debt the
            // system has; returning `Err` for the first unparseable byte would mean one truncated
            // file — a disk that filled at the wrong moment, a botched manual edit — leaves *every*
            // other accepted job unanswered, and each of those is a tree Hull will not re-check
            // without a human (spec §10). Skipping costs exactly the one job whose record we lost,
            // which is the smallest blast radius available. It is warned about, loudly, because a
            // silent skip here is indistinguishable from having had nothing to do.
            match std::fs::read(&path).map_err(|e| e.to_string()).and_then(|bytes| {
                serde_json::from_slice::<JobIntent>(&bytes).map_err(|e| e.to_string())
            }) {
                Ok(intent) => out.push(intent),
                Err(detail) => tracing::warn!(
                    file = %path.display(), error = %detail,
                    "skipping an unreadable journal entry — this job will not be answered"
                ),
            }
        }
        Ok(out)
    }
}

/// Answer every outstanding entry, then forget the ones that landed. Runs once, before serving.
///
/// This is the payoff for everything else in this module. Design D§4.1 makes the ack mean "durably
/// ours"; spec §10 makes Hull's in-flight set clearable only by our callback. A job that was accepted
/// and never answered is therefore not late, it is stuck — and the tree stays unverified until a human
/// forces a rerun. Sending *something* for each entry is what unsticks it.
///
/// What gets sent:
///
/// * `verdict: Some(v)` → **`v`**. Only the delivery failed; the verdict itself is the true answer and
///   re-sending it is the whole reason a decided-but-undelivered entry survives.
/// * `verdict: None` → `errored` with [`Reason::Infra`]. Spec §7 makes `errored` the honest answer for
///   "we could not produce a verdict", and — critically — Hull does **not** memoize it, so a restart
///   costs a re-check rather than poisoning the tree with a `green`/`red` nobody computed.
///
/// Re-delivery is safe: spec §10 says the callback is idempotent and §9 makes a duplicate an explicit
/// re-affirmation. So a crash between a successful POST and the unlink below costs one duplicate
/// callback on the next start, which is a cost we take on purpose — the other ordering (forget first,
/// then send) would lose the debt entirely if the send never happened.
///
/// A failure to deliver **keeps** the entry and does not stop startup. The runner has jobs to serve,
/// and an entry that survives is one the next start will try again; refusing to boot because Hull is
/// unreachable would take the runner down for the duration of Hull's outage.
///
/// This pass is not the only retry, and must not be read as one. Once the runner is serving,
/// `hull_ci_control::Control::drain_undelivered` retries a parked verdict whenever a later dispatch
/// arrives, so an unreachable Hull that comes back does not need a restart to be told what happened.
/// What is left to *this* pass is the debt the running process cannot see: a job it crashed on, and a
/// job its bounded store had to give up.
pub async fn recover(
    journal: &dyn Journal,
    transport: &dyn CallbackTransport,
    secret: Option<&str>,
    retry: &RetryPolicy,
) {
    let entries = match journal.outstanding() {
        Ok(e) => e,
        Err(e) => {
            // Not fatal, for the same reason a single corrupt entry is not: the runner still works,
            // and refusing to start would turn a bookkeeping problem into a total outage.
            tracing::error!(error = %e, "could not read the journal; in-flight jobs from the last run stay unanswered");
            return;
        }
    };
    if entries.is_empty() {
        return;
    }

    tracing::info!(
        jobs = entries.len(),
        "recovering jobs the last run never answered (spec §10: Hull does not poll us, so silence wedges the tree)"
    );

    let mut answered = 0usize;
    for intent in entries {
        let verdict = match &intent.verdict {
            // The true answer. Only its delivery failed.
            Some(v) => v.clone(),
            // Sanitized like every other summary (spec §14.5). This one is ours rather than a job's,
            // but the rule is about the field, not about who wrote it — and a summary that is only
            // sanitized on some paths is a summary nobody can reason about.
            None => Verdict::errored(
                Reason::Infra,
                sanitize_summary(
                    "the runner restarted before this job produced a verdict",
                    SUMMARY_MAX_CHARS,
                ),
            ),
        };

        let mut delivered_anywhere = false;
        for url in &intent.callback_urls {
            let req = CallbackRequest {
                // Verbatim, as it arrived (spec §5) — a round trip through a JSON file does not make
                // it ours to normalize.
                url: url.clone(),
                secret: secret.map(str::to_string),
                verdict: verdict.clone(),
                job_id: intent.job_id.clone(),
            };
            delivered_anywhere |= deliver(transport, &req, retry).await.is_delivered();
        }

        if delivered_anywhere {
            // Only now. See the note above about the one duplicate a crash here can cost.
            journal.forget(&intent.job_id);
            answered += 1;
            tracing::info!(
                job_id = %intent.job_id, repo = %intent.repo, tree_id = %intent.tree_id,
                status = verdict.status.as_str(),
                "answered a job stranded by the last run"
            );
        } else {
            tracing::error!(
                alert = true,
                job_id = %intent.job_id, repo = %intent.repo, tree_id = %intent.tree_id,
                "could not answer a stranded job — its entry is kept and the next start will retry"
            );
        }
    }

    tracing::info!(recovered = answered, "journal recovery finished");
}

/// The retry budget the recovery pass uses.
///
/// Deliberately shorter than [`RetryPolicy::default`]: this runs *before the runner serves*, and the
/// default schedule is roughly an hour per destination against an unreachable Hull. Spending that at
/// boot would turn one unreachable Hull into a runner that never comes up — while the entries it is
/// retrying are exactly the ones designed to survive to the next start. Try briefly, keep what did not
/// land, get on with serving.
pub fn recovery_retry() -> RetryPolicy {
    RetryPolicy { base: Duration::from_millis(250), max_delay: Duration::from_secs(2), max_attempts: 3 }
}

/// Choose a journal for this deployment: the real one, or the one that remembers nothing.
///
/// A refusal to open the journal is a startup error rather than a fallback, and that is the same rule
/// [`crate::config::SandboxChoice`] follows: an operator who asked for durability must not silently get
/// a runner without it. Falling back would leave them believing in-flight jobs survive a restart.
pub fn assemble(config: &crate::config::Config) -> Result<Arc<dyn Journal>, JournalError> {
    if !config.journal {
        return Ok(Arc::new(hull_ci_control::NoJournal));
    }
    let journal = FileJournal::open(&config.store_root)?;
    tracing::info!(
        dir = %journal.dir().display(),
        "write-ahead journal on: every accepted dispatch is answered, across a restart"
    );
    Ok(Arc::new(journal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hull_ci_control::callback::{BoxFuture, CallbackResponse, TransportError};
    use hull_ci_proto::Status;
    use std::sync::Mutex;

    // ── Fakes ────────────────────────────────────────────────────────────────────────────────────

    /// Records what was sent and answers with a fixed status.
    struct SpyTransport {
        status: u16,
        seen: Mutex<Vec<CallbackRequest>>,
    }

    impl SpyTransport {
        fn new(status: u16) -> Arc<Self> {
            Arc::new(SpyTransport { status, seen: Mutex::new(Vec::new()) })
        }
        fn seen(&self) -> Vec<CallbackRequest> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl CallbackTransport for SpyTransport {
        fn post<'a>(
            &'a self,
            req: &'a CallbackRequest,
        ) -> BoxFuture<'a, Result<CallbackResponse, TransportError>> {
            Box::pin(async move {
                self.seen.lock().unwrap().push(req.clone());
                Ok(CallbackResponse { status: self.status })
            })
        }
    }

    fn intent(job_id: &str) -> JobIntent {
        JobIntent {
            job_id: job_id.into(),
            repo: "acme/widget".into(),
            tree_id: "tree1".into(),
            callback_urls: vec!["https://hull.example/ci-result".into()],
            accepted_at_unix: 1_700_000_000,
            verdict: None,
        }
    }

    fn journal() -> (tempfile::TempDir, FileJournal) {
        let dir = tempfile::tempdir().unwrap();
        let j = FileJournal::open(dir.path()).unwrap();
        (dir, j)
    }

    /// No wall-clock cost; the schedule itself is tested in `hull-ci-control`.
    fn fast() -> RetryPolicy {
        RetryPolicy { base: Duration::ZERO, max_delay: Duration::ZERO, max_attempts: 2 }
    }

    // ── The file format ──────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_entry_round_trips_and_disappears_when_it_is_forgotten() {
        let (_d, j) = journal();
        j.record(&intent("job_0000000000000001")).unwrap();
        let out = j.outstanding().unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], intent("job_0000000000000001"));

        j.forget("job_0000000000000001");
        assert!(j.outstanding().unwrap().is_empty(), "a paid debt leaves nothing behind");
        // And forgetting twice is not an error: `forget` runs on every delivered job, including ones
        // whose entry was already gone.
        j.forget("job_0000000000000001");
    }

    #[test]
    fn recording_the_same_job_again_replaces_its_entry() {
        // The `Admit::Live` and verdict shapes, on disk. Two files for one job would let a reader
        // answer the same tree twice with two different verdicts.
        let (_d, j) = journal();
        j.record(&intent("job_0000000000000001")).unwrap();
        let decided = JobIntent { verdict: Some(Verdict::green("ok")), ..intent("job_0000000000000001") };
        j.record(&decided).unwrap();

        let out = j.outstanding().unwrap();
        assert_eq!(out.len(), 1, "one job, one file");
        assert_eq!(out[0].verdict.as_ref().unwrap().status, Status::Green);
    }

    #[test]
    fn a_corrupt_entry_is_skipped_rather_than_failing_the_whole_recovery() {
        // The trade this asserts: one unreadable file costs one job, never the other debts. Failing
        // the call would leave every *other* accepted tree wedged, and Hull does not re-check a wedged
        // tree without a human (spec §10).
        let (dir, j) = journal();
        j.record(&intent("job_0000000000000001")).unwrap();
        j.record(&intent("job_0000000000000002")).unwrap();
        std::fs::write(dir.path().join(JOURNAL_DIR).join("job_0000000000000002.json"), b"{not json").unwrap();

        let out = j.outstanding().unwrap();
        assert_eq!(out.len(), 1, "the readable entry survives the corrupt one");
        assert_eq!(out[0].job_id, "job_0000000000000001");
    }

    #[test]
    fn a_partially_written_file_is_never_read_as_a_valid_entry() {
        // Truncation is not silently tolerated. A prefix of a valid entry — the shape a non-atomic
        // write leaves behind after a power loss — must not parse, or recovery would send a verdict
        // assembled from whatever bytes happened to survive.
        let (dir, j) = journal();
        let full = JobIntent { verdict: Some(Verdict::green("42 tests, 0 failed")), ..intent("job_00000000000000ff") };
        j.record(&full).unwrap();
        let path = dir.path().join(JOURNAL_DIR).join("job_00000000000000ff.json");
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
        assert!(j.outstanding().unwrap().is_empty(), "a truncated entry is not an entry");
    }

    #[test]
    fn a_record_is_published_by_a_rename_so_the_entry_is_never_half_visible() {
        // The reason the truncation above cannot happen through `record`, asserted rather than
        // assumed — and it is the property the whole file format rests on: a reader either sees the
        // previous entry or the new one, never a prefix of the new one.
        //
        // Observed through a handle opened *before* the second write. A rename leaves that handle on
        // the old, now-unlinked inode, so it still reads the old bytes; an in-place truncate-and-write
        // would show it the new ones — and would therefore also be able to show a reader an empty or
        // half-written file at the same path.
        use std::io::Read;

        let (dir, j) = journal();
        let first = JobIntent { verdict: Some(Verdict::red("2 failed")), ..intent("job_00000000000000ff") };
        j.record(&first).unwrap();
        let path = dir.path().join(JOURNAL_DIR).join("job_00000000000000ff.json");

        let mut held = std::fs::File::open(&path).unwrap();
        let second = JobIntent {
            verdict: Some(Verdict::green("a much, much longer summary than the first one had")),
            ..first.clone()
        };
        j.record(&second).unwrap();

        let mut through_the_old_handle = String::new();
        held.read_to_string(&mut through_the_old_handle).unwrap();
        assert_eq!(
            serde_json::from_str::<JobIntent>(&through_the_old_handle).unwrap(),
            first,
            "the previous entry stayed whole and intact while the new one was being written"
        );
        // …and the name now resolves to the new entry, whole.
        assert_eq!(j.outstanding().unwrap(), vec![second]);

        // Scratch is written under a name `outstanding` does not consider an entry, and is gone by the
        // time `record` returns — a directory that accumulated one file per write would be its own
        // outage.
        let stray: Vec<_> = std::fs::read_dir(dir.path().join(JOURNAL_DIR))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| !n.ends_with(".json"))
            .collect();
        assert!(stray.is_empty(), "no scratch is left behind: {stray:?}");
    }

    #[test]
    fn a_job_id_that_is_not_a_name_cannot_escape_the_directory() {
        // `job_id` is minted as hex today, so nothing hostile reaches here now — but a filename
        // derived from a string is a path whatever its provenance, and this is the check that keeps it
        // one. `..` and `/` are the traversals; the empty string is the one that silently writes the
        // directory itself.
        let (dir, j) = journal();
        let canary = dir.path().join("escaped.json");

        for bad in ["..", "../escaped", "../../escaped", "a/b", "", ".", "a\\b", "with space", "x\u{0}y"] {
            let intent = JobIntent { job_id: bad.into(), ..intent("unused") };
            assert!(j.record(&intent).is_err(), "{bad:?} was accepted as a file name");
            j.forget(bad); // must also refuse to unlink, rather than unlinking something else
        }

        assert!(!canary.exists(), "nothing was written outside the journal directory");
        assert!(j.outstanding().unwrap().is_empty(), "and nothing landed inside it either");
        // The store root itself is untouched: only the journal subdirectory exists under it.
        let top: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(top, vec![JOURNAL_DIR.to_string()]);
    }

    // ── Recovery ─────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_job_that_never_reached_a_verdict_is_recovered_as_errored_infra() {
        // The case the whole feature exists for: accepted, then the process died. Anything is better
        // than silence, because silence leaves Hull's in-flight set holding the tree forever — and
        // `errored` is the one answer spec §7 does not memoize, so it costs a re-check rather than
        // poisoning the tree.
        let (_d, j) = journal();
        j.record(&intent("job_0000000000000001")).unwrap();
        let t = SpyTransport::new(200);

        recover(&j, &*t, Some("s3cret"), &fast()).await;

        let seen = t.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].verdict.status, Status::Errored);
        assert_eq!(seen[0].verdict.reason, Some(Reason::Infra));
        assert!(seen[0].verdict.summary.as_deref().unwrap().contains("restarted"));
        assert_eq!(seen[0].secret.as_deref(), Some("s3cret"), "spec §8 requires the echo");
        assert_eq!(seen[0].url, "https://hull.example/ci-result", "spec §5: verbatim");
        assert!(j.outstanding().unwrap().is_empty(), "and the debt is paid");
    }

    #[tokio::test]
    async fn a_job_that_reached_a_verdict_is_recovered_with_that_verdict_not_an_error() {
        // The defect this prevents, stated plainly: reporting `errored` for a job that genuinely went
        // green is a *wrong* answer, not merely a late one. It costs the user a real green result and
        // a re-run of work that already passed — which is why the verdict is journaled before delivery
        // is attempted rather than after.
        let (_d, j) = journal();
        let decided =
            JobIntent { verdict: Some(Verdict::green("42 tests, 0 failed")), ..intent("job_0000000000000001") };
        j.record(&decided).unwrap();
        let t = SpyTransport::new(200);

        recover(&j, &*t, None, &fast()).await;

        let seen = t.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].verdict.status, Status::Green, "the recorded verdict, not an error");
        assert_eq!(seen[0].verdict.summary.as_deref(), Some("42 tests, 0 failed"));
        assert!(j.outstanding().unwrap().is_empty());
    }

    #[tokio::test]
    async fn every_callback_url_on_an_entry_is_answered() {
        // Work is deduplicated by (repo, tree_id); delivery is not. An entry that answered only the
        // first dispatcher would leave the second change waiting on a verdict delivered elsewhere.
        let (_d, j) = journal();
        let two = JobIntent {
            callback_urls: vec!["https://hull.example/a".into(), "https://hull.example/b".into()],
            ..intent("job_0000000000000001")
        };
        j.record(&two).unwrap();
        let t = SpyTransport::new(200);

        recover(&j, &*t, None, &fast()).await;

        let urls: Vec<String> = t.seen().into_iter().map(|r| r.url).collect();
        assert_eq!(urls, ["https://hull.example/a", "https://hull.example/b"]);
    }

    #[tokio::test]
    async fn an_entry_whose_delivery_fails_is_kept_for_the_next_start() {
        // The outbox property, at the recovery end. Hull never got this verdict, so the tree is still
        // wedged; dropping the entry because we tried once would lose the debt permanently.
        let (_d, j) = journal();
        j.record(&intent("job_0000000000000001")).unwrap();
        let t = SpyTransport::new(503);

        recover(&j, &*t, None, &fast()).await;

        assert_eq!(j.outstanding().unwrap().len(), 1, "an undelivered debt survives");
        assert_eq!(t.seen().len(), 2, "and the full (short) boot budget was spent on it");
    }

    #[tokio::test]
    async fn recovery_with_nothing_outstanding_sends_nothing() {
        let (_d, j) = journal();
        let t = SpyTransport::new(200);
        recover(&j, &*t, None, &fast()).await;
        assert!(t.seen().is_empty());
    }

    // ── End to end: a real Control, a real journal on disk, and a restart ────────────────────────

    mod restart {
        use super::*;
        use hull_ci_control::model::StepSpec;
        use hull_ci_control::seams::{
            FetchError, FetchRequest, Fetcher, Membership, NodeError, NodeSink, PlanError, Planner,
            VerifiedTree,
        };
        use hull_ci_control::{Control, ControlConfig, Deps};
        use hull_ci_proto::{AuthorClass, Dispatch};

        // The control plane's own harness is `#[cfg(test)]`-private to its crate, so the seams are
        // stubbed here — enough to park a job in `running` and no more.

        struct StubFetcher;
        impl Fetcher for StubFetcher {
            fn fetch<'a>(&'a self, req: &'a FetchRequest) -> BoxFuture<'a, Result<VerifiedTree, FetchError>> {
                let tree_id = req.tree_id.clone();
                Box::pin(async move {
                    // A path nothing opens: the control plane never reads a workspace (spec §14.1),
                    // and a fixture that existed would hide it if that ever stopped being true.
                    Ok(VerifiedTree {
                        tree_id,
                        path: std::path::PathBuf::from("/nonexistent/control-plane-never-opens-this"),
                        cached: false, keep_alive: None
                    })
                })
            }
        }

        struct StubPlanner;
        impl Planner for StubPlanner {
            fn plan<'a>(&'a self, _t: &'a VerifiedTree) -> BoxFuture<'a, Result<Vec<StepSpec>, PlanError>> {
                Box::pin(async { Ok(vec![StepSpec::new("test", vec!["/bin/true".into()], "img")]) })
            }
        }

        /// Leases every step and then does nothing, so the job sits in `running` — genuinely in
        /// flight, which is the only state where losing it costs Hull anything.
        struct StubNode;
        impl NodeSink for StubNode {
            fn assign(&self, _a: &hull_ci_proto::Assignment, _t: &VerifiedTree) -> Result<String, NodeError> {
                Ok("node-test".into())
            }
            fn cancel(&self, _job_id: &str, _step_id: &str) {}
        }

        struct Everyone;
        impl Membership for Everyone {
            fn classify(&self, _repo: &str, _author: &str) -> AuthorClass {
                AuthorClass::Member
            }
        }

        fn control(journal: Arc<dyn Journal>, transport: Arc<dyn CallbackTransport>) -> Arc<Control> {
            let deps = Deps {
                fetcher: Arc::new(StubFetcher),
                planner: Arc::new(StubPlanner),
                node: Arc::new(StubNode),
                transport,
                membership: Arc::new(Everyone),
                journal,
            };
            Control::new(
                ControlConfig {
                    secret: Some("s3cret".into()),
                    // The same code path at no wall-clock cost: the real schedule spends the better
                    // part of an hour against a Hull that refuses, and the second test needs a job
                    // that has *decided* and failed to deliver, not one that is still trying.
                    retry: fast(),
                    ..Default::default()
                },
                deps,
            )
        }

        fn dispatch() -> Dispatch {
            Dispatch {
                repo: "acme/widget".into(),
                change: "21ea2242186c99ff".into(),
                tree_id: "tree-aaaaaaaaaaaaaaaa".into(),
                intent: "fixes #6".into(),
                author: "justin".into(),
                source_url: "https://hull.example/tree/tar".into(),
                callback_url: "https://hull.example/api/repos/acme/widget/change/21ea/ci-result".into(),
                fetch_token: None,
            }
        }

        async fn wait_until(mut f: impl FnMut() -> bool) -> bool {
            for _ in 0..400 {
                if f() {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            false
        }

        /// **The test that would have caught the real bug**, end to end and on a real filesystem.
        ///
        /// All runner state lived in memory, so a process that died mid-job left Hull holding an
        /// in-flight tree that no ordinary re-check could dislodge (spec §10: Hull neither polls us
        /// nor times the job out, and clears its in-flight set only in the callback handler). No
        /// verdict, no `errored`, and — the part that made it unfixable rather than merely bad —
        /// nothing anywhere that knew a callback was owed.
        ///
        /// Here: one `Control` accepts a dispatch and is dropped while the job is genuinely running.
        /// A second process is simulated by re-opening the same directory, draining it exactly the
        /// way [`crate::assemble`] does, and then building a fresh `Control` over it. The tree gets
        /// its answer.
        #[tokio::test]
        async fn a_restarted_runner_answers_a_job_the_previous_process_never_finished() {
            let dir = tempfile::tempdir().unwrap();

            // ── First process ────────────────────────────────────────────────────────────────────
            let journal = Arc::new(FileJournal::open(dir.path()).unwrap());
            let first = control(
                Arc::clone(&journal) as Arc<dyn Journal>,
                SpyTransport::new(200) as Arc<dyn CallbackTransport>,
            );
            let accepted = first.accept(dispatch()).unwrap();
            let ctrl = Arc::clone(&first);
            let id = accepted.job_id.clone();
            assert!(
                wait_until(move || ctrl.with_job(&id, |j| j.steps.len() == 1).unwrap_or(false)).await,
                "the job must be genuinely in flight when the process dies"
            );
            // The crash. Every job, step and waker goes with it; only the directory survives.
            drop(first);
            drop(journal);

            // ── Second process ───────────────────────────────────────────────────────────────────
            let journal = Arc::new(FileJournal::open(dir.path()).unwrap());
            assert_eq!(journal.outstanding().unwrap().len(), 1, "the debt outlived the process");

            let t = SpyTransport::new(200);
            // Exactly what `assemble` does, in the same order: drain the journal, *then* build the
            // control plane and serve.
            recover(&*journal, &*t, Some("s3cret"), &fast()).await;
            let restarted = control(Arc::clone(&journal) as Arc<dyn Journal>, Arc::clone(&t) as Arc<dyn CallbackTransport>);

            let seen = t.seen();
            assert_eq!(seen.len(), 1, "the stranded job was answered exactly once");
            assert_eq!(seen[0].job_id, accepted.job_id);
            assert_eq!(seen[0].url, dispatch().callback_url, "spec §5: verbatim");
            assert_eq!(seen[0].secret.as_deref(), Some("s3cret"), "spec §8: echoed");
            assert_eq!(seen[0].verdict.status, Status::Errored);
            assert_eq!(
                seen[0].verdict.reason,
                Some(Reason::Infra),
                "spec §7: `errored` is a statement about us, and Hull does not memoize it"
            );
            assert!(journal.outstanding().unwrap().is_empty(), "and the debt is paid");

            // The restarted runner is a normal runner: the same tree dispatched again is new work
            // (its answer was `errored`, which Hull does not memoize, so a re-check is expected) and
            // it is journaled like any other.
            let again = restarted.accept(dispatch()).unwrap();
            assert!(!again.duplicate, "a fresh process has no memory of the old job");
            assert_eq!(journal.outstanding().unwrap().len(), 1, "and the new job is owed an answer");
        }

        /// The other half: a job that *did* reach a verdict before the crash is re-sent with **that**
        /// verdict. Reporting `errored` for work that genuinely went green is a wrong answer, not a
        /// late one — the user loses a real result and re-runs work that already passed.
        #[tokio::test]
        async fn a_restart_re_sends_the_recorded_verdict_rather_than_inventing_an_error() {
            let dir = tempfile::tempdir().unwrap();

            let journal = Arc::new(FileJournal::open(dir.path()).unwrap());
            // A Hull that refuses everything: the job decides, delivery fails, `report_failed`.
            let dead = SpyTransport::new(503);
            let first = control(
                Arc::clone(&journal) as Arc<dyn Journal>,
                Arc::clone(&dead) as Arc<dyn CallbackTransport>,
            );
            let accepted = first.accept(dispatch()).unwrap();
            let ctrl = Arc::clone(&first);
            let id = accepted.job_id.clone();
            assert!(
                wait_until(move || ctrl.with_job(&id, |j| j.steps.len() == 1).unwrap_or(false)).await,
                "the step never reached the fleet"
            );
            let step = first.with_job(&accepted.job_id, |j| j.steps[0].id.clone()).unwrap();
            first
                .record_step_report(
                    &hull_ci_proto::StepReport {
                        job_id: accepted.job_id.clone(),
                        step_id: step,
                        outcome: hull_ci_proto::StepOutcome::Passed,
                        reason: None,
                        exit_code: Some(0),
                        log_key: None,
                        detail: "42 tests, 0 failed".into(),
                    },
                    "node-test",
                )
                .unwrap();
            let ctrl = Arc::clone(&first);
            let id = accepted.job_id.clone();
            assert!(
                wait_until(move || ctrl.verdict(&id).is_some()).await,
                "the job should have decided before the crash"
            );
            drop(first);
            drop(journal);

            let journal = Arc::new(FileJournal::open(dir.path()).unwrap());
            let owed = journal.outstanding().unwrap();
            assert_eq!(owed.len(), 1, "an undelivered verdict is still a debt");
            assert_eq!(owed[0].verdict.as_ref().unwrap().status, Status::Green);

            let t = SpyTransport::new(200);
            recover(&*journal, &*t, Some("s3cret"), &fast()).await;
            let seen = t.seen();
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].verdict.status, Status::Green, "the recorded verdict, not an error");
            assert_eq!(
                seen[0].verdict.summary,
                owed[0].verdict.as_ref().unwrap().summary,
                "the summary the aggregator wrote, byte for byte — a re-send re-affirms, it does not rebuild"
            );
            assert!(journal.outstanding().unwrap().is_empty());
        }
    }

    // ── Wiring ───────────────────────────────────────────────────────────────────────────────────

    /// The journal is **on** for an operator who configures nothing, and both spellings of that
    /// default agree.
    ///
    /// The second half is the point. `Config::default()` and `Config::from_env()` are two doors into
    /// the same struct, and a switch that reads differently through each is a switch nobody can
    /// reason about — this one decides whether an accepted dispatch is ever answered, so a
    /// disagreement would mean the tests exercised a runner the operator never runs. `from_env` has
    /// its own test for the `off` spelling; this pins the value they must share.
    #[test]
    fn the_journal_is_on_unless_it_is_configured_off() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = crate::config::Config { store_root: dir.path().into(), ..Default::default() };
        assert!(config.journal, "on by default: silence wedges the tree (spec §10)");
        assemble(&config).unwrap();
        assert!(dir.path().join(JOURNAL_DIR).exists(), "on, it owns a directory of its own");

        let dir2 = tempfile::tempdir().unwrap();
        config.store_root = dir2.path().into();
        config.journal = false;
        let off = assemble(&config).unwrap();
        assert!(off.outstanding().unwrap().is_empty());
        assert!(!dir2.path().join(JOURNAL_DIR).exists(), "turned off, it creates nothing");
    }
}
