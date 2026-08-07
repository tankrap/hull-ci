//! The write-ahead journal — the outbox that makes "every accepted dispatch is answered" survive a
//! restart (design D§4.1, spec §10).
//!
//! ## Why an outbox and not a log
//!
//! Spec §10 is explicit about who owns the timeout and who owns the recovery: "Hull does not time out
//! a dispatched job… Your system SHOULD enforce its own job timeout and report `errored` when it
//! fires", and "If a callback never arrives (your system crashed), the tree stays unverified. A human
//! (or an automated re-check with `force`) re-triggers it. **Hull does not poll you.**"
//!
//! Hull's side of that is a set of in-flight tree ids that is only ever cleared by the callback
//! handler, so a tree we accepted and never answered is not merely late — it is *wedged*. An ordinary
//! re-check finds the tree in flight and returns `Pending` rather than dispatching again, so the only
//! way out is a human clicking "force rerun". The corollary drives everything in this module:
//!
//! > **Reporting anything unwedges Hull. Reporting nothing wedges it permanently.**
//!
//! Until now the whole job store was in memory (see [`crate::store`]), so a restart stranded every
//! in-flight job forever: no verdict, no `errored`, no callback, and nothing anywhere that knew a
//! callback was owed. This is the durable record of that debt.
//!
//! ## The three states of an entry
//!
//! | Entry | Means | What recovery sends |
//! |---|---|---|
//! | present, `verdict: None` | accepted, no verdict was ever reached | `errored` + [`Reason::Infra`](hull_ci_proto::Reason::Infra) |
//! | present, `verdict: Some(v)` | a verdict exists but was **not** confirmed delivered | `v` — it is the true answer |
//! | absent | delivered, or never accepted | nothing is owed |
//!
//! The middle row is what makes this an outbox rather than a crash log. A verdict whose delivery
//! failed (`report_failed`) leaves Hull exactly as wedged as one that was never computed, so the
//! entry has to outlive the failed delivery — see the settle site in [`crate::control`].
//!
//! It is then retried from **two** places, and it needs both:
//!
//! * in this process, by `Control::drain_undelivered`, whenever a later dispatch arrives. An
//!   unreachable Hull is the likelier failure, and a runner that is still up and still holding the
//!   verdict must not need a restart to try again;
//! * at the next start, by `hull_ci_server::journal::recover`, which is the only thing that can
//!   answer a debt this process no longer remembers — one it crashed on, or one eviction gave up
//!   under cap pressure (see [`JobStore::evict`](crate::store::JobStore::evict)).
//!
//! ## Why `record` is fallible and `forget` is not
//!
//! [`Journal::record`] gates the ack: spec §5 makes a 2xx mean *accepted*, Hull tells the user
//! "dispatched" on the strength of it, and then stops caring. So a dispatch we cannot durably record
//! must be refused loudly (a 503 the dispatcher can see and retry) rather than acked and lost.
//!
//! [`Journal::forget`] cannot fail in any way the caller could act on. It runs after a verdict has
//! already reached Hull; a failure to delete leaves a stale entry, and a stale entry costs exactly one
//! duplicate callback on the next start — which spec §10 makes idempotent. Making it fallible would
//! invite a caller to treat "could not delete" as "could not deliver", which is the more dangerous
//! direction.

use hull_ci_proto::Verdict;
use serde::{Deserialize, Serialize};

/// One accepted dispatch and everything needed to answer it **without the job store** — because after
/// a restart the job store is empty, and this is all that is left.
///
/// Deliberately not a `Job`. A `Job` carries `dispatch`, and `dispatch` carries `source_url` and
/// `fetch_token` — credentials spec §14.2 keeps away from everything that is not the broker, and
/// which have no business being written to a file that outlives the process. Recovery re-*reports*;
/// it never re-*runs*, so it needs no way to fetch anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobIntent {
    pub job_id: String,
    pub repo: String,
    pub tree_id: String,
    /// **Every** destination that has asked about this tree, not just the first.
    ///
    /// Work is deduplicated by `(repo, tree_id)` and delivery is not (see [`crate::model::Job`]'s
    /// `callback_urls`). A second dispatch for a live tree attaches a second `callback_url`, and an
    /// entry carrying only the first would leave that second change waiting forever on an answer
    /// delivered somewhere else — the same wedge, one level down.
    pub callback_urls: Vec<String>,
    /// Wall clock, seconds since the Unix epoch. Wall clock rather than the `Instant` the rest of the
    /// control plane runs on, because an `Instant` is meaningless to the process that reads this file
    /// back: monotonic clocks do not survive a reboot, and this record exists precisely to be read
    /// after one. Only ever used to say *how long ago* in a log line.
    pub accepted_at_unix: u64,
    /// `None` = accepted, never reached a verdict.
    /// `Some` = reached a verdict that has **not** been confirmed delivered.
    ///
    /// Both are debts; they differ only in what recovery should send. See the table in the module
    /// docs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
}

/// Why the journal could not do what was asked.
///
/// Both variants name the job where one is known, because the operator-facing question when this
/// appears is "which change is now failing to dispatch", and an errno on its own does not answer it.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("could not record job {job_id} durably: {detail}")]
    Write { job_id: String, detail: String },
    #[error("could not read the journal: {detail}")]
    Read { detail: String },
}

/// The durable record of dispatches we owe an answer for.
///
/// A seam rather than a concrete store for the usual reason — the control plane must stay a crate
/// that opens no file (spec §14.1, see [`crate::lib`]) — and for one more: the real implementation
/// lives in the composition root next to the store root it writes under, so the decision *whether to
/// be durable at all* is an operator's, made in one place, and every existing test keeps the
/// [`NoJournal`] behaviour it was written against.
///
/// [`crate::lib`]: crate
pub trait Journal: Send + Sync + 'static {
    /// Create or replace the entry for `intent.job_id`.
    ///
    /// **Upsert, not insert.** The same job is recorded more than once by design: once when it is
    /// created, again when a second dispatch attaches another `callback_url`, and again when it
    /// reaches a verdict. Each call carries the *complete* current intent, so a reader never has to
    /// merge two records to learn the truth — the last write is the whole answer.
    ///
    /// Returning `Err` refuses the dispatch (see [`crate::control::AcceptError`]). An implementation
    /// must therefore only report success once the entry would survive this process dying.
    fn record(&self, intent: &JobIntent) -> Result<(), JournalError>;

    /// Drop the entry: the debt is paid.
    ///
    /// Infallible on purpose — see the module docs. A failure here is logged where it happens and
    /// costs at most one duplicate callback, which spec §10 makes safe.
    fn forget(&self, job_id: &str);

    /// Every entry still owed an answer, in no particular order.
    ///
    /// Read once at startup, before the process serves. An implementation should skip an entry it
    /// cannot parse rather than failing the whole call: one unreadable file must not stop the other
    /// jobs from being unwedged.
    fn outstanding(&self) -> Result<Vec<JobIntent>, JournalError>;
}

/// The default: **remember nothing**.
///
/// Not a stub. It is the exact behaviour every deployment had before this module existed — a restart
/// strands in-flight jobs — and keeping it as the default means turning durability *on* is a
/// deliberate act with a documented cost (a directory that has to be writable, on storage that has to
/// outlive the process), rather than a silent new failure mode on every existing install.
///
/// `record` succeeds, because refusing dispatches on a deployment that never asked for a journal
/// would be an outage introduced by a feature nobody enabled.
pub struct NoJournal;

impl Journal for NoJournal {
    fn record(&self, _intent: &JobIntent) -> Result<(), JournalError> {
        Ok(())
    }

    fn forget(&self, _job_id: &str) {}

    fn outstanding(&self) -> Result<Vec<JobIntent>, JournalError> {
        Ok(Vec::new())
    }
}

/// Seconds since the Unix epoch, or `0` on a clock behind the epoch.
///
/// Saturating rather than erroring: a nonsensical system clock must not be able to refuse a dispatch.
/// The field is only ever rendered as "accepted N seconds ago" in a recovery log line, so being wrong
/// costs a confusing number, and being fatal would cost a wedged tree.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// An in-memory [`Journal`] that survives being handed to a *second*
/// [`Control`](crate::control::Control) — which is how the restart tests simulate a process boundary
/// without a filesystem. The real durable implementation lives in `hull-ci-server`.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MemJournal {
    entries: std::sync::Mutex<std::collections::HashMap<String, JobIntent>>,
}

#[cfg(test)]
impl Journal for MemJournal {
    fn record(&self, intent: &JobIntent) -> Result<(), JournalError> {
        self.entries.lock().unwrap().insert(intent.job_id.clone(), intent.clone());
        Ok(())
    }
    fn forget(&self, job_id: &str) {
        self.entries.lock().unwrap().remove(job_id);
    }
    fn outstanding(&self) -> Result<Vec<JobIntent>, JournalError> {
        Ok(self.entries.lock().unwrap().values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent(job_id: &str) -> JobIntent {
        JobIntent {
            job_id: job_id.into(),
            repo: "acme/widget".into(),
            tree_id: "tree1".into(),
            callback_urls: vec!["https://hull.example/cb".into()],
            accepted_at_unix: now_unix(),
            verdict: None,
        }
    }

    #[test]
    fn the_default_journal_remembers_nothing_and_refuses_nothing() {
        // Both halves matter. "Remembers nothing" is the pre-existing behaviour; "refuses nothing" is
        // what keeps a deployment that never asked for durability from losing its ingest.
        let j = NoJournal;
        assert!(j.record(&intent("job_1")).is_ok());
        j.forget("job_1");
        assert!(j.outstanding().unwrap().is_empty());
    }

    #[test]
    fn recording_the_same_job_twice_replaces_rather_than_duplicates() {
        // The `Admit::Live` shape: a second dispatch attaches another callback_url and re-records the
        // *complete* intent. A journal that appended would leave a reader merging two half-truths.
        let j = MemJournal::default();
        j.record(&intent("job_1")).unwrap();
        let mut second = intent("job_1");
        second.callback_urls.push("https://hull.example/other".into());
        j.record(&second).unwrap();

        let out = j.outstanding().unwrap();
        assert_eq!(out.len(), 1, "one job, one entry");
        assert_eq!(out[0].callback_urls.len(), 2, "and it carries the full current URL set");
    }

    #[test]
    fn an_intent_round_trips_through_json_with_its_verdict() {
        // The wire shape a `FileJournal` writes. `verdict: None` must survive as `None` rather than
        // becoming a missing field that fails to parse — that entry is the *commonest* one, since it
        // is written on every accept.
        let accepted = intent("job_1");
        let json = serde_json::to_string(&accepted).unwrap();
        assert!(!json.contains("verdict"), "an unanswered job writes no verdict field");
        assert_eq!(serde_json::from_str::<JobIntent>(&json).unwrap(), accepted);

        let decided = JobIntent { verdict: Some(Verdict::green("42 tests, 0 failed")), ..accepted };
        let json = serde_json::to_string(&decided).unwrap();
        assert_eq!(serde_json::from_str::<JobIntent>(&json).unwrap(), decided);
    }

    #[test]
    fn an_intent_carries_no_credential_from_the_dispatch() {
        // Structural, and asserted so it stays that way: `JobIntent` has no `source_url` and no
        // `fetch_token`, so the durable record cannot leak the two fields spec §14.2 keeps away from
        // everything that is not the broker. Recovery re-reports; it never re-fetches.
        let json = serde_json::to_string(&intent("job_1")).unwrap();
        assert!(!json.contains("fetch_token"));
        assert!(!json.contains("source_url"));
    }
}
