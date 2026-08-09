//! The shared claim store, on Postgres — design D§4.5, and the seam it fills is
//! [`hull_ci_control::claims`].
//!
//! [`JobClaims`] is the trait; this is the one real implementation, and it lives here rather than in
//! the control plane for the reason [`FileJournal`](crate::journal::FileJournal) does: that crate
//! parses JSON and nothing else (spec §14.1), and holding a connection string, a driver and a socket
//! is the composition root's business.
//!
//! # What Postgres is being asked for
//!
//! Two guarantees, and deliberately nothing else:
//!
//! 1. **One tree, one job.** `hull_ci_claim` is keyed by `(repo, tree_id)` and admission is a single
//!    `INSERT … ON CONFLICT DO UPDATE`. Two replicas admitting the same tree in the same millisecond
//!    contend on one row; one inserts, the other is told the winner's `job_id`, and *both* dispatchers'
//!    `callback_url`s are on the row when the statement commits.
//! 2. **One replica, one step.** `hull_ci_step_claim` is keyed by `(job_id, step_id)` and the insert
//!    is conditional on the claimant still holding the job's current `fence`. A replica that was
//!    superseded cannot insert, so it cannot dispatch.
//!
//! Design D§4.5 anticipated `FOR UPDATE SKIP LOCKED`, which is the shape for *pulling work off a
//! queue*. Neither of these is that: both are "exactly one winner for this key", which a unique index
//! answers in one statement, without a transaction to hold open or a lock to leak on a dropped
//! connection. The queue itself is still process-local (see the module docs in `claims`), so the
//! statement this phase does not need is the one it does not have.
//!
//! # Everything is one statement
//!
//! There is no `BEGIN` anywhere in this file, and that is a design decision rather than an omission.
//! Every operation is a single statement, so every operation is its own transaction and there is no
//! window between a read and the write that depends on it — which is precisely the window a
//! read-modify-write over a network loses updates in. The cost is that the SQL carries `CASE`
//! expressions where procedural code would have an `if`; the benefit is that no amount of
//! interleaving between replicas can produce a state a single replica could not.
//!
//! # Time
//!
//! Every timestamp is epoch milliseconds supplied by the **caller**, never `now()` read from the
//! database. That keeps lease expiry testable by passing a number rather than by sleeping (this
//! repository does not assert on wall-clock timing), and it keeps the clock that decides a lease the
//! same clock the control plane schedules on. The assumption it buys — replicas whose clocks agree to
//! well within one lease TTL — is stated where the trait is defined, along with what skew costs.
//!
//! # Blocking
//!
//! [`JobClaims`] is a synchronous trait, because its callers are synchronous: `Control::accept` runs
//! on the ack path and `Control::pump` is called from inside the scheduler. So this type runs a small
//! tokio runtime on a thread of its own and blocks the calling thread on a channel while that runtime
//! drives the query. It is the same trade [`Journal::record`](hull_ci_control::Journal::record)
//! already makes by doing an `fsync` on the ack path, and it is honest about what it is: **a database
//! round trip on a request thread.** Making the seam async instead would mean making `pump` async,
//! which would mean making the scheduler async — a much larger change than the one this phase is for.

use std::sync::Arc;

use hull_ci_control::claims::{JobClaims, LocalClaims};

use crate::config::Config;
use crate::StartupError;

/// Choose the claim store this deployment runs on.
///
/// The default is [`LocalClaims`] — the process-local index — and that is not a degraded mode: it is
/// what every single-replica runner has always done, moved out of the job store so it has one owner.
/// Configuring `HULL_CI_POSTGRES_URL` is the operator saying "there is more than one of me".
///
/// Two refusals, both loud, both at startup:
///
/// * a URL on a binary built without `--features postgres` fails, naming the feature, rather than
///   silently falling back to the local index. Falling back would give an operator two replicas that
///   each believe they are alone — every tree dispatched twice, every step run twice, and nothing in
///   the logs saying so. This is the failure this whole module exists to prevent, so it must not be
///   reachable by forgetting a build flag (the same rule `HULL_CI_SECRETS=infisical` follows);
/// * a URL with no `HULL_CI_REPLICA_ID` fails too. Every claim records who holds it, and two replicas
///   sharing an identity can take each other's leases and each other's step claims — which is a
///   split brain wearing the mask of correct bookkeeping. There is no default that is safe here, so
///   there is no default.
pub fn assemble(config: &Config) -> Result<Arc<dyn JobClaims>, StartupError> {
    let Some(url) = config.postgres_url.as_deref() else {
        return Ok(Arc::new(LocalClaims::new()));
    };

    let Some(replica) = config.replica_id.clone() else {
        return Err(StartupError::Claims(
            "HULL_CI_POSTGRES_URL is set but HULL_CI_REPLICA_ID is not. Every claim records which \
             replica holds it, and two replicas sharing one identity would take each other's leases \
             and each other's step claims. Give each replica a distinct id."
                .into(),
        ));
    };

    #[cfg(not(feature = "postgres"))]
    {
        let _ = url;
        Err(StartupError::Claims(format!(
            "HULL_CI_POSTGRES_URL is set, but this binary was built without the `postgres` feature, \
             so it cannot share claims with another replica. Rebuild with \
             `--features hull-ci-server/postgres`. Refusing to start rather than running as replica \
             `{replica}` believing it is the only one — two such replicas would run every tree twice."
        )))
    }

    #[cfg(feature = "postgres")]
    {
        let claims = PgClaims::connect(url, replica.clone())
            .map_err(|e| StartupError::Claims(e.to_string()))?;
        tracing::info!(
            replica = %replica,
            "shared claim store on: `(repo, tree_id)` and step claims are decided in Postgres"
        );
        Ok(Arc::new(claims))
    }
}

#[cfg(feature = "postgres")]
pub use pg::PgClaims;

#[cfg(feature = "postgres")]
mod pg {
    use super::*;
    use std::future::Future;

    use hull_ci_control::claims::{Admitted, ClaimError, DriveLease, StepClaim, TreeKey};
    use hull_ci_proto::Verdict;
    use tokio_postgres::{Client, NoTls};

    /// The tables, created on connect.
    ///
    /// No migration tool, on purpose: there are two tables and the phase that adds a third is the
    /// phase that should bring one. `IF NOT EXISTS` throughout, so several replicas starting at once
    /// race harmlessly — the loser's `CREATE` is a no-op rather than an error that would take a
    /// replica down for being second.
    ///
    /// Every time column is `bigint` epoch milliseconds rather than `timestamptz`, because the clock
    /// that matters is the caller's (see the module docs) and a column Postgres could default to
    /// `now()` would invite someone to let it.
    const SCHEMA: &str = "
        CREATE TABLE IF NOT EXISTS hull_ci_claim (
            repo             text   NOT NULL,
            tree_id          text   NOT NULL,
            job_id           text   NOT NULL,
            owner            text   NOT NULL,
            fence            bigint NOT NULL,
            lease_expires_ms bigint NOT NULL,
            callback_urls    text[] NOT NULL,
            verdict          text,
            settled_at_ms    bigint,
            PRIMARY KEY (repo, tree_id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS hull_ci_claim_job_id ON hull_ci_claim (job_id);
        CREATE TABLE IF NOT EXISTS hull_ci_step_claim (
            job_id        text   NOT NULL,
            step_id       text   NOT NULL,
            owner         text   NOT NULL,
            fence         bigint NOT NULL,
            claimed_at_ms bigint NOT NULL,
            PRIMARY KEY (job_id, step_id)
        );
    ";

    /// The condition under which an existing claim is **taken over** by the admitting replica.
    ///
    /// Written once and pasted into the one statement that needs it, because the three columns it
    /// governs (`job_id`, `owner`, `fence`) must agree about it exactly — a row that took a new owner
    /// but kept the old fence would let the old owner keep claiming steps.
    ///
    /// Two disjoint cases:
    ///
    /// * `$5` is `now_ms`: an **unsettled** claim whose lease has lapsed. Its replica died, or is
    ///   partitioned; either way the tree must become dispatchable again, or a forced re-check comes
    ///   back attached to a job nobody is driving and spec §10 leaves it wedged for good.
    /// * `$8` is the retention window: a **settled** claim old enough that the local job store would
    ///   have evicted its record. Keeping it would answer a duplicate from a verdict the replicas no
    ///   longer hold the details of; dropping it costs a re-run, never a wrong answer (spec §9).
    ///
    /// A settled claim inside retention is **never** taken over. That is what stops a job being
    /// adopted out from under the replica that is still delivering its verdict.
    const TAKEOVER: &str = "((c.verdict IS NULL AND c.lease_expires_ms < $5::bigint) \
                            OR (c.settled_at_ms IS NOT NULL AND c.settled_at_ms + $8::bigint <= $5::bigint))";

    /// Postgres-backed [`JobClaims`].
    pub struct PgClaims {
        owner: String,
        client: Arc<Client>,
        /// A handle to a runtime of this type's own, living on a thread of its own.
        ///
        /// Not the caller's runtime: the trait is synchronous and its callers may already be inside a
        /// tokio worker, so driving a query on *their* runtime would mean blocking a thread that is
        /// supposed to be polling it. Queries are `spawn`ed through this handle and the calling
        /// thread waits on a channel, which is a plain blocking wait rather than a nested `block_on`.
        handle: tokio::runtime::Handle,
        /// Dropping this tells the runtime's thread to shut down; see [`PgClaims::drop`].
        ///
        /// A handle rather than the `Runtime` itself is what makes that possible, and it is not a
        /// stylistic choice: **dropping a `Runtime` from inside an async context panics**, and this
        /// value is reachable from `Deps`, which a runner may well drop while its own runtime is
        /// still running. Owning the runtime here would turn an ordinary shutdown into a crash.
        shutdown: Option<std::sync::mpsc::Sender<()>>,
    }

    impl Drop for PgClaims {
        fn drop(&mut self) {
            // Closing the channel is the whole signal: the runtime's thread is parked on `recv`, and
            // an `Err` means the last `PgClaims` has gone. The runtime is then dropped *there* — on a
            // plain thread, where blocking is allowed — rather than wherever this value happened to
            // be released. Deliberately not joined: a join from an async context is another blocking
            // wait, and nothing here needs the teardown to have finished.
            self.shutdown.take();
        }
    }

    /// Run `fut` on `handle`'s runtime and block the current thread until it answers.
    ///
    /// `spawn` + a channel rather than `Runtime::block_on`, which panics when called from inside
    /// another runtime — and every caller of this trait is inside one.
    fn block<F, T>(handle: &tokio::runtime::Handle, fut: F) -> Result<T, ClaimError>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        handle.spawn(async move {
            let _ = tx.send(fut.await);
        });
        rx.recv().map_err(|_| {
            ClaimError::Unavailable("the claim store's runtime stopped before answering".into())
        })
    }

    /// A driver error, with the server's own message kept.
    ///
    /// `tokio_postgres::Error` renders as the bare word "db error" — the useful half is in its
    /// source, and an operator staring at "the claim store is unavailable: db error" learns nothing
    /// about whether they have a syntax problem, a permissions problem, or a dead socket.
    fn db(e: tokio_postgres::Error) -> ClaimError {
        let detail = match std::error::Error::source(&e) {
            Some(cause) => format!("{e}: {cause}"),
            None => e.to_string(),
        };
        ClaimError::Unavailable(detail)
    }

    impl PgClaims {
        /// Connect, create the tables if they are not there, and take `owner` as this replica's
        /// identity for every claim it makes.
        pub fn connect(url: &str, owner: String) -> Result<PgClaims, ClaimError> {
            // The runtime is *built on* the thread that will also drop it, and this function only
            // ever holds a handle — see the `shutdown` field for why owning it here would be a crash
            // waiting for a shutdown.
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
            std::thread::Builder::new()
                .name("hull-ci-claims".into())
                .spawn(move || {
                    // Two worker threads: one is enough for the query load (every call is a single
                    // round trip) and the second keeps the connection task from ever being stuck
                    // behind a query.
                    let runtime = match tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .thread_name("hull-ci-claims-worker")
                        .build()
                    {
                        Ok(rt) => rt,
                        Err(e) => {
                            let _ = ready_tx.send(Err(format!("could not start a runtime: {e}")));
                            return;
                        }
                    };
                    if ready_tx.send(Ok(runtime.handle().clone())).is_err() {
                        return;
                    }
                    // Parked until the last `PgClaims` is dropped, then the runtime goes with it.
                    let _ = stop_rx.recv();
                    drop(runtime);
                })
                .map_err(|e| {
                    ClaimError::Unavailable(format!("could not start the claim store thread: {e}"))
                })?;

            let handle = ready_rx
                .recv()
                .map_err(|_| {
                    ClaimError::Unavailable("the claim store thread stopped before starting".into())
                })?
                .map_err(ClaimError::Unavailable)?;

            let owned_url = url.to_string();
            let client = block(&handle, async move {
                let (client, connection) = tokio_postgres::connect(&owned_url, NoTls).await?;
                // The connection future is the thing that actually drives the socket; dropping it
                // would leave a client that answers every query with "connection closed".
                tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        tracing::error!(error = %e, "the claim store connection ended");
                    }
                });
                client.batch_execute(SCHEMA).await?;
                Ok::<_, tokio_postgres::Error>(client)
            })?
            .map_err(db)?;

            Ok(PgClaims { owner, client: Arc::new(client), handle, shutdown: Some(stop_tx) })
        }

        fn run<F, T>(&self, f: impl FnOnce(Arc<Client>) -> F) -> Result<T, ClaimError>
        where
            F: Future<Output = Result<T, tokio_postgres::Error>> + Send + 'static,
            T: Send + 'static,
        {
            block(&self.handle, f(Arc::clone(&self.client)))?.map_err(db)
        }
    }

    /// A `fence` is a `u64` in the seam and a `bigint` in the row.
    ///
    /// The cast is lossless for every value that can occur: a fence starts at 1 and is incremented
    /// once per takeover of one job, so reaching `i64::MAX` would take longer than the heat death of
    /// the deployment. Written as a function rather than an `as` at four call sites so there is one
    /// place to look when that stops being true.
    fn fence_of(lease: &DriveLease) -> i64 {
        lease.fence() as i64
    }

    impl JobClaims for PgClaims {
        fn owner(&self) -> &str {
            &self.owner
        }

        /// Leases here are real and expire, so a driver must keep saying it is alive.
        fn needs_renewal(&self) -> bool {
            true
        }

        fn admit(
            &self,
            key: &TreeKey,
            proposed_job_id: &str,
            callback_url: &str,
            now_ms: i64,
            lease_ms: i64,
            settled_retention_ms: i64,
        ) -> Result<Admitted, ClaimError> {
            // One statement, so the whole decision — create, attach, or take over — commits at once.
            // `RETURNING` is what makes it a decision we can read: `ON CONFLICT DO NOTHING` would
            // return no row and force a second `SELECT`, and the gap between the two is exactly where
            // a third replica's takeover would hide.
            //
            // `callback_urls` is the reason the attach branch is not a no-op. Work is deduplicated by
            // `(repo, tree_id)` and delivery is not, so the losing dispatcher's URL has to land on
            // the row in this same commit — the replica that eventually delivers may never see this
            // dispatch at all, and reads the set back with `destinations`.
            let sql = format!(
                "INSERT INTO hull_ci_claim AS c
                     (repo, tree_id, job_id, owner, fence, lease_expires_ms, callback_urls,
                      verdict, settled_at_ms)
                 VALUES ($1, $2, $3, $4, 1, $5::bigint + $6::bigint, ARRAY[$7::text], NULL, NULL)
                 ON CONFLICT (repo, tree_id) DO UPDATE SET
                     job_id           = CASE WHEN {t} THEN EXCLUDED.job_id ELSE c.job_id END,
                     owner            = CASE WHEN {t} THEN EXCLUDED.owner ELSE c.owner END,
                     fence            = CASE WHEN {t} THEN c.fence + 1 ELSE c.fence END,
                     lease_expires_ms = CASE WHEN {t} THEN EXCLUDED.lease_expires_ms
                                             ELSE c.lease_expires_ms END,
                     verdict          = CASE WHEN {t} THEN NULL ELSE c.verdict END,
                     settled_at_ms    = CASE WHEN {t} THEN NULL ELSE c.settled_at_ms END,
                     -- A tree whose *settled* claim aged out has already been answered, so its old
                     -- destinations are paid debts and start again from this dispatch. A claim taken
                     -- over because its replica died has not been answered, so those dispatchers are
                     -- still waiting and their URLs come along.
                     callback_urls    = CASE
                         WHEN (c.settled_at_ms IS NOT NULL AND c.settled_at_ms + $8::bigint <= $5::bigint)
                             THEN ARRAY[$7::text]
                         WHEN $7::text = ANY(c.callback_urls) THEN c.callback_urls
                         ELSE c.callback_urls || $7::text END
                 -- `xmax <> 0` distinguishes a row this statement *updated* from one it inserted.
                 -- Combined with \"is the id ours\" it separates the three outcomes — insert, takeover,
                 -- attach — without a second query that a third replica could interleave with.
                 RETURNING job_id, owner, fence, verdict, (xmax <> 0) AS was_update",
                t = TAKEOVER
            );

            let (repo, tree_id) = (key.repo.clone(), key.tree_id.clone());
            let (proposed, url) = (proposed_job_id.to_string(), callback_url.to_string());
            // Bound out here, not inside the future: query parameters must outlive it, and nothing
            // borrowed from `&self` may cross into a `spawn`.
            let me = self.owner.clone();
            let row = self.run(move |c| async move {
                c.query_one(
                    sql.as_str(),
                    &[
                        &repo,
                        &tree_id,
                        &proposed,
                        &me,
                        &now_ms,
                        &lease_ms,
                        &url,
                        &settled_retention_ms,
                    ],
                )
                .await
            })?;

            let job_id: String = row.get(0);
            let owner: String = row.get(1);
            let fence: i64 = row.get(2);
            let verdict: Option<String> = row.get(3);
            let was_update: bool = row.get(4);

            // We won exactly when the row came back carrying the id we proposed. Job ids are 64 bits
            // of hex minted per process, so "the row has our id" cannot mean anything else.
            if job_id == proposed_job_id {
                if was_update {
                    // A takeover, so a previous job's step claims are now unreachable: their job id
                    // is not in `hull_ci_claim` any more and can never be claimed against again.
                    // Swept only on this path — takeovers happen when a replica dies, which is rare,
                    // and the sweep is an anti-join nobody should pay for on an ordinary dispatch.
                    let _ = self.run(move |c| async move {
                        c.execute(
                            "DELETE FROM hull_ci_step_claim s
                             WHERE NOT EXISTS (SELECT 1 FROM hull_ci_claim k WHERE k.job_id = s.job_id)",
                            &[],
                        )
                        .await
                    });
                }
                return Ok(Admitted::Created {
                    lease: DriveLease::issued(job_id, &self.owner, fence as u64),
                });
            }

            Ok(Admitted::Attached {
                job_id,
                owner,
                verdict: verdict.and_then(|raw| decode_verdict(&raw)),
            })
        }

        fn renew(&self, lease: &DriveLease, now_ms: i64, lease_ms: i64) -> Result<bool, ClaimError> {
            // Fenced on `owner` *and* `fence`: a replica that was superseded and then restarted with
            // the same id must not be able to renew a lease it no longer holds.
            let (job_id, owner, fence) =
                (lease.job_id().to_string(), lease.owner().to_string(), fence_of(lease));
            let n = self.run(move |c| async move {
                c.execute(
                    "UPDATE hull_ci_claim SET lease_expires_ms = $2::bigint + $3::bigint
                     WHERE job_id = $1 AND owner = $4 AND fence = $5",
                    &[&job_id, &now_ms, &lease_ms, &owner, &fence],
                )
                .await
            })?;
            Ok(n == 1)
        }

        fn claim_step(
            &self,
            lease: &DriveLease,
            step_id: &str,
            now_ms: i64,
        ) -> Result<StepClaim, ClaimError> {
            // The whole guarantee, in one statement. The `SELECT … FROM hull_ci_claim` is not a
            // lookup: it is the condition. No row is produced unless this replica still holds the
            // job's current fence, so a superseded replica inserts nothing and therefore dispatches
            // nothing. `ON CONFLICT DO NOTHING` is the other half — the step's own key admits one
            // claimant, whichever replica gets there first.
            let (job_id, owner, fence) =
                (lease.job_id().to_string(), lease.owner().to_string(), fence_of(lease));
            let (j, o, s) = (job_id.clone(), owner.clone(), step_id.to_string());
            let inserted = self.run(move |c| async move {
                c.execute(
                    "INSERT INTO hull_ci_step_claim (job_id, step_id, owner, fence, claimed_at_ms)
                     SELECT $1, $2, $3, $4, $5 FROM hull_ci_claim k
                     WHERE k.job_id = $1 AND k.fence = $4 AND k.owner = $3
                     ON CONFLICT (job_id, step_id) DO NOTHING",
                    &[&j, &s, &o, &fence, &now_ms],
                )
                .await
            })?;
            if inserted == 1 {
                return Ok(StepClaim::Granted);
            }

            // Nothing was inserted, and the two reasons need different answers — see [`StepClaim`].
            // This second query is a *diagnosis*, never a decision: whatever it says, this replica is
            // not dispatching the step, so a race with a third replica between the two statements can
            // only change the wording of a log line.
            let (j, s) = (job_id.clone(), step_id.to_string());
            let held = self.run(move |c| async move {
                c.query_opt(
                    "SELECT owner FROM hull_ci_step_claim WHERE job_id = $1 AND step_id = $2",
                    &[&j, &s],
                )
                .await
            })?;
            if let Some(row) = held {
                return Ok(StepClaim::Taken { by: row.get(0) });
            }

            let j = job_id.clone();
            let claim = self.run(move |c| async move {
                c.query_opt("SELECT owner FROM hull_ci_claim WHERE job_id = $1", &[&j]).await
            })?;
            Ok(match claim {
                Some(row) => StepClaim::Fenced { held_by: row.get(0) },
                // No row with our job id at all. Two things look like this and neither is
                // distinguishable from here: the claim was evicted past retention, or it was taken
                // over — a takeover mints a new job id, so ours simply stops existing. Both mean the
                // same thing to the caller and get the same answer (see [`StepClaim::Fenced`]).
                None => StepClaim::Fenced { held_by: hull_ci_control::claims::NO_CLAIM.into() },
            })
        }

        fn release_step(&self, lease: &DriveLease, step_id: &str) -> Result<(), ClaimError> {
            // Only our own claim, at our own fence. A replica that has been superseded must not be
            // able to release the claim its successor took.
            let (job_id, owner, fence) =
                (lease.job_id().to_string(), lease.owner().to_string(), fence_of(lease));
            let s = step_id.to_string();
            self.run(move |c| async move {
                c.execute(
                    "DELETE FROM hull_ci_step_claim
                     WHERE job_id = $1 AND step_id = $2 AND owner = $3 AND fence = $4",
                    &[&job_id, &s, &owner, &fence],
                )
                .await
            })?;
            Ok(())
        }

        fn settle(
            &self,
            lease: &DriveLease,
            verdict: &Verdict,
            now_ms: i64,
        ) -> Result<(), ClaimError> {
            let encoded = serde_json::to_string(verdict).map_err(|e| {
                ClaimError::Unavailable(format!("could not encode the verdict: {e}"))
            })?;
            let (job_id, owner, fence) =
                (lease.job_id().to_string(), lease.owner().to_string(), fence_of(lease));
            let n = self.run(move |c| async move {
                c.execute(
                    "UPDATE hull_ci_claim SET verdict = $2, settled_at_ms = $3
                     WHERE job_id = $1 AND owner = $4 AND fence = $5",
                    &[&job_id, &encoded, &now_ms, &owner, &fence],
                )
                .await
            })?;
            if n == 0 {
                // Fenced. We still hold and will still deliver this verdict — that is not in doubt —
                // but another replica now owns the tree and may produce its own. Spec §9 makes the
                // duplicate callback a re-affirmation rather than a conflict, so this is loud but not
                // fatal.
                tracing::error!(
                    alert = true, job_id = %lease.job_id(),
                    "our claim was taken over before this verdict could be published; \
                     the tree may be verified twice"
                );
            }
            Ok(())
        }

        fn destinations(&self, job_id: &str) -> Result<Vec<String>, ClaimError> {
            let j = job_id.to_string();
            let row = self.run(move |c| async move {
                c.query_opt("SELECT callback_urls FROM hull_ci_claim WHERE job_id = $1", &[&j]).await
            })?;
            Ok(row.map(|r| r.get::<_, Vec<String>>(0)).unwrap_or_default())
        }

        fn forget(&self, job_id: &str) {
            // **Structurally unable to forget somebody else's running job.** A settled claim is fair
            // game for anyone (its verdict is delivered or delivering, and losing it costs a re-run);
            // an unsettled one may only be dropped by the replica that holds it. Without that guard,
            // one replica's retention sweep could hand another replica's live tree to a second
            // dispatcher.
            //
            // The step claims go in the same statement, via the `DELETE … RETURNING` — so they can
            // only be dropped when the claim they belong to actually was. Two statements would leave
            // the door open for the second to run when the first had refused.
            let (j, owner) = (job_id.to_string(), self.owner.clone());
            let done = self.run(move |c| async move {
                c.execute(
                    "WITH gone AS (
                         DELETE FROM hull_ci_claim
                         WHERE job_id = $1 AND (verdict IS NOT NULL OR owner = $2)
                         RETURNING job_id
                     )
                     DELETE FROM hull_ci_step_claim s USING gone WHERE s.job_id = gone.job_id",
                    &[&j, &owner],
                )
                .await
            });
            if let Err(e) = done {
                // Infallible by contract — see the trait. A stale claim costs a duplicate dispatch
                // being told "already running" until it ages out of retention, which is bounded.
                tracing::warn!(%job_id, error = %e, "could not release this job's claim");
            }
        }
    }

    /// A stored verdict, or `None` if it will not parse.
    ///
    /// A row we cannot read is treated as an unsettled claim, which means a duplicate dispatch
    /// re-runs the tree rather than being answered from bytes we do not understand. Loud, because the
    /// only way this happens is a version of this runner writing a shape another version cannot read,
    /// and that is worth finding before it is the whole table.
    fn decode_verdict(raw: &str) -> Option<Box<Verdict>> {
        match serde_json::from_str::<Verdict>(raw) {
            Ok(v) => Some(Box::new(v)),
            Err(e) => {
                tracing::error!(error = %e, "a stored verdict could not be read; treating the claim as undecided");
                None
            }
        }
    }
}

/// The refusals, which need no database because they happen before one is opened.
#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config::default()
    }

    #[test]
    fn no_url_means_the_process_local_index_and_nothing_to_configure() {
        // The default path, and the one every existing deployment is on. It must not be able to fail.
        let claims = assemble(&config()).expect("the default assembles");
        assert_eq!(claims.owner(), "local");
        assert!(!claims.needs_renewal(), "and asks for no heartbeat");
    }

    #[test]
    fn a_shared_store_without_a_replica_id_refuses_to_start() {
        // No default is safe here. Two replicas sharing an identity would renew each other's leases
        // and release each other's step claims — a split brain that looks like correct bookkeeping,
        // which is worse than the outage this refusal causes.
        let config = Config { postgres_url: Some("postgres://x/y".into()), ..config() };
        let Err(err) = assemble(&config) else { panic!("must refuse") };
        let msg = err.to_string();
        assert!(msg.contains("HULL_CI_REPLICA_ID"), "the error has to name the fix: {msg}");
    }

    #[test]
    #[cfg(not(feature = "postgres"))]
    fn a_shared_store_on_a_binary_that_cannot_have_one_refuses_to_start() {
        // The failure this whole module exists to prevent must not be reachable by forgetting a
        // build flag. Falling back to the local index here would give an operator two replicas that
        // each believe they are alone: every tree run twice, and nothing in the logs saying so.
        let config = Config {
            postgres_url: Some("postgres://x/y".into()),
            replica_id: Some("replica-a".into()),
            ..config()
        };
        let Err(err) = assemble(&config) else { panic!("must refuse") };
        let msg = err.to_string();
        assert!(msg.contains("postgres"), "the error has to name the missing feature: {msg}");
    }
}

/// Live probes against a real Postgres — the only place the shared path is actually proved.
///
/// `#[ignore]`d like the container probes in `hull_ci_node`, so `cargo test` stays hermetic, and run
/// with:
///
/// ```text
/// docker run -d --name hullci-pg -e POSTGRES_PASSWORD=hullci -e POSTGRES_USER=hullci \
///            -e POSTGRES_DB=hullci -p 55440:5432 postgres:16
/// HULL_CI_TEST_POSTGRES=postgres://hullci:hullci@127.0.0.1:55440/hullci \
///   cargo test -p hull-ci-server --features postgres claims -- --ignored --test-threads=1
/// ```
///
/// # What these tests are careful about
///
/// **Every one of them uses two `PgClaims` on two connections**, and asserts that the second sees
/// what the first wrote. That is the point. A claim seam that compiles, is wired, and quietly serves
/// everything from process-local memory would pass any test with one replica in it, so no test here
/// has one: the property under test is always a fact one connection can only know because another
/// connection put it there.
///
/// **Nothing here asserts on elapsed time.** Lease expiry is exercised by passing a larger `now_ms`,
/// never by sleeping — the trait takes the caller's clock precisely so that this is possible. Where a
/// test has to wait for an asynchronous driver it polls for the *state* it needs and fails on a
/// generous ceiling, which is synchronisation rather than a timing assertion.
///
/// **Rows are namespaced per test.** One database, one schema, and a `(repo, tree_id)` unique to each
/// test, so the suite exercises the same tables production would rather than a private copy each.
#[cfg(all(test, feature = "postgres"))]
mod live_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    use hull_ci_control::callback::{
        BoxFuture, CallbackRequest, CallbackResponse, CallbackTransport, TransportError,
    };
    use hull_ci_control::claims::{now_ms, Admitted, DriveLease, StepClaim, TreeKey};
    use hull_ci_control::seams::{
        FetchError, FetchRequest, Fetcher, Membership, PlanError, Planner, VerifiedTree,
    };
    use hull_ci_control::model::StepSpec;
    use hull_ci_control::{Control, ControlConfig, Deps};
    use hull_ci_proto::{AuthorClass, Dispatch};

    /// The database to run against, or `None` when the probe should be skipped.
    ///
    /// Read from the environment rather than hard-coded so the port a developer's container happens
    /// to be on is not baked into the source.
    fn url() -> String {
        std::env::var("HULL_CI_TEST_POSTGRES").expect(
            "set HULL_CI_TEST_POSTGRES to a postgres:// url — see this module's docs for the \
             `docker run` line",
        )
    }

    fn claims(replica: &str) -> PgClaims {
        PgClaims::connect(&url(), replica.to_string()).expect("connects to the test database")
    }

    /// Names no other test — and no *previous run* of this suite — uses.
    ///
    /// Both halves matter, and the second is the one that is easy to miss: these tests share one
    /// database with every run before them, and `job_id` is globally unique in `hull_ci_claim`, so a
    /// fixed id would pass once and then fail forever on a constraint that has nothing to do with
    /// what is being tested.
    fn unique(what: &str) -> String {
        static N: AtomicU64 = AtomicU64::new(0);
        format!("{what}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed))
    }

    fn key(what: &str) -> TreeKey {
        TreeKey::new(format!("acme/{what}"), format!("tree-{}", unique(what)))
    }

    fn job(tag: &str) -> String {
        format!("job_{}", unique(tag).replace('-', "_"))
    }

    const LEASE_MS: i64 = 60_000;
    const RETENTION_MS: i64 = 60 * 60 * 1000;

    fn admit(c: &PgClaims, k: &TreeKey, job: &str, url: &str, at: i64) -> Admitted {
        c.admit(k, job, url, at, LEASE_MS, RETENTION_MS).expect("the claim store answers")
    }

    // ── The acceptance tests ─────────────────────────────────────────────────────────────────────

    #[test]
    #[ignore = "requires a running postgres (see this module's docs)"]
    fn one_tree_is_one_job_however_many_replicas_are_asked() {
        // Spec §9 across a process boundary. Two replicas, two connections, one row: whichever
        // inserts first owns the job, and the other is told that job's id rather than minting one.
        //
        // The second half is what makes it more than a unique index: **both dispatchers' callback
        // URLs are on the claim**, put there by two different connections. Work is deduplicated by
        // `(repo, tree_id)`; delivery is not, and the replica that eventually answers may be neither
        // of the two that see this row today.
        let a = claims("replica-a");
        let b = claims("replica-b");
        let k = key("one-job");
        let now = now_ms();

        let (ja, jb, jb2) = (job("a"), job("b"), job("b"));

        let first = admit(&a, &k, &ja, "https://one/cb", now);
        let second = admit(&b, &k, &jb, "https://two/cb", now);

        let lease = match &first {
            Admitted::Created { lease } => lease.clone(),
            other => panic!("the first admit must create the job, got {other:?}"),
        };
        assert_eq!(lease.job_id(), ja);
        match &second {
            Admitted::Attached { job_id, owner, verdict } => {
                assert_eq!(job_id, &ja, "the loser is told the winner's id");
                assert_eq!(owner, "replica-a", "and who holds it");
                assert!(verdict.is_none(), "nothing has been decided yet");
            }
            other => panic!("the second admit must attach, got {other:?}"),
        }

        // Read back over **a third connection**, so the assertion cannot be satisfied by either
        // writer's own memory.
        let observer = claims("replica-c");
        let mut dests = observer.destinations(&ja).expect("destinations read");
        dests.sort();
        assert_eq!(
            dests,
            vec!["https://one/cb".to_string(), "https://two/cb".to_string()],
            "both dispatchers must be answered, whichever replica ends up delivering"
        );

        // And the verdict travels the same way: replica A decides, replica B answers a later
        // duplicate from the claim without running a single step.
        a.settle(&lease, &hull_ci_proto::Verdict::green("42 tests, 0 failed"), now)
            .expect("the verdict publishes");
        match admit(&b, &k, &jb2, "https://three/cb", now) {
            Admitted::Attached { verdict: Some(v), .. } => {
                assert_eq!(v.summary.as_deref(), Some("42 tests, 0 failed"));
            }
            other => panic!("a settled claim must hand back its verdict, got {other:?}"),
        }
    }

    #[test]
    #[ignore = "requires a running postgres (see this module's docs)"]
    fn two_replicas_cannot_both_claim_one_step() {
        // The guarantee that stops a step running twice, tested the only way that means anything:
        // two connections presenting the **same valid lease** for the same step. Nothing about the
        // credential distinguishes them, so if the exclusion is anywhere but in the database, both
        // get to dispatch.
        //
        // Asserted on the row, not on which call happened to win — the point is that exactly one did.
        let a = claims("replica-a");
        let b = claims("replica-b");
        let k = key("one-step");
        let now = now_ms();

        let ja = job("a");
        let Admitted::Created { lease } = admit(&a, &k, &ja, "https://one/cb", now) else {
            panic!("the first admit must create the job");
        };

        let first = a.claim_step(&lease, "step_00", now).expect("claim answers");
        let second = b.claim_step(&lease, "step_00", now).expect("claim answers");

        let granted = [&first, &second].iter().filter(|c| **c == &StepClaim::Granted).count();
        assert_eq!(granted, 1, "exactly one replica may dispatch a step: {first:?} / {second:?}");
        let refused = if first == StepClaim::Granted { &second } else { &first };
        assert!(
            matches!(refused, StepClaim::Taken { .. }),
            "and the other is told it is taken, not fenced: {refused:?}"
        );

        // A different step of the same job is unaffected — the claim is per step, not a lock on the
        // job, or a pipeline that fans out would serialize.
        assert_eq!(b.claim_step(&lease, "step_01", now).unwrap(), StepClaim::Granted);

        // The other mechanism, and the one that survives a replica coming back from the dead: a
        // lease at a stale fence claims nothing at all. Fence 1 is current here, so 99 is a replica
        // that believes it still drives a job it was superseded on.
        let stale = DriveLease::issued(&ja, "replica-a", 99);
        let out = b.claim_step(&stale, "step_02", now).expect("claim answers");
        assert!(matches!(out, StepClaim::Fenced { .. }), "a stale fence claims nothing: {out:?}");
    }

    #[test]
    #[ignore = "requires a running postgres (see this module's docs)"]
    fn a_replica_that_dies_holding_a_tree_does_not_hold_it_forever() {
        // The recovery bound, stated exactly. A replica that dies mid-job leaves an unsettled claim
        // on `(repo, tree_id)`; without expiry, a forced re-check would be told "already running"
        // about a job nobody is driving, and spec §10 leaves that tree wedged permanently — the one
        // failure mode a human cannot get out of by re-checking.
        //
        // **What the bound is:** one lease TTL, evaluated when the next dispatch arrives. There is no
        // sweeper in this phase, so nothing reclaims a dead claim in the absence of traffic, and
        // nothing re-runs the dead replica's job either — the claim deliberately carries no
        // `source_url` (spec §14.2), so a new dispatch is the only thing that can start the work
        // again. Recovering the *debt* for the job that died is still the journal's, on that
        // replica's own next start.
        let a = claims("replica-a");
        let b = claims("replica-b");
        let k = key("dead-replica");
        let now = now_ms();

        let (ja, jb, jb2) = (job("a"), job("b"), job("b"));
        let Admitted::Created { lease } = admit(&a, &k, &ja, "https://one/cb", now) else {
            panic!("the first admit must create the job");
        };
        a.claim_step(&lease, "step_00", now).expect("claim answers");

        // Replica A stops existing here. Inside the lease, the tree is still A's and B must not
        // touch it — a live replica being adopted mid-job is the failure in the other direction.
        match admit(&b, &k, &jb, "https://two/cb", now + LEASE_MS / 2) {
            Admitted::Attached { job_id, .. } => assert_eq!(job_id, ja),
            other => panic!("a live claim must not be taken over, got {other:?}"),
        }

        // Past the lease, the tree is dispatchable again. No sleeping: the clock is the caller's.
        let after = admit(&b, &k, &jb2, "https://three/cb", now + LEASE_MS + 1);
        let Admitted::Created { lease: b_lease } = after else {
            panic!("an expired claim must be takeable, got {after:?}");
        };
        assert_eq!(b_lease.job_id(), jb2, "B drives its own job for this tree");
        assert!(b_lease.fence() > lease.fence(), "and at a higher fence than the replica it replaced");

        // The dispatchers who were still waiting come along: they were never answered, so their URLs
        // are the new job's to deliver to.
        let mut dests = b.destinations(&jb2).expect("destinations read");
        dests.sort();
        assert_eq!(
            dests,
            vec![
                "https://one/cb".to_string(),
                "https://three/cb".to_string(),
                "https://two/cb".to_string()
            ]
        );

        // And A, if it ever wakes up, is fenced out of everything — before it can reach the fleet.
        assert!(!a.renew(&lease, now + LEASE_MS + 2, LEASE_MS).unwrap(), "its lease is gone");
        let out = a.claim_step(&lease, "step_01", now + LEASE_MS + 2).expect("claim answers");
        assert!(matches!(out, StepClaim::Fenced { .. }), "and it can dispatch nothing: {out:?}");
    }

    // ── The same thing, one level up: two whole control planes ───────────────────────────────────

    /// Blocks in `fetch` until released, so a second dispatch can be made to arrive while the first
    /// job is genuinely in flight rather than by hoping the scheduler cooperates.
    struct GatedFetcher(Arc<tokio::sync::Semaphore>);

    impl Fetcher for GatedFetcher {
        fn fetch<'a>(&'a self, req: &'a FetchRequest) -> BoxFuture<'a, Result<VerifiedTree, FetchError>> {
            let gate = Arc::clone(&self.0);
            let tree_id = req.tree_id.clone();
            Box::pin(async move {
                let _permit = gate.acquire().await.expect("the gate is not closed");
                Ok(VerifiedTree {
                    // A path nothing opens: the control plane never reads a workspace (spec §14.1).
                    tree_id,
                    path: std::path::PathBuf::from("/nonexistent/control-plane-never-opens-this"),
                    cached: false,
                    keep_alive: None,
                })
            })
        }
    }

    /// No steps, so the job decides `errored`/`no_tests` the moment it is planned. The pipeline under
    /// test here is admission and delivery, not the fleet.
    struct NoSteps;
    impl Planner for NoSteps {
        fn plan<'a>(&'a self, _t: &'a VerifiedTree) -> BoxFuture<'a, Result<Vec<StepSpec>, PlanError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    struct Everyone;
    impl Membership for Everyone {
        fn classify(&self, _repo: &str, _author: &str) -> AuthorClass {
            AuthorClass::Member
        }
    }

    /// Records every URL a verdict was actually POSTed to.
    #[derive(Default)]
    struct Recorder(Mutex<Vec<String>>);

    impl Recorder {
        fn urls(&self) -> Vec<String> {
            let mut v = self.0.lock().unwrap().clone();
            v.sort();
            v
        }
    }

    impl CallbackTransport for Recorder {
        fn post<'a>(
            &'a self,
            req: &'a CallbackRequest,
        ) -> BoxFuture<'a, Result<CallbackResponse, TransportError>> {
            self.0.lock().unwrap().push(req.url.clone());
            Box::pin(async { Ok(CallbackResponse { status: 200 }) })
        }
    }

    fn control(claims: Arc<dyn JobClaims>, transport: Arc<Recorder>, gate: Arc<tokio::sync::Semaphore>) -> Arc<Control> {
        Control::new(
            ControlConfig::default(),
            Deps {
                fetcher: Arc::new(GatedFetcher(gate)),
                planner: Arc::new(NoSteps),
                node: Arc::new(hull_ci_control::seams::UnwiredNodes),
                transport,
                membership: Arc::new(Everyone),
                journal: Arc::new(hull_ci_control::NoJournal),
                claims,
            },
        )
    }

    fn dispatch(k: &TreeKey, callback_url: &str) -> Dispatch {
        Dispatch {
            repo: k.repo.clone(),
            change: "21ea2242186c99ff".into(),
            tree_id: k.tree_id.clone(),
            intent: "fixes #6".into(),
            author: "justin".into(),
            source_url: "https://hull.example/tree/tar".into(),
            callback_url: callback_url.into(),
            fetch_token: None,
        }
    }

    /// Poll for a state rather than sleeping for a duration. Not a timing assertion: the ceiling is
    /// only there so a broken build fails instead of hanging.
    async fn wait_until(mut done: impl FnMut() -> bool) -> bool {
        for _ in 0..600 {
            if done() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires a running postgres (see this module's docs)"]
    async fn two_control_planes_over_one_database_run_one_job_and_answer_both_callers() {
        // The whole phase, end to end. Two `Control`s that share nothing but a database:
        //
        //   * the same `(repo, tree_id)` dispatched to both produces **one** job — replica B never
        //     starts a driver, never fetches, and never plans;
        //   * and **both** dispatchers get the verdict, delivered by the replica that computed it,
        //     to a URL it only knows because the other replica's connection wrote it down.
        //
        // The second bullet is the one that cannot pass by accident. If the destination set were
        // still read from process-local memory, replica A would deliver to exactly one URL and this
        // test would fail — which is precisely what it was checked against.
        let k = key("two-planes");
        let gate = Arc::new(tokio::sync::Semaphore::new(0));

        let recorder_a = Arc::new(Recorder::default());
        let a = control(Arc::new(claims("replica-a")), Arc::clone(&recorder_a), Arc::clone(&gate));
        let recorder_b = Arc::new(Recorder::default());
        let b = control(Arc::new(claims("replica-b")), Arc::clone(&recorder_b), Arc::clone(&gate));

        // A takes the tree and blocks in `fetch`, so the job is genuinely in flight.
        let first = a.accept(dispatch(&k, "https://one/cb")).expect("accepted");
        assert!(!first.duplicate, "the first dispatch for a tree is new work");

        // B is handed the same tree with a different destination.
        let second = b.accept(dispatch(&k, "https://two/cb")).expect("accepted");
        assert!(second.duplicate, "the second replica must recognise the tree as already claimed");
        assert_eq!(second.job_id, first.job_id, "one tree, one job, across two processes");
        assert_eq!(b.job_state(&second.job_id), None, "and B holds no record of work it is not doing");

        // Let A finish. An empty plan decides immediately, so there is no fleet in this path.
        gate.add_permits(1);
        let ctrl = Arc::clone(&a);
        let id = first.job_id.clone();
        assert!(
            wait_until(move || ctrl.verdict(&id).is_some()).await,
            "A must reach a verdict"
        );

        let ctrl = Arc::clone(&a);
        let id = first.job_id.clone();
        assert!(
            wait_until(move || {
                ctrl.job_state(&id) == Some(hull_ci_control::model::JobState::Reported)
            })
            .await,
            "A must finish delivering"
        );

        assert_eq!(
            recorder_a.urls(),
            vec!["https://one/cb".to_string(), "https://two/cb".to_string()],
            "the replica that computed the verdict answers both dispatchers"
        );
        assert!(recorder_b.urls().is_empty(), "and the other replica sends nothing of its own");
    }
}
