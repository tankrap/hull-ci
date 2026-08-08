//! The internal content store: verified trees on disk, keyed by `(tenant, tree_id)`, with each
//! tenant's file contents held **once** and shared by every tree of that tenant that contains them.
//!
//! Three jobs:
//!
//! 1. **Fetch once per tree, not once per node** (design D§4.2). A 12-way sharded test step must not
//!    pull the same archive from Hull twelve times, so the first thing [`FetchBroker`] does is ask
//!    this store whether the tree is already here. Content addresses are immutable, so a hit is
//!    always safe — there is no invalidation question, only GC.
//! 2. **Keep tenants apart.** The key is `(tenant, tree_id)`, never `tree_id` alone — and, since
//!    M4, the key of a *blob* is `(tenant, content, mode)`, never `(content, mode)` alone.
//! 3. **Store each of a tenant's files once** (design D§4.2, the M4 dedup item). Two trees that
//!    differ by one file used to cost two whole checkouts of disk. The product thesis is that CI is
//!    dominated by bytes you already have, and a store that copies a 400 MiB checkout per commit is
//!    that thesis' most direct contradiction.
//!
//! **Cross-tenant dedup is not a setting.** Two tenants holding byte-identical trees get two copies.
//! Sharing them would save disk and hand out an oracle: a tenant could learn that *somebody else*
//! holds a given tree — by timing a fetch, by a store hit on a tree they never pushed — which for a
//! content-addressed store means learning that a specific file exists somewhere in the fleet. Repo
//! contents, and the fact of a proprietary dependency, leak that way. Design D§4.2/D7 makes this a
//! hard rule, so the API does not offer a tenant-free lookup at all: there is no `has(tree_id)` to
//! call by mistake, and no blob path that can be computed without a tenant.
//!
//! # Layout
//!
//! ```text
//! {root}/{tenant_scope}/
//!     trees/{tree_id}/…                 one directory per tree — unchanged, see below
//!     blobs/{ab}/{cdef…}.{644|755}      one file per distinct (content, mode) this tenant holds
//!     staging/                          scratch: in-flight downloads and half-extracted trees
//!     used/{tree_id}                    when each tree was last used — see "Reclamation" below
//!     reclaiming/                       scratch: trees and blobs on their way out
//! ```
//!
//! **A tree is still a full directory**, and that is the point of the design rather than a leftover
//! of it. Every reader above this module — [`crate::verify`]'s re-hash, [`crate::digest`]'s index
//! walk, `hull-ci-server`'s workspace materializer, and any future `tar` of a stored tree — walks an
//! ordinary directory and needs to know nothing about blobs. Dedup lives *below* the directory
//! entry, at the inode: a tree entry and its blob are two names for one file. Nothing above the
//! filesystem needs a manifest format, a reference index, or a second code path, and no reader can
//! be broken by a dedup bug that a plain `ls` would not also show. (This is the M1 note that used to
//! be here promising "directory-per-tree, simple by choice": the directory stayed, the second copy
//! of the bytes did not.)
//!
//! The blob store sits **inside the tenant scope**, next to `staging` and `trees`, for a mechanical
//! reason as well as the privacy one: `link(2)` cannot cross a filesystem, so putting blobs where
//! they are guaranteed to be on the same device as both staging and trees is what makes the sharing
//! mechanism available at all. A second configurable root would make `EXDEV` the normal case.
//!
//! `{ab}` is the first byte of the content address, hex — a 256-way fan-out. One level, not two:
//! a tenant holding ten million distinct files puts ~40k entries in a shard directory, which every
//! filesystem this runs on indexes rather than scans, while two levels would cost 65k `mkdir`s to
//! reach the same place. The shard exists so a tenant's blob count never lands as one flat directory
//! of millions of entries, which is where `readdir` and directory locking actually fall over.
//!
//! # Why a hard link here, when `workspace.rs` argues the opposite
//!
//! `hull-ci-server`'s workspace materializer refuses hard links in the strongest terms and uses a
//! copy-on-write clone instead. Same mechanism, opposite verdict, and both are right, because the
//! two destinations differ in exactly the property that matters:
//!
//! * **A workspace is written to, by definition.** It exists so `cargo test` can create `target/`
//!   and a hostile tree can do whatever it likes. A second name for the store's inode means the
//!   job's first `>`, `chmod +x` or `truncate` edits the stored tree in place, and a directory whose
//!   *name is a content address* stops hashing to its name — silently, for every later job.
//! * **A store tree is never written to, by contract.** Its path *is* a content address; the whole
//!   reason `workspace.rs` exists is so that no job ever holds a writable handle to one. Nothing in
//!   this process opens a stored tree for writing, and the extractor's own destination is a staging
//!   directory that no reader can see.
//!
//! So a hard link inside the store aliases inodes that are only ever read, while a hard link into a
//! workspace aliases an inode that is about to be written. Sharing an immutable thing is free;
//! sharing a mutable one is corruption. The dangerous case has a test in `workspace.rs`
//! (`a_write_in_one_workspace_cannot_reach_a_second_tree_that_shares_the_blob`) that specifically
//! covers this feature's new stake in it: before dedup, a job that corrupted a store tree ruined one
//! tree; now it would ruin every tree sharing the blob. The CoW clone is what keeps that hypothetical.
//!
//! # What a blob is keyed on, and why the mode is in the key
//!
//! A blob's key is the pair `(blob_id, mode)` — keel's content address for the bytes, and keel's
//! mode class for the file — which is exactly the pair a keel `TreeEntry` records (see
//! [`crate::verify::blob_id`]). Two entries agreeing on that pair are indistinguishable to every
//! tree address in the system, so giving them one inode cannot change what any tree hashes to.
//!
//! The mode is in the key because **a hard link shares an inode and an inode carries the mode**.
//! Key on content alone and the second tree to arrive with `run.sh` at 0644 would take a link to the
//! 0755 inode — flipping the executable bit of a file whose exec bit keel *addresses*. The tree
//! would then hash to something other than the `tree_id` it is filed under: verification passed, and
//! the store quietly broke it afterwards. With the mode in the key, the two are different paths and
//! therefore different inodes, and the failure cannot be written.
//!
//! A file's mode is normalized to the canonical `0644`/`0755` for its class *before* it becomes a
//! blob, so a blob's mode is a function of its key rather than of whichever tree happened to arrive
//! first. [`crate::extract`] already normalizes to those two values for its own reasons, so for
//! every real fetch this changes nothing; it is here so the invariant does not depend on the caller.
//! Both values map to the same keel mode class, so normalizing can never move a tree's address.
//!
//! # Reclamation
//!
//! [`ContentStore::reclaim`] is the GC the sentence above ("there is no invalidation question, only
//! GC") has always referred to. It has two halves, in this order and for a reason:
//!
//! 1. **Trees go by retention.** A tree nothing has used for [`ReclaimPolicy::tree_retention`] is
//!    renamed out of the addressed namespace and deleted.
//! 2. **Blobs go by link count.** Once the trees are gone, a blob with `st_nlink == 1` is named by
//!    the blob store and by nothing else, which is precisely "referenced by no tree". That is a
//!    consequence of the layout rather than a bookkeeping claim, so there is no reference index to
//!    build, to persist, or to get wrong — and no way for the index and the filesystem to disagree,
//!    which is the failure mode every hand-rolled refcount eventually has.
//!
//! **Removing a tree returns almost no disk on its own.** Its regular files are links; unlinking one
//! frees a directory entry and nothing else. The bytes come back when the *last* link goes, which is
//! the blob sweep, and that is why [`ReclaimReport::bytes_reclaimed`] counts blob bytes only. A
//! report of "40 trees removed, 0 bytes" is not a bug — it is a run where every one of those trees'
//! files is still held by a tree that survived.
//!
//! ## "Last used" is recorded, never inferred from the filesystem
//!
//! Each tree has a stamp at `{tenant_scope}/used/{tree_id}` holding the milliseconds since the Unix
//! epoch at which the tree was last handed out. Three choices in that sentence are load-bearing:
//!
//! * **Not `atime`.** `relatime` is the default mount option on Linux and `noatime` is a common
//!   tuning; on either, a tree read a thousand times a day carries the access time of its first read
//!   or of its creation. Retention keyed on `atime` would therefore be silently wrong in whichever
//!   direction the mount happened to be set — a no-op on a machine that updates it eagerly, and a
//!   reaper that deletes the hottest trees on a machine that does not. Neither failure announces
//!   itself.
//! * **Not inside the tree.** A file under `{tree_id}/` is an entry of a directory whose *name is a
//!   content address*: the tree would stop hashing to the id it is filed under the moment it was
//!   stamped. The stamp lives beside the tree for the same reason the dedup scratch link does.
//! * **A written timestamp, not the stamp file's `mtime`.** `mtime` granularity is one second on
//!   some filesystems, which makes a test either slow or flaky, and an operator debugging retention
//!   can `cat` a number. The value is what is compared; the file is just where it lives.
//!
//! The stamp is written wherever a **hit** happens ([`ContentStore::open`]) and not only where a
//! commit happens. A tree fetched once and hit every day for a year is, on its commit date, a year
//! stale and, on its use date, current — and the whole point of the store is that the second number
//! is the one that predicts whether it will be wanted again. [`ContentStore::has`] deliberately does
//! *not* stamp: it is a probe, and a diagnostic that renews a lease is its own kind of lie.
//!
//! A missing or unparseable stamp is treated as **just used** and rewritten, so a tree that predates
//! this feature, or whose stamp was lost, gets a full retention window rather than being deleted on
//! the first sweep. Wall clock, so an NTP step backwards makes a tree look newer than it is: that
//! costs disk, never a job, because retention is not what protects a running job — see below.
//!
//! ## What protects a job that is already running: a pin, not a grace period
//!
//! `hull-ci-server`'s workspace materializer opens a store tree when a **step** starts, and a job can
//! sit in the queue between its fetch and its first step for as long as the queue is deep. Deleting
//! that tree in the meantime breaks a job that was already admitted, and it breaks it late and
//! confusingly — the fetch said `cached: true`, and the failure surfaces as a materialize error on a
//! path that verified minutes ago.
//!
//! A long retention does **not** fix this, and it is worth being blunt about why, because it is the
//! fix that looks sufficient. Retention is measured from the last *use*, which for a queued job is
//! the moment of the fetch — before the wait, not during it. So the protection it offers is exactly
//! "retention > queue wait + step duration", a comparison between a storage setting and a scheduling
//! outcome that no code enforces and nothing checks: the two are configured in different files, by
//! different people, for different reasons. Under a backlog the queue wait is bounded only by the
//! job timeout, which an operator may well set larger than a storage retention. A grace period makes
//! the failure rare and load-dependent, which is worse than making it common, because it will first
//! occur on the busiest day.
//!
//! The protection is therefore a **pin** ([`ContentStore::pin`], [`TreePin`]): an explicit, RAII
//! declaration that somebody is using this tree. [`reclaim`](ContentStore::reclaim) skips a pinned
//! tree at any age, and says so in [`ReclaimReport::trees_pinned`] rather than silently. Every path
//! that hands out a tree takes one — [`ContentStore::open`] returns it and [`StoredTree`] carries it
//! — so holding the value you were given *is* holding the tree, and there is no separate call for a
//! caller to forget.
//!
//! The check and the removal happen under one lock. Reading the pin count and then renaming would
//! leave a window in which a hit lands on a tree already condemned, so `reclaim` holds the pin
//! table's lock across the rename and `open` takes its pin *before* it tests for the directory —
//! whichever gets the lock first, the other sees a consistent answer (an absent tree, or a pinned
//! one), and never a pin on a tree that is about to go.
//!
//! The pin is **process-local**: it lives in memory, shared by every clone of a [`ContentStore`] but
//! not by two `ContentStore` values, and not across processes. The composition root builds exactly
//! one (`hull-ci-server`'s `lib.rs`), so within this runner that is the whole store; a second process
//! pointed at the same root would sweep without seeing any of these claims, and the day that becomes
//! a configuration, this is the thing that has to grow a lock file.
//!
//! ## Who holds the pin, all the way to the last read
//!
//! A claim nobody holds protects nothing, so the pin is carried the full length of a job rather than
//! handed back at the fetch:
//!
//! 1. [`Self::open`] takes it and [`StoredTree`] carries it.
//! 2. `hull-ci-server`'s `BrokerFetcher` moves it into the control plane's `VerifiedTree` as an
//!    **opaque** keep-alive (`Arc<dyn Any + Send + Sync>`). Opaque because `hull-ci-control` must not
//!    name a type from this crate — the seams are traits precisely to keep that dependency edge from
//!    existing — and it does not need to: its entire contract is not to drop the value.
//! 3. `Control` holds that `VerifiedTree` in its per-job map from before the first step is pending
//!    until `retire`, which spans the whole queue wait — the window a retention clock cannot cover,
//!    because retention is measured from the fetch and the wait happens after it.
//! 4. Each placement gets a clone, and the node's run owns the whole `VerifiedTree` rather than just
//!    its path, so the guard cannot be lost without also losing the thing being read. That last hop
//!    matters because a step's materialize is `spawn_blocking` work: `abort` cannot stop it, so it
//!    can still be walking the tree after its job has been retired.
//!
//! Clones share one claim, so those four holders add up to a single lifetime that ends when the last
//! of them goes.
//!
//! ## The commit/sweep race, and what it actually costs
//!
//! A blob can gain a link between the sweep's `stat` and its unlink — [`ContentStore::share_one`]
//! links an existing blob into a tree it is publishing, and nothing serializes that against a sweep.
//! Deleting a blob a commit just linked to does **not** lose data: the commit's tree entry is a
//! second name for the same inode, so the bytes and the tree survive intact and the tree still hashes
//! to its id. What is lost is *dedup* — the next tree with those bytes creates a fresh blob and stores
//! them a second time.
//!
//! The window is narrowed rather than argued away, in two places:
//!
//! * The sweep does not unlink a candidate; it **renames** it into scratch, re-`stat`s it there, and
//!   only then deletes it. The rename takes the blob's name out of circulation atomically, so after
//!   it no commit can link to that inode through the blob store at all; and if the re-`stat` shows a
//!   link somebody won just before the rename, the blob is linked back into place
//!   ([`ReclaimReport::blobs_restored`]) instead of destroyed.
//! * A commit whose blob vanishes underneath it (`ENOENT` on the reuse link) retries the create path
//!   once, so it becomes the blob rather than falling back to a private copy.
//!
//! What remains, stated plainly: a commit that loses both of those — the blob is renamed away after
//! its `EEXIST` and its retry also loses — stores that one file unshared. It is a few bytes on a rare
//! interleaving, it is reported as [`DedupReport::unshared`] rather than hidden, and it is repaired
//! by the next commit of the same content. There is no lock here and this is not a guarantee that a
//! blob is never dropped from under a commit; it is a bound on what that costs.
//!
//! Two `reclaim`s running at once do not fail each other. Every removal treats `ENOENT` as "somebody
//! else got there first", which is a normal outcome and not an error, and the rename is what
//! arbitrates: exactly one caller can rename a given tree or blob away, so a tree is counted removed
//! exactly once no matter how many sweeps are running.
//!
//! ## What still has to happen for any of this to run
//!
//! One thing: **nothing calls [`reclaim`](ContentStore::reclaim).** There is no timer, no background
//! task and no size ceiling wired to it, so the store still grows without bound. When it gets
//! called, and against what policy, is a composition-root decision; this module is the mechanism,
//! and — since the pin now reaches the last read — a mechanism that is safe to switch on.
//!
//! Two smaller things are still not reclaimed by anything, and are named here rather than implied
//! away: a `staging/` directory orphaned by a `SIGKILL` between `stage()` and `commit()`, and a
//! `reclaiming/` scratch directory orphaned the same way. Both are bounded by how often the process
//! is killed mid-operation rather than by how long it runs, which is why they are a different and
//! much smaller problem than the one above.
//!
//! [`FetchBroker`]: crate::FetchBroker

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use keel_store::snapshot::MODE_EXEC;

/// A verified tree in the store.
#[derive(Debug, Clone)]
pub struct StoredTree {
    pub tree_id: String,
    /// Directory holding the extracted tree. Read-only as far as the broker is concerned; nodes
    /// materialize their own workspace from it. Since M4 its regular files are shared with the
    /// tenant's blob store, which makes "read-only" load-bearing rather than merely tidy.
    pub path: PathBuf,
    /// True when the tree was already present — the fetch, extract and verify were all skipped.
    pub cached: bool,
    /// What publishing this tree did to its files, or `None` when this call published nothing
    /// (`cached`). Not folded into a zeroed report, because "we shared nothing" and "we did nothing"
    /// are the two states a dedup layer must never be allowed to confuse — the first is the silent
    /// regression this feature is most likely to suffer.
    pub dedup: Option<DedupReport>,
    /// Keeps [`ContentStore::reclaim`] off this tree for as long as this value lives.
    ///
    /// A field rather than a separate `store.pin(…)` call the caller has to remember, because the
    /// caller who forgets is not punished at the point of the mistake: the tree survives every test,
    /// every quiet day and every shallow queue, and is deleted under a backlog on the one occasion a
    /// job waited longer than the retention. Holding the value you were handed is the whole protocol.
    ///
    /// Cloning a `StoredTree` shares one pin rather than taking a second, so the tree is protected
    /// until the *last* clone goes.
    pub pin: TreePin,
}

/// A live claim on `(tenant, tree_id)`: while one exists, [`ContentStore::reclaim`] will not remove
/// that tree at any age.
///
/// RAII, refcounted, and `Clone` — the count is shared between clones, so a pin released is a pin
/// whose last holder dropped it. See the module docs for why a claim rather than a longer retention,
/// and for the one limit on what this claim means: it is process-local, so it is a statement about
/// this runner and not about a second process pointed at the same store root.
///
/// It says nothing about whether the tree *exists*: it is a claim on the address, so it is safe to
/// take before the check that the directory is there ([`ContentStore::open`] relies on exactly that
/// ordering), and safe to hold across a commit that is still staging.
#[derive(Debug, Clone)]
pub struct TreePin(
    // Never read, and that is the point: the claim is registered when this is created and released
    // when the last clone of it drops, so the field's entire value is its destructor.
    #[allow(dead_code)] Arc<PinGuard>,
);

/// The half of a [`TreePin`] that has a destructor. Separate so that cloning the pin shares one
/// registration instead of making another.
#[derive(Debug)]
struct PinGuard {
    pins: Arc<PinTable>,
    key: PinKey,
}

impl Drop for PinGuard {
    fn drop(&mut self) {
        let mut held = PinTable::lock(&self.pins.held);
        if let Some(n) = held.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                // Removed rather than left at zero: the table is keyed by tenant scope and tree id,
                // so a store that only ever decremented would keep one entry per tree it had ever
                // served — an unbounded map inside the fix for an unbounded directory.
                held.remove(&self.key);
            }
        }
    }
}

/// `(tenant_scope, tree_id)` — the same key the filesystem uses, so a pin cannot be taken out on one
/// tenant's tree and honoured for another's.
type PinKey = (String, String);

/// Which trees are in use, in this process.
///
/// Shared by every clone of a [`ContentStore`] — the broker is `Clone` and the server clones it per
/// task, and a pin table that cloned with it would protect nothing.
#[derive(Debug, Default)]
struct PinTable {
    held: Mutex<HashMap<PinKey, usize>>,
}

impl PinTable {
    /// A panic somewhere else in the process must not wedge the store: a poisoned pin table is
    /// recovered rather than propagated. The invariant it holds is a counter, and the worst a
    /// half-updated one can do is keep a tree alive longer than necessary.
    fn lock(m: &Mutex<HashMap<PinKey, usize>>) -> std::sync::MutexGuard<'_, HashMap<PinKey, usize>> {
        m.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// What one publish did with a tree's files, so **sharing is a reported fact rather than an
/// inference**.
///
/// The failure this exists to prevent: a dedup layer that silently stops deduping still passes every
/// correctness test, because the trees are all still right — only fat. Counts alone would be the
/// implementation's own claim about itself, so the tests below assert these *and* inode identity and
/// link counts; the report is what makes an operator (and a regression) able to see the difference
/// between a store that is sharing and one that is not. `workspace.rs`'s `MaterializeReport` exists
/// for the same reason pointing the other way.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DedupReport {
    /// Regular files that *became* a blob: this tenant held no file with that (content, mode) yet.
    pub blobs_created: usize,
    /// Regular files replaced by a link to a blob the tenant already had. This is the saving: each
    /// one is a file's worth of bytes not written, counting duplicates inside a single tree too.
    pub blobs_reused: usize,
    /// Regular files left as their own private copy because the filesystem refused to link them.
    /// Correct, just fat — see [`ContentStore::share_one`] for why this is not an error.
    pub unshared: usize,
    /// Why the first `unshared` file happened, if any. The first rather than the last, and only one:
    /// a filesystem that cannot link fails identically for every file, and the hundred-thousandth
    /// copy of the reason says nothing the first did not.
    pub unshared_reason: Option<String>,
    /// Symlinks left exactly as the extractor made them. Never blobs — see [`ContentStore::share_one`].
    pub symlinks: usize,
    /// Directories walked (excluding the tree root itself).
    pub directories: usize,
}

/// When a tree stops being worth keeping.
///
/// `now` is a parameter rather than a call to the clock, for the same reason
/// `hull_ci_control::store::JobStore::evict` takes one: a retention decision that reads the clock
/// itself can only be tested by sleeping, and this repository already has one flaky timing test.
/// Every retention property below is asserted on an injected instant instead.
#[derive(Debug, Clone, Copy)]
pub struct ReclaimPolicy {
    /// How long a tree survives after its last use. Measured from the **use** stamp, not from the
    /// commit — see the module docs on why a tree that keeps getting hits must never look stale.
    pub tree_retention: Duration,
    /// The instant to measure against.
    pub now: SystemTime,
}

impl Default for ReclaimPolicy {
    /// Seven days, which is a starting point and not a finding. The number that matters is not in
    /// this file: it is whatever the composition root eventually passes, and it wants to be longer
    /// than the interval over which a tenant re-pushes the same dependencies — the whole value of the
    /// store is the hit, and a retention shorter than a working week converts hits into fetches.
    fn default() -> Self {
        ReclaimPolicy { tree_retention: Duration::from_secs(7 * 24 * 60 * 60), now: SystemTime::now() }
    }
}

/// What one [`reclaim`](ContentStore::reclaim) actually did.
///
/// Exists for the same reason [`DedupReport`] does, pointing the other way: **a reclaimer that
/// silently reclaims nothing passes every "the store is still correct" test**, because the store is
/// simply correct and full. Counts and bytes here are what make reclamation an asserted fact rather
/// than something inferred from the absence of a complaint — the tests below check them alongside
/// link counts and inode identity, and an operator watching a disk fill can tell "the sweep did not
/// run" from "the sweep ran and everything is still referenced", which are the same picture from the
/// outside.
///
/// The two "kept" counters are not decoration. A sweep that removes nothing because every tree is
/// pinned and one that removes nothing because a bug skipped the whole directory report identically
/// on `trees_removed`, and differently here.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReclaimReport {
    /// Trees taken out of the addressed namespace and deleted.
    pub trees_removed: usize,
    /// Trees left alone because somebody holds a [`TreePin`] on them. Age is not consulted; see the
    /// module docs on why a running job's tree is protected by a claim and not by a clock.
    pub trees_pinned: usize,
    /// Trees left alone because they were used inside the retention window (or have no readable
    /// stamp, which is treated as "just used" and restamped).
    pub trees_in_retention: usize,
    /// Blobs unlinked: `st_nlink == 1`, so no tree named them.
    pub blobs_removed: usize,
    /// Blobs left alone because a tree still holds a link to them.
    pub blobs_kept: usize,
    /// Blobs that looked orphaned, were renamed into scratch, and turned out to have gained a link
    /// from a commit racing this sweep — so they were linked back rather than deleted. Non-zero
    /// means the race described in the module docs actually happened, which is worth being able to
    /// see rather than infer.
    pub blobs_restored: usize,
    /// Disk actually returned, in bytes: the size of every blob unlinked, counted once each (a blob
    /// with `st_nlink == 1` is one inode with one name, so there is no double count to avoid).
    ///
    /// Tree removal contributes nothing here, and that is not an omission — see the module docs. A
    /// run reporting many trees and zero bytes means every file in them is still held elsewhere.
    pub bytes_reclaimed: u64,
    /// Removals that failed for a reason that is not "already gone". `ENOENT` is never counted: losing
    /// a race to another sweep is the expected outcome of running two, not a fault.
    pub errors: usize,
    /// Why the first error happened. The first rather than the last, and only one: a permission
    /// problem or a read-only filesystem fails identically for every entry.
    pub first_error: Option<String>,
}

impl ReclaimReport {
    /// Record a failure without abandoning the sweep.
    ///
    /// Reclamation runs because a disk is filling; a sweep that returns on its first `EACCES` leaves
    /// every later tree in place and turns one unreadable directory into no reclamation at all. The
    /// counter is what keeps that from being a silent partial success.
    fn failed(&mut self, what: &str, e: &io::Error) {
        self.errors += 1;
        self.first_error.get_or_insert_with(|| format!("{what}: {e}"));
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("content store i/o error: {0}")]
    Io(String),
}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        StoreError::Io(e.to_string())
    }
}

/// A filesystem CAS rooted at one directory: a directory per tree, a file per distinct
/// (content, mode) pair, and a hard link joining the two. See the module docs for the layout and for
/// why the link is safe here and forbidden one crate over.
#[derive(Debug, Clone)]
pub struct ContentStore {
    root: PathBuf,
    /// Which of this store's trees are in use right now. Behind an `Arc` so that a cloned store —
    /// and the broker is cloned per fetch — shares one table; a per-clone table would let a sweep
    /// through one handle delete a tree pinned through another.
    pins: Arc<PinTable>,
}

impl ContentStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        ContentStore { root: root.into(), pins: Arc::new(PinTable::default()) }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The on-disk directory name for a tenant.
    ///
    /// Hashed rather than sanitized, for two reasons. A sanitizer that strips `/` and `..` is
    /// **not injective** — `acme/x` and `acme-x` can collapse to one directory, which is a
    /// cross-tenant dedup bug arriving through the back door, and cross-tenant sharing is the one
    /// thing this store must make impossible. Hashing is injective for every practical purpose and
    /// cannot produce a path component at all, so tenant text never reaches the filesystem.
    ///
    /// Blob dedup raises the stakes on this function rather than changing it: the scope is now the
    /// only thing standing between two tenants and a *shared inode*, which is a stronger form of
    /// sharing than a shared directory and would survive a later reader being careful.
    fn tenant_scope(tenant: &str) -> String {
        let h = blake3::hash(tenant.as_bytes());
        hex::encode(&h.as_bytes()[..16])
    }

    /// Where `(tenant, tree_id)` lives. `tree_id` must already be normalized (64 lowercase hex) —
    /// [`crate::verify::normalize_tree_id`] is the gate, and it runs before anything reaches here.
    pub fn tree_path(&self, tenant: &str, tree_id: &str) -> PathBuf {
        self.root.join(Self::tenant_scope(tenant)).join("trees").join(tree_id)
    }

    /// Is this tree already here, for this tenant? A **probe**, and only a probe.
    ///
    /// It records no use and takes no pin, so the answer is a fact about the store and not an event
    /// in its life. The hit path is [`Self::open`], which does both — a `has()` that renewed a
    /// tree's lease would mean an operator's status check, or a test's assertion, kept trees alive,
    /// and a `has()` that pinned would hand out a claim nobody can release.
    ///
    /// The consequence for callers: `has()` followed by [`Self::tree_path`] is a tree you are reading
    /// without having said so, which is both invisible to retention and unprotected from a sweep. Use
    /// [`Self::open`] for anything that is about to read the tree.
    pub fn has(&self, tenant: &str, tree_id: &str) -> bool {
        self.tree_path(tenant, tree_id).is_dir()
    }

    /// Take the tree if it is here: the `if store.has(tree_id) { return }` of D§4.2, done so that the
    /// hit is recorded and the tree is protected while the caller uses it.
    ///
    /// Returns `None` when the tree is absent. On a hit it does two things `has()` does not:
    ///
    /// * **Stamps the use.** This is the point at which a cache hit becomes visible to retention. A
    ///   tree fetched once and hit daily is current, not a year old, and a store that only stamped on
    ///   commit would reap exactly its most valuable trees. It is stamped here, at the hit, rather
    ///   than in the broker, because the broker is not the only thing that can hit.
    /// * **Returns a [`TreePin`].** For as long as the caller holds it, no sweep removes this tree.
    ///
    /// The pin is taken **before** the directory is tested, and that order is the whole race
    /// argument: `reclaim` holds the same lock across its rename, so either this call registers first
    /// (and the sweep sees a pinned tree and skips it) or the sweep renames first (and the test below
    /// fails, and the pin is dropped on the way out). There is no interleaving in which a caller holds
    /// a pin on a tree that is being deleted.
    pub fn open(&self, tenant: &str, tree_id: &str) -> Option<TreePin> {
        let pin = self.pin(tenant, tree_id);
        if !self.tree_path(tenant, tree_id).is_dir() {
            return None;
        }
        self.record_use(tenant, tree_id);
        Some(pin)
    }

    /// Claim `(tenant, tree_id)` against reclamation until the returned value is dropped.
    ///
    /// Public and existence-free on purpose: the claim is on the *address*, so it can be taken before
    /// a tree exists (which is what lets [`Self::commit`] hold one across its own staging and rename)
    /// and before it is known to exist (which is what makes [`Self::open`]'s ordering sound).
    pub fn pin(&self, tenant: &str, tree_id: &str) -> TreePin {
        let key = (Self::tenant_scope(tenant), tree_id.to_string());
        *PinTable::lock(&self.pins.held).entry(key.clone()).or_insert(0) += 1;
        TreePin(Arc::new(PinGuard { pins: self.pins.clone(), key }))
    }

    /// Where a tree's last-use stamp lives — beside the tree, never inside it. A file under
    /// `{tree_id}/` would be an entry of a directory whose name is a content address, so stamping a
    /// tree would stop it hashing to its own id.
    fn used_path(&self, tenant: &str, tree_id: &str) -> PathBuf {
        self.root.join(Self::tenant_scope(tenant)).join("used").join(tree_id)
    }

    /// Record that this tree was wanted, now.
    ///
    /// Best effort, and deliberately not a `Result`: a stamp we could not write must never fail a
    /// fetch, and it fails safe in the one direction that matters — an unstamped tree is treated by
    /// [`Self::reclaim`] as freshly used and given a full window, so the failure costs disk rather
    /// than a tree somebody was about to run.
    fn record_use(&self, tenant: &str, tree_id: &str) {
        let path = self.used_path(tenant, tree_id);
        let millis = Self::millis_at(SystemTime::now());
        let write = path
            .parent()
            .map(fs::create_dir_all)
            .unwrap_or(Ok(()))
            .and_then(|()| fs::write(&path, millis.to_string().as_bytes()));
        if let Err(e) = write {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "could not stamp a tree's last use; it will be treated as freshly used and kept"
            );
        }
    }

    /// Milliseconds since the Unix epoch, saturating at zero for a clock set before 1970 — a value
    /// this store cannot represent and does not need to, since the only thing it means is "very old".
    fn millis_at(t: SystemTime) -> u128 {
        t.duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
    }

    /// Test-only: say when a tree was last used.
    ///
    /// Lives here rather than being reimplemented per test module so that the on-disk stamp format
    /// has exactly one writer besides [`Self::record_use`] — a test fixture that spelled the format
    /// itself would keep passing after the real writer changed, which is a test asserting on its own
    /// copy of the implementation.
    #[cfg(test)]
    pub(crate) fn set_last_used(&self, tenant: &str, tree_id: &str, when: SystemTime) {
        let p = self.used_path(tenant, tree_id);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, Self::millis_at(when).to_string()).unwrap();
    }

    /// When this tree was last used, or `None` if that is unknown — no stamp, an unreadable one, or
    /// one holding something that is not a number.
    ///
    /// Every `None` here means the same thing to the caller (`treat it as just used`), so the three
    /// cases are deliberately not distinguished: a reclaimer that deleted trees when it could not
    /// read a stamp would turn a permissions mistake in `used/` into data loss.
    fn last_used(&self, tenant: &str, tree_id: &str) -> Option<SystemTime> {
        let raw = fs::read_to_string(self.used_path(tenant, tree_id)).ok()?;
        let millis: u64 = raw.trim().parse().ok()?;
        Some(UNIX_EPOCH + Duration::from_millis(millis))
    }

    /// A fresh, empty staging directory on the same filesystem as the final location, so the commit
    /// is a rename and never a copy.
    ///
    /// Extraction happens here, not at the destination: a half-extracted or failed-verification tree
    /// must never be visible at its content address for even an instant, or another worker could
    /// take a `has()` hit on it and run a job against bytes we rejected.
    pub fn stage(&self, tenant: &str) -> Result<tempfile::TempDir, StoreError> {
        Ok(tempfile::TempDir::new_in(self.staging_dir(tenant)?)?)
    }

    /// The tenant's scratch area — staging trees and in-flight archive downloads both live here, on
    /// the store's filesystem so publishing is a rename. Scoped by tenant like everything else, so a
    /// half-downloaded archive is not even transiently in another tenant's directory.
    pub fn staging_dir(&self, tenant: &str) -> Result<PathBuf, StoreError> {
        let staging = self.root.join(Self::tenant_scope(tenant)).join("staging");
        fs::create_dir_all(&staging)?;
        Ok(staging)
    }

    /// Publish a staged tree at its content address, atomically.
    ///
    /// If another worker got there first we keep theirs and drop ours: both are verified to hash to
    /// the same `tree_id`, so they are the same tree by definition, and preferring the existing one
    /// means no reader ever sees the directory change under it.
    ///
    /// **Dedup runs here, and strictly before the rename.** Two reasons, both about the atomicity
    /// this function has always provided:
    ///
    /// * The publish must stay *exactly one* `rename(2)`. A tree is complete or absent; there is no
    ///   instant at which `has()` is true and a file is missing, because at the moment the directory
    ///   appears every file in it is already final. Replacing files with links *after* the rename
    ///   would open precisely that window, and a crash inside it leaves a tree that looks present,
    ///   passes `has()`, and is missing a file forever — the one regression this refactor could
    ///   plausibly cause.
    /// * A crash *during* dedup costs orphaned blobs and nothing else: the staged directory is
    ///   dropped, no tree was ever visible, and a later attempt re-links against blobs that are
    ///   already correct (they are content-addressed, so "already there" and "what we would have
    ///   written" are the same bytes).
    ///
    /// Dedup also runs strictly *after* [`crate::verify`], which is the caller's ordering, so the
    /// bytes that become a shared blob are bytes that re-hashed to their `tree_id` first.
    ///
    /// **The pin comes first, before anything is examined or written.** A commit publishes a tree and
    /// hands it to a caller who is about to use it, so the window between the rename and the caller's
    /// first read is exactly the window a sweep must not fit inside. Pinning the address up front
    /// closes it for both outcomes — the tree this call publishes, and the tree it finds already
    /// there — with no ordering left to get right further down.
    pub fn commit(&self, tenant: &str, tree_id: &str, staged: tempfile::TempDir) -> Result<StoredTree, StoreError> {
        let pin = self.pin(tenant, tree_id);
        let dest = self.tree_path(tenant, tree_id);
        if dest.is_dir() {
            // A hit, and therefore a use: without this stamp a tree that is committed repeatedly —
            // every racing member of a sharded fan-out takes this path — would carry the timestamp of
            // whichever attempt happened to win, and age out while it was still being asked for.
            self.record_use(tenant, tree_id);
            return Ok(StoredTree { tree_id: tree_id.to_string(), path: dest, cached: true, dedup: None, pin });
        }
        let dedup = self.link_into_blobs(tenant, staged.path())?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        // `keep` disarms the TempDir's destructor: the directory is about to become the store's.
        let from = staged.keep();
        match fs::rename(&from, &dest) {
            Ok(()) => {
                self.record_use(tenant, tree_id);
                Ok(StoredTree { tree_id: tree_id.to_string(), path: dest, cached: false, dedup: Some(dedup), pin })
            }
            Err(e) => {
                // Lost the race (rename onto a non-empty directory fails), or a real i/o problem.
                // Whatever this call linked into the blob store stays: the winner's tree references
                // the same content-addressed blobs, so at worst a few of them are momentarily
                // orphaned, and every byte of them is bytes the winner would have written anyway.
                let _ = fs::remove_dir_all(&from);
                if dest.is_dir() {
                    self.record_use(tenant, tree_id);
                    Ok(StoredTree { tree_id: tree_id.to_string(), path: dest, cached: true, dedup: None, pin })
                } else {
                    Err(StoreError::Io(e.to_string()))
                }
            }
        }
    }

    /// Where a tenant's blob with this key lives. Private, and it takes a tenant, so there is no way
    /// to name another tenant's blob by accident — the same rule as [`Self::tree_path`], applied to
    /// the sharper kind of sharing.
    fn blob_path(&self, tenant: &str, key: &BlobKey) -> PathBuf {
        self.root
            .join(Self::tenant_scope(tenant))
            .join("blobs")
            .join(&key.id[..2])
            .join(format!("{}.{}", &key.id[2..], key.mode_suffix()))
    }

    /// Replace every regular file in a staged tree with a link to the tenant's single copy of its
    /// contents, creating that copy when the tenant does not have one yet.
    ///
    /// Iterative rather than recursive: the extractor bounds path depth, but a stack-recursive walk
    /// would make that bound load-bearing for *our* stack over what is still attacker-shaped input.
    /// (`hull-ci-server`'s `copy_dir` is iterative for the same reason.)
    ///
    /// `symlink_metadata`, never `metadata`: a symlink is examined, never resolved, and the walk
    /// descends only into real directories. The extractor already guarantees no entry sits under a
    /// symlink, but that is a guarantee made by a different module, and "somebody else validated it"
    /// is how the second copy of a rule stops being true.
    fn link_into_blobs(&self, tenant: &str, root: &Path) -> Result<DedupReport, StoreError> {
        let mut report = DedupReport::default();
        let scratch = link_scratch_path(root)?;
        let mut pending = vec![root.to_path_buf()];

        while let Some(dir) = pending.pop() {
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                let path = entry.path();
                let meta = fs::symlink_metadata(&path)?;

                if meta.is_dir() {
                    report.directories += 1;
                    pending.push(path);
                } else if meta.is_symlink() {
                    // Not a blob, and not negotiable. keel addresses a symlink as a blob over its
                    // *target path*, so a link and a regular file can share a content address — the
                    // tests below use exactly that collision — while being different kinds of thing
                    // on disk. Hard-linking one to the other would turn a symlink into a regular
                    // file (or the reverse) and change the tree's address. Nothing here follows a
                    // link either, which is what keeps the extractor's containment intact.
                    report.symlinks += 1;
                } else if meta.is_file() {
                    self.share_one(tenant, &path, &meta, &scratch, &mut report)?;
                } else {
                    // A device node, fifo or socket. The extractor refuses all of these and
                    // verification would have failed on one, so its presence means something wrote
                    // into staging behind us. Refuse rather than skip: a tree that silently differs
                    // from what was verified is the failure the content address exists to rule out.
                    return Err(StoreError::Io(format!(
                        "unexpected file type in the staged tree at `{}`",
                        path.display()
                    )));
                }
            }
        }
        let _ = fs::remove_file(&scratch);
        Ok(report)
    }

    /// Point one staged file at the tenant's single copy of its contents.
    ///
    /// Two directions, and neither one copies a byte:
    ///
    /// * **First arrival.** `link(2)` the staged file *into* the blob store. The file we already
    ///   have becomes the blob — there is no third copy and no `write`, just a second name for an
    ///   inode that was going to exist anyway.
    /// * **Already there.** Link the blob back over the staged path. The staged inode is unlinked
    ///   and its blocks returned; that is where the saving is realized.
    ///
    /// The replacement goes through a scratch name and a `rename(2)` rather than
    /// `remove_file` + `link`, so the staged path is **never** momentarily absent. The unlink-first
    /// form has a real failure: `link(2)` can fail after the unlink — `EMLINK` when a very popular
    /// blob hits the filesystem's link ceiling (65 000 on ext4, and "the empty file" is exactly the
    /// blob that gets there) — leaving a hole in a tree we are about to publish. `rename(2)` cannot
    /// leave that state.
    ///
    /// **`EEXIST` is the expected case, not an error.** Two fetches racing to store overlapping
    /// trees will both try to create the same blob; the loser takes the reuse path and gets the
    /// winner's bytes, which are its own bytes, because the name is a content address.
    ///
    /// **`ENOENT` on the reuse path is the sweep, and is retried once.** A blob that existed at the
    /// `EEXIST` and is gone a syscall later was renamed away by [`Self::sweep_blobs`]. Falling back
    /// to a private copy there would let a sweep quietly cost dedup on a file that is very much in
    /// use, so the create path is tried again — the bytes are in hand and the name is now free.
    ///
    /// A link failure that is not `EEXIST` leaves the file exactly as it is and records why. A
    /// filesystem that will not link (no hard-link support, a link-count ceiling, a quota) must cost
    /// disk, never a job: the tree is completely correct either way, and turning an optimization's
    /// failure into an `errored` verdict would report a storage problem as a statement about the
    /// author's code. The counter is what keeps that quiet fallback from being invisible.
    fn share_one(
        &self,
        tenant: &str,
        path: &Path,
        meta: &fs::Metadata,
        scratch: &Path,
        report: &mut DedupReport,
    ) -> Result<(), StoreError> {
        let key = BlobKey::of(path, meta)?;
        // Before it can become a blob, and only ever within its own keel mode class, so the blob's
        // mode is a function of its key. See the module docs: without this the mode of a shared
        // inode would be whichever tree arrived first.
        set_canonical_mode(path, &key)?;

        let blob = self.blob_path(tenant, &key);
        if let Some(parent) = blob.parent() {
            // `create_dir_all` is safe here in a way it is not in the extractor: every component
            // below the store root is hex this module generated, so there is no attacker-chosen name
            // for a planted symlink to hide in.
            fs::create_dir_all(parent)?;
        }

        match fs::hard_link(path, &blob) {
            Ok(()) => {
                report.blobs_created += 1;
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                self.share_with_existing_blob(&blob, path, scratch, report);
                Ok(())
            }
            Err(e) => {
                report.unshared += 1;
                report.unshared_reason.get_or_insert_with(|| e.to_string());
                Ok(())
            }
        }
    }

    /// The `EEXIST` half of [`Self::share_one`]: the tenant already has a blob for these bytes, so
    /// take a link to it rather than keeping a second copy.
    ///
    /// A separate function because of its second branch, which only a sweep can produce and only a
    /// direct call can test: between the caller's `EEXIST` and the link below, a concurrent
    /// [`Self::sweep_blobs`] can rename the blob away, and the link then fails with `ENOENT`. Left
    /// inline, that branch would be reachable in production and unreachable from a test, which is
    /// the same as untested.
    fn share_with_existing_blob(&self, blob: &Path, path: &Path, scratch: &Path, report: &mut DedupReport) {
        match self.link_blob_over(blob, path, scratch) {
            Ok(()) => report.blobs_reused += 1,
            // The blob existed a moment ago and is gone now. Try once to *become* the blob instead
            // of giving up on sharing — the bytes are right here and the name is now free, so the
            // ordinary create path is exactly what this file needs. Falling straight through to a
            // private copy would let a sweep quietly cost dedup on a file that is very much in use.
            //
            // Once, not in a loop: a second failure means a sweep and a commit are contending hard
            // enough that a private copy is the cheaper answer, and an unbounded retry against a
            // concurrent deleter is how a commit hangs.
            Err(e) if e.kind() == io::ErrorKind::NotFound => match fs::hard_link(path, blob) {
                Ok(()) => report.blobs_created += 1,
                Err(e) => {
                    report.unshared += 1;
                    report.unshared_reason.get_or_insert_with(|| e.to_string());
                }
            },
            Err(e) => {
                // The blob exists and we could not link to it (`EMLINK`, a quota). The staged file
                // is untouched — that is what the scratch name bought — so the tree is still correct
                // and merely unshared.
                report.unshared += 1;
                report.unshared_reason.get_or_insert_with(|| e.to_string());
            }
        }
    }

    /// Link `blob` back over the staged file, through a scratch name so the staged path is never
    /// momentarily absent. `Ok(())` means the file is now a link to the blob.
    ///
    /// Split out of [`Self::share_one`] only so the `ENOENT` retry there can express itself as "try
    /// the other direction once" instead of as a second nested `match`.
    fn link_blob_over(&self, blob: &Path, path: &Path, scratch: &Path) -> io::Result<()> {
        // A leftover scratch link can only come from a process that died between the link and the
        // rename below; removing it keeps that from failing this commit.
        let _ = fs::remove_file(scratch);
        let r = fs::hard_link(blob, scratch).and_then(|()| fs::rename(scratch, path));
        if r.is_err() {
            let _ = fs::remove_file(scratch);
        }
        r
    }

    // ---------------------------------------------------------------------------------------------
    // Reclamation. See the module docs for the design: trees by recorded use, blobs by link count,
    // a running job protected by a pin rather than by a clock, and an honest account of what the
    // commit/sweep race costs.
    // ---------------------------------------------------------------------------------------------

    /// Remove this tenant's unused trees, then the blobs nothing references any more.
    ///
    /// **Per tenant, and there is deliberately no `reclaim_all`.** That is not a convenience left
    /// undone: [`Self::tenant_scope`] is a one-way hash, so a scope directory on disk cannot be
    /// turned back into the tenant it belongs to, and a whole-store sweep would have to walk scopes it
    /// cannot name. Every operation in this type takes a tenant and this one is not an exception —
    /// which also means a sweep cannot wander into another tenant's blobs by walking one path
    /// component too far up.
    ///
    /// The two phases run in this order and the first finishes completely before the second starts:
    /// a blob is only recognizable as garbage once the trees that referenced it are *deleted*, not
    /// merely condemned, so the tree phase deletes its scratch copies before the blob phase stats
    /// anything. A sweep that interleaved them would under-report, harmlessly but confusingly, on
    /// exactly the run that was supposed to free the disk.
    ///
    /// Errors are counted, not raised: this runs because a disk is filling, and returning on the
    /// first unreadable directory would leave every later tree in place. The one genuine failure is
    /// not being able to make the scratch directory that removals move things into, which means no
    /// removal is possible at all.
    pub fn reclaim(&self, tenant: &str, policy: &ReclaimPolicy) -> Result<ReclaimReport, StoreError> {
        let mut report = ReclaimReport::default();
        if !self.root.join(Self::tenant_scope(tenant)).is_dir() {
            // A tenant this store has never held anything for. Not an error — the caller is a sweep
            // over a list of tenants, and one that has pushed nothing is the normal case, not a typo.
            return Ok(report);
        }
        let scratch = self.reclaiming_dir(tenant)?;
        self.reclaim_trees(tenant, policy, &scratch, &mut report);
        self.sweep_stamps(tenant, &mut report);
        self.sweep_blobs(tenant, &scratch, &mut report);
        Ok(report)
    }

    /// Scratch space on the store's own filesystem, so a removal is a `rename(2)` and never a copy —
    /// the same reason [`Self::staging_dir`] exists on the publishing side.
    fn reclaiming_dir(&self, tenant: &str) -> Result<PathBuf, StoreError> {
        let dir = self.root.join(Self::tenant_scope(tenant)).join("reclaiming");
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Phase one: trees whose last recorded use is older than the retention, and which nobody holds.
    ///
    /// Every removal is **`rename` into scratch first, delete afterwards**, mirroring the publish. A
    /// `remove_dir_all` in place would leave the tree visible at its content address while it was
    /// being emptied, so a `has()` hit or a materialize could catch a directory that is half a tree —
    /// which is precisely the state the one-rename publish exists to make impossible. After the
    /// rename the address is simply absent, which every reader already handles.
    fn reclaim_trees(&self, tenant: &str, policy: &ReclaimPolicy, scratch: &Path, report: &mut ReclaimReport) {
        let trees = self.root.join(Self::tenant_scope(tenant)).join("trees");
        let entries = match fs::read_dir(&trees) {
            Ok(e) => e,
            // No trees directory at all: nothing has been committed for this tenant.
            Err(e) if e.kind() == io::ErrorKind::NotFound => return,
            Err(e) => return report.failed("listing trees", &e),
        };
        // One grave per call, not one per tree: it makes the whole phase a run of cheap renames
        // followed by a single deletion, and it gives concurrent sweeps disjoint scratch names for
        // free, so two of them can never collide on a destination.
        let grave = match tempfile::TempDir::new_in(scratch) {
            Ok(g) => g,
            Err(e) => return report.failed("creating the tree scratch directory", &e),
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    report.failed("reading a tree entry", &e);
                    continue;
                }
            };
            // A name this module did not write, or something that is not a directory: not a tree, so
            // not ours to delete. Skipping rather than removing keeps a sweep from being the thing
            // that cleans up after a bug it does not understand.
            let Some(tree_id) = entry.file_name().to_str().map(str::to_owned) else { continue };
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }

            match self.last_used(tenant, &tree_id) {
                // An unreadable stamp is treated as a use, and restamped, so the tree gets a full
                // window instead of being deleted by a sweep that could not tell how old it was.
                // Trees that predate this feature take this path exactly once.
                None => {
                    self.record_use(tenant, &tree_id);
                    report.trees_in_retention += 1;
                    continue;
                }
                // `Err` from `duration_since` means the stamp is in the future — a clock step, or a
                // stamp written by a machine that is ahead. Treated as fresh: the safe direction.
                Some(used) => match policy.now.duration_since(used) {
                    Ok(age) if age >= policy.tree_retention => {}
                    _ => {
                        report.trees_in_retention += 1;
                        continue;
                    }
                },
            }

            // The pin check and the rename are one indivisible step. Checking the count, releasing
            // the lock, and then renaming would leave a window in which `open` takes a pin on a tree
            // this loop has already decided to remove — the caller would hold a valid-looking claim
            // on a directory that is about to disappear, and would discover it as a materialize
            // failure much later. See the module docs.
            let key = (Self::tenant_scope(tenant), tree_id.clone());
            let renamed = {
                let held = PinTable::lock(&self.pins.held);
                if held.contains_key(&key) {
                    None
                } else {
                    Some(fs::rename(entry.path(), grave.path().join(&tree_id)))
                }
            };
            match renamed {
                None => report.trees_pinned += 1,
                Some(Ok(())) => report.trees_removed += 1,
                // Another sweep renamed it first. Losing that race is the expected outcome of running
                // two sweeps, not a fault, and the rename is what makes "removed" countable exactly
                // once across all of them.
                Some(Err(e)) if e.kind() == io::ErrorKind::NotFound => {}
                Some(Err(e)) => report.failed("removing a tree", &e),
            }
        }

        // Deleted here rather than left to `Drop`, because the blob phase's whole premise is that the
        // links these trees held are already gone — and because `Drop` would swallow the failure that
        // says they are not.
        if let Err(e) = grave.close() {
            report.failed("deleting reclaimed trees", &e);
        }
    }

    /// Drop use-stamps whose tree is gone: the ones this sweep just removed, and any left by a commit
    /// that failed after stamping.
    ///
    /// A stamp is a few bytes, so this is about not accumulating one inode per tree ever held rather
    /// than about disk. It races a commit in flight — a stamp written by a `commit` whose `rename` has
    /// not landed yet looks orphaned and is removed — and that costs nothing: an unstamped tree is
    /// treated as freshly used and restamped by the next sweep, which is the same safe direction the
    /// rest of the retention path leans in.
    fn sweep_stamps(&self, tenant: &str, report: &mut ReclaimReport) {
        let used = self.root.join(Self::tenant_scope(tenant)).join("used");
        let entries = match fs::read_dir(&used) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return,
            Err(e) => return report.failed("listing use stamps", &e),
        };
        for entry in entries.flatten() {
            let Some(tree_id) = entry.file_name().to_str().map(str::to_owned) else { continue };
            if self.tree_path(tenant, &tree_id).is_dir() {
                continue;
            }
            match fs::remove_file(entry.path()) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => report.failed("removing a use stamp", &e),
            }
        }
    }

    /// Phase two: every blob no tree names any more.
    ///
    /// The test is `st_nlink == 1` and it needs no index, which is the property the layout was chosen
    /// to give: a blob's names are its entry in the blob store plus one per tree entry that shares
    /// the inode, so one name means no tree. It cannot drift from the truth the way a reference count
    /// in a sidecar file can, because it *is* the truth — the kernel maintains it.
    ///
    /// A candidate is renamed into scratch, re-`stat`ed, and only then unlinked. The rename takes the
    /// name out of circulation atomically, so from that instant no commit can reach this inode through
    /// the blob store; the re-`stat` catches the one that got there just before, and links it back
    /// rather than destroying a blob somebody is using. See the module docs for what is left over
    /// after that and what it costs — it is dedup, never data.
    fn sweep_blobs(&self, tenant: &str, scratch: &Path, report: &mut ReclaimReport) {
        let blobs = self.root.join(Self::tenant_scope(tenant)).join("blobs");
        let shards = match fs::read_dir(&blobs) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return,
            Err(e) => return report.failed("listing blob shards", &e),
        };
        let grave = match tempfile::TempDir::new_in(scratch) {
            Ok(g) => g,
            Err(e) => return report.failed("creating the blob scratch directory", &e),
        };
        let mut seq: u64 = 0;

        for shard in shards.flatten() {
            let entries = match fs::read_dir(shard.path()) {
                Ok(e) => e,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => {
                    report.failed("listing a blob shard", &e);
                    continue;
                }
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let meta = match fs::symlink_metadata(&path) {
                    Ok(m) => m,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => {
                        report.failed("stating a blob", &e);
                        continue;
                    }
                };
                if !meta.is_file() {
                    continue;
                }
                if nlink_of(&meta) > 1 {
                    report.blobs_kept += 1;
                    continue;
                }

                seq += 1;
                self.reclaim_one_blob(&path, &grave.path().join(seq.to_string()), report);
            }
        }

        if let Err(e) = grave.close() {
            report.failed("clearing the blob scratch directory", &e);
        }
    }

    /// Retire one blob the caller has just observed with `st_nlink == 1`, via `scratch` — a name only
    /// this sweep can see.
    ///
    /// Split out of [`Self::sweep_blobs`] because it *is* the commit/sweep race, in four syscalls,
    /// and because the interesting interleaving — a commit linking the blob after the caller's `stat`
    /// and before the rename — is one a test can only produce by calling this directly, with the link
    /// already made. Left inline, the restore branch would be code no test can reach, which is
    /// indistinguishable from code that does not work.
    ///
    /// `rename` first, `unlink` last, and that order is the argument: the rename takes the name out
    /// of circulation atomically, so from that instant no commit can reach this inode through the
    /// blob store and the second `stat` observes a link count that can no longer grow. A count that
    /// grew before the rename means somebody linked it, so it is put back rather than destroyed.
    fn reclaim_one_blob(&self, path: &Path, scratch: &Path, report: &mut ReclaimReport) {
        match fs::rename(path, scratch) {
            Ok(()) => {}
            // Another sweep took it. Expected, not a fault.
            Err(e) if e.kind() == io::ErrorKind::NotFound => return,
            Err(e) => return report.failed("removing a blob", &e),
        }

        let meta = match fs::symlink_metadata(scratch) {
            Ok(m) => m,
            Err(e) => return report.failed("re-stating a blob", &e),
        };
        if nlink_of(&meta) > 1 {
            // A commit linked to this inode between the caller's `stat` and the rename. Put it back
            // where commits look for it, so the *next* tree holding these bytes still shares them.
            // `AlreadyExists` means the commit gave up on the link and created a fresh blob at the
            // name instead — a correct store either way, since the inode still lives on its tree
            // entry — so the link is not retried and the scratch name is simply dropped.
            match fs::hard_link(scratch, path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => report.failed("restoring a blob a commit had just linked", &e),
            }
            let _ = fs::remove_file(scratch);
            report.blobs_restored += 1;
            return;
        }

        // `len()` from the metadata already in hand, not from a second stat: the file is about to be
        // unlinked, and a size read after that is a size read from nothing.
        let len = meta.len();
        match fs::remove_file(scratch) {
            Ok(()) => {
                report.blobs_removed += 1;
                report.bytes_reclaimed += len;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => report.failed("unlinking a blob", &e),
        }
    }
}

/// How many names an inode has.
///
/// The whole blob sweep rests on this number, so on a platform that cannot supply it the answer is
/// **2** — "assume something references this" — and nothing is ever swept. A reclaimer that guessed
/// the other way would delete a tenant's every blob on the first run on an unsupported target.
#[cfg(unix)]
fn nlink_of(meta: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.nlink()
}

#[cfg(not(unix))]
fn nlink_of(_meta: &fs::Metadata) -> u64 {
    2
}

/// The two halves of a blob's identity, which are exactly the two halves of a keel `TreeEntry`'s
/// identity for a file: the content address, and the mode class. See the module docs for why the
/// mode cannot be left out, and [`crate::verify::blob_id`] for why both come from the verifier's
/// definitions rather than from a second one here.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BlobKey {
    /// `blake3(0x01 ++ contents)` as lowercase hex — keel's blob id.
    id: String,
    /// True when keel records this file as `MODE_EXEC`.
    exec: bool,
}

impl BlobKey {
    fn of(path: &Path, meta: &fs::Metadata) -> Result<BlobKey, StoreError> {
        let id = crate::verify::blob_id(path).map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(BlobKey { id: id.to_hex(), exec: crate::verify::file_mode(meta) == MODE_EXEC })
    }

    /// The mode written into the blob's file name. Spelled as the octal permission a reader would
    /// see in `ls -l`, because a directory listing of the blob store is how anyone will ever debug
    /// this, and `100755` (keel's encoding) means nothing to `stat`.
    fn mode_suffix(&self) -> &'static str {
        if self.exec {
            "755"
        } else {
            "644"
        }
    }
}

/// The scratch name used to swap a blob link into place, derived from the staged directory's own
/// (unique) name and kept **beside** it rather than inside it.
///
/// Inside the tree it would be a file that the rename normally removes — and that a failure between
/// the link and the rename would publish as part of the tree, changing its address. Beside it, in
/// the tenant's staging area, the worst case is a stray link in scratch space.
fn link_scratch_path(staged_root: &Path) -> Result<PathBuf, StoreError> {
    let name = staged_root
        .file_name()
        .ok_or_else(|| StoreError::Io(format!("staged tree `{}` has no name", staged_root.display())))?;
    Ok(staged_root.with_file_name(format!("{}.blob-link", name.to_string_lossy())))
}

/// Force a file to the canonical permission for its keel mode class.
///
/// Both values keel can address (`0644`, `0755`) survive; anything else in the mode is dropped. That
/// is not a new policy — [`crate::extract::set_mode`] already normalizes to exactly these two, for
/// the same reason (keel records two file modes, so nothing else can round-trip to a `tree_id`) —
/// it is that policy restated where the blob store depends on it.
#[cfg(unix)]
fn set_canonical_mode(path: &Path, key: &BlobKey) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(if key.exec { 0o755 } else { 0o644 }))
}

#[cfg(not(unix))]
fn set_canonical_mode(_path: &Path, _key: &BlobKey) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::{KeelTreeVerifier, TreeVerifier};
    use tempfile::TempDir;

    const TREE: &str = "f7a2d47020c63c8e00000000000000000000000000000000000000000000abcd";
    const TREE2: &str = "0123456789abcdef000000000000000000000000000000000000000000009999";
    const TREE3: &str = "fedcba987654321000000000000000000000000000000000000000000000aaaa";

    fn store() -> (TempDir, ContentStore) {
        let dir = TempDir::new().unwrap();
        let store = ContentStore::new(dir.path());
        (dir, store)
    }

    #[test]
    fn a_committed_tree_is_a_hit_and_keeps_its_content() {
        let (_d, store) = store();
        assert!(!store.has("acme", TREE));

        let staged = store.stage("acme").unwrap();
        fs::write(staged.path().join("a.txt"), b"hi").unwrap();
        let stored = store.commit("acme", TREE, staged).unwrap();

        assert!(!stored.cached);
        assert!(store.has("acme", TREE));
        assert_eq!(fs::read_to_string(stored.path.join("a.txt")).unwrap(), "hi");
    }

    #[test]
    fn the_same_tree_id_is_a_different_directory_for_each_tenant() {
        // The hard rule (D§4.2/D7): identical content, no sharing.
        let (_d, store) = store();
        let a = store.tree_path("acme", TREE);
        let b = store.tree_path("globex", TREE);
        assert_ne!(a, b);

        let staged = store.stage("acme").unwrap();
        fs::write(staged.path().join("secret.txt"), b"acme's source").unwrap();
        store.commit("acme", TREE, staged).unwrap();

        // Globex must see a miss for a tree Acme holds — otherwise a `has()` hit is an oracle for
        // "another tenant has this exact file", and the store answers questions about repos the
        // caller cannot read.
        assert!(store.has("acme", TREE));
        assert!(!store.has("globex", TREE), "cross-tenant dedup must be impossible, not merely off");
    }

    #[test]
    fn tenant_scopes_are_injective_where_a_sanitizer_would_collide() {
        // `acme/x` vs `acme-x` vs `acme..x`: a strip-the-bad-characters scheme maps several of these
        // to one directory; hashing does not. And no tenant string can produce a traversal.
        let names = ["acme", "acme/x", "acme-x", "acme..x", "../../etc", "acme\0x", ""];
        let scopes: Vec<_> = names.iter().map(|t| ContentStore::tenant_scope(t)).collect();
        for (i, a) in scopes.iter().enumerate() {
            assert!(a.bytes().all(|b| b.is_ascii_hexdigit()), "a scope is never attacker text");
            for b in scopes.iter().skip(i + 1) {
                assert_ne!(a, b, "two tenants must never share a scope");
            }
        }
    }

    #[test]
    fn staging_is_outside_the_addressed_namespace() {
        // A tree only becomes visible at its address after verification, so a `has()` hit can never
        // catch a half-written or rejected extraction.
        let (_d, store) = store();
        let staged = store.stage("acme").unwrap();
        fs::write(staged.path().join("partial"), b"...").unwrap();
        assert!(!store.has("acme", TREE));
        assert!(!staged.path().starts_with(store.tree_path("acme", TREE)));
        drop(staged);
    }

    #[test]
    fn committing_over_an_existing_tree_keeps_the_existing_one() {
        let (_d, store) = store();
        let first = store.stage("acme").unwrap();
        fs::write(first.path().join("a.txt"), b"first").unwrap();
        store.commit("acme", TREE, first).unwrap();

        let second = store.stage("acme").unwrap();
        fs::write(second.path().join("a.txt"), b"second").unwrap();
        let path = second.path().to_path_buf();
        let stored = store.commit("acme", TREE, second).unwrap();

        assert!(stored.cached, "the loser of the race reports a hit, not an error");
        assert_eq!(stored.dedup, None, "a call that published nothing did no dedup work");
        assert_eq!(fs::read_to_string(stored.path.join("a.txt")).unwrap(), "first");
        assert!(!path.exists(), "the losing staging directory is cleaned up");
    }

    // ---------------------------------------------------------------------------------------------
    // Dedup (design D§4.2, the M4 item).
    //
    // Everything below asserts on **structure** — inode identity and link counts — and not on
    // contents, because every one of these tests passes on an implementation that stores two full
    // copies. A dedup layer that silently stops deduping leaves every tree correct and every
    // content assertion green; the sharing itself is the only thing that can catch it, so it is what
    // is asserted. Nothing here measures time.
    // ---------------------------------------------------------------------------------------------

    #[cfg(unix)]
    mod dedup {
        use super::*;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        /// Stage a tree of `(relative path, contents, executable)` and publish it at `tree_id`.
        pub(super) fn commit_tree(
            store: &ContentStore,
            tenant: &str,
            tree_id: &str,
            files: &[(&str, &[u8], bool)],
        ) -> StoredTree {
            let staged = store.stage(tenant).unwrap();
            for (name, body, exec) in files {
                let p = staged.path().join(name);
                if let Some(parent) = p.parent() {
                    fs::create_dir_all(parent).unwrap();
                }
                fs::write(&p, body).unwrap();
                fs::set_permissions(&p, fs::Permissions::from_mode(if *exec { 0o755 } else { 0o644 })).unwrap();
            }
            store.commit(tenant, tree_id, staged).unwrap()
        }

        /// `(device, inode)` — the identity of a file, as opposed to a copy of one.
        pub(super) fn id_of(p: &Path) -> (u64, u64) {
            let m = fs::symlink_metadata(p).unwrap();
            (m.dev(), m.ino())
        }

        pub(super) fn nlink(p: &Path) -> u64 {
            fs::symlink_metadata(p).unwrap().nlink()
        }

        fn mode_of(p: &Path) -> u32 {
            fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
        }

        /// Every blob this tenant holds, as `<shard>/<name>` strings.
        pub(super) fn blobs(store: &ContentStore, tenant: &str) -> Vec<String> {
            let root = store.root.join(ContentStore::tenant_scope(tenant)).join("blobs");
            let mut out = Vec::new();
            let Ok(shards) = fs::read_dir(&root) else { return out };
            for shard in shards {
                let shard = shard.unwrap();
                for blob in fs::read_dir(shard.path()).unwrap() {
                    out.push(format!(
                        "{}/{}",
                        shard.file_name().to_string_lossy(),
                        blob.unwrap().file_name().to_string_lossy()
                    ));
                }
            }
            out.sort();
            out
        }

        /// The bytes a tenant's **content** actually costs — its trees and its blobs — counting a
        /// shared inode once, and counting nothing else in the scope.
        ///
        /// This is the `du` question rather than the `ls` one, and it is the only honest way to
        /// state a saving: summing `len()` per path counts a hard link twice and would report a
        /// saving of zero on an implementation that is working perfectly.
        ///
        /// Scoped to `trees` and `blobs` rather than to the whole tenant directory because the scope
        /// also holds bookkeeping — a use stamp per tree since reclamation landed — and a measurement
        /// of "what two overlapping trees cost" that drifts when a few bytes of metadata are added
        /// beside them is measuring the wrong thing.
        pub(super) fn content_bytes(store: &ContentStore, tenant: &str) -> u64 {
            let scope = store.root.join(ContentStore::tenant_scope(tenant));
            let mut seen = std::collections::HashSet::new();
            let mut total = 0;
            let mut pending = vec![scope.join("trees"), scope.join("blobs")];
            while let Some(dir) = pending.pop() {
                // A directory that is not there yet holds nothing, which is the right answer for a
                // tenant that has committed no tree or whose every blob has been swept.
                let Ok(entries) = fs::read_dir(&dir) else { continue };
                for e in entries {
                    let e = e.unwrap();
                    let m = fs::symlink_metadata(e.path()).unwrap();
                    if m.is_dir() {
                        pending.push(e.path());
                    } else if m.is_file() && seen.insert((m.dev(), m.ino())) {
                        total += m.len();
                    }
                }
            }
            total
        }

        #[test]
        fn two_trees_that_share_a_file_share_its_inode() {
            // The feature, stated as the only thing that can prove it happened. Contents are equal
            // in both the deduped and the duplicated implementation; one inode is not.
            let (_d, store) = store();
            let a = commit_tree(
                &store,
                "acme",
                TREE,
                &[("shared.txt", b"the bytes both trees hold", false), ("only-a.txt", b"a", false)],
            );
            let b = commit_tree(
                &store,
                "acme",
                TREE2,
                &[("shared.txt", b"the bytes both trees hold", false), ("only-b.txt", b"b", false)],
            );

            assert_eq!(
                id_of(&a.path.join("shared.txt")),
                id_of(&b.path.join("shared.txt")),
                "the second tree stored a second copy of a file the tenant already had"
            );
            assert_ne!(
                id_of(&a.path.join("only-a.txt")),
                id_of(&b.path.join("only-b.txt")),
                "different content must never land on one inode"
            );

            // Three names for one file: the blob, and one directory entry in each tree. This is the
            // number that a future reclaimer reads, and the number that silently drops to 2 if a
            // later tree stops being linked.
            assert_eq!(nlink(&a.path.join("shared.txt")), 3);
            assert_eq!(nlink(&a.path.join("only-a.txt")), 2, "an unshared file is still blob + tree");

            assert_eq!(a.dedup.unwrap(), DedupReport { blobs_created: 2, ..DedupReport::default() });
            assert_eq!(
                b.dedup.unwrap(),
                DedupReport { blobs_created: 1, blobs_reused: 1, ..DedupReport::default() },
                "the report must show the reuse; a silent stop is the failure this feature invites"
            );
        }

        #[test]
        fn duplicate_files_inside_one_tree_are_stored_once() {
            // Vendored copies, generated headers, the same LICENSE in twelve crates. The intra-tree
            // case costs nothing extra to support and is a large share of a real saving.
            let (_d, store) = store();
            let t = commit_tree(
                &store,
                "acme",
                TREE,
                &[("a/LICENSE", b"Apache-2.0 ...", false), ("b/LICENSE", b"Apache-2.0 ...", false)],
            );
            assert_eq!(id_of(&t.path.join("a/LICENSE")), id_of(&t.path.join("b/LICENSE")));
            assert_eq!(blobs(&store, "acme").len(), 1);
            assert_eq!(t.dedup.unwrap().blobs_reused, 1);
        }

        #[test]
        fn identical_bytes_with_different_modes_are_never_one_inode() {
            // The trap the mode-in-the-key exists for. A hard link shares an inode and an inode
            // carries the mode, so sharing these two would flip one file's exec bit — and keel
            // *addresses* the exec bit, so the loser's tree would stop hashing to the `tree_id` it
            // is filed under. Verification passed; the store would have broken it afterwards.
            const SCRIPT: &[u8] = b"#!/bin/sh\nexec make test\n";
            let (_d, store) = store();
            let a = commit_tree(&store, "acme", TREE, &[("run.sh", SCRIPT, true)]);
            let b = commit_tree(&store, "acme", TREE2, &[("run.sh", SCRIPT, false)]);

            assert_ne!(
                id_of(&a.path.join("run.sh")),
                id_of(&b.path.join("run.sh")),
                "same bytes, different mode: one inode cannot hold both"
            );
            assert_eq!(mode_of(&a.path.join("run.sh")), 0o755, "the executable file is still executable");
            assert_eq!(mode_of(&b.path.join("run.sh")), 0o644, "and the plain one did not become so");
            assert_eq!(b.dedup.unwrap().blobs_reused, 0, "a mode difference is not a reuse");

            // Two blobs, one per (content, mode) pair, and the mode is visible in the name.
            let names = blobs(&store, "acme");
            assert_eq!(names.len(), 2, "{names:?}");
            assert!(names.iter().any(|n| n.ends_with(".755")));
            assert!(names.iter().any(|n| n.ends_with(".644")));

            // The same trap inside a single tree, where a link would be even easier to write.
            let c = commit_tree(&store, "acme", TREE3, &[("x.sh", SCRIPT, true), ("x.txt", SCRIPT, false)]);
            assert_ne!(id_of(&c.path.join("x.sh")), id_of(&c.path.join("x.txt")));
            assert_eq!(mode_of(&c.path.join("x.sh")) & 0o111, 0o111);
            assert_eq!(mode_of(&c.path.join("x.txt")) & 0o111, 0);
        }

        #[test]
        fn a_blobs_mode_does_not_depend_on_which_tree_arrived_first() {
            // A caller that is not our extractor can stage a file at any mode. Normalizing to the
            // canonical permission for the keel class before it becomes a blob keeps a later tree
            // from inheriting `0600` (or `0777`) because of who got there first. Both spellings are
            // the same keel mode, so no tree's address moves.
            let (_d, store) = store();
            let staged = store.stage("acme").unwrap();
            fs::write(staged.path().join("odd"), b"body").unwrap();
            fs::set_permissions(staged.path().join("odd"), fs::Permissions::from_mode(0o600)).unwrap();
            let a = store.commit("acme", TREE, staged).unwrap();
            assert_eq!(mode_of(&a.path.join("odd")), 0o644);

            let b = commit_tree(&store, "acme", TREE2, &[("odd", b"body", false)]);
            assert_eq!(id_of(&a.path.join("odd")), id_of(&b.path.join("odd")), "they are the same keel entry");
            assert_eq!(mode_of(&b.path.join("odd")), 0o644);
        }

        #[test]
        fn two_tenants_holding_the_same_bytes_hold_two_inodes() {
            // The store's single most important property, and the one a "harmless" refactor of the
            // key would take away. Asserted on inode identity, not on content equality: content is
            // equal in *both* the safe and the catastrophic implementation.
            let (_d, store) = store();
            let a = commit_tree(&store, "acme", TREE, &[("dep.tar", b"a proprietary dependency", false)]);
            let b = commit_tree(&store, "globex", TREE, &[("dep.tar", b"a proprietary dependency", false)]);

            assert_ne!(a.path, b.path);
            assert_ne!(
                id_of(&a.path.join("dep.tar")),
                id_of(&b.path.join("dep.tar")),
                "one inode across tenants is a cross-tenant existence oracle with a shared fate"
            );
            assert_eq!(nlink(&a.path.join("dep.tar")), 2, "acme's file is named by acme's blob and nothing else");
            assert_eq!(nlink(&b.path.join("dep.tar")), 2);
            assert_eq!(b.dedup.unwrap().blobs_reused, 0, "globex reused nothing; it had nothing");
            assert_eq!(blobs(&store, "acme").len(), 1);
            assert_eq!(blobs(&store, "globex").len(), 1);
        }

        #[test]
        fn a_deduped_tree_still_hashes_to_its_tree_id() {
            // The content address is the only thing the store promises. Wired to the real verifier —
            // the same `KeelTreeVerifier` the broker runs before committing — rather than asserted
            // informally, and checked on *both* trees after the second one shares the first's blobs.
            let (_d, store) = store();
            let verifier = KeelTreeVerifier::default();

            let stage_one = |files: &[(&str, &[u8], bool)]| {
                let staged = store.stage("acme").unwrap();
                for (name, body, exec) in files {
                    let p = staged.path().join(name);
                    fs::create_dir_all(p.parent().unwrap()).unwrap();
                    fs::write(&p, body).unwrap();
                    fs::set_permissions(&p, fs::Permissions::from_mode(if *exec { 0o755 } else { 0o644 })).unwrap();
                }
                std::os::unix::fs::symlink("src/main.rs", staged.path().join("link")).unwrap();
                // The address of what was staged, computed before the store touches it.
                let id = verifier.tree_id(staged.path()).unwrap();
                (staged, id)
            };

            let (staged_a, id_a) = stage_one(&[
                ("README.md", b"hello\n", false),
                ("src/main.rs", b"fn main() {}\n", false),
                ("run.sh", b"#!/bin/sh\n", true),
            ]);
            let a = store.commit("acme", &id_a, staged_a).unwrap();
            verifier.verify(&a.path, &id_a).expect("a deduped tree must still be the tree it is filed under");

            // A second tree overlapping the first in two of three files, so most of its entries are
            // now links into blobs the first tree's inodes provided.
            let (staged_b, id_b) = stage_one(&[
                ("README.md", b"hello\n", false),
                ("src/main.rs", b"fn main() {}\n", false),
                ("run.sh", b"#!/bin/sh\necho more\n", true),
            ]);
            let b = store.commit("acme", &id_b, staged_b).unwrap();
            assert_ne!(id_a, id_b);
            assert_eq!(b.dedup.as_ref().unwrap().blobs_reused, 2);
            assert_eq!(id_of(&a.path.join("README.md")), id_of(&b.path.join("README.md")));

            verifier.verify(&b.path, &id_b).expect("the sharing tree hashes to its own id");
            verifier.verify(&a.path, &id_a).expect("and the shared-from tree still hashes to its");
        }

        #[test]
        fn a_symlink_is_never_a_blob_even_when_it_shares_a_content_address() {
            // keel addresses a symlink as a blob over its *target path*, so `link -> real.txt` and a
            // regular file containing "real.txt" have the same keel blob id. They are different
            // kinds of thing on disk, and hard-linking one to the other would change the tree's
            // address (MODE_SYMLINK vs MODE_FILE) as well as let a link stand where a file belongs.
            let (_d, store) = store();
            let staged = store.stage("acme").unwrap();
            fs::write(staged.path().join("real.txt"), b"payload\n").unwrap();
            fs::write(staged.path().join("decoy"), b"real.txt").unwrap();
            std::os::unix::fs::symlink("real.txt", staged.path().join("link")).unwrap();
            let t = store.commit("acme", TREE, staged).unwrap();

            let link = t.path.join("link");
            assert!(fs::symlink_metadata(&link).unwrap().is_symlink(), "the link is still a link");
            assert_eq!(fs::read_link(&link).unwrap(), Path::new("real.txt"));
            assert_ne!(id_of(&link), id_of(&t.path.join("decoy")), "a symlink and a file are not one inode");
            assert_eq!(nlink(&link), 1, "nothing linked the symlink into the blob store");

            let report = t.dedup.unwrap();
            assert_eq!(report.symlinks, 1);
            assert_eq!(report.blobs_created, 2, "only the two regular files became blobs");
            assert_eq!(blobs(&store, "acme").len(), 2);
        }

        #[test]
        fn a_file_type_that_cannot_be_a_blob_is_refused_rather_than_skipped() {
            // Unreachable through the extractor, which rejects sockets, fifos and device nodes — so
            // one in a staged tree means something wrote into staging behind us, and publishing a
            // tree that differs from what was verified is exactly what the address rules out.
            //
            // Rooted somewhere short on purpose: a unix socket's path is capped at ~104 bytes
            // (`sun_path`), and macOS's default temp directory (`/var/folders/…`) plus a 32-character
            // tenant scope plus a staging name sits close enough to that ceiling that `bind` would
            // be a coin flip. The store under test is ordinary; only its root is chosen.
            let dir = tempfile::Builder::new().prefix("hullci").tempdir_in("/tmp").unwrap();
            let store = ContentStore::new(dir.path());
            let staged = store.stage("acme").unwrap();
            let _sock = std::os::unix::net::UnixListener::bind(staged.path().join("sock")).unwrap();
            let err = store.commit("acme", TREE, staged).unwrap_err();
            assert!(err.to_string().contains("unexpected file type"), "{err}");
            assert!(!store.has("acme", TREE), "and nothing was published");
        }

        #[test]
        fn the_publish_is_still_one_rename_so_a_crash_cannot_leave_a_partial_tree() {
            // Dedup runs entirely on the staged tree. Proved by doing the dedup half by hand and
            // asserting the tree is still invisible: at no point is `has()` true while a file is
            // still being replaced. Then the staged directory is dropped — the crash — and the tree
            // is absent rather than present-and-holed.
            let (_d, store) = store();
            let staged = store.stage("acme").unwrap();
            fs::write(staged.path().join("a"), b"one").unwrap();
            fs::write(staged.path().join("b"), b"two").unwrap();

            let report = store.link_into_blobs("acme", staged.path()).unwrap();
            assert_eq!(report.blobs_created, 2, "the files are shared before the rename, not after");
            assert!(!store.has("acme", TREE), "no tree is visible at its address mid-commit");

            let path = staged.path().to_path_buf();
            drop(staged);
            assert!(!path.exists());
            assert!(!store.has("acme", TREE), "a crash during dedup leaves no tree at all");

            // The cost of that crash: two orphaned blobs, which stay until something calls
            // `reclaim` (nothing does yet — see the module docs and the README's known gaps). A
            // later commit of the same content re-links them rather than duplicating them.
            assert_eq!(blobs(&store, "acme").len(), 2);
            let t = commit_tree(&store, "acme", TREE, &[("a", b"one", false), ("b", b"two", false)]);
            assert_eq!(t.dedup.unwrap().blobs_reused, 2, "the orphans are reused, not duplicated");
            assert_eq!(blobs(&store, "acme").len(), 2);
        }

        #[test]
        fn no_scratch_link_is_left_inside_a_published_tree() {
            // The swap goes through a scratch name; if that name lived inside the tree, a leftover
            // would be an extra entry and the tree would hash to something else. It lives beside it.
            let (_d, store) = store();
            commit_tree(&store, "acme", TREE, &[("a", b"same", false)]);
            let t = commit_tree(&store, "acme", TREE2, &[("a", b"same", false)]);
            let names: Vec<_> = fs::read_dir(&t.path)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert_eq!(names, vec!["a".to_string()], "the published tree holds exactly its own entries");
        }

        #[test]
        fn concurrent_commits_of_overlapping_trees_all_succeed_and_share() {
            // Two fetches racing to create the same blob is the normal case, not an edge: every
            // node in a sharded step arrives with the same dependencies. `EEXIST` must be tolerated
            // rather than fatal, and the loser must end up with the winner's bytes — which are its
            // own bytes, because the name is a content address.
            const SHARED: &[u8] = b"the dependency every branch of the fan-out holds\n";
            let (_d, store) = store();
            let ids = [TREE, TREE2, TREE3];

            let done: Vec<_> = std::thread::scope(|scope| {
                let handles: Vec<_> = ids
                    .iter()
                    .enumerate()
                    .map(|(i, id)| {
                        let store = store.clone();
                        scope.spawn(move || {
                            commit_tree(
                                &store,
                                "acme",
                                id,
                                &[("vendor/dep.rs", SHARED, false), ("unique", format!("{i}").as_bytes(), false)],
                            )
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().expect("a racing commit must not panic")).collect()
            });

            let first = id_of(&done[0].path.join("vendor/dep.rs"));
            for t in &done {
                assert!(!t.cached);
                let p = t.path.join("vendor/dep.rs");
                assert_eq!(fs::read(&p).unwrap(), SHARED, "the winner's bytes are the right bytes");
                assert_eq!(id_of(&p), first, "one of the racers stored a second copy");
            }
            assert_eq!(nlink(&done[0].path.join("vendor/dep.rs")), 1 + ids.len() as u64);

            // Exactly one blob for the shared file plus one per unique file: the race produced no
            // duplicates and no partial state.
            assert_eq!(blobs(&store, "acme").len(), 1 + ids.len());
            let created: usize = done.iter().map(|t| t.dedup.as_ref().unwrap().blobs_created).sum();
            let reused: usize = done.iter().map(|t| t.dedup.as_ref().unwrap().blobs_reused).sum();
            assert_eq!(created + reused, 2 * ids.len(), "every file is accounted for exactly once");
            assert_eq!(created, 1 + ids.len(), "and only one racer created the shared blob");
        }

        #[test]
        fn the_store_holds_one_blob_per_distinct_content_and_mode() {
            // The invariant behind the saving, stated as a count that a stalled dedup layer fails.
            let (_d, store) = store();
            commit_tree(
                &store,
                "acme",
                TREE,
                &[("a", b"one", false), ("b", b"one", false), ("c", b"one", true), ("d", b"two", false)],
            );
            commit_tree(&store, "acme", TREE2, &[("e", b"one", false), ("f", b"three", false)]);

            // Distinct pairs: (one,644) (one,755) (two,644) (three,644).
            assert_eq!(blobs(&store, "acme").len(), 4, "{:?}", blobs(&store, "acme"));
        }

        #[test]
        fn two_ninety_percent_overlapping_trees_cost_about_one_tree() {
            // The benefit, measured on structure rather than on a clock: the store's allocated bytes
            // for two trees that share 90% of their files, against the same measurement for one.
            // (This repo already has one flaky wall-clock test; a second is not worth a benchmark
            // that a loaded CI machine can fail.)
            const FILES: usize = 20;
            const SHARED: usize = 18;
            const SIZE: usize = 8 * 1024;
            // Distinct per seed by construction. An earlier version of this fixture keyed the fill
            // byte on `seed % 26` and two "different" files collided, which made the measurement
            // report a saving that was partly an accident of the test data.
            let body = |seed: usize| {
                let mut v = vec![b'.'; SIZE];
                v[..8].copy_from_slice(&(seed as u64).to_le_bytes());
                v
            };

            let (_d, store) = store();

            let tree_a: Vec<_> = (0..FILES).map(|i| (format!("f{i}"), body(i))).collect();
            let files_a: Vec<_> = tree_a.iter().map(|(n, b)| (n.as_str(), b.as_slice(), false)).collect();
            commit_tree(&store, "acme", TREE, &files_a);
            let one_tree = content_bytes(&store, "acme");
            assert_eq!(one_tree, (FILES * SIZE) as u64, "one tree costs its own bytes once, not twice");

            // The second tree differs in its last two files — a realistic "changed two files" push.
            let tree_b: Vec<_> = (0..FILES)
                .map(|i| (format!("f{i}"), if i < SHARED { body(i) } else { body(i + 100) }))
                .collect();
            let files_b: Vec<_> = tree_b.iter().map(|(n, b)| (n.as_str(), b.as_slice(), false)).collect();
            let b = commit_tree(&store, "acme", TREE2, &files_b);
            assert_eq!(b.dedup.as_ref().unwrap().blobs_reused, SHARED);
            assert_eq!(b.dedup.as_ref().unwrap().blobs_created, FILES - SHARED);

            let two_trees = content_bytes(&store, "acme");
            let duplicated = 2 * one_tree;
            assert_eq!(
                two_trees,
                one_tree + ((FILES - SHARED) * SIZE) as u64,
                "the second tree must cost only the files it actually changed"
            );
            // Stated as the ratio the milestone claims, so a regression to full copies reads as the
            // number it is: 1.10x of one tree, where storing both whole would be 2.00x.
            assert!(
                two_trees * 100 <= one_tree * 115,
                "two 90%-overlapping trees cost {two_trees} bytes; one tree is {one_tree} and two \
                 full copies would be {duplicated}"
            );
        }

        #[test]
        fn nothing_removes_a_tree_or_a_blob_until_reclaim_is_called() {
            // The store deletes nothing on its own: no size ceiling, no timer, no removal hidden in
            // a commit. Reclamation is an explicit call and this is the assertion that it stays one
            // — if a background reaper is ever wired in here, this is where it announces itself.
            let (_d, store) = store();
            let t = commit_tree(&store, "acme", TREE, &[("a", b"one", false)]);
            drop(t);
            for _ in 0..3 {
                commit_tree(&store, "acme", TREE2, &[("b", b"two", false)]);
            }
            assert!(store.has("acme", TREE), "nothing evicted it");
            assert_eq!(blobs(&store, "acme").len(), 2);

            // An orphan is recognizable without an index, which is what makes the sweep cheap.
            let orphan = {
                let staged = store.stage("acme").unwrap();
                fs::write(staged.path().join("x"), b"never published").unwrap();
                store.link_into_blobs("acme", staged.path()).unwrap();
                let key = BlobKey::of(
                    &staged.path().join("x"),
                    &fs::symlink_metadata(staged.path().join("x")).unwrap(),
                )
                .unwrap();
                store.blob_path("acme", &key)
            };
            assert_eq!(nlink(&orphan), 1, "an unreferenced blob has exactly one name");
            assert_eq!(nlink(&store.tree_path("acme", TREE).join("a")), 2, "a referenced one has more");
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Reclamation.
    //
    // The failure this suite is built against: **a reclaimer that reclaims nothing passes every
    // "the store is still correct" test**, because the store is simply correct and full. So nothing
    // below infers that work happened from the absence of a complaint. Every "this survived"
    // assertion is paired, in the same `reclaim` call, with a "this did not" — so a sweep that
    // skipped the whole directory fails the test that a sweep that worked passes. Removals are
    // asserted on the report's counts *and* on the filesystem (link counts, inode identity, bytes
    // measured once per inode), because either one alone is the implementation's own account of
    // itself.
    //
    // Nothing here measures wall-clock time: `ReclaimPolicy::now` is injected, and use stamps are
    // written directly, so a "three weeks old" tree costs no sleep and cannot be made flaky by a
    // loaded machine.
    // ---------------------------------------------------------------------------------------------

    #[cfg(unix)]
    mod reclaim {
        use super::dedup::*;
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        const DAY: Duration = Duration::from_secs(24 * 60 * 60);

        /// A policy that reclaims anything unused for a week, evaluated `age` after the epoch-ish
        /// instant the fixtures stamp against.
        fn at(now: SystemTime, retention: Duration) -> ReclaimPolicy {
            ReclaimPolicy { tree_retention: retention, now }
        }

        /// The instant these tests call "now".
        ///
        /// Anchored to the real clock rather than to a fixed epoch offset, because retention is
        /// measured against the wall clock and has to be: a use stamp must survive a restart, so it
        /// cannot be an `Instant`. A fixed anchor would put every stamp `record_use` writes — written
        /// with the real clock, on the code path under test — months away from the policy's `now`,
        /// and the test would be asserting on the gap between two clocks instead of on retention.
        ///
        /// This is not a timing test and cannot become one: every margin below is a day or more, no
        /// test sleeps, waits or asserts on elapsed time, and `ReclaimPolicy::now` is a parameter
        /// precisely so that "three weeks old" costs nothing to arrange.
        fn t0() -> SystemTime {
            SystemTime::now()
        }

        /// Say when a tree was last used, directly. This is what makes every retention assertion
        /// below deterministic and instant — the alternative is `sleep`, and this repository already
        /// has one flaky timing test.
        fn stamp(store: &ContentStore, tenant: &str, tree_id: &str, when: SystemTime) {
            store.set_last_used(tenant, tree_id, when);
        }

        #[test]
        fn a_tree_past_its_retention_goes_and_one_inside_it_stays() {
            // The two halves in one call, on purpose. A sweep that removes nothing and a sweep that
            // removes everything are both wrong, and either one passes a test that only checks the
            // other's tree.
            let (_d, store) = store();
            commit_tree(&store, "acme", TREE, &[("a", b"old tree", false)]);
            commit_tree(&store, "acme", TREE2, &[("b", b"fresh tree", false)]);
            stamp(&store, "acme", TREE, t0() - 8 * DAY);
            stamp(&store, "acme", TREE2, t0() - DAY);

            let report = store.reclaim("acme", &at(t0(), 7 * DAY)).unwrap();

            assert_eq!(report.trees_removed, 1);
            assert_eq!(report.trees_in_retention, 1);
            assert_eq!(report.trees_pinned, 0);
            assert!(!store.has("acme", TREE), "a tree nothing has wanted for eight days is gone");
            assert!(store.has("acme", TREE2), "and one used yesterday is not");
            assert_eq!(
                fs::read_to_string(store.tree_path("acme", TREE2).join("b")).unwrap(),
                "fresh tree",
                "the survivor is intact, not merely present"
            );
            // The stamp goes with the tree: otherwise the store trades one unbounded directory for
            // another, one inode per tree it has ever held.
            assert!(!store.used_path("acme", TREE).exists());
            assert!(store.used_path("acme", TREE2).exists());
        }

        #[test]
        fn a_tree_that_keeps_getting_hits_is_never_reclaimed_however_old_its_commit_is() {
            // The test that catches an `atime`-shaped mistake, or a touch written only into
            // `commit`. Both trees are committed at the same instant and both are stamped a month
            // into the past; the only difference is that one of them is *opened* — a cache hit,
            // exactly what a warm tree gets and what `FetchBroker::ensure_tree` calls. If the hit
            // does not record a use, the opened tree ages out with the other one and this fails.
            //
            // The unopened tree is the control: without it, an implementation that reclaims nothing
            // at all would pass.
            let (_d, store) = store();
            commit_tree(&store, "acme", TREE, &[("hot", b"wanted every day", false)]);
            commit_tree(&store, "acme", TREE2, &[("cold", b"wanted once", false)]);
            stamp(&store, "acme", TREE, t0() - 30 * DAY);
            stamp(&store, "acme", TREE2, t0() - 30 * DAY);

            // A year of daily hits, in the only form that matters to retention.
            for _ in 0..365 {
                let pin = store.open("acme", TREE).expect("the hot tree is a hit every time");
                drop(pin);
            }

            let report = store.reclaim("acme", &at(t0(), 7 * DAY)).unwrap();

            assert_eq!(report.trees_removed, 1, "exactly the tree nobody asked for");
            assert!(
                store.has("acme", TREE),
                "a tree hit every day was reclaimed: the hit path is not recording use"
            );
            assert!(!store.has("acme", TREE2), "and the tree nobody opened is gone");
            assert_eq!(fs::read_to_string(store.tree_path("acme", TREE).join("hot")).unwrap(), "wanted every day");
        }

        #[test]
        fn has_is_a_probe_and_open_is_a_hit() {
            // The distinction the module docs make, asserted, because it is invisible otherwise and
            // a `has()` that renewed a lease would make an operator's status page keep the disk
            // full. Same age, same tenant; one is probed, the other opened.
            let (_d, store) = store();
            commit_tree(&store, "acme", TREE, &[("a", b"probed", false)]);
            commit_tree(&store, "acme", TREE2, &[("b", b"opened", false)]);
            stamp(&store, "acme", TREE, t0() - 30 * DAY);
            stamp(&store, "acme", TREE2, t0() - 30 * DAY);

            assert!(store.has("acme", TREE));
            drop(store.open("acme", TREE2));

            let report = store.reclaim("acme", &at(t0(), 7 * DAY)).unwrap();
            assert_eq!(report.trees_removed, 1);
            assert!(!store.has("acme", TREE), "a probe is not a use");
            assert!(store.has("acme", TREE2), "an open is");
        }

        #[test]
        fn a_pinned_tree_is_never_reclaimed_at_any_age_and_goes_once_the_pin_does() {
            // What actually protects a job that was admitted and is still queued. `materialize`
            // opens the store's tree when the *step* starts, which can be long after the fetch said
            // `cached: true`, so the tree has to be held by a claim rather than by a clock — see the
            // module docs on why a longer retention is not this guarantee.
            //
            // The unpinned tree is the same age and is the control: it proves the sweep ran.
            let (_d, store) = store();
            let held = commit_tree(&store, "acme", TREE, &[("a", b"a job is using this", false)]);
            commit_tree(&store, "acme", TREE2, &[("b", b"nobody is", false)]);
            stamp(&store, "acme", TREE, t0() - 400 * DAY);
            stamp(&store, "acme", TREE2, t0() - 400 * DAY);

            let report = store.reclaim("acme", &at(t0(), 7 * DAY)).unwrap();
            assert_eq!(report.trees_pinned, 1, "the pin is honoured, and reported rather than silent");
            assert_eq!(report.trees_removed, 1);
            assert!(store.has("acme", TREE), "a tree somebody holds must survive any retention");
            assert!(!store.has("acme", TREE2));
            assert_eq!(
                fs::read_to_string(held.path.join("a")).unwrap(),
                "a job is using this",
                "and it is still readable through the path the holder was given"
            );

            // A clone shares the claim rather than taking a second, so releasing one releases
            // nothing. This is the case a refcount gets wrong in the dangerous direction.
            let clone = held.clone();
            drop(held);
            let report = store.reclaim("acme", &at(t0(), 7 * DAY)).unwrap();
            assert_eq!(report.trees_pinned, 1, "one clone still holds it");
            assert!(store.has("acme", TREE));

            drop(clone);
            let report = store.reclaim("acme", &at(t0(), 7 * DAY)).unwrap();
            assert_eq!(report.trees_pinned, 0);
            assert_eq!(report.trees_removed, 1, "and once nobody holds it, it goes");
            assert!(!store.has("acme", TREE));
        }

        #[test]
        fn a_pin_taken_through_one_handle_is_honoured_by_a_sweep_through_another() {
            // `ContentStore` is `Clone` and the broker clones it per fetch, so a pin table that
            // cloned with the store would protect nothing: the fetch's handle would hold the claim
            // and the sweep's handle would never see it. Same root, two handles, one table.
            let (_d, store) = store();
            let holder = store.clone();
            let sweeper = store.clone();
            let pin = holder.commit("acme", TREE, {
                let s = holder.stage("acme").unwrap();
                fs::write(s.path().join("a"), b"x").unwrap();
                s
            });
            let pin = pin.unwrap();
            stamp(&store, "acme", TREE, t0() - 400 * DAY);

            let report = sweeper.reclaim("acme", &at(t0(), 7 * DAY)).unwrap();
            assert_eq!(report.trees_pinned, 1, "the pin table is shared, not cloned");
            assert!(sweeper.has("acme", TREE));
            drop(pin);
            assert_eq!(sweeper.reclaim("acme", &at(t0(), 7 * DAY)).unwrap().trees_removed, 1);
        }

        #[test]
        fn a_blob_a_surviving_tree_still_references_is_not_swept() {
            // Asserted by link count and inode identity, never by content: the blob's *bytes* are
            // still readable through the surviving tree's entry even if the sweep wrongly unlinked
            // the blob, so a content assertion here passes on the broken implementation. What
            // changes is the number of names.
            //
            // Paired with an orphan in the same call, so "the sweep did nothing" fails too.
            let (_d, store) = store();
            commit_tree(&store, "acme", TREE, &[("shared", b"held by two trees", false)]);
            let survivor = commit_tree(&store, "acme", TREE2, &[("shared", b"held by two trees", false)]);
            stamp(&store, "acme", TREE, t0() - 30 * DAY);
            stamp(&store, "acme", TREE2, t0());
            let shared = survivor.path.join("shared");
            assert_eq!(nlink(&shared), 3, "blob + one entry in each tree");

            // An orphan: linked into the blob store by a commit that never published.
            let orphan_path = {
                let staged = store.stage("acme").unwrap();
                fs::write(staged.path().join("x"), b"referenced by nothing").unwrap();
                store.link_into_blobs("acme", staged.path()).unwrap();
                let p = staged.path().join("x");
                let key = BlobKey::of(&p, &fs::symlink_metadata(&p).unwrap()).unwrap();
                store.blob_path("acme", &key)
            };
            assert_eq!(nlink(&orphan_path), 1);
            let shared_ino = id_of(&shared);

            let report = store.reclaim("acme", &at(t0(), 7 * DAY)).unwrap();

            assert_eq!(report.blobs_removed, 1, "only the orphan");
            assert!(report.blobs_kept >= 1, "and the referenced blob was seen and left alone");
            assert!(!orphan_path.exists());
            assert_eq!(
                nlink(&shared),
                2,
                "blob + the one surviving tree entry: the blob itself must still be a name for this \
                 inode, or the next tree with these bytes stores them again"
            );
            assert_eq!(id_of(&shared), shared_ino, "and it is the same inode, not a replacement");
        }

        #[test]
        fn a_blob_nothing_references_is_swept_and_its_bytes_come_back() {
            // The number that makes reclamation a fact rather than a claim. Measured once per
            // `(dev, ino)`, as the dedup tests do, because the store is full of hard links and a
            // per-path sum would be fiction in both directions.
            const SIZE: usize = 64 * 1024;
            let gone = vec![b'g'; SIZE];
            let kept = vec![b'k'; SIZE];

            let (_d, store) = store();
            commit_tree(&store, "acme", TREE, &[("doomed", &gone, false)]);
            commit_tree(&store, "acme", TREE2, &[("survivor", &kept, false)]);
            stamp(&store, "acme", TREE, t0() - 30 * DAY);
            stamp(&store, "acme", TREE2, t0());

            let before = content_bytes(&store, "acme");
            assert_eq!(before, 2 * SIZE as u64, "two distinct files, stored once each");

            let report = store.reclaim("acme", &at(t0(), 7 * DAY)).unwrap();
            let after = content_bytes(&store, "acme");

            assert_eq!(report.trees_removed, 1);
            assert_eq!(report.blobs_removed, 1);
            assert_eq!(
                report.bytes_reclaimed, SIZE as u64,
                "the report must state the saving, or a sweep that frees nothing looks identical"
            );
            assert_eq!(
                before - after,
                report.bytes_reclaimed,
                "and the filesystem must agree with the report: {before} → {after}"
            );
            assert_eq!(after, SIZE as u64, "exactly the surviving tree's bytes are left");
            assert_eq!(blobs(&store, "acme").len(), 1);
        }

        #[test]
        fn reclaiming_one_tenant_never_touches_another_tenants_blobs() {
            // Two tenants holding byte-identical files hold two inodes (the store's most important
            // property), so acme's sweep must not so much as stat globex's copy. The bytes are
            // identical, which is why this is asserted on inode identity and link count.
            let (_d, store) = store();
            commit_tree(&store, "acme", TREE, &[("dep.tar", b"a proprietary dependency", false)]);
            let globex = commit_tree(&store, "globex", TREE, &[("dep.tar", b"a proprietary dependency", false)]);
            stamp(&store, "acme", TREE, t0() - 30 * DAY);
            stamp(&store, "globex", TREE, t0() - 30 * DAY);

            let globex_file = globex.path.join("dep.tar");
            let globex_ino = id_of(&globex_file);

            let report = store.reclaim("acme", &at(t0(), 7 * DAY)).unwrap();

            assert_eq!(report.trees_removed, 1);
            assert_eq!(report.blobs_removed, 1);
            assert!(!store.has("acme", TREE));
            assert_eq!(blobs(&store, "acme").len(), 0, "acme's blob store is empty");

            // Globex is untouched by every measure: the tree, the inode, the link count, the bytes.
            assert!(store.has("globex", TREE), "one tenant's retention is not another's");
            assert_eq!(blobs(&store, "globex").len(), 1);
            assert_eq!(id_of(&globex_file), globex_ino);
            assert_eq!(nlink(&globex_file), 2, "globex's blob + globex's tree entry, exactly as before");
            assert_eq!(fs::read(&globex_file).unwrap(), b"a proprietary dependency");
        }

        #[test]
        fn a_reclaim_racing_a_commit_leaves_every_committed_tree_correct() {
            // The interleaving that matters in production: a sweep is running while fetches keep
            // publishing. A commit takes its pin before it stages anything, so the tree it is about
            // to publish cannot be condemned underneath it — and the blob it links to can be, which
            // is the residual the module docs describe and which costs dedup, never data.
            //
            // The pre-seeded old trees are what keep this from passing vacuously: the sweeps have to
            // have actually removed something.
            const TENANT: &str = "acme";
            const OLD: usize = 12;
            let (_d, store) = store();

            let old_ids: Vec<String> = (0..OLD).map(|i| format!("{:0>64}", format!("a{i}"))).collect();
            for (i, id) in old_ids.iter().enumerate() {
                commit_tree(&store, TENANT, id, &[("junk", format!("old {i}").as_bytes(), false)]);
                stamp(&store, TENANT, id, t0() - 30 * DAY);
            }

            // The trees the racing committer publishes. Their contents overlap, so the committer is
            // exercising the shared-blob path the sweep is walking at the same time.
            let new_ids: Vec<String> = (0..12).map(|i| format!("{:0>64}", format!("b{i}"))).collect();
            const SHARED: &[u8] = b"a dependency every branch of the fan-out holds\n";

            let (committed, swept) = std::thread::scope(|scope| {
                let committer = {
                    let store = store.clone();
                    let ids = new_ids.clone();
                    scope.spawn(move || {
                        ids.iter()
                            .enumerate()
                            .map(|(i, id)| {
                                let unique = format!("unique {i}");
                                commit_tree(
                                    &store,
                                    TENANT,
                                    id,
                                    &[
                                        ("vendor/dep.rs", SHARED, false),
                                        ("only-mine", unique.as_bytes(), false),
                                    ],
                                )
                            })
                            .collect::<Vec<_>>()
                    })
                };
                let sweepers: Vec<_> = (0..3)
                    .map(|_| {
                        let store = store.clone();
                        scope.spawn(move || {
                            let mut total = ReclaimReport::default();
                            for _ in 0..8 {
                                let r = store.reclaim(TENANT, &at(t0(), 7 * DAY)).unwrap();
                                total.trees_removed += r.trees_removed;
                                total.blobs_removed += r.blobs_removed;
                                total.blobs_restored += r.blobs_restored;
                                total.errors += r.errors;
                                total.first_error = total.first_error.or(r.first_error);
                            }
                            total
                        })
                    })
                    .collect();
                let committed = committer.join().expect("a commit racing a sweep must not panic");
                let swept: Vec<_> =
                    sweepers.into_iter().map(|h| h.join().expect("a sweep racing a commit must not panic")).collect();
                (committed, swept)
            });

            let removed: usize = swept.iter().map(|r| r.trees_removed).sum();
            let errors: usize = swept.iter().map(|r| r.errors).sum();
            assert_eq!(errors, 0, "concurrent sweeps must not fail each other: {:?}", swept[0].first_error);
            assert_eq!(
                removed, OLD,
                "every stale tree is removed exactly once across all sweeps — the rename is what \
                 arbitrates, so a double count would mean two of them deleted the same directory"
            );
            for id in &old_ids {
                assert!(!store.has(TENANT, id));
            }

            // The whole point: nothing the sweeps did damaged a tree the committer published.
            assert_eq!(committed.len(), new_ids.len());
            for (i, t) in committed.iter().enumerate() {
                assert!(store.has(TENANT, &new_ids[i]), "a committed tree was reclaimed out from under its holder");
                assert_eq!(fs::read(t.path.join("vendor/dep.rs")).unwrap(), SHARED);
                assert_eq!(fs::read_to_string(t.path.join("only-mine")).unwrap(), format!("unique {i}"));
                let names: Vec<_> = fs::read_dir(&t.path)
                    .unwrap()
                    .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect();
                assert_eq!(names.len(), 2, "the published tree holds exactly its own entries: {names:?}");
            }

            // A final quiet sweep: whatever the concurrent ones left behind (a sweep can finish its
            // blob phase before another finishes deleting trees) is garbage, and goes now.
            let last = store.reclaim(TENANT, &at(t0(), 7 * DAY)).unwrap();
            assert_eq!(last.errors, 0);
            for id in &new_ids {
                assert!(store.has(TENANT, id), "the committed trees are still fresh and still here");
            }
            // Nothing the committer published lost its data to the race. Dedup may have been lost on
            // a file or two — that is the documented residual — but every byte is still there.
            for (i, t) in committed.iter().enumerate() {
                assert_eq!(fs::read(t.path.join("vendor/dep.rs")).unwrap(), SHARED, "tree {i}");
            }
        }

        #[test]
        fn every_removal_survives_the_thing_already_being_gone() {
            // `ENOENT` is what losing a race looks like, and it can arrive at any step: the tree
            // directory, its stamp, or the blob. None of them may count as an error, because the
            // report's `errors` is what an operator would page on.
            let (_d, store) = store();
            commit_tree(&store, "acme", TREE, &[("a", b"one", false)]);
            commit_tree(&store, "acme", TREE2, &[("b", b"two", false)]);
            stamp(&store, "acme", TREE, t0() - 30 * DAY);
            stamp(&store, "acme", TREE2, t0() - 30 * DAY);

            // A tree deleted behind the sweep's back, and a stamp for a tree that never existed.
            fs::remove_dir_all(store.tree_path("acme", TREE)).unwrap();
            stamp(&store, "acme", TREE3, t0() - 30 * DAY);
            // A blob unlinked behind its back too — the one belonging to the tree we just deleted.
            for name in blobs(&store, "acme") {
                let (shard, file) = name.split_once('/').unwrap();
                let p = store.root.join(ContentStore::tenant_scope("acme")).join("blobs").join(shard).join(file);
                if fs::read(&p).map(|b| b == b"one").unwrap_or(false) {
                    fs::remove_file(&p).unwrap();
                }
            }

            let first = store.reclaim("acme", &at(t0(), 7 * DAY)).unwrap();
            assert_eq!(first.errors, 0, "{:?}", first.first_error);
            assert_eq!(first.trees_removed, 1, "the tree that was still there");
            assert!(!store.used_path("acme", TREE).exists(), "the vanished tree's stamp was cleaned up");
            assert!(!store.used_path("acme", TREE3).exists(), "and so was the stamp with no tree at all");

            // Idempotent: a second sweep over a scope with nothing left finds nothing and complains
            // about nothing. This is also the ENOENT path for every removal at once.
            let second = store.reclaim("acme", &at(t0(), 7 * DAY)).unwrap();
            assert_eq!(second, ReclaimReport::default(), "a second sweep is a no-op, not a pile of errors");

            // And a tenant this store has never held anything for is not an error either — a sweep
            // walks a list of tenants, and one that has pushed nothing is the normal case.
            assert_eq!(store.reclaim("never-seen", &ReclaimPolicy::default()).unwrap(), ReclaimReport::default());
        }

        #[test]
        fn a_tree_with_no_readable_stamp_is_given_a_full_window_rather_than_deleted() {
            // The fail-safe direction, and the one a trees-that-predate-the-feature upgrade takes.
            // Guessing "very old" here would delete a tenant's entire store on the first sweep after
            // a deploy, which is the worst available outcome for a bug in a stamp reader.
            let (_d, store) = store();
            commit_tree(&store, "acme", TREE, &[("a", b"no stamp", false)]);
            commit_tree(&store, "acme", TREE2, &[("b", b"bad stamp", false)]);
            fs::remove_file(store.used_path("acme", TREE)).unwrap();
            fs::write(store.used_path("acme", TREE2), b"not a number").unwrap();

            let report = store.reclaim("acme", &at(t0(), Duration::ZERO)).unwrap();
            assert_eq!(report.trees_removed, 0, "an unreadable age is not evidence of age");
            assert_eq!(report.trees_in_retention, 2);
            assert!(store.has("acme", TREE));
            assert!(store.has("acme", TREE2));

            // And they were restamped, so they are due one retention window from now rather than
            // being immortal.
            assert!(store.last_used("acme", TREE).is_some(), "the sweep repaired the missing stamp");
            assert!(store.last_used("acme", TREE2).is_some());
            let later = SystemTime::now() + 30 * DAY;
            assert_eq!(store.reclaim("acme", &at(later, 7 * DAY)).unwrap().trees_removed, 2);
        }

        #[test]
        fn a_use_stamp_from_the_future_keeps_a_tree_rather_than_deleting_it() {
            // A clock stepped backwards by NTP makes every stamp look like the future. `duration_since`
            // fails there, and the failure has to mean "keep" — a reaper that read a negative age as
            // a very large one would empty the store on the first bad sync.
            let (_d, store) = store();
            commit_tree(&store, "acme", TREE, &[("a", b"x", false)]);
            commit_tree(&store, "acme", TREE2, &[("b", b"y", false)]);
            stamp(&store, "acme", TREE, t0() + 30 * DAY);
            stamp(&store, "acme", TREE2, t0() - 30 * DAY);

            let report = store.reclaim("acme", &at(t0(), 7 * DAY)).unwrap();
            assert_eq!(report.trees_in_retention, 1);
            assert_eq!(report.trees_removed, 1);
            assert!(store.has("acme", TREE), "a stamp in the future is not an old tree");
            assert!(!store.has("acme", TREE2));
        }

        #[test]
        fn a_tree_is_never_visible_half_removed_even_when_its_deletion_fails() {
            // Removal is a rename out of the addressed namespace followed by a deletion, mirroring
            // the one-rename publish. The difference from a plain `remove_dir_all` is invisible on a
            // deletion that succeeds — both end with the tree gone — so this forces the deletion to
            // *fail*, which is the case the ordering exists for.
            //
            // A directory the process cannot write to cannot have its children unlinked. So a tree
            // holding one is a tree `remove_dir_all` cannot finish, and the two implementations
            // separate cleanly: renaming first takes the tree out of the addressed namespace before
            // anything is unlinked, so `has()` is false and no reader can catch a directory that is
            // half a tree; deleting in place leaves `trees/{tree_id}` present with some of its
            // entries already gone — a tree that passes `has()` and no longer hashes to its own name.
            let (_d, store) = store();
            commit_tree(
                &store,
                "acme",
                TREE,
                &[("top.txt", b"deleted first", false), ("locked/inner.txt", b"cannot be unlinked", false)],
            );
            let locked = store.tree_path("acme", TREE).join("locked");
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).unwrap();
            // Root ignores the mode, which would make this test pass without discriminating. Loud
            // rather than silently skipped: a test that quietly proves nothing is worse than absent.
            assert!(
                fs::write(locked.join("probe"), b"x").is_err(),
                "this test needs a user the directory mode applies to; it cannot discriminate as root"
            );
            stamp(&store, "acme", TREE, t0() - 30 * DAY);

            let report = store.reclaim("acme", &at(t0(), 7 * DAY)).unwrap();

            assert!(
                !store.has("acme", TREE),
                "a tree whose deletion failed is still gone from its content address: leaving it \
                 there half-emptied is a directory that passes `has()` and no longer hashes to its \
                 own name"
            );
            assert_eq!(report.trees_removed, 1, "the removal counts, because the address is free");
            assert_eq!(
                report.errors, 1,
                "and the deletion that could not finish is reported rather than swallowed"
            );
            assert!(report.first_error.unwrap().contains("deleting reclaimed trees"));

            // Put it back so the fixture's own teardown can finish; the leftover is the residual the
            // module docs name (scratch orphaned by a failure), not something this test asserts away.
            let scratch = store.root.join(ContentStore::tenant_scope("acme")).join("reclaiming");
            let mut pending = vec![scratch.clone()];
            while let Some(dir) = pending.pop() {
                let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o755));
                for e in fs::read_dir(&dir).into_iter().flatten().flatten() {
                    if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        pending.push(e.path());
                    }
                }
            }
            fs::remove_dir_all(&scratch).unwrap();
        }

        #[test]
        fn a_clean_removal_leaves_no_scratch_and_returns_every_byte() {
            // The ordinary path, and the counterpart to the test above: when the deletion does
            // succeed, nothing is left anywhere — not in the addressed namespace, and not in the
            // sweep's own scratch space, which would otherwise just be a new place for the store to
            // grow without bound.
            let (_d, store) = store();
            commit_tree(&store, "acme", TREE, &[("a/b/c", b"deep", false), ("x", b"shallow", false)]);
            stamp(&store, "acme", TREE, t0() - 30 * DAY);

            let report = store.reclaim("acme", &at(t0(), 7 * DAY)).unwrap();
            assert_eq!(report.trees_removed, 1);
            assert_eq!(report.blobs_removed, 2);
            assert_eq!(report.errors, 0);

            let scope = store.root.join(ContentStore::tenant_scope("acme"));
            assert_eq!(fs::read_dir(scope.join("trees")).unwrap().count(), 0, "the tree directory is empty");
            assert_eq!(
                fs::read_dir(scope.join("reclaiming")).unwrap().count(),
                0,
                "and the sweep's scratch space is cleaned up rather than becoming the new leak"
            );
            assert_eq!(content_bytes(&store, "acme"), 0, "every byte the tree cost is back");
        }

        #[test]
        fn a_commit_whose_blob_the_sweep_took_still_shares_rather_than_copying() {
            // The commit side of the documented race, at the interleaving no outside caller can
            // produce: `share_one` saw `EEXIST`, so the blob was there — and by the time it links,
            // a sweep has renamed it away. `share_with_existing_blob` is called directly with that
            // state arranged, which is the only way to stand between the two syscalls.
            //
            // Without the retry the file lands as a private copy: correct, and quietly costing the
            // dedup the whole store exists for. The second half is the control — the same call with
            // the blob still present has to take the ordinary reuse path, or "it always creates"
            // would pass this too.
            let (_d, store) = store();
            let live = commit_tree(&store, "acme", TREE, &[("a", b"contended bytes", false)]);
            let blob = {
                let p = live.path.join("a");
                let key = BlobKey::of(&p, &fs::symlink_metadata(&p).unwrap()).unwrap();
                store.blob_path("acme", &key)
            };
            assert_eq!(nlink(&blob), 2, "blob + the one tree that holds it");

            // A second tree staged with the same bytes. The sweep takes the blob in the window.
            let staged = store.stage("acme").unwrap();
            let contended = staged.path().join("b");
            fs::write(&contended, b"contended bytes").unwrap();
            let scratch = link_scratch_path(staged.path()).unwrap();
            fs::remove_file(&blob).unwrap();

            let mut report = DedupReport::default();
            store.share_with_existing_blob(&blob, &contended, &scratch, &mut report);

            assert_eq!(report.unshared, 0, "a swept blob must not cost this file its sharing: {report:?}");
            assert_eq!(report.blobs_created, 1, "the commit became the blob instead of keeping a private copy");
            assert!(blob.exists(), "and the blob is back at the name commits look for");
            assert_eq!(fs::read(&contended).unwrap(), b"contended bytes");
            assert_eq!(id_of(&contended), id_of(&blob), "the staged file and the blob are one inode");
            assert!(!scratch.exists(), "no scratch link is left beside the staged tree");

            // The control: with the blob present, the same call reuses it rather than recreating.
            let third = staged.path().join("c");
            fs::write(&third, b"contended bytes").unwrap();
            let mut report = DedupReport::default();
            store.share_with_existing_blob(&blob, &third, &scratch, &mut report);
            assert_eq!(report, DedupReport { blobs_reused: 1, ..DedupReport::default() });
            assert_eq!(id_of(&third), id_of(&blob));
        }

        #[test]
        fn a_blob_a_commit_linked_during_the_sweep_is_put_back_rather_than_destroyed() {
            // The sweep side of the race, at the one interleaving a whole-`reclaim` test cannot
            // reach: the blob had `st_nlink == 1` when the sweep looked at it, and a commit linked
            // it before the rename landed. `reclaim_one_blob` is called directly with that state
            // already arranged, because standing between the two observations is not something an
            // outside caller can do — and that is exactly why the branch is a function instead of an
            // inline `continue` no test can enter.
            //
            // The second blob is the control: the same call, on one that really is unreferenced,
            // must delete it. Without it, "the restore works" is satisfied by a sweep that has quietly
            // stopped deleting anything at all.
            let (_d, store) = store();
            let live = commit_tree(&store, "acme", TREE, &[("keep", b"keep me", false)]);

            let orphan_blob = |body: &[u8]| {
                let staged = store.stage("acme").unwrap();
                fs::write(staged.path().join("x"), body).unwrap();
                store.link_into_blobs("acme", staged.path()).unwrap();
                let p = staged.path().join("x");
                let key = BlobKey::of(&p, &fs::symlink_metadata(&p).unwrap()).unwrap();
                store.blob_path("acme", &key)
            };
            let adopted_blob = orphan_blob(b"about to be adopted");
            let doomed_blob = orphan_blob(b"referenced by nothing at all");
            assert_eq!(nlink(&adopted_blob), 1, "both look like garbage at the sweep's first stat");
            assert_eq!(nlink(&doomed_blob), 1);

            // The commit that wins the race: a tree entry now names the same inode.
            let adopted = live.path.join("adopted");
            fs::hard_link(&adopted_blob, &adopted).unwrap();

            let scratch = store.staging_dir("acme").unwrap();
            let mut report = ReclaimReport::default();
            store.reclaim_one_blob(&adopted_blob, &scratch.join("held-1"), &mut report);
            store.reclaim_one_blob(&doomed_blob, &scratch.join("held-2"), &mut report);

            assert_eq!(report.errors, 0, "{:?}", report.first_error);
            assert_eq!(report.blobs_restored, 1, "the blob a commit had just linked was put back");
            assert_eq!(report.blobs_removed, 1, "and the one nobody linked was still deleted");
            assert!(!doomed_blob.exists());
            assert!(!scratch.join("held-1").exists(), "the sweep leaves no scratch name behind");
            assert!(!scratch.join("held-2").exists());

            assert!(adopted_blob.exists(), "a blob a tree references must survive the sweep that condemned it");
            assert_eq!(id_of(&adopted_blob), id_of(&adopted), "and be the tree's inode, not a copy of it");
            assert_eq!(nlink(&adopted_blob), 2, "blob + tree entry: the sharing survived");
            assert_eq!(fs::read(&adopted).unwrap(), b"about to be adopted");

            // The restore is only worth anything if a later tree can still share it — which is the
            // whole reason not to just delete and let the tree entry keep the bytes.
            let next = commit_tree(&store, "acme", TREE2, &[("same", b"about to be adopted", false)]);
            assert_eq!(next.dedup.unwrap().blobs_reused, 1, "the restored blob is a live blob again");
            assert_eq!(id_of(&next.path.join("same")), id_of(&adopted));
        }
    }
}
