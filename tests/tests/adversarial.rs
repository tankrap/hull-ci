//! **The adversarial cases from the runner design, D§14 ("How we prove it").**
//!
//! The §11 checklist says what a well-behaved CI does when everything is normal. These are the cases
//! that decide whether it *fails closed*: a wrong secret in either direction, a dispatch from a
//! future contract version, an archive that is not the tree it claims to be, and a job whose output
//! is written by an attacker.
//!
//! Three of these enforce a spec **MAY**/**SHOULD** that our own design promotes to a MUST for
//! `hull-ci` (D§4.2: "re-hashes to tree_id — §5 permits it; we make it mandatory"). They are marked
//! and can be switched off with `HULL_CI_SKIP_STRICT=1` when judging a third-party CI that is
//! conforming but not ours.

use hull_ci_conformance::{
    bidi_characters, config, control_characters, describe_requests, escape_for_message,
    hull::{Source, StubHull, SECRET_HEADER, VERSION_HEADER},
    tree::{self, TreeFile},
};

fn hull() -> StubHull {
    StubHull::start(Some(config::secret()))
}

// ── Wrong secret, direction 1: Hull → CI (spec §8, §11.2) ───────────────────────────────────────

#[test]
fn adversarial_dispatch_with_no_secret_at_all_is_refused() {
    // The wrong-value case lives in conformance.rs (§11.2). This is the other half an attacker would
    // actually try first: no header at all, hoping the check is `if header_present && header != s`.
    let hull = hull();
    let job = hull.job().with_secret(None);

    let response = hull.dispatch(&job).expect("dispatch failed to send");
    assert!(
        !response.is_success(),
        "CI-SPEC §8 / §11.2: a dispatch with no {SECRET_HEADER} at all MUST be refused by an endpoint \
         that has a secret configured — a presence-guarded comparison (`if h and h != secret`) lets an \
         unauthenticated caller queue jobs. The endpoint answered {}.",
        response.status,
    );

    hull.settle();
    assert!(
        hull.source_fetches(&job.token).is_empty() && hull.callbacks(&job.token).is_empty(),
        "CI-SPEC §8: an unauthenticated dispatch MUST NOT do work. Source fetches: {}; callbacks: {}",
        describe_requests(&hull.source_fetches(&job.token)),
        hull.callbacks(&job.token).len(),
    );
}

// ── Wrong secret, direction 2: CI → Hull (spec §8) ──────────────────────────────────────────────

#[test]
fn adversarial_callback_with_missing_or_wrong_secret_is_401_and_records_nothing() {
    // Direction 2 is not something a *conforming* CI can be made to do on demand — there is no
    // black-box lever that makes it send a bad secret. What the suite can do, and what matters for
    // every other assertion in it, is prove that the receiving side actually enforces §8: if the stub
    // Hull accepted anything, "the runner echoed the secret" would be unfalsifiable and §11.4's
    // assertion would be worthless. So this test drives the receiver directly.
    let hull = hull();
    let job = hull.job();

    let no_secret = hull
        .post_callback_directly(&job, None, r#"{"status":"green","summary":"forged"}"#)
        .expect("callback failed to send");
    assert_eq!(
        no_secret.status, 401,
        "CI-SPEC §8: a callback with no {SECRET_HEADER} MUST be rejected 401; got {}",
        no_secret.status,
    );

    let wrong_secret = hull
        .post_callback_directly(
            &job,
            Some(&config::wrong_secret()),
            r#"{"status":"green","summary":"forged"}"#,
        )
        .expect("callback failed to send");
    assert_eq!(
        wrong_secret.status, 401,
        "CI-SPEC §8: a callback with a wrong {SECRET_HEADER} MUST be rejected 401; got {}",
        wrong_secret.status,
    );

    assert!(
        hull.accepted_callbacks(&job.token).is_empty(),
        "CI-SPEC §8: 'a missing or wrong secret on the callback is rejected 401, and **no verdict is \
         recorded**' — {} verdict(s) were recorded anyway",
        hull.accepted_callbacks(&job.token).len(),
    );
    assert_eq!(
        hull.rejected_callbacks(&job.token).len(),
        2,
        "both forged callbacks should have been seen and refused",
    );
}

#[test]
fn adversarial_callback_with_an_invalid_status_is_refused_400() {
    // §7: "`green` | `red` | `errored`. Anything else → 400." Same reasoning as above — this pins the
    // receiver so that §11.4's `callback.accepted` assertion means something.
    let hull = hull();
    let job = hull.job();

    for body in [
        r#"{"status":"passed","summary":"wrong vocabulary"}"#,
        r#"{"status":"GREEN"}"#,
        r#"{"summary":"no status at all"}"#,
        r#"not json at all"#,
    ] {
        let response = hull
            .post_callback_directly(&job, Some(&config::secret()), body)
            .expect("callback failed to send");
        assert_eq!(
            response.status, 400,
            "CI-SPEC §7: status must be green|red|errored, anything else → 400. Body {} got {}",
            escape_for_message(body),
            response.status,
        );
    }
    assert!(
        hull.accepted_callbacks(&job.token).is_empty(),
        "CI-SPEC §7: an invalid status MUST NOT be recorded as a verdict",
    );
}

// ── An unknown contract major (spec §13, design D§14) ───────────────────────────────────────────

#[test]
fn adversarial_dispatch_with_an_unknown_major_version_is_refused() {
    if !config::strict() {
        config::skipped_strict("§13: refusing an unknown X-Hull-CI-Version major");
        return;
    }
    let hull = hull();
    let job = hull.job().with_version(Some("2"));

    let response = hull.dispatch(&job).expect("dispatch failed to send");
    assert!(
        !response.is_success(),
        "CI-SPEC §13 (STRICT — design D§14): a dispatch announcing an unknown contract major MUST be \
         refused rather than guessed at. Version 2 exists precisely to rename or re-mean fields, so a \
         v1 runner that proceeds is interpreting a payload it cannot read — and will report a verdict \
         about the wrong thing. The endpoint answered {} to {VERSION_HEADER}: 2. \
         (Set HULL_CI_SKIP_STRICT=1 if the endpoint under test is a spec-minimal third party: §13 puts \
         the version negotiation duty on Hull, so tolerating it is not itself a spec violation.)",
        response.status,
    );

    hull.settle();
    assert!(
        hull.callbacks(&job.token).is_empty(),
        "CI-SPEC §13 (STRICT): a refused dispatch MUST NOT produce a verdict; got {}",
        hull.callbacks(&job.token).len(),
    );
}

// ── An archive that is not the tree it claims to be (spec §6, design D§4.2) ─────────────────────

#[test]
fn adversarial_corrupt_archive_must_fail_the_tree_id_rehash_rather_than_run() {
    if !config::strict() {
        config::skipped_strict("§6: re-hashing the fetched archive to tree_id before running it");
        return;
    }
    let hull = hull();

    // Advertise the content address of one tree and serve the bytes of another. The served archive is
    // a perfectly valid tar — the only thing wrong with it is that it is not the tree the dispatch
    // named, which is exactly the case a content-addressed fetch exists to catch.
    let advertised = tree::benign_project();
    let substituted = vec![
        TreeFile::new("README.md", "# not the tree you asked for\n"),
        TreeFile::executable("run-tests.sh", "#!/bin/sh\necho \"attacker's tests pass\"\nexit 0\n"),
        TreeFile::new("Makefile", "test:\n\t@echo \"attacker's tests pass\"\n"),
    ];
    let job = hull.job_raw(&tree::tree_id(&advertised));
    hull.set_source(&job.token, Source::Tar(tree::tar(&substituted)));

    hull.dispatch(&job).expect("dispatch failed to send");

    let callback = hull.wait_for_callback(&job.token).unwrap_or_else(|| {
        panic!(
            "CI-SPEC §6 (STRICT — design D§4.2): the runner must verify the fetched archive re-hashes \
             to tree_id and abort → `errored`. No callback arrived within {:?}, so we cannot tell \
             whether it refused the tree or silently ran it.",
            config::callback_timeout()
        )
    });

    let status = callback.status.as_deref().unwrap_or("<none>");
    assert!(
        status != "green",
        "CI-SPEC §6 (STRICT — design D§4.2): the runner reported `green` for an archive that does not \
         hash to the dispatch's tree_id. Hull memoises green by tree_id, so this writes a verdict about \
         *substituted* content against the address of the real tree — the failure mode content \
         addressing exists to prevent. Advertised {} and served a different tree.",
        &job.tree_id[..16],
    );
    assert_eq!(
        status, "errored",
        "CI-SPEC §6 / §7 (STRICT — design D§4.2): a tree_id mismatch is our failure, not the code's, \
         so it MUST be `errored` (not memoised) rather than `red` (memoised as a statement about the \
         code). Got {status:?}.",
    );
}

#[test]
fn adversarial_unextractable_archive_reports_errored_not_a_verdict_about_the_code() {
    // Not strict: this needs no tree_id verification at all. Any runner must notice that what came
    // back is not a tar, and §7 is unambiguous that a fetch/extract failure is `errored`.
    let hull = hull();
    let job = hull.job_raw("0000000000000000000000000000000000000000000000000000000000000000");
    hull.set_source(
        &job.token,
        Source::Tar(b"this is not a tar archive, it is 47 bytes of prose".to_vec()),
    );

    hull.dispatch(&job).expect("dispatch failed to send");

    let callback = hull.wait_for_callback(&job.token).unwrap_or_else(|| {
        panic!(
            "CI-SPEC §7: a fetch or extract failure MUST still produce a verdict — `errored`. \
             source_url served a non-tar body and no callback arrived within {:?}; the tree is left \
             unverified with nothing to explain it, which §10 says a human then has to chase.",
            config::callback_timeout()
        )
    });

    assert_eq!(
        callback.status.as_deref().unwrap_or("<none>"),
        "errored",
        "CI-SPEC §7 / §11.5: an archive that cannot be extracted is an infrastructure failure — \
         `errored`, never `red`, because `red` is memoised as a statement about the code. Got {:?}.",
        callback.status,
    );
}

// ── Hostile job output (spec §14.5, design D§14) ────────────────────────────────────────────────

#[test]
fn adversarial_hostile_job_output_never_reaches_hull_as_control_characters() {
    if !config::strict() {
        config::skipped_strict("§14.5: sanitising and capping `summary` built from job output");
        return;
    }
    let hull = hull();
    // The tree's checks emit ANSI colour and screen-clear sequences, a NUL, a bidi override, embedded
    // CRLFs that look like extra JSON fields, and 64 KiB of padding — on every entry point a runner
    // might autodetect.
    let job = hull.job_with_tree(&tree::hostile_output_project());
    hull.dispatch(&job).expect("dispatch failed to send");

    let callback = hull.wait_for_callback(&job.token).unwrap_or_else(|| {
        panic!(
            "CI-SPEC §14.5: a job that floods its output must still produce a verdict; none arrived \
             within {:?} — a runner that hangs or OOMs on job output is the denial-of-service §14.4 \
             calls for capping.",
            config::callback_timeout()
        )
    });

    let summary = callback.summary.clone().unwrap_or_default();

    let control = control_characters(&summary);
    assert!(
        control.is_empty(),
        "CI-SPEC §14.5: 'never let job output smuggle control characters'. The runner passed {control:?} \
         through into `summary`, which Hull renders in its UI and notifications. Summary: {}",
        escape_for_message(&summary),
    );
    assert!(
        !summary.contains('\u{1b}'),
        "CI-SPEC §14.5: an ANSI escape introducer survived into `summary`: {}",
        escape_for_message(&summary),
    );
    let bidi = bidi_characters(&summary);
    assert!(
        bidi.is_empty(),
        "CI-SPEC §14.5: bidirectional-override characters {bidi:?} survived into `summary` — they let \
         job output render as text it is not. Summary: {}",
        escape_for_message(&summary),
    );
    assert!(
        summary.chars().count() <= config::summary_max_chars(),
        "CI-SPEC §14.4/§14.5: captured output MUST be capped so a job cannot flood the runner or the \
         UI. `summary` came back {} chars long (cap {}); the job emitted 64 KiB deliberately.",
        summary.chars().count(),
        config::summary_max_chars(),
    );

    // §14.5's other half: output must not be able to forge *fields*. The fixture prints a fragment
    // that reads as `"status": "green", "summary": "forged"`; if the runner built its JSON by string
    // concatenation, the body would parse with the job's chosen status.
    let parsed: serde_json::Value =
        serde_json::from_str(&callback.body).unwrap_or(serde_json::Value::Null);
    assert!(
        parsed.is_object(),
        "CI-SPEC §7: the callback body must be a JSON object even when the job's output is hostile; \
         got {}",
        escape_for_message(&callback.body),
    );
    assert!(
        !summary.contains("\"status\""),
        "CI-SPEC §14.5: job output smuggled a `status` fragment into `summary` — the runner is \
         concatenating job bytes into its JSON rather than encoding them. Summary: {}",
        escape_for_message(&summary),
    );

    // A runner that never executes anything (the reference stand-in, for one) passes this test
    // trivially: no job output means no hostile bytes to leak. That is not detectable from Hull's end
    // — the same clean callback is indistinguishable from a correctly sanitised one — so this test
    // proves the absence of a leak, not the presence of a sanitiser.
}
