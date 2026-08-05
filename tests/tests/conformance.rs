//! **CI-SPEC.md §11, the conformance checklist — one test per line.**
//!
//! Each test names the clause it enforces, and each failure message says which MUST broke and what
//! the endpoint did instead. Run with `cargo test` from `hull-ci/tests` against any CI endpoint
//! (`HULL_CI_ENDPOINT`); see README.md.

use hull_ci_conformance::{
    config, control_characters, describe_requests, escape_for_message,
    hull::{Source, StubHull, SECRET_HEADER},
    tree, VALID_STATUSES,
};

/// A stub Hull configured with the shared secret the endpoint under test is expected to know (§8).
fn hull() -> StubHull {
    StubHull::start(Some(config::secret()))
}

// ── §11.1 — "Accepts POST at its configured endpoint and returns 2xx on receipt." ────────────────

#[test]
fn spec_11_1_accepts_post_and_returns_2xx_on_receipt() {
    let hull = hull();
    let job = hull.job();

    let response = hull
        .dispatch(&job)
        .expect("CI-SPEC §11.1: the CI endpoint must accept a POST — the connection itself failed");

    assert!(
        response.is_success(),
        "CI-SPEC §11.1 / §5: a dispatch MUST be acknowledged with 2xx on receipt \
         (acknowledgement is 'accepted', not 'done'). {} answered {} — Hull treats any non-2xx as a \
         failed dispatch and surfaces an error to the caller. Body: {}",
        config::endpoint(),
        response.status,
        escape_for_message(&response.body_text()),
    );

    // Deliberately not asserted: *how promptly* the ack came. The reference CI answers with an
    // unframed HTTP/1.0 response (no Content-Length), so the client cannot distinguish "responded
    // immediately, closed late" from "responded late" without timing the first byte, which is below
    // the level this suite works at. §5's "promptly" is covered in practice by the callback timeout.
}

// ── §11.2 — "Verifies X-Hull-CI-Secret on dispatch when a secret is configured." ─────────────────

#[test]
fn spec_11_2_accepts_dispatch_carrying_the_configured_secret() {
    let hull = hull();
    let job = hull.job();

    let response = hull.dispatch(&job).expect("dispatch failed to send");
    assert!(
        response.is_success(),
        "CI-SPEC §11.2 / §8: a dispatch carrying the *correct* {SECRET_HEADER} MUST be accepted; \
         got {}. (If this endpoint is configured with a different secret, set HULL_CI_SECRET.)",
        response.status,
    );

    let fetches = hull.wait_for_source_fetch(&job.token);
    assert!(
        !fetches.is_empty(),
        "CI-SPEC §11.2: an authenticated dispatch must actually start the job — the endpoint \
         acknowledged it but never fetched source_url within {:?}",
        config::callback_timeout(),
    );
}

#[test]
fn spec_11_2_rejects_dispatch_carrying_a_wrong_secret() {
    let hull = hull();
    let job = hull.job().with_secret(Some(&config::wrong_secret()));

    let response = hull.dispatch(&job).expect("dispatch failed to send");
    assert!(
        !response.is_success(),
        "CI-SPEC §11.2 / §8: a dispatch whose {SECRET_HEADER} does not match the configured secret \
         MUST be rejected, not run. The endpoint answered {} and accepted the job. \
         (An endpoint configured with no secret at all fails here — that is the finding, not a false \
         alarm: §8 says an endpoint SHOULD configure one, and this suite cannot verify §11.2 without.)",
        response.status,
    );

    // ...and rejection must mean nothing happened, not "rejected the ack but ran it anyway".
    hull.settle();
    assert!(
        hull.source_fetches(&job.token).is_empty(),
        "CI-SPEC §11.2 / §8: the endpoint rejected the dispatch ({}) but still fetched source_url — \
         a rejected dispatch MUST NOT start work. Fetches: {}",
        response.status,
        describe_requests(&hull.source_fetches(&job.token)),
    );
    assert!(
        hull.callbacks(&job.token).is_empty(),
        "CI-SPEC §11.2 / §8: the endpoint rejected the dispatch but still posted a verdict to \
         callback_url — an unauthenticated dispatch MUST NOT produce a verdict.",
    );
}

// ── §11.3 — "Fetches source_url (keel tree tar), extracts, runs its checks in isolation — no git." ─

#[test]
fn spec_11_3_fetches_the_source_url_it_was_given() {
    let hull = hull();
    let job = hull.job();
    hull.dispatch(&job).expect("dispatch failed to send");

    let fetches = hull.wait_for_source_fetch(&job.token);
    assert!(
        !fetches.is_empty(),
        "CI-SPEC §11.3 / §6: the runner MUST fetch source_url — the only fetch path in contract v1. \
         Nothing arrived at {} within {:?}. Other requests seen: {}",
        job.source_target(),
        config::callback_timeout(),
        describe_requests(&hull.unmatched()),
    );

    let first = &fetches[0];
    assert_eq!(
        first.method, "GET",
        "CI-SPEC §6: source_url is fetched with GET; the runner used {}",
        first.method,
    );
    assert_eq!(
        first.target,
        job.source_target(),
        "CI-SPEC §5: source_url is **opaque** — GET it verbatim, never rebuild it. The runner asked \
         for {:?} instead of {:?}",
        first.target,
        job.source_target(),
    );
}

#[test]
fn spec_11_3_makes_no_git_shaped_requests_to_hull() {
    let hull = hull();
    let job = hull.job();
    hull.dispatch(&job).expect("dispatch failed to send");
    hull.wait_for_source_fetch(&job.token);
    hull.wait_for_callback(&job.token);

    // §6: "do not `git clone`. A runner that shells out to git for source is not conforming; there
    // is no ref to check out and no `.git` in the archive." The dispatch contains no git URL at all,
    // so a runner that tried would have to invent one against the only host it knows: this Hull.
    let git_shaped: Vec<_> = hull
        .unmatched()
        .into_iter()
        .filter(|r| {
            let t = r.target.to_ascii_lowercase();
            t.contains("info/refs")
                || t.contains("git-upload-pack")
                || t.contains("git-receive-pack")
                || t.ends_with(".git")
                || t.contains(".git/")
        })
        .collect();

    assert!(
        git_shaped.is_empty(),
        "CI-SPEC §11.3 / §6: source is fetched by content address over keel, never with git. \
         The runner made git-protocol requests to Hull: {}",
        describe_requests(&git_shaped),
    );

    // The stronger claim — that the runner never shelled out to git *anywhere* — is not observable
    // from Hull's end of the wire and is not asserted here. It is provable only inside the runner
    // (watch the sandbox's egress, or its process table); see lib.rs, "What a black-box suite cannot
    // see". What this test does establish is that no clone was attempted against the one host the
    // dispatch names.
}

#[test]
fn spec_11_3_runs_the_checks_it_finds_in_the_fetched_tree() {
    let hull = hull();
    let job = hull.job();
    hull.dispatch(&job).expect("dispatch failed to send");

    let callback = hull.wait_for_callback(&job.token).unwrap_or_else(|| {
        panic!(
            "CI-SPEC §11.3: after fetching source_url the runner must run its checks and report; \
             no callback arrived within {:?}",
            config::callback_timeout()
        )
    });

    assert!(
        VALID_STATUSES.contains(&callback.status.as_deref().unwrap_or("")),
        "CI-SPEC §7: status MUST be one of {VALID_STATUSES:?}; got {:?} (body: {})",
        callback.status,
        escape_for_message(&callback.body),
    );

    // "in isolation" (§11.3, §14.1) is a property of the runner's own sandbox and cannot be seen from
    // here — deliberately not asserted rather than asserted vacuously.
}

#[test]
fn spec_11_3_does_not_report_errored_for_a_well_formed_tree() {
    // `green` is not assertable — whether the fixture's checks pass is the CI's business, and a
    // runner with no `make` may legitimately disagree with one that has it. `errored` is different:
    // §7 defines it as a statement about the *runner*, "anything that stops us producing a verdict
    // about the code". This dispatch is well-formed, its `source_url` serves a valid archive, and
    // that archive really is the tree the dispatch names — so there is nothing here to be stopped by.
    //
    // Without this line the checklist is satisfiable by a CI that refuses every job: each of the
    // other tests accepts any of the three statuses, and `errored` is one of them. That matters most
    // for the thing this file cannot see — `HULL_CI_TREE_ID`. Point the suite at a *verifying* runner
    // in the wrong addressing mode and every job legitimately fails its `tree_id` re-hash; the
    // endpoint is doing exactly the right thing, the harness is at fault, and every other assertion
    // in this file stays green while it happens.
    let hull = hull();
    let job = hull.job();
    hull.dispatch(&job).expect("dispatch failed to send");

    let callback = hull.wait_for_callback(&job.token).unwrap_or_else(|| {
        panic!(
            "CI-SPEC §11.3: no callback arrived within {:?}",
            config::callback_timeout()
        )
    });

    assert_ne!(
        callback.status.as_deref(),
        Some("errored"),
        "CI-SPEC §7 / §11.3: `errored` means the runner could not produce a verdict about the code, \
         but this job gave it nothing to fail on — a valid tar, served at the exact source_url, that \
         re-hashes to the tree_id the dispatch advertised (addressing mode: {}). \
         If the endpoint under test verifies tree_id (ours does — design D§4.2), check that mode \
         first: HULL_CI_TREE_ID=keel for a keel-native runner, `opaque` for a CI that reproduces the \
         canonicalisation documented in src/tree.rs. The endpoint said: {}",
        config::addressing().name(),
        escape_for_message(callback.summary.as_deref().unwrap_or("(no summary)")),
    );
}

// ── §11.4 — "POSTs {status, summary} to the exact callback_url, echoing X-Hull-CI-Secret." ───────

#[test]
fn spec_11_4_posts_the_verdict_to_the_exact_callback_url() {
    let hull = hull();
    let job = hull.job();
    hull.dispatch(&job).expect("dispatch failed to send");

    let callback = hull.wait_for_callback(&job.token).unwrap_or_else(|| {
        panic!(
            "CI-SPEC §11.4 / §7: the runner MUST POST a verdict to callback_url; nothing arrived at \
             {} within {:?}. Requests that hit no route (a reconstructed URL would land here): {}",
            job.callback_target(),
            config::callback_timeout(),
            describe_requests(&hull.unmatched()),
        )
    });

    let actual = match &callback.query {
        Some(q) => format!("{}?{}", callback.path, q),
        None => callback.path.clone(),
    };
    assert_eq!(
        actual,
        job.callback_target(),
        "CI-SPEC §5 / §11.4: callback_url is **opaque** — use it verbatim, do not construct it. \
         The dispatch said {:?} (note the query string); the runner POSTed to {:?}",
        job.callback_target(),
        actual,
    );

    assert!(
        callback.status.is_some(),
        "CI-SPEC §7: the callback body MUST carry a `status` field; got {}",
        escape_for_message(&callback.body),
    );
    assert!(
        callback.accepted,
        "CI-SPEC §11.4: the verdict was refused by Hull with {} — see §7 (status must be \
         green|red|errored) and §8 (the secret must be echoed). Body: {}",
        callback.response_code,
        escape_for_message(&callback.body),
    );
}

#[test]
fn spec_11_4_echoes_the_shared_secret_on_the_callback() {
    let hull = hull();
    let job = hull.job();
    hull.dispatch(&job).expect("dispatch failed to send");

    let callback = hull
        .wait_for_callback(&job.token)
        .expect("CI-SPEC §11.4: no callback arrived, so the secret could not be checked");

    assert_eq!(
        callback.header(SECRET_HEADER),
        Some(config::secret().as_str()),
        "CI-SPEC §11.4 / §8: the callback MUST echo {SECRET_HEADER} when the endpoint has a secret — \
         Hull rejects a missing or wrong one with 401 and records nothing. Headers seen: {:?}",
        callback.headers.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
    );
    assert!(
        hull.rejected_callbacks(&job.token).is_empty(),
        "CI-SPEC §8: Hull rejected {} callback(s) for this job — the verdict was lost.",
        hull.rejected_callbacks(&job.token).len(),
    );
}

// ── §11.5 — "Uses `errored` (not `red`) for infrastructure failures." ───────────────────────────

#[test]
fn spec_11_5_reports_errored_not_red_when_the_source_cannot_be_fetched() {
    let hull = hull();
    let job = hull.job();
    // An induced infrastructure failure that is unambiguous from the runner's side and needs no
    // access to its internals: source_url answers 500, so there is nothing to run and the failure is
    // emphatically not a statement about the code.
    hull.set_source(&job.token, Source::Status(500));

    hull.dispatch(&job).expect("dispatch failed to send");

    let callback = hull.wait_for_callback(&job.token).unwrap_or_else(|| {
        panic!(
            "CI-SPEC §11.5 / §7: when the job cannot produce a verdict the runner MUST report \
             `errored` — silence is not a verdict. source_url returned 500 and no callback arrived \
             within {:?}, so the tree is left unverified with nothing to explain it.",
            config::callback_timeout()
        )
    });

    let status = callback.status.as_deref().unwrap_or("<none>");
    assert_eq!(
        status, "errored",
        "CI-SPEC §11.5 / §7: infrastructure failures MUST be `errored`, never `red` — `red` is a \
         statement about the code and Hull memoises it by tree_id, so reporting `red` for our own \
         outage poisons that tree's verdict until someone forces a re-check. source_url returned 500 \
         and the runner reported {status:?}.",
    );
}

// ── §11.6 — "Ignores unknown dispatch fields (forward-compatible)." ─────────────────────────────

#[test]
fn spec_11_6_ignores_unknown_dispatch_fields() {
    let hull = hull();
    let job = hull
        .job()
        // §13: "Treat any field not defined in this document as reserved." Hull MAY add fields
        // without bumping X-Hull-CI-Version, so an endpoint that rejects them breaks on our next
        // additive release (design G1–G4 are all additive).
        .with_extra("totally_bogus_field", serde_json::json!({"nested": [1, 2, 3]}))
        .with_extra("fetch_token", serde_json::json!("reserved-for-a-future-version"))
        .with_extra("priority", serde_json::json!(7));

    let response = hull.dispatch(&job).expect("dispatch failed to send");
    assert!(
        response.is_success(),
        "CI-SPEC §11.6 / §5: unknown dispatch fields MUST be ignored, not rejected; the endpoint \
         answered {} to a dispatch carrying three extra fields",
        response.status,
    );

    let callback = hull.wait_for_callback(&job.token).unwrap_or_else(|| {
        panic!(
            "CI-SPEC §11.6 / §5: a dispatch with unknown fields must still run to a verdict — the \
             endpoint acknowledged it but never called back within {:?}",
            config::callback_timeout()
        )
    });
    assert!(
        VALID_STATUSES.contains(&callback.status.as_deref().unwrap_or("")),
        "CI-SPEC §11.6: the job ran but reported {:?}, which is not a valid status",
        callback.status,
    );
}

// ── §11.7 — "Is safe under duplicate dispatch and duplicate callback." ──────────────────────────

#[test]
fn spec_11_7_is_safe_under_duplicate_dispatch() {
    let hull = hull();
    let job = hull.job();

    // The same job, twice — identical change, tree_id, source_url and callback_url. §9: Hull's
    // in-flight de-dup is best-effort and in-memory, so the CI "SHOULD itself be idempotent per
    // (tree_id) or per callback_url: a duplicate dispatch MUST be safe to run".
    let first = hull.dispatch(&job).expect("first dispatch failed to send");
    let second = hull.dispatch(&job).expect("second dispatch failed to send");

    assert!(
        first.is_success() && second.is_success(),
        "CI-SPEC §11.7 / §9: a duplicate dispatch MUST be safe — both must be acknowledged 2xx. \
         Got {} then {}.",
        first.status,
        second.status,
    );

    hull.wait_for_callback(&job.token);
    hull.settle();
    let callbacks = hull.callbacks(&job.token);
    assert!(
        !callbacks.is_empty(),
        "CI-SPEC §11.7: two dispatches produced no verdict at all",
    );

    let statuses: Vec<_> = callbacks.iter().map(|c| c.status.clone()).collect();
    let first_status = statuses[0].clone();
    assert!(
        statuses.iter().all(|s| *s == first_status),
        "CI-SPEC §11.7 / §9: duplicate dispatches for one tree MUST NOT disagree — a duplicate \
         callback 're-affirms the same verdict'. Got {statuses:?} for tree {}",
        job.tree_id,
    );
    assert!(
        hull.rejected_callbacks(&job.token).is_empty(),
        "CI-SPEC §11.7: {} of the callbacks from the duplicated dispatch were rejected by Hull",
        hull.rejected_callbacks(&job.token).len(),
    );

    // How many callbacks arrive is *not* asserted: one (the runner de-duplicated on tree_id) and two
    // (it ran both) are equally conforming — §9 puts de-duplication in Hull. The invariant is that
    // they agree.
}

#[test]
fn spec_11_7_is_safe_under_duplicate_callback() {
    let hull = hull();
    let job = hull.job();
    hull.dispatch(&job).expect("dispatch failed to send");

    let original = hull
        .wait_for_callback(&job.token)
        .expect("CI-SPEC §11.7: no callback arrived, so it could not be duplicated");
    assert!(original.accepted, "the first callback must be accepted before duplicating it");

    // A conforming CI has no black-box trigger for "send that verdict again" — retry only happens
    // when Hull is unreachable (§10), which we cannot induce without breaking the very endpoint the
    // assertion reads from. So the suite replays the runner's own callback byte for byte: the
    // property under test is that the same verdict delivered twice re-affirms rather than conflicts
    // (§9), and a replay is exactly the message a retrying runner would send.
    let replayed = hull.replay(&original).expect("replay failed to send");

    assert_eq!(
        replayed.status, 200,
        "CI-SPEC §9 / §11.7: a duplicate callback for an already-recorded tree MUST simply re-affirm \
         the same verdict (200), not conflict; got {} — body {}",
        replayed.status,
        escape_for_message(&replayed.body_text()),
    );
    let recorded: serde_json::Value =
        serde_json::from_str(&replayed.body_text()).unwrap_or(serde_json::Value::Null);
    assert_eq!(
        recorded["recorded"].as_str(),
        original.status.as_deref(),
        "CI-SPEC §9: the replayed verdict was recorded as {:?} but the original was {:?}",
        recorded["recorded"],
        original.status,
    );

    let after = hull.callbacks(&job.token);
    assert!(
        after.iter().all(|c| c.status == original.status),
        "CI-SPEC §9: a duplicate callback must not change the verdict; statuses now {:?}",
        after.iter().map(|c| c.status.clone()).collect::<Vec<_>>(),
    );
}

// ── §7 — the summary is a display string, and it comes from untrusted output (§14.5) ────────────

#[test]
fn spec_7_summary_is_a_single_clean_line() {
    // Holds for *every* job, not just the hostile fixture: a summary is "one-line" by definition and
    // is built from job output, so control characters must never survive into it (§7, §14.5).
    let hull = hull();
    let job = hull.job_with_tree(&tree::benign_project());
    hull.dispatch(&job).expect("dispatch failed to send");

    let callback = hull
        .wait_for_callback(&job.token)
        .expect("CI-SPEC §7: no callback arrived, so the summary could not be inspected");

    if let Some(summary) = &callback.summary {
        let control = control_characters(summary);
        assert!(
            control.is_empty(),
            "CI-SPEC §7 / §14.5: `summary` is a one-line display string and MUST NOT carry control \
             characters; found {control:?} in {:?}",
            escape_for_message(summary),
        );
        assert!(
            summary.chars().count() <= config::summary_max_chars(),
            "CI-SPEC §14.5 / design D§6.6: `summary` MUST be length-capped ({} chars); got {}",
            config::summary_max_chars(),
            summary.chars().count(),
        );
    }
    // `summary` is optional (§7 field table), so its absence is conforming and not asserted against.
}
