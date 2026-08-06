//! The [`Planner`] seam, M2: `.hull/ci.star` when the tree has one, autodetection when it does not.
//!
//! [`PipelinePlanner`] wraps [`AutodetectPlanner`](crate::plan::AutodetectPlanner) rather than
//! replacing it. A repo that has never heard of hull-ci keeps working exactly as it did in M1 —
//! pointing it at this endpoint should not change what its CI does (design D§4.4) — and a repo that
//! adds a pipeline gets a DAG. The fallback is the common case for a long time yet.
//!
//! # Reading the pipeline is the dangerous part, not running it
//!
//! `.hull/ci.star` is attacker-controlled input evaluated on the **control plane**, which spec §14.1
//! otherwise forbids running anything from a tree on. The safety argument is `hull-ci-plan`'s: the
//! dialect is hermetic, and — the part D§4.4 originally missed — the *parser* is bounded before it
//! ever sees the source, because a nested-bracket bomb overflows the parse stack and aborts the
//! process regardless of how well-behaved the language is afterwards.
//!
//! This module's own contribution to that is the bounded read below: we refuse to hand the evaluator
//! a file we have not size-checked, so a multi-gigabyte `ci.star` is a rejected pipeline rather than
//! a memory spike on the host.

use std::path::Path;

use hull_ci_control::callback::BoxFuture;
use hull_ci_control::model::StepSpec;
use hull_ci_control::seams::{PlanError, Planner, VerifiedTree};
use hull_ci_plan::{Limits, Pipeline, PlanStep, StepKind, PIPELINE_PATH};

use crate::plan::AutodetectPlanner;

/// Built-in actions the node binary implements, for `uses = "..."`.
///
/// **Deliberately empty.** No action is implemented yet, so a pipeline naming one is rejected at plan
/// time with "unknown action" instead of being accepted and silently doing nothing — which would be a
/// step the author believes ran. When `hull/secret-scan` lands in the node, it is added here and the
/// evaluator starts accepting it; the registry is a parameter precisely so this file, which knows
/// which build of the node is deployed, is the one that decides.
pub const ACTIONS: &[&str] = &[];

/// Plans from `.hull/ci.star`, falling back to marker-file autodetection.
pub struct PipelinePlanner {
    fallback: AutodetectPlanner,
    default_image: String,
    limits: Limits,
    /// Whether this deployment has a secret broker wired ([`crate::secrets`]). Read for one purpose
    /// only — deciding whether a `secrets = [...]` declaration deserves the "not honoured" warning
    /// below. It is **not** an authority input: the planner never decides whether a secret is
    /// delivered, and a `true` here on a job whose author is an outsider still delivers nothing.
    secrets_delivered: bool,
}

impl PipelinePlanner {
    pub fn new(default_image: impl Into<String>) -> Self {
        let default_image = default_image.into();
        PipelinePlanner {
            fallback: AutodetectPlanner::new(default_image.clone()),
            default_image,
            limits: Limits::default(),
            secrets_delivered: false,
        }
    }

    /// Tell the planner a broker exists, so it stops warning that `secrets` go undelivered.
    pub fn with_secret_delivery(mut self, delivered: bool) -> Self {
        self.secrets_delivered = delivered;
        self
    }
}

/// Read the pipeline file if the tree has one, refusing anything over the evaluator's byte budget.
///
/// Returns `Ok(None)` when the file is simply absent — that is the autodetect path, not an error.
/// An unreadable-but-present file *is* an error: silently falling back would run a different plan
/// than the author wrote, which is worse than refusing.
fn read_pipeline(root: &Path, max_bytes: usize) -> Result<Option<String>, PlanError> {
    let path = root.join(PIPELINE_PATH);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(PlanError::Invalid(format!("{PIPELINE_PATH} could not be read: {e}"))),
    };
    // A symlink here would be a way to make us read something outside the tree. The extractor already
    // refuses links that escape the root, so this is the second lock on the same door — cheap, and
    // the cost of being wrong is reading an arbitrary host file into an error message.
    if !meta.is_file() {
        return Err(PlanError::Invalid(format!("{PIPELINE_PATH} is not a regular file")));
    }
    if meta.len() as usize > max_bytes {
        return Err(PlanError::Invalid(format!(
            "{PIPELINE_PATH} is {} bytes, over the {max_bytes}-byte limit",
            meta.len()
        )));
    }
    match std::fs::read_to_string(&path) {
        Ok(s) => Ok(Some(s)),
        // Non-UTF-8 is a malformed pipeline, not an infrastructure fault.
        Err(e) => Err(PlanError::Invalid(format!("{PIPELINE_PATH} could not be read: {e}"))),
    }
}

/// Turn one evaluated [`PlanStep`] into the control plane's [`StepSpec`].
///
/// The interesting line is `run` → `argv`. `hull-ci-node` deliberately has no string-taking spawn, so
/// nothing can build a host command line; a `run` string therefore becomes three argv elements with
/// the script as **one opaque element**, interpreted by a shell *inside the sandbox*. That is the
/// normal CI contract (`run:` means "a shell runs this") and it is safe for the same reason the whole
/// design is: the sandbox is the boundary, not the argv.
///
/// It is worth being precise about where that stops being true — under the development
/// local-process backend there is no sandbox, so the shell is the host's. That backend already
/// reports every §14 control unmet and refuses untrusted authors, which is exactly the situation this
/// relies on.
fn to_step_spec(step: &PlanStep, pipeline: &Pipeline, default_image: &str) -> StepSpec {
    let argv = match &step.kind {
        StepKind::Run(script) => {
            vec!["/bin/sh".to_string(), "-c".to_string(), script.clone()]
        }
        // Unreachable while ACTIONS is empty — the evaluator rejects an unknown `uses` — but a plan
        // that reached here with an action would otherwise become an empty argv, and an empty argv is
        // a step that claims to have run something it did not name.
        StepKind::Action(id) => vec!["/bin/false".to_string(), id.clone()],
    };

    let mut spec = StepSpec::new(
        step.name.clone(),
        argv,
        step.effective_image(pipeline).unwrap_or(default_image).to_string(),
    )
    .needs(step.needs.clone())
    // Names only (D§7.4). Copying them here is the whole of the plan's involvement with secrets: the
    // evaluator ran on attacker-controlled input, so nothing it produced may be treated as authority.
    // Whether any of these is ever *delivered* is decided at placement, by the broker, from the job's
    // author class — a fact about the actor that no edit to this file can raise.
    .secrets(step.secrets.clone())
    // The globs that decide this step's memo key (design D§6.1). Carried verbatim: they are author
    // text, resolved against the *verified* tree by the digester, and a step that declares none is
    // refused a key rather than given an empty one — an empty input set folds the same digest on
    // every tree that has ever existed.
    //
    // Worth knowing when writing a pipeline: a directory-prefix glob (`crates/**`) resolves by
    // descent to a subtree address keel already computed, while a pattern (`**/*.rs`) walks the tree's
    // node structure. Measured on 100k entries that is 464ns against 23.9ms — the advice to prefer
    // prefixes is five orders of magnitude, not a rounding note.
    .inputs(step.inputs.clone());
    spec.timeout = step.timeout;
    spec.continue_on_error = step.continue_on_error;
    spec
}

/// Log, once per plan, the pipeline features this milestone parses but does not yet honour.
///
/// Accepting a field and ignoring it is the failure mode worth being loud about: the author wrote
/// `shard = "auto"` or `secrets = [...]` and believes it took effect. Rejecting the pipeline outright
/// would be worse — it would make a repo's pipeline unusable until every feature lands — so the
/// compromise is that it runs, and the operator can see exactly what was dropped.
fn warn_unhonoured(pipeline: &Pipeline, tree_id: &str, secrets_delivered: bool) {
    let sharded: Vec<&str> =
        pipeline.steps.iter().filter(|s| s.shard.is_some()).map(|s| s.name.as_str()).collect();
    if !sharded.is_empty() {
        tracing::warn!(%tree_id, steps = ?sharded, "`shard` is not implemented yet (design D§6.5, M5): these steps run unsharded");
    }
    let with_secrets: Vec<&str> =
        pipeline.steps.iter().filter(|s| !s.secrets.is_empty()).map(|s| s.name.as_str()).collect();
    if !with_secrets.is_empty() && !secrets_delivered {
        // The security-relevant one. With no broker configured (`HULL_CI_SECRETS=off`, the default)
        // the variables simply do not appear — a step expecting them fails on its own terms rather
        // than running without them unnoticed. There is deliberately no warning for the *delivered*
        // case: a member's job receiving its declared secret is the feature working, and an outsider
        // receiving nothing is refused at the broker, which logs its own refusal with the actor
        // attached (D§7.4).
        tracing::warn!(
            %tree_id,
            steps = ?with_secrets,
            "no secret broker is configured (HULL_CI_SECRETS=off): these steps run without their declared secrets"
        );
    }
    let cached: Vec<&str> =
        pipeline.steps.iter().filter(|s| !s.cache.is_empty()).map(|s| s.name.as_str()).collect();
    if !cached.is_empty() {
        tracing::warn!(%tree_id, steps = ?cached, "`cache` mounts are not implemented yet (design D§6.3, M4): these steps run cold");
    }
    if pipeline.trust.is_some() {
        // `trust()` only ever *requests* an isolation tier and is clamped upward by policy (design
        // D§1). Saying so out loud matters because the naive reading is that it grants something.
        tracing::info!(%tree_id, "pipeline requested an isolation tier; policy clamps it and never lowers it");
    }
}

impl Planner for PipelinePlanner {
    fn plan<'a>(&'a self, tree: &'a VerifiedTree) -> BoxFuture<'a, Result<Vec<StepSpec>, PlanError>> {
        Box::pin(async move {
            let root = tree.path.clone();
            let max = self.limits.max_source_bytes;
            let source = tokio::task::spawn_blocking(move || read_pipeline(&root, max))
                .await
                .map_err(|e| PlanError::Invalid(format!("reading {PIPELINE_PATH} did not complete: {e}")))??;

            let Some(source) = source else {
                tracing::debug!(tree_id = %tree.tree_id, "no {PIPELINE_PATH}; falling back to autodetection");
                return self.fallback.plan(tree).await;
            };

            // Evaluation is CPU-bound, bounded, and runs the evaluator's own guarded thread inside —
            // but it is still blocking, so it does not belong on an async worker.
            let limits = self.limits.clone();
            let evaluated = tokio::task::spawn_blocking(move || {
                hull_ci_plan::evaluate_with(&source, &limits, ACTIONS)
            })
            .await
            .map_err(|e| PlanError::Invalid(format!("evaluating {PIPELINE_PATH} did not complete: {e}")))?;

            let pipeline = match evaluated {
                Ok(p) => p,
                // A malformed pipeline is the author's error and is **permanent** — no amount of
                // re-checking makes a syntax error parse. The seam has only `Invalid`, which the
                // control plane folds to `errored`/`infra`, and `infra` reads as "transient, try
                // again". The message carries the truth even though the reason code cannot; see the
                // note in the design's G4 about `errored` being under-discriminated.
                Err(e) => {
                    tracing::warn!(tree_id = %tree.tree_id, error = %e, "pipeline rejected");
                    return Err(PlanError::Invalid(e.to_string()));
                }
            };

            warn_unhonoured(&pipeline, &tree.tree_id, self.secrets_delivered);
            tracing::info!(
                tree_id = %tree.tree_id,
                steps = pipeline.steps.len(),
                "planned from {PIPELINE_PATH}"
            );

            // An empty pipeline is an empty plan, which the aggregator turns into
            // `errored`/`no_tests` — the same path a tree with no markers takes, and the state spec
            // §9.1 reads as *self_attested*. A pipeline that declares no steps has said, precisely,
            // that there is nothing to run.
            Ok(pipeline
                .steps
                .iter()
                .map(|s| to_step_spec(s, &pipeline, &self.default_image))
                .collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tree(path: PathBuf) -> VerifiedTree {
        VerifiedTree { tree_id: "t".into(), path, cached: false }
    }

    fn write(dir: &Path, rel: &str, body: &str) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    #[tokio::test]
    async fn a_pipeline_becomes_its_dag() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            PIPELINE_PATH,
            r#"
image("rust:1.83")
b = step("build", run = "cargo build")
step("test", run = "cargo test", needs = [b], timeout = "5m")
"#,
        );

        let steps = PipelinePlanner::new("default:img").plan(&tree(dir.path().into())).await.unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].name, "build");
        assert_eq!(steps[0].image, "rust:1.83", "the pipeline's image beats the server default");
        assert!(steps[0].needs.is_empty());
        assert_eq!(steps[1].needs, ["build"], "the edge survives into the control plane's model");
        assert_eq!(steps[1].timeout, Some(std::time::Duration::from_secs(300)));
        // The `run` script is one opaque argv element; nothing splits or interprets it here.
        assert_eq!(steps[1].argv, ["/bin/sh", "-c", "cargo test"]);
    }

    #[tokio::test]
    async fn a_computed_matrix_is_the_whole_point_of_the_format() {
        // The ergonomics that justify Starlark over YAML (design D§4.4), end to end through the seam.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            PIPELINE_PATH,
            r#"
for target in ["linux", "darwin", "windows"]:
    step("build-" + target, run = "cargo build --target " + target)
"#,
        );

        let steps = PipelinePlanner::new("img").plan(&tree(dir.path().into())).await.unwrap();
        let names: Vec<&str> = steps.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["build-linux", "build-darwin", "build-windows"]);
    }

    #[tokio::test]
    async fn no_pipeline_falls_back_to_autodetection() {
        // The compatibility promise: a repo that has never heard of hull-ci behaves as it did in M1.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "Cargo.toml", "[package]\nname='x'\n");

        let steps = PipelinePlanner::new("img").plan(&tree(dir.path().into())).await.unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].argv, ["cargo", "test"], "the autodetected command, not a shell wrapper");
    }

    #[tokio::test]
    async fn a_malformed_pipeline_is_refused_rather_than_quietly_autodetected() {
        // Falling back here would run a plan the author did not write, and would do it silently.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "Cargo.toml", "[package]\nname='x'\n");
        write(dir.path(), PIPELINE_PATH, "step(\n");

        let err = PipelinePlanner::new("img").plan(&tree(dir.path().into())).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(PIPELINE_PATH), "the error should name the file: {msg}");
        assert!(!msg.contains("/private/"), "and must not leak a host path: {msg}");
        assert!(!msg.contains(".rs:"), "nor a source location: {msg}");
    }

    #[tokio::test]
    async fn an_unknown_action_is_rejected_not_silently_skipped() {
        // ACTIONS is empty, so `uses` names nothing this node can run. A step that is accepted and
        // does nothing is worse than a refused pipeline: the author believes it ran.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), PIPELINE_PATH, r#"action("scan", uses = "hull/secret-scan")"#);

        let err = PipelinePlanner::new("img").plan(&tree(dir.path().into())).await.unwrap_err();
        assert!(err.to_string().contains("action"), "{err}");
    }

    #[tokio::test]
    async fn an_oversized_pipeline_is_refused_before_the_parser_sees_it() {
        let dir = tempfile::tempdir().unwrap();
        let huge = "# ".to_string() + &"x".repeat(Limits::default().max_source_bytes + 1);
        write(dir.path(), PIPELINE_PATH, &huge);

        let err = PipelinePlanner::new("img").plan(&tree(dir.path().into())).await.unwrap_err();
        assert!(err.to_string().contains("limit"), "{err}");
    }

    #[tokio::test]
    async fn a_pipeline_with_no_steps_is_an_empty_plan_not_an_error() {
        // Folds to `errored`/`no_tests` (*self_attested*, spec §9.1) — a pipeline that declares no
        // steps has said exactly that there is nothing to run.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), PIPELINE_PATH, "image(\"img\")\n");

        let steps = PipelinePlanner::new("img").plan(&tree(dir.path().into())).await.unwrap();
        assert!(steps.is_empty());
    }
}
