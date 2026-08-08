//! The [`Planner`] seam: one step, autodetected from the tree.
//!
//! M1 has no pipeline file (design D§13), so the plan comes from marker files — `Cargo.toml`,
//! `package.json`, `go.mod`, a `Makefile` with a `test` target — using `hull-ci-node`'s [`detect`]
//! module so that this runner picks the *same* command Hull's built-in runner would (design D§4.4).
//! Pointing a repo at this endpoint should not change what its CI does. M2 replaces the body of
//! [`AutodetectPlanner::plan`] with the Starlark evaluator and this seam does not move.
//!
//! **Detection is done here, not on the node**, even though the node can also autodetect from an
//! empty `argv`. Two reasons, both about where a decision is legible:
//!
//! * "Nothing detectable to run" has to become `errored`/`no_tests` — which spec §9.1 reads as
//!   *self_attested*, a claim about coverage that routes a human into the review. Deciding it at plan
//!   time means the job ends with **no steps at all** and the aggregator's empty-plan path produces
//!   that verdict directly (design D§4.4). Deciding it on the node means leasing a sandbox, spawning
//!   it, and discovering there is nothing to run inside it.
//! * The plan is the record of what we intended to run. A step whose `argv` is empty is a plan that
//!   does not say what it planned.
//!
//! The node's own detection stays as the backstop it was written to be, and the two agree because
//! they are the same function.
//!
//! # This reads the tree; it never runs it
//!
//! Spec §14.1 forbids executing job code on the control-plane host, and this is the one place on that
//! host that opens a file the tree contains. `detect_test_command` reads marker *names* and performs
//! one bounded lexical scan of a makefile — no `make -n`, no `npm run`, no include resolution, no
//! execution of anything (see `hull-ci-node`'s `detect` module docs). The bytes are untrusted data
//! and stay data.

use hull_ci_control::callback::BoxFuture;
use hull_ci_control::model::StepSpec;
use hull_ci_control::seams::{PlanError, Planner, VerifiedTree};
use hull_ci_node::detect::{detect_test_command, Detection};

/// The name every M1 step carries. Fixed, because it is not derived from anything a dispatch or a
/// tree can influence, and it is echoed into the verdict summary (spec §14.5).
pub const STEP_NAME: &str = "test";

/// Plans one step from the tree's marker files.
pub struct AutodetectPlanner {
    image: String,
}

impl AutodetectPlanner {
    pub fn new(image: impl Into<String>) -> Self {
        AutodetectPlanner { image: image.into() }
    }
}

impl Planner for AutodetectPlanner {
    fn plan<'a>(&'a self, tree: &'a VerifiedTree) -> BoxFuture<'a, Result<Vec<StepSpec>, PlanError>> {
        Box::pin(async move {
            // Marker detection is a handful of `stat`s and at most one bounded read, but it is
            // blocking filesystem work on a shared runtime, and the tree may be on slow storage.
            let root = tree.path.clone();
            let detection = tokio::task::spawn_blocking(move || detect_test_command(&root))
                .await
                // A panicked or cancelled blocking task is our failure, not a bad pipeline. The seam
                // has no infrastructure variant, and the control plane folds every `PlanError` to
                // `errored`/`infra` regardless, so the distinction lives in the message.
                .map_err(|e| PlanError::Invalid(format!("test-command detection did not complete: {e}")))?;

            Ok(match detection {
                Detection::Found(cmd) => {
                    tracing::info!(
                        tree_id = %tree.tree_id,
                        marker = cmd.marker,
                        argv = ?cmd.argv,
                        "planned one autodetected step"
                    );
                    vec![StepSpec::new(STEP_NAME, cmd.argv, self.image.clone())]
                }
                Detection::None => {
                    // Empty is not an error at this seam: the aggregator owns the wording and turns
                    // it into `errored`/`no_tests` (design D§4.4).
                    tracing::info!(tree_id = %tree.tree_id, "no test command detected in the tree");
                    Vec::new()
                }
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tree(path: PathBuf) -> VerifiedTree {
        VerifiedTree { tree_id: "t".into(), path, cached: false, keep_alive: None }
    }

    #[tokio::test]
    async fn a_marker_file_becomes_one_step_naming_the_command() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\nname='x'\n").unwrap();

        let planner = AutodetectPlanner::new("rust:1.83");
        let steps = planner.plan(&tree(dir.path().to_path_buf())).await.unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].name, STEP_NAME);
        assert_eq!(steps[0].argv, ["cargo", "test"]);
        assert_eq!(steps[0].image, "rust:1.83");
    }

    #[tokio::test]
    async fn nothing_detectable_is_an_empty_plan_not_an_error() {
        // The distinction spec §9.1 rests on: an empty plan folds to `errored`/`no_tests`
        // (*self_attested*), whereas an `Err` here would fold to `errored`/`infra` and tell Hull to
        // retry something that will never succeed.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("README.md"), "no tests here").unwrap();

        let steps = AutodetectPlanner::new("img").plan(&tree(dir.path().to_path_buf())).await.unwrap();
        assert!(steps.is_empty());
    }

    #[tokio::test]
    async fn a_tree_that_is_not_there_is_an_empty_plan_too() {
        // A missing directory reads as "no markers", which is the same honest answer: there is
        // nothing to run. It must not panic, and it must not be mistaken for a detected command.
        let steps = AutodetectPlanner::new("img")
            .plan(&tree(PathBuf::from("/nonexistent/tree")))
            .await
            .unwrap();
        assert!(steps.is_empty());
    }
}
