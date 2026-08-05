//! What an evaluated `.hull/ci.star` *is*: a validated, acyclic step DAG (design D§4.4).
//!
//! These types are deliberately defined here rather than imported from `hull-ci-control`. The
//! dependency points the other way — the server composes the evaluator and the scheduler — so the
//! evaluator has no idea a scheduler exists, and a change to the job model cannot reach into the
//! surface that parses attacker-controlled input.
//!
//! **Nothing in this module is executable.** [`StepKind::Run`] holds the pipeline's `run` string
//! verbatim: the evaluator never splits it, never interpolates into it, and never runs it. Word
//! splitting is a sandbox-side decision (design D§4.4 — "opaque data executed inside the sandbox
//! only"), and doing it here would mean the control plane had parsed a shell command line, which is
//! one refactor away from having run one.

use std::time::Duration;

use hull_ci_proto::IsolationTier;
use serde::{Deserialize, Serialize};

/// The isolation tier a pipeline *requests* (design D§4.4, `trust`).
///
/// A request, never a grant. Two things this cannot do, both load-bearing:
///
/// * It cannot lower the tier. Policy clamps upward only ([`Trust::effective_tier`]), and the
///   multi-tenant floor is [`IsolationTier::MicroVm`], so on the hosted fleet `trust("trusted")` is
///   inert — exactly as intended for a value that arrives inside the untrusted tree.
/// * It cannot touch [`AuthorClass`](hull_ci_proto::AuthorClass). Cache-write and secret access hang
///   off the *actor* (design D§1), so no pipeline can grant itself either by editing a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trust {
    /// Container — the weaker box. Only reachable on a single-tenant operator's floor.
    Trusted,
    /// microVM. The default and the fleet floor.
    Untrusted,
}

impl Trust {
    /// The tier this request maps to on its own, before policy.
    pub fn requested_tier(self) -> IsolationTier {
        match self {
            Trust::Trusted => IsolationTier::Container,
            Trust::Untrusted => IsolationTier::MicroVm,
        }
    }

    /// `max(policy_floor, request)` (design D§4.4).
    ///
    /// "Max" over a two-element lattice where [`IsolationTier::MicroVm`] is the strong end: if
    /// either the floor or the request says microVM, the answer is microVM. Written as a total
    /// function over the enum rather than an ordering, so adding a tier later is a compile error
    /// here instead of a silent downgrade.
    pub fn effective_tier(self, policy_floor: IsolationTier) -> IsolationTier {
        match (policy_floor, self.requested_tier()) {
            (IsolationTier::MicroVm, _) | (_, IsolationTier::MicroVm) => IsolationTier::MicroVm,
            (IsolationTier::Container, IsolationTier::Container) => IsolationTier::Container,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Trust::Trusted => "trusted",
            Trust::Untrusted => "untrusted",
        }
    }
}

/// `shard = "auto"` or `shard = <int>` (design D§4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Shard {
    /// Split by historical timing (design D§6.5). The planner decides the count.
    Auto,
    /// An explicit fan-out, 1..=256.
    Fixed(u32),
}

/// What a step actually does. The two cases are not interchangeable and must not collapse into one
/// "command" field: an [`Action`](StepKind::Action) is implemented in the node binary and involves
/// **no user shell at all** (design D§4.4), which is the entire reason `hull/secret-scan` can be
/// trusted to observe a tree that a `run` string must not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    /// The pipeline's `run` string, **verbatim and opaque**. Executed inside the sandbox only.
    Run(String),
    /// `uses` — the id of a built-in action, checked against the registry at plan time.
    Action(String),
}

/// One node of the emitted DAG.
///
/// The shape a YAML file would have produced (design D§4.4), so everything downstream — §6
/// memoization, §8 independence trees — is unchanged by the authoring surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanStep {
    /// Unique within the pipeline, `[A-Za-z0-9_/-]`, 1..=64 chars.
    pub name: String,
    pub kind: StepKind,
    /// Globs deciding the step key (design D§6.1). Never resolved here — the evaluator touches no
    /// filesystem, so a glob is a string until the node expands it against the extracted tree.
    pub inputs: Vec<String>,
    /// Cache mount paths, resolved against [`Pipeline::cache_scope`].
    pub cache: Vec<String>,
    /// Tenant secret *names*. Naming one is a request the secret broker adjudicates against the
    /// job's author class (design D§7.4); the broker never consults this list for authority, only
    /// for which secrets to consider.
    pub secrets: Vec<String>,
    /// Steps that must finish first. Guaranteed to name earlier entries of [`Pipeline::steps`], so
    /// the graph is acyclic by construction — see [`crate::eval`].
    pub needs: Vec<String>,
    pub shard: Option<Shard>,
    /// Parsed from the pipeline's `"20m"`-style string at plan time, so a malformed duration is a
    /// pipeline error the author sees rather than a surprise default at dispatch time.
    pub timeout: Option<Duration>,
    /// Per-step override of [`Pipeline::image`].
    pub image: Option<String>,
    /// A failure here does not decide the job red (design D§6.6).
    pub continue_on_error: bool,
}

impl PlanStep {
    /// The image this step runs in: its own override, else the pipeline default.
    pub fn effective_image<'a>(&'a self, pipeline: &'a Pipeline) -> Option<&'a str> {
        self.image.as_deref().or(pipeline.image.as_deref())
    }
}

/// A whole evaluated pipeline.
///
/// `image`/`trust`/`cache_scope` are `Option` because a pipeline need not set them: the *server*
/// owns the defaults (an image policy, the tier floor, this repo as the scope), and an evaluator
/// that invented them would be asserting policy from inside attacker-controlled input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pipeline {
    /// Default OCI ref, resolved to a digest at plan time — by the server, not here.
    pub image: Option<String>,
    pub trust: Option<Trust>,
    /// A scope *name*, always resolved within this tenant. Naming a scope this repo may not write
    /// yields read-only access, not an error (design D§6.3), so there is nothing to validate here
    /// beyond the charset — authority lives in the tenant's grants.
    pub cache_scope: Option<String>,
    /// Topologically ordered by construction: every `needs` target appears earlier.
    pub steps: Vec<PlanStep>,
}

impl Pipeline {
    pub fn step(&self, name: &str) -> Option<&PlanStep> {
        self.steps.iter().find(|s| s.name == name)
    }

    /// Longest path through the DAG, in nodes. `0` for an empty pipeline.
    ///
    /// A single forward pass suffices *because* the steps are topologically ordered — the same
    /// property that makes cycles unrepresentable also makes depth cheap to compute.
    pub fn depth(&self) -> usize {
        let mut depths: Vec<(&str, usize)> = Vec::with_capacity(self.steps.len());
        let mut max = 0;
        for step in &self.steps {
            let d = 1 + step
                .needs
                .iter()
                .filter_map(|n| depths.iter().find(|(name, _)| *name == n.as_str()))
                .map(|(_, d)| *d)
                .max()
                .unwrap_or(0);
            max = max.max(d);
            depths.push((&step.name, d));
        }
        max
    }
}
