//! The environment that points a job's package managers at the proxy.
//!
//! §14.2 requires the job environment to be an allowlist, and this is a contribution *to* that
//! allowlist rather than an exception from it — every variable here is a URL, and the only credential
//! among them is the job's own grant, embedded in the URL because that is the one place `npm`, `pip`
//! and `cargo` all agree to carry one ([`crate::grant`] explains the trade).
//!
//! # Why these variables and not a `*_proxy` pair
//!
//! `http_proxy`/`https_proxy` would make `https` requests go out as `CONNECT`, which
//! [`crate::server`] refuses on purpose. Pointing each tool at a *registry URL* instead keeps every
//! request in the terminating shape, so the allowlist sees paths and the proxy can authenticate
//! outbound. It also fails **closed** in a useful way: a tool that is not configured here does not
//! silently get open egress, it gets nothing at all, because the sandbox has no route anywhere else
//! (D§7.3).
//!
//! # What this does not do
//!
//! It does not configure every ecosystem. `go`, `maven`, `nuget`, `apt` and friends each need their
//! own variable or config file, and several (notably `cargo`'s source replacement and `maven`'s
//! `settings.xml`) need a *file* rather than an environment variable, which is a workspace-mutation
//! decision this module has no standing to make. Listing what is covered, rather than implying
//! everything is, is the honest shape: an unconfigured tool fails to resolve, which is a loud and
//! correct outcome under egress-deny.

/// A job's package-proxy endpoint, as the *sandbox* sees it.
#[derive(Debug, Clone)]
pub struct JobProxyEndpoint {
    /// `http://<host>:<port>` — the address reachable from inside the sandbox network, which is not
    /// the address the proxy binds on the node.
    pub base_url: String,
    /// The job's grant token. Held as a plain `String` rather than [`crate::grant::GrantToken`]
    /// because it is on its way into an environment variable the job will read anyway; there is
    /// nothing left to protect it from at this point.
    pub grant: String,
}

impl JobProxyEndpoint {
    pub fn new(base_url: impl Into<String>, grant: impl Into<String>) -> Self {
        JobProxyEndpoint { base_url: into_base(base_url.into()), grant: grant.into() }
    }

    /// The job-facing URL for one upstream label, with a trailing slash.
    ///
    /// The trailing slash matters for the same reason it does in
    /// [`crate::allowlist`]: `npm` and `pip` both join paths onto a configured registry URL, and one
    /// that does not end in `/` loses its last segment.
    pub fn upstream_url(&self, label: &str) -> String {
        format!("{}/j/{}/u/{}/", self.base_url, self.grant, label)
    }

    /// Environment variables for the ecosystems this module covers.
    ///
    /// Each is emitted only when its upstream label is present in `labels`, so a deployment that
    /// allowlists only npm does not hand a job a `PIP_INDEX_URL` pointing at an upstream that will
    /// 403.
    pub fn env_vars(&self, labels: &[String]) -> Vec<(String, String)> {
        let mut env = Vec::new();
        let has = |l: &str| labels.iter().any(|x| x == l);

        if has(NPM_LABEL) {
            // Lowercase `npm_config_*` is npm's own environment form and beats any `.npmrc` in the
            // tree — which matters, because the tree is written by the change's author and a
            // `.npmrc` naming a different registry would otherwise win.
            env.push(("npm_config_registry".into(), self.upstream_url(NPM_LABEL)));
            env.push(("NPM_CONFIG_REGISTRY".into(), self.upstream_url(NPM_LABEL)));
        }
        if has(PYPI_LABEL) {
            env.push(("PIP_INDEX_URL".into(), format!("{}simple/", self.upstream_url(PYPI_LABEL))));
            // Without this, pip refuses a plain-http index. The hop is inside the sandbox network
            // (see `crate::server`), and the TLS that matters is proxy→upstream.
            env.push(("PIP_TRUSTED_HOST".into(), self.host().unwrap_or_default()));
        }
        if has(CRATES_LABEL) {
            // Cargo's registry protocol reads an index URL from the environment; source replacement
            // for crates.io proper needs a config file, which this module does not write.
            env.push((
                "CARGO_REGISTRIES_HULL_INDEX".into(),
                format!("sparse+{}", self.upstream_url(CRATES_LABEL)),
            ));
        }
        env
    }

    /// Host (and port) of the endpoint, for the tools that want it separately from the URL.
    pub fn host(&self) -> Option<String> {
        let rest = self.base_url.strip_prefix("http://").or_else(|| self.base_url.strip_prefix("https://"))?;
        Some(rest.split('/').next()?.to_string())
    }
}

/// Labels this module knows how to configure. An operator may allowlist an upstream under any label;
/// these are the ones that also get environment wiring.
pub const NPM_LABEL: &str = "npm";
pub const PYPI_LABEL: &str = "pypi";
pub const CRATES_LABEL: &str = "crates";

fn into_base(mut s: String) -> String {
    while s.ends_with('/') {
        s.pop();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> JobProxyEndpoint {
        JobProxyEndpoint::new("http://172.20.0.1:3128/", "hpkg_aa.bb")
    }

    #[test]
    fn an_upstream_url_carries_the_grant_and_ends_in_a_slash() {
        assert_eq!(endpoint().upstream_url("npm"), "http://172.20.0.1:3128/j/hpkg_aa.bb/u/npm/");
    }

    #[test]
    fn only_allowlisted_ecosystems_are_configured() {
        // Handing a job a `PIP_INDEX_URL` for an upstream that does not exist turns a clear
        // "nothing is allowlisted" into a confusing 403 mid-resolution.
        let env = endpoint().env_vars(&["npm".to_string()]);
        let names: Vec<&str> = env.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"npm_config_registry"));
        assert!(!names.iter().any(|n| n.starts_with("PIP_")));
        assert!(!names.iter().any(|n| n.starts_with("CARGO_")));
    }

    #[test]
    fn every_ecosystem_points_at_the_proxy_and_nowhere_else() {
        let labels = vec!["npm".to_string(), "pypi".to_string(), "crates".to_string()];
        let env = endpoint().env_vars(&labels);
        assert!(env.len() >= 5);
        for (name, value) in &env {
            if name == "PIP_TRUSTED_HOST" {
                assert_eq!(value, "172.20.0.1:3128");
                continue;
            }
            assert!(value.contains("172.20.0.1:3128"), "{name} points off-proxy: {value}");
            assert!(value.contains("/j/hpkg_aa.bb/u/"), "{name} lost its grant: {value}");
        }
    }

    #[test]
    fn none_of_these_names_are_credential_shaped() {
        // They travel through §14.2's `reject_forbidden` check on the way into a sandbox, and a name
        // containing `TOKEN` would be refused there. The grant rides in the URL value instead.
        let labels = vec!["npm".to_string(), "pypi".to_string(), "crates".to_string()];
        for (name, _) in endpoint().env_vars(&labels) {
            let upper = name.to_ascii_uppercase();
            for fragment in ["SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "API_KEY", "HULL_CI"] {
                assert!(!upper.contains(fragment), "{name} would be refused by §14.2's backstop");
            }
        }
    }

    #[test]
    fn a_base_url_is_normalized_so_urls_never_double_up_their_slashes() {
        for raw in ["http://p:3128", "http://p:3128/", "http://p:3128///"] {
            assert_eq!(
                JobProxyEndpoint::new(raw, "t").upstream_url("npm"),
                "http://p:3128/j/t/u/npm/"
            );
        }
    }
}
