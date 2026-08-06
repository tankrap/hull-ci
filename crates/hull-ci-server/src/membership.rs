//! Who counts as a member — the [`AuthorClass`] half of design D§1.
//!
//! Author class is a fact about the **actor**, never something a pipeline or a dispatch can assert,
//! and it gates the two things that matter: shared-cache writes and tenant secrets. M1 has neither
//! yet, so today it gates exactly one thing — whether the job is allowed to run at all, because no
//! M1 backend admits untrusted work (`BackendCapabilities::admits_untrusted()`, design D§7.2/D§13).
//!
//! The real derivation is "a principal of the tenant with write access to the repo", which needs a
//! membership lookup against Hull. M1 does not have one, and inventing a heuristic from the
//! dispatch's `author` string would be worse than having none: `author` is display-only text (spec
//! §5) that we would be turning into an authorization decision. So the M1 answer is an operator
//! statement instead — *this deployment serves these tenants, and everyone who can reach this
//! endpoint with a valid secret is trusted within them* — which is exactly design D§13's precondition
//! for M1 ("single-tenant, trusted-input only") written down as configuration rather than assumed.
//!
//! Default: nobody. An unconfigured deployment classifies every author as an outsider, every M1
//! backend refuses outsider work, and jobs come back `errored` with the reason in the summary. That
//! is the correct direction to be wrong in — the other one runs a fork PR on a shared kernel.

use std::collections::BTreeSet;

use hull_ci_control::seams::Membership;
use hull_ci_proto::AuthorClass;

/// The tenants whose authors this deployment treats as members.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedTenants {
    /// `*` — every tenant. A single-tenant operator's honest configuration, and a footgun on any
    /// other kind of deployment, which is why it has to be typed out.
    all: bool,
    names: BTreeSet<String>,
}

impl TrustedTenants {
    /// Trust nobody. The default, and the reason a misconfigured deployment is inert rather than
    /// dangerous.
    pub fn none() -> Self {
        TrustedTenants::default()
    }

    /// Parse a comma-separated list. `*` anywhere in the list means every tenant.
    pub fn parse(raw: &str) -> Self {
        let mut out = TrustedTenants::default();
        for name in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if name == "*" {
                out.all = true;
            } else {
                out.names.insert(name.to_string());
            }
        }
        out
    }

    pub fn is_trusted(&self, tenant: &str) -> bool {
        self.all || self.names.contains(tenant)
    }

    pub fn trusts_everyone(&self) -> bool {
        self.all
    }

    /// For the startup banner: what an operator actually configured.
    pub fn describe(&self) -> String {
        if self.all {
            "* (every tenant)".into()
        } else if self.names.is_empty() {
            "none".into()
        } else {
            self.names.iter().cloned().collect::<Vec<_>>().join(", ")
        }
    }
}

impl Membership for TrustedTenants {
    /// `repo` is `tenant/repo`; the tenant half is the boundary everything else is scoped by (D§1).
    ///
    /// `author` is deliberately unused. It is display-only text from the dispatch, and reading an
    /// authorization decision out of it would let whoever authored the change choose their own class.
    fn classify(&self, repo: &str, _author: &str) -> AuthorClass {
        let tenant = repo.split('/').next().unwrap_or(repo);
        if self.is_trusted(tenant) {
            AuthorClass::Member
        } else {
            AuthorClass::Outsider
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nobody_is_a_member_by_default() {
        let t = TrustedTenants::none();
        assert_eq!(t.classify("acme/widget", "justin"), AuthorClass::Outsider);
        assert_eq!(t.describe(), "none");
    }

    #[test]
    fn only_the_named_tenants_are_members() {
        let t = TrustedTenants::parse("acme, globex");
        assert_eq!(t.classify("acme/widget", "justin"), AuthorClass::Member);
        assert_eq!(t.classify("globex/thing", "anyone"), AuthorClass::Member);
        assert_eq!(t.classify("evilcorp/thing", "justin"), AuthorClass::Outsider);
        // An unqualified repo is its own tenant name, and is not one of ours.
        assert_eq!(t.classify("acme", "justin"), AuthorClass::Member);
        assert_eq!(t.classify("widget", "justin"), AuthorClass::Outsider);
    }

    #[test]
    fn the_star_is_a_deliberate_single_tenant_statement() {
        let t = TrustedTenants::parse("*");
        assert!(t.trusts_everyone());
        assert_eq!(t.classify("anyone/anything", "someone"), AuthorClass::Member);
    }

    #[test]
    fn a_repo_whose_tenant_half_is_empty_is_never_a_member() {
        // `Dispatch::tenant()` splits on `/` and takes the first component, so a `repo` of
        // `/widget` — or `//x`, or a bare `/` — yields the empty tenant. Nothing upstream rejects
        // that: `Dispatch::validate` only checks that `repo` is non-blank. The empty string is then
        // a perfectly ordinary key in the memo, the fair-share plan table and this set, which makes
        // it a namespace two different dispatches could share. Whatever else it is, it must not be
        // privileged, and `parse` drops empty names so it can never be in the trusted set.
        let t = TrustedTenants::parse("acme, , globex");
        for repo in ["/widget", "//x", "/", "/acme/widget"] {
            assert_eq!(
                t.classify(repo, "justin"),
                AuthorClass::Outsider,
                "{repo} classified above outsider on an empty tenant"
            );
        }
    }

    #[test]
    fn the_author_string_cannot_choose_its_own_class() {
        // Spec §5: `author` is display only. Two dispatches differing only in `author` must classify
        // identically, or whoever wrote the change picks their own privileges.
        let t = TrustedTenants::parse("acme");
        assert_eq!(t.classify("acme/widget", "justin"), t.classify("acme/widget", "admin"));
        assert_eq!(t.classify("evil/widget", "justin"), t.classify("evil/widget", "admin"));
    }
}
