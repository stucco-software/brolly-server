//! The normalized result of authentication.
//!
//! Whatever scheme a request arrived with — session cookie, Mastodon Bearer,
//! ATProtocol DPoP, Solid-OIDC DPoP — it becomes a `Subject`. Handlers take a
//! `Subject` and nothing else, so authorization (`brolly-authz`) sees one shape
//! and there is no per-protocol notion of "who is asking".

use uuid::Uuid;

/// Which scheme produced this subject. Kept for audit and for the few decisions
/// that genuinely differ by scheme (DPoP replay windows, for instance) — never
/// for authorization, which reads the WebID and scopes only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// Browser session cookie. The dashboard and admin console.
    Session,
    /// Mastodon Client API bearer token.
    MastodonBearer,
    /// ATProtocol OAuth, DPoP-bound.
    AtprotoDpop,
    /// Solid-OIDC, DPoP-bound.
    SolidDpop,
    /// ATProtocol inter-service auth JWT (`lxm`-scoped).
    ServiceAuth,
}

impl Via {
    /// True when the credential is bound to a proof-of-possession key, so a
    /// stolen token alone is insufficient.
    pub fn is_key_bound(self) -> bool {
        matches!(self, Via::AtprotoDpop | Via::SolidDpop)
    }
}

/// A raw credential lifted off a request, before verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    Session(String),
    Bearer(String),
    Dpop { token: String, proof: String },
}

/// Granted scopes, normalized across protocols.
///
/// Each protocol spells its scopes differently — Mastodon `read:statuses`,
/// ATProtocol `transition:generic`, Solid `webid`. They are kept verbatim and
/// compared verbatim; translating them would invent authority nobody granted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scope(Vec<String>);

impl Scope {
    pub fn parse(raw: &str) -> Self {
        Self(raw.split_whitespace().map(str::to_string).collect())
    }

    pub fn includes(&self, scope: &str) -> bool {
        self.0.iter().any(|s| s == scope)
    }

    /// True if any of `any` is present. Mastodon's coarse scopes (`read`) stand
    /// in for finer ones (`read:statuses`), so call sites list both rather than
    /// encoding a hierarchy that only one protocol has.
    pub fn includes_any(&self, any: &[&str]) -> bool {
        any.iter().any(|s| self.includes(s))
    }

    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}

/// Who is making this request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    /// Local user, when the credential maps to one. `None` for a verified remote
    /// caller (a federating peer) that has no account here.
    pub user_id: Option<Uuid>,
    /// Canonical federation identity. **`did:plc` for local users** (D11).
    pub did: Option<String>,
    /// WebID. This is what `brolly-authz` matches against `acl:agent`.
    pub webid: Option<String>,
    pub scope: Scope,
    pub via: Via,
}

impl Subject {
    /// An authenticated local user.
    pub fn local(user_id: Uuid, did: String, webid: String, scope: Scope, via: Via) -> Self {
        Self {
            user_id: Some(user_id),
            did: Some(did),
            webid: Some(webid),
            scope,
            via,
        }
    }

    /// A verified remote caller: a WebID with no account on this instance
    /// (spec 6, H5 — a token from another Solid-OIDC issuer, bound to its
    /// WebID by the WebID's own `solid:oidcIssuer`).
    ///
    /// `user_id: None` and `did: None` — the shape `user_id`'s doc comment
    /// describes — because there is no local account to name: WAC, the only
    /// thing the pod surface consults, matches the WebID, and resolving a
    /// local user instead would be a special case shaped like a bypass of the
    /// issuer binding.
    pub fn remote(webid: String, scope: Scope, via: Via) -> Self {
        Self {
            user_id: None,
            did: None,
            webid: Some(webid),
            scope,
            via,
        }
    }

    /// Nobody: no credential was presented, or the one that was did not
    /// resolve to a person.
    ///
    /// `via` is `Via::Session` because it has to be something; it is kept for
    /// audit and for the few decisions that differ by scheme, and an anonymous
    /// subject makes none of them. What matters is `webid: None`, which makes
    /// [`Subject::agent`] `Agent::Anonymous`, so only
    /// `acl:agentClass foaf:Agent` can grant it anything.
    ///
    /// Used twice for different reasons: `pod.rs` falls back to it when a
    /// request carries no credential, and `ldp::describe` probes with it to
    /// find out what the *public* may do with a resource (spec 5b, H9).
    pub fn anonymous() -> Self {
        Self {
            user_id: None,
            did: None,
            webid: None,
            scope: Scope::default(),
            via: Via::Session,
        }
    }

    /// The authz agent for this subject.
    ///
    /// A subject with no WebID is anonymous *for authorization purposes* even if
    /// it authenticated — a service-auth JWT proves which server is calling, not
    /// which person, and must not inherit a user's grants.
    pub fn agent(&self) -> brolly_authz::Agent {
        match &self.webid {
            Some(webid) => brolly_authz::Agent::Authenticated(webid.clone()),
            None => brolly_authz::Agent::Anonymous,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_auth_does_not_become_an_authorized_agent() {
        let subject = Subject {
            user_id: None,
            did: Some("did:plc:remote".into()),
            webid: None,
            scope: Scope::parse(""),
            via: Via::ServiceAuth,
        };
        assert_eq!(
            subject.agent(),
            brolly_authz::Agent::Anonymous,
            "a server proving its own identity must not inherit a user's grants"
        );
    }

    #[test]
    fn coarse_and_fine_scopes_are_both_accepted() {
        let scope = Scope::parse("read write:statuses");
        assert!(scope.includes_any(&["read:statuses", "read"]));
        assert!(scope.includes("write:statuses"));
        assert!(!scope.includes("admin"));
    }

    /// The pod, the ActivityPub inbox and `ldp::describe`'s `public=` probe
    /// each need "nobody". Three private copies of this struct literal is how
    /// one of them ends up with a `webid` of `Some("")`, which `authorize`
    /// would then match against `acl:agent`.
    #[test]
    fn an_anonymous_subject_authorizes_as_nobody() {
        let nobody = Subject::anonymous();
        assert_eq!(nobody.agent(), brolly_authz::Agent::Anonymous);
        assert_eq!(nobody.webid, None, "a WebID is what grants match on");
        assert_eq!(nobody.user_id, None);
        assert_eq!(nobody.did, None);
        assert!(nobody.scope.as_slice().is_empty(), "no scope is granted");
    }

    #[test]
    fn a_remote_caller_is_no_local_user_and_still_an_authenticated_agent() {
        // The shape `user_id: None` was designed for (spec 6, H5): a foreign
        // issuer's token verifies to a WebID this instance does not host, and
        // nothing else. A `user_id` here would be a local account the binding
        // never established.
        let webid = "https://bob.example.org/profile#me".to_string();
        let subject = Subject::remote(webid.clone(), Scope::parse("webid"), Via::SolidDpop);
        assert_eq!(subject.user_id, None);
        assert_eq!(subject.did, None);
        assert_eq!(subject.webid.as_deref(), Some(webid.as_str()));
        assert_eq!(
            subject.agent(),
            brolly_authz::Agent::Authenticated(webid),
            "the WebID is what WAC matches"
        );
    }

    #[test]
    fn dpop_schemes_are_key_bound() {
        assert!(Via::AtprotoDpop.is_key_bound());
        assert!(Via::SolidDpop.is_key_bound());
        assert!(!Via::MastodonBearer.is_key_bound());
        assert!(!Via::Session.is_key_bound());
    }
}
