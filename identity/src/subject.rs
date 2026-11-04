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

    /// Is this subject the owner of the pod at `pod_origin`
    /// (`https://<user>.<base>`, the `base` LDP is handed)?
    ///
    /// The owner always holds every mode on every resource in their own pod,
    /// whatever its ACLs say (ADR 0019). WAC alone has no such rule, so one
    /// `.acl` that forgets the member locks them out of their own storage and
    /// — since repairing it needs Control — keeps them out.
    ///
    /// **Two conditions, both required.**
    ///
    /// * `user_id` is `Some`: this instance authenticated the caller — a
    ///   session, our own Solid-OIDC token, a Mastodon token, ATProto.
    ///   [`Subject::remote`] has `None`, so a token another issuer signed is
    ///   never the owner, *even when it names a local WebID*. The issuer
    ///   binding already refuses that token (our profiles name only this
    ///   instance as `solid:oidcIssuer`); this is the wall behind it, so a
    ///   binding regression degrades to "WAC decides", not to full control.
    /// * The WebID is exactly the pod's own, derived from the origin the same
    ///   way [`crate::webid::webid`] derives it. A string match on an IRI the
    ///   server minted, not a parse: near misses (another fragment, a nested
    ///   subdomain, `http:`) are not the owner.
    ///
    /// A service-auth subject has no WebID and so owns nothing, whatever its
    /// `user_id`.
    pub fn owns(&self, pod_origin: &str) -> bool {
        self.user_id.is_some()
            && self
                .webid
                .as_deref()
                .is_some_and(|webid| webid == crate::webid::webid_at(pod_origin))
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

    /// The owner bypass's predicate (ADR 0019). Alice's pod lives at
    /// `https://alice.brolly.id`; its owner is a subject this instance
    /// authenticated *as* `https://alice.brolly.id/profile#me`.
    #[test]
    fn the_owner_is_a_local_subject_with_the_pods_own_webid() {
        let pod = "https://alice.brolly.id";
        let alice = crate::webid::webid("alice", "brolly.id");
        for via in [
            Via::Session,
            Via::SolidDpop,
            Via::MastodonBearer,
            Via::AtprotoDpop,
        ] {
            let local = Subject::local(
                Uuid::new_v4(),
                "did:plc:alice".into(),
                alice.clone(),
                Scope::parse("webid"),
                via,
            );
            assert!(local.owns(pod), "{via:?}: alice owns her own pod");
            assert!(
                !local.owns("https://bob.brolly.id"),
                "{via:?}: and nobody else's"
            );
        }
    }

    #[test]
    fn a_remote_subject_never_owns_a_pod_even_naming_its_webid() {
        // `user_id: None` is a subject this instance did not authenticate.
        // The issuer binding already refuses a foreign token for a local
        // WebID; this is the wall behind it.
        let remote = Subject::remote(
            crate::webid::webid("alice", "brolly.id"),
            Scope::parse("webid"),
            Via::SolidDpop,
        );
        assert!(!remote.owns("https://alice.brolly.id"));
    }

    #[test]
    fn nobody_and_a_server_own_nothing() {
        assert!(!Subject::anonymous().owns("https://alice.brolly.id"));
        let service = Subject {
            user_id: Some(Uuid::new_v4()),
            did: Some("did:plc:alice".into()),
            webid: None,
            scope: Scope::default(),
            via: Via::ServiceAuth,
        };
        assert!(!service.owns("https://alice.brolly.id"));
    }

    #[test]
    fn ownership_is_an_exact_webid_match() {
        let as_webid = |webid: &str| {
            Subject::local(
                Uuid::new_v4(),
                "did:plc:x".into(),
                webid.into(),
                Scope::parse("webid"),
                Via::Session,
            )
        };
        let pod = "https://alice.brolly.id";
        for near_miss in [
            "https://alice.brolly.id/profile",
            "https://alice.brolly.id/profile#you",
            "https://evil.alice.brolly.id/profile#me",
            "http://alice.brolly.id/profile#me",
            "https://alice.brolly.id.evil/profile#me",
        ] {
            assert!(!as_webid(near_miss).owns(pod), "{near_miss}");
        }
        // A pod origin with a trailing slash names no pod: `base` never has
        // one, and a predicate that tolerated it would be guessing.
        assert!(!as_webid("https://alice.brolly.id/profile#me").owns("https://alice.brolly.id/"));
    }

    #[test]
    fn dpop_schemes_are_key_bound() {
        assert!(Via::AtprotoDpop.is_key_bound());
        assert!(Via::SolidDpop.is_key_bound());
        assert!(!Via::MastodonBearer.is_key_bound());
        assert!(!Via::Session.is_key_bound());
    }
}
