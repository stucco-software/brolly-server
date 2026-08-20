//! Rendering OAuth scopes as one comprehensible question (ADR 0011).
//!
//! Presentation only. [`crate::Subject`] keeps scopes verbatim and
//! `brolly-authz` matches them literally; nothing here widens or narrows a
//! grant.

use crate::oauth::Protocol;

/// What a capability touches. People reason about resources, not about which
/// specification named the scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Group {
    Identity,
    Profile,
    Posts,
    Social,
    Pod,
    /// Reaches beyond the grantor's own data.
    Administration,
    /// Not in the table. Shown verbatim and flagged.
    Unrecognised,
}

impl Group {
    pub fn heading(self) -> &'static str {
        match self {
            Group::Identity => "Your identity",
            Group::Profile => "Your profile",
            Group::Posts => "Your posts",
            Group::Social => "Who you follow",
            Group::Pod => "Your pod",
            Group::Administration => "Other people's data",
            Group::Unrecognised => "Permissions we don't recognise",
        }
    }
}

/// One line on the consent screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub group: Group,
    /// Plain language. An interpretation, which is why `raw` is always shown.
    pub summary: String,
    /// The literal protocol scope. A developer debugging a grant needs this,
    /// and hiding it would make the screen unauditable.
    pub raw: String,
    /// False when the scope is not in the table — displayed, flagged, never
    /// omitted.
    pub recognised: bool,
}

impl Capability {
    /// True when this line deserves visual emphasis: administrative reach, or a
    /// scope we could not explain.
    pub fn needs_attention(&self) -> bool {
        !self.recognised || self.group == Group::Administration
    }
}

/// The table. Data rather than branches, so adding a scope is one row.
fn lookup(protocol: Protocol, scope: &str) -> Option<(Group, &'static str)> {
    use Group::*;
    let row = match (protocol, scope) {
        // --- Mastodon ---
        (Protocol::Mastodon, "read") => (Posts, "Read everything you can see"),
        (Protocol::Mastodon, "write") => (Posts, "Post, edit and delete as you"),
        (Protocol::Mastodon, "follow") => (Social, "Follow and unfollow people as you"),
        (Protocol::Mastodon, "push") => (Identity, "Send you notifications"),
        (Protocol::Mastodon, "read:accounts") => (Profile, "Read your profile"),
        (Protocol::Mastodon, "write:accounts") => (Profile, "Change your profile"),
        (Protocol::Mastodon, "read:statuses") => (Posts, "Read your posts and timelines"),
        (Protocol::Mastodon, "write:statuses") => (Posts, "Post and delete as you"),
        (Protocol::Mastodon, "write:media") => (Posts, "Upload images and video as you"),
        (Protocol::Mastodon, "read:follows") => (Social, "See who you follow"),
        (Protocol::Mastodon, "write:follows") => (Social, "Follow and unfollow people as you"),
        (Protocol::Mastodon, "admin:read") => {
            (Administration, "Read any member's data on this server")
        }
        (Protocol::Mastodon, "admin:write") => {
            (Administration, "Moderate this server and act on any member")
        }

        // --- ATProtocol ---
        (Protocol::Atproto, "atproto") => (Identity, "Confirm which account you are"),
        (Protocol::Atproto, "transition:generic") => {
            (Pod, "Read and write records in your repository")
        }
        (Protocol::Atproto, "transition:chat.bsky") => {
            (Posts, "Read and send your direct messages")
        }
        (Protocol::Atproto, "transition:email") => (Identity, "See your email address"),

        // --- Solid-OIDC ---
        (Protocol::SolidOidc, "openid") => (Identity, "Confirm which account you are"),
        (Protocol::SolidOidc, "webid") => (Identity, "See your WebID"),
        (Protocol::SolidOidc, "profile") => (Profile, "Read your profile"),
        (Protocol::SolidOidc, "offline_access") => {
            (Identity, "Stay signed in when you are not using the app")
        }
        _ => return None,
    };
    Some(row)
}

/// Render a scope string for a protocol.
///
/// Order is stable and by group, so the same grant always reads the same way,
/// and anything needing attention is not buried in the middle of a list.
pub fn describe(protocol: Protocol, scopes: &str) -> Vec<Capability> {
    let mut out: Vec<Capability> = scopes
        .split_whitespace()
        .map(|scope| match lookup(protocol, scope) {
            Some((group, summary)) => Capability {
                group,
                summary: summary.to_string(),
                raw: scope.to_string(),
                recognised: true,
            },
            None => Capability {
                group: Group::Unrecognised,
                // Never guessed at. The user is told plainly that we cannot
                // explain it, rather than shown a plausible-sounding summary.
                summary: "This app is asking for something we can't describe.".to_string(),
                raw: scope.to_string(),
                recognised: false,
            },
        })
        .collect();

    out.sort_by(|a, b| a.group.cmp(&b.group).then(a.raw.cmp(&b.raw)));
    out.dedup_by(|a, b| a.raw == b.raw);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_protocol_renders_through_the_same_component() {
        // The property that matters: one vocabulary, not three screens that
        // drift. Each protocol's "read my posts" lands in the same group.
        let mastodon = describe(Protocol::Mastodon, "read:statuses");
        let atproto = describe(Protocol::Atproto, "transition:generic");
        let solid = describe(Protocol::SolidOidc, "webid");

        for set in [&mastodon, &atproto, &solid] {
            assert_eq!(set.len(), 1);
            assert!(set[0].recognised);
            assert!(!set[0].summary.is_empty());
            assert!(!set[0].raw.is_empty(), "the literal scope is always shown");
        }
        assert_eq!(mastodon[0].group, Group::Posts);
        assert_eq!(atproto[0].group, Group::Pod);
        assert_eq!(solid[0].group, Group::Identity);
    }

    #[test]
    fn an_unknown_scope_is_shown_and_flagged_never_dropped() {
        // The load-bearing rule. A protocol will add scopes we have not mapped;
        // the failure mode must be visible, not silent.
        let caps = describe(Protocol::Mastodon, "read:statuses invented:scope");
        assert_eq!(caps.len(), 2, "the unknown scope must not be omitted");

        let unknown = caps.iter().find(|c| c.raw == "invented:scope").unwrap();
        assert!(!unknown.recognised);
        assert!(unknown.needs_attention());
        assert_eq!(unknown.group, Group::Unrecognised);
    }

    #[test]
    fn an_unknown_scope_is_never_guessed_at() {
        let caps = describe(Protocol::Atproto, "transition:something-new");
        assert!(
            !caps[0].summary.contains("something-new"),
            "a plausible-sounding summary invented from the scope name would \
             mislead someone into approving it"
        );
        assert!(
            caps[0].raw.contains("something-new"),
            "but the literal scope is shown"
        );
    }

    #[test]
    fn admin_scopes_are_marked_as_reaching_other_people() {
        let caps = describe(Protocol::Mastodon, "admin:write");
        assert_eq!(caps[0].group, Group::Administration);
        assert!(
            caps[0].needs_attention(),
            "admin:write is not a bigger version of write — it reaches other people's data"
        );
    }

    #[test]
    fn ordinary_scopes_do_not_cry_wolf() {
        for cap in describe(Protocol::Mastodon, "read write follow") {
            assert!(!cap.needs_attention(), "{} should be unremarkable", cap.raw);
        }
    }

    #[test]
    fn attention_lines_sort_to_the_end_not_the_middle() {
        let caps = describe(
            Protocol::Mastodon,
            "invented:scope read:statuses admin:write",
        );
        let groups: Vec<Group> = caps.iter().map(|c| c.group).collect();
        assert_eq!(
            groups,
            vec![Group::Posts, Group::Administration, Group::Unrecognised]
        );
    }

    #[test]
    fn duplicate_scopes_render_once() {
        let caps = describe(Protocol::Mastodon, "read read");
        assert_eq!(caps.len(), 1);
    }

    #[test]
    fn every_row_in_the_table_has_copy() {
        // Guards against a row added with an empty summary, which would render
        // a blank line on the highest-stakes screen in the product.
        for (protocol, scope) in [
            (Protocol::Mastodon, "read"),
            (Protocol::Mastodon, "admin:write"),
            (Protocol::Atproto, "atproto"),
            (Protocol::Atproto, "transition:generic"),
            (Protocol::SolidOidc, "openid"),
            (Protocol::SolidOidc, "offline_access"),
        ] {
            let (_, summary) = lookup(protocol, scope).expect("mapped");
            assert!(!summary.is_empty(), "{protocol:?} {scope} has no copy");
        }
    }

    #[test]
    fn group_headings_are_all_populated() {
        for group in [
            Group::Identity,
            Group::Profile,
            Group::Posts,
            Group::Social,
            Group::Pod,
            Group::Administration,
            Group::Unrecognised,
        ] {
            assert!(!group.heading().is_empty());
        }
    }
}
