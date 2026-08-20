//! The OAuth consent screen — one component, three protocol callers.
//!
//! §4.1 calls this the highest-stakes surface in the product: it renders inside
//! someone else's app flow, and it is the moment a person decides whether to
//! hand an app access to their pod. Solid-OIDC, ATProtocol and Mastodon all
//! render through here, so the copy cannot drift between protocols — nobody
//! compares consent wording across three screens.
//!
//! Scope vocabulary and the unknown-scope rule live in
//! [`brolly_identity::consent`] (ADR 0011). This module is layout.

use askama::Template;
use axum::response::Response;
use brolly_identity::consent::{Capability, describe};
use brolly_identity::oauth::Protocol;

use crate::render;

/// Capabilities sharing a resource group, rendered as one block.
pub struct Section {
    pub heading: &'static str,
    pub capabilities: Vec<Capability>,
    /// True when the whole block deserves emphasis — administrative reach or
    /// scopes we could not explain.
    pub attention: bool,
}

#[derive(Template)]
#[template(path = "consent.html")]
struct ConsentPage<'a> {
    instance_name: &'a str,
    app_name: &'a str,
    username: &'a str,
    client_id: &'a str,
    protocol_label: &'a str,
    action: &'a str,
    request_token: &'a str,
    sections: Vec<Section>,
}

fn protocol_label(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Mastodon => "the Mastodon API",
        Protocol::Atproto => "ATProtocol",
        Protocol::SolidOidc => "Solid",
    }
}

/// Group a flat capability list into display sections, preserving the ordering
/// [`describe`] established — anything needing attention sorts last rather than
/// being buried mid-list.
pub fn sections_for(protocol: Protocol, scopes: &str) -> Vec<Section> {
    let capabilities = describe(protocol, scopes);
    let mut sections: Vec<Section> = Vec::new();

    for capability in capabilities {
        let group = capability.group;
        match sections.last_mut() {
            Some(section) if section.heading == group.heading() => {
                section.attention |= capability.needs_attention();
                section.capabilities.push(capability);
            }
            _ => sections.push(Section {
                heading: group.heading(),
                attention: capability.needs_attention(),
                capabilities: vec![capability],
            }),
        }
    }
    sections
}

/// Render the consent screen.
///
/// `action` is the protocol's own decision endpoint, so the three callers keep
/// their separate flows (ADR 0008) while sharing this surface.
#[allow(clippy::too_many_arguments)]
pub fn render_consent(
    instance_name: &str,
    protocol: Protocol,
    app_name: &str,
    username: &str,
    client_id: &str,
    scopes: &str,
    action: &str,
    request_token: &str,
) -> Response {
    render(&ConsentPage {
        instance_name,
        app_name,
        username,
        client_id,
        protocol_label: protocol_label(protocol),
        action,
        request_token,
        sections: sections_for(protocol, scopes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use brolly_identity::consent::Group;

    #[test]
    fn capabilities_group_by_resource() {
        let sections = sections_for(
            Protocol::Mastodon,
            "read:statuses write:statuses read:accounts",
        );
        assert_eq!(sections.len(), 2, "posts and profile");
        assert_eq!(sections[0].heading, Group::Profile.heading());
        assert_eq!(sections[1].heading, Group::Posts.heading());
        assert_eq!(sections[1].capabilities.len(), 2);
    }

    #[test]
    fn an_unknown_scope_makes_its_section_conspicuous() {
        let sections = sections_for(Protocol::Atproto, "atproto transition:not-yet-invented");
        let last = sections.last().unwrap();
        assert!(
            last.attention,
            "unrecognised scopes must be visually distinct"
        );
        assert_eq!(last.heading, Group::Unrecognised.heading());
    }

    #[test]
    fn all_three_protocols_produce_the_same_shape() {
        for (protocol, scopes) in [
            (Protocol::Mastodon, "read write"),
            (Protocol::Atproto, "atproto transition:generic"),
            (Protocol::SolidOidc, "openid webid offline_access"),
        ] {
            let sections = sections_for(protocol, scopes);
            assert!(!sections.is_empty(), "{protocol:?} rendered nothing");
            for section in &sections {
                assert!(!section.heading.is_empty());
                assert!(!section.capabilities.is_empty());
            }
        }
    }

    #[test]
    fn an_ordinary_grant_has_no_attention_sections() {
        let sections = sections_for(Protocol::SolidOidc, "openid webid");
        assert!(sections.iter().all(|s| !s.attention));
    }

    #[test]
    fn every_protocol_has_a_label() {
        for protocol in [Protocol::Mastodon, Protocol::Atproto, Protocol::SolidOidc] {
            assert!(!protocol_label(protocol).is_empty());
        }
    }
}
