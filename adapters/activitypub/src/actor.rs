//! Actor documents, WebFinger and NodeInfo.
//!
//! Pure builders: they take what they need and return JSON. No store, no
//! database, no network — which is what lets the shapes be asserted directly
//! rather than through a request.
//!
//! An actor document is a **projection**, never a second copy. The name and
//! summary come from the profile triples asserted onto the WebID (D8), the same
//! node the Solid profile writer and the ATProtocol adapter write to. Nothing
//! here owns any state.

use serde_json::{Value, json};

/// The AS2 context, plus the security vocabulary that gives `publicKey` its
/// meaning. Without the second entry `publicKey` is an undefined term and a
/// strict JSON-LD processor drops it — taking the key with it.
fn context() -> Value {
    json!([
        "https://www.w3.org/ns/activitystreams",
        "https://w3id.org/security/v1",
        // `discoverable` is Mastodon's term, so its namespace has to be in
        // scope or a strict JSON-LD processor drops it.
        {"toot": "http://joinmastodon.org/ns#", "discoverable": "toot:discoverable"},
    ])
}

/// The key id a verifier dereferences out of a `Signature` header.
///
/// `#main-key` is not in any spec, but it is what Mastodon publishes and what
/// most implementations expect to find, so following the convention is worth
/// more than following the silence.
pub fn key_id(actor: &str) -> String {
    format!("{actor}#main-key")
}

fn public_key(actor: &str, public_key_pem: &str) -> Value {
    json!({
        "id": key_id(actor),
        "owner": actor,
        "publicKeyPem": public_key_pem,
    })
}

/// The profile flags that change how a remote instance treats an actor.
#[derive(Debug, Clone, Copy, Default)]
pub struct Flags {
    /// Follows need approval. Remote instances read this to know whether to
    /// expect an `Accept`; an actor that lies here strands every follow it
    /// receives, because the sender waits forever for a reply that never comes.
    pub locked: bool,
    pub bot: bool,
    pub discoverable: bool,
}

/// A member's actor document.
///
/// Every collection is on the member's own host. An `inbox` on the apex would
/// route their private delivery to the shared inbox, where the instance
/// processor — not the member's — would handle it.
///
/// `icon` is the member's `foaf:depiction` target (spec 4, H6), emitted with
/// no access check: a pointer, not bytes, and the fetch of it answers to the
/// target's own ACL. An `Image` object because that is the shape every
/// ActivityPub client reads an icon out of; the IRI is in `url`, and no
/// `mediaType` is invented — the profile triple does not carry one, and
/// guessing would be a lie the client renders.
pub fn person(
    username: &str,
    base_domain: &str,
    public_key_pem: &str,
    name: &str,
    summary: &str,
    icon: Option<&str>,
    flags: Flags,
) -> Value {
    use brolly_identity::webid;
    let actor = webid::actor(username, base_domain);

    let mut document = json!({
        "@context": context(),
        // `Service` is how the fediverse marks an automated account; clients
        // badge it and some filter on it.
        "type": if flags.bot { "Service" } else { "Person" },
        "manuallyApprovesFollowers": flags.locked,
        "discoverable": flags.discoverable,
        "id": actor,
        "preferredUsername": username,
        "inbox": webid::inbox(username, base_domain),
        "outbox": webid::outbox(username, base_domain),
        "followers": webid::followers(username, base_domain),
        "following": webid::following(username, base_domain),
        "endpoints": {
            // Remote instances delivering to several of our members send once
            // here instead of once each.
            "sharedInbox": webid::shared_inbox(base_domain),
        },
        // The Solid storage root, so a client that finds the actor can also
        // find the pod. This is the join between the two protocols.
        "url": format!("https://{username}.{base_domain}/"),
        "publicKey": public_key(&actor, public_key_pem),
    });

    // Absent rather than empty: `"name": ""` renders as a blank display name in
    // most clients, where a missing one falls back to the username.
    if !name.trim().is_empty() {
        document["name"] = json!(name);
    }
    if !summary.trim().is_empty() {
        document["summary"] = json!(summary);
    }
    // Absent for the same reason as the name: a client that finds no `icon`
    // renders its own placeholder, where an empty one renders as a broken
    // image.
    if let Some(icon) = icon {
        document["icon"] = json!({"type": "Image", "url": icon});
    }
    document
}

/// The instance's own actor (D4).
///
/// `Application` rather than `Person`: clients render service actors
/// differently, and it is not someone anyone should be able to follow expecting
/// a human.
pub fn application(base_domain: &str, public_key_pem: &str) -> Value {
    use brolly_identity::webid;
    let actor = webid::instance_actor(base_domain);

    json!({
        "@context": context(),
        "type": "Application",
        "id": actor,
        "preferredUsername": base_domain,
        "name": base_domain,
        "inbox": webid::shared_inbox(base_domain),
        "outbox": format!("https://{base_domain}/outbox"),
        "url": format!("https://{base_domain}/"),
        "publicKey": public_key(&actor, public_key_pem),
    })
}

/// A WebFinger response (RFC 7033), as JRD.
pub fn webfinger(username: &str, base_domain: &str) -> Value {
    use brolly_identity::webid;
    let actor = webid::actor(username, base_domain);

    json!({
        "subject": format!("acct:{}", webid::handle(username, base_domain)),
        "aliases": [actor, format!("https://{username}.{base_domain}/")],
        "links": [
            {
                "rel": "self",
                "type": "application/activity+json",
                "href": actor,
            },
            {
                "rel": "http://webfinger.net/rel/profile-page",
                "type": "text/html",
                "href": format!("https://{username}.{base_domain}/"),
            },
            // Solid clients discover the pod from the same lookup.
            {
                "rel": "http://www.w3.org/ns/pim/space#storage",
                "href": brolly_identity::routing::storage_root(username, base_domain),
            },
        ],
    })
}

/// Split a WebFinger `resource` into `(username, host)`.
///
/// Accepts `acct:alice@host`, a bare `alice@host`, and the `@alice@host` form
/// people paste out of a client. Returns `None` for anything else rather than
/// guessing — a resource we cannot parse is not one we should answer for.
pub fn parse_resource(resource: &str) -> Option<(String, String)> {
    // Trim before stripping, not after: a resource that arrives with leading
    // whitespace would otherwise fail to match `acct:` and carry its trailing
    // spaces into the host.
    let account = resource.trim();
    let account = account.strip_prefix("acct:").unwrap_or(account).trim();
    let account = account.strip_prefix('@').unwrap_or(account);

    let (username, host) = account.split_once('@')?;
    if username.is_empty() || host.is_empty() || host.contains('@') {
        return None;
    }
    Some((username.to_ascii_lowercase(), host.to_ascii_lowercase()))
}

/// `/.well-known/nodeinfo` — the discovery document that points at the real one.
pub fn nodeinfo_discovery(base_domain: &str) -> Value {
    json!({
        "links": [{
            "rel": "http://nodeinfo.diaspora.software/ns/schema/2.1",
            "href": format!("https://{base_domain}/nodeinfo/2.1"),
        }],
    })
}

/// NodeInfo 2.1.
///
/// The counts are deliberately the only numbers here. NodeInfo is a public,
/// unauthenticated document that aggregators scrape, so anything added to it is
/// published to everyone forever.
pub fn nodeinfo(users: i64, posts: i64) -> Value {
    json!({
        "version": "2.1",
        "software": {
            "name": "brolly",
            "version": env!("CARGO_PKG_VERSION"),
            "repository": "https://github.com/",
        },
        "protocols": ["activitypub"],
        "services": {"inbound": [], "outbound": []},
        // Invite-only. Advertising open registration would put us in the
        // signup lists that spam registrations come from.
        "openRegistrations": false,
        "usage": {
            "users": {"total": users},
            "localPosts": posts,
        },
        "metadata": {},
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "brolly.id";
    const PEM: &str = "-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----\n";

    #[test]
    fn a_persons_collections_are_all_on_their_own_host() {
        let actor = person("alice", BASE, PEM, "", "", None, Flags::default());
        for field in ["id", "inbox", "outbox", "followers", "following"] {
            let value = actor[field].as_str().expect(field);
            assert!(
                value.starts_with("https://alice.brolly.id/"),
                "{field} is {value}, not on alice's host"
            );
        }
    }

    #[test]
    fn the_shared_inbox_is_the_instances_and_the_personal_one_is_not() {
        let actor = person("alice", BASE, PEM, "", "", None, Flags::default());
        assert_eq!(actor["inbox"], "https://alice.brolly.id/inbox");
        assert_eq!(
            actor["endpoints"]["sharedInbox"], "https://brolly.id/inbox",
            "the shared inbox is the instance's, or fan-in defeats its purpose"
        );
    }

    #[test]
    fn an_empty_name_is_omitted_rather_than_blank() {
        // `"name": ""` renders as an empty display name; a missing one falls
        // back to the username.
        let actor = person("alice", BASE, PEM, "", "", None, Flags::default());
        assert!(actor.get("name").is_none());
        assert!(actor.get("summary").is_none());

        let named = person(
            "alice",
            BASE,
            PEM,
            "Alice Example",
            "Hello",
            None,
            Flags::default(),
        );
        assert_eq!(named["name"], "Alice Example");
        assert_eq!(named["summary"], "Hello");
    }

    #[test]
    fn the_icon_is_the_depiction_iri_and_absent_without_one() {
        // H6 (spec 4): the actor's icon is the member's `foaf:depiction`
        // target, and absent without one — a missing `icon` renders the
        // client's own placeholder, where an empty one renders a broken
        // image. An `Image` object because that is the shape every
        // ActivityPub client reads an icon out of.
        let bare = person("alice", BASE, PEM, "", "", None, Flags::default());
        assert!(bare.get("icon").is_none());

        let depicted = person(
            "alice",
            BASE,
            PEM,
            "",
            "",
            Some("https://alice.brolly.id/~/media/01J5ZP7WQC5V1TQ3M8BRFNV8HA"),
            Flags::default(),
        );
        assert_eq!(depicted["icon"]["type"], "Image");
        assert_eq!(
            depicted["icon"]["url"],
            "https://alice.brolly.id/~/media/01J5ZP7WQC5V1TQ3M8BRFNV8HA"
        );
    }

    #[test]
    fn the_security_context_is_present_so_the_key_survives_processing() {
        let actor = person("alice", BASE, PEM, "", "", None, Flags::default());
        let context = actor["@context"].to_string();
        assert!(context.contains("activitystreams"));
        assert!(
            context.contains("w3id.org/security"),
            "without this, publicKey is an undefined term and gets dropped"
        );
    }

    #[test]
    fn the_key_id_is_the_actor_with_a_main_key_fragment() {
        let actor = person("alice", BASE, PEM, "", "", None, Flags::default());
        assert_eq!(
            actor["publicKey"]["id"],
            "https://alice.brolly.id/actor#main-key"
        );
        assert_eq!(actor["publicKey"]["owner"], actor["id"]);
    }

    #[test]
    fn a_locked_actor_says_so_where_remote_instances_look() {
        // An actor that does not advertise the lock strands every follow: the
        // sender waits for an Accept that is never coming.
        let actor = person(
            "alice",
            BASE,
            PEM,
            "",
            "",
            None,
            Flags {
                locked: true,
                ..Default::default()
            },
        );
        assert_eq!(actor["manuallyApprovesFollowers"], true);
    }

    #[test]
    fn a_bot_is_typed_as_a_service() {
        let actor = person(
            "alice",
            BASE,
            PEM,
            "",
            "",
            None,
            Flags {
                bot: true,
                ..Default::default()
            },
        );
        assert_eq!(
            actor["type"], "Service",
            "clients badge automated accounts off the type"
        );
    }

    #[test]
    fn the_instance_actor_is_an_application_on_the_apex() {
        let actor = application(BASE, PEM);
        assert_eq!(actor["type"], "Application");
        assert_eq!(actor["id"], "https://brolly.id/actor");
        assert_eq!(actor["inbox"], "https://brolly.id/inbox");
    }

    #[test]
    fn webfinger_points_at_both_the_actor_and_the_pod() {
        let jrd = webfinger("alice", BASE);
        assert_eq!(jrd["subject"], "acct:alice@brolly.id");

        let links = jrd["links"].as_array().expect("links");
        let self_link = links.iter().find(|l| l["rel"] == "self").expect("self");
        assert_eq!(self_link["href"], "https://alice.brolly.id/actor");
        assert_eq!(self_link["type"], "application/activity+json");

        let storage = links
            .iter()
            .find(|l| l["rel"].as_str().is_some_and(|r| r.ends_with("#storage")))
            .expect("a storage link");
        assert_eq!(storage["href"], "https://alice.brolly.id/~/");
    }

    #[test]
    fn a_resource_parses_in_every_form_a_client_sends() {
        for input in [
            "acct:alice@brolly.id",
            "alice@brolly.id",
            "@alice@brolly.id",
            "acct:@alice@brolly.id",
            "  acct:alice@brolly.id  ",
            "acct:ALICE@BROLLY.ID",
        ] {
            assert_eq!(
                parse_resource(input),
                Some(("alice".into(), "brolly.id".into())),
                "failed to parse {input}"
            );
        }
    }

    #[test]
    fn nonsense_resources_are_refused_rather_than_guessed() {
        for input in [
            "",
            "acct:",
            "alice",
            "@brolly.id",
            "alice@",
            "https://alice.brolly.id/actor",
            // Two hosts is ambiguous; answering for either would be a guess.
            "acct:alice@one@two",
        ] {
            assert_eq!(parse_resource(input), None, "{input} should not parse");
        }
    }

    #[test]
    fn nodeinfo_does_not_advertise_open_registration() {
        let node = nodeinfo(3, 7);
        assert_eq!(node["version"], "2.1");
        assert_eq!(node["software"]["name"], "brolly");
        assert_eq!(node["openRegistrations"], false);
        assert_eq!(node["usage"]["users"]["total"], 3);
        assert_eq!(node["usage"]["localPosts"], 7);
    }

    #[test]
    fn nodeinfo_discovery_points_at_a_document_we_serve() {
        let discovery = nodeinfo_discovery(BASE);
        let href = discovery["links"][0]["href"].as_str().expect("href");
        assert_eq!(href, "https://brolly.id/nodeinfo/2.1");
    }
}
