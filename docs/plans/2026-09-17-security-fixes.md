# Stage 0 Security Fixes Implementation Plan

<!-- doc-paths: skip -->
<!-- A plan cites the files it is about to create, so the paths it names
     are not expected to resolve until it has been executed. -->

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close four exploitable holes and one blocking defect:
- activities that overwrite another member's graphs
- `.acl` files writable without Control
- ATProto OAuth that never validates clients
- DPoP proofs that can be replayed
- no outbound HTTPS

**Architecture:** Five chunks, one per spec section, landing as **six commits
on `main`**. Chunk 5's first commit, threading `ClientLookup` through
`AppState`, is a separate commit with no behaviour change.
- An origin rule in the ActivityPub processor and outbox.
- A governed-path rule in `ldp::check`.
- An `Unspent<T>` type that makes recording a DPoP `jti` a compile-time
  requirement.
- rustls with ring for reqwest.
- A validated, SSRF-hardened client-metadata lookup in front of ATProto PAR.

**Tech Stack:** Rust, axum 0.8, sqlx/Postgres, oxigraph, reqwest 0.13
(rustls-no-provider plus ring), moka, testcontainers.

**Spec:** [`docs/specs/2026-09-17-security-fixes.md`](../specs/2026-09-17-security-fixes.md)
**Roadmap:** [`docs/specs/2026-09-17-interop-roadmap.md`](../specs/2026-09-17-interop-roadmap.md), stage 0.

---

## Ordering

Chunks run in order: **1 (A1), 2 (A2), 3 (C), 4 (B0), 5 (B).** Each chunk
assumes the previous ones are merged. Rules:

- **Gates, then commit.** Each commit runs the gates and is verified from a
  clean checkout (below).
- **Chunks that are one commit.** A1, A2 and C each land as a single commit
  spread across several tasks. Only a chunk's last task commits; the earlier
  tasks run their tests and gates and stage their files. Don't commit in the
  middle of one of these chunks, because the intermediate trees don't compile
  (C changes `dpop::verify`'s return type for every caller at once) or leave a
  hole half-closed.
- **Chunk 5 is four commits:** rules, threading, fetcher, PAR. Only the last
  one changes behaviour.

## Interfaces fixed across chunks

- **Chunk 3:** `brolly_identity::dpop::{Unspent<T>, DpopError::{Replayed, Storage}}`.
  `Unspent::{spend(pool, now), replace(value), bound_to(jkt)}`.
  `atproto_oauth::proof_thumbprint` becomes `async` and spends the proof.
  `tokens::verify_access` returns `Access::{Bearer, Bound}`.
- **Chunk 4:** `brolly_server::tls::install_crypto_provider()`, which is
  idempotent.
- **Chunk 5:**
  - `brolly_atproto::client_metadata::{ClientId, ClientMetadata, ClientError, parse_client_id, loopback_metadata, validate, check_request}`
  - `brolly_server::client_metadata::{ClientLookup, StaticClients, Fetcher, PublicOnly, LookupError, lookup_client}`
  - `AppState.clients: Arc<dyn ClientLookup>`
  - Chunk 3's XRPC replay test runs a real PAR, so chunk 5 must register
    `https://app.example/client-metadata.json` in `server/tests/xrpc.rs` as well
    as in `atproto_oauth.rs`.

## Verify every commit from a clean checkout

Passing the gates in your own working tree only proves that tree is
consistent, not that `main` is. So after each commit:

```bash
rm -rf /tmp/verify && git worktree add --detach /tmp/verify HEAD
cd /tmp/verify && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings
cd - && git worktree remove /tmp/verify --force
```

The commit isn't done until that passes. Chunk 4's first build needs crates.io
access, because `rustls-platform-verifier` is new to the lock.

## After deploying

- **Chunk 2:** stop the server, run `brolly-admin acl-uncontain` once, then
  start it again.
- **Chunk 4:** on an instance with `BROLLY_PLC_SUBMIT` set, `brolly-admin plc-retry`
  can now reach plc.directory. That's an optional manual check, not a gate.

## Chunk 1: Activities only touch graphs their actor owns (A1)

Spec section A1, and its tests under **Testing → A1**. This is rollout commit 1,
and the spec ships it as **one commit**. Tasks 1–4 each leave the workspace
green, but only Task 5 commits. Don't commit before then. A half-landed A1
leaves the outbox writing graphs the processor would refuse.

**What changes, in one place:**

| File | Change |
|---|---|
| `adapters/activitypub/src/processor.rs` | `same_origin`, `ProcessError::ForeignObject`, the origin gate in `process`, `Recipient::Member { inbox, outbox }`, `Delete` removes only embedded carriers, index guards |
| `store/src/index.rs` | `record_note` never adds a second author |
| `server/src/outbox.rs` | `as_activity` mints and flattens; `deliver` becomes `pub`, checks `authored` first, and returns `DeliverError`; refusals logged at `warn` |
| `server/src/mastodon_api.rs` | `create_status` maps `DeliverError` |
| `adapters/activitypub/tests/processor.rs` | adapter-level tests |
| `store/tests/storage_invariants.rs` | one author per pointer |
| `server/tests/federation_flows.rs` | the spec's A1 tests; harness gains `mallory`, real root ACLs, and `state` |

---

### Task 1: The processor refuses foreign ids

**Files:**
- Modify: `adapters/activitypub/src/processor.rs:41-54` (`ProcessError` and its `Display`), `:76-87` (`process`), plus two new functions after `object_id` (`:176-183`), plus the unit test module (`:204-245`)
- Modify: `server/src/outbox.rs:199-208` (instance delivery in `deliver`) and `:304-306` (`deliver_locally`), so refusals are logged at `warn`
- Test: `adapters/activitypub/tests/processor.rs`

- [ ] **Step 1: Write the failing tests**

In `adapters/activitypub/src/processor.rs`, add this to `mod tests` (after `a_post_addressed_only_to_followers_is_not_public`):

```rust
    #[test]
    fn origin_is_scheme_host_and_port() {
        let actor = "https://alice.brolly.test/actor";
        assert!(same_origin("https://alice.brolly.test/~/notes/1", actor));
        assert!(
            same_origin("https://alice.brolly.test:443/~/notes/1", actor),
            "the default port is the port"
        );
        assert!(
            same_origin("https://ALICE.brolly.test/~/notes/1", actor),
            "hosts compare case-insensitively"
        );

        assert!(!same_origin("https://alice.brolly.test:8443/x", actor), "port");
        assert!(!same_origin("http://alice.brolly.test/x", actor), "scheme");
        assert!(!same_origin("https://bob.brolly.test/x", actor), "host");
        assert!(!same_origin("https://alice.brolly.test.evil/x", actor), "host suffix");
    }

    #[test]
    fn an_unparseable_or_opaque_iri_has_no_origin_in_common() {
        let actor = "https://alice.brolly.test/actor";
        assert!(!same_origin("not a url", actor));
        assert!(!same_origin(actor, ""));
        assert!(!same_origin("", ""));
        // An opaque origin equals nothing, not even itself.
        assert!(!same_origin("urn:example:a", "urn:example:a"));
    }
```

In `adapters/activitypub/tests/processor.rs`, replace the imports (`:14-18`):

```rust
use brolly_activitypub::inbox;
use brolly_activitypub::processor::{self, ProcessError, Recipient};
use brolly_store::{Store, StoreManager, index};
use oxigraph::model::{GraphName, GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Term};
use serde_json::{Value, json};
```

Add a constant after `ACTIVITY` (`:24`):

```rust
const ALICE_ACL: &str = "https://alice.brolly.test/~/.acl";
```

Add two helpers after `literals` (`:49-59`):

```rust
/// Put one quad in `name`, standing in for a resource someone would attack.
fn seed(store: &Store, name: &str) {
    brolly_store::insert_quads(
        store,
        &[Quad::new(
            NamedOrBlankNode::NamedNode(NamedNode::new_unchecked(format!("{name}#owner"))),
            NamedNode::new_unchecked("http://www.w3.org/ns/auth/acl#mode"),
            Term::NamedNode(NamedNode::new_unchecked(
                "http://www.w3.org/ns/auth/acl#Control",
            )),
            GraphName::NamedNode(NamedNode::new_unchecked(name)),
        )],
    )
    .unwrap();
}

/// Every quad in one graph, as sorted text, so "untouched" compares content
/// and not only size.
fn graph(store: &Store, name: &str) -> Vec<String> {
    let mut quads: Vec<String> = store
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(NamedNode::new_unchecked(name).as_ref())),
        )
        .filter_map(Result::ok)
        .map(|quad| quad.to_string())
        .collect();
    quads.sort();
    quads
}
```

Append a new section at the end of the file:

```rust
// --- origin -----------------------------------------------------------------

#[test]
fn an_embedded_object_on_another_origin_is_refused_and_writes_nothing() {
    // The hole: Bob's Create, carrying an object whose id is Alice's root ACL,
    // cleared that graph and wrote Bob's content into it.
    let (_dir, manager) = stores();
    let pod = manager.pod(uuid::Uuid::new_v4()).unwrap();
    seed(&pod, ALICE_ACL);
    let before = graph(&pod, ALICE_ACL);

    let mut attack = create(PUBLIC, "bob holds acl:Control now");
    attack["object"]["id"] = json!(ALICE_ACL);

    let delivered = processor::process(
        &pod,
        Recipient::Member { inbox: ALICE_INBOX },
        &attack,
        "2026-08-26T12:00:01Z",
    );
    assert!(
        matches!(delivered, Err(ProcessError::ForeignObject)),
        "got {delivered:?}"
    );
    assert_eq!(graph(&pod, ALICE_ACL), before, "the ACL graph was rewritten");
    assert!(
        inbox::members(&pod, ALICE_INBOX).is_empty(),
        "a refused activity must not be delivered at all"
    );

    let indexed = processor::process(
        manager.instance(),
        Recipient::Instance,
        &attack,
        "2026-08-26T12:00:01Z",
    );
    assert!(
        matches!(indexed, Err(ProcessError::ForeignObject)),
        "got {indexed:?}"
    );
    assert_eq!(index::count_notes(manager.instance()).unwrap(), 0);
}

#[test]
fn an_activity_whose_own_id_is_on_another_origin_is_refused() {
    let (_dir, manager) = stores();
    let pod = manager.pod(uuid::Uuid::new_v4()).unwrap();
    seed(&pod, ALICE_ACL);
    let before = graph(&pod, ALICE_ACL);

    let mut attack = create(PUBLIC, "hello");
    attack["id"] = json!(ALICE_ACL);

    let result = processor::process(
        &pod,
        Recipient::Member { inbox: ALICE_INBOX },
        &attack,
        "2026-08-26T12:00:01Z",
    );
    assert!(
        matches!(result, Err(ProcessError::ForeignObject)),
        "got {result:?}"
    );
    assert_eq!(graph(&pod, ALICE_ACL), before);
}

#[test]
fn an_activity_without_an_actor_is_refused() {
    // With no actor there is no origin to check against, so nothing is owned.
    let (_dir, manager) = stores();
    let pod = manager.pod(uuid::Uuid::new_v4()).unwrap();

    let mut anonymous = create(PUBLIC, "hello");
    anonymous.as_object_mut().unwrap().remove("actor");

    let result = processor::process(
        &pod,
        Recipient::Member { inbox: ALICE_INBOX },
        &anonymous,
        "2026-08-26T12:00:01Z",
    );
    assert!(
        matches!(result, Err(ProcessError::ForeignObject)),
        "got {result:?}"
    );
}

#[test]
fn a_reference_may_name_anyone() {
    // A Like or a Follow names another actor's IRI by definition. Only embedded
    // objects are held to the actor's origin.
    let (_dir, manager) = stores();
    let pod = manager.pod(uuid::Uuid::new_v4()).unwrap();

    for activity in [
        json!({
            "type": "Like",
            "id": "https://bob.brolly.test/~/activities/1",
            "actor": BOB_ACTOR,
            "object": "https://alice.brolly.test/~/notes/1",
        }),
        json!({
            "type": "Follow",
            "id": "https://bob.brolly.test/~/activities/2",
            "actor": BOB_ACTOR,
            "object": "https://alice.brolly.test/actor",
        }),
    ] {
        processor::process(
            &pod,
            Recipient::Member { inbox: ALICE_INBOX },
            &activity,
            "2026-08-26T12:00:01Z",
        )
        .expect("a reference is not a foreign object");
    }

    assert_eq!(inbox::members(&pod, ALICE_INBOX).len(), 2);
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p brolly-activitypub`
Expected: FAIL to compile. `error[E0599]: no variant or associated item named 'ForeignObject'` in `tests/processor.rs`, and `error[E0425]: cannot find function 'same_origin'` in `src/processor.rs`.

- [ ] **Step 3: Implement**

In `adapters/activitypub/src/processor.rs`, replace `ProcessError` and its `Display` (`:41-54`):

```rust
#[derive(Debug)]
pub enum ProcessError {
    Inbox(InboxError),
    Store(String),
    /// The activity's own id, or the id of an object embedded in it, isn't on
    /// its actor's origin. Delivering it would let one actor write a graph
    /// another actor owns.
    ForeignObject,
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessError::Inbox(e) => write!(f, "{e}"),
            ProcessError::Store(e) => write!(f, "storage: {e}"),
            ProcessError::ForeignObject => {
                write!(f, "activity names a graph its actor does not own")
            }
        }
    }
}
```

Replace `process` (`:76-87`):

```rust
/// Handle one delivered activity.
///
/// Before anything is written, the activity is refused with
/// [`ProcessError::ForeignObject`] if its own id, or the id of an object
/// embedded in it, isn't on its actor's origin. A string `object` is a
/// reference and may name anyone's IRI: that is what a `Like` or a `Follow` is.
///
/// This is where every recipient's copy arrives, whether from local delivery
/// or, once federation is on, from another server (ADR 0016).
pub fn process(
    store: &Store,
    recipient: Recipient<'_>,
    activity: &Value,
    received_at: &str,
) -> Result<(), ProcessError> {
    owning_actor(activity)?;
    match recipient {
        Recipient::Member { inbox } => process_for_member(store, inbox, activity, received_at),
        Recipient::Instance => process_for_instance(store, activity),
    }
}
```

Add these two functions directly after `object_id` (`:176-183`):

```rust
/// The activity's actor, provided every graph the activity would write is on
/// that actor's origin.
///
/// Strict on shape: no string `actor`, no string `id`, or an embedded object
/// whose `id` isn't a string, all refuse. Each of them leaves nothing to check
/// ownership against.
fn owning_actor(activity: &Value) -> Result<&str, ProcessError> {
    let actor = activity["actor"]
        .as_str()
        .ok_or(ProcessError::ForeignObject)?;
    let own_id = activity["id"]
        .as_str()
        .is_some_and(|id| same_origin(id, actor));
    let own_object = match activity.get("object") {
        Some(object @ Value::Object(_)) => object
            .get("id")
            .is_none_or(|id| id.as_str().is_some_and(|id| same_origin(id, actor))),
        _ => true,
    };
    if own_id && own_object {
        Ok(actor)
    } else {
        Err(ProcessError::ForeignObject)
    }
}

/// Do two IRIs share an origin: scheme, host and port?
///
/// False if either doesn't parse, or has an opaque origin (`urn:` and the
/// like). Nobody owns an origin that can't be compared.
fn same_origin(a: &str, b: &str) -> bool {
    match (url::Url::parse(a), url::Url::parse(b)) {
        (Ok(a), Ok(b)) => {
            let origin = a.origin();
            origin.is_tuple() && origin == b.origin()
        }
        _ => false,
    }
}
```

In `server/src/outbox.rs`, change the processor import (`:19`):

```rust
use brolly_activitypub::processor::{self, ProcessError, Recipient};
```

Replace the instance delivery at the end of `deliver` (`:199-208`):

```rust
    // The instance is a recipient like any other (D4), and its processor writes
    // the pointer row. This is the only way anything reaches the public index.
    match processor::process(
        state.stores.instance(),
        Recipient::Instance,
        activity,
        &received,
    ) {
        Ok(()) => {}
        Err(e @ ProcessError::ForeignObject) => tracing::warn!(error = %e, "indexing refused"),
        Err(e) => tracing::error!(error = %e, "indexing failed"),
    }
```

Replace the last statement of `deliver_locally` (`:304-306`):

```rust
    // A refusal isn't a failure: the activity named a graph its actor doesn't
    // own. Delivery to every other recipient carries on either way.
    match processor::process(&pod, Recipient::Member { inbox }, activity, received) {
        Ok(()) => {}
        Err(e @ ProcessError::ForeignObject) => {
            tracing::warn!(error = %e, %inbox, "local delivery refused");
        }
        Err(e) => tracing::error!(error = %e, %inbox, "local delivery failed"),
    }
```

- [ ] **Step 4: Run it and watch it pass**

Run: `cargo test -p brolly-activitypub`
Expected: PASS, including every existing test in `tests/processor.rs`. They all use ids on Bob's origin, and `an_announce_is_indexed_like_a_create` names Carol's note only by string.

- [ ] **Step 5: Gates**

```bash
cargo fmt --all
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

- [ ] **Step 6: Don't commit**

A1 is one commit (spec, Rollout 1). Carry on to Task 2 with the tree dirty.

---

### Task 2: A `Delete` removes only what delivery embedded, from inbox and outbox

**Files:**
- Modify: `adapters/activitypub/src/processor.rs:32-39` (`Recipient`), `process` (as left by Task 1), `:89-110` (`process_for_member`), `:112-118` (`references`, which is deleted)
- Modify: `server/src/outbox.rs:159-166` (author's `Delete` copy in `deliver`) and `deliver_locally` (as left by Task 1)
- Test: `adapters/activitypub/tests/processor.rs`, `server/tests/federation_flows.rs`

- [ ] **Step 1: Write the failing tests**

**Adapter.** In `adapters/activitypub/tests/processor.rs`, first give every existing `Recipient::Member` literal its outbox. The file names only Alice's inbox:

```bash
sed -i '' 's/Recipient::Member { inbox: ALICE_INBOX }/Recipient::Member { inbox: ALICE_INBOX, outbox: ALICE_OUTBOX }/g' adapters/activitypub/tests/processor.rs
```

Add constants after `ALICE_ACL`:

```rust
const ALICE_OUTBOX: &str = "https://alice.brolly.test/outbox";
const BOB_INBOX: &str = "https://bob.brolly.test/inbox";
const BOB_OUTBOX: &str = "https://bob.brolly.test/outbox";
const BOB_ACL: &str = "https://bob.brolly.test/~/.acl";
```

Append to the `// --- deletion ---` section (after `a_delete_for_something_we_never_had_is_not_an_error`):

```rust
#[test]
fn a_delete_of_a_graph_on_another_origin_removes_nothing() {
    let (_dir, manager) = stores();
    let pod = manager.pod(uuid::Uuid::new_v4()).unwrap();
    seed(&pod, ALICE_ACL);
    let before = graph(&pod, ALICE_ACL);

    processor::process(
        &pod,
        Recipient::Member { inbox: ALICE_INBOX, outbox: ALICE_OUTBOX },
        &json!({
            "type": "Delete",
            "id": "https://bob.brolly.test/~/activities/9",
            "actor": BOB_ACTOR,
            "object": ALICE_ACL,
        }),
        "2026-08-26T12:01:00Z",
    )
    .unwrap();

    assert_eq!(graph(&pod, ALICE_ACL), before, "Bob's Delete cleared Alice's ACL");
}

#[test]
fn a_delete_removes_only_what_arrived_embedded() {
    // Bob's own pod. Origin alone would let him clear his own ACL through
    // delivery without WAC ever seeing the request.
    let (_dir, manager) = stores();
    let pod = manager.pod(uuid::Uuid::new_v4()).unwrap();
    seed(&pod, BOB_ACL);
    let before = graph(&pod, BOB_ACL);

    // Named, not embedded: a string object is a graph delivery never wrote.
    inbox::deliver(
        &pod,
        BOB_OUTBOX,
        &json!({
            "type": "Create",
            "id": "https://bob.brolly.test/~/activities/1",
            "actor": BOB_ACTOR,
            "to": [PUBLIC],
            "object": BOB_ACL,
        }),
        "2026-08-26T12:00:00Z",
    )
    .unwrap();

    processor::process(
        &pod,
        Recipient::Member { inbox: BOB_INBOX, outbox: BOB_OUTBOX },
        &json!({
            "type": "Delete",
            "id": "https://bob.brolly.test/~/activities/2",
            "actor": BOB_ACTOR,
            "object": BOB_ACL,
        }),
        "2026-08-26T12:01:00Z",
    )
    .unwrap();

    assert_eq!(graph(&pod, BOB_ACL), before, "a Delete reached an LDP resource");
}

#[test]
fn a_delete_also_clears_the_authors_outbox_copy() {
    let (_dir, manager) = stores();
    let pod = manager.pod(uuid::Uuid::new_v4()).unwrap();

    // Stored the way outbox::deliver stores the author's copy: straight into
    // the outbox, not through `process`.
    inbox::deliver(
        &pod,
        BOB_OUTBOX,
        &create(PUBLIC, "regrettable"),
        "2026-08-26T12:00:00Z",
    )
    .unwrap();

    processor::process(
        &pod,
        Recipient::Member { inbox: BOB_INBOX, outbox: BOB_OUTBOX },
        &json!({
            "type": "Delete",
            "id": "https://bob.brolly.test/~/activities/2",
            "actor": BOB_ACTOR,
            "object": NOTE,
        }),
        "2026-08-26T12:01:00Z",
    )
    .unwrap();

    assert!(inbox::read_activity(&pod, NOTE).is_none(), "the note survived");
    assert!(
        inbox::read_activity(&pod, ACTIVITY).is_none(),
        "the Create that carried it survived"
    );
    assert!(
        inbox::members(&pod, BOB_OUTBOX).is_empty(),
        "the outbox still lists a deleted post"
    );
}
```

**Server.** `server/tests/federation_flows.rs` needs a third member, and real
root ACLs. Today's harness only calls `storage::init_storage_root`, so there is
no ACL to protect.

Delete the import `use brolly_solid::storage;` (`:14`).

In `harness()` (`:40-48`), replace the member loop:

```rust
    let mut ids = std::collections::HashMap::new();
    for name in ["alice", "bob", "mallory"] {
        let user = db::create_user(&db.pool, name, None, PASSWORD, "member")
            .await
            .unwrap();
        let pod = stores.pod(user.id).unwrap();
        // The real provisioning, so each member has the root ACL an attack
        // would aim at.
        brolly_server::provision::pod(&pod, name, BASE).unwrap();
        ids.insert(name.to_string(), user.id);
    }
```

Add these to `impl Harness`, after `index_count` (`:147-149`):

```rust
    /// Every quad in one graph of a member's pod, as text, so "left untouched"
    /// compares content and not only size.
    fn graph(&self, username: &str, graph: &str) -> std::collections::BTreeSet<String> {
        self.pod(username)
            .quads_for_pattern(
                None,
                None,
                None,
                Some(oxigraph::model::GraphNameRef::NamedNode(
                    NamedNode::new_unchecked(graph).as_ref(),
                )),
            )
            .filter_map(Result::ok)
            .map(|quad| quad.to_string())
            .collect()
    }

    /// GET a path in a member's pod with a session, for "can she still read her
    /// own storage".
    async fn get_status(&self, username: &str, cookie: &str, path: &str) -> StatusCode {
        self.router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .header(header::HOST, format!("{username}.{BASE}"))
                    .header(header::ACCEPT, "text/turtle")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }
```

Add free helpers after `inbox_of` (`:156-158`):

```rust
fn outbox_of(username: &str) -> String {
    format!("https://{username}.{BASE}/outbox")
}

fn acl_of(username: &str) -> String {
    format!("https://{username}.{BASE}/~/.acl")
}
```

Append a new section at the end of the file:

```rust
// --- an activity only touches graphs its actor owns (stage 0, A1) -----------

#[tokio::test]
async fn a_delete_naming_another_members_acl_leaves_it_alone() {
    let h = harness().await;
    let alice = h.login("alice").await;
    let mallory = h.login("mallory").await;
    let before = h.graph("alice", &acl_of("alice"));
    assert!(!before.is_empty(), "setup: alice has a root ACL");
    assert_eq!(h.get_status("alice", &alice, "/~/").await, StatusCode::OK, "setup");

    let (status, body) = h
        .publish(
            "mallory",
            &mallory,
            &json!({"type": "Delete", "object": acl_of("alice")}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    assert_eq!(
        h.graph("alice", &acl_of("alice")),
        before,
        "Mallory's Delete cleared Alice's ACL"
    );
    assert_eq!(
        h.get_status("alice", &alice, "/~/").await,
        StatusCode::OK,
        "Alice is locked out of her own storage"
    );
}

#[tokio::test]
async fn a_delete_of_your_own_note_removes_every_copy() {
    let h = harness().await;
    let alice = h.login("alice").await;
    let mallory = h.login("mallory").await;
    h.publish(
        "alice",
        &alice,
        &json!({"type": "Follow", "object": actor("mallory")}),
    )
    .await;

    let (_, created) = h
        .publish(
            "mallory",
            &mallory,
            &json!({"type": "Note", "content": "mine to take back", "to": [PUBLIC]}),
        )
        .await;
    let note = created["object"]["id"].as_str().unwrap().to_string();
    let create = created["id"].as_str().unwrap().to_string();

    // Setup: every copy exists, or the assertions below prove nothing.
    assert!(inbox::read_activity(&h.pod("alice"), &note).is_some());
    assert!(inbox::read_activity(&h.pod("mallory"), &note).is_some());
    assert_eq!(
        inbox::members(&h.pod("mallory"), &outbox_of("mallory")),
        vec![create.clone()]
    );
    assert_eq!(h.index_count(), 1);

    let (status, _) = h
        .publish(
            "mallory",
            &mallory,
            &json!({"type": "Delete", "object": note, "to": [PUBLIC]}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    assert!(
        inbox::read_activity(&h.pod("alice"), &note).is_none(),
        "the follower's copy survived"
    );
    assert!(
        inbox::timeline(&h.pod("alice"), &inbox_of("alice"), &["Create"], 10, None).is_empty(),
        "a deleted post left a hole in the follower's timeline"
    );
    assert!(
        inbox::read_activity(&h.pod("mallory"), &note).is_none(),
        "the author's own note survived"
    );
    assert!(
        inbox::read_activity(&h.pod("mallory"), &create).is_none(),
        "the author's Create survived"
    );
    assert!(
        inbox::members(&h.pod("mallory"), &outbox_of("mallory")).is_empty(),
        "the author's outbox still lists the deleted post"
    );
    assert_eq!(h.index_count(), 0, "the public timeline still shows it");
}

#[tokio::test]
async fn an_owner_cannot_delete_their_own_acl_through_the_outbox() {
    let h = harness().await;
    let alice = h.login("alice").await;
    let before = h.graph("alice", &acl_of("alice"));
    assert!(!before.is_empty(), "setup: alice has a root ACL");

    // Straight at it.
    h.publish(
        "alice",
        &alice,
        &json!({"type": "Delete", "object": acl_of("alice")}),
    )
    .await;
    assert_eq!(
        h.graph("alice", &acl_of("alice")),
        before,
        "a Delete through the outbox cleared an LDP resource without WAC"
    );

    // And after naming it in a Create first, so a stored activity mentions it.
    let (status, body) = h
        .publish(
            "alice",
            &alice,
            &json!({"type": "Create", "object": acl_of("alice"), "to": [PUBLIC]}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    h.publish(
        "alice",
        &alice,
        &json!({"type": "Delete", "object": acl_of("alice")}),
    )
    .await;

    assert_eq!(
        h.graph("alice", &acl_of("alice")),
        before,
        "a Create naming the ACL by string made it deletable"
    );
    assert_eq!(h.get_status("alice", &alice, "/~/").await, StatusCode::OK);
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p brolly-activitypub --test processor`
Expected: FAIL to compile. `error[E0026]: variant 'Recipient::Member' does not have a field named 'outbox'`.

Run: `cargo test -p brolly-server --test federation_flows -- a_delete_naming_another_members_acl a_delete_of_your_own_note an_owner_cannot_delete`
Expected: all three FAIL. The first two on "cleared Alice's ACL" or "cleared an LDP resource without WAC", because `process_for_member` calls `inbox::remove(store, inbox, target)` unconditionally. The third on "the author's outbox still lists the deleted post", because the author's copy is swept from the inbox only.

- [ ] **Step 3: Implement**

In `adapters/activitypub/src/processor.rs`, replace `Recipient` (`:32-39`):

```rust
/// Who a delivery is for.
pub enum Recipient<'a> {
    /// A member. Their inbox is their home timeline (D6), so it holds the
    /// activity itself. Their outbox holds their own published activities, and
    /// a `Delete` has to be able to clear a copy in either.
    Member { inbox: &'a str, outbox: &'a str },
    /// The instance actor (D4). Records a pointer, never content.
    Instance,
}
```

Replace the body of `process` (as left by Task 1):

```rust
    let actor = owning_actor(activity)?;
    match recipient {
        Recipient::Member { inbox, outbox } => {
            process_for_member(store, inbox, outbox, actor, activity, received_at)
        }
        Recipient::Instance => process_for_instance(store, activity),
    }
```

Replace `process_for_member` and `references` (`:89-118`) with:

```rust
fn process_for_member(
    store: &Store,
    inbox: &str,
    outbox: &str,
    actor: &str,
    activity: &Value,
    received_at: &str,
) -> Result<(), ProcessError> {
    if activity["type"] == "Delete" {
        // Remove only what delivery put there: a graph on the actor's origin
        // that arrived as the embedded object of one of the actor's activities,
        // in this pod's inbox (a recipient's copy) or outbox (the author's own).
        //
        // Origin alone isn't enough. The owner's pod receives the owner's own
        // activities, so a Delete naming their `/~/.acl` would pass it and clear
        // the ACL without WAC ever seeing the request. An LDP resource is never
        // the embedded object of a delivered activity, so this can't reach one.
        if let Some(target) = object_id(activity)
            && same_origin(target, actor)
        {
            let mut carried = false;
            for collection in [inbox, outbox] {
                for carrier in carriers(store, collection, actor, target) {
                    inbox::remove(store, collection, &carrier)?;
                    carried = true;
                }
            }
            if carried {
                inbox::remove(store, inbox, target)?;
            }
        }
        return Ok(());
    }

    inbox::deliver(store, inbox, activity, received_at)?;
    Ok(())
}

/// The actor's activities in `collection` that carried `target` in as their
/// embedded object.
///
/// Embedded, not merely named. A `Create` whose `object` is a plain string IRI
/// names a graph delivery never wrote, so it's no evidence the graph is
/// delivery's to remove. That's why this doesn't use [`object_id`], which
/// treats the two alike.
fn carriers(store: &Store, collection: &str, actor: &str, target: &str) -> Vec<String> {
    inbox::members(store, collection)
        .into_iter()
        .filter(|member| same_origin(member, actor))
        .filter(|member| {
            inbox::read_activity(store, member).is_some_and(|stored| {
                stored["object"].is_object() && stored["object"]["id"].as_str() == Some(target)
            })
        })
        .collect()
}
```

In `server/src/outbox.rs`, the author's `Delete` copy in `deliver` (`:159-166`) becomes:

```rust
        if let Err(e) = processor::process(
            &author_pod,
            Recipient::Member {
                inbox: &webid::inbox(&author.username, &state.base_domain),
                outbox: &webid::outbox(&author.username, &state.base_domain),
            },
            activity,
            &received,
        ) {
```

In `deliver_locally`, name the recipient's outbox. Replace the `match processor::process(&pod, Recipient::Member { inbox }, ...)` that Task 1 wrote with:

```rust
    // A refusal isn't a failure: the activity named a graph its actor doesn't
    // own. Delivery to every other recipient carries on either way.
    let outbox = webid::outbox(&user.username, &state.base_domain);
    match processor::process(
        &pod,
        Recipient::Member {
            inbox,
            outbox: &outbox,
        },
        activity,
        received,
    ) {
        Ok(()) => {}
        Err(e @ ProcessError::ForeignObject) => {
            tracing::warn!(error = %e, %inbox, "local delivery refused");
        }
        Err(e) => tracing::error!(error = %e, %inbox, "local delivery failed"),
    }
```

- [ ] **Step 4: Run it and watch it pass**

Run: `cargo test -p brolly-activitypub --test processor`
Expected: PASS, including `a_delete_removes_both_the_members_copy_and_the_pointer`. Its `Create` sits in Alice's inbox, on Bob's origin, with `NOTE` embedded.

Run: `cargo test -p brolly-server --test federation_flows`
Expected: PASS, including the existing `a_delete_reaches_everyone_the_post_did`.

- [ ] **Step 5: Gates**

```bash
cargo fmt --all
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

- [ ] **Step 6: Don't commit**

Still one commit. Carry on to Task 3.

---

### Task 3: The public index follows the same rule

**Files:**
- Modify: `adapters/activitypub/src/processor.rs` (`process` from Task 2; `process_for_instance`, originally `:120-136`)
- Modify: `store/src/index.rs:67-100` (`record_note`), plus a new private `has_author`
- Test: `adapters/activitypub/tests/processor.rs`, `store/tests/storage_invariants.rs`, `server/tests/federation_flows.rs`

- [ ] **Step 1: Write the failing tests**

**Store.** In `store/tests/storage_invariants.rs`, append after `the_index_can_count_its_notes_without_opening_a_pod`:

```rust
#[test]
fn a_pointer_keeps_the_author_it_was_first_recorded_with() {
    // An Announce records the pointer again, naming the announcer. A second
    // author triple would let anyone who boosts a post claim it.
    let (mgr, _dir) = manager();
    let pointer = |author: &str, published: &str| NotePointer {
        note: node("https://alice.brolly.id/~/notes/1"),
        author: node(author),
        published: published.to_string(),
        audience: node("https://www.w3.org/ns/activitystreams#Public"),
        in_reply_to: None,
    };

    index::record_note(
        mgr.instance(),
        &pointer("https://alice.brolly.id/actor", "2026-09-17T10:00:00Z"),
    )
    .unwrap();
    index::record_note(
        mgr.instance(),
        &pointer("https://mallory.brolly.id/actor", "2026-09-17T11:00:00Z"),
    )
    .unwrap();

    let authors: Vec<String> = mgr
        .instance()
        .quads_for_pattern(None, Some(node(index::P_AUTHOR).as_ref()), None, None)
        .filter_map(Result::ok)
        .map(|quad| quad.object.to_string())
        .collect();
    assert_eq!(authors, vec!["<https://alice.brolly.id/actor>".to_string()]);
    assert_eq!(index::count_notes(mgr.instance()).unwrap(), 1);
}
```

**Adapter.** In `adapters/activitypub/tests/processor.rs`, add a constant after `BOB_ACL`:

```rust
const MALLORY_ACTOR: &str = "https://mallory.brolly.test/actor";
```

Append to the `// --- the instance subscriber ---` section (after `a_reply_records_what_it_replies_to`):

```rust
#[test]
fn a_create_naming_someone_elses_note_is_not_indexed() {
    // A Create publishes the actor's own note. Indexing one that names somebody
    // else's would put it on the public timeline under the wrong name.
    let (_dir, manager) = stores();
    let index_store = manager.instance();

    processor::process(
        index_store,
        Recipient::Instance,
        &json!({
            "type": "Create",
            "id": "https://mallory.brolly.test/~/activities/1",
            "actor": MALLORY_ACTOR,
            "to": [PUBLIC],
            "object": NOTE,
        }),
        "2026-08-26T12:00:01Z",
    )
    .unwrap();

    assert_eq!(index::count_notes(index_store).unwrap(), 0);
}

#[test]
fn an_announce_of_an_indexed_note_keeps_its_author() {
    let (_dir, manager) = stores();
    let index_store = manager.instance();
    processor::process(
        index_store,
        Recipient::Instance,
        &create(PUBLIC, "hello"),
        "2026-08-26T12:00:01Z",
    )
    .unwrap();

    processor::process(
        index_store,
        Recipient::Instance,
        &json!({
            "type": "Announce",
            "id": "https://mallory.brolly.test/~/activities/1",
            "actor": MALLORY_ACTOR,
            "published": "2026-08-26T12:05:00Z",
            "to": [PUBLIC],
            "object": NOTE,
        }),
        "2026-08-26T12:05:01Z",
    )
    .unwrap();

    assert_eq!(
        index::count_notes(index_store).unwrap(),
        1,
        "the Announce added a second author"
    );
    let page = index::public_timeline(index_store, &NamedNode::new_unchecked(PUBLIC), 10, None)
        .expect("query");
    assert!(page.iter().all(|row| row.author.as_str() == BOB_ACTOR), "{page:?}");
}
```

Append to the `// --- deletion ---` section:

```rust
#[test]
fn a_delete_from_another_origin_leaves_the_pointer() {
    let (_dir, manager) = stores();
    let index_store = manager.instance();
    processor::process(
        index_store,
        Recipient::Instance,
        &create(PUBLIC, "hello"),
        "2026-08-26T12:00:01Z",
    )
    .unwrap();

    processor::process(
        index_store,
        Recipient::Instance,
        &json!({
            "type": "Delete",
            "id": "https://mallory.brolly.test/~/activities/2",
            "actor": MALLORY_ACTOR,
            "object": NOTE,
        }),
        "2026-08-26T12:01:00Z",
    )
    .unwrap();

    assert_eq!(
        index::count_notes(index_store).unwrap(),
        1,
        "Mallory took Bob's post off the public timeline"
    );
}
```

**Server.** Append to the A1 section of `server/tests/federation_flows.rs`:

```rust
#[tokio::test]
async fn another_member_cannot_take_over_a_post_on_the_public_timeline() {
    let h = harness().await;
    let alice = h.login("alice").await;
    let mallory = h.login("mallory").await;

    let (_, created) = h
        .publish(
            "alice",
            &alice,
            &json!({"type": "Note", "content": "hello", "to": [PUBLIC]}),
        )
        .await;
    let note = created["object"]["id"].as_str().unwrap().to_string();
    assert_eq!(h.index_count(), 1, "setup");

    h.publish(
        "mallory",
        &mallory,
        &json!({"type": "Delete", "object": note, "to": [PUBLIC]}),
    )
    .await;
    let page = index::public_timeline(
        h.stores.instance(),
        &NamedNode::new_unchecked(PUBLIC),
        10,
        None,
    )
    .unwrap();
    assert_eq!(page.len(), 1, "Mallory's Delete took Alice's post off the public timeline");
    assert_eq!(page[0].note.as_str(), note);

    h.publish(
        "mallory",
        &mallory,
        &json!({"type": "Announce", "object": note, "to": [PUBLIC]}),
    )
    .await;
    assert_eq!(
        h.index_count(),
        1,
        "Mallory's Announce added a second author to Alice's post"
    );
    let page = index::public_timeline(
        h.stores.instance(),
        &NamedNode::new_unchecked(PUBLIC),
        10,
        None,
    )
    .unwrap();
    assert!(
        page.iter().all(|row| row.author.as_str() == actor("alice")),
        "{page:?}"
    );
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p brolly-store --test storage_invariants a_pointer_keeps_the_author`
Expected: FAIL. `authors` has two entries.

Run: `cargo test -p brolly-activitypub --test processor`
Expected: `a_create_naming_someone_elses_note_is_not_indexed` fails (count 1), `an_announce_of_an_indexed_note_keeps_its_author` fails (count 2), and `a_delete_from_another_origin_leaves_the_pointer` fails (count 0).

Run: `cargo test -p brolly-server --test federation_flows another_member_cannot_take_over`
Expected: FAIL on "Mallory's Delete took Alice's post off the public timeline".

- [ ] **Step 3: Implement**

In `store/src/index.rs`, replace `record_note` (`:67-100`) and add `has_author` after it:

```rust
/// Record a note in the public timeline index.
///
/// The author is whoever first recorded the pointer, and it's never added a
/// second time. An `Announce` records a pointer to someone else's note, with
/// the announcer as actor. If that added an author triple, anyone who boosts a
/// post could claim it, and `count_notes` would count it twice.
pub fn record_note(store: &Store, pointer: &NotePointer) -> Result<(), WriteError> {
    let subject = NamedOrBlankNode::NamedNode(pointer.note.clone());
    let mut quads = vec![
        Quad::new(
            subject.clone(),
            iri(P_PUBLISHED),
            Term::Literal(Literal::new_simple_literal(&pointer.published)),
            graph(),
        ),
        Quad::new(
            subject.clone(),
            iri(P_AUDIENCE),
            Term::NamedNode(pointer.audience.clone()),
            graph(),
        ),
    ];
    if !has_author(store, &subject)? {
        quads.push(Quad::new(
            subject.clone(),
            iri(P_AUTHOR),
            Term::NamedNode(pointer.author.clone()),
            graph(),
        ));
    }
    if let Some(parent) = &pointer.in_reply_to {
        quads.push(Quad::new(
            subject,
            iri(P_IN_REPLY_TO),
            Term::NamedNode(parent.clone()),
            graph(),
        ));
    }
    insert_quads(store, &quads)?;
    Ok(())
}

/// Does this pointer already name an author?
fn has_author(store: &Store, subject: &NamedOrBlankNode) -> Result<bool, WriteError> {
    let first = store
        .quads_for_pattern(
            Some(subject.into()),
            Some(iri(P_AUTHOR).as_ref()),
            None,
            Some(GraphNameRef::NamedNode(iri(PUBLIC_TIMELINE).as_ref())),
        )
        .next()
        .transpose()
        .map_err(|e| WriteError::Store(StoreError::from(e)))?;
    Ok(first.is_some())
}
```

In `adapters/activitypub/src/processor.rs`, pass the actor through in `process`:

```rust
        Recipient::Instance => process_for_instance(store, actor, activity),
```

Replace `process_for_instance`:

```rust
fn process_for_instance(store: &Store, actor: &str, activity: &Value) -> Result<(), ProcessError> {
    match activity["type"].as_str() {
        // A Create publishes the actor's own note. Indexing one that names
        // somebody else's would put it on the public timeline under the wrong
        // name.
        Some("Create") => match object_id(activity) {
            Some(note) if same_origin(note, actor) => index_note(store, activity),
            _ => Ok(()),
        },
        // An Announce names someone else's note by definition. The pointer
        // keeps whoever created the note as its author (`index::record_note`).
        Some("Announce") => index_note(store, activity),
        Some("Delete") => {
            // A delete for something we never saw is normal, not an error: the
            // sender fans out to every follower's instance regardless of what
            // each one happened to store.
            //
            // Only the note's own origin can take it off the public timeline.
            if let Some(target) = object_id(activity)
                && same_origin(target, actor)
            {
                index::forget_note(store, &NamedNode::new_unchecked(target))?;
            }
            Ok(())
        }
        // A Like or a Follow is a notification, not a post. Neither belongs on
        // a public timeline.
        _ => Ok(()),
    }
}
```

- [ ] **Step 4: Run it and watch it pass**

Run: `cargo test -p brolly-store --test storage_invariants && cargo test -p brolly-activitypub --test processor && cargo test -p brolly-server --test federation_flows`
Expected: PASS, including `an_announce_is_indexed_like_a_create` and `a_delete_removes_both_the_members_copy_and_the_pointer`.

- [ ] **Step 5: Gates**

```bash
cargo fmt --all
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

- [ ] **Step 6: Don't commit**

Still one commit. Carry on to Task 4.

---

### Task 4: The server chooses embedded object ids

**Files:**
- Modify: `server/src/outbox.rs:27-74` (`as_activity`), plus a new `mint_note`
- Test: `server/src/outbox.rs` `mod tests` (`:317-393`), `server/tests/federation_flows.rs`

- [ ] **Step 1: Write the failing tests**

In `server/src/outbox.rs` `mod tests`, add after `the_actor_is_always_the_outbox_owner`:

```rust
    #[test]
    fn a_create_gets_a_minted_object_id_whatever_the_client_claimed() {
        let activity = as_activity(
            &json!({
                "type": "Create",
                "object": {"type": "Note", "id": "https://alice.brolly.test/~/.acl", "content": "hello"},
            }),
            ACTOR,
            BASE,
            "2026-08-26T12:00:00Z",
        );
        let id = activity["object"]["id"].as_str().expect("an object IRI");
        assert!(
            id.starts_with("https://alice.brolly.test/~/notes/"),
            "the client chose where content lives: {id}"
        );
        assert_eq!(
            activity["object"]["content"], "hello",
            "minting the id must keep the object"
        );
    }

    #[test]
    fn a_bare_object_claiming_an_id_gets_a_minted_one() {
        let activity = as_activity(
            &json!({"type": "Note", "id": "https://alice.brolly.test/~/.acl"}),
            ACTOR,
            BASE,
            "2026-08-26T12:00:00Z",
        );
        let id = activity["object"]["id"].as_str().expect("an object IRI");
        assert!(id.starts_with("https://alice.brolly.test/~/notes/"), "{id}");
    }

    #[test]
    fn any_other_activity_names_an_embedded_object_by_its_id() {
        for kind in ["Delete", "Undo", "Like", "Follow", "Announce"] {
            let activity = as_activity(
                &json!({
                    "type": kind,
                    "object": {"type": "Tombstone", "id": "https://bob.brolly.test/~/notes/1"},
                }),
                ACTOR,
                BASE,
                "2026-08-26T12:00:00Z",
            );
            assert_eq!(
                activity["object"], "https://bob.brolly.test/~/notes/1",
                "{kind} kept its embedded object"
            );
        }
    }

    #[test]
    fn an_embedded_object_with_no_id_is_left_for_deliver_to_refuse() {
        // There's nothing to name it by, so as_activity can't flatten it.
        let activity = as_activity(
            &json!({"type": "Like", "object": {"type": "Note"}}),
            ACTOR,
            BASE,
            "2026-08-26T12:00:00Z",
        );
        assert!(activity["object"].is_object());
    }
```

Append to the A1 section of `server/tests/federation_flows.rs`:

```rust
#[tokio::test]
async fn a_create_claiming_another_members_acl_gets_a_minted_id() {
    let h = harness().await;
    let alice = h.login("alice").await;
    let mallory = h.login("mallory").await;
    // Alice follows Mallory, so Mallory's posts are delivered into Alice's pod.
    h.publish(
        "alice",
        &alice,
        &json!({"type": "Follow", "object": actor("mallory")}),
    )
    .await;
    let before = h.graph("alice", &acl_of("alice"));
    assert!(!before.is_empty(), "setup: alice has a root ACL");

    let (status, created) = h
        .publish(
            "mallory",
            &mallory,
            &json!({
                "type": "Create",
                "to": [PUBLIC],
                "object": {
                    "type": "Note",
                    "id": acl_of("alice"),
                    "content": "mallory holds acl:Control now",
                },
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let note = created["object"]["id"].as_str().unwrap();
    assert!(
        note.starts_with(&format!("https://mallory.{BASE}/~/notes/")),
        "{note}"
    );
    assert!(
        inbox::read_activity(&h.pod("alice"), note).is_some(),
        "the post is still delivered, under the id the server chose"
    );

    assert_eq!(h.graph("alice", &acl_of("alice")), before);
    assert_eq!(h.get_status("alice", &alice, "/~/").await, StatusCode::OK);
}

#[tokio::test]
async fn an_owner_cannot_overwrite_their_own_acl_through_the_outbox() {
    let h = harness().await;
    let alice = h.login("alice").await;
    let before = h.graph("alice", &acl_of("alice"));
    assert!(!before.is_empty(), "setup: alice has a root ACL");

    let (status, created) = h
        .publish(
            "alice",
            &alice,
            &json!({
                "type": "Create",
                "to": [PUBLIC],
                "object": {"type": "Note", "id": acl_of("alice"), "content": "no WAC here"},
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let note = created["object"]["id"].as_str().unwrap();
    assert!(
        note.starts_with(&format!("https://alice.{BASE}/~/notes/")),
        "{note}"
    );

    assert_eq!(
        h.graph("alice", &acl_of("alice")),
        before,
        "publishing replaced an LDP resource without WAC"
    );
    assert_eq!(h.get_status("alice", &alice, "/~/").await, StatusCode::OK);
}

#[tokio::test]
async fn a_delete_of_an_embedded_tombstone_removes_the_note_everywhere() {
    let h = harness().await;
    let alice = h.login("alice").await;
    let bob = h.login("bob").await;
    h.publish(
        "bob",
        &bob,
        &json!({"type": "Follow", "object": actor("alice")}),
    )
    .await;

    let (_, created) = h
        .publish(
            "alice",
            &alice,
            &json!({"type": "Note", "content": "regrettable", "to": [PUBLIC]}),
        )
        .await;
    let note = created["object"]["id"].as_str().unwrap().to_string();

    let (status, delete) = h
        .publish(
            "alice",
            &alice,
            &json!({
                "type": "Delete",
                "object": {"type": "Tombstone", "id": note},
                "to": [PUBLIC],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{delete}");
    assert_eq!(delete["object"], json!(note), "the Tombstone is named by id");

    assert!(inbox::read_activity(&h.pod("bob"), &note).is_none());
    assert!(inbox::timeline(&h.pod("bob"), &inbox_of("bob"), &["Create"], 10, None).is_empty());
    assert!(inbox::read_activity(&h.pod("alice"), &note).is_none());
    assert!(inbox::members(&h.pod("alice"), &outbox_of("alice")).is_empty());
    assert_eq!(h.index_count(), 0);
}

#[tokio::test]
async fn an_undo_embedding_a_follow_names_it_by_id() {
    let h = harness().await;
    let alice = h.login("alice").await;
    let bob = h.login("bob").await;
    // Alice follows Bob, so Bob's activities reach her as a follower.
    h.publish(
        "alice",
        &alice,
        &json!({"type": "Follow", "object": actor("bob")}),
    )
    .await;
    let (_, follow) = h
        .publish(
            "bob",
            &bob,
            &json!({"type": "Follow", "object": actor("alice")}),
        )
        .await;
    let follow_id = follow["id"].as_str().unwrap().to_string();

    let (status, undo) = h
        .publish("bob", &bob, &json!({"type": "Undo", "object": follow}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{undo}");
    assert_eq!(undo["object"], json!(follow_id));

    let undos = inbox::timeline(&h.pod("alice"), &inbox_of("alice"), &["Undo"], 10, None);
    assert_eq!(undos.len(), 1, "the Undo did not reach Alice");
    let stored = inbox::read_activity(&h.pod("alice"), &undos[0].activity).unwrap();
    assert_eq!(stored["object"], json!(follow_id));
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p brolly-server --lib outbox`
Expected: `a_create_gets_a_minted_object_id_whatever_the_client_claimed` and `any_other_activity_names_an_embedded_object_by_its_id` FAIL. The other two already pass. They are guards: one on the bare-object path, one on the case `deliver` refuses in Task 5.

Run: `cargo test -p brolly-server --test federation_flows -- a_create_claiming an_owner_cannot_overwrite a_delete_of_an_embedded an_undo_embedding`
Expected: the first two FAIL on the `starts_with` assertion, because the client's id is kept. The last two FAIL on the `object` equality, because the embedded object is kept.

- [ ] **Step 3: Implement**

In `server/src/outbox.rs`, replace `as_activity` (`:27-74`) and add `mint_note` after it:

```rust
/// Wrap a bare object in the `Create` that publishes it.
///
/// A client may POST either an activity or a plain object; ActivityPub says the
/// server wraps the latter. Doing it here means every downstream stage sees an
/// activity and none of them has to ask.
///
/// **The server chooses embedded object ids.** A client-supplied id could name
/// one of the author's own LDP resources, such as `/~/.acl`. Delivery would then
/// clear and replace it, and a later `Delete` could remove it, all without WAC.
/// So a `Create`'s object gets a freshly minted note id. Any other activity's
/// embedded object becomes its `id` string, because there `object` names
/// something that already exists.
fn as_activity(body: &Value, actor: &str, base: &str, now: &str) -> Value {
    const ACTIVITY_TYPES: [&str; 6] = ["Create", "Follow", "Like", "Announce", "Delete", "Undo"];

    let kind = body["type"].as_str().unwrap_or("Note");
    let id = format!("{base}/~/activities/{}", uuid::Uuid::new_v4());

    if ACTIVITY_TYPES.contains(&kind) {
        let mut activity = body.clone();
        activity["id"] = json!(id);
        activity["actor"] = json!(actor);
        if activity.get("published").is_none() {
            activity["published"] = json!(now);
        }
        if let Some(object) = activity.get_mut("object").filter(|o| o.is_object()) {
            if kind == "Create" {
                object["id"] = json!(mint_note(base));
            } else if let Some(named) = object["id"].as_str().map(str::to_string) {
                *object = json!(named);
            }
            // An embedded object with no id is left as it is, and `deliver`
            // refuses it.
        }
        return activity;
    }

    // A bare object: give it its own IRI in the author's pod, then wrap it.
    let mut object = body.clone();
    object["id"] = json!(mint_note(base));
    object["attributedTo"] = json!(actor);
    if object.get("published").is_none() {
        object["published"] = json!(now);
    }

    json!({
        "type": "Create",
        "id": id,
        "actor": actor,
        "published": now,
        "to": body.get("to").cloned().unwrap_or_else(|| json!([])),
        "cc": body.get("cc").cloned().unwrap_or_else(|| json!([])),
        "object": object,
    })
}

/// A fresh note IRI in the author's pod.
///
/// A ULID, not a UUIDv4, and the reason lives one protocol over: ADR 0015
/// builds Mastodon's status ID out of this identifier, and Mastodon clients
/// are permitted to sort IDs lexically. A v4 local part would claim an
/// ordering it does not have.
fn mint_note(base: &str) -> String {
    format!(
        "{base}/~/notes/{}",
        brolly_mastodon::status_id::mint_note_id()
    )
}
```

- [ ] **Step 4: Run it and watch it pass**

Run: `cargo test -p brolly-server --lib outbox && cargo test -p brolly-server --test federation_flows`
Expected: PASS, including the existing `an_activity_is_left_as_one` (its objects are strings) and `a_follow_is_delivered_and_recorded_on_both_sides`.

- [ ] **Step 5: Gates**

```bash
cargo fmt --all
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

- [ ] **Step 6: Don't commit**

Still one commit. Carry on to Task 5.

---

### Task 5: `outbox::deliver` refuses what the server didn't mint, then commit A1

**Files:**
- Modify: `server/src/outbox.rs` (new `Refusal`, `DeliverError`, `authored`, `minted_under`; `publish`'s match at `:117-134`; `deliver` at `:137-211` becomes `pub`, checks first, and returns `DeliverError`)
- Modify: `server/src/mastodon_api.rs:811-813` (`create_status`)
- Test: `server/src/outbox.rs` `mod tests`, `server/tests/federation_flows.rs`

- [ ] **Step 1: Write the failing tests**

In `server/src/outbox.rs` `mod tests`, add:

```rust
    fn activity_id(base: &str) -> String {
        format!("{base}/~/activities/{}", uuid::Uuid::new_v4())
    }

    fn note_id(base: &str) -> String {
        format!(
            "{base}/~/notes/{}",
            brolly_mastodon::status_id::mint_note_id()
        )
    }

    #[test]
    fn what_as_activity_produces_deliver_accepts() {
        for body in [
            json!({"type": "Note", "content": "hello"}),
            json!({"type": "Create", "object": {"type": "Note", "id": "https://alice.brolly.test/~/.acl"}}),
            json!({"type": "Create", "object": "https://alice.brolly.test/~/.acl"}),
            json!({"type": "Delete", "object": {"type": "Tombstone", "id": "https://alice.brolly.test/~/notes/1"}}),
            json!({"type": "Like", "object": "https://bob.brolly.test/~/notes/1"}),
        ] {
            let activity = as_activity(&body, ACTOR, BASE, "2026-08-26T12:00:00Z");
            assert_eq!(authored(&activity, BASE), Ok(()), "{activity}");
        }
    }

    #[test]
    fn deliver_refuses_an_activity_id_it_did_not_mint() {
        for id in [
            "https://alice.brolly.test/~/.acl".to_string(),
            activity_id("https://bob.brolly.test"),
            format!("{BASE}/~/activities/"),
            format!("{BASE}/~/activities/../.acl"),
            format!("{BASE}/~/activities/a/b"),
        ] {
            let activity = json!({"type": "Like", "id": id, "object": "https://bob.brolly.test/~/notes/1"});
            assert_eq!(authored(&activity, BASE), Err(Refusal::ActivityId), "{id}");
        }
        assert_eq!(
            authored(&json!({"type": "Like"}), BASE),
            Err(Refusal::ActivityId)
        );
    }

    #[test]
    fn deliver_refuses_a_create_whose_object_id_it_did_not_mint() {
        for object in [
            json!({"type": "Note", "id": "https://alice.brolly.test/~/.acl"}),
            json!({"type": "Note", "id": note_id("https://bob.brolly.test")}),
            json!({"type": "Note", "id": format!("{BASE}/~/notes/not-a-ulid")}),
            json!({"type": "Note"}),
        ] {
            let activity = json!({"type": "Create", "id": activity_id(BASE), "object": object});
            assert_eq!(authored(&activity, BASE), Err(Refusal::ObjectId), "{object}");
        }
    }

    #[test]
    fn deliver_refuses_any_other_activity_that_embeds_its_object() {
        for kind in ["Delete", "Undo", "Like", "Follow", "Announce"] {
            let activity = json!({"type": kind, "id": activity_id(BASE), "object": {"id": note_id(BASE)}});
            assert_eq!(
                authored(&activity, BASE),
                Err(Refusal::EmbeddedObject),
                "{kind}"
            );
        }
    }
```

In `server/tests/federation_flows.rs`, extend the imports (`:11-13`):

```rust
use brolly_activitypub::processor::{self, ProcessError, Recipient};
use brolly_activitypub::{follows, inbox};
use brolly_identity::db;
use brolly_server::outbox::{DeliverError, Refusal, deliver};
use brolly_server::{AppState, app};
```

Give `Harness` the state (`:26-32`):

```rust
struct Harness {
    db: brolly_test_support::TestDb,
    _dir: tempfile::TempDir,
    router: axum::Router,
    /// The state the router was built with, so a test can call
    /// `outbox::deliver` directly, the way a future caller might.
    state: AppState,
    stores: std::sync::Arc<StoreManager>,
    ids: std::collections::HashMap<String, Uuid>,
}
```

In `harness()`, bind the `AppState { ... }` literal (`:51-75`, unchanged inside) to `let state = AppState { ... };`, then build the router and harness from it:

```rust
    let router = app(state.clone(), "server/static");

    Harness {
        db,
        _dir: dir,
        router,
        state,
        stores,
        ids,
    }
```

Add to `impl Harness`:

```rust
    async fn user(&self, username: &str) -> db::User {
        db::find_by_username(&self.db.pool, username)
            .await
            .unwrap()
            .unwrap()
    }
```

Append to the A1 section:

```rust
#[tokio::test]
async fn a_create_embedding_another_members_acl_is_refused_at_both_ends() {
    let h = harness().await;
    let alice = h.login("alice").await;
    // Alice follows Mallory, so Mallory's posts would be delivered to her.
    h.publish(
        "alice",
        &alice,
        &json!({"type": "Follow", "object": actor("mallory")}),
    )
    .await;
    let before = h.graph("alice", &acl_of("alice"));
    assert!(!before.is_empty(), "setup: alice has a root ACL");

    let attack = json!({
        "type": "Create",
        "id": format!("https://mallory.{BASE}/~/activities/{}", Uuid::new_v4()),
        "actor": actor("mallory"),
        "to": [PUBLIC],
        "object": {
            "type": "Note",
            "id": acl_of("alice"),
            "content": "mallory holds acl:Control now",
        },
    });

    // The outbox refuses it...
    let refused = deliver(&h.state, &h.user("mallory").await, &actor("mallory"), &attack).await;
    assert!(
        matches!(refused, Err(DeliverError::Refused(Refusal::ObjectId))),
        "got {refused:?}"
    );
    assert!(
        inbox::members(&h.pod("mallory"), &outbox_of("mallory")).is_empty(),
        "the author's copy was written before the refusal"
    );

    // ...and so does the processor, for the day it arrives from another server.
    let processed = processor::process(
        &h.pod("alice"),
        Recipient::Member {
            inbox: &inbox_of("alice"),
            outbox: &outbox_of("alice"),
        },
        &attack,
        "2026-09-17T12:00:00Z",
    );
    assert!(
        matches!(processed, Err(ProcessError::ForeignObject)),
        "got {processed:?}"
    );

    assert_eq!(h.graph("alice", &acl_of("alice")), before);
    assert_eq!(h.get_status("alice", &alice, "/~/").await, StatusCode::OK);
}

#[tokio::test]
async fn every_publishing_path_refuses_an_id_it_did_not_mint() {
    // POST /outbox and POST /api/v1/statuses both publish through
    // outbox::deliver, and both build a Create with an embedded note. Neither
    // can be made to carry a foreign id over HTTP any more, so this drives
    // deliver with each shape directly. The check has to hold for a caller that
    // forgets to mint.
    let h = harness().await;
    let alice = h.user("alice").await;
    let before = h.graph("alice", &acl_of("alice"));
    let activity_id = format!("https://alice.{BASE}/~/activities/{}", Uuid::new_v4());
    let followers = format!("https://alice.{BASE}/followers");

    let outbox_shaped = json!({
        "type": "Create",
        "id": activity_id,
        "actor": actor("alice"),
        "published": "2026-09-17T12:00:00Z",
        "to": [PUBLIC],
        "cc": [],
        "object": {
            "type": "Note",
            "id": acl_of("alice"),
            "attributedTo": actor("alice"),
            "content": "outbox",
        },
    });
    let compose_shaped = json!({
        "type": "Create",
        "id": activity_id,
        "actor": actor("alice"),
        "published": "2026-09-17T12:00:00Z",
        "to": [PUBLIC],
        "cc": [followers],
        "object": {
            "type": "Note",
            "id": format!(
                "https://bob.{BASE}/~/notes/{}",
                brolly_mastodon::status_id::mint_note_id()
            ),
            "attributedTo": actor("alice"),
            "content": "<p>compose</p>",
            "to": [PUBLIC],
            "cc": [followers],
            "sensitive": false,
        },
    });

    for activity in [&outbox_shaped, &compose_shaped] {
        let result = deliver(&h.state, &alice, &actor("alice"), activity).await;
        assert!(
            matches!(result, Err(DeliverError::Refused(Refusal::ObjectId))),
            "got {result:?} for {activity}"
        );
    }

    let mut foreign_activity = outbox_shaped.clone();
    foreign_activity["id"] = json!(acl_of("alice"));
    let result = deliver(&h.state, &alice, &actor("alice"), &foreign_activity).await;
    assert!(
        matches!(result, Err(DeliverError::Refused(Refusal::ActivityId))),
        "got {result:?}"
    );

    assert!(
        inbox::members(&h.pod("alice"), &outbox_of("alice")).is_empty(),
        "the author's copy was written before the refusal"
    );
    assert_eq!(h.graph("alice", &acl_of("alice")), before);
}

#[tokio::test]
async fn an_embedded_object_the_server_cannot_name_is_a_bad_request() {
    let h = harness().await;
    let bob = h.login("bob").await;

    let (status, body) = h
        .publish(
            "bob",
            &bob,
            &json!({"type": "Like", "object": {"type": "Note", "content": "no id"}}),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        inbox::members(&h.pod("bob"), &outbox_of("bob")).is_empty(),
        "a refused activity was stored"
    );
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p brolly-server --lib outbox`
Expected: FAIL to compile. `error[E0425]: cannot find function 'authored'` and `error[E0433]: ... undeclared type 'Refusal'`.

Run: `cargo test -p brolly-server --test federation_flows`
Expected: FAIL to compile. `error[E0432]: unresolved imports 'brolly_server::outbox::DeliverError', 'brolly_server::outbox::Refusal'`, and `error[E0603]: function 'deliver' is private`.

- [ ] **Step 3: Implement**

In `server/src/outbox.rs`, add the refusal types and checks after `now()` (`:76-80`):

```rust
/// Why [`deliver`] refused an activity. Each is the caller's fault, so each is
/// a `400`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The activity's id isn't one the server minted under the author's
    /// `/~/activities/`.
    ActivityId,
    /// A `Create`'s embedded object id isn't one the server minted under the
    /// author's `/~/notes/`.
    ObjectId,
    /// An activity other than `Create` still embeds its object.
    EmbeddedObject,
}

impl Refusal {
    pub fn describe(self) -> &'static str {
        match self {
            Refusal::ActivityId => "The activity id must be one this server minted.",
            Refusal::ObjectId => "A Create's object id must be one this server minted.",
            Refusal::EmbeddedObject => {
                "Only a Create may embed its object. Name it by its id instead."
            }
        }
    }
}

/// What went wrong publishing.
#[derive(Debug)]
pub enum DeliverError {
    /// Nothing was stored or sent.
    Refused(Refusal),
    /// Storing the author's copy failed.
    Failed,
}

/// Is `iri` exactly one minted segment directly under `prefix`?
///
/// One segment of letters, digits and hyphens. A UUID and a ULID are both that,
/// and `..`, `/` and an empty remainder are not.
fn minted_under(iri: &str, prefix: &str) -> bool {
    iri.strip_prefix(prefix).is_some_and(|rest| {
        !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// Does this activity name only graphs the server minted for its author?
///
/// `base` is the author's origin, `https://<username>.<base_domain>`. This is
/// what keeps the author's own copy, which `deliver` writes without going
/// through the processor, off their LDP resources.
fn authored(activity: &Value, base: &str) -> Result<(), Refusal> {
    let id = activity["id"].as_str().unwrap_or_default();
    if !minted_under(id, &format!("{base}/~/activities/")) {
        return Err(Refusal::ActivityId);
    }
    let embedded = activity.get("object").filter(|o| o.is_object());
    match (activity["type"].as_str(), embedded) {
        (Some("Create"), Some(object)) => {
            let note = object["id"].as_str().unwrap_or_default();
            let minted = note
                .strip_prefix(&format!("{base}/~/notes/"))
                .is_some_and(brolly_mastodon::status_id::is_note_id);
            if minted {
                Ok(())
            } else {
                Err(Refusal::ObjectId)
            }
        }
        (_, None) => Ok(()),
        (_, Some(_)) => Err(Refusal::EmbeddedObject),
    }
}
```

Replace the `match deliver(...)` in `publish` (`:117-134`):

```rust
    match deliver(&state, &caller, &actor, &activity).await {
        Ok(()) => (
            StatusCode::CREATED,
            [
                (
                    header::CONTENT_TYPE,
                    "application/activity+json".to_string(),
                ),
                (
                    header::LOCATION,
                    activity["id"].as_str().unwrap_or_default().to_string(),
                ),
            ],
            activity.to_string(),
        )
            .into_response(),
        Err(DeliverError::Refused(refusal)) => {
            (StatusCode::BAD_REQUEST, refusal.describe()).into_response()
        }
        Err(DeliverError::Failed) => server_error(),
    }
```

Replace the head of `deliver` (`:137-178`), from the doc comment through the author's-copy `if`/`else if`:

```rust
/// Publish an activity: store the author's copy, then fan out.
///
/// Exposed to the Mastodon composer so that `POST /api/v1/statuses` goes
/// through the *same* delivery path as `POST /outbox`. The predecessor had a
/// second fan-out for the Mastodon side that queried a table a migration had
/// dropped, and the error was swallowed — so statuses were delivered to nobody,
/// silently. One path, or the second one rots.
///
/// Refuses, before anything is stored, an activity naming a graph the server
/// didn't mint for its author (see [`authored`]). The author's copy is written
/// here directly and not through the processor, so this is the only check it
/// gets.
pub async fn deliver(
    state: &AppState,
    author: &User,
    actor: &str,
    activity: &Value,
) -> Result<(), DeliverError> {
    let base = format!("https://{}.{}", author.username, state.base_domain);
    authored(activity, &base).map_err(DeliverError::Refused)?;

    let received = now();
    let Ok(author_pod) = state.stores.pod(author.id) else {
        return Err(DeliverError::Failed);
    };

    // The author holds their own post — content lives in exactly one place (D2)
    // and this is it. A Delete removes rather than stores.
    if activity["type"] == "Delete" {
        if let Err(e) = processor::process(
            &author_pod,
            Recipient::Member {
                inbox: &webid::inbox(&author.username, &state.base_domain),
                outbox: &webid::outbox(&author.username, &state.base_domain),
            },
            activity,
            &received,
        ) {
            tracing::error!(error = %e, "removing the author's copy failed");
            return Err(DeliverError::Failed);
        }
    } else if let Err(e) = brolly_activitypub::inbox::deliver(
        &author_pod,
        &webid::outbox(&author.username, &state.base_domain),
        activity,
        &received,
    ) {
        tracing::error!(error = %e, "storing the author's copy failed");
        return Err(DeliverError::Failed);
    }
```

The rest of `deliver` (follow bookkeeping, fan-out, instance) is unchanged from Tasks 1–2.

In `server/src/mastodon_api.rs`, replace `:811-813` in `create_status`:

```rust
    match crate::outbox::deliver(&state, &user, &actor, &activity).await {
        Ok(()) => {}
        Err(crate::outbox::DeliverError::Refused(refusal)) => {
            return error(StatusCode::BAD_REQUEST, refusal.describe());
        }
        Err(crate::outbox::DeliverError::Failed) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong. Try again.",
            );
        }
    }
```

- [ ] **Step 4: Run it and watch it pass**

Run: `cargo test -p brolly-server --lib outbox && cargo test -p brolly-server --test federation_flows && cargo test -p brolly-server --test mastodon_compose`
Expected: PASS. `mastodon_compose` is the regression check that compose's own minted ids (`mastodon_api.rs:797-809`) satisfy `authored`: `a_content_warning_survives_being_posted` and the rest still get `200`.

- [ ] **Step 5: Gates**

```bash
cargo fmt --all
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

- [ ] **Step 6: Commit**

```bash
git add adapters/activitypub/src/processor.rs \
        adapters/activitypub/tests/processor.rs \
        store/src/index.rs \
        store/tests/storage_invariants.rs \
        server/src/outbox.rs \
        server/src/mastodon_api.rs \
        server/tests/federation_flows.rs
git commit -m "fix(activitypub): an activity only touches graphs its actor owns

Any member could overwrite or wipe any graph in another member's pod,
their ACL included. A Delete naming https://alice.<base>/~/.acl cleared
it through local delivery, and a Create embedding an object with that id
replaced it with the sender's content, all without WAC.

processor::process now refuses, with ForeignObject, an activity whose id
or embedded object id isn't on its actor's origin. A Delete removes a
graph only if it arrived as the embedded object of one of the actor's
own activities, in the pod's inbox or outbox, so the owner can't reach
their own LDP resources through the outbox either. The public index
follows the same rule, and a pointer's author is never added twice.

POST /outbox now mints every Create's object id and names any other
activity's object by id. outbox::deliver refuses, with a 400, anything
it didn't mint, which covers Mastodon compose too.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

Then verify from a clean checkout (see "Verify every commit from a clean checkout"):

```bash
rm -rf /tmp/verify && git worktree add --detach /tmp/verify HEAD
cd /tmp/verify && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings
cd - && git worktree remove /tmp/verify --force
```

Green there, or the commit isn't done. The first compile in a new worktree takes about three minutes, so run it in the background rather than skipping it.

---

### Notes for the reviewer

1. **One commit across five tasks.** Rollout item 1 ships A1 as a single commit, so Tasks 1–4 run the gates but don't commit, and only Task 5 commits and verifies from a clean checkout.
2. **"The outbox answers 400" for Mallory's `Create`.** The same spec also says `as_activity` overwrites any client-supplied embedded id. Over HTTP, then, Mallory's `Create` gets `201` with a minted id, and `a_create_claiming_another_members_acl_gets_a_minted_id` asserts that. The refusal is asserted by calling `outbox::deliver` directly: `a_create_embedding_another_members_acl_is_refused_at_both_ends`. The HTTP `400` path is exercised by a non-`Create` whose embedded object has no id, the one case `as_activity` can't normalise.
3. **`outbox::deliver` goes from `pub(crate)` to `pub`** and returns a typed `DeliverError { Refused(Refusal), Failed }` instead of `Response`. Without that, the integration tests can't call it "directly" as the spec asks. `Refusal::describe()` gives the `400` body.
4. **The Mastodon compose refusal can't be driven over HTTP**, because `create_status` mints both ids. It's covered by passing a compose-shaped activity to `deliver` directly (`every_publishing_path_refuses_an_id_it_did_not_mint`). The `Refused → 400` arm in `create_status` has no HTTP test. Its `Failed` arm now returns Mastodon's JSON error shape rather than the outbox's plain-text 500.
5. **The origin gate is strict about shape.** A missing or non-string `actor`, a missing `id`, or an embedded object whose `id` isn't a string all give `ForeignObject`. Before, `Recipient::Instance` accepted an activity with no `id`, and `Member` failed it with `InboxError::NoId`. An AS2 `actor` given as an object, not a string, is refused too. Federation will need to normalise that first.
6. **"Minted" is checked strictly.** An activity id must be one `[A-Za-z0-9-]+` segment directly under `/~/activities/`, and a `Create`'s note id must pass `status_id::is_note_id` directly under `/~/notes/`. The spec only says "under", but this also rules out `..`, nested paths and non-ULID note ids, none of which the server produces.
7. **The `Undo` test.** Once the object is flattened, `recipients` routes on the Follow's own IRI, which is on the *author's* origin. The Undo therefore goes to the author's followers and the author's own inbox, not to the Follow's target. That's no change: an embedded object reached followers only before this, too. The test makes Alice a follower of Bob, so "reaches its target" is observable. Routing an `Undo` to the undone activity's target is a follow-up, not part of A1.
8. **A `Delete` naming an activity IRI** (say, a `Like`'s id) no longer removes anything, because only embedded objects are removable. This follows the spec's rule, but it's a behaviour change.
9. **`record_note` skips only the author triple.** When the pointer exists, `published` and `audience` are still added, so an `Announce` of an indexed note adds a second `published` literal, and `public_timeline` may list that note twice. That's existing behaviour. The tests assert on `count_notes` (author triples) and on every row's author, not on page length. There's also a related gap the spec left "as today": an `Announce` that arrives *before* the note is indexed (for example, a boost of a followers-only note) records the announcer as author, and a later `Create` can't correct it.
10. **Federation harness.** It switches from `storage::init_storage_root` to `brolly_server::provision::pod`, so members have a real root ACL, and it adds `mallory`. `the_public_index_is_populated_only_by_delivery` now does its `ldp::put` against a pod whose ACL allows it, and its index assertion still holds.
11. **`Create` with a string `object`** is still accepted, delivered and, if public and same-origin, indexed. So Alice can put a pointer to her own `/~/.acl` IRI on the public timeline. Nothing is written or read around WAC, since the timeline only dereferences faithful records, but a follow-up may want to refuse string-object `Create`s.
12. **"References still work"** (a `Like` and a `Follow` naming another member) is covered by the new adapter test `a_reference_may_name_anyone` and by the existing HTTP tests `a_follow_is_delivered_and_recorded_on_both_sides` and `a_like_reaches_the_author`. No new HTTP test duplicates them.
13. **`same_origin` stays private** to `processor.rs`, as the spec names it. `outbox.rs` doesn't need it, because its checks are stricter prefix checks against the author's base.


## Chunk 2: ACL resources require Control (A2)

Implements spec section **A2** (`docs/specs/2026-09-17-security-fixes.md`) and
rollout item 2: `.acl` resources need `acl:Control` on the resource they govern,
they stop being container members, deleting a resource deletes its ACL, and
`brolly-admin acl-uncontain` removes the old containment triples.

**One commit.** The rollout lists A2 and `acl-uncontain` as one of six commits,
so Tasks 1–6 stage their work and Task 7 commits it all. Each task still runs
its own tests and the gates, so a broken step shows up in that task and not at
the end.

**Everything funnels through two private functions.** `check`
(`adapters/solid/src/ldp.rs:131-146`) and `granted_modes` (`:148-161`) are what
`read`, `put`, `append`, `may_write` and `delete` call, and `may_write` is what
`server/src/pod.rs::patch` (`:355`) calls. `authz/src/wac.rs` does not change
(decision S2).

**Paths vs IRIs.** `check` gets a *path* (`/~/shared/.acl`) plus `base`.
`effective_acl(store, base, path)` (`authz/src/wac.rs:111`) builds its candidates
from that path, so asking about `/~/shared/` looks at `/~/shared/.acl` first,
then `/~/.acl`, then `/.acl`. That is exactly "the governed resource's own ACL
or an ancestor's `acl:default`". `governed` only looks at the suffix, so it
works on a full IRI too, which `append` and `storage::uncontain_acls` rely on.

**The pod_http harness root ACL has no Control** (`server/tests/pod_http.rs:61-80`
grants Alice Read and Write only). The HTTP tests below give her Control on
`/~/shared/` in that container's own ACL rather than editing the shared harness.
Real pods get Control from `server::provision::pod` (`server/src/provision.rs:718-733`).

---

### Task 1: `governed`, the path rule

**Files:**
- Modify: `adapters/solid/src/ldp.rs`: add `governed` after `iri` (`:126-128`), and a `#[cfg(test)] mod tests` at the end of the file (after `:476`)

- [ ] **Step 1: Write the failing test**

Add at the end of `adapters/solid/src/ldp.rs`. The crate root already has
`#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]`
(`adapters/solid/src/lib.rs:10`).

```rust
#[cfg(test)]
mod tests {
    use super::governed;

    /// The table in spec A2, row for row.
    #[test]
    fn an_acl_governs_its_path_without_the_suffix() {
        assert_eq!(governed("/~/notes/.acl"), Some("/~/notes/"));
        assert_eq!(governed("/~/notes/first.acl"), Some("/~/notes/first"));
        // An ACL of an ACL is still guarded by Control on the thing at the
        // bottom, not by the ACL above it.
        assert_eq!(governed("/~/x.acl.acl"), Some("/~/x"));
    }

    #[test]
    fn other_paths_are_not_acl_resources() {
        assert_eq!(governed("/~/notes"), None);
        assert_eq!(governed("/~/x.aclx"), None);
    }

    #[test]
    fn a_full_iri_works_the_same_way() {
        assert_eq!(
            governed("https://alice.brolly.id/~/notes/.acl"),
            Some("https://alice.brolly.id/~/notes/")
        );
    }
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p brolly-solid --lib ldp::tests`
Expected: compile error, `cannot find function 'governed' in module 'super'`.

- [ ] **Step 3: Implement**

In `adapters/solid/src/ldp.rs`, directly after `fn iri` (`:126-128`):

```rust
/// The resource an ACL resource governs, or `None` if `path` is not one.
///
/// A path is an ACL resource when it ends in `.acl`. Every trailing `.acl`
/// comes off, so `/~/x.acl.acl` governs `/~/x`. Stopping after one would make
/// `/~/x.acl` the governed resource, and whoever holds Control over *that*
/// (which is anyone with Control over `/~/x`'s container, not over `/~/x`)
/// could reach it. Only the suffix is examined, so this works on a full IRI as
/// well as on a path.
pub fn governed(path: &str) -> Option<&str> {
    let mut resource = path.strip_suffix(".acl")?;
    while let Some(shorter) = resource.strip_suffix(".acl") {
        resource = shorter;
    }
    Some(resource)
}
```

- [ ] **Step 4: Run it and watch it pass**

Run: `cargo test -p brolly-solid --lib ldp::tests`
Expected: 3 passed. `governed` is `pub`, so clippy has no dead-code warning
for it before Task 2 uses it.

- [ ] **Step 5: Gates**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

- [ ] **Step 6: Stage, don't commit**

```bash
git add adapters/solid/src/ldp.rs
```

A2 is one commit (rollout item 2). Task 7 commits.

---

### Task 2: every mode on an ACL resource needs Control

**Files:**
- Modify: `adapters/solid/src/ldp.rs:130-161` (`check`, `granted_modes`)
- Create: `adapters/solid/tests/acl_control.rs`
- Modify: `server/tests/pod_http.rs`: append after `:694`

- [ ] **Step 1: Write the failing tests**

**Adapter level.** Create `adapters/solid/tests/acl_control.rs`. The harness copies
`pod()`, `n`, `t` and the subject constructors from
`adapters/solid/tests/ldp_conformance.rs:21-94`, because integration test files
can't share helpers without a `mod common` this crate doesn't have.

```rust
//! Stage 0, A2: an ACL resource is guarded by Control on the resource it
//! governs, never by the modes that resource hands out.
//!
//! `bob` holds Read and Write on everything under `/~/shared/` through
//! `acl:default`, and no Control. Before this fix that was enough to read the
//! container's ACL (learning who else has access), rewrite it (granting himself
//! Control), or delete it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_authz::AccessMode;
use brolly_identity::{Scope, Subject, Via};
use brolly_solid::ldp::{self, LdpError};
use brolly_solid::storage;
use brolly_store::{StoreManager, insert_quads};
use oxigraph::model::{GraphName, NamedNode, NamedOrBlankNode, Quad, Term};
use uuid::Uuid;

const BASE: &str = "https://alice.brolly.id";
const ROOT: &str = "https://alice.brolly.id/~/";
const ACL: &str = "http://www.w3.org/ns/auth/acl#";
const ALICE: &str = "https://alice.brolly.id/profile#me";
const BOB: &str = "https://bob.brolly.id/profile#me";
const CAROL: &str = "https://carol.brolly.id/profile#me";

const NOTE: &[u8] = br#"<> <https://example.org/title> "A note" ."#;

const ALL: [AccessMode; 4] = [
    AccessMode::Read,
    AccessMode::Write,
    AccessMode::Append,
    AccessMode::Control,
];

fn n(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

fn t(graph: &str, s: &str, p: &str, o: &str) -> Quad {
    Quad::new(
        NamedOrBlankNode::NamedNode(n(s)),
        n(p),
        Term::NamedNode(n(o)),
        GraphName::NamedNode(n(graph)),
    )
}

fn member(name: &str, webid: &str) -> Subject {
    Subject::local(
        Uuid::new_v4(),
        format!("did:plc:{name}"),
        webid.into(),
        Scope::parse("webid"),
        Via::SolidDpop,
    )
}

fn alice() -> Subject {
    member("alice", ALICE)
}

fn bob() -> Subject {
    member("bob", BOB)
}

fn carol() -> Subject {
    member("carol", CAROL)
}

/// A pod whose root ACL gives Alice Read, Write and Control over everything.
fn pod() -> (
    StoreManager,
    tempfile::TempDir,
    std::sync::Arc<oxigraph::store::Store>,
) {
    let dir = tempfile::tempdir().unwrap();
    let mgr = StoreManager::open(dir.path(), 4, 60).unwrap();
    let store = mgr.pod(Uuid::new_v4()).unwrap();
    storage::init_storage_root(&store, ROOT).unwrap();

    let g = format!("{ROOT}.acl");
    let a = format!("{g}#owner");
    insert_quads(
        &store,
        &[
            t(&g, &a, &format!("{ACL}default"), ROOT),
            t(&g, &a, &format!("{ACL}accessTo"), ROOT),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Control")),
            t(&g, &a, &format!("{ACL}agent"), ALICE),
        ],
    )
    .unwrap();
    (mgr, dir, store)
}

/// `pod()`, plus `/~/shared/.acl`: Alice controls the container, Bob may read
/// and write inside it through `acl:default`, and holds no Control.
///
/// Written straight into the store so the setup doesn't depend on the code
/// under test.
fn shared_pod() -> (
    StoreManager,
    tempfile::TempDir,
    std::sync::Arc<oxigraph::store::Store>,
) {
    let (mgr, dir, store) = pod();
    let shared = format!("{ROOT}shared/");
    let g = format!("{shared}.acl");
    let owner = format!("{g}#owner");
    let bob = format!("{g}#bob");
    insert_quads(
        &store,
        &[
            t(&g, &owner, &format!("{ACL}accessTo"), &shared),
            t(&g, &owner, &format!("{ACL}default"), &shared),
            t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Control")),
            t(&g, &owner, &format!("{ACL}agent"), ALICE),
            t(&g, &bob, &format!("{ACL}default"), &shared),
            t(&g, &bob, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &bob, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(&g, &bob, &format!("{ACL}agent"), BOB),
        ],
    )
    .unwrap();
    (mgr, dir, store)
}

/// An ACL document giving `agent` Read, Write and Control over `resource` and
/// everything under it.
fn acl_granting(agent: &str, resource: &str) -> String {
    format!(
        "@prefix acl: <{ACL}> .\n\
         <#grant> a acl:Authorization ;\n\
           acl:agent <{agent}> ;\n\
           acl:accessTo <{resource}> ;\n\
           acl:default <{resource}> ;\n\
           acl:mode acl:Read, acl:Write, acl:Control .\n"
    )
}

#[test]
fn bob_cannot_read_rewrite_or_delete_the_containers_acl() {
    let (_m, _d, store) = shared_pod();
    let takeover = acl_granting(BOB, &format!("{ROOT}shared/"));

    assert!(
        matches!(
            ldp::read(&store, None, BASE, "/~/shared/.acl", &bob(), None),
            Err(LdpError::NotFound)
        ),
        "inherited Read must not reveal who else has access"
    );
    assert!(matches!(
        ldp::put(
            &store,
            None,
            BASE,
            "/~/shared/.acl",
            &bob(),
            takeover.as_bytes(),
            "text/turtle",
            ROOT
        ),
        Err(LdpError::Forbidden)
    ));
    assert!(matches!(
        ldp::append(
            &store,
            None,
            BASE,
            "/~/shared/.acl",
            &bob(),
            takeover.as_bytes(),
            "text/turtle",
            ROOT
        ),
        Err(LdpError::Forbidden)
    ));
    assert!(
        !ldp::may_write(&store, BASE, "/~/shared/.acl", &bob()).unwrap(),
        "PATCH goes through may_write"
    );
    assert!(matches!(
        ldp::delete(&store, None, BASE, "/~/shared/.acl", &bob(), ROOT),
        Err(LdpError::Forbidden)
    ));

    // Nothing above landed: Bob still holds exactly what he was given.
    assert_eq!(
        ldp::granted_modes(&store, BASE, "/~/shared/doc", &bob()),
        vec![AccessMode::Read, AccessMode::Write, AccessMode::Append]
    );
}

#[test]
fn bob_cannot_reach_the_acls_of_what_he_can_write() {
    let (_m, _d, store) = shared_pod();
    // Alice creates both, so a refusal below means "refused", not "absent".
    for path in ["/~/shared/doc", "/~/shared/doc.acl.acl"] {
        ldp::put(&store, None, BASE, path, &alice(), NOTE, "text/turtle", ROOT).unwrap();
    }

    let takeover = acl_granting(BOB, &format!("{ROOT}shared/doc"));
    assert!(
        matches!(
            ldp::put(
                &store,
                None,
                BASE,
                "/~/shared/doc.acl",
                &bob(),
                takeover.as_bytes(),
                "text/turtle",
                ROOT
            ),
            Err(LdpError::Forbidden)
        ),
        "Write on a document must not let Bob create its ACL"
    );
    assert!(matches!(
        ldp::read(&store, None, BASE, "/~/shared/doc.acl.acl", &bob(), None),
        Err(LdpError::NotFound)
    ));
}

#[test]
fn bob_keeps_his_access_to_ordinary_resources() {
    let (_m, _d, store) = shared_pod();
    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/doc",
        &bob(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap();

    let out = ldp::read(&store, None, BASE, "/~/shared/doc", &bob(), None).unwrap();
    assert!(String::from_utf8(out.body).unwrap().contains("A note"));
    assert_eq!(
        out.granted,
        vec![AccessMode::Read, AccessMode::Write, AccessMode::Append]
    );
}

#[test]
fn the_owner_can_do_all_of_it() {
    let (_m, _d, store) = shared_pod();
    let doc = format!("{ROOT}shared/doc");

    assert!(ldp::read(&store, None, BASE, "/~/shared/.acl", &alice(), None).is_ok());
    assert!(ldp::may_write(&store, BASE, "/~/shared/.acl", &alice()).unwrap());

    ldp::put(&store, None, BASE, "/~/shared/doc", &alice(), NOTE, "text/turtle", ROOT).unwrap();
    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/doc.acl",
        &alice(),
        acl_granting(ALICE, &doc).as_bytes(),
        "text/turtle",
        ROOT,
    )
    .unwrap();
    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/doc.acl.acl",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap();
    assert!(ldp::read(&store, None, BASE, "/~/shared/doc.acl.acl", &alice(), None).is_ok());

    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/.acl",
        &alice(),
        acl_granting(ALICE, &format!("{ROOT}shared/")).as_bytes(),
        "text/turtle",
        ROOT,
    )
    .unwrap();
    ldp::delete(&store, None, BASE, "/~/shared/doc.acl", &alice(), ROOT).unwrap();
    ldp::delete(&store, None, BASE, "/~/shared/.acl", &alice(), ROOT).unwrap();
}

/// `WAC-Allow` on an ACL is all or nothing: Control on the governed resource
/// means every mode, and anything short of it means none.
#[test]
fn wac_allow_on_an_acl_is_all_or_nothing() {
    let (_m, _d, store) = shared_pod();

    // Carol holds Control on /~/shared/ and nothing else, which is still
    // enough to manage its ACL.
    let g = format!("{ROOT}shared/.acl");
    let c = format!("{g}#carol");
    insert_quads(
        &store,
        &[
            t(&g, &c, &format!("{ACL}accessTo"), &format!("{ROOT}shared/")),
            t(&g, &c, &format!("{ACL}mode"), &format!("{ACL}Control")),
            t(&g, &c, &format!("{ACL}agent"), CAROL),
        ],
    )
    .unwrap();

    let owner = ldp::read(&store, None, BASE, "/~/shared/.acl", &alice(), None).unwrap();
    assert_eq!(owner.granted, ALL.to_vec());

    let carol = ldp::read(&store, None, BASE, "/~/shared/.acl", &carol(), None).unwrap();
    assert_eq!(carol.granted, ALL.to_vec());

    assert!(ldp::granted_modes(&store, BASE, "/~/shared/.acl", &bob()).is_empty());
}
```

**HTTP level.** Append to `server/tests/pod_http.rs` after `:694`. It reuses
`Harness`, `harness()`, `n`, `t`, `ROOT`, `HOST` and `ACL` from the top of that
file. `send` (`:122-150`) always uses Alice's session, so there's a second
helper for Bob.

```rust
// --- ACL resources -------------------------------------------------------------

/// Another member with a live session, for requests made by someone other
/// than the pod's owner.
async fn member_session(h: &Harness, username: &str) -> String {
    let user = db::create_user(
        &h._db.pool,
        username,
        None,
        "correct-horse-battery",
        "member",
    )
    .await
    .unwrap();
    db::create_session(&h._db.pool, user.id, time::Duration::hours(1), None)
        .await
        .unwrap()
}

/// [`Harness::send`], as whoever holds `session`.
async fn send_as(
    h: &Harness,
    session: &str,
    method: &str,
    path: &str,
    body: Option<(&str, &str)>,
) -> (StatusCode, String, axum::http::HeaderMap) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST)
        .header(header::COOKIE, format!("brolly_session={session}"));
    if let Some((content_type, _)) = body {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    let request = builder
        .body(body.map_or(Body::empty(), |(_, b)| Body::from(b.to_string())))
        .unwrap();
    let response = h.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let text = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    (status, text, headers)
}

const BOB_WEBID: &str = "https://bob.brolly.test/profile#me";

/// `/~/shared/.acl`: Alice controls `/~/shared/`; Bob may read and write
/// everything inside it through `acl:default`, and holds no Control.
fn share_with_bob(h: &Harness) {
    let pod = h.stores.pod(h.user).unwrap();
    let shared = format!("{ROOT}shared/");
    let g = format!("{shared}.acl");
    let owner = format!("{g}#owner");
    let bob = format!("{g}#bob");
    insert_quads(
        &pod,
        &[
            t(&g, &owner, &format!("{ACL}accessTo"), &shared),
            t(&g, &owner, &format!("{ACL}default"), &shared),
            t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Control")),
            t(&g, &owner, &format!("{ACL}agent"), &format!("{BASE}/profile#me")),
            t(&g, &bob, &format!("{ACL}default"), &shared),
            t(&g, &bob, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &bob, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(&g, &bob, &format!("{ACL}agent"), BOB_WEBID),
        ],
    )
    .unwrap();
}

/// The takeover over the wire: inherited Write used to be enough to PATCH the
/// container's ACL and grant yourself Control.
#[tokio::test]
async fn bob_cannot_patch_an_acl_he_does_not_control() {
    let h = harness().await;
    share_with_bob(&h);
    let bob = member_session(&h, "bob").await;

    let bob_auth = format!("{ROOT}shared/.acl#bob");
    let grab = format!("INSERT DATA {{ <{bob_auth}> <{ACL}mode> <{ACL}Control> }}");
    let (status, _, _) = send_as(
        &h,
        &bob,
        "PATCH",
        "/~/shared/.acl",
        Some(("application/sparql-update", &grab)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let pod = h.stores.pod(h.user).unwrap();
    let granted = pod
        .contains(&t(
            &format!("{ROOT}shared/.acl"),
            &bob_auth,
            &format!("{ACL}mode"),
            &format!("{ACL}Control"),
        ))
        .unwrap();
    assert!(!granted, "the refused PATCH must not have landed");
}

#[tokio::test]
async fn wac_allow_on_an_acl_names_nothing_for_bob() {
    let h = harness().await;
    share_with_bob(&h);
    let bob = member_session(&h, "bob").await;

    let (status, _, headers) = send_as(&h, &bob, "GET", "/~/shared/.acl", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "existence is a disclosure");
    // A refusal carries no WAC-Allow at all, and an empty one would do too.
    // What must never appear is a mode.
    let allowed = headers
        .get("wac-allow")
        .map(|v| v.to_str().unwrap().to_string());
    assert!(
        matches!(allowed.as_deref(), None | Some("user=\"\"")),
        "got {allowed:?}"
    );

    let (status, _, headers) = h.send("GET", "/~/shared/.acl", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["wac-allow"], "user=\"read write append control\"");
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-solid --test acl_control`
Expected: compile error, `function 'granted_modes' is private`
(`error[E0603]`). If you make it `pub` on its own first, three tests fail on
their assertions instead (`bob_cannot_read_rewrite_or_delete_the_containers_acl`,
`bob_cannot_reach_the_acls_of_what_he_can_write`,
`wac_allow_on_an_acl_is_all_or_nothing`). For example, `bob_cannot_read_rewrite_or_delete_the_containers_acl`
panics at the first `matches!`, because Bob's inherited Read lets him read the
ACL.

Run: `cargo test -p brolly-server --test pod_http acl`
Expected: `bob_cannot_patch_an_acl_he_does_not_control` fails with
`left: 204, right: 403`. `wac_allow_on_an_acl_names_nothing_for_bob` fails with
`left: 200, right: 404`.

- [ ] **Step 3: Implement**

In `adapters/solid/src/ldp.rs`, replace `check` and `granted_modes` (`:130-161`)
with:

```rust
/// Resolve and evaluate the ACL governing `resource`.
///
/// An ACL resource is the exception (stage 0, A2). Whatever mode is asked for,
/// it needs `acl:Control` on the resource it [`governed`]s, from that
/// resource's own ACL or an ancestor's `acl:default`. Without this, a caller
/// with inherited Write could rewrite the ACL above them and grant themselves
/// anything, and one with inherited Read could list who else has access.
fn check(
    store: &Store,
    base: &str,
    path: &str,
    subject: &Subject,
    mode: AccessMode,
) -> Result<bool, LdpError> {
    let (path, mode) = match governed(path) {
        Some(resource) => (resource, AccessMode::Control),
        None => (path, mode),
    };
    let Some(acl) = effective_acl(store, base, path).map_err(|e| LdpError::Store(e.to_string()))?
    else {
        // No ACL anywhere in the hierarchy grants nothing. The storage root is
        // initialised with one, so this means a broken pod rather than a
        // default-open resource.
        return Ok(false);
    };
    authorize(store, &acl, &subject.agent(), mode).map_err(|e| LdpError::Store(e.to_string()))
}

/// Modes `subject` holds on `path`, for the `WAC-Allow` header.
///
/// On an ACL resource this is all or nothing. Every mode needs Control on the
/// governed resource, so holding it grants all four and lacking it grants none.
/// Reporting the governed resource's own modes instead would advertise an edit
/// affordance the request would then refuse.
pub fn granted_modes(store: &Store, base: &str, path: &str, subject: &Subject) -> Vec<AccessMode> {
    const ALL: [AccessMode; 4] = [
        AccessMode::Read,
        AccessMode::Write,
        AccessMode::Append,
        AccessMode::Control,
    ];

    if governed(path).is_some() {
        return match check(store, base, path, subject, AccessMode::Control) {
            Ok(true) => ALL.to_vec(),
            _ => Vec::new(),
        };
    }

    let Ok(Some(acl)) = effective_acl(store, base, path) else {
        return Vec::new();
    };
    ALL.into_iter()
        .filter(|mode| matches!(authorize(store, &acl, &subject.agent(), *mode), Ok(true)))
        .collect()
}
```

`read` (`:168`), `put` (`:231`), `append` (`:341`), `may_write` (`:392`) and
`delete` (`:402`) don't change. They all call `check`, and `read` calls
`granted_modes`. Refusals stay as they are: `read` answers `NotFound`, and the
writes answer `Forbidden`, which `server/src/pod.rs::ldp_error` (`:199-216`)
turns into 404 and 403.

- [ ] **Step 4: Run them and watch them pass**

Run: `cargo test -p brolly-solid --test acl_control`
Expected: 5 passed.

Run: `cargo test -p brolly-server --test pod_http acl`
Expected: 2 passed.

- [ ] **Step 5: Gates**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

Every other test must still pass. None of them writes an `.acl` through `ldp`.
They all seed ACLs with `insert_quads`
(`adapters/solid/tests/ldp_conformance.rs:76`, `ldp_nonrdf.rs:49`,
`publication_boundary.rs:57`, `server/tests/pod_http.rs:59`,
`server/tests/solid_token_access.rs:66`).

- [ ] **Step 6: Stage, don't commit**

```bash
git add adapters/solid/src/ldp.rs adapters/solid/tests/acl_control.rs server/tests/pod_http.rs
```

---

### Task 3: ACL resources aren't contained

**Files:**
- Modify: `adapters/solid/src/ldp.rs`: `put` (`:274`, `:279`), `append` (`:378`, `:384`), plus a new private `contain` after `put`
- Test: `adapters/solid/tests/acl_control.rs` (append)

- [ ] **Step 1: Write the failing tests**

Append to `adapters/solid/tests/acl_control.rs`:

```rust
/// ACLs are auxiliary resources, not members of their container
/// (Solid Protocol §4.3).
#[test]
fn an_acl_is_not_a_member_of_its_container() {
    let (_m, _d, store) = shared_pod();
    let doc = format!("{ROOT}shared/doc");

    ldp::put(&store, None, BASE, "/~/shared/doc", &alice(), NOTE, "text/turtle", ROOT).unwrap();
    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/doc.acl",
        &alice(),
        acl_granting(ALICE, &doc).as_bytes(),
        "text/turtle",
        ROOT,
    )
    .unwrap();
    let appended = ldp::append(
        &store,
        None,
        BASE,
        "/~/shared/.acl",
        &alice(),
        acl_granting(CAROL, &format!("{ROOT}shared/")).as_bytes(),
        "text/turtle",
        ROOT,
    )
    .unwrap();
    assert_eq!(appended, format!("{ROOT}shared/.acl"));

    let members = storage::members(&store, &format!("{ROOT}shared/"));
    assert!(members.contains(&doc), "an ordinary resource is still contained");
    assert!(!members.contains(&format!("{ROOT}shared/doc.acl")), "got {members:?}");
    assert!(!members.contains(&format!("{ROOT}shared/.acl")), "got {members:?}");
}

/// An ACL may exist before the resource it governs. Writing one must not
/// create that resource as a side effect.
#[test]
fn an_acl_does_not_create_the_container_it_governs() {
    let (_m, _d, store) = pod();
    let newdir = format!("{ROOT}newdir/");

    ldp::put(
        &store,
        None,
        BASE,
        "/~/newdir/.acl",
        &alice(),
        acl_granting(ALICE, &newdir).as_bytes(),
        "text/turtle",
        ROOT,
    )
    .unwrap();

    assert!(storage::exists(&store, &format!("{newdir}.acl")));
    assert!(!storage::exists(&store, &newdir), "/~/newdir/ was created");
    assert!(!storage::members(&store, ROOT).contains(&newdir));
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-solid --test acl_control an_acl_`
Expected: both fail. `an_acl_is_not_a_member_of_its_container` fails at the
`doc.acl` assertion, and `an_acl_does_not_create_the_container_it_governs` fails
with `/~/newdir/ was created`.

- [ ] **Step 3: Implement**

In `adapters/solid/src/ldp.rs`, add this directly after `put` (after `:281`):

```rust
/// Record `resource` as a member of its container, unless it is an ACL.
///
/// ACL resources are auxiliary resources and aren't contained (Solid Protocol
/// §4.3). Skipping the whole walk up the tree, not just the last step, is what
/// stops a write to `/~/newdir/.acl` from creating `/~/newdir/` as a side
/// effect. The ACL may exist before the resource it governs, and WAC applies it
/// once that resource does.
fn contain(store: &Store, resource: &str, storage_root: &str) -> Result<(), LdpError> {
    if governed(resource).is_some() {
        return Ok(());
    }
    storage::add_containment(store, resource, storage_root)?;
    Ok(())
}
```

In `put`, replace both calls:
- `:274` `storage::add_containment(store, &resource, storage_root)?;` → `contain(store, &resource, storage_root)?;`
- `:279` `storage::add_containment(store, &resource, storage_root)?;` → `contain(store, &resource, storage_root)?;`

In `append`, replace both calls:
- `:378` `storage::add_containment(store, &target, storage_root)?;` → `contain(store, &target, storage_root)?;`
- `:384` `storage::add_containment(store, &target, storage_root)?;` → `contain(store, &target, storage_root)?;`

`append` gets `target`, a full IRI. `governed` only checks the suffix, so that's
fine. A POST to a container mints `{container}{uuid}`, which never ends in
`.acl`. A POST to `…/.acl` appends to the ACL itself.

- [ ] **Step 4: Run them and watch them pass**

Run: `cargo test -p brolly-solid --test acl_control`
Expected: 7 passed. `containment_is_maintained_up_the_tree` and
`posting_to_a_container_mints_a_member` in `ldp_conformance` must still pass.

- [ ] **Step 5: Gates**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

- [ ] **Step 6: Stage, don't commit**

```bash
git add adapters/solid/src/ldp.rs adapters/solid/tests/acl_control.rs
```

---

### Task 4: deleting a resource deletes its ACL

**Files:**
- Modify: `adapters/solid/src/ldp.rs`: `delete`, after `:432`
- Test: `adapters/solid/tests/acl_control.rs` (append)

- [ ] **Step 1: Write the failing tests**

Append to `adapters/solid/tests/acl_control.rs`:

```rust
/// Solid Protocol §5.4: deleting a resource deletes its auxiliary resources.
#[test]
fn deleting_a_resource_deletes_its_acl() {
    let (_m, _d, store) = shared_pod();
    let doc = format!("{ROOT}shared/doc");

    ldp::put(&store, None, BASE, "/~/shared/doc", &alice(), NOTE, "text/turtle", ROOT).unwrap();
    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/doc.acl",
        &alice(),
        acl_granting(ALICE, &doc).as_bytes(),
        "text/turtle",
        ROOT,
    )
    .unwrap();

    ldp::delete(&store, None, BASE, "/~/shared/doc", &alice(), ROOT).unwrap();

    assert!(!storage::exists(&store, &doc));
    assert!(!storage::exists(&store, &format!("{doc}.acl")));
}

/// A container with an ACL can now be deleted, because the ACL isn't a
/// member. Recreating it must not silently restore the grants.
#[test]
fn a_recreated_container_does_not_get_its_old_grants_back() {
    let (_m, _d, store) = pod();
    let shared = format!("{ROOT}shared/");
    let grants = format!(
        "@prefix acl: <{ACL}> .\n\
         <#owner> acl:agent <{ALICE}> ; acl:accessTo <{shared}> ; acl:default <{shared}> ;\n\
           acl:mode acl:Read, acl:Write, acl:Control .\n\
         <#bob> acl:agent <{BOB}> ; acl:default <{shared}> ;\n\
           acl:mode acl:Read, acl:Write .\n"
    );

    ldp::put(&store, None, BASE, "/~/shared/", &alice(), NOTE, "text/turtle", ROOT).unwrap();
    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/.acl",
        &alice(),
        grants.as_bytes(),
        "text/turtle",
        ROOT,
    )
    .unwrap();
    assert!(
        ldp::granted_modes(&store, BASE, "/~/shared/doc", &bob()).contains(&AccessMode::Write),
        "precondition: Bob was granted Write"
    );

    ldp::delete(&store, None, BASE, "/~/shared/", &alice(), ROOT).unwrap();
    assert!(!storage::exists(&store, &format!("{shared}.acl")));

    ldp::put(&store, None, BASE, "/~/shared/", &alice(), NOTE, "text/turtle", ROOT).unwrap();
    assert!(
        ldp::granted_modes(&store, BASE, "/~/shared/doc", &bob()).is_empty(),
        "the old grants came back with the container"
    );
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-solid --test acl_control -- deleting_a_resource a_recreated_container`
Expected: both fail. After Task 3 the container is empty and can be deleted, so
the failure is `!storage::exists(... .acl)` in each test, because the ACL graph
survives the delete.

- [ ] **Step 3: Implement**

In `adapters/solid/src/ldp.rs` `delete`, replace:

```rust
    let digest = blob_digest(store, &resource);
    store.clear_graph(GraphNameRef::NamedNode(iri(&resource).as_ref()))?;
    storage::remove_containment(store, &resource, storage_root)?;
```

(`:430-432`) with:

```rust
    let digest = blob_digest(store, &resource);
    store.clear_graph(GraphNameRef::NamedNode(iri(&resource).as_ref()))?;
    storage::remove_containment(store, &resource, storage_root)?;

    // Deleting a resource deletes its ACL (Solid Protocol §5.4). Now that an
    // ACL isn't a member, a container that has one can be deleted, and
    // recreating it would otherwise quietly bring the old grants back.
    //
    // After the resource, not before: if this fails, the resource is already
    // gone. The other order could leave a live resource with its own ACL
    // stripped and falling back to an ancestor's broader default.
    let acl = format!("{resource}.acl");
    store.clear_graph(GraphNameRef::NamedNode(iri(&acl).as_ref()))?;
```

The blob release that follows (`:434-441`) doesn't change.

- [ ] **Step 4: Run them and watch them pass**

Run: `cargo test -p brolly-solid --test acl_control`
Expected: 9 passed.

- [ ] **Step 5: Gates**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

`a_non_empty_container_cannot_be_deleted` (`ldp_conformance.rs`) must still
pass. A container with real members is still refused.

- [ ] **Step 6: Stage, don't commit**

```bash
git add adapters/solid/src/ldp.rs adapters/solid/tests/acl_control.rs
```

---

### Task 5: `storage::uncontain_acls`, the per-pod sweep

Existing pods still hold the `ldp:contains` triples `put` used to write for
ACLs. Until they're gone, those containers still list their ACL, and a container
with an ACL still can't be deleted. This is the store operation.
`brolly-admin acl-uncontain` (Tasks 6–7) runs it over every pod.

**Files:**
- Modify: `adapters/solid/src/storage.rs`: add after `members` (`:112-128`)
- Test: `adapters/solid/tests/acl_control.rs` (append)

- [ ] **Step 1: Write the failing test**

Append to `adapters/solid/tests/acl_control.rs`:

```rust
/// What `put` wrote before this fix, and the sweep that removes it.
#[test]
fn stale_acl_containment_is_swept_and_a_rerun_removes_nothing() {
    let (_m, _d, store) = shared_pod();
    ldp::put(&store, None, BASE, "/~/shared/doc", &alice(), NOTE, "text/turtle", ROOT).unwrap();

    // The triples an old `put` of each ACL would have left behind.
    storage::add_containment(&store, &format!("{ROOT}.acl"), ROOT).unwrap();
    storage::add_containment(&store, &format!("{ROOT}shared/.acl"), ROOT).unwrap();

    assert_eq!(storage::uncontain_acls(&store).unwrap(), 2);
    assert_eq!(
        storage::members(&store, &format!("{ROOT}shared/")),
        vec![format!("{ROOT}shared/doc")]
    );
    let root = storage::members(&store, ROOT);
    assert!(!root.contains(&format!("{ROOT}.acl")), "got {root:?}");
    assert!(root.contains(&format!("{ROOT}shared/")), "got {root:?}");

    // The ACLs themselves are untouched; only their membership goes.
    assert!(storage::exists(&store, &format!("{ROOT}.acl")));
    assert!(storage::exists(&store, &format!("{ROOT}shared/.acl")));

    assert_eq!(storage::uncontain_acls(&store).unwrap(), 0, "idempotent");
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p brolly-solid --test acl_control stale_acl_containment`
Expected: compile error, `cannot find function 'uncontain_acls' in module 'storage'`.

- [ ] **Step 3: Implement**

In `adapters/solid/src/storage.rs`, directly after `members` (`:112-128`).
`GraphName`, `NamedOrBlankNode`, `Quad` and `Term` are already imported (`:5`).

```rust
/// Remove every `ldp:contains` triple that names an ACL resource.
///
/// ACL resources are auxiliary and aren't members of their container (Solid
/// Protocol §4.3), but `ldp::put` recorded them as members until stage 0. This
/// is the repair `brolly-admin acl-uncontain` runs on each pod. It returns how
/// many triples it removed, so a second run reports zero.
pub fn uncontain_acls(store: &Store) -> Result<usize, oxigraph::store::StorageError> {
    let stale = store
        .quads_for_pattern(None, Some(iri(LDP_CONTAINS).as_ref()), None, None)
        .filter_map(|quad| match quad {
            Ok(quad) => is_acl_containment(&quad).then_some(Ok(quad)),
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<Vec<Quad>, _>>()?;
    for quad in &stale {
        store.remove(quad)?;
    }
    Ok(stale.len())
}

/// The shape [`add_containment`] writes, naming an ACL: a container's own
/// graph saying it contains an `.acl` resource.
///
/// Matching the graph as well as the predicate leaves a member's own documents
/// alone, even if they happen to use `ldp:contains`.
fn is_acl_containment(quad: &Quad) -> bool {
    let (
        NamedOrBlankNode::NamedNode(container),
        Term::NamedNode(member),
        GraphName::NamedNode(graph),
    ) = (&quad.subject, &quad.object, &quad.graph_name)
    else {
        return false;
    };
    container == graph
        && is_container(container.as_str())
        && crate::ldp::governed(member.as_str()).is_some()
}
```

- [ ] **Step 4: Run it and watch it pass**

Run: `cargo test -p brolly-solid --test acl_control`
Expected: 10 passed.

- [ ] **Step 5: Gates**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

- [ ] **Step 6: Stage, don't commit**

```bash
git add adapters/solid/src/storage.rs adapters/solid/tests/acl_control.rs
```

---

### Task 6: `maintenance::acl_uncontain`, the sweep over every pod

Keep the loop in the library, not the binary, so a test can call it without
spawning a process.

**Files:**
- Create: `server/src/maintenance.rs`
- Modify: `server/src/lib.rs:17-30`: add `pub mod maintenance;` between `pub mod mastodon_oauth;` and `pub mod outbox;`
- Create: `server/tests/maintenance.rs`

- [ ] **Step 1: Write the failing test**

Create `server/tests/maintenance.rs`:

```rust
//! The sweeps behind `brolly-admin`, called as a library.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_identity::{db, routing};
use brolly_solid::storage;
use brolly_store::StoreManager;

const BASE_DOMAIN: &str = "brolly.test";

/// Every member's pod is swept, disabled members included (they can be
/// re-enabled, and their pod is unchanged meanwhile). A member whose pod was
/// never opened doesn't get one created.
#[tokio::test]
async fn acl_uncontain_sweeps_every_pod_and_a_rerun_is_a_no_op() {
    let db = brolly_test_support::postgres().await;
    db::MIGRATOR.run(&db.pool).await.expect("migrations");
    let dir = tempfile::tempdir().unwrap();
    let stores = StoreManager::open(dir.path(), 4, 60).unwrap();

    let mut seeded = Vec::new();
    for username in ["alice", "carol"] {
        let user = db::create_user(&db.pool, username, None, "correct-horse-battery", "member")
            .await
            .unwrap();
        let pod = stores.pod(user.id).unwrap();
        brolly_server::provision::pod(&pod, username, BASE_DOMAIN).unwrap();
        // What an old `put` of the root ACL left behind.
        let root = routing::storage_root(username, BASE_DOMAIN);
        storage::add_containment(&pod, &format!("{root}.acl"), &root).unwrap();
        seeded.push((user.id, root));
    }
    sqlx::query("UPDATE users SET status = 'disabled' WHERE username = 'carol'")
        .execute(&db.pool)
        .await
        .unwrap();
    let bob = db::create_user(&db.pool, "bob", None, "correct-horse-battery", "member")
        .await
        .unwrap();

    let first = brolly_server::maintenance::acl_uncontain(&db.pool, &stores)
        .await
        .unwrap();
    let mut removed: Vec<(String, usize)> = first
        .iter()
        .map(|sweep| (sweep.username.clone(), *sweep.outcome.as_ref().unwrap()))
        .collect();
    removed.sort();
    assert_eq!(
        removed,
        vec![("alice".to_string(), 1), ("carol".to_string(), 1)]
    );
    assert!(!stores.pod_exists(bob.id), "the sweep created a pod");

    for (user, root) in &seeded {
        let pod = stores.pod(*user).unwrap();
        assert!(!storage::members(&pod, root).contains(&format!("{root}.acl")));
        assert!(storage::exists(&pod, &format!("{root}.acl")), "the ACL stays");
    }

    let second = brolly_server::maintenance::acl_uncontain(&db.pool, &stores)
        .await
        .unwrap();
    assert_eq!(second.len(), 2);
    assert!(
        second.iter().all(|sweep| matches!(sweep.outcome, Ok(0))),
        "a rerun removed something: {second:?}"
    );
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p brolly-server --test maintenance`
Expected: compile error, `could not find 'maintenance' in 'brolly_server'`.

- [ ] **Step 3: Implement**

Create `server/src/maintenance.rs`:

```rust
//! One-off repairs an operator runs through `brolly-admin`.
//!
//! The loops live here, not in the binary, so tests can call them without
//! spawning a process, and the binary is left with arguments and printing.

use brolly_identity::db::{self, DbError};
use brolly_store::StoreManager;
use sqlx::PgPool;

/// What a sweep did to one member's pod.
#[derive(Debug)]
pub struct PodSweep {
    pub username: String,
    /// How many triples were removed, or why this pod couldn't be swept. One
    /// pod failing doesn't stop the rest, and a rerun picks it up.
    pub outcome: Result<usize, String>,
}

/// Stop listing `.acl` resources as members of their containers, in every pod.
///
/// Stage 0 (A2) made ACL resources auxiliary, and `ldp::put` no longer records
/// them as members. This removes the triples it recorded before that. It's
/// idempotent. Every account is visited whatever its status. An account whose
/// pod has never been opened is skipped rather than having one created.
///
/// This is a command, not a startup task, because it opens every pod. At
/// startup that would slow boot and churn the store cache on a large instance.
pub async fn acl_uncontain(pool: &PgPool, stores: &StoreManager) -> Result<Vec<PodSweep>, DbError> {
    let users = db::list_users(pool).await?;
    Ok(users
        .into_iter()
        .filter(|user| stores.pod_exists(user.id))
        .map(|user| {
            let outcome = stores
                .pod(user.id)
                .map_err(|e| e.to_string())
                .and_then(|pod| {
                    brolly_solid::storage::uncontain_acls(&pod).map_err(|e| e.to_string())
                });
            PodSweep {
                username: user.username,
                outcome,
            }
        })
        .collect())
}
```

In `server/src/lib.rs`, add the module in order:

```rust
pub mod mastodon_oauth;
pub mod maintenance;
pub mod outbox;
```

(If `cargo fmt` reorders it, go with fmt.)

- [ ] **Step 4: Run it and watch it pass**

Run: `cargo test -p brolly-server --test maintenance`
Expected: 1 passed.

- [ ] **Step 5: Gates**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

- [ ] **Step 6: Stage, don't commit**

```bash
git add server/src/maintenance.rs server/src/lib.rs server/tests/maintenance.rs
```

---

### Task 7: `brolly-admin acl-uncontain`, then commit A2

**Files:**
- Modify: `test-support/src/lib.rs:24-27`, `:49-52`: expose the connection URL
- Modify: `server/src/bin/admin.rs:15-39` (USAGE), `:77-87` (dispatch), and add a handler after `whoami` (after `:331`)
- Create: `server/tests/admin_cli.rs`
- Modify: `docs/deploying.md`: add a section at the end

- [ ] **Step 1: Expose the connection URL**

`TestDb` (`test-support/src/lib.rs:24-27`) has no way to hand a subprocess a
`DATABASE_URL`, and `brolly-admin` connects with nothing else. The URL is built
at `:44` and then dropped. Replace the struct:

```rust
pub struct TestDb {
    _container: ContainerAsync<Postgres>,
    pub pool: PgPool,
    /// The connection string, for tests that spawn a subprocess rather than
    /// using the pool. `brolly-admin` connects with `DATABASE_URL`.
    pub url: String,
}
```

and the constructor (`:49-52`):

```rust
    TestDb {
        _container: container,
        pool,
        url,
    }
```

- [ ] **Step 2: Write the failing test**

Create `server/tests/admin_cli.rs`:

```rust
//! `brolly-admin`, spawned as a real binary.
//!
//! `CARGO_BIN_EXE_brolly-admin` is set by Cargo for integration tests in the
//! package that declares the binary, which `server` does.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

use brolly_identity::{db, routing};
use brolly_solid::storage;
use brolly_store::StoreManager;

#[tokio::test]
async fn acl_uncontain_sweeps_the_configured_data_dir_and_is_safe_to_rerun() {
    let db = brolly_test_support::postgres().await;
    db::MIGRATOR.run(&db.pool).await.expect("migrations");
    let dir = tempfile::tempdir().unwrap();
    let alice = db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let root = routing::storage_root("alice", "brolly.test");
    let acl = format!("{root}.acl");

    // Seeded in a scope of its own. Oxigraph opens a store exclusively, so the
    // test must let go of it before the binary can open it. That's also why
    // operators stop the server first.
    {
        let stores = StoreManager::open(dir.path(), 4, 60).unwrap();
        let pod = stores.pod(alice.id).unwrap();
        brolly_server::provision::pod(&pod, "alice", "brolly.test").unwrap();
        storage::add_containment(&pod, &acl, &root).unwrap();
    }

    let run = || {
        Command::new(env!("CARGO_BIN_EXE_brolly-admin"))
            .arg("acl-uncontain")
            .env("DATABASE_URL", &db.url)
            .env("BROLLY_DATA_DIR", dir.path())
            .output()
            .expect("spawn brolly-admin")
    };

    let first = run();
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&first.stdout), "alice\t1\n");

    let second = run();
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&second.stdout), "alice\t0\n");

    let stores = StoreManager::open(dir.path(), 4, 60).unwrap();
    let pod = stores.pod(alice.id).unwrap();
    assert!(!storage::members(&pod, &root).contains(&acl));
    assert!(storage::exists(&pod, &acl), "the ACL itself stays");
}
```

- [ ] **Step 3: Run it and watch it fail**

Run: `cargo test -p brolly-server --test admin_cli`
Expected: the first `assert!` fails. Its stderr contains
`unknown command: acl-uncontain`.

- [ ] **Step 4: Implement**

In `server/src/bin/admin.rs`, replace `USAGE` (`:15-39`) with:

```rust
const USAGE: &str = "\
brolly-admin — operational commands

USAGE:
    brolly-admin invite [--uses N] [--expires-days N] [--admin]
    brolly-admin promote <username>
    brolly-admin demote <username>
    brolly-admin plc-retry [--dry-run]
    brolly-admin whoami <username>
    brolly-admin acl-uncontain

COMMANDS:
    invite       Mint an invite code and print it. The code is shown once;
                 only its hash is stored. --admin makes the account it
                 creates an admin, which is how an instance is handed over
                 without also handing over the database password.
    promote      Make a member an admin.
    demote       Make an admin an ordinary member. Refuses the last one.
    plc-retry    Submit PLC operations the directory has not accepted yet.
                 Safe to re-run — already-submitted operations are skipped.
    whoami       Print what a member's identity resolves to.
    acl-uncontain
                 Stop listing .acl resources as members of their containers,
                 in every pod. Run once after upgrading past stage 0. Stop
                 the server first: it holds the stores open. Safe to re-run.

ENVIRONMENT:
    DATABASE_URL          required
    BROLLY_BASE_DOMAIN    defaults to brolly.test
    BROLLY_DATA_DIR       defaults to data (acl-uncontain)
";
```

In the dispatch (`:77-87`), add an arm after `"whoami"`:

```rust
        "whoami" => whoami(&pool, &base_domain, &args).await,
        "acl-uncontain" => acl_uncontain(&pool).await,
```

Append after `whoami` (after `:331`):

```rust
/// Sweep every pod for `ldp:contains` triples naming `.acl` resources.
///
/// One line per pod on stdout, `username<TAB>removed`, so the output can be
/// piped. Failures go to stderr and make the exit status non-zero. A rerun
/// skips nothing and removes only what's left.
async fn acl_uncontain(pool: &sqlx::PgPool) -> ExitCode {
    let data_dir = std::env::var("BROLLY_DATA_DIR").unwrap_or_else(|_| "data".to_string());
    // A small resident set: the sweep visits each pod once, so there is no
    // working set to keep warm.
    let stores = match brolly_store::StoreManager::open(&data_dir, 16, 60) {
        Ok(stores) => stores,
        Err(e) => {
            eprintln!("could not open the stores under {data_dir}: {e}");
            eprintln!("is the server still running? it holds the stores open; stop it first");
            return ExitCode::FAILURE;
        }
    };

    let sweeps = match brolly_server::maintenance::acl_uncontain(pool, &stores).await {
        Ok(sweeps) => sweeps,
        Err(e) => {
            eprintln!("could not list members: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut removed = 0usize;
    let mut failed = 0usize;
    for sweep in &sweeps {
        match &sweep.outcome {
            Ok(count) => {
                removed += count;
                println!("{}\t{count}", sweep.username);
            }
            Err(e) => {
                failed += 1;
                eprintln!("{}: {e}", sweep.username);
            }
        }
    }

    eprintln!(
        "{removed} containment triple(s) removed across {} pod(s)",
        sweeps.len()
    );
    if failed > 0 {
        eprintln!("{failed} pod(s) could not be swept; safe to re-run");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
```

Append to `docs/deploying.md`:

~~~markdown
## Upgrading

### Past stage 0 (ACL resources)

`.acl` resources are no longer members of their containers. Pods written
before the upgrade still list them. Until that's cleaned up, those containers
show their ACL in listings, and a container with an ACL can't be deleted.
Once, after deploying:

```fish
# stop the server first: it holds the stores open
brolly-admin acl-uncontain
```

It prints one `username<TAB>removed` line per pod and is safe to re-run. Point
`BROLLY_DATA_DIR` at the same volume the server uses.
~~~

- [ ] **Step 5: Run it and watch it pass**

Run: `cargo test -p brolly-server --test admin_cli`
Expected: 1 passed.

Run the whole A2 set once more:
`cargo test -p brolly-solid --lib ldp::tests && cargo test -p brolly-solid --test acl_control && cargo test -p brolly-server --test pod_http acl && cargo test -p brolly-server --test maintenance`

- [ ] **Step 6: Gates**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && ./tools/check-doc-paths.sh
```

No `Cargo.toml` changes, so `cargo deny check` isn't needed.

- [ ] **Step 7: Commit**

```bash
git add adapters/solid/src/ldp.rs adapters/solid/src/storage.rs \
        adapters/solid/tests/acl_control.rs \
        server/src/maintenance.rs server/src/lib.rs server/src/bin/admin.rs \
        server/tests/pod_http.rs server/tests/maintenance.rs server/tests/admin_cli.rs \
        test-support/src/lib.rs docs/deploying.md
git commit -m "fix(solid): an ACL needs Control on what it governs

check and granted_modes treated a .acl like any other document, so
inherited acl:Write was enough to PUT, PATCH or DELETE a container's ACL
and grant yourself Control, and inherited Read listed who else had
access. Every mode on an ACL resource now needs acl:Control on the
resource it governs (the path with every trailing .acl removed). That
covers every LDP verb, including pod writes from other protocols made
through brolly_solid::ldp. WAC-Allow on an ACL is all four modes or none.
wac.rs is unchanged.

ACLs are auxiliary resources, so put and append no longer record them as
container members, and writing /~/newdir/.acl no longer creates
/~/newdir/. With ACLs no longer members, a container with an ACL can be
deleted, so delete now clears the deleted resource's .acl. Otherwise
recreating the container would quietly bring the old grants back.

brolly-admin acl-uncontain removes the ldp:contains triples existing pods
still hold for ACLs. Run it once after deploying, with the server stopped
because it holds the stores open. It is idempotent.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 8: Verify the commit from a clean checkout**

```bash
rm -rf /tmp/verify && git worktree add --detach /tmp/verify HEAD
cd /tmp/verify && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings
cd - && git worktree remove /tmp/verify --force
```

Green there, or the commit is not done. The first compile in a new worktree takes
about three minutes; run it in the background rather than skipping it.

---

### Notes for the reviewer

1. **One commit for seven tasks.** Rollout item 2 ships A2 and `acl-uncontain`
   together, so Tasks 1–6 stage and Task 7 commits. Each task still runs its own
   tests and the gates.
2. **`granted_modes` becomes `pub`.** The spec wants a test that `granted` for
   `/~/shared/.acl` is empty for Bob. Bob's `read` is refused with `NotFound`, so
   no `LdpOutcome` ever reaches him. The only way to observe his (empty) modes
   is to call `granted_modes` directly. The owner's side is still checked
   through `LdpOutcome.granted`.
3. **"The `WAC-Allow` header is empty for Bob" over HTTP.** A refused GET is a
   404 from `ldp_error`, and that response has no `WAC-Allow` header. The spec
   says refusals look the same as today, so the header isn't added to 404s. The
   test accepts no header or `user=""`, and checks that the owner's header on the
   same resource names all four modes.
4. **The pod_http harness root ACL grants no Control.** The HTTP tests give
   Alice Control on `/~/shared/` in `/~/shared/.acl` and leave the shared
   harness (`pod_http.rs:61-80`) alone. Provisioned pods do grant Control
   (`provision.rs`).
5. **Deleting a resource clears its ACL with no Control check.** The spec says
   `delete` clears the `.acl` and names no extra mode, and Solid Protocol §5.4
   agrees. So Bob, with inherited Write on `/~/shared/doc`, can delete it and
   with it `/~/shared/doc.acl`, which he couldn't delete directly. Anything he
   recreates there inherits the container's defaults, which only someone with
   Control on the container wrote. `delete` also clears `x.acl.acl` when deleting
   `x.acl`. No `acl_candidates` lookup ever reads it, so it's inert, and it keeps
   the rule uniform.
6. **The ACL is cleared after the resource, not before.** If the second
   `clear_graph` fails, a deleted resource keeps a stale ACL, which is today's
   behaviour. The other order could leave a live resource without its own ACL,
   falling back to a broader inherited default.
7. **`acl-uncontain` needs the server stopped.** `StoreManager::open` opens the
   instance store, and `pod` opens RocksDB directories exclusively. With the
   server running, the command fails on open with a message saying so. The spec
   says "run once after deploying", and the usage text and `docs/deploying.md`
   add "stop the server first". On Railway a one-off command against a running
   service's volume would hit this. Until the command runs, the stale triples
   only affect listings and container deletes, not access, so running it at the
   next maintenance window is fine. If that's not acceptable, the alternative is
   a startup task, which the spec rejected.
8. **The sweep goes by the `users` table, not by directories on disk.** It covers
   every account whatever its status, including disabled ones, and skips
   accounts whose pod directory doesn't exist (`StoreManager::pod_exists`), so
   it never creates a pod. A pod directory with no user row isn't visited.
9. **`uncontain_acls` removes only triples shaped like `add_containment`'s
   output:** a container IRI (ends in `/`) as subject, in its own graph, with an
   ACL object. A member's own document that uses `ldp:contains` is left alone.
   Containers that an old ACL write created as a side effect (such as
   `/~/newdir/` holding only an ACL) are not removed. Deleting them isn't part of
   the spec, and they are ordinary empty containers.
10. **`TestDb.url` is added here.** `docs/plans/2026-09-10-admin-actions.md`
    (Chunk 5) plans the same field and the same `server/tests/admin_cli.rs`
    file, and neither exists yet. If that plan runs later, its Step 1 is already
    done and its test belongs in the existing `admin_cli.rs`.
11. **`governed` works on IRIs as well as paths.** `append` and
    `uncontain_acls` call it with full IRIs. It only looks at the suffix, so the
    result is the same. The unit test covers one IRI case.
12. **Cross-chunk.** Nothing here touches `AppState`. The new `pod_http.rs`
    tests use the existing `harness()`, which chunk 5's mechanical step updates
    anyway. `server/tests/maintenance.rs` and `admin_cli.rs` build no
    `AppState`, so they need no `clients` field. `brolly-admin` doesn't build a reqwest client in
    `acl-uncontain`, so chunk 4's `install_crypto_provider` call at the top of
    `main` is unaffected.


## Chunk 3: DPoP proofs are single-use (C)

**Spec:** `docs/specs/2026-09-17-security-fixes.md`, section C and its tests.

**Shape of the chunk.** Changing what `dpop::verify` returns breaks every call
site at once: `adapters/solid/src/oidc/tokens.rs`, `server/src/pod.rs`,
`server/src/solid_oidc.rs`, `server/src/atproto_oauth.rs` and
`server/src/xrpc.rs`. The workspace doesn't compile again until all of them are
done, so the work is **one commit** (Rollout step 3, "C, with the migration")
spread over three tasks:

1. **Task 1** writes the four HTTP-level replay tests. They compile against
   today's code and fail because the replayed request succeeds. No commit.
2. **Task 2** does the identity crate: the migration, `Unspent<T>`, the new
   errors, the rewritten unit tests, the doctest pair, and the database tests.
   It is checked with `cargo test -p brolly-identity`, which builds only that
   crate. No commit, because the rest of the workspace doesn't compile yet.
3. **Task 3** changes every call site, runs the gates, and commits everything
   from Tasks 1 to 3 together.

| File | Change |
|---|---|
| `migrations/20260917000000_identity_dpop_jti.sql` | Create |
| `identity/src/dpop.rs` | `Unspent<T>`, `Replayed`, `Storage`, `verify` returns `Unspent`, tests rewritten |
| `identity/tests/dpop_replay.rs` | Create: spend once, two keys with one `jti`, pruning by the app clock, storage failure |
| `adapters/solid/src/oidc/tokens.rs` | `Access` enum; `verify_access` returns it |
| `server/src/pod.rs` | `subject_for` spends a `Bound` |
| `server/src/solid_oidc.rs` | token endpoint spends |
| `server/src/atproto_oauth.rs` | `proof_thumbprint` becomes `async` and spends |
| `server/src/xrpc.rs` | `token_caller` spends |
| `server/tests/solid_oidc_flow.rs`, `solid_token_access.rs`, `atproto_oauth.rs`, `xrpc.rs` | One replay test each |

`server/tests/dashboard.rs` needs no change. Its `dpop_proof` (`:400`) already
mints a fresh `Uuid::new_v4()` `jti` for every proof, as do the helpers in the
other three DPoP test files. So no existing test sends the same proof twice, and
none of them start failing.

---

### Task 1: Replay tests at every HTTP call site

**Files:**
- Test: `server/tests/solid_oidc_flow.rs` (append after
  `a_refresh_token_cannot_be_used_by_a_different_key`, end of file)
- Test: `server/tests/solid_token_access.rs` (append at end of file)
- Test: `server/tests/atproto_oauth.rs:164-195` (split `push`), plus a new test
  after `a_client_id_that_is_not_a_fetchable_url_is_refused` (`:439`)
- Test: `server/tests/xrpc.rs` (new imports at `:11-18`; new helpers and test
  after `a_deleted_record_is_gone_from_the_repo`, before the
  `// --- hygiene` divider at `:468`)

Every test sends a request that would succeed, then sends a second request that
would also succeed except that it reuses the first request's proof. A third
request with a fresh proof must succeed. That shows the refusal came from the
replay and not from the token or grant being used up.

- [ ] **Step 1: Solid token endpoint, in `server/tests/solid_oidc_flow.rs`**

This file's helpers are `register`, `a_logged_in_member`, `pkce`, `a_code`,
`client_key`, `dpop_proof(key, method, url, ath)`, `builder` and `send`. `Reply`
has `status`, `body: String` and `json()`.

```rust
#[tokio::test]
async fn a_token_endpoint_proof_is_good_for_one_request() {
    // RFC 9449: a proof's jti is used once. Otherwise a proof captured in
    // transit works for its whole freshness window, at any endpoint where the
    // attacker holds something else worth presenting — here, a refresh token.
    let harness = harness().await;
    let client_id = register(&harness).await;
    let cookie = a_logged_in_member(&harness).await;
    let (verifier, challenge) = pkce();
    let code = a_code(&harness, &client_id, &challenge, &cookie).await;

    let key = client_key();
    let url = format!("https://{BASE}/oauth/solid/token");
    let token_request = |body: String, proof: &str| {
        builder("POST", "/oauth/solid/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("DPoP", proof)
            .body(Body::from(body))
            .unwrap()
    };

    let proof = dpop_proof(&key, "POST", &url, None);
    let exchange = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &code)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("client_id", &client_id)
        .append_pair("code_verifier", &verifier)
        .finish();
    let first = send(&harness, token_request(exchange, &proof)).await;
    assert_eq!(first.status, StatusCode::OK, "token: {}", first.body);
    let refresh = first.json()["refresh_token"]
        .as_str()
        .expect("offline_access was requested")
        .to_string();

    let refresh_body = || {
        form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("refresh_token", &refresh)
            .append_pair("client_id", &client_id)
            .finish()
    };

    // A valid refresh, carrying the proof the exchange already spent.
    let replayed = send(&harness, token_request(refresh_body(), &proof)).await;
    assert_eq!(replayed.status, StatusCode::BAD_REQUEST, "{}", replayed.body);
    assert_eq!(replayed.json()["error"], "invalid_dpop_proof");

    // Refused before the grant was touched, so the refresh token still
    // rotates once the client signs a new proof.
    let fresh = dpop_proof(&key, "POST", &url, None);
    let rotated = send(&harness, token_request(refresh_body(), &fresh)).await;
    assert_eq!(rotated.status, StatusCode::OK, "refresh: {}", rotated.body);
}
```

- [ ] **Step 2: Solid resource GET, in `server/tests/solid_token_access.rs`**

This file's helpers are `harness`, `access_token(harness, key)`, `client_key`,
`dpop_proof(key, method, url, ath)`, `read_note(authorization, proof)` and
`send`, which returns `(StatusCode, String)`.

```rust
#[tokio::test]
async fn a_resource_proof_is_good_for_one_request() {
    // `ath` binds a proof to the token and `htu` to the resource, but neither
    // stops the identical request being sent again. Only the jti does.
    let harness = harness().await;
    let key = client_key();
    let token = access_token(&harness, &key).await;
    let ath = B64.encode(Sha256::digest(token.as_bytes()));
    let authorization = format!("DPoP {token}");

    let proof = dpop_proof(&key, "GET", NOTE, Some(&ath));
    let (status, body) = send(&harness, read_note(Some(&authorization), Some(&proof))).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let (status, _) = send(&harness, read_note(Some(&authorization), Some(&proof))).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a replayed proof must leave the caller anonymous"
    );

    let fresh = dpop_proof(&key, "GET", NOTE, Some(&ath));
    let (status, _) = send(&harness, read_note(Some(&authorization), Some(&fresh))).await;
    assert_eq!(status, StatusCode::OK, "the token itself is still good");
}
```

- [ ] **Step 3: ATProto PAR, in `server/tests/atproto_oauth.rs`**

`push` (`:164-195`) builds its proof internally, so a test can't send the same
proof twice. Replace `push` with these two functions. Every existing caller
keeps calling `push` with the same arguments.

```rust
async fn push(h: &Harness, key: &SigningKey, challenge: &str) -> Reply {
    let dpop = proof(
        key,
        "POST",
        &format!("https://{BASE}/oauth/atproto/par"),
        None,
    );
    push_with_proof(h, &dpop, challenge).await
}

/// PAR with a proof the caller supplies, so a test can present one twice.
async fn push_with_proof(h: &Harness, dpop: &str, challenge: &str) -> Reply {
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", CLIENT)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("response_type", "code")
        .append_pair("scope", "atproto transition:generic")
        .append_pair("state", "client-state")
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();

    send(
        h,
        Request::builder()
            .method("POST")
            .uri("/oauth/atproto/par")
            .header(header::HOST, BASE)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("DPoP", dpop)
            .body(Body::from(body))
            .unwrap(),
    )
    .await
}
```

Then add, after `a_client_id_that_is_not_a_fetchable_url_is_refused`:

```rust
#[tokio::test]
async fn a_par_proof_is_good_for_one_request() {
    // PAR is where the key is pledged. A replayed proof would let anyone who
    // saw one push requests pledged to a key they don't hold.
    let h = harness().await;
    let key = client_key();
    let (_, challenge) = pkce();
    let dpop = proof(
        &key,
        "POST",
        &format!("https://{BASE}/oauth/atproto/par"),
        None,
    );

    let first = push_with_proof(&h, &dpop, &challenge).await;
    assert_eq!(first.status, StatusCode::CREATED, "{}", first.body);

    let replayed = push_with_proof(&h, &dpop, &challenge).await;
    assert_eq!(replayed.status, StatusCode::BAD_REQUEST, "{}", replayed.body);
    assert_eq!(replayed.json()["error"], "invalid_dpop_proof");

    let fresh = push(&h, &key, &challenge).await;
    assert_eq!(fresh.status, StatusCode::CREATED, "{}", fresh.body);
}
```

- [ ] **Step 4: XRPC write, in `server/tests/xrpc.rs`**

This file has no DPoP tests. Its `send` drops `Location`, and its `a_member`
(`:137`) provisions a pod, a repo and a signing key, then returns
`(user_id, cookie)`. The test builds the full ATProto OAuth flow on top of that
member, following `full_flow` in `server/tests/atproto_oauth.rs:233`.

Add to the imports at the top (`:11-18`). `p256::ecdsa::SigningKey` is written
out in full below, so it can't be confused with `brolly_atproto::keys::SigningKey`,
which this file already names in full.

```rust
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use p256::ecdsa::signature::Signer;
use sha2::{Digest, Sha256};
```

Add the helpers and the test before the `// --- hygiene` divider:

```rust
// --- DPoP-bound callers ------------------------------------------------------------

const OAUTH_CLIENT: &str = "https://app.example/client-metadata.json";
const OAUTH_REDIRECT: &str = "https://app.example/cb";

/// A DPoP proof, as a real client produces one.
fn dpop_proof(key: &p256::ecdsa::SigningKey, method: &str, url: &str, ath: Option<&str>) -> String {
    let sec1 = key.verifying_key().to_sec1_bytes();
    let header = json!({
        "alg": "ES256", "typ": "dpop+jwt",
        "jwk": {"kty": "EC", "crv": "P-256",
                "x": B64.encode(&sec1[1..33]), "y": B64.encode(&sec1[33..65])},
    });
    let mut claims = json!({
        "htm": method, "htu": url,
        "jti": uuid::Uuid::new_v4().to_string(),
        "iat": time::OffsetDateTime::now_utc().unix_timestamp(),
    });
    if let Some(ath) = ath {
        claims["ath"] = json!(ath);
    }
    let signed = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).unwrap()),
        B64.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature: p256::ecdsa::Signature = key.sign(signed.as_bytes());
    format!("{signed}.{}", B64.encode(signature.to_bytes()))
}

/// Take `cookie`'s member through ATProto OAuth and return an access token
/// bound to `key`: PAR, consent, decision, token, each through the router.
async fn atproto_access_token(h: &Harness, cookie: &str, key: &p256::ecdsa::SigningKey) -> String {
    let verifier = "a-high-entropy-value-for-the-xrpc-dpop-replay-test-0123456789";
    let challenge = B64.encode(Sha256::digest(verifier.as_bytes()));

    let par = form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", OAUTH_CLIENT)
        .append_pair("redirect_uri", OAUTH_REDIRECT)
        .append_pair("response_type", "code")
        .append_pair("scope", "atproto transition:generic")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();
    let pushed = send(
        h,
        Request::builder()
            .method("POST")
            .uri("/oauth/atproto/par")
            .header(header::HOST, BASE)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                "DPoP",
                dpop_proof(key, "POST", &format!("https://{BASE}/oauth/atproto/par"), None),
            )
            .body(Body::from(par))
            .unwrap(),
    )
    .await;
    assert_eq!(pushed.status, StatusCode::CREATED, "par: {}", pushed.text());
    let request_uri = pushed.json()["request_uri"].as_str().unwrap().to_string();

    let authorize = form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", OAUTH_CLIENT)
        .append_pair("request_uri", &request_uri)
        .finish();
    let consent = send(
        h,
        Request::builder()
            .uri(format!("/oauth/atproto/authorize?{authorize}"))
            .header(header::HOST, BASE)
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(consent.status, StatusCode::OK, "authorize: {}", consent.text());
    let html = consent.text();
    let marker = r#"name="request" value=""#;
    let start = html.find(marker).expect("a consent form") + marker.len();
    let request_token = html[start..].split('"').next().unwrap().to_string();

    // Straight through the router: `send` does not keep `Location`.
    let decision = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/atproto/authorize")
                .header(header::HOST, BASE)
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    form_urlencoded::Serializer::new(String::new())
                        .append_pair("request", &request_token)
                        .append_pair("decision", "allow")
                        .finish(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let location = decision
        .headers()
        .get(header::LOCATION)
        .expect("a redirect back to the client")
        .to_str()
        .unwrap()
        .to_string();
    let code = form_urlencoded::parse(location.split_once('?').unwrap().1.as_bytes())
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .expect("a code");

    let exchange = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &code)
        .append_pair("redirect_uri", OAUTH_REDIRECT)
        .append_pair("client_id", OAUTH_CLIENT)
        .append_pair("code_verifier", verifier)
        .finish();
    let token = send(
        h,
        Request::builder()
            .method("POST")
            .uri("/oauth/atproto/token")
            .header(header::HOST, BASE)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                "DPoP",
                dpop_proof(key, "POST", &format!("https://{BASE}/oauth/atproto/token"), None),
            )
            .body(Body::from(exchange))
            .unwrap(),
    )
    .await;
    assert_eq!(token.status, StatusCode::OK, "token: {}", token.text());
    token.json()["access_token"].as_str().unwrap().to_string()
}

/// `createRecord` authenticated by nothing but a DPoP-bound token.
///
/// The proof has to sign `POST https://<base>/xrpc/`, because that fixed target
/// is what `token_caller` checks today. Stage 2 changes it to the method's
/// real URL.
async fn create_with_token(h: &Harness, token: &str, proof: &str, rkey: &str) -> Reply {
    send(
        h,
        Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header(header::HOST, BASE)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("DPoP {token}"))
            .header("DPoP", proof)
            .body(Body::from(
                json!({
                    "repo": format!("alice.{BASE}"),
                    "collection": "app.bsky.feed.post",
                    "rkey": rkey,
                    "record": {"$type": "app.bsky.feed.post", "text": "signed once"},
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
}

#[tokio::test]
async fn an_xrpc_write_proof_is_good_for_one_request() {
    // A write is the costliest thing to replay: each replay is another record.
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;
    let key = p256::ecdsa::SigningKey::from_slice(&[21u8; 32]).unwrap();
    let token = atproto_access_token(&h, &cookie, &key).await;
    let target = format!("https://{BASE}/xrpc/");
    let ath = B64.encode(Sha256::digest(token.as_bytes()));

    let proof = dpop_proof(&key, "POST", &target, Some(&ath));
    let first = create_with_token(&h, &token, &proof, "3kaaaaaaaaaab").await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text());

    // A different record, so the only thing this request repeats is the proof.
    let replayed = create_with_token(&h, &token, &proof, "3kaaaaaaaaaac").await;
    assert_eq!(replayed.status, StatusCode::UNAUTHORIZED, "{}", replayed.text());
    assert_eq!(replayed.json()["error"], "AuthenticationRequired");

    let fresh = dpop_proof(&key, "POST", &target, Some(&ath));
    let third = create_with_token(&h, &token, &fresh, "3kaaaaaaaaaac").await;
    assert_eq!(third.status, StatusCode::OK, "{}", third.text());
}
```

- [ ] **Step 5: Run them and watch them fail**

```bash
cargo test -p brolly-server --test solid_oidc_flow a_token_endpoint_proof_is_good_for_one_request
cargo test -p brolly-server --test solid_token_access a_resource_proof_is_good_for_one_request
cargo test -p brolly-server --test atproto_oauth a_par_proof_is_good_for_one_request
cargo test -p brolly-server --test xrpc an_xrpc_write_proof_is_good_for_one_request
```

Expected: all four compile. Each fails on its **replay** assertion: the Solid
token endpoint returns `200` where `400` was expected, the resource GET `200`
where `404` was expected, PAR `201` where `400` was expected, and the XRPC write
`200` where `401` was expected. If one fails earlier, in setup, fix the test
before going on. A setup failure would still be red after Task 3.

Then check that the refactored `push` didn't break its existing callers:
`cargo test -p brolly-server --test atproto_oauth`. Expected: every test passes
except `a_par_proof_is_good_for_one_request`.

- [ ] **Step 6: Don't commit**

These four tests land in Task 3's commit, together with the fix. Committing them
now would put a red commit on `main`.

---

### Task 2: `Unspent<T>` and the `dpop_jti` table

**Files:**
- Create: `migrations/20260917000000_identity_dpop_jti.sql`
- Modify: `identity/src/dpop.rs`: module doc (`:1-23`), imports (`:25-30`),
  `DpopError` (`:38-69`), `Claims` (`:89-98`), a new `Unspent` after
  `VerifiedProof` (`:100-109`), `verify` (`:161-230`), and the whole `tests`
  module (`:240-443`)
- Test: `identity/tests/dpop_replay.rs` (create)

- [ ] **Step 1: Write the failing database tests**

Create `identity/tests/dpop_replay.rs`. It uses the same `fresh()` shape as
`identity/tests/persistence.rs:11`. `p256`, `base64`, `serde_json` and `sqlx`
are regular dependencies of `brolly-identity`, so an integration test can use
them without adding anything to `Cargo.toml`.

```rust
//! A DPoP proof is good for one request (RFC 9449).
//!
//! `verify` checks a proof's signature, target and freshness. A proof that
//! passes all three could still be captured and sent again for as long as it
//! stays fresh. `Unspent::spend` records the `jti` so the second use fails.
//! These tests run against a real Postgres, because the guarantee comes from
//! its primary key.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use brolly_identity::db::MIGRATOR;
use brolly_identity::dpop::{self, DpopError, MAX_AGE_SECONDS, VerifiedProof};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sqlx::PgPool;

const URL: &str = "https://brolly.test/oauth/solid/token";

async fn fresh() -> (brolly_test_support::TestDb, PgPool) {
    let db = brolly_test_support::postgres().await;
    MIGRATOR.run(&db.pool).await.expect("migrations run");
    let pool = db.pool.clone();
    (db, pool)
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}

/// A token-endpoint proof with the `jti` and `iat` the test chooses.
fn proof(key: &SigningKey, jti: &str, iat: i64) -> String {
    let sec1 = key.verifying_key().to_sec1_bytes();
    let header = serde_json::json!({
        "alg": "ES256", "typ": "dpop+jwt",
        "jwk": {"kty": "EC", "crv": "P-256",
                "x": B64.encode(&sec1[1..33]), "y": B64.encode(&sec1[33..65])},
    });
    let claims = serde_json::json!({"htm": "POST", "htu": URL, "jti": jti, "iat": iat});
    let signed = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).unwrap()),
        B64.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature: Signature = key.sign(signed.as_bytes());
    format!("{signed}.{}", B64.encode(signature.to_bytes()))
}

/// Verify and spend, as a call site does, with `now` as the application clock.
async fn present(pool: &PgPool, proof: &str, now: i64) -> Result<VerifiedProof, DpopError> {
    let unspent = dpop::verify(proof, "POST", URL, None, now).expect("the proof itself is valid");
    unspent.spend(pool, now).await
}

async fn rows_for(pool: &PgPool, jti: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM dpop_jti WHERE jti = $1")
        .bind(jti)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_proof_is_spent_once_and_refused_the_second_time() {
    let (_db, pool) = fresh().await;
    let p = proof(&key(7), "only-once", 1000);

    assert!(present(&pool, &p, 1000).await.is_ok());
    assert_eq!(
        present(&pool, &p, 1001).await.err(),
        Some(DpopError::Replayed)
    );
}

#[tokio::test]
async fn two_keys_may_each_use_the_same_jti() {
    // The client picks the jti. Keying on (jkt, jti) means one client's choice
    // can't get another client's proofs refused.
    let (_db, pool) = fresh().await;

    assert!(present(&pool, &proof(&key(7), "shared", 1000), 1000).await.is_ok());
    assert!(present(&pool, &proof(&key(9), "shared", 1000), 1000).await.is_ok());
    assert_eq!(rows_for(&pool, "shared").await, 2);
}

#[tokio::test]
async fn a_proof_stays_spent_for_its_whole_window_whatever_the_database_clock_says() {
    // To Postgres, iat 1000 is 1970. Pruning by the database's now() would drop
    // the row at the next spend and let the replay through, even though the
    // application still considers the proof fresh.
    let (_db, pool) = fresh().await;
    let p = proof(&key(7), "early", 1000);
    present(&pool, &p, 1000).await.unwrap();

    // Another spend runs the prune, while the application clock is still
    // inside the first proof's window.
    let edge = 1000 + MAX_AGE_SECONDS;
    present(&pool, &proof(&key(7), "later", edge), edge)
        .await
        .unwrap();

    assert_eq!(rows_for(&pool, "early").await, 1);
    assert_eq!(
        present(&pool, &p, edge).await.err(),
        Some(DpopError::Replayed)
    );
}

#[tokio::test]
async fn the_next_spend_prunes_rows_past_their_window_by_the_application_clock() {
    // 2096 to Postgres. Only the application's clock can call this row expired,
    // so if it disappears, the prune used that clock.
    const FUTURE: i64 = 4_000_000_000;
    let (_db, pool) = fresh().await;
    present(&pool, &proof(&key(7), "old", FUTURE), FUTURE)
        .await
        .unwrap();

    let later = FUTURE + 2 * MAX_AGE_SECONDS + 1;
    present(&pool, &proof(&key(7), "new", later), later)
        .await
        .unwrap();

    assert_eq!(rows_for(&pool, "old").await, 0, "a row past its window is pruned");
    assert_eq!(rows_for(&pool, "new").await, 1);
}

#[tokio::test]
async fn a_storage_failure_refuses_the_proof() {
    // Fail closed. A proof that couldn't be recorded can't be known unspent.
    let (_db, pool) = fresh().await;
    let unspent = dpop::verify(&proof(&key(7), "unrecorded", 1000), "POST", URL, None, 1000)
        .expect("the proof itself is valid");
    pool.close().await;

    assert!(matches!(
        unspent.spend(&pool, 1000).await,
        Err(DpopError::Storage(_))
    ));
}
```

- [ ] **Step 2: Rewrite the unit tests in `identity/src/dpop.rs`**

`Unspent` deliberately derives neither `Debug` nor `PartialEq` (see Step 6), so
`assert_eq!(verify(..), Err(..))` no longer compiles. Those assertions become
`assert_eq!(verify(..).err(), Some(..))`. The two tests that read `.thumbprint`
now use `bound_to` with a thumbprint the test computes itself. Replace the whole
`#[cfg(test)] mod tests` (`:240-443`) with:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;

    fn make_proof(
        key: &SigningKey,
        method: &str,
        url: &str,
        iat: i64,
        ath: Option<&str>,
        typ: &str,
    ) -> String {
        // SEC1 uncompressed: 0x04 || x || y.
        let sec1 = key.verifying_key().to_sec1_bytes();
        assert_eq!(sec1[0], 0x04, "expected an uncompressed point");
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": B64.encode(&sec1[1..33]),
            "y": B64.encode(&sec1[33..65]),
        });
        let header = serde_json::json!({"alg": "ES256", "typ": typ, "jwk": jwk});
        let mut claims = serde_json::json!({
            "htm": method, "htu": url, "jti": "unique", "iat": iat
        });
        if let Some(ath) = ath {
            claims["ath"] = serde_json::Value::String(ath.to_string());
        }

        let signed = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&header).unwrap()),
            B64.encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature: Signature = key.sign(signed.as_bytes());
        // to_bytes() is P1363 — the format WebCrypto emits.
        format!("{signed}.{}", B64.encode(signature.to_bytes()))
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32].into()).unwrap()
    }

    /// RFC 7638 for a P-256 key, written out here instead of calling
    /// `thumbprint`, so the assertions below test the thumbprint too.
    fn jkt_of(key: &SigningKey) -> String {
        let sec1 = key.verifying_key().to_sec1_bytes();
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            B64.encode(&sec1[1..33]),
            B64.encode(&sec1[33..65])
        );
        B64.encode(Sha256::digest(canonical.as_bytes()))
    }

    const URL: &str = "https://alice.brolly.id/~/note";

    #[test]
    fn a_valid_resource_proof_verifies() {
        let token = "access-token";
        let proof = make_proof(
            &key(),
            "GET",
            URL,
            1000,
            Some(&access_token_hash(token)),
            "dpop+jwt",
        );
        let verified = verify(&proof, "GET", URL, Some(token), 1000).unwrap();
        assert!(verified.bound_to(&jkt_of(&key())));
    }

    #[test]
    fn a_token_endpoint_proof_needs_no_ath() {
        // The commonest login failure if a server requires ath everywhere.
        let proof = make_proof(
            &key(),
            "POST",
            "https://brolly.id/oauth/solid/token",
            1000,
            None,
            "dpop+jwt",
        );
        assert!(
            verify(
                &proof,
                "POST",
                "https://brolly.id/oauth/solid/token",
                None,
                1000
            )
            .is_ok()
        );
    }

    #[test]
    fn a_resource_proof_without_ath_is_refused() {
        let proof = make_proof(&key(), "GET", URL, 1000, None, "dpop+jwt");
        assert_eq!(
            verify(&proof, "GET", URL, Some("access-token"), 1000).err(),
            Some(DpopError::TokenBindingFailed)
        );
    }

    #[test]
    fn a_proof_for_a_different_token_is_refused() {
        // Otherwise a proof captured with one token could be replayed with
        // another the attacker also holds.
        let proof = make_proof(
            &key(),
            "GET",
            URL,
            1000,
            Some(&access_token_hash("some-other-token")),
            "dpop+jwt",
        );
        assert_eq!(
            verify(&proof, "GET", URL, Some("access-token"), 1000).err(),
            Some(DpopError::TokenBindingFailed)
        );
    }

    #[test]
    fn a_proof_for_another_method_or_url_is_refused() {
        let proof = make_proof(&key(), "GET", URL, 1000, None, "dpop+jwt");
        assert!(matches!(
            verify(&proof, "DELETE", URL, None, 1000),
            Err(DpopError::WrongTarget { .. })
        ));
        assert!(matches!(
            verify(&proof, "GET", "https://alice.brolly.id/~/other", None, 1000),
            Err(DpopError::WrongTarget { .. })
        ));
    }

    #[test]
    fn query_and_fragment_are_ignored_when_matching_htu() {
        // RFC 9449 compares the URL without query or fragment.
        let proof = make_proof(&key(), "GET", URL, 1000, None, "dpop+jwt");
        assert!(verify(&proof, "GET", &format!("{URL}?page=2"), None, 1000).is_ok());
    }

    #[test]
    fn a_stale_or_future_proof_is_refused() {
        let proof = make_proof(&key(), "GET", URL, 1000, None, "dpop+jwt");
        assert_eq!(
            verify(&proof, "GET", URL, None, 5000).err(),
            Some(DpopError::Expired)
        );
        assert_eq!(
            verify(&proof, "GET", URL, None, 0).err(),
            Some(DpopError::Expired)
        );
    }

    #[test]
    fn a_plain_jwt_is_not_a_proof() {
        let proof = make_proof(&key(), "GET", URL, 1000, None, "JWT");
        assert_eq!(
            verify(&proof, "GET", URL, None, 1000).err(),
            Some(DpopError::WrongType)
        );
    }

    #[test]
    fn a_tampered_proof_fails_verification() {
        let proof = make_proof(&key(), "GET", URL, 1000, None, "dpop+jwt");
        let mut parts: Vec<&str> = proof.split('.').collect();
        let forged = B64.encode(
            serde_json::to_vec(&serde_json::json!({
                "htm": "DELETE", "htu": URL, "jti": "x", "iat": 1000
            }))
            .unwrap(),
        );
        parts[1] = &forged;
        assert_eq!(
            verify(&parts.join("."), "DELETE", URL, None, 1000).err(),
            Some(DpopError::BadSignature)
        );
    }

    #[test]
    fn thumbprints_are_stable_and_key_specific() {
        let mine = jkt_of(&key());
        let other = SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let theirs = jkt_of(&other);
        assert_ne!(mine, theirs, "the jkt must identify the key");

        let a = make_proof(&key(), "GET", URL, 1000, None, "dpop+jwt");
        assert!(verify(&a, "GET", URL, None, 1000).unwrap().bound_to(&mine));
        assert!(verify(&a, "GET", URL, None, 1000).unwrap().bound_to(&mine));

        let b = make_proof(&other, "GET", URL, 1000, None, "dpop+jwt");
        let different = verify(&b, "GET", URL, None, 1000).unwrap();
        assert!(different.bound_to(&theirs));
        assert!(!different.bound_to(&mine));
    }

    #[test]
    fn a_verified_proof_carries_what_spending_it_needs() {
        let proof = make_proof(&key(), "GET", URL, 1000, None, "dpop+jwt");
        let unspent = verify(&proof, "GET", URL, None, 1000).unwrap();
        assert_eq!(unspent.jti, "unique");
        assert_eq!(unspent.iat, 1000);
        assert_eq!(unspent.jkt, jkt_of(&key()));
    }

    #[test]
    fn replace_swaps_the_value_and_keeps_the_proof() {
        // What verify_access relies on: the claims come from the token, but
        // the proof that has to be spent is still this one.
        let proof = make_proof(&key(), "GET", URL, 1000, None, "dpop+jwt");
        let replaced = verify(&proof, "GET", URL, None, 1000)
            .unwrap()
            .replace("claims");
        assert_eq!(replaced.value, "claims");
        assert_eq!(replaced.jti, "unique");
        assert_eq!(replaced.iat, 1000);
        assert!(replaced.bound_to(&jkt_of(&key())));
    }

    #[test]
    fn a_der_encoded_signature_is_rejected_not_accidentally_accepted() {
        // Guards the P1363 decision: if this ever starts passing, someone has
        // loosened signature parsing and browser clients may silently break.
        let key = key();
        let proof = make_proof(&key, "GET", URL, 1000, None, "dpop+jwt");
        let parts: Vec<&str> = proof.split('.').collect();
        let signature: Signature = key.sign(format!("{}.{}", parts[0], parts[1]).as_bytes());
        let der = B64.encode(signature.to_der().as_bytes());
        let rebuilt = format!("{}.{}.{}", parts[0], parts[1], der);
        assert_eq!(
            verify(&rebuilt, "GET", URL, None, 1000).err(),
            Some(DpopError::BadSignature)
        );
    }

    #[test]
    fn malformed_input_is_an_error_not_a_panic() {
        for bad in ["", "a.b", "a.b.c.d", "not-base64.!!!.???"] {
            assert!(verify(bad, "GET", URL, None, 1000).is_err());
        }
    }
}
```

- [ ] **Step 3: Run them and watch them fail**

```bash
cargo test -p brolly-identity --test dpop_replay
cargo test -p brolly-identity --lib dpop
```

Expected: neither compiles. The errors include `no method named 'spend'`,
`no method named 'bound_to'`, `no method named 'replace'`, and
`no field 'jti' on type 'VerifiedProof'`.

- [ ] **Step 4: The migration**

Create `migrations/20260917000000_identity_dpop_jti.sql`. The spec gives the
name as `<timestamp>_dpop_jti.sql`. `migrations/README.md` rule 2 also requires
the owning crate's prefix, which here is `identity_`.

```sql
-- Every DPoP proof's jti, so a proof is accepted once (RFC 9449).
--
-- Keyed on (jkt, jti), not jti alone. The client picks the jti, and one client's
-- choice must not get another client's proofs refused.
--
-- A row only has to outlive its proof's freshness window, iat + MAX_AGE_SECONDS.
-- `Unspent::spend` (identity/src/dpop.rs) prunes expired rows in the same
-- statement that inserts. It uses the application's clock, not now(), because
-- that is the clock that decides freshness. There is no background job.
CREATE TABLE dpop_jti (
    jkt        TEXT        NOT NULL,
    jti        TEXT        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (jkt, jti)
);
CREATE INDEX dpop_jti_expires ON dpop_jti (expires_at);
```

`identity/build.rs` already reruns `sqlx::migrate!` when `../migrations`
changes, so no source file needs touching.

- [ ] **Step 5: Errors, imports and the module doc**

In `identity/src/dpop.rs`, append this to the module doc after line 23:

```rust
//!
//! A proof is also **single-use**. `verify` can't know whether it has seen a
//! proof before, because that needs the database. So it returns [`Unspent`],
//! and the only way to reach the value inside is [`Unspent::spend`], which
//! records the proof's `jti`. A call site that forgets the replay check doesn't
//! compile.
```

Add to the imports (`:25-30`):

```rust
use sqlx::PgPool;
```

Replace `DpopError` and its `Display` (`:38-69`) with:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpopError {
    Malformed(String),
    /// `typ` was not `dpop+jwt`. A plain JWT must not be accepted as a proof.
    WrongType,
    UnsupportedAlgorithm(String),
    BadSignature,
    /// `htm`/`htu` did not match the request the proof arrived on.
    WrongTarget {
        expected: String,
        found: String,
    },
    Expired,
    /// `ath` missing, or not the hash of the presented access token.
    TokenBindingFailed,
    /// This key has already presented a proof with this `jti`.
    Replayed,
    /// The proof could not be recorded, so it is not accepted.
    ///
    /// Holds the message rather than the `sqlx::Error`, so this enum can stay
    /// `Clone` and `Eq`. Call sites log it and must not send it to the client.
    Storage(String),
}

impl std::fmt::Display for DpopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DpopError::Malformed(m) => write!(f, "malformed DPoP proof: {m}"),
            DpopError::WrongType => write!(f, "proof is not typ=dpop+jwt"),
            DpopError::UnsupportedAlgorithm(a) => write!(f, "unsupported DPoP algorithm {a}"),
            DpopError::BadSignature => write!(f, "DPoP signature does not verify"),
            DpopError::WrongTarget { expected, found } => {
                write!(f, "DPoP proof is for {found}, not {expected}")
            }
            DpopError::Expired => write!(f, "DPoP proof is outside the freshness window"),
            DpopError::TokenBindingFailed => write!(f, "DPoP proof is not bound to this token"),
            DpopError::Replayed => write!(f, "DPoP proof has already been used"),
            DpopError::Storage(e) => write!(f, "could not record the DPoP proof: {e}"),
        }
    }
}
```

In `Claims` (`:89-98`), remove `#[allow(dead_code)]` from `jti`, since `verify`
now reads it:

```rust
#[derive(Debug, Deserialize)]
struct Claims {
    htm: String,
    htu: String,
    jti: String,
    iat: i64,
    #[serde(default)]
    ath: Option<String>,
}
```

- [ ] **Step 6: `Unspent<T>`, with the doctest pair**

Insert after `VerifiedProof` (after `:109`):

```rust
/// A verified value that can't be used until its proof has been recorded.
///
/// The fields are private, and [`Unspent::spend`] is the only way to get the
/// value out. There is no `map`, because a closure could copy the value out.
/// Nor is there `Clone`, `Debug` or `PartialEq`, because each of those would
/// reach the value some other way.
///
/// Spending hands the value over:
///
/// ```
/// use brolly_identity::dpop::{DpopError, Unspent, VerifiedProof};
///
/// async fn thumbprint_of(
///     proof: Unspent<VerifiedProof>,
///     pool: &sqlx::PgPool,
///     now: i64,
/// ) -> Result<String, DpopError> {
///     let verified = proof.spend(pool, now).await?;
///     Ok(verified.thumbprint)
/// }
/// ```
///
/// Reaching past `spend` doesn't compile. This is the example above with that
/// one line changed, so it fails because the field is private, not because of a
/// typo:
///
/// ```compile_fail,E0616
/// use brolly_identity::dpop::{DpopError, Unspent, VerifiedProof};
///
/// async fn thumbprint_of(
///     proof: Unspent<VerifiedProof>,
///     pool: &sqlx::PgPool,
///     now: i64,
/// ) -> Result<String, DpopError> {
///     let verified = proof.value;
///     Ok(verified.thumbprint)
/// }
/// ```
#[must_use = "a verified proof proves nothing until it is spent"]
pub struct Unspent<T> {
    value: T,
    /// Thumbprint of the key that signed the proof.
    jkt: String,
    jti: String,
    iat: i64,
}

/// Record a proof and prune expired ones, in one statement.
///
/// `$3` is the row's expiry and `$4` the prune cutoff. Both come from the
/// application's clock. No row back means the `(jkt, jti)` pair already existed.
const SPEND_JTI: &str = "\
    WITH pruned AS (DELETE FROM dpop_jti WHERE expires_at < to_timestamp($4)) \
    INSERT INTO dpop_jti (jkt, jti, expires_at) \
    VALUES ($1, $2, to_timestamp($3)) \
    ON CONFLICT DO NOTHING \
    RETURNING jti";

impl<T> Unspent<T> {
    /// Record this proof's `jti` and hand over the value.
    ///
    /// **A proof is spent as soon as it is verified, even if the request then
    /// fails**, for example a PAR refused for its client metadata, or a token
    /// request with a bad code. RFC 9449 counts a `jti` as used once it has been
    /// presented. Don't move spending to after the request succeeds: a captured
    /// proof could then be retried until one attempt worked.
    ///
    /// `now` is the application's clock. It sets the row's expiry and decides
    /// which rows are pruned. The database's clock is never used: `verify`
    /// judges freshness by the application's clock, and pruning by a database
    /// clock running ahead would forget a proof that is still fresh.
    ///
    /// Returns [`DpopError::Replayed`] if this key has already used this `jti`,
    /// and [`DpopError::Storage`] if the proof couldn't be recorded. Callers
    /// must treat both as a refusal.
    pub async fn spend(self, pool: &PgPool, now: i64) -> Result<T, DpopError> {
        let recorded: Option<String> = sqlx::query_scalar(SPEND_JTI)
            .bind(self.jkt.as_str())
            .bind(self.jti.as_str())
            .bind(self.iat.saturating_add(MAX_AGE_SECONDS))
            .bind(now.saturating_sub(MAX_AGE_SECONDS))
            .fetch_optional(pool)
            .await
            .map_err(|e| DpopError::Storage(e.to_string()))?;
        match recorded {
            Some(_) => Ok(self.value),
            None => Err(DpopError::Replayed),
        }
    }

    /// Swap the wrapped value for another, keeping the proof that must be
    /// spent. The old value is dropped unread.
    ///
    /// `verify_access` uses this to turn `Unspent<VerifiedProof>` into
    /// `Unspent<AccessClaims>`, because the claims come from the token, not
    /// the proof.
    pub fn replace<U>(self, value: U) -> Unspent<U> {
        Unspent {
            value,
            jkt: self.jkt,
            jti: self.jti,
            iat: self.iat,
        }
    }

    /// Whether the proof was signed by the key with this thumbprint, without
    /// giving the thumbprint out.
    pub fn bound_to(&self, jkt: &str) -> bool {
        self.jkt == jkt
    }
}
```

- [ ] **Step 7: `verify` returns `Unspent`**

Replace `verify` (`:161-230`). The checks and the signature don't change; only
the return type and the final `Ok` do:

```rust
/// Verify a DPoP proof against the request it arrived on.
///
/// `access_token` is `Some` for resource requests, where the proof must carry a
/// matching `ath`, and `None` at the token endpoint, where there is no token to
/// bind to yet.
///
/// Passing every check here doesn't make the proof usable yet. It has not been
/// checked for replay, so it comes back [`Unspent`].
pub fn verify(
    proof: &str,
    method: &str,
    url: &str,
    access_token: Option<&str>,
    now: i64,
) -> Result<Unspent<VerifiedProof>, DpopError> {
    let mut parts = proof.split('.');
    let (Some(header_b64), Some(claims_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(DpopError::Malformed("expected three JWT segments".into()));
    };

    let header: Header = decode_part(header_b64)?;
    if header.typ != "dpop+jwt" {
        // Refusing anything else stops a general-purpose JWT the client holds
        // for another purpose from being replayed as a proof.
        return Err(DpopError::WrongType);
    }
    if header.alg != "ES256" {
        return Err(DpopError::UnsupportedAlgorithm(header.alg));
    }

    let key = verifying_key(&header.jwk)?;
    let signature_bytes = B64
        .decode(signature_b64)
        .map_err(|e| DpopError::Malformed(e.to_string()))?;
    // IEEE P1363, not DER — see the module docs.
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| DpopError::BadSignature)?;

    let signed = format!("{header_b64}.{claims_b64}");
    key.verify(signed.as_bytes(), &signature)
        .map_err(|_| DpopError::BadSignature)?;

    let claims: Claims = decode_part(claims_b64)?;

    if !claims.htm.eq_ignore_ascii_case(method) {
        return Err(DpopError::WrongTarget {
            expected: method.to_string(),
            found: claims.htm,
        });
    }
    if !htu_matches(&claims.htu, url) {
        return Err(DpopError::WrongTarget {
            expected: url.to_string(),
            found: claims.htu,
        });
    }
    if (now - claims.iat).abs() > MAX_AGE_SECONDS {
        return Err(DpopError::Expired);
    }

    match (access_token, claims.ath.as_deref()) {
        (Some(token), Some(ath)) if ath == access_token_hash(token) => {}
        (Some(_), _) => return Err(DpopError::TokenBindingFailed),
        // A proof at the token endpoint carries no ath, which is correct.
        (None, _) => {}
    }

    let jkt = thumbprint(&header.jwk);
    Ok(Unspent {
        value: VerifiedProof {
            thumbprint: jkt.clone(),
            jwk: header.jwk,
        },
        jkt,
        jti: claims.jti,
        iat: claims.iat,
    })
}
```

- [ ] **Step 8: Run the identity crate's tests and watch them pass**

```bash
cargo test -p brolly-identity --lib dpop
cargo test -p brolly-identity --doc dpop
cargo test -p brolly-identity --test dpop_replay
cargo test -p brolly-identity
```

Expected: all pass. The doc run reports two doctests on `Unspent`: the plain
one passes, and the `compile_fail` one passes because it fails to compile.
`-p brolly-identity` builds only this crate and its dependencies, so the broken
call sites elsewhere don't matter yet. `cargo test --workspace` won't compile
until Task 3.

- [ ] **Step 9: Don't commit**

The workspace doesn't compile at this point. Task 3 commits.

---

### Task 3: Every call site spends, and C lands

**Files:**
- Modify: `adapters/solid/src/oidc/tokens.rs:117-149` (`verify_access`), and
  its tests at `:244-263` and a new test after `:352`
- Modify: `server/src/pod.rs:10-17` (imports), `:128-150` (`Credential::Dpop`
  arm of `subject_for`)
- Modify: `server/src/solid_oidc.rs:419-437` (`token`)
- Modify: `server/src/atproto_oauth.rs:61-81` (`proof_thumbprint`), `:150`
  (`par`), `:449` (`token`)
- Modify: `server/src/xrpc.rs:82-120` (`token_caller`)

**How each call site handles the two new errors.** Every one of them fails
closed.

| Call site | `Replayed` | `Storage` |
|---|---|---|
| Solid token endpoint | `400 invalid_dpop_proof`, logged at `warn` | `500 server_error`, logged at `error` |
| ATProto PAR and token (`proof_thumbprint`) | `400 invalid_dpop_proof`, logged at `warn` | `400 invalid_dpop_proof`, logged at `error` (see the notes for the reviewer) |
| Solid resource (`subject_for`, which covers the pod and the ActivityPub inbox GET) | anonymous, logged at `warn` | anonymous, logged at `error` |
| XRPC (`token_caller`) | `None`, so the caller falls back to the cookie and otherwise gets `401`, logged at `warn` | same, logged at `error` |

- [ ] **Step 1: Write the failing unit tests in `tokens.rs`**

In `adapters/solid/src/oidc/tokens.rs`, replace
`a_bound_token_verifies_with_its_own_proof` (`:244-263`) with the test below.
A bound token's claims can't be read without spending, and spending needs the
database. So this test checks which key the claims are held for, and a new
`Bearer` test checks the claims themselves. The HTTP test
`an_app_reads_the_pod_with_the_token_it_was_issued` still covers a bound token's
WebID end to end.

```rust
    #[test]
    fn a_bound_token_verifies_with_its_own_proof() {
        let p = provider();
        let client = client_key(7);
        let token = issue_access(
            &p,
            ISSUER,
            WEBID,
            "urn:uuid:c",
            "webid",
            &jkt_of(&client),
            1000,
        )
        .unwrap();
        let proof = proof_for(&client, "GET", URL, Some(&token), 1000);

        let Access::Bound(unspent) =
            verify_access(&p, &token, Some(&proof), "GET", URL, 1000).unwrap()
        else {
            panic!("a token with cnf.jkt must come back bound to its proof");
        };
        // The claims stay wrapped until the pod spends the proof.
        assert!(unspent.bound_to(&jkt_of(&client)));
    }
```

Add after `an_expired_access_token_is_refused` (`:352`):

```rust
    #[test]
    fn a_token_without_a_binding_is_bearer_and_its_claims_are_readable() {
        // Unchanged behaviour: only cnf.jkt makes a proof necessary, so there
        // is nothing to spend.
        let p = provider();
        let token = p
            .sign(&json!({
                "webid": WEBID,
                "client_id": "urn:uuid:c",
                "scope": "webid",
                "exp": 1000 + ACCESS_TOKEN_TTL,
            }))
            .unwrap();

        let Access::Bearer(claims) = verify_access(&p, &token, None, "GET", URL, 1000).unwrap()
        else {
            panic!("a token without cnf.jkt has no proof to spend");
        };
        assert_eq!(claims.webid, WEBID);
        assert_eq!(claims.client_id, "urn:uuid:c");
        assert_eq!(claims.scope, "webid");
    }
```

The other tests (`a_stolen_token_is_useless_without_the_key`,
`a_bound_token_without_a_proof_is_refused_not_downgraded`,
`a_proof_for_a_different_request_does_not_help`,
`an_expired_access_token_is_refused`) only match on `Err`, so they don't change.

- [ ] **Step 2: Run them and watch them fail**

`cargo test -p brolly-solid --lib oidc::tokens`

Expected: compile error, `cannot find type 'Access' in this scope`, together
with `no field 'thumbprint'` at `:139`, left over from Task 2.

- [ ] **Step 3: `Access` and `verify_access`**

Replace `verify_access` (`:117-149`) with:

```rust
/// What [`verify_access`] found.
pub enum Access {
    /// A token without `cnf.jkt`. Nothing to prove, so nothing to spend.
    Bearer(AccessClaims),
    /// A DPoP-bound token whose proof checked out and was signed by the
    /// token's key. The claims stay wrapped until the proof is spent. Spending
    /// needs the database, and keeping it out of this function keeps this
    /// function synchronous.
    Bound(dpop::Unspent<AccessClaims>),
}

/// Verify an access token **and** the proof that it belongs to this caller.
///
/// Both or neither: a token whose `cnf.jkt` does not match the proof's key was
/// not presented by its holder, and a bound token with no proof at all is
/// refused rather than downgraded to bearer semantics. Downgrading is the
/// mistake that makes DPoP decorative.
///
/// A bound token comes back as [`Access::Bound`]. Its claims are reachable only
/// by spending the proof, so the caller can't skip the replay check.
pub fn verify_access(
    key: &ProviderKey,
    token: &str,
    proof: Option<&str>,
    method: &str,
    url: &str,
    now: i64,
) -> Result<Access, TokenError> {
    let claims = key.verify(token, now)?;
    let access = AccessClaims {
        webid: claims["webid"].as_str().unwrap_or_default().to_string(),
        client_id: claims["client_id"].as_str().unwrap_or_default().to_string(),
        scope: claims["scope"].as_str().unwrap_or_default().to_string(),
    };

    let Some(jkt) = claims["cnf"]["jkt"].as_str() else {
        return Ok(Access::Bearer(access));
    };
    let Some(proof) = proof else {
        return Err(TokenError::ProofRequired);
    };
    let verified = dpop::verify(proof, method, url, Some(token), now)?;
    if !verified.bound_to(jkt) {
        return Err(TokenError::WrongHolder);
    }
    // The proof's own value is dropped unread; the claims are the token's.
    Ok(Access::Bound(verified.replace(access)))
}
```

- [ ] **Step 4: Run them and watch them pass**

`cargo test -p brolly-solid --lib oidc::tokens`

Expected: PASS.

- [ ] **Step 5: `subject_for` spends**

In `server/src/pod.rs`, add to the imports (`:10-17`):

```rust
use brolly_identity::dpop::DpopError;
```

Replace the `Credential::Dpop { token, proof } => { ... }` arm (`:128-150`)
with:

```rust
        Credential::Dpop { token, proof } => {
            // Token and proof are verified together or not at all: a token whose
            // `cnf.jkt` does not match the proof was not presented by its holder,
            // and a bound token with no proof is refused rather than downgraded
            // to bearer semantics.
            //
            // A bound token's claims arrive `Unspent`. Spending records the proof
            // so it can't be sent again. A replay, or a failure to record the
            // proof, leaves the caller anonymous, like any other bad proof.
            let proof = (!proof.is_empty()).then_some(proof);
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let claims = match tokens::verify_access(
                &state.provider_key,
                &token,
                proof.as_deref(),
                method,
                url,
                now,
            ) {
                Ok(tokens::Access::Bearer(claims)) => claims,
                Ok(tokens::Access::Bound(unspent)) => match unspent.spend(&state.pool, now).await {
                    Ok(claims) => claims,
                    Err(DpopError::Storage(e)) => {
                        tracing::error!(error = %e, "recording a DPoP proof failed");
                        return anonymous;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Solid access token proof refused");
                        return anonymous;
                    }
                },
                Err(e) => {
                    tracing::debug!(error = %e, "Solid access token rejected");
                    return anonymous;
                }
            };
            solid_subject(state, claims).await.unwrap_or(anonymous)
        }
```

`subject_for` is also what `inbox_collection` (`server/src/activitypub.rs:289`)
calls, so the ActivityPub inbox GET is covered without touching that file. Each
pod handler calls `resolve` (`pod.rs:239`, `:281`, `:313`, `:345`, `:408`)
exactly once, so no request spends its own proof twice.

- [ ] **Step 6: The Solid token endpoint spends**

In `server/src/solid_oidc.rs`, replace the proof check in `token`
(`:427-437`, from `let jkt = match dpop::verify` to the closing `};`) with:

```rust
    let at = now();
    let unspent = match dpop::verify(proof, "POST", &url, None, at) {
        Ok(unspent) => unspent,
        Err(e) => {
            tracing::warn!(error = %e, "DPoP proof rejected at the token endpoint");
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_dpop_proof",
                &e.to_string(),
            );
        }
    };
    // Spent before the grant is looked at: a request that fails later has still
    // used its proof (see `Unspent::spend`).
    let jkt = match unspent.spend(&state.pool, at).await {
        Ok(verified) => verified.thumbprint,
        Err(dpop::DpopError::Storage(e)) => {
            tracing::error!(error = %e, "recording a DPoP proof failed");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "could not check the DPoP proof",
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "DPoP proof refused at the token endpoint");
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_dpop_proof",
                &e.to_string(),
            );
        }
    };
```

`dpop` here is `brolly_solid::oidc::dpop`, which re-exports
`brolly_identity::dpop`, so `dpop::DpopError` resolves. The local is named `at`
so it doesn't shadow `fn now()`.

- [ ] **Step 7: ATProto's `proof_thumbprint` becomes async and spends**

In `server/src/atproto_oauth.rs`, change the import at `:28`:

```rust
use brolly_identity::dpop::{self, DpopError};
use brolly_identity::extract;
```

Replace `proof_thumbprint` (`:61-81`) with:

```rust
/// Verify and spend the DPoP proof on a request to one of these endpoints.
///
/// Returns the key thumbprint the token will be bound to.
/// `Option`, not `Result<_, Response>`: a `Response` is a large `Err` to
/// carry, and both callers want the same error anyway — [`missing_proof`].
///
/// The proof is spent before anything else about the request is checked, so a
/// request refused later has still used it (see `Unspent::spend`). A failure to
/// record the proof refuses the request too. It is logged at `error` so it
/// isn't mistaken for a client's mistake.
async fn proof_thumbprint(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    path: &str,
) -> Option<String> {
    let proof = headers.get("dpop").and_then(|h| h.to_str().ok())?;
    let url = format!("https://{}{path}", state.base_domain);
    let at = now();
    let unspent = match dpop::verify(proof, method, &url, None, at) {
        Ok(unspent) => unspent,
        Err(e) => {
            tracing::warn!(error = %e, "DPoP proof rejected");
            return None;
        }
    };
    match unspent.spend(&state.pool, at).await {
        Ok(verified) => Some(verified.thumbprint),
        Err(DpopError::Storage(e)) => {
            tracing::error!(error = %e, "recording a DPoP proof failed");
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "DPoP proof refused");
            None
        }
    }
}
```

In `par` (`:150`) and `token` (`:449`), add `.await`:

```rust
    let Some(jkt) = proof_thumbprint(&state, &headers, "POST", "/oauth/atproto/par").await else {
        return missing_proof();
    };
```

```rust
    let Some(jkt) = proof_thumbprint(&state, &headers, "POST", "/oauth/atproto/token").await else {
        return missing_proof();
    };
```

- [ ] **Step 8: XRPC's `token_caller` spends**

In `server/src/xrpc.rs`, replace the proof check in `token_caller` (`:99-113`,
from the `// The proof must be for this request` comment through the closing
`}` of the thumbprint check) with:

```rust
    // The proof must be for this request, must name the key the token was
    // issued to, and must not have been presented before.
    let proof = headers.get("dpop").and_then(|h| h.to_str().ok())?;
    let url = format!("https://{}/xrpc/", state.base_domain);
    let method = "POST";
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let unspent = brolly_identity::dpop::verify(proof, method, &url, Some(&token), now).ok()?;
    if !unspent.bound_to(&grant.dpop_jkt) {
        tracing::warn!("an ATProtocol token was presented by a key it was not issued to");
        return None;
    }
    match unspent.spend(&state.pool, now).await {
        Ok(_) => {}
        Err(brolly_identity::dpop::DpopError::Storage(e)) => {
            tracing::error!(error = %e, "recording a DPoP proof failed");
            return None;
        }
        Err(e) => {
            tracing::warn!(error = %e, "an ATProtocol DPoP proof was refused");
            return None;
        }
    }
```

`caller` is called once per handler (`create_record` at `:420` and
`delete_record` at `:534`), so no request spends its proof twice.

- [ ] **Step 9: Run Task 1's tests and watch them pass**

```bash
cargo test -p brolly-server --test solid_oidc_flow a_token_endpoint_proof_is_good_for_one_request
cargo test -p brolly-server --test solid_token_access a_resource_proof_is_good_for_one_request
cargo test -p brolly-server --test atproto_oauth a_par_proof_is_good_for_one_request
cargo test -p brolly-server --test xrpc an_xrpc_write_proof_is_good_for_one_request
```

Expected: PASS, all four.

Then run the whole of each DPoP test file. Every existing proof helper mints a
fresh `jti`, so none of them should start failing:

```bash
cargo test -p brolly-server --test solid_oidc_flow --test solid_token_access --test atproto_oauth --test xrpc --test dashboard
```

Expected: PASS.

- [ ] **Step 10: Gates**

Run `cargo fmt --all` first. Some of the code above has lines longer than
rustfmt allows, for example the `Bound` arm in `pod.rs` and the helper
signatures in `xrpc.rs`. Formatting changes layout only. Then:

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

Expected: all green. `cargo test --workspace` includes the doctests, so the
`compile_fail` pair runs here too. No `Cargo.toml` changes, so no
`cargo deny check`.

- [ ] **Step 11: Commit**

```bash
git add migrations/20260917000000_identity_dpop_jti.sql \
  identity/src/dpop.rs identity/tests/dpop_replay.rs \
  adapters/solid/src/oidc/tokens.rs \
  server/src/pod.rs server/src/solid_oidc.rs server/src/atproto_oauth.rs server/src/xrpc.rs \
  server/tests/solid_oidc_flow.rs server/tests/solid_token_access.rs \
  server/tests/atproto_oauth.rs server/tests/xrpc.rs
git commit -m "$(cat <<'EOF'
fix(dpop): a proof is good for one request

dpop::verify parsed jti and never checked it, so a captured proof worked
for MAX_AGE_SECONDS either side of its iat: at the Solid and ATProto
token endpoints, at PAR, on every pod read and write, and on XRPC writes.

verify now returns Unspent<VerifiedProof>. The value is reachable only
through spend, which records (jkt, jti) in the new dpop_jti table, so a
call site that skips the replay check does not compile. Pruning runs in
the same statement, using the application's clock, because that is the
clock that decides freshness.

A replay gets the same refusal as any other bad proof. A storage failure
fails closed.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 12: Verify the commit from a clean checkout**

```bash
rm -rf /tmp/verify && git worktree add --detach /tmp/verify HEAD
cd /tmp/verify && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings
cd - && git worktree remove /tmp/verify --force
```

Green there, or the commit isn't done. The first build in a fresh worktree takes
a few minutes, so run it in the background rather than skip it. This matters
more than usual for this commit. The migration is a new file that only the
`sqlx::migrate!` expansion picks up, and a clean checkout is the one place a
stale expansion can't hide.

---

### Notes for the reviewer

1. **At ATProto PAR and token, a storage failure gets `400 invalid_dpop_proof`,
   not `500 server_error`.** The spec says token endpoints answer
   `500 server_error` when storage fails. But the cross-chunk interface fixes
   `proof_thumbprint` as `async fn ... -> Option<String>`, and Chunk 5 (B) calls
   it that way, so it can't carry the difference. The request still fails
   closed, and the failure is logged at `error`, not `warn`. The Solid token
   endpoint does return `500`. If `500` matters here, change the return type to
   a small `enum Proof { Spent(String), Refused, Unavailable }` in both this
   chunk and Chunk 5.
2. **The migration is named `20260917000000_identity_dpop_jti.sql`**, not
   `<timestamp>_dpop_jti.sql`. `migrations/README.md` rule 2 requires the
   owning crate's prefix. No earlier chunk adds a migration, so the timestamp
   doesn't collide.
3. **C lands as one commit, with its tests (Tasks 1 to 3).** This matches
   Rollout step 3. Changing `verify`'s return type breaks every call site, so
   there's no smaller commit that compiles. The HTTP replay tests are written
   first so they're seen to fail, but they aren't committed on their own
   because that would put a red commit on `main`.
4. **`Unspent` has no `Debug`, `Clone` or `PartialEq`, and it is
   `#[must_use]`.** The spec only says "there is no other way to get `T` out".
   Each of those traits would be another way. So the existing `dpop.rs` unit
   tests change from `assert_eq!(verify(..), Err(..))` to
   `assert_eq!(verify(..).err(), Some(..))`, beyond the `.thumbprint` rewrites
   the spec lists. The assertions themselves don't change.
5. **In `token_caller`, the key is checked before the proof is spent.** A proof
   from the wrong key is refused without being recorded. This matches
   `verify_access`, which has to decide `WrongHolder` before returning
   `Unspent`, so the spec already has this order there. A wrong-key proof can't
   authenticate anyone, so leaving it unrecorded opens nothing. The spec's "spent
   as soon as it's verified" is read as "before the request's own checks", which
   is where both token endpoints and PAR spend.
6. **The `tokens.rs` unit test for a bound token no longer checks `webid` and
   `scope`.** Reading them needs `spend`, which needs a database, and the spec
   keeps these tests database-free. The test now checks `bound_to`. A new
   `Bearer` unit test checks claim extraction, and
   `an_app_reads_the_pod_with_the_token_it_was_issued` still checks a bound
   token's WebID over HTTP.
7. **For Chunk 5 (B): the XRPC replay test runs a real PAR with
   `https://app.example/client-metadata.json` in `server/tests/xrpc.rs`.** When
   B threads `clients` through every `AppState`, that file's `StaticClients`
   has to register this client the same way `server/tests/atproto_oauth.rs`
   does. Otherwise `an_xrpc_write_proof_is_good_for_one_request` fails at PAR
   with `invalid_client`.
8. **Each replay test sends a third request with a fresh proof and expects it
   to succeed.** The spec only asks that the replay be refused. The third
   request shows the refusal came from the reused `jti`, not from the code,
   refresh token, token or pushed request being used up. At the Solid token
   endpoint the replayed request is a valid refresh, so the test also shows the
   proof is checked before the grant is touched.
9. **The `iat + MAX_AGE_SECONDS` and `now - MAX_AGE_SECONDS` parameters use
   `saturating_add` and `saturating_sub`.** `verify` has already kept `iat`
   within 60 seconds of `now`, so saturation should never happen. It only stops
   a debug-build overflow panic on hostile input. Library crates deny `panic`,
   and an arithmetic overflow is one in spirit.
10. **A storage failure is tested by closing the pool**
    (`a_storage_failure_refuses_the_proof`). The spec only says storage failures
    fail closed. At the adapter level this checks that `spend` returns
    `Storage`, not `Ok`. How each call site maps `Storage` is in Task 3's table
    and has no HTTP-level test, because the test harness can't break the
    database halfway through a request.


## Chunk 4: Outbound HTTPS (B0)

**Spec:** `docs/specs/2026-09-17-security-fixes.md`, § B0, and problem 5.

Right now `reqwest` is declared with `default-features = false, features = ["json"]` in
both `server/Cargo.toml:45` and `adapters/atproto/Cargo.toml:36`. No TLS
backend is compiled in (`Cargo.lock`'s `reqwest 0.13.4` entry lists no
`rustls`, `hyper-rustls` or `tokio-rustls`), so every `https://` request fails
at send time. The only production callers today are:

- `server/src/main.rs:90-92`: `plc_client` is built with `reqwest::Client::new` when
  `BROLLY_PLC_SUBMIT` is set, and is used by `provision.rs:109` to call
  `brolly_atproto::plc::submit`.
- `server/src/bin/admin.rs:236`: `plc-retry` builds a `reqwest::Client::new()` and
  calls `brolly_atproto::plc::submit` (`adapters/atproto/src/plc.rs:582`). That
  posts to `https://plc.directory/{did}` (`plc.rs:239-241`).

Both have never been able to reach the directory. After this chunk they can.

**What changes underneath.** `rustls-no-provider` makes reqwest's
`ClientBuilder::build` look up `rustls::crypto::CryptoProvider::get_default()`.
If no provider is installed it hits `default_rustls_crypto_provider()`, which
**panics** ("No rustls crypto provider is configured…"). See
`reqwest-0.13.4/src/async_impl/client.rs:719-721` and `:2482-2491`.
`Client::new()` is `ClientBuilder::new().build().expect(..)`, so either way the
process dies. The provider has to be installed before any client is built.
That's why `install_crypto_provider()` is the first statement of both `main`s.

**The lib crate is `brolly_server`** (`server/Cargo.toml` `[lib] name =
"brolly_server"`). Both binaries and every integration test reach the new
function as `brolly_server::tls::install_crypto_provider()`.

**Existing tests that build a reqwest client: none.** Every hand-built
`AppState` in `server/tests/*.rs` sets `plc_client: None`. No file under
`server/tests`, `adapters/*/src`, `adapters/*/tests`, `identity` or
`test-support` calls `reqwest::Client::new`/`builder`. The only non-binary use
is the `&reqwest::Client` parameter of `plc::submit` and `provision`. The
`activitypub_federation` crate links reqwest, but brolly only uses its
`http_signatures::generate_actor_keypair` (`adapters/activitypub/src/keys.rs:15`),
which never builds a client. Step 7 re-checks this with a grep so the claim is
verified rather than assumed. Chunk 5 (B) is the first to add a test-built
client, and it calls the function this chunk adds.

### Task 1: Outbound HTTPS works

One commit, as the spec's rollout requires ("Its own commit").

**Files:**
- Modify: `server/Cargo.toml:45` (reqwest features), add `rustls` after `:45`,
  and add `rcgen` to `[dev-dependencies]` (`:54-78`)
- Modify: `adapters/atproto/Cargo.toml:32-36` (reqwest features and its comment)
- Modify: `Cargo.lock` (regenerated by cargo)
- Create: `server/src/tls.rs`
- Modify: `server/src/lib.rs:29-30` (`pub mod tls;` between `solid_oidc` and `xrpc`)
- Modify: `server/src/main.rs:6-9` (first statement of `main`)
- Modify: `server/src/bin/admin.rs:42-43` (first statement of `main`)
- Test: `server/src/tls.rs` (`#[cfg(test)] mod tests`)

- [ ] **Step 1: Add the test-only dependencies, and write the failing tests**

The tests need `rustls` for the local server and `rcgen` for the test CA. Add
those two dependencies now, but **not** the reqwest feature. That way Step 2
fails for the right reason.

In `server/Cargo.toml`, directly after the `reqwest = …` line (`:45`), add:

```toml
# Named directly only to reach `rustls::crypto::ring` and install it as the
# process-wide provider (server/src/tls.rs). It resolves to the same 0.23 copy
# reqwest and sqlx already link, and ring 0.17 is already in the tree. The
# `rustls` reqwest feature would pull in aws-lc-rs and a second C build instead.
rustls = { version = "0.23", default-features = false, features = ["ring", "std"] }
```

In `server/Cargo.toml` `[dev-dependencies]`, after `serde_json = "1.0.151"`
(`:78`), add:

```toml
# A throwaway CA and a leaf for `localhost`, generated on every run, so the TLS
# handshake test has no fixture to expire. `ring`, not the default aws-lc-rs,
# so it adds no C build.
rcgen = { version = "0.13", default-features = false, features = ["crypto", "ring"] }
```

Create `server/src/tls.rs`. For now `install_crypto_provider` is a no-op
stub, so the file compiles once the reqwest feature lands in Step 3:

```rust
//! Outbound TLS.
//!
//! reqwest is built with `rustls-no-provider`, the only TLS option it has that
//! avoids aws-lc-rs. That means no rustls crypto provider is chosen at compile
//! time, and building a `reqwest::Client` **panics** until one is installed.
//! [`install_crypto_provider`] installs ring. Both binaries call it as their
//! first statement, and so does every test that builds a client.
//!
//! Root certificates come from `rustls-platform-verifier`, which reads the OS
//! store. The runtime image installs `ca-certificates` for that (`Dockerfile`).

/// Install ring as the process-wide rustls crypto provider.
///
/// Idempotent. rustls allows exactly one install per process and reports a
/// second one as an error. That error is ignored: ring is the only provider
/// compiled into this binary, so "already installed" can only mean "already
/// installed by us". Tests call this from many threads in one process, so
/// the second call being harmless is required, not just convenient.
pub fn install_crypto_provider() {}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::Arc;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    use super::*;

    /// A CA, and a certificate for `localhost` it signed.
    struct Pki {
        ca: CertificateDer<'static>,
        leaf: CertificateDer<'static>,
        leaf_key: PrivateKeyDer<'static>,
    }

    /// Generated per run: a committed fixture would expire, and then the test
    /// would fail for reasons unrelated to what it checks.
    fn pki() -> Pki {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let mut leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();

        Pki {
            ca: ca.der().clone(),
            leaf: leaf.der().clone(),
            leaf_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        }
    }

    /// Answer one HTTPS request with `200 ok`, on its own thread. Returns the
    /// address it listens on.
    ///
    /// Plain blocking rustls rather than tokio-rustls, so it needs no dependency
    /// beyond the one the server already has. The server uses its own explicit
    /// provider, so it can't be what makes the client side work.
    fn serve_once(leaf: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> SocketAddr {
        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf], key)
            .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        std::thread::spawn(move || {
            // No unwraps in here. A refused handshake is the expected outcome
            // of one test and shows up as a read error. The thread just ends,
            // and the assertion that matters is on the client's side.
            let Ok((socket, _)) = listener.accept() else {
                return;
            };
            let Ok(conn) = rustls::ServerConnection::new(config) else {
                return;
            };
            let mut tls = rustls::StreamOwned::new(conn, socket);
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                match tls.read(&mut byte) {
                    Ok(1) => head.push(byte[0]),
                    _ => return,
                }
            }
            let _ = tls.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
            );
            tls.conn.send_close_notify();
            let _ = tls.flush();
        });

        addr
    }

    /// A client trusting only `roots`, with `localhost` pinned to `addr`.
    ///
    /// `resolve` so the test never depends on whether `localhost` resolves to
    /// `::1` or `127.0.0.1` first. The URL's port is the one used.
    fn client_trusting(roots: &[&CertificateDer<'static>], addr: SocketAddr) -> reqwest::Client {
        reqwest::Client::builder()
            .tls_certs_only(
                roots
                    .iter()
                    .map(|der| reqwest::Certificate::from_der(der).unwrap()),
            )
            .resolve("localhost", addr)
            .no_proxy()
            .build()
            .unwrap()
    }

    #[test]
    fn installing_the_provider_twice_is_harmless() {
        install_crypto_provider();
        install_crypto_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }

    /// Exactly the constructor `main.rs` (`plc_client`) and `brolly-admin
    /// plc-retry` use. With `rustls-no-provider` and no provider installed,
    /// this panics inside reqwest.
    #[test]
    fn a_client_builds_once_the_provider_is_installed() {
        install_crypto_provider();
        let _client = reqwest::Client::new();
    }

    /// Nothing may be `#[ignore]`d, so no call to a real host. A real handshake
    /// against a local server proves the same thing: the TLS stack reqwest
    /// was compiled with verifies a chain and completes a request.
    #[tokio::test]
    async fn https_completes_against_a_trusted_root() {
        install_crypto_provider();
        let pki = pki();
        let addr = serve_once(pki.leaf, pki.leaf_key);
        let client = client_trusting(&[&pki.ca], addr);

        let response = client
            .get(format!("https://localhost:{}/", addr.port()))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "ok");
    }

    /// Without this, the test above would also pass against a client that
    /// verifies nothing.
    #[tokio::test]
    async fn https_refuses_a_certificate_from_an_untrusted_root() {
        install_crypto_provider();
        let served = pki();
        let stranger = pki();
        let addr = serve_once(served.leaf, served.leaf_key);
        let client = client_trusting(&[&stranger.ca], addr);

        let result = client
            .get(format!("https://localhost:{}/", addr.port()))
            .send()
            .await;

        assert!(result.is_err(), "an unknown issuer was accepted: {result:?}");
    }
}
```

In `server/src/lib.rs`, between `pub mod solid_oidc;` (`:29`) and
`pub mod xrpc;` (`:30`), add:

```rust
pub mod tls;
```

- [ ] **Step 2: Run it and watch it fail**

```bash
cargo test -p brolly-server --lib tls::
```

Expected: **compile error**, `no method named `tls_certs_only` found for struct
`ClientBuilder``. That method is `#[cfg(feature = "__tls")]`
(`reqwest-0.13.4/src/async_impl/client.rs:1878-1885`), and no TLS feature is on.
This is problem 5 as a compiler error: this reqwest can't do TLS at all. The
first build downloads `rcgen`, `yasna` and their dependencies, so it needs
network.

- [ ] **Step 3: Turn on reqwest's TLS, and watch the provider tests fail**

`server/Cargo.toml:45`, replace:

```toml
reqwest = { version = "0.13.4", default-features = false, features = ["json"] }
```

with:

```toml
# `rustls-no-provider`, not `rustls`: the latter compiles aws-lc-rs, a second C
# build next to RocksDB. Without a provider, building a Client panics, so both
# binaries call `tls::install_crypto_provider()` first. Roots come from
# rustls-platform-verifier (the OS store; `ca-certificates` in the image).
reqwest = { version = "0.13.4", default-features = false, features = ["json", "rustls-no-provider"] }
```

`adapters/atproto/Cargo.toml:32-36`. Keep the existing three-line comment and
replace only the `reqwest = …` line (`:36`) with:

```toml
# `rustls-no-provider`: PLC submission is https-only, and without a TLS feature
# every request to plc.directory failed. This crate builds no Client itself.
# The binary that passes one in installs the crypto provider (server/src/tls.rs).
reqwest = { version = "0.13.4", default-features = false, features = ["json", "rustls-no-provider"] }
```

The feature is declared here as well as in `server`, although unification
would turn it on anyway. That way the crate that calls `https://plc.directory`
states that it needs TLS, and a future split of the workspace can't silently
remove it.

Run:

```bash
cargo test -p brolly-server --lib tls::
```

This first build adds `rustls-platform-verifier` and its dependencies to
`Cargo.lock`, which needs network. Expected: it compiles, and
`installing_the_provider_twice_is_harmless` fails its assertion. The other three
panic with reqwest's
`No rustls crypto provider is configured. When using the `rustls-no-provider` feature you must install a crypto provider before building a Client.`
That's the panic `main.rs` and `brolly-admin` would hit if they didn't install
one.

- [ ] **Step 4: Implement**

In `server/src/tls.rs`, replace the stub:

```rust
pub fn install_crypto_provider() {}
```

with:

```rust
pub fn install_crypto_provider() {
    let _already_installed = rustls::crypto::ring::default_provider().install_default();
}
```

(`install_default` returns `Result<(), Arc<CryptoProvider>>`.
`rustls-0.23.43/src/crypto/mod.rs:227`. Binding the result to a named `_`
variable discards it without `unwrap`. The workspace lints forbid `unwrap`.)

- [ ] **Step 5: Run it and watch it pass**

```bash
cargo test -p brolly-server --lib tls::
```

Expected: 4 passed.

- [ ] **Step 6: Install the provider in both binaries**

`server/src/main.rs`. Replace lines 6-9:

```rust
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Structured logging from the first line. No `println!` anywhere in the
    // workspace — the lint denies it (implementation plan §5).
    tracing_subscriber::fmt()
```

with:

```rust
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Before anything can build a reqwest client: with `rustls-no-provider`,
    // building one without a provider panics. It comes before logging too,
    // so no future edit can add a client above it.
    brolly_server::tls::install_crypto_provider();

    // Structured logging from the first line. No `println!` anywhere in the
    // workspace — the lint denies it (implementation plan §5).
    tracing_subscriber::fmt()
```

`server/src/bin/admin.rs`. Replace lines 42-43:

```rust
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
```

with:

```rust
async fn main() -> ExitCode {
    // `plc-retry` builds a reqwest client, and with `rustls-no-provider` that
    // panics until a provider is installed. First, so no command can get ahead of it.
    brolly_server::tls::install_crypto_provider();

    let args: Vec<String> = std::env::args().skip(1).collect();
```

Leave `main.rs:92` (`.then(reqwest::Client::new)`) and `admin.rs:236`
(`reqwest::Client::new()`) unchanged. They now run after the install.

```bash
cargo build -p brolly-server --bins
```

Expected: builds.

- [ ] **Step 7: Confirm no other client is built without the provider**

```bash
grep -rn "Client::new\|Client::builder\|ClientBuilder::new\|Client::default" \
  --include='*.rs' server adapters identity store authz domain test-support
```

Expected: only `server/src/main.rs`, `server/src/bin/admin.rs` and the tests in
`server/src/tls.rs`. If anything else appears, it's a client built outside
`main`. Add `brolly_server::tls::install_crypto_provider();` as the first line
of that test, or of its harness setup function. An adapter crate has no
`rustls` dependency, so in an adapter, move the construction to the server
instead.

- [ ] **Step 8: Check the supply chain**

```bash
cargo deny check
```

Expected: `advisories ok, bans ok, licenses ok, sources ok`. You may see new
`multiple-versions` **warnings**, which are allowed (`deny.toml` `[bans]`).
`rustls-platform-verifier` and `rcgen` are `MIT OR Apache-2.0`. `yasna` is
`MIT OR Apache-2.0`. `webpki-root-certs`, if it arrives, is
`CDLA-Permissive-2.0`, which is already allowed.

If a license is refused, check which crate brings it with `cargo tree -i <crate>
--target all`. Add it to `[licenses] allow` only if it is permissive and
OSI-approved, with a comment naming that crate, as the existing
`CDLA-Permissive-2.0` entry does. Anything else: stop and raise it. Don't
widen the list to get green.

Also confirm that the only provider compiled in is ring. `install_crypto_provider`'s
doc comment relies on this, and so does sqlx's `ClientConfig::builder()`:

```bash
cargo tree -p brolly-server -e features -i aws-lc-rs --target all
```

Expected: `error: package ID specification `aws-lc-rs` did not match any
packages` (or no output). If aws-lc-rs is present, something enabled reqwest's
`rustls` feature. Find it and remove it.

- [ ] **Step 9: Gates**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo deny check
```

- [ ] **Step 10: Commit**

```bash
git add server/Cargo.toml adapters/atproto/Cargo.toml Cargo.lock \
  server/src/tls.rs server/src/lib.rs server/src/main.rs server/src/bin/admin.rs
git commit -F - <<'MSG'
fix(tls): outbound HTTPS works, so PLC submission reaches the directory

reqwest was built with no TLS backend, so every https request failed.
BROLLY_PLC_SUBMIT and `brolly-admin plc-retry` could never register a
did:plc with plc.directory, and validating ATProto OAuth clients needs to
fetch their metadata over https.

reqwest now uses `rustls-no-provider` in brolly-server and brolly-atproto, and
the server installs ring as the rustls crypto provider first thing in both
binaries (`tls::install_crypto_provider`, idempotent). The `rustls` feature
would have compiled aws-lc-rs. Roots come from the OS store through
rustls-platform-verifier.

Tested with a real handshake against a local rustls server whose certificate
comes from a CA generated at test time, a refusal of an untrusted root, and a
check that `Client::new()` builds once the provider is installed.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

Then verify from a clean checkout:

```bash
rm -rf /tmp/verify && git worktree add --detach /tmp/verify HEAD
cd /tmp/verify && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo deny check
cd - && git worktree remove /tmp/verify --force
```

Green there, or the commit is not done. Here the clean checkout also catches
a `Cargo.lock` that was left out of `git add`.

**How this shows PLC submission is fixed, without the network.** `plc::submit`
does a single `client.post(https://plc.directory/…)` with the client it's given.
Its URL is hard-coded, and a local server can't stand in for `plc.directory:443`
without binding a privileged port. So the fix is shown in two parts that
together cover the path:

1. `a_client_builds_once_the_provider_is_installed` runs exactly the
   constructor `main.rs:92` and `admin.rs:236` use, in the same order the
   binaries now run it.
2. `https_completes_against_a_trusted_root` shows that same reqwest build
   completing a verified TLS request. Before this commit, the request was
   impossible: Step 2's compile error.

The only thing the unit tests don't cover is the platform verifier's reading
of the OS store. Covering it needs a public host. An operator can check it on
a deployed instance with `brolly-admin plc-retry --dry-run`, and then without
`--dry-run`. The last message should be about the directory's answer, not
`Unreachable(... scheme is not http ...)`. That check is optional and not a gate.

### Notes for the reviewer

- **Test CA: `rcgen` dev-dependency, not committed PEM fixtures.** `rcgen` is
  not in `Cargo.lock` today, but it's in the local registry cache (0.13.2), and
  with `default-features = false, features = ["crypto", "ring"]` it adds only
  `rcgen` and `yasna`. It reuses the ring, time and rustls-pki-types already in
  the tree, with no aws-lc-rs and no `pem` crate. Both are `MIT OR Apache-2.0`,
  so `cargo deny` stays green. Static fixtures would need a `not_after` far in
  the future. They'd also need exactly the extensions webpki insists on (CA
  basicConstraints, leaf SAN, serverAuth EKU), written by hand in a tool
  outside the repo that can't be checked here. And they'd be opaque in review.
  Generating at test time keeps every property the test depends on visible in
  the test itself.
- **Test server: blocking `rustls::StreamOwned` on a `std::thread`, not
  `tokio-rustls`.** It needs no dependency beyond the `rustls` the spec already
  adds. The server config uses `builder_with_provider(ring)` explicitly, so it
  never installs the process default. That's what lets Step 3 show the
  client-side panic honestly.
- **A fourth test beyond the spec's two:** `https_refuses_a_certificate_from_an_untrusted_root`.
  Without it, the handshake test would also pass against a client that
  verified nothing. `installing_the_provider_twice_is_harmless` makes the
  spec's "calling it twice is harmless" executable. Both are small and
  local, and neither is `#[ignore]`d.
- **The handshake client uses `.resolve("localhost", addr)` and `.no_proxy()`.**
  The spec forbids `resolve` for the production `Fetcher` (B). This is a
  test-only client, and pinning it avoids depending on the order `localhost`
  resolves in, or on a proxy in the CI environment.
- **"Every test that builds a reqwest client" is currently the empty set**
  outside `tls.rs`. Every `AppState` in `server/tests` uses `plc_client: None`.
  No integration test is modified. Step 7 checks this with a grep rather than
  trusting this plan. Chunk 5 is the first to need the call in an integration test.
- **`install_crypto_provider` binds the result to `_already_installed`**
  rather than distinguishing "already installed, ring" from "already installed,
  something else". The spec says to ignore "already installed", and ring is
  the only provider compiled in. Step 8's `cargo tree -i aws-lc-rs` guards that
  assumption.
- **`adapters/atproto` gets the feature but no provider call.** It's a library
  crate that builds no client, so it has nothing to install and no `rustls`
  dependency. The spec's feature list applies to it, and the binary installs
  the provider.
- **Placement "first thing":** the call goes before `tracing_subscriber`
  initialisation in `main.rs`, and before argument parsing in `admin.rs`, so
  even `--help` runs after it. It costs nothing and does no I/O.
- **The Dockerfile is unchanged:** the runtime stage already installs
  `ca-certificates`, and the build stage already has the C toolchain ring
  needs. ring is already built there for sqlx.
- **The PLC fix is verified at unit level only** (see the end of Task 1). An
  https request to the real `plc.directory` can't be a test without the
  network, and `plc::submit`'s hard-coded URL can't be redirected to a local
  server without binding port 443.
- **Network for the first build:** `rustls-platform-verifier` is not in the
  local registry cache, so Steps 2-3 need crates.io access once. After that
  the lock pins it.


## Chunk 5: ATProto OAuth validates clients (B)

Closes hole 3: PAR (`server/src/atproto_oauth.rs::par`) accepts any `client_id`
starting with `https://` (`is_valid_client_id`, `adapters/atproto/src/oauth.rs:252`),
never fetches the client's metadata, and stores whatever `redirect_uri` it is
given. Anyone who gets a member to approve the consent screen gets a token for
their repo, and the endpoint is an open redirect.

**Assumes chunks 1–4 are merged.** In particular:

- Chunk 3 (C) made `proof_thumbprint` async:
  `async fn proof_thumbprint(state: &AppState, headers: &HeaderMap, method: &str, path: &str) -> Option<String>`.
  PAR therefore starts `let Some(jkt) = proof_thumbprint(&state, &headers, "POST", "/oauth/atproto/par").await else { return missing_proof(); };`.
  Keep whatever chunk 3 left for that line; Task 4 below replaces only what
  follows it.
- Chunk 4 (B0) gave `server` and `adapters/atproto` the reqwest feature
  `rustls-no-provider` and added `server/src/tls.rs` with
  `pub fn install_crypto_provider()` (idempotent). `server` is a lib + bin crate
  whose lib is named `brolly_server` (`server/Cargo.toml` `[lib] name`), so inside
  the crate it is `crate::tls::install_crypto_provider()` and from integration
  tests `brolly_server::tls::install_crypto_provider()`.

**Line numbers** below are as of `ae8470a`. Chunks 1–4 shift some of them
(chunk 3 in particular rewrites parts of `server/src/atproto_oauth.rs`); every
citation also names the item, so locate by name when a number has moved.

**Four tasks, four commits,** each deployable:

1. The pure rules (`adapters/atproto/src/client_metadata.rs`). Nothing calls them yet.
2. `ClientLookup`, `StaticClients` and `lookup_client`, threaded through
   `AppState`, `main.rs` and all 15 test constructors. No behaviour change: PAR
   doesn't consult it yet. (Spec rollout step 5.)
3. `Fetcher`, `PublicOnly` and the cache. `main.rs` builds the `Fetcher`. Still no
   behaviour change: PAR doesn't consult it yet.
4. PAR uses all of it, the consent screen names the client by host, and
   `is_valid_client_id` goes. (Spec rollout step 6: the behaviour change.)

---

### Task 1: The rules a client and its metadata must pass

**Files:**
- Create: `adapters/atproto/src/client_metadata.rs`
- Modify: `adapters/atproto/src/lib.rs:10-19` (module list)
- Modify: `adapters/atproto/Cargo.toml:18-44` (`[dependencies]`: add `url`)

- [ ] **Step 1: Write the failing tests**

Add the module to `adapters/atproto/src/lib.rs`, keeping the list alphabetical:

```rust
pub mod blocks;
pub mod client_metadata;
pub mod firehose;
```

Add `url` to `adapters/atproto/Cargo.toml` `[dependencies]`, directly after
`serde_json` (the same version `server` and `adapters/activitypub` already use,
so no new crate enters the lock):

```toml
serde_json = "1.0.151"
# client_id and redirect_uri checks are URL-structural (host kind, port,
# userinfo, origin); string prefixes are how is_valid_client_id went wrong.
url = "2.5.8"
```

Create `adapters/atproto/src/client_metadata.rs` with only the tests for now:

```rust
//! Which ATProto OAuth clients we talk to, and what they may ask for.

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const APP: &str = "https://app.example/client-metadata.json";
    const NATIVE: &str = "https://app.example.com/client-metadata.json";

    // --- helpers ------------------------------------------------------------

    fn id(raw: &str) -> ClientId {
        parse_client_id(raw).unwrap_or_else(|e| panic!("{raw} should parse: {e}"))
    }

    fn refused_id(raw: &str) {
        assert!(
            matches!(parse_client_id(raw), Err(ClientError::InvalidClientId(_))),
            "{raw} should be refused as a client_id, got {:?}",
            parse_client_id(raw)
        );
    }

    fn web_document() -> Value {
        json!({
            "client_id": APP,
            "client_name": "Example App",
            "redirect_uris": ["https://app.example/cb"],
            "scope": "atproto transition:generic",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "application_type": "web",
            "dpop_bound_access_tokens": true,
        })
    }

    fn native_document(redirect: &str) -> Value {
        json!({
            "client_id": NATIVE,
            "redirect_uris": [redirect],
            "scope": "atproto",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "application_type": "native",
            "dpop_bound_access_tokens": true,
        })
    }

    fn validating(document: &Value) -> Result<ClientMetadata, ClientError> {
        validate(&id(APP), "application/json", document.to_string().as_bytes())
    }

    fn validating_native(redirect: &str) -> Result<ClientMetadata, ClientError> {
        validate(
            &id(NATIVE),
            "application/json",
            native_document(redirect).to_string().as_bytes(),
        )
    }

    fn with(mut document: Value, field: &str, value: Value) -> Value {
        document[field] = value;
        document
    }

    fn without(mut document: Value, field: &str) -> Value {
        document.as_object_mut().unwrap().remove(field);
        document
    }

    /// Refused as invalid metadata, for the rule named by `rule`.
    fn refused_for(result: Result<ClientMetadata, ClientError>, rule: &str) {
        match result {
            Err(ClientError::InvalidMetadata(message)) => assert!(
                message.contains(rule),
                "refused for {message:?}, expected the {rule:?} rule"
            ),
            other => panic!("expected InvalidMetadata for {rule:?}, got {other:?}"),
        }
    }

    // --- parse_client_id: discoverable ------------------------------------------

    #[test]
    fn an_https_client_id_is_discoverable() {
        assert!(matches!(id(APP), ClientId::Discoverable(_)));
        assert_eq!(id(APP).url().as_str(), APP);
        assert!(!id(APP).is_loopback());
    }

    #[test]
    fn a_client_id_with_a_port_is_refused() {
        refused_id("https://app.example:8443/client-metadata.json");
    }

    #[test]
    fn a_client_id_with_userinfo_is_refused() {
        refused_id("https://user@app.example/client-metadata.json");
        refused_id("https://user:secret@app.example/client-metadata.json");
    }

    #[test]
    fn a_client_id_with_a_fragment_is_refused() {
        refused_id("https://app.example/client-metadata.json#x");
        refused_id("https://app.example/client-metadata.json#");
    }

    #[test]
    fn a_client_id_with_an_ip_host_is_refused() {
        // hyper connects to IP literals without resolving them, so they would
        // never pass through the PublicOnly resolver.
        refused_id("https://203.0.113.9/client-metadata.json");
        refused_id("https://127.0.0.1/client-metadata.json");
        refused_id("https://[2001:db8::1]/client-metadata.json");
        refused_id("https://[::1]/client-metadata.json");
    }

    #[test]
    fn a_client_id_not_in_canonical_form_is_refused() {
        // "client_id equals the fetch URL, as an exact string" needs there to
        // be one string. The url crate would silently lowercase the host and
        // drop a default port.
        refused_id("https://APP.example/client-metadata.json");
        refused_id("https://app.example:443/client-metadata.json");
    }

    #[test]
    fn a_client_id_that_is_not_an_https_url_is_refused() {
        refused_id("http://app.example/client-metadata.json");
        refused_id("urn:uuid:1234");
        refused_id("my-app");
        refused_id("");
    }

    // --- parse_client_id: loopback ---------------------------------------------

    #[test]
    fn http_localhost_is_a_loopback_client() {
        for raw in [
            "http://localhost",
            "http://localhost/",
            "http://localhost?scope=atproto",
            "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Fcb",
            "http://localhost/?redirect_uri=http%3A%2F%2F%5B%3A%3A1%5D%3A9000%2Fcb&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcb",
        ] {
            assert!(id(raw).is_loopback(), "{raw}");
        }
    }

    #[test]
    fn a_loopback_client_id_with_a_port_path_or_fragment_is_refused() {
        refused_id("http://localhost:3000");
        refused_id("http://localhost:80/");
        refused_id("http://localhost/client-metadata.json");
        refused_id("http://localhost/#x");
        refused_id("http://localhost.evil.example/");
        refused_id("http://localhost@evil.example/");
        refused_id("http://127.0.0.1/");
    }

    #[test]
    fn a_loopback_client_id_naming_an_external_redirect_is_refused() {
        // Without this the loopback exception would reopen hole 3.
        refused_id("http://localhost?redirect_uri=https%3A%2F%2Fevil.example%2Fcb");
        refused_id("http://localhost?redirect_uri=http%3A%2F%2Fevil.example%2Fcb");
        // localhost the *name* is not a loopback redirect; only the addresses are.
        refused_id("http://localhost?redirect_uri=http%3A%2F%2Flocalhost%2Fcb");
        refused_id("http://localhost?redirect_uri=https%3A%2F%2F127.0.0.1%2Fcb");
    }

    #[test]
    fn a_loopback_client_id_with_two_scopes_is_refused() {
        refused_id("http://localhost?scope=atproto&scope=transition%3Ageneric");
    }

    // --- loopback_metadata --------------------------------------------------------

    #[test]
    fn loopback_metadata_has_the_spec_defaults() {
        let meta = loopback_metadata(&id("http://localhost"));
        assert_eq!(
            meta.redirect_uris(),
            ["http://127.0.0.1/".to_string(), "http://[::1]/".to_string()]
        );
        assert_eq!(meta.scope(), "atproto");
        assert_eq!(meta.token_endpoint_auth_method(), "none");
        assert!(meta.dpop_bound_access_tokens());
        assert_eq!(meta.application_type(), ApplicationType::Native);
    }

    #[test]
    fn loopback_metadata_takes_redirects_and_scope_from_the_query() {
        let meta = loopback_metadata(&id(
            "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&scope=atproto%20transition%3Ageneric",
        ));
        assert_eq!(meta.redirect_uris(), ["http://127.0.0.1/callback".to_string()]);
        assert_eq!(meta.scope(), "atproto transition:generic");
    }

    #[test]
    fn loopback_metadata_for_a_discoverable_id_allows_nothing() {
        let meta = loopback_metadata(&id(APP));
        assert!(check_request(&meta, "http://127.0.0.1/", "atproto").is_err());
    }

    // --- validate -------------------------------------------------------------------

    #[test]
    fn a_complete_web_document_validates() {
        let meta = validating(&web_document()).unwrap();
        assert_eq!(meta.client_id(), APP);
        assert_eq!(meta.redirect_uris(), ["https://app.example/cb".to_string()]);
        assert_eq!(meta.scope(), "atproto transition:generic");
        assert_eq!(meta.application_type(), ApplicationType::Web);
    }

    #[test]
    fn the_content_type_must_be_json() {
        let body = web_document().to_string();
        assert!(validate(&id(APP), "application/json; charset=utf-8", body.as_bytes()).is_ok());
        assert!(validate(&id(APP), "Application/JSON", body.as_bytes()).is_ok());
        refused_for(
            validate(&id(APP), "text/html", body.as_bytes()),
            "application/json",
        );
        refused_for(validate(&id(APP), "", body.as_bytes()), "application/json");
    }

    #[test]
    fn the_body_must_be_a_json_object() {
        refused_for(
            validate(&id(APP), "application/json", b"[]"),
            "JSON object",
        );
        refused_for(
            validate(&id(APP), "application/json", b"<html>"),
            "JSON object",
        );
        refused_for(
            validating(&with(web_document(), "redirect_uris", json!("https://app.example/cb"))),
            "wrong type",
        );
    }

    #[test]
    fn the_client_id_must_equal_the_fetch_url() {
        refused_for(
            validating(&with(
                web_document(),
                "client_id",
                json!("https://other.example/client-metadata.json"),
            )),
            "client_id",
        );
        refused_for(validating(&without(web_document(), "client_id")), "client_id");
        refused_for(
            validating(&with(
                web_document(),
                "client_id",
                json!("https://app.example/client-metadata.json/"),
            )),
            "client_id",
        );
    }

    #[test]
    fn a_loopback_id_has_no_document_to_validate() {
        assert!(matches!(
            validate(
                &id("http://localhost"),
                "application/json",
                web_document().to_string().as_bytes()
            ),
            Err(ClientError::InvalidClientId(_))
        ));
    }

    #[test]
    fn dpop_bound_access_tokens_must_be_true() {
        refused_for(
            validating(&without(web_document(), "dpop_bound_access_tokens")),
            "dpop_bound_access_tokens",
        );
        refused_for(
            validating(&with(web_document(), "dpop_bound_access_tokens", json!(false))),
            "dpop_bound_access_tokens",
        );
    }

    #[test]
    fn grant_types_must_include_authorization_code() {
        refused_for(
            validating(&with(web_document(), "grant_types", json!(["refresh_token"]))),
            "grant_types",
        );
        refused_for(validating(&without(web_document(), "grant_types")), "grant_types");
    }

    #[test]
    fn response_types_must_include_code() {
        refused_for(
            validating(&with(web_document(), "response_types", json!(["token"]))),
            "response_types",
        );
        refused_for(
            validating(&without(web_document(), "response_types")),
            "response_types",
        );
    }

    #[test]
    fn the_declared_scope_must_include_atproto() {
        refused_for(
            validating(&with(web_document(), "scope", json!("transition:generic"))),
            "scope",
        );
        refused_for(validating(&without(web_document(), "scope")), "scope");
        // Split on spaces, not substring-matched.
        refused_for(
            validating(&with(web_document(), "scope", json!("atprotox"))),
            "scope",
        );
    }

    #[test]
    fn a_public_client_may_omit_or_name_the_auth_method() {
        assert!(validating(&without(web_document(), "token_endpoint_auth_method")).is_ok());
    }

    #[test]
    fn private_key_jwt_is_refused_as_confidential() {
        assert_eq!(
            validating(&with(
                web_document(),
                "token_endpoint_auth_method",
                json!("private_key_jwt")
            )),
            Err(ClientError::ConfidentialUnsupported)
        );
        refused_for(
            validating(&with(
                web_document(),
                "token_endpoint_auth_method",
                json!("client_secret_basic"),
            )),
            "token_endpoint_auth_method",
        );
    }

    #[test]
    fn application_type_is_web_native_or_absent() {
        let absent = validating(&without(web_document(), "application_type")).unwrap();
        assert_eq!(absent.application_type(), ApplicationType::Web);
        refused_for(
            validating(&with(web_document(), "application_type", json!("desktop"))),
            "application_type",
        );
    }

    #[test]
    fn redirect_uris_must_not_be_empty() {
        refused_for(
            validating(&with(web_document(), "redirect_uris", json!([]))),
            "redirect_uris must not be empty",
        );
        refused_for(
            validating(&without(web_document(), "redirect_uris")),
            "redirect_uris must not be empty",
        );
    }

    #[test]
    fn a_web_client_must_redirect_to_https() {
        refused_for(
            validating(&with(web_document(), "redirect_uris", json!(["http://app.example/cb"]))),
            "web client",
        );
        // Loopback redirects belong to loopback clients only.
        refused_for(
            validating(&with(web_document(), "redirect_uris", json!(["http://127.0.0.1/cb"]))),
            "web client",
        );
        // Every entry is checked, not just the first.
        refused_for(
            validating(&with(
                web_document(),
                "redirect_uris",
                json!(["https://app.example/cb", "http://app.example/cb"]),
            )),
            "web client",
        );
    }

    #[test]
    fn a_native_client_may_use_its_reverse_domain_scheme() {
        assert!(validating_native("com.example.app:/callback").is_ok());
    }

    #[test]
    fn a_native_client_with_a_scheme_that_does_not_match_is_refused() {
        refused_for(validating_native("com.evil.app:/callback"), "native client");
        refused_for(validating_native("app.example.com:/callback"), "native client");
        // "a single colon then a single forward slash"
        refused_for(validating_native("com.example.app://callback"), "native client");
        refused_for(validating_native("com.example.app:callback"), "native client");
    }

    #[test]
    fn a_native_client_may_use_https_on_its_own_origin_only() {
        assert!(validating_native("https://app.example.com/callback").is_ok());
        refused_for(validating_native("https://evil.example/callback"), "native client");
    }

    #[test]
    fn a_native_client_may_not_use_loopback_redirects_yet() {
        // A deliberate divergence from the ATProto spec, revisited in stage 2.
        refused_for(validating_native("http://127.0.0.1/callback"), "native client");
        refused_for(validating_native("http://[::1]/callback"), "native client");
    }

    // --- check_request ------------------------------------------------------------

    #[test]
    fn a_declared_redirect_uri_is_accepted_exactly() {
        let web = validating(&web_document()).unwrap();
        assert_eq!(check_request(&web, "https://app.example/cb", "atproto"), Ok(()));
        assert_eq!(
            check_request(&web, "https://evil.example/cb", "atproto"),
            Err(ClientError::RedirectUriNotAllowed)
        );
        assert_eq!(
            check_request(&web, "https://app.example/cb/", "atproto"),
            Err(ClientError::RedirectUriNotAllowed)
        );
    }

    #[test]
    fn a_web_client_gets_no_port_leniency() {
        let web = validating(&web_document()).unwrap();
        assert_eq!(
            check_request(&web, "https://app.example:8443/cb", "atproto"),
            Err(ClientError::RedirectUriNotAllowed)
        );
    }

    #[test]
    fn a_loopback_redirect_on_a_different_port_is_accepted() {
        let meta = loopback_metadata(&id(
            "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback",
        ));
        assert_eq!(
            check_request(&meta, "http://127.0.0.1:61234/callback", "atproto"),
            Ok(())
        );
        let defaults = loopback_metadata(&id("http://localhost"));
        assert_eq!(check_request(&defaults, "http://[::1]:4000/", "atproto"), Ok(()));
    }

    #[test]
    fn a_loopback_redirect_on_a_different_path_is_refused() {
        let meta = loopback_metadata(&id(
            "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback",
        ));
        assert_eq!(
            check_request(&meta, "http://127.0.0.1:61234/elsewhere", "atproto"),
            Err(ClientError::RedirectUriNotAllowed)
        );
        assert_eq!(
            check_request(&meta, "http://[::1]:61234/callback", "atproto"),
            Err(ClientError::RedirectUriNotAllowed),
            "the host is matched too"
        );
    }

    #[test]
    fn a_requested_scope_without_atproto_is_refused() {
        let web = validating(&web_document()).unwrap();
        assert!(matches!(
            check_request(&web, "https://app.example/cb", "transition:generic"),
            Err(ClientError::ScopeNotAllowed(_))
        ));
        assert!(matches!(
            check_request(&web, "https://app.example/cb", ""),
            Err(ClientError::ScopeNotAllowed(_))
        ));
    }

    #[test]
    fn a_scope_escalation_is_refused() {
        let narrow = validating(&with(web_document(), "scope", json!("atproto"))).unwrap();
        assert!(matches!(
            check_request(&narrow, "https://app.example/cb", "atproto transition:generic"),
            Err(ClientError::ScopeNotAllowed(_))
        ));
    }

    #[test]
    fn a_subset_of_the_declared_scope_is_accepted() {
        let web = validating(&web_document()).unwrap();
        assert_eq!(check_request(&web, "https://app.example/cb", "atproto"), Ok(()));
        assert_eq!(
            check_request(&web, "https://app.example/cb", "transition:generic atproto"),
            Ok(())
        );
    }
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-atproto --lib client_metadata`
Expected: FAIL to compile — `cannot find type ClientId in this scope`,
`cannot find function parse_client_id`, and so on.

- [ ] **Step 3: Implement**

Replace the first line of `adapters/atproto/src/client_metadata.rs` (the
one-line module doc) with the following, leaving the `#[cfg(test)] mod tests`
block below it untouched:

```rust
//! Which ATProto OAuth clients we talk to, and what they may ask for.
//!
//! Pure rules, no I/O: the server fetches a client's metadata document and
//! hands the bytes here. Each rule follows the ATProto OAuth specification
//! (<https://atproto.com/specs/oauth>), and the doc comments quote it, because
//! a rule looser than the spec is a hole and a stricter one is a real client
//! refused.
//!
//! This exists because PAR used to accept any `https://` `client_id`, never
//! fetch its metadata, and store whatever `redirect_uri` it was given, so an
//! authorization code went wherever a request asked.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Deserialize;
use url::{Host, Url};

/// A `client_id` that has passed [`parse_client_id`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientId {
    /// An `https` URL serving the client's metadata document.
    Discoverable(Url),
    /// `http://localhost`, "for development". It has no metadata document;
    /// [`loopback_metadata`] derives one from its query.
    Loopback(Url),
}

impl ClientId {
    pub fn url(&self) -> &Url {
        match self {
            ClientId::Discoverable(url) | ClientId::Loopback(url) => url,
        }
    }

    pub fn is_loopback(&self) -> bool {
        matches!(self, ClientId::Loopback(_))
    }
}

/// `application_type`. Absent means `web`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationType {
    Web,
    Native,
}

/// Client metadata that has passed [`validate`], or been derived by
/// [`loopback_metadata`].
///
/// The fields are private so nothing outside this module can build one. A
/// test double that holds `ClientMetadata` therefore holds only what
/// production would accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientMetadata {
    client_id: String,
    redirect_uris: Vec<String>,
    scope: String,
    token_endpoint_auth_method: String,
    dpop_bound_access_tokens: bool,
    application_type: ApplicationType,
    /// Loopback redirects match with the port ignored. Only ever true for
    /// metadata from [`loopback_metadata`].
    loopback: bool,
}

impl ClientMetadata {
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn redirect_uris(&self) -> &[String] {
        &self.redirect_uris
    }
    pub fn scope(&self) -> &str {
        &self.scope
    }
    pub fn token_endpoint_auth_method(&self) -> &str {
        &self.token_endpoint_auth_method
    }
    pub fn dpop_bound_access_tokens(&self) -> bool {
        self.dpop_bound_access_tokens
    }
    pub fn application_type(&self) -> ApplicationType {
        self.application_type
    }
}

/// Why a client, or what it asked for, was refused.
///
/// Every message is safe to show the caller: it names the rule, never anything
/// fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    InvalidClientId(&'static str),
    InvalidMetadata(&'static str),
    /// `private_key_jwt`. Accepting it without verifying the client assertion
    /// would be worse than refusing it (S6); stage 2.
    ConfidentialUnsupported,
    RedirectUriNotAllowed,
    ScopeNotAllowed(&'static str),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::InvalidClientId(rule) => f.write_str(rule),
            ClientError::InvalidMetadata(rule) => write!(f, "client metadata is invalid: {rule}"),
            ClientError::ConfidentialUnsupported => {
                f.write_str("confidential clients (private_key_jwt) are not supported yet")
            }
            ClientError::RedirectUriNotAllowed => {
                f.write_str("redirect_uri is not one the client's metadata declares")
            }
            ClientError::ScopeNotAllowed(rule) => f.write_str(rule),
        }
    }
}

impl std::error::Error for ClientError {}

const LOOPBACK_CLIENT: &str = "http://localhost";

/// Parse and check a `client_id`.
///
/// **Discoverable:** a well-formed `https` URL with no port, no userinfo and no
/// fragment, whose host is a domain name. Never an IP literal: hyper connects
/// to those without resolving them, so they would bypass the server's
/// public-address filter. It must also already be in canonical form, so the
/// string the client sent is the string its metadata has to repeat.
///
/// **Loopback:** exactly `http://localhost`, no port, path `/`, no fragment.
/// The query may carry `redirect_uri` (repeatable) and `scope`, and every
/// `redirect_uri` must be `http` on `127.0.0.1` or `[::1]`. Without that check
/// the loopback exception would send codes anywhere again.
pub fn parse_client_id(raw: &str) -> Result<ClientId, ClientError> {
    if raw.starts_with("http:") {
        return parse_loopback(raw);
    }
    let url = Url::parse(raw)
        .map_err(|_| ClientError::InvalidClientId("client_id must be an https URL"))?;
    if url.scheme() != "https" {
        return Err(ClientError::InvalidClientId(
            "client_id must be an https URL, or http://localhost for development",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ClientError::InvalidClientId("client_id must not carry userinfo"));
    }
    if url.port().is_some() {
        return Err(ClientError::InvalidClientId("client_id must not have a port"));
    }
    if url.fragment().is_some() {
        return Err(ClientError::InvalidClientId("client_id must not have a fragment"));
    }
    if !matches!(url.host(), Some(Host::Domain(_))) {
        return Err(ClientError::InvalidClientId(
            "client_id must name a host by domain, not by IP address",
        ));
    }
    if url.as_str() != raw {
        return Err(ClientError::InvalidClientId(
            "client_id must be in canonical form (lowercase host, no default port)",
        ));
    }
    Ok(ClientId::Discoverable(url))
}

fn parse_loopback(raw: &str) -> Result<ClientId, ClientError> {
    const NOT_LOOPBACK: ClientError = ClientError::InvalidClientId(
        "an http client_id must be exactly http://localhost, with no port or path",
    );
    // Literal prefix first: it rules out ports, userinfo, other hosts and
    // case variants before the URL parser can normalise any of them away.
    let rest = raw.strip_prefix(LOOPBACK_CLIENT).ok_or(NOT_LOOPBACK)?;
    if !(rest.is_empty() || rest.starts_with('/') || rest.starts_with('?')) {
        return Err(NOT_LOOPBACK);
    }
    let url = Url::parse(raw).map_err(|_| NOT_LOOPBACK)?;
    if url.host() != Some(Host::Domain("localhost")) || url.port().is_some() || url.path() != "/"
    {
        return Err(NOT_LOOPBACK);
    }
    if url.fragment().is_some() {
        return Err(ClientError::InvalidClientId("client_id must not have a fragment"));
    }
    let mut scopes = 0;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "redirect_uri" if !is_loopback_redirect(&value) => {
                return Err(ClientError::InvalidClientId(
                    "a localhost client's redirect_uri must be http://127.0.0.1 or http://[::1]",
                ));
            }
            "scope" => {
                scopes += 1;
                if scopes > 1 {
                    return Err(ClientError::InvalidClientId(
                        "a localhost client_id may name scope only once",
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(ClientId::Loopback(url))
}

fn is_loopback_redirect(uri: &str) -> bool {
    Url::parse(uri).is_ok_and(|url| url.scheme() == "http" && is_loopback_host(&url))
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(ip)) => ip == Ipv4Addr::LOCALHOST,
        Some(Host::Ipv6(ip)) => ip == Ipv6Addr::LOCALHOST,
        _ => false,
    }
}

/// The metadata a loopback client implies.
///
/// `redirect_uris` from the query, defaulting to `http://127.0.0.1/` and
/// `http://[::1]/`; `scope` from the query, defaulting to `atproto`; a public,
/// DPoP-bound, native client.
///
/// Given a discoverable id, which has real metadata to fetch, it returns
/// metadata that allows nothing: no redirect URIs and no scope.
pub fn loopback_metadata(id: &ClientId) -> ClientMetadata {
    let ClientId::Loopback(url) = id else {
        return ClientMetadata {
            client_id: id.url().as_str().to_owned(),
            redirect_uris: Vec::new(),
            scope: String::new(),
            token_endpoint_auth_method: "none".to_owned(),
            dpop_bound_access_tokens: true,
            application_type: ApplicationType::Native,
            loopback: false,
        };
    };
    let mut redirect_uris = Vec::new();
    let mut scope = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "redirect_uri" => redirect_uris.push(value.into_owned()),
            "scope" => scope = Some(value.into_owned()),
            _ => {}
        }
    }
    if redirect_uris.is_empty() {
        redirect_uris = vec!["http://127.0.0.1/".to_owned(), "http://[::1]/".to_owned()];
    }
    ClientMetadata {
        client_id: url.as_str().to_owned(),
        redirect_uris,
        scope: scope.unwrap_or_else(|| "atproto".to_owned()),
        token_endpoint_auth_method: "none".to_owned(),
        dpop_bound_access_tokens: true,
        application_type: ApplicationType::Native,
        loopback: true,
    }
}

/// The fields we read. Everything else, `client_name` and `logo_uri`
/// included, is ignored: without a vetted list they are self-asserted and not
/// shown (S5).
#[derive(Deserialize)]
struct Document {
    client_id: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
    scope: Option<String>,
    #[serde(default)]
    grant_types: Vec<String>,
    #[serde(default)]
    response_types: Vec<String>,
    dpop_bound_access_tokens: Option<bool>,
    token_endpoint_auth_method: Option<String>,
    application_type: Option<String>,
}

/// Check a fetched metadata document against the `client_id` it was fetched
/// from.
pub fn validate(
    id: &ClientId,
    content_type: &str,
    body: &[u8],
) -> Result<ClientMetadata, ClientError> {
    let ClientId::Discoverable(url) = id else {
        return Err(ClientError::InvalidClientId(
            "a localhost client has no metadata document",
        ));
    };

    let media_type = content_type.split(';').next().unwrap_or_default().trim();
    if !media_type.eq_ignore_ascii_case("application/json") {
        return Err(ClientError::InvalidMetadata(
            "client metadata must be served as application/json",
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|_| ClientError::InvalidMetadata("client metadata is not a JSON object"))?;
    if !value.is_object() {
        return Err(ClientError::InvalidMetadata("client metadata is not a JSON object"));
    }
    let doc: Document = serde_json::from_value(value)
        .map_err(|_| ClientError::InvalidMetadata("a client metadata field has the wrong type"))?;

    // "the client_id ... must exactly match the URL used to fetch the document"
    if doc.client_id.as_deref() != Some(url.as_str()) {
        return Err(ClientError::InvalidMetadata(
            "client_id does not match the URL the metadata was fetched from",
        ));
    }
    // "dpop_bound_access_tokens (boolean, required): DPoP is mandatory ... must be true"
    if doc.dpop_bound_access_tokens != Some(true) {
        return Err(ClientError::InvalidMetadata("dpop_bound_access_tokens must be true"));
    }
    // "grant_types ... authorization_code must always be included"
    if !doc.grant_types.iter().any(|g| g == "authorization_code") {
        return Err(ClientError::InvalidMetadata(
            "grant_types must include authorization_code",
        ));
    }
    // "response_types ... code must be included"
    if !doc.response_types.iter().any(|r| r == "code") {
        return Err(ClientError::InvalidMetadata("response_types must include code"));
    }
    // "scope (string, sub-strings space-separated, required): ... must include atproto"
    let scope = doc.scope.unwrap_or_default();
    if !scope.split(' ').any(|s| s == "atproto") {
        return Err(ClientError::InvalidMetadata("scope must include atproto"));
    }
    // "token_endpoint_auth_method ... none (public client) or private_key_jwt
    // (confidential client)"
    match doc.token_endpoint_auth_method.as_deref() {
        None | Some("none") => {}
        Some("private_key_jwt") => return Err(ClientError::ConfidentialUnsupported),
        Some(_) => {
            return Err(ClientError::InvalidMetadata(
                "token_endpoint_auth_method must be none",
            ));
        }
    }
    // "application_type (string, optional): must be one of web or native,
    // with web as the default if not specified"
    let application_type = match doc.application_type.as_deref() {
        None | Some("web") => ApplicationType::Web,
        Some("native") => ApplicationType::Native,
        Some(_) => {
            return Err(ClientError::InvalidMetadata(
                "application_type must be web or native",
            ));
        }
    };
    // "redirect_uris (array of strings, required): at least one redirect URI is required"
    if doc.redirect_uris.is_empty() {
        return Err(ClientError::InvalidMetadata("redirect_uris must not be empty"));
    }
    for uri in &doc.redirect_uris {
        match application_type {
            ApplicationType::Web if !is_https(uri) => {
                return Err(ClientError::InvalidMetadata(
                    "a web client's redirect_uris must be https URLs",
                ));
            }
            ApplicationType::Native if !is_native_redirect(url, uri) => {
                return Err(ClientError::InvalidMetadata(
                    "a native client's redirect_uris must use its reverse-domain scheme \
                     or its own https origin",
                ));
            }
            _ => {}
        }
    }

    Ok(ClientMetadata {
        client_id: url.as_str().to_owned(),
        redirect_uris: doc.redirect_uris,
        scope,
        token_endpoint_auth_method: "none".to_owned(),
        dpop_bound_access_tokens: true,
        application_type,
        loopback: false,
    })
}

fn is_https(uri: &str) -> bool {
    Url::parse(uri).is_ok_and(|url| url.scheme() == "https")
}

/// A native client's redirect: "Any custom scheme must match the client_id
/// hostname in reverse-domain order. The URI scheme must be followed by a
/// single colon (:) then a single forward slash (/) and then a URI path
/// component" — or an `https` URL on the client's own origin.
///
/// Loopback `http` redirects, which the spec also allows for native clients,
/// are refused until stage 2.
fn is_native_redirect(client: &Url, uri: &str) -> bool {
    let Ok(redirect) = Url::parse(uri) else {
        return false;
    };
    match redirect.scheme() {
        "https" => redirect.origin() == client.origin(),
        "http" => false,
        _ => {
            let Some(host) = client.host_str() else {
                return false;
            };
            let scheme = host.split('.').rev().collect::<Vec<_>>().join(".");
            uri.strip_prefix(scheme.as_str())
                .and_then(|rest| rest.strip_prefix(':'))
                .is_some_and(|path| path.starts_with('/') && !path.starts_with("//"))
        }
    }
}

/// May this client make this request?
///
/// **Redirect URI:** "must exactly match one of the redirect_uris in the
/// client metadata". For a loopback client, `127.0.0.1` and `[::1]` redirects
/// match with the port ignored ("path component matched but port numbers
/// ignored"); everything else about them still has to match.
///
/// **Scope:** "Must include atproto", and the requested scopes "must be a
/// subset" of the client's declared scope.
pub fn check_request(
    metadata: &ClientMetadata,
    redirect_uri: &str,
    scope: &str,
) -> Result<(), ClientError> {
    let declared = metadata.redirect_uris.iter().any(|allowed| {
        allowed == redirect_uri
            || (metadata.loopback && same_loopback_redirect(allowed, redirect_uri))
    });
    if !declared {
        return Err(ClientError::RedirectUriNotAllowed);
    }

    let requested: Vec<&str> = scope.split(' ').filter(|s| !s.is_empty()).collect();
    if !requested.contains(&"atproto") {
        return Err(ClientError::ScopeNotAllowed("scope must include atproto"));
    }
    let allowed: Vec<&str> = metadata.scope.split(' ').collect();
    if requested.iter().any(|s| !allowed.contains(s)) {
        return Err(ClientError::ScopeNotAllowed(
            "scope asks for more than the client's metadata declares",
        ));
    }
    Ok(())
}

fn same_loopback_redirect(allowed: &str, requested: &str) -> bool {
    let (Ok(mut allowed), Ok(mut requested)) = (Url::parse(allowed), Url::parse(requested)) else {
        return false;
    };
    requested.scheme() == "http"
        && is_loopback_host(&requested)
        && allowed.set_port(None).is_ok()
        && requested.set_port(None).is_ok()
        && allowed == requested
}
```

- [ ] **Step 4: Run them and watch them pass**

Run: `cargo test -p brolly-atproto --lib client_metadata`
Expected: PASS, every test in the module.

- [ ] **Step 5: Gates**

```bash
cargo fmt --all
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
cargo deny check
```

`cargo deny check` because `adapters/atproto/Cargo.toml` changed. `url 2.5.8` is
already in `Cargo.lock`, so nothing new should appear.

- [ ] **Step 6: Commit**

```bash
git add adapters/atproto/Cargo.toml adapters/atproto/src/lib.rs adapters/atproto/src/client_metadata.rs Cargo.lock
git commit -m "feat(atproto): the rules a client and its metadata must pass

PAR accepts any client_id that starts with https://, never fetches the
client's metadata, and stores whatever redirect_uri it is given. This is
the first half of fixing that: pure functions for what the ATProto OAuth
spec requires of a client_id, of its metadata document, and of a request
made under it.

Discoverable ids must be canonical https URLs on a domain name, so an IP
literal can't bypass the resolver filter that comes next. Loopback ids
may only name 127.0.0.1 and [::1] redirects. Confidential clients are
refused until stage 2. Nothing calls these yet.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 7: Verify from a clean checkout**

```bash
rm -rf /tmp/verify && git worktree add --detach /tmp/verify HEAD
cd /tmp/verify && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings
cd - && git worktree remove /tmp/verify --force
```

Green there, or the commit isn't done.

---

### Task 2: Thread a `ClientLookup` through `AppState`

No behaviour change. PAR doesn't read the new field until Task 4.

**Files:**
- Create: `server/src/client_metadata.rs`
- Modify: `server/src/lib.rs:17-30` (module list), `:35-83` (`AppState`)
- Modify: `server/src/main.rs:57-93` (the `AppState` literal)
- Modify: every `AppState { .. }` literal under `server/tests/`, 15 files:
  `activitypub_discovery.rs:70`, `admin.rs:42`, `atproto_oauth.rs:66`,
  `auth_flow.rs:40`, `dashboard.rs:75`, `federation_flows.rs:74`,
  `harmonization.rs:60`, `mastodon_api.rs:57`, `mastodon_compose.rs:60`,
  `mastodon_oauth_flow.rs:55`, `mastodon_profile_flags.rs:56`, `pod_http.rs:106`,
  `solid_oidc_flow.rs:55`, `solid_token_access.rs:111`, `xrpc.rs:58` (each the
  `plc_client: None,` line)
- Modify: `server/tests/atproto_oauth.rs:26-28` (constants; add `app_example`)

- [ ] **Step 1: Write the failing tests**

Add the module to `server/src/lib.rs`, alphabetically:

```rust
pub mod auth;
pub mod client_metadata;
pub mod consent;
```

Create `server/src/client_metadata.rs` with only its tests:

```rust
//! Looking up ATProto OAuth client metadata.

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const APP: &str = "https://app.example/client-metadata.json";

    fn document(client_id: &str) -> String {
        serde_json::json!({
            "client_id": client_id,
            "redirect_uris": ["https://app.example/cb"],
            "scope": "atproto",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "dpop_bound_access_tokens": true,
        })
        .to_string()
    }

    /// Counts calls to `fetch`. Here rather than on `StaticClients`, so the
    /// production types carry no counters.
    struct Counting {
        inner: StaticClients,
        lookups: Arc<AtomicUsize>,
    }

    impl ClientLookup for Counting {
        fn fetch<'a>(&'a self, url: &'a Url) -> Lookup<'a> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            self.inner.fetch(url)
        }
    }

    #[test]
    fn static_clients_hold_only_what_validate_accepts() {
        let no_dpop = serde_json::json!({
            "client_id": APP,
            "redirect_uris": ["https://app.example/cb"],
            "scope": "atproto",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
        })
        .to_string();
        assert!(matches!(
            StaticClients::default().with(APP, &no_dpop),
            Err(ClientError::InvalidMetadata(_))
        ));
        assert!(matches!(
            StaticClients::default().with("http://localhost", &document("http://localhost")),
            Err(ClientError::InvalidClientId(_))
        ));
        assert!(StaticClients::default().with(APP, &document(APP)).is_ok());
    }

    #[tokio::test]
    async fn a_registered_client_is_found_and_an_unknown_one_is_unreachable() {
        let clients = StaticClients::default().with(APP, &document(APP)).unwrap();

        let found = clients.fetch(&Url::parse(APP).unwrap()).await.unwrap();
        assert_eq!(found.client_id(), APP);

        let unknown = Url::parse("https://unknown.example/client-metadata.json").unwrap();
        assert_eq!(clients.fetch(&unknown).await, Err(LookupError::Unreachable));
    }

    #[tokio::test]
    async fn a_loopback_client_never_reaches_fetch() {
        let lookups = Arc::new(AtomicUsize::new(0));
        let clients = Counting {
            inner: StaticClients::default().with(APP, &document(APP)).unwrap(),
            lookups: lookups.clone(),
        };

        let loopback = parse_client_id("http://localhost").unwrap();
        let meta = lookup_client(&clients, &loopback).await.unwrap();
        assert_eq!(meta.scope(), "atproto");
        assert_eq!(lookups.load(Ordering::SeqCst), 0, "loopback ids never hit the network");

        let discoverable = parse_client_id(APP).unwrap();
        lookup_client(&clients, &discoverable).await.unwrap();
        assert_eq!(lookups.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn every_unreachable_client_is_described_the_same_way() {
        assert_eq!(
            LookupError::Unreachable.to_string(),
            "client metadata could not be retrieved"
        );
    }
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-server --lib client_metadata`
Expected: FAIL to compile — `cannot find trait ClientLookup`, `cannot find type
StaticClients`, `cannot find type Lookup`, and so on.

- [ ] **Step 3: Implement the module**

Replace the first line of `server/src/client_metadata.rs` with the following,
leaving the tests block untouched:

```rust
//! Looking up ATProto OAuth client metadata.
//!
//! The rules live in [`brolly_atproto::client_metadata`]. This module decides
//! where the metadata comes from: the network in production (`Fetcher`), a
//! fixed map in integration tests ([`StaticClients`]).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use brolly_atproto::client_metadata::{
    ClientError, ClientId, ClientMetadata, loopback_metadata, parse_client_id, validate,
};
use url::Url;

/// Why a client's metadata couldn't be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupError {
    /// The document was retrieved and broke a rule. Safe to describe.
    Invalid(ClientError),
    /// DNS refusal, connection failure, timeout, TLS failure, a non-200 status
    /// or an oversized body. All of them get one description, so PAR can't be
    /// used to map which internal hosts exist or answer (S4).
    Unreachable,
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LookupError::Invalid(e) => e.fmt(f),
            LookupError::Unreachable => f.write_str("client metadata could not be retrieved"),
        }
    }
}

impl std::error::Error for LookupError {}

/// What [`ClientLookup::fetch`] returns: a boxed future, because an `async fn`
/// in a trait can't be called through `dyn`.
pub type Lookup<'a> = Pin<Box<dyn Future<Output = Result<ClientMetadata, LookupError>> + Send + 'a>>;

/// Where client metadata comes from.
///
/// `Send + Sync` so it can live in axum state as `Arc<dyn ClientLookup>`.
pub trait ClientLookup: Send + Sync {
    /// Retrieve and validate the metadata document at `url`.
    ///
    /// Only ever called for discoverable clients: PAR goes through
    /// [`lookup_client`], which answers loopback clients itself.
    fn fetch<'a>(&'a self, url: &'a Url) -> Lookup<'a>;
}

/// The metadata for a parsed `client_id`.
///
/// A free function rather than a default method on [`ClientLookup`], so no
/// implementation can override the loopback branch and send a `localhost`
/// client to the network.
pub async fn lookup_client(
    clients: &dyn ClientLookup,
    id: &ClientId,
) -> Result<ClientMetadata, LookupError> {
    match id {
        ClientId::Loopback(_) => Ok(loopback_metadata(id)),
        ClientId::Discoverable(url) => clients.fetch(url).await,
    }
}

/// A fixed set of clients, for integration tests.
///
/// It skips fetching, not validation: [`StaticClients::with`] runs the
/// document through `validate`, so a test can't register a client production
/// would refuse (S8). An id that isn't registered is `Unreachable`, as a 404
/// would be.
#[derive(Debug, Clone, Default)]
pub struct StaticClients {
    clients: HashMap<String, ClientMetadata>,
}

impl StaticClients {
    /// Register `client_id`, serving `document` as `application/json`.
    pub fn with(mut self, client_id: &str, document: &str) -> Result<Self, ClientError> {
        let id = parse_client_id(client_id)?;
        let metadata = validate(&id, "application/json", document.as_bytes())?;
        self.clients.insert(metadata.client_id().to_owned(), metadata);
        Ok(self)
    }
}

impl ClientLookup for StaticClients {
    fn fetch<'a>(&'a self, url: &'a Url) -> Lookup<'a> {
        let found = self
            .clients
            .get(url.as_str())
            .cloned()
            .ok_or(LookupError::Unreachable);
        Box::pin(std::future::ready(found))
    }
}
```

- [ ] **Step 4: Run the module tests and watch them pass**

Run: `cargo test -p brolly-server --lib client_metadata`
Expected: PASS.

- [ ] **Step 5: Add the field to `AppState`**

In `server/src/lib.rs`, add after `plc_client` (the last field, `:82`):

```rust
    /// Where ATProto OAuth client metadata comes from.
    ///
    /// The network in production (`client_metadata::Fetcher`), a fixed,
    /// validated set in tests (`client_metadata::StaticClients`). A trait
    /// object so tests never need a TLS server to register a client.
    pub clients: std::sync::Arc<dyn client_metadata::ClientLookup>,
```

In `server/src/main.rs`, add immediately after the `plc_client` field of the
`AppState` literal (`:88-92`):

```rust
        // Nothing reads this yet. The next commit replaces it with the fetcher.
        clients: std::sync::Arc::new(brolly_server::client_metadata::StaticClients::default()),
```

- [ ] **Step 6: Add it to every test constructor, in one mechanical step**

Every test `AppState` literal ends with `plc_client: None,`. Add the field after
it, keeping each file's indentation:

```bash
perl -0pi -e 's/^( *)plc_client: None,\n/$1plc_client: None,\n$1clients: std::sync::Arc::new(brolly_server::client_metadata::StaticClients::default()),\n/mg' server/tests/*.rs
grep -c "clients: std::sync::Arc::new" server/tests/*.rs | grep -v ":0"
```

Expected: 15 files, each with a count of 1. If `grep -rn "AppState {" server/tests`
lists a file the second command didn't, that file builds its state differently.
Add the field there by hand.

Now give `server/tests/atproto_oauth.rs` the one client its tests use. After the
`REDIRECT` constant (`:28`) add:

```rust
/// The client every test here pushes as, registered the way production would
/// accept it: through `validate`, so it can't be a client production refuses.
fn app_example() -> brolly_server::client_metadata::StaticClients {
    brolly_server::client_metadata::StaticClients::default()
        .with(
            CLIENT,
            &serde_json::json!({
                "client_id": CLIENT,
                "client_name": "Example App",
                "redirect_uris": [REDIRECT],
                "scope": "atproto transition:generic",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "application_type": "web",
                "dpop_bound_access_tokens": true,
            })
            .to_string(),
        )
        .expect("app.example's metadata validates")
}
```

and in its `harness()` replace the line the `perl` command just added with:

```rust
            clients: std::sync::Arc::new(app_example()),
```

- [ ] **Step 7: Run the suites that build an `AppState`**

Run: `cargo test -p brolly-server`
Expected: PASS. Nothing reads `clients` yet, so every existing test behaves
exactly as before.

- [ ] **Step 8: Gates**

```bash
cargo fmt --all
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

- [ ] **Step 9: Commit**

```bash
git add server/src/client_metadata.rs server/src/lib.rs server/src/main.rs server/tests/
git commit -m "refactor(server): thread a ClientLookup through AppState

ATProto PAR is about to fetch and validate client metadata. AppState gets
the one field that needs, clients: Arc<dyn ClientLookup>, and every test
constructor gets it too, in this commit, so the next ones stay small.

StaticClients, for tests, builds each entry through validate, so a test
can't register a client production would refuse. lookup_client answers
loopback clients itself, as a free function so no implementation can
send them to the network.

Nothing reads the field yet; no behaviour changes.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 10: Verify from a clean checkout**

```bash
rm -rf /tmp/verify && git worktree add --detach /tmp/verify HEAD
cd /tmp/verify && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings
cd - && git worktree remove /tmp/verify --force
```

---

### Task 3: Fetch client metadata, from public addresses only

**Files:**
- Modify: `server/Cargo.toml:25-50` (`[dependencies]`: add `moka`)
- Modify: `server/src/client_metadata.rs` (add `PublicOnly`, `Fetcher`, and their tests)
- Modify: `server/src/main.rs` (the `clients` field Task 2 added)

- [ ] **Step 1: Write the failing tests**

Append a second test module to the end of `server/src/client_metadata.rs`:

```rust
#[cfg(test)]
mod fetch_tests {
    use super::*;
    use axum::Router;
    use axum::http::{StatusCode, header};
    use axum::routing::get;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const MINUTE: Duration = Duration::from_secs(60);

    fn document(client_id: &str) -> serde_json::Value {
        serde_json::json!({
            "client_id": client_id,
            "redirect_uris": ["https://app.example/cb"],
            "scope": "atproto",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "dpop_bound_access_tokens": true,
        })
    }

    /// Serve `app(url)` on an ephemeral loopback port. `url` is the address of
    /// `/client-metadata.json` on it, which a valid document must repeat.
    async fn serve(app: impl FnOnce(String) -> Router) -> Url {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!(
            "http://{}/client-metadata.json",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let router = app(url.to_string());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        url
    }

    /// `/client-metadata.json`, always answering with these, counting hits.
    fn answering(
        status: StatusCode,
        content_type: &'static str,
        body: String,
        hits: &Arc<AtomicUsize>,
    ) -> Router {
        let hits = hits.clone();
        Router::new().route(
            "/client-metadata.json",
            get(move || {
                let hits = hits.clone();
                let body = body.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    (status, [(header::CONTENT_TYPE, content_type)], body)
                }
            }),
        )
    }

    fn local_fetcher() -> Fetcher {
        Fetcher::for_tests(true, true, MINUTE, MINUTE)
    }

    #[tokio::test]
    async fn a_valid_document_is_fetched_and_cached() {
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|url| {
            answering(StatusCode::OK, "application/json", document(&url).to_string(), &hits)
        })
        .await;
        let fetcher = local_fetcher();

        let first = fetcher.fetch(&url).await.unwrap();
        assert_eq!(first.client_id(), url.as_str());
        let second = fetcher.fetch(&url).await.unwrap();
        assert_eq!(first, second);
        assert_eq!(hits.load(Ordering::SeqCst), 1, "the second lookup is a cache hit");
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|url| {
            answering(StatusCode::OK, "application/json", document(&url).to_string(), &hits)
                .route(
                    "/moved.json",
                    get(|| async { (StatusCode::FOUND, [(header::LOCATION, "/client-metadata.json")]) }),
                )
        })
        .await;
        let moved = url.join("/moved.json").unwrap();

        assert_eq!(local_fetcher().fetch(&moved).await, Err(LookupError::Unreachable));
        assert_eq!(hits.load(Ordering::SeqCst), 0, "the redirect target was never fetched");
    }

    #[tokio::test]
    async fn only_200_is_accepted() {
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|url| {
            answering(StatusCode::CREATED, "application/json", document(&url).to_string(), &hits)
        })
        .await;
        assert_eq!(local_fetcher().fetch(&url).await, Err(LookupError::Unreachable));
    }

    #[tokio::test]
    async fn a_body_over_64_kib_is_refused() {
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|url| {
            let mut padded = document(&url);
            padded["padding"] = serde_json::Value::String("x".repeat(70 * 1024));
            answering(StatusCode::OK, "application/json", padded.to_string(), &hits)
        })
        .await;
        assert_eq!(local_fetcher().fetch(&url).await, Err(LookupError::Unreachable));
    }

    #[tokio::test]
    async fn a_slow_server_hits_the_timeout() {
        let url = serve(|url| {
            let body = document(&url).to_string();
            Router::new().route(
                "/client-metadata.json",
                get(move || {
                    let body = body.clone();
                    async move {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        ([(header::CONTENT_TYPE, "application/json")], body)
                    }
                }),
            )
        })
        .await;

        let started = std::time::Instant::now();
        assert_eq!(local_fetcher().fetch(&url).await, Err(LookupError::Unreachable));
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_secs(4) && waited < Duration::from_secs(10),
            "gave up after {waited:?}, expected the 5 s timeout"
        );
    }

    #[tokio::test]
    async fn text_html_is_refused() {
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|url| {
            answering(StatusCode::OK, "text/html", document(&url).to_string(), &hits)
        })
        .await;
        assert!(matches!(
            local_fetcher().fetch(&url).await,
            Err(LookupError::Invalid(ClientError::InvalidMetadata(_)))
        ));
    }

    #[tokio::test]
    async fn a_failure_is_cached_for_its_lifetime_then_retried() {
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|_| {
            answering(StatusCode::NOT_FOUND, "text/plain", "gone".to_string(), &hits)
        })
        .await;
        let fetcher = Fetcher::for_tests(true, true, MINUTE, Duration::from_millis(50));

        assert_eq!(fetcher.fetch(&url).await, Err(LookupError::Unreachable));
        assert_eq!(fetcher.fetch(&url).await, Err(LookupError::Unreachable));
        assert_eq!(hits.load(Ordering::SeqCst), 1, "a failure is cached too");

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(fetcher.fetch(&url).await, Err(LookupError::Unreachable));
        assert_eq!(hits.load(Ordering::SeqCst), 2, "and retried once it expires");
    }

    #[tokio::test]
    async fn an_ip_literal_is_refused_unless_loopback_is_allowed() {
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|url| {
            answering(StatusCode::OK, "application/json", document(&url).to_string(), &hits)
        })
        .await;
        let fetcher = Fetcher::for_tests(false, true, MINUTE, MINUTE);
        assert_eq!(fetcher.fetch(&url).await, Err(LookupError::Unreachable));
        assert_eq!(hits.load(Ordering::SeqCst), 0, "refused before connecting");
    }

    #[tokio::test]
    async fn a_name_that_resolves_only_to_loopback_is_refused() {
        let hits = Arc::new(AtomicUsize::new(0));
        let ip_url = serve(|url| {
            answering(StatusCode::OK, "application/json", document(&url).to_string(), &hits)
        })
        .await;
        let mut by_name = ip_url.clone();
        by_name.set_host(Some("localhost")).unwrap();

        let fetcher = Fetcher::for_tests(false, true, MINUTE, MINUTE);
        assert_eq!(fetcher.fetch(&by_name).await, Err(LookupError::Unreachable));
        assert_eq!(hits.load(Ordering::SeqCst), 0, "PublicOnly dropped every address");
    }

    #[tokio::test]
    async fn plain_http_is_refused_unless_allowed() {
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|url| {
            answering(StatusCode::OK, "application/json", document(&url).to_string(), &hits)
        })
        .await;
        let fetcher = Fetcher::for_tests(true, false, MINUTE, MINUTE);
        assert_eq!(fetcher.fetch(&url).await, Err(LookupError::Unreachable));
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    // --- PublicOnly -----------------------------------------------------------------

    #[test]
    fn every_refused_range_is_refused() {
        for ip in [
            // IPv4
            "0.0.0.0",         // unspecified
            "0.1.2.3",         // "this network"
            "127.0.0.1",       // loopback
            "127.255.255.254", // loopback
            "10.0.0.1",        // RFC 1918
            "172.16.0.1",      // RFC 1918
            "172.31.255.255",  // RFC 1918
            "192.168.1.1",     // RFC 1918
            "169.254.169.254", // link-local, and the cloud metadata service
            "100.64.0.1",      // CGNAT
            "100.127.255.254", // CGNAT
            "224.0.0.1",       // multicast
            "239.255.255.255", // multicast
            "255.255.255.255", // broadcast
            "240.0.0.1",       // reserved
            "192.0.2.1",       // documentation
            "198.51.100.7",    // documentation
            "203.0.113.9",     // documentation
            "198.18.0.1",      // benchmarking
            "198.19.255.254",  // benchmarking
            "192.0.0.8",       // IETF protocol assignments
            // IPv6
            "::",             // unspecified
            "::1",            // loopback
            "fc00::1",        // unique local (RFC 4193)
            "fd12:3456::1",   // unique local (RFC 4193)
            "fe80::1",        // link-local
            "fec0::1",        // site-local (deprecated)
            "ff02::1",        // multicast
            "2001:db8::1",    // documentation
            "2001:2::1",      // benchmarking
            "::127.0.0.1",    // IPv4-compatible (deprecated)
            "64:ff9b::a00:1", // NAT64 of 10.0.0.1
            // IPv4-mapped IPv6 forms
            "::ffff:0.0.0.0",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:172.16.0.1",
            "::ffff:192.168.1.1",
            "::ffff:169.254.169.254",
            "::ffff:100.64.0.1",
            "::ffff:224.0.0.1",
            "::ffff:255.255.255.255",
            "::ffff:192.0.2.1",
            "::ffff:198.18.0.1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip} should be refused");
        }
    }

    #[test]
    fn a_public_address_is_allowed() {
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.215.14",
            "100.63.255.255", // just below CGNAT
            "100.128.0.1",    // just above CGNAT
            "172.15.255.255", // just below RFC 1918
            "172.32.0.1",     // just above RFC 1918
            "198.17.255.255", // just below benchmarking
            "198.20.0.1",     // just above benchmarking
            "2606:4700:4700::1111",
            "2a00:1450:4001::1",
            "::ffff:1.1.1.1",
            "64:ff9b::808:808", // NAT64 of 8.8.8.8
        ] {
            assert!(is_public(ip.parse().unwrap()), "{ip} should be allowed");
        }
    }

    #[tokio::test]
    async fn the_resolver_drops_loopback_unless_told_otherwise() {
        let refused = PublicOnly::default().resolve("localhost".parse().unwrap()).await;
        assert!(refused.is_err(), "localhost has no public address");

        let allowed = PublicOnly { allow_loopback: true }
            .resolve("localhost".parse().unwrap())
            .await;
        assert!(allowed.is_ok_and(|mut addrs| addrs.next().is_some()));
    }
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-server --lib client_metadata::fetch_tests`
Expected: FAIL to compile — `cannot find type Duration`, `cannot find type
Fetcher`, `cannot find function is_public`, `cannot find struct PublicOnly`.

- [ ] **Step 3: Add `moka`**

In `server/Cargo.toml` `[dependencies]`, after `uuid`:

```toml
# Client metadata cache for ATProto PAR. `future` because lookups happen
# inside handlers; store already takes moka with `sync`, and the two unify.
moka = { version = "0.12.16", features = ["future"] }
```

- [ ] **Step 4: Implement**

In `server/src/client_metadata.rs`, extend the imports at the top to:

```rust
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::time::{Duration, Instant};

use brolly_atproto::client_metadata::{
    ClientError, ClientId, ClientMetadata, loopback_metadata, parse_client_id, validate,
};
use moka::Expiry;
use moka::future::Cache;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use url::{Host, Url};
```

Then insert the following after the
`impl ClientLookup for StaticClients` block and before the first
`#[cfg(test)]`:

```rust
// --- fetching --------------------------------------------------------------------

/// Total time for one fetch: connect, TLS, headers and body.
const TIMEOUT: Duration = Duration::from_secs(5);
/// Client metadata is a few hundred bytes. Anything this big isn't metadata.
const MAX_BODY: usize = 64 * 1024;
const OK_TTL: Duration = Duration::from_secs(10 * 60);
/// Failures are cached too, so a bad or slow client can't make every PAR
/// fetch again.
const ERR_TTL: Duration = Duration::from_secs(60);
const CAPACITY: u64 = 1_000;

type Cached = Result<ClientMetadata, LookupError>;

/// Fetches client metadata over the network, from public addresses only, and
/// caches the answer.
///
/// What `main.rs` builds. Every bypass of the address filter is closed where it
/// happens (S3):
/// - redirects aren't followed, so a public host can't bounce the fetch inward;
/// - proxies are off, so an environment proxy can't resolve names the filter
///   never sees;
/// - names resolve through [`PublicOnly`], which filters at resolution, leaving
///   no window between checking an address and connecting to it;
/// - IP-literal hosts never reach a resolver, so they're refused here (and
///   `parse_client_id` refuses them before that).
///
/// It never calls `ClientBuilder::resolve` or `resolve_to_addrs`: reqwest
/// applies those overrides on top of the custom resolver.
pub struct Fetcher {
    http: reqwest::Client,
    cache: Cache<String, Cached>,
    allow_loopback: bool,
}

impl Fetcher {
    pub fn new() -> Result<Self, reqwest::Error> {
        Self::build(false, false, OK_TTL, ERR_TTL)
    }

    /// For this module's unit tests, which fetch from `http://127.0.0.1:PORT`
    /// and need cache lifetimes in milliseconds.
    ///
    /// `allow_loopback` lets loopback IP literals through and stops
    /// [`PublicOnly`] dropping loopback addresses. `allow_http` lifts
    /// https-only.
    #[cfg(test)]
    pub fn for_tests(
        allow_loopback: bool,
        allow_http: bool,
        ok_ttl: Duration,
        err_ttl: Duration,
    ) -> Self {
        Self::build(allow_loopback, allow_http, ok_ttl, err_ttl).unwrap()
    }

    fn build(
        allow_loopback: bool,
        allow_http: bool,
        ok_ttl: Duration,
        err_ttl: Duration,
    ) -> Result<Self, reqwest::Error> {
        // Idempotent. Here as well as in main so no constructor can reach
        // reqwest's panic for a missing crypto provider.
        crate::tls::install_crypto_provider();
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(TIMEOUT)
            .https_only(!allow_http)
            .dns_resolver(PublicOnly { allow_loopback })
            .build()?;
        let cache = Cache::builder()
            .max_capacity(CAPACITY)
            .expire_after(Lifetimes {
                ok: ok_ttl,
                err: err_ttl,
            })
            .build();
        Ok(Self {
            http,
            cache,
            allow_loopback,
        })
    }

    /// Would connecting to this URL's host skip the resolver filter?
    fn host_allowed(&self, url: &Url) -> bool {
        match url.host() {
            Some(Host::Domain(_)) => true,
            Some(Host::Ipv4(ip)) => self.allow_loopback && ip.is_loopback(),
            Some(Host::Ipv6(ip)) => self.allow_loopback && ip.is_loopback(),
            None => false,
        }
    }

    async fn retrieve(&self, url: &Url) -> Cached {
        if !self.host_allowed(url) {
            return Err(LookupError::Unreachable);
        }
        let result = self.request(url).await;
        if let Err(e) = &result {
            // The caller gets one description; the operator gets the detail.
            tracing::info!(client_id = %url, error = %e, "client metadata lookup failed");
        }
        result
    }

    async fn request(&self, url: &Url) -> Cached {
        let unreachable = |e: reqwest::Error| {
            tracing::info!(client_id = %url, error = %e, "client metadata fetch failed");
            LookupError::Unreachable
        };
        let mut response = self
            .http
            .get(url.as_str())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(unreachable)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(LookupError::Unreachable);
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();

        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(unreachable)? {
            if body.len() + chunk.len() > MAX_BODY {
                return Err(LookupError::Unreachable);
            }
            body.extend_from_slice(&chunk);
        }

        validate(&ClientId::Discoverable(url.clone()), &content_type, &body)
            .map_err(LookupError::Invalid)
    }
}

impl ClientLookup for Fetcher {
    fn fetch<'a>(&'a self, url: &'a Url) -> Lookup<'a> {
        // get_with also collapses concurrent lookups of one client into a
        // single fetch.
        Box::pin(async move {
            self.cache
                .get_with(url.as_str().to_owned(), self.retrieve(url))
                .await
        })
    }
}

/// Successes are kept longer than failures.
struct Lifetimes {
    ok: Duration,
    err: Duration,
}

impl Expiry<String, Cached> for Lifetimes {
    fn expire_after_create(&self, _key: &String, value: &Cached, _at: Instant) -> Option<Duration> {
        Some(if value.is_ok() { self.ok } else { self.err })
    }
}

// --- address filtering ------------------------------------------------------------

/// A DNS resolver that only returns public addresses.
///
/// Resolves with tokio's resolver, then drops every address [`is_public`]
/// refuses. If none survive, resolution fails, so the connection is never
/// attempted.
#[derive(Debug, Clone, Copy, Default)]
pub struct PublicOnly {
    allow_loopback: bool,
}

impl Resolve for PublicOnly {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(resolve_public(name.as_str().to_owned(), self.allow_loopback))
    }
}

async fn resolve_public(
    host: String,
    allow_loopback: bool,
) -> Result<Addrs, Box<dyn std::error::Error + Send + Sync>> {
    let allowed: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
        .await?
        .filter(|addr| {
            is_public(addr.ip()) || (allow_loopback && addr.ip().to_canonical().is_loopback())
        })
        .collect();
    if allowed.is_empty() {
        return Err(std::io::Error::other("the host has no public address").into());
    }
    Ok(Box::new(allowed.into_iter()))
}

/// May a client metadata fetch connect to this address?
///
/// Refuses loopback, private (RFC 1918 / RFC 4193), link-local, unspecified,
/// multicast, broadcast, CGNAT, documentation and benchmarking ranges, and
/// every IPv6 form that embeds one of those IPv4 addresses.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public_v4(v4),
            None => is_public_v6(v6),
        },
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let refused = a == 0                                  // 0.0.0.0/8, unspecified and "this network"
        || ip.is_loopback()                               // 127.0.0.0/8
        || ip.is_private()                                // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()                             // 169.254.0.0/16
        || (a == 100 && (b & 0b1100_0000) == 64)          // 100.64.0.0/10, CGNAT
        || (a == 192 && b == 0 && c == 0)                 // 192.0.0.0/24, IETF protocol assignments
        || ip.is_documentation()                          // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || (a == 198 && (b & 0b1111_1110) == 18)          // 198.18.0.0/15, benchmarking
        || ip.is_multicast()                              // 224.0.0.0/4
        || a >= 240; // 240.0.0.0/4 reserved, including 255.255.255.255 broadcast
    !refused
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    // IPv4-compatible (::/96, deprecated), which also covers :: and ::1.
    if s[..6] == [0; 6] {
        return false;
    }
    // NAT64 (64:ff9b::/96) reaches whatever IPv4 address it embeds.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0; 4] {
        let [a, b] = s[6].to_be_bytes();
        let [c, d] = s[7].to_be_bytes();
        return is_public_v4(Ipv4Addr::new(a, b, c, d));
    }
    let refused = (s[0] & 0xfe00) == 0xfc00             // fc00::/7, unique local (RFC 4193)
        || (s[0] & 0xffc0) == 0xfe80                    // fe80::/10, link-local
        || (s[0] & 0xffc0) == 0xfec0                    // fec0::/10, site-local (deprecated)
        || (s[0] & 0xff00) == 0xff00                    // ff00::/8, multicast
        || (s[0] == 0x2001 && s[1] == 0x0db8)           // 2001:db8::/32, documentation
        || (s[0] == 0x2001 && s[1] == 0x0002 && s[2] == 0); // 2001:2::/48, benchmarking
    !refused
}
```

In `server/src/main.rs`, replace the two lines Task 2 added with:

```rust
        // ATProto OAuth clients are identified by a URL serving their
        // metadata. Fetched from public addresses only, validated, cached.
        clients: std::sync::Arc::new(brolly_server::client_metadata::Fetcher::new()?),
```

- [ ] **Step 5: Run them and watch them pass**

Run: `cargo test -p brolly-server --lib client_metadata`
Expected: PASS, both modules. `a_slow_server_hits_the_timeout` takes about five
seconds; that's the production timeout, not a hang.

- [ ] **Step 6: Gates**

```bash
cargo fmt --all
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
cargo deny check
```

`moka`'s `future` feature pulls in `async-lock`, `event-listener` and
`futures-util`, which are all already in `Cargo.lock`.

- [ ] **Step 7: Commit**

```bash
git add server/Cargo.toml Cargo.lock server/src/client_metadata.rs server/src/main.rs
git commit -m "feat(atproto): fetch client metadata, from public addresses only

The fetcher ATProto PAR will use. Fetching a URL an unauthenticated
caller names is a server-side request forgery surface, so every way
around the address filter is closed where it happens: PublicOnly
filters at DNS resolution (no rebinding window), redirects aren't
followed, proxies are off, and IP-literal hosts are refused before
connecting.

Only a 200 with at most 64 KiB, within 5 seconds, is read. Successes
are cached for 10 minutes and failures for 60 seconds, so a slow client
can't make every PAR fetch again. Every failure to retrieve has one
description, so PAR can't map internal hosts.

main.rs builds it; PAR doesn't use it yet.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 8: Verify from a clean checkout**

```bash
rm -rf /tmp/verify && git worktree add --detach /tmp/verify HEAD
cd /tmp/verify && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings
cd - && git worktree remove /tmp/verify --force
```

---

### Task 4: PAR accepts only what the client's metadata allows

**Files:**
- Modify: `server/src/atproto_oauth.rs:19-33` (imports), `:141-218` (`par`),
  `:228-309` (`authorize`); add `client_refusal`, `lookup_refusal`, `app_name`
- Modify: `adapters/atproto/src/oauth.rs:246-279` (remove `is_valid_client_id`
  and its tests module)
- Test: `server/tests/atproto_oauth.rs` (harness `:36-75`; new helpers and tests)
- Test: any other `server/tests/*.rs` that pushes a PAR (see Step 6)

- [ ] **Step 1: Write the failing tests**

In `server/tests/atproto_oauth.rs`, add to the imports:

```rust
use brolly_server::client_metadata::{ClientLookup, Lookup, StaticClients};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
```

and shorten `app_example`'s return type (added in Task 2) to `StaticClients`.

Split `harness()` (`:36-75`) so a test can supply its own clients. Rename the
existing function to `harness_with`, give it a parameter, and use it for the
field:

```rust
async fn harness() -> Harness {
    harness_with(Arc::new(app_example())).await
}

async fn harness_with(clients: Arc<dyn ClientLookup>) -> Harness {
    let db = brolly_test_support::postgres().await;
    // ... the existing body, unchanged, except for the one field:
            clients,
    // ...
}
```

After `push` (`:164-195`) add two helpers:

```rust
/// PAR with exactly these form fields, signed by the test client's key.
async fn par_with(h: &Harness, fields: &[(&str, &str)]) -> Reply {
    let mut form = form_urlencoded::Serializer::new(String::new());
    for (name, value) in fields {
        form.append_pair(name, value);
    }
    send(
        h,
        Request::builder()
            .method("POST")
            .uri("/oauth/atproto/par")
            .header(header::HOST, BASE)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                "DPoP",
                proof(
                    &client_key(),
                    "POST",
                    &format!("https://{BASE}/oauth/atproto/par"),
                    None,
                ),
            )
            .body(Body::from(form.finish()))
            .unwrap(),
    )
    .await
}

/// The consent screen for a pushed request, as a logged-in member sees it.
async fn consent_page(h: &Harness, client_id: &str, request_uri: &str, cookie: &str) -> Reply {
    send(
        h,
        Request::builder()
            .uri(format!(
                "/oauth/atproto/authorize?client_id={}&request_uri={}",
                urlencode(client_id),
                urlencode(request_uri)
            ))
            .header(header::HOST, BASE)
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

/// Counts lookups. Defined here so the production types carry no counters.
struct CountingClients {
    inner: StaticClients,
    lookups: Arc<AtomicUsize>,
}

impl ClientLookup for CountingClients {
    fn fetch<'a>(&'a self, url: &'a url::Url) -> Lookup<'a> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        self.inner.fetch(url)
    }
}
```

After `a_client_id_that_is_not_a_fetchable_url_is_refused` (`:402-439`) add:

```rust
#[tokio::test]
async fn an_unknown_client_is_refused_without_saying_why_it_could_not_be_reached() {
    // Every unreachable client gets the same words, so PAR can't be used to
    // find out which internal hosts exist or answer.
    let h = harness().await;
    let (_, challenge) = pkce();
    let reply = par_with(
        &h,
        &[
            ("client_id", "https://unknown.example/client-metadata.json"),
            ("redirect_uri", "https://unknown.example/cb"),
            ("response_type", "code"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert_eq!(reply.json()["error"], "invalid_client");
    assert_eq!(
        reply.json()["error_description"],
        "client metadata could not be retrieved"
    );
}

#[tokio::test]
async fn an_undeclared_redirect_uri_is_refused_without_redirecting() {
    // Hole 3: this is where the code used to go.
    let h = harness().await;
    let (_, challenge) = pkce();
    let reply = par_with(
        &h,
        &[
            ("client_id", CLIENT),
            ("redirect_uri", "https://evil.example/cb"),
            ("response_type", "code"),
            ("scope", "atproto"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert_eq!(reply.json()["error"], "invalid_request");
    assert!(reply.location.is_none(), "a refusal never redirects");
}

#[tokio::test]
async fn a_scope_without_atproto_is_refused() {
    let h = harness().await;
    let (_, challenge) = pkce();
    let reply = par_with(
        &h,
        &[
            ("client_id", CLIENT),
            ("redirect_uri", REDIRECT),
            ("response_type", "code"),
            ("scope", "transition:generic"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert_eq!(reply.json()["error"], "invalid_scope");
}

#[tokio::test]
async fn a_scope_the_client_did_not_declare_is_refused() {
    let h = harness().await;
    let (_, challenge) = pkce();
    let reply = par_with(
        &h,
        &[
            ("client_id", CLIENT),
            ("redirect_uri", REDIRECT),
            ("response_type", "code"),
            ("scope", "atproto transition:chat.bsky"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert_eq!(reply.json()["error"], "invalid_scope");
}

#[tokio::test]
async fn a_loopback_client_id_naming_an_external_redirect_is_refused() {
    let h = harness().await;
    let (_, challenge) = pkce();
    let reply = par_with(
        &h,
        &[
            (
                "client_id",
                "http://localhost?redirect_uri=https%3A%2F%2Fevil.example%2Fcb",
            ),
            ("redirect_uri", "https://evil.example/cb"),
            ("response_type", "code"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert_eq!(reply.json()["error"], "invalid_client");
    assert!(reply.location.is_none());
}

#[tokio::test]
async fn a_request_missing_pkce_is_refused_before_any_lookup() {
    // The request's own checks cost nothing; a fetch costs up to five seconds
    // and a request to someone else's server.
    let lookups = Arc::new(AtomicUsize::new(0));
    let h = harness_with(Arc::new(CountingClients {
        inner: app_example(),
        lookups: lookups.clone(),
    }))
    .await;

    let reply = par_with(
        &h,
        &[
            ("client_id", CLIENT),
            ("redirect_uri", REDIRECT),
            ("response_type", "code"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json()["error"], "invalid_request");
    assert_eq!(lookups.load(Ordering::SeqCst), 0, "refused before the lookup");

    // And the counter isn't vacuous: a complete request does look the client up.
    let (_, challenge) = pkce();
    let pushed = push(&h, &client_key(), &challenge).await;
    assert_eq!(pushed.status, StatusCode::CREATED, "{}", pushed.body);
    assert_eq!(lookups.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_consent_screen_names_the_client_by_its_host() {
    // Not its self-asserted client_name: brolly has no list of vetted clients
    // (S5). The full client_id is still shown as the requester.
    let h = harness().await;
    let (_, challenge) = pkce();
    let pushed = push(&h, &client_key(), &challenge).await;
    let request_uri = pushed.json()["request_uri"].as_str().unwrap().to_string();
    let cookie = a_logged_in_member(&h).await;

    let consent = consent_page(&h, CLIENT, &request_uri, &cookie).await;
    assert_eq!(consent.status, StatusCode::OK, "{}", consent.body);
    assert!(
        consent.body.contains("Authorise app.example"),
        "{}",
        consent.body
    );
    assert!(!consent.body.contains("Authorise https://"));
    assert!(!consent.body.contains("Example App"), "client_name is not shown");
    assert!(consent.body.contains("client-metadata.json"), "the full client_id still appears");
}

#[tokio::test]
async fn a_loopback_client_needs_no_metadata_and_is_named_as_development() {
    let h = harness().await;
    let (_, challenge) = pkce();
    let client = "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&scope=atproto";
    let pushed = par_with(
        &h,
        &[
            ("client_id", client),
            ("redirect_uri", "http://127.0.0.1:52431/callback"),
            ("response_type", "code"),
            ("scope", "atproto"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    assert_eq!(pushed.status, StatusCode::CREATED, "{}", pushed.body);
    let request_uri = pushed.json()["request_uri"].as_str().unwrap().to_string();
    let cookie = a_logged_in_member(&h).await;

    let consent = consent_page(&h, client, &request_uri, &cookie).await;
    assert_eq!(consent.status, StatusCode::OK, "{}", consent.body);
    assert!(
        consent.body.contains("Authorise localhost (development)"),
        "{}",
        consent.body
    );
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-server --test atproto_oauth`
Expected: FAIL.
- `an_unknown_client_is_refused_without_saying_why_it_could_not_be_reached`,
  `an_undeclared_redirect_uri_is_refused_without_redirecting`,
  `a_scope_without_atproto_is_refused`,
  `a_scope_the_client_did_not_declare_is_refused` and
  `a_loopback_client_id_naming_an_external_redirect_is_refused`: 201 where 400 was expected.
- `a_request_missing_pkce_is_refused_before_any_lookup`: the second
  `lookups` assertion, 0 where 1 was expected.
- `the_consent_screen_names_the_client_by_its_host`: the page says
  `Authorise https://app.example/client-metadata.json`.
- `a_loopback_client_needs_no_metadata_and_is_named_as_development`: PAR
  already answers 201 (`is_valid_client_id` accepts anything starting with
  `http://localhost`), so it fails on the consent assertion: the page says
  `Authorise http://localhost?redirect_uri=...`.

Everything that already existed still passes.

- [ ] **Step 3: Implement PAR**

In `server/src/atproto_oauth.rs`, add to the imports (`:19-33`):

```rust
use brolly_atproto::client_metadata::{ClientError, ClientId, check_request, parse_client_id};

use crate::client_metadata::{LookupError, lookup_client};
```

After `missing_proof` (`:83-89`) add:

```rust
/// A client, or what it asked for, was refused.
///
/// Always JSON, never a redirect: the redirect URI is exactly the thing that
/// hasn't been shown to belong to the client.
fn client_refusal(e: &ClientError) -> Response {
    let code = match e {
        ClientError::RedirectUriNotAllowed => "invalid_request",
        ClientError::ScopeNotAllowed(_) => "invalid_scope",
        ClientError::InvalidClientId(_)
        | ClientError::InvalidMetadata(_)
        | ClientError::ConfidentialUnsupported => "invalid_client",
    };
    oauth_error(StatusCode::BAD_REQUEST, code, &e.to_string())
}

/// The client's metadata couldn't be used.
///
/// `LookupError`'s `Display` gives every `Unreachable` the same description,
/// so this can't be used to map internal hosts (S4).
fn lookup_refusal(e: &LookupError) -> Response {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_client", &e.to_string())
}

/// What the consent screen calls a client: its host, or
/// `localhost (development)`.
///
/// Never its self-asserted `client_name` or `logo_uri`. The spec says not to
/// show those for clients the operator hasn't vetted, and brolly has no vetted
/// list (S5). `None` if the stored `client_id` no longer parses.
fn app_name(client_id: &str) -> Option<String> {
    match parse_client_id(client_id).ok()? {
        ClientId::Discoverable(url) => url.host_str().map(str::to_owned),
        ClientId::Loopback(_) => Some("localhost (development)".to_owned()),
    }
}
```

In `par` (`:141-218`), keep everything up to and including the DPoP
`let Some(jkt) = proof_thumbprint(...).await else { ... };` statement exactly as
chunk 3 left it. Replace everything after it, through the end of the function,
with:

```rust
    let form: ParForm = serde_urlencoded::from_bytes(&body).unwrap_or_default();

    // The request's own checks first. They cost nothing, and a request that
    // fails them must not make us fetch anything.
    let Some(redirect_uri) = form.redirect_uri else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is required",
        );
    };
    if form.response_type.as_deref() != Some("code") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "only response_type=code is supported",
        );
    }
    let Some(code_challenge) = form.code_challenge else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "PKCE is required",
        );
    };
    if form.code_challenge_method.as_deref() != Some("S256") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge_method must be S256",
        );
    }

    // Then the client: who it is, what its metadata says, and whether this
    // request is within it. Only then is anything stored.
    let Some(raw_client_id) = form.client_id else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "client_id is required",
        );
    };
    let client_id = match parse_client_id(&raw_client_id) {
        Ok(id) => id,
        Err(e) => return client_refusal(&e),
    };
    let metadata = match lookup_client(state.clients.as_ref(), &client_id).await {
        Ok(metadata) => metadata,
        Err(e) => return lookup_refusal(&e),
    };
    let scope = form.scope.as_deref().unwrap_or("atproto");
    if let Err(e) = check_request(&metadata, &redirect_uri, scope) {
        return client_refusal(&e);
    }

    match oauth::push_request(
        &state.pool,
        &raw_client_id,
        &redirect_uri,
        scope,
        form.state.as_deref(),
        &code_challenge,
        &jkt,
        form.login_hint.as_deref(),
    )
    .await
    {
        Ok(request_uri) => (
            StatusCode::CREATED,
            Json(json!({"request_uri": request_uri, "expires_in": 300})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "storing a pushed request failed");
            oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "could not store the request",
            )
        }
    }
}
```

The stored `client_id` is the string the client sent (`raw_client_id`), because
`authorize` and the token endpoint compare against exactly that.

- [ ] **Step 4: Name the client by host on the consent screen**

In `authorize` (`:228-309`), directly after the
`if pushed.client_id != client_id { ... }` block (`:257-263`), add:

```rust
    let Some(app_name) = app_name(&client_id) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "this request's client_id is not valid",
        );
    };
```

and change the `render_consent` call (`:299-308`) so the app name is that, not
the full `client_id`:

```rust
    consent::render_consent(
        &state,
        Protocol::Atproto,
        &app_name,
        &user.username,
        &client_id,
        &pushed.scope,
        "/oauth/atproto/authorize",
        &request_token,
    )
```

`server/src/consent.rs` and `server/templates/consent.html` don't change: the
template already shows `client_id` in "Requested by", which is where the full id
belongs.

- [ ] **Step 5: Remove `is_valid_client_id`**

In `adapters/atproto/src/oauth.rs`, delete `is_valid_client_id` and its doc
comment (`:246-254`) and the whole `#[cfg(test)] mod tests` block (`:256-279`),
whose two tests only exercised it. `parse_client_id` and its tests replace both.

Run: `grep -rn is_valid_client_id --exclude-dir=target --exclude-dir=spikes .`
Expected: matches only in `docs/`.

- [ ] **Step 6: Give every other PAR-pushing test file its client**

Run: `grep -rln "oauth/atproto/par" server/tests`

For every file listed other than `atproto_oauth.rs` (chunk 3's XRPC
DPoP-replay test in `server/tests/xrpc.rs` builds the full ATProto token flow,
so expect at least that one): its harness has
`clients: std::sync::Arc::new(brolly_server::client_metadata::StaticClients::default()),`
from Task 2, which now refuses its client as unreachable. Replace that
`StaticClients::default()` with one that registers the `client_id`,
`redirect_uri` and scope that file's PAR sends, for example for a file whose PAR
uses `CLIENT`, `REDIRECT` and `atproto transition:generic`:

```rust
            clients: std::sync::Arc::new(
                brolly_server::client_metadata::StaticClients::default()
                    .with(
                        CLIENT,
                        &serde_json::json!({
                            "client_id": CLIENT,
                            "redirect_uris": [REDIRECT],
                            "scope": "atproto transition:generic",
                            "grant_types": ["authorization_code", "refresh_token"],
                            "response_types": ["code"],
                            "token_endpoint_auth_method": "none",
                            "dpop_bound_access_tokens": true,
                        })
                        .to_string(),
                    )
                    .expect("the test client's metadata validates"),
            ),
```

Use that file's own constants or literals for the id, redirect and scope. If its
PAR used a `client_id` that `parse_client_id` refuses (an `http://` id other than
`http://localhost`, or an IP host), change the test's id to
`https://app.example/client-metadata.json` in both the PAR and the token request.

- [ ] **Step 7: Run it all and watch it pass**

Run: `cargo test -p brolly-server --test atproto_oauth`
Expected: PASS, the new tests and every existing one
(`a_client_gets_a_dpop_bound_token_pair`, `a_refresh_rotates_and_the_old_token_dies`,
`a_client_id_that_is_not_a_fetchable_url_is_refused` and the rest).

Run: `cargo test -p brolly-atproto --lib`
Expected: PASS, with `oauth::tests` gone.

- [ ] **Step 8: Gates**

```bash
cargo fmt --all
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

- [ ] **Step 9: Commit**

```bash
git add server/src/atproto_oauth.rs adapters/atproto/src/oauth.rs server/tests/
git commit -m "fix(atproto): PAR accepts only what the client's metadata allows

PAR accepted any client_id starting with https://, never fetched the
client's metadata, and stored whatever redirect_uri it was given.
Anyone who got a member to approve the consent screen received a token
for that member's repo, and the endpoint was an open redirect.

PAR now runs the request's own checks first, then parses the client_id,
looks up its metadata (loopback clients never touch the network), and
refuses a redirect_uri or scope the metadata doesn't declare. Refusals
are JSON 400s and never redirect: invalid_client, invalid_request or
invalid_scope. An unreachable client always gets the same description.

The consent screen names the client by its host, or 'localhost
(development)', rather than the full client_id or a self-asserted
client_name. is_valid_client_id is gone.

Tokens already issued stay valid until they expire.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 10: Verify from a clean checkout**

```bash
rm -rf /tmp/verify && git worktree add --detach /tmp/verify HEAD
cd /tmp/verify && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings
cd - && git worktree remove /tmp/verify --force
```

Green there, or the commit isn't done.

---

### Notes for the reviewer

1. **`state.clients.lookup` vs `lookup_client`.** The spec's PAR step 3 says
   `state.clients.lookup`, but its lookup section requires a free
   `lookup_client(clients, id)` so no implementation can override the loopback
   branch. The plan follows the lookup section:
   `lookup_client(state.clients.as_ref(), &client_id)`.
2. **`ClientId` is an enum with public variants** (`Discoverable(Url)`,
   `Loopback(Url)`). `Fetcher::fetch` receives a bare `&Url` (fixed interface),
   and `validate` takes `&ClientId`, so the fetcher builds
   `ClientId::Discoverable(url.clone())` itself. That's also what lets unit tests
   fetch `http://127.0.0.1:PORT`, which `parse_client_id` refuses. `validate`
   still applies every metadata rule. The IP-literal defence is duplicated in
   `Fetcher::host_allowed` so it doesn't rest on the caller having used
   `parse_client_id`.
3. **Discoverable `client_id`s must be canonical** (`Url::as_str() == raw`), so
   "equals the fetch URL, as an exact string" has one string to compare. This
   refuses e.g. an uppercase host or an explicit `:443`. The spec doesn't say
   this.
4. **Loopback `client_id` strictness beyond the spec.** It must start with the
   literal `http://localhost` followed by nothing, `/` or `?`. That rules out
   `:80`, userinfo and case variants before URL normalisation can hide them. A
   repeated `scope` is refused. Unknown query parameters are ignored.
5. **Native custom-scheme redirects also enforce the ATProto spec's "single
   colon then a single forward slash".** Our spec quotes only the
   reverse-domain part. Drop the `path.starts_with('/') && !path.starts_with("//")`
   clause if that's unwanted.
6. **Loopback redirect matching ignores only the port.** Scheme, host, path
   *and query* must match. The spec says "scheme, host and path".
7. **`loopback_metadata(&ClientId) -> ClientMetadata` has no error path.** Given a
   discoverable id, it returns metadata with no redirect URIs and an empty scope,
   so `check_request` refuses everything. `lookup_client` never does this.
8. **`ClientMetadata` has private fields and getters.** The only constructors
   are `validate` and `loopback_metadata`, which is what makes `StaticClients`
   unable to hold unvalidated metadata. `StaticClients::with(client_id, document_json)`
   is the registration API. An unregistered id answers `Unreachable`.
9. **`PublicOnly` refuses more than the spec lists:** `0.0.0.0/8` (not just
   `0.0.0.0`), `240.0.0.0/4`, `192.0.0.0/24`, IPv4-compatible `::/96`,
   deprecated site-local `fec0::/10`, and NAT64 `64:ff9b::/96` when its embedded
   IPv4 address isn't public. `is_public` is hand-rolled on octets and segments
   because `Ipv4Addr::is_shared`, `is_benchmarking` and `is_global` are unstable.
10. **What `for_tests`' flags mean.** `allow_loopback` lets loopback IP literals
    past `host_allowed` and stops `PublicOnly` dropping loopback addresses.
    `allow_http` maps to reqwest's `https_only(!allow_http)`. Production
    (`Fetcher::new`) is `false, false`, so it's https-only, which the spec
    implies but doesn't state.
11. **`Fetcher::build` calls `crate::tls::install_crypto_provider()` itself**
    (idempotent), so neither constructor can hit reqwest's missing-provider
    panic even if `main`'s call were moved.
12. **`ClientLookup::fetch`'s return type is spelled through
    `pub type Lookup<'a>`.** It's the same type as the fixed interface, and it
    avoids `clippy::type_complexity` and repeating the type in every
    implementation.
13. **The timeout test takes about 5 seconds.** `for_tests` has no timeout
    parameter (fixed interface), so it runs against the production 5-second
    timeout.
14. **Failure logging.** `Fetcher` logs the underlying reqwest error at `info`
    for the operator. The caller only ever sees the single `Unreachable`
    description.
15. **`authorize` refuses a stored `client_id` that no longer parses** with a
    400 `invalid_client`. Only PARs pushed before this deploy can hit that, and
    they expire within 300 seconds.
16. **Missing `client_id`** is checked after the cheap request checks and
    answers `invalid_client` ("client_id is required"). Before, it was
    `invalid_client` checked first.
17. **Rollout granularity.** The spec lists "`ClientLookup` threaded" and "B" as
    two commits. The plan makes four: rules (1), threading (2), fetcher (3) and
    PAR (4). Tasks 1 and 3 add code nothing calls yet and are safe to deploy.
    Only Task 4 changes behaviour.
18. **Main.rs holds an empty `StaticClients` for exactly one commit** (Task 2).
    Nothing reads it until Task 4, and Task 3 replaces it with `Fetcher::new()?`.
19. **Other PAR-pushing test files.** Chunk 3's XRPC DPoP-replay test runs the
    full ATProto token flow, which this chunk can't see. Task 4 Step 6 finds
    every such file by grep and registers its client. If chunk 3's test used a
    `client_id` that `parse_client_id` refuses, it's changed to
    `https://app.example/client-metadata.json`.
20. **`moka` features.** `store` already takes moka 0.12.16 with `sync`, and
    `server` adds it with `future`. Cargo unifies them into one build.


## Done when

- **Every chunk is merged,** with its clean-checkout verification green.
- **These tests pass:**
  - `cargo test --workspace` includes every test named in the spec's Testing
    section
  - the `Unspent` `compile_fail` doctest fails for the right reason, next to its
    passing twin
- **`cargo deny check` is green.**
- **Deployment steps are done:** `acl-uncontain` has run on every deployed
  instance.
- **The roadmap is updated:** stage 0 is marked done in
  `docs/specs/2026-09-17-interop-roadmap.md`.
