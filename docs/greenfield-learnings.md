<!-- doc-paths: skip -->

# Learnings & Takeaways — what to do differently greenfield

**Date:** 2026-08-18\


**Basis:** `mycomyco` @ `0929d6d` — 8 crates, ~50.7k lines of Rust, 461 commits,
37 migrations, ~200 plan docs, 11 ADRs, 637 tests.\


**Goals assumed for the rewrite:** Solid Protocol support, ATProtocol support,
a Mastodon instance, and **all data harmonized across all protocols via the
triplestore**.

---

## 0. The headline

The fourth goal is the one this codebase did not achieve, and the reason is
structural rather than incidental. Today there are **three different, mutually
incompatible stories about what "the triplestore is canonical" means**, and each
one ships with an escape hatch that quietly admits it isn't:

| Surface | Stored as | Escape hatch |
|---|---|---|
| ActivityPub / Mastodon | AS2 JSON-LD expanded into a named graph at the activity IRI | `mycorriza:rawJson` literal holding the original JSON verbatim (`mycorriza-activitypub/src/storage.rs:66`) |
| ATProtocol | JSON flattened to triples under synthetic `urn:atproto:field:*` predicates (`mycorriza-atproto/src/translate.rs:19`) | The predicates are private; no Solid or AP reader understands them |
| Solid / LDP | Arbitrary user RDF | None — but it's an island; LDP writes were deliberately unhooked from everything else (`docs/plans/v0.16/06a-remove-ldp-atproto-mirror.md`) |

Only **one** pair is genuinely harmonized: ActivityPub ↔ Mastodon. That works
because Mastodon is not a storage model at all — it's a *projection* over AS2
graphs computed at read time (`mycorriza-mastodon/src/translate.rs`,
`timelines.rs`). That is the pattern that worked, and it is the pattern to
generalize.

ATProto ↔ everything else is bridged by exactly one hand-written shim covering
exactly two fields: `profile_sync.rs` syncs `displayName`/`description` between
`app.bsky.actor.profile` and `foaf:name`/`vcard:note`. Every other atproto field
lands in the store as an opaque `urn:atproto:field:` triple that no other
protocol can read. There is no third bridge, and none was ever planned.

**Takeaway:** "harmonize via the triplestore" is not a storage decision. It is a
*vocabulary* decision. Storing four protocols' JSON in one quadstore harmonizes
nothing if each protocol writes its own private predicates. The rewrite must
start by choosing one canonical domain vocabulary and treating every protocol as
a lossy view over it.

[nk]: The core goal here is to ensure that data written across all three surfaces is at the very least _accessible_ through each other surface. When I say that "all data is harmonized via triplestore" I mean that when a user hits "export" they get a single dump of triples with all their data from all protocols. This means that where data makes _sense_ to join in talking about things like ARE the same things, like user profiles, we then can make vocab decisions (or context decisions) to say "My User Profile is this" and that gets displayed in Bsky, Mastodon, or any Solid app.

[claude]: That's a materially different — and easier — target than §0 argues for, and it corrects me on one point. You need **two layers, not one canonical vocabulary**:

**Faithful layer (always on).** Every protocol write lands as triples that round-trip exactly. Lossless, no mapping required, works for lexicons nobody has seen yet. This is what makes "export" whole — and it means my criticism of `urn:atproto:field:*` was half wrong. As a faithful layer it is correct and necessary. Its actual defect was being the *only* layer.

**Canonical layer (only where things genuinely are the same thing).** For the subset with real cross-protocol identity — profile first — *additionally* assert canonical triples. Start with profile and stop there until a second case earns it.

The mechanism matters. Don't join with `owl:sameAs` and reasoning. **Agree on the subject IRI.** The WebID `https://alice.base/profile#me` is the node; the Solid profile writer, the AP actor builder, and the atproto profile adapter each assert `foaf:name` onto *that same subject*, in their own named graphs for provenance. Then there is no join to perform — it is one node with contributions from three sources, and `project_profile` already reads exactly that shape. **Harmonization is agreement on the subject, not just the predicate.**

So §0's "every protocol is a lossy view over one vocabulary" is too strong for your goal; the two-layer framing above replaces it.

---

## 1. What worked — keep these

These are load-bearing and correct. Carry them forward without re-litigating.

**Read-time projection instead of per-protocol tables.** `ProfileProjection`
(`mycorriza-base/src/profile.rs`) reads the WebID graph once and feeds the
Solid profile document, the AP actor doc, and the Mastodon Account JSON. Adding
a field to the graph flows to all three with no index to maintain. This is the
single best idea in the codebase.

**ADRs, written as decisions are made.** Eleven of them, Nygard format, short.
When I needed to understand why `did:web` and `did:plc` coexist, ADR 0007
answered it in 40 lines. Keep this discipline; it survived the codebase.

**Trunk-based development with dormant flags** (ADR 0003, ADR 0008). Federation
shipped fully integrated with `federation_enabled = false`, so every crypto and
queue path was exercised locally from day one. 461 commits with no merge debt.

**Local-only-by-default federation.** Safe default, all code paths still hot.

**Workspace decomposition along protocol seams** (ADR 0010). Correct destination.
The mistake was arriving there at month three (see §2.5).

**Per-user subdomains** (ADR 0004). `https://alice.base/profile#me` is a natural
WebID and the subdomain *is* the identity prefix. Costs are real (wildcard DNS,
wildcard TLS, apex-vs-subdomain router split) but they're paid once.

**Migration ownership by filename prefix** (ADR 0009). One directory keeps
`sqlx-cli` working; prefixes keep ownership legible. Cheap, effective.

---

## 2. What to do differently

### 2.1 Keep per-user stores — the fan-out was self-inflicted, not inherent

Per-user isolation is a hard requirement, and nothing below asks you to give it
up. But two different problems got conflated in the original analysis of this
codebase, and separating them changes the answer.

**Cross-*protocol* joins are not constrained by per-user stores at all.**
"My AP followers vs my atproto follows," "my profile as Solid sees it vs as
Mastodon sees it," "every graph in my pod that mentions this IRI" — all of these
live inside one user's data and are a single SPARQL query against that user's
store. What blocks them today is not topology, it's that each protocol writes
private predicates (`urn:atproto:field:*`) into that store, so there is no shared
term to join *on*. That is the vocabulary problem in §2.3, and fixing it makes
cross-protocol joins work in a per-user store with no topology change whatsoever.

**Only cross-*user* queries are genuinely constrained**, because embedded
Oxigraph `Store` instances have no federated query — SPARQL `SERVICE` needs an
HTTP endpoint per store, which an in-process store doesn't expose. A query
spanning alice's and bob's stores has to be executed by application code opening
both. That much is real.

**But most timeline work never needed a cross-user query.** ActivityPub already
solved this with push: delivery writes into the *recipient's* store. Your inbox
is your home timeline, pre-denormalized by the protocol itself. And this codebase
already does the write half correctly —
`mycorriza-activitypub/src/processors/create.rs:35` calls
`insert_activity_graph(&store, note_id, object)` where `store` is the
**recipient's** store, and `mycorriza-mastodon/src/notifications.rs` correctly
projects notifications out of those inbox graphs.

Then the home timeline ignores all of it. `timelines.rs:140-162` reads the
viewer's `following` collection, resolves each followee to a user, opens *that
user's* store, and walks *their* outbox — N stores per request, to reassemble
data that is already sitting in the one store it just closed. The read path
contradicts the write path. That is the O(n), and it is self-inflicted.

**Greenfield: read your own store.** Home timeline = enumerate the viewer's own
inbox graphs, filter to `Create`/`Announce`, sort by key, paginate. One store
open, no fan-out, and it stays correct for remote authors too — which the
outbox-walking version never could, since it can only resolve *local* actors
(`local_actor_to_user`, `timelines.rs:149`) and silently drops every remote
followee's posts with a `continue`.

The one piece missing today is enumerability: `process_create` writes the note
graph into the recipient's store but never adds a containment triple, so there is
no collection to walk. Add membership plus a sort key on inbox arrival and the
timeline becomes a single-store read.

**What no user's own store can answer** — and therefore wants the server-agent
store in §2.2, which preserves isolation because it holds derived pointers, never
content. Note that these are not exceptions to the push principle so much as a
second subscriber: the server agent receives the same deliveries a user does, and
records a pointer instead of the content.

| Query | Why push doesn't cover it | Where it goes |
|---|---|---|
| Public / local timeline | no *user* recipient — nobody delivered it to anyone | deliver it to the **server agent** instead; that is exactly what a relay is (§2.2) |
| Search, discovery, trends | instance-wide by definition | server agent index |
| Admin lists (the `profile_display_name` case) | needs a column across all users at once | server agent index, or a projection cache |
| Status lookup by opaque ID | ULID doesn't say who owns it | see below |

That last one doesn't even need an index if you design the identifier right. The
resource IRI *already* names its owner — `https://alice.base/notes/01H…` — so
lookup by IRI is O(1). It is only Mastodon's opaque numeric/ULID status IDs that
lose the author. Mint Mastodon-facing IDs that encode the owning user, or keep a
pure `id → user_id` routing table (an address, not a copy).

**The Postgres denormalization was a symptom of having no server-agent store, not
of having per-user stores.** v0.15 dropped four content tables on principle —
four create-then-drop migration pairs inside one week of the ledger — and then in
June `20260612000000_add_profile_display_name.sql` put display names back into
Postgres *with a backfill job* (`db.rs:1028`), because the admin list can't open
500 Oxigraph stores to render a table. That instance-wide read had nowhere
legitimate to live, so it went to the only shared surface available. Give it one
(§2.2) and the pressure goes away without touching isolation.

**What isolation costs you, honestly.** Every instance-wide read becomes an index
you have to build, populate, and be able to rebuild. That is a real and ongoing
tax — but it is bounded, it is a known set of queries, and it buys genuine data
portability and a clean delete story. Pay it deliberately, once, in the server
agent, rather than four times by accident in Postgres.

### 2.2 Model the server itself as an agent, with its own store

Today the server is not an agent. There is a shared ActivityPub inbox routed at
the apex (`mycorriza-core/src/lib.rs:1052`) with **no actor and no pod behind
it**, and every `StoreManager` call in the workspace is keyed by a user id —
there is no server-owned graph anywhere. Server-owned state consequently has no
home and is scattered across ad-hoc Postgres tables: `pds_config`, `invites`,
`mastodon_reports`, `instance_rules`, plus the in-memory federation cache.

Give the server a WebID, a DID, a keypair, and a store, exactly like a user. This
is not a workaround — it is a first-class concept in all three protocols:
Mastodon has an **instance actor** (required for authorized fetch), ActivityPub
has the **shared inbox** (already routed here), and ATProto has the **relay**.
The server agent is the natural owner of:

- the local/public timeline index (below),
- moderation state — reports, rules, blocklists, defederation decisions,
- instance metadata that NodeInfo and `/api/v2/instance` project,
- the remote-actor / federation cache,
- inbound activities addressed to the instance rather than to a user.

**Three constraints make it work.**

1. **Index, not mirror — pointers only, content stays home.** The server graph
   stores *references to pod IRIs*, never copies of the content. The core data
   remains canonical in its home store. This is the property everything else
   hangs off, so it's worth being precise about four things.

   **What the index carries: exactly the `WHERE` and `ORDER BY` keys.** A bare
   list of IRIs isn't enough — if you can't sort or filter without dereferencing,
   you reopen every store at query time and you've moved the fan-out rather than
   removed it. So the index carries the predicates a timeline query actually
   filters and sorts on, and nothing else:

   ```turtle
   GRAPH <https://base/index/public> {
     <https://alice.base/notes/01H…>
         myc:author    <https://alice.base/actor> ;
         as:published  "2026-08-18T12:00:00Z"^^xsd:dateTime ;
         myc:audience  as:Public ;
         as:inReplyTo  <https://bob.base/notes/01H…> .
   }
   ```

   Everything in the `SELECT` — content, attachments, tags, CWs — is dereferenced
   from the author's pod, and only for the rows that survive pagination. **Store
   opens collapse from O(local users) to O(page size).** Twenty stores for twenty
   notes, regardless of instance size. That's the whole win, and it only works if
   the filter keys are inlined.

   **This isn't a novel structure — it's an AS2 `OrderedCollection`.** Items in
   AS2 collections are permitted to be IRIs rather than embedded objects; that is
   already how paged outboxes work on the wire. So the server agent's public
   timeline *is* the collection the protocol already specifies, materialized. The
   index stays valid, dereferenceable Linked Data that a Solid or AP client can
   walk — not an opaque cache table in RDF costume.

   **Sort keys are safe to denormalize; authorization keys are not.** If the
   index says a note is public and the pod has since been changed to
   followers-only, an index-trusting read leaks it. So split the decision by
   scale: the index's `myc:audience` is a **bulk narrowing filter** that keeps
   the query from scanning everything and is allowed to over-include; the pod is
   the **grant**, re-checked on the surviving page you are already opening for
   content. That costs nothing extra — the page deref happens either way — and it
   is bounded by page size, so it does not reintroduce the fan-out. Fail-open in
   the index, fail-closed in the pod. This is also what makes the design compose
   with §2.8's "authz evaluates on every read path."

   **Dangling references are the correct steady state, not a bug.** A user
   deletes a note, or you delete their entire store, and the index is left
   pointing at nothing. That is the *good* failure mode — it is the observable
   proof that the pod is canonical. Sweep lazily: a dereference that 404s drops
   the row. It also means account deletion is genuinely `rm -rf` on one store
   with the index self-healing, rather than a hunt for every table that copied
   something. Pointer-only indexing is what makes the delete story real, and
   delete is the acid test of any "canonical" claim.

   Make the full rebuild an operational command from day one; `tools/` already
   has the analogous repo-rebuild binary, and the Node port design proposes the
   same reconciliation pass for oxigraph→repo drift.

2. **Populate it by push, not by scanning.** The index should never be built by
   crawling every user's store — that is the O(n) from §2.1 moved to write time.
   Instead the server agent is *a delivery recipient like any other*: local
   activities are delivered to it, and its processor writes the pointer row. The
   public timeline is then literally the server actor's inbox, which is precisely
   what an ActivityPub relay is and what ATProto's relay does with the firehose.
   The same delivery path that fills a user's inbox fills the index — one
   mechanism, two subscribers, no crawler to schedule or debug.

3. **Keep it visibly derived.** A pointer index in a server-owned RDF graph is
   still denormalization — the same second copy ADR 0001 rejected as a Postgres
   table, wearing RDF clothes. That's fine, and it is materially better than the
   table was: queryable in the same language as everything else, inspectable,
   exportable, and aligned with a real protocol concept rather than invented for
   us. ADR 0011 already sanctions "re-introduce as an *explicit* index whose
   population is a pod-graph mirror, documented as a perf optimization, not a
   source of truth." This is the good shape of that. What it must not become is
   an index nobody remembers is derived — so: rebuildable by one command, never
   read when the pod could answer, and never the thing a delete has to remember
   to update.

**The division of labour with §2.1.** Neither section asks you to weaken
isolation; they answer different halves:

| | Per-user store | Server-agent store |
|---|---|---|
| Holds | all authoritative content | pointers + filter keys only |
| Populated by | the user's own writes, and push delivery | push delivery to the instance actor |
| Answers | home timeline, notifications, follows, every cross-protocol join within one user | public timeline, search, admin projections, ID routing |
| On delete | content is gone — one `rm -rf` | dangling rows, swept lazily |

**The rule that keeps it honest: if a query can be answered from the viewer's own
store, it must be.** Routing it through the server index instead is how you end
up with a mirror you can't retire.

The agent role stands on its own regardless of any of this. Build the server
actor early — it has a shared inbox with nothing behind it and five tables' worth
of homeless state today.

### 2.3 Choose one canonical vocabulary, and make adapters pure and tested both ways

Today the same conceptual "post" has four unrelated representations and no
round-trip guarantee anywhere. The `rawJson` literal exists precisely because
nobody trusts the triples to reconstruct the wire format.

**Greenfield:**

- Pick the canonical vocabulary first. **AS2 + FOAF/vCard is the pragmatic
  choice** — it is already an RDF vocabulary with a published context, it is what
  ActivityPub speaks natively, Mastodon is a trivial projection over it, and
  Solid consumers can read it directly. ATProto lexicons then map *into* AS2
  (`app.bsky.feed.post` → `as:Note`), not into `urn:atproto:field:text`.
- Write each protocol adapter as a **pure function pair** — `wire → canonical
  quads` and `canonical quads → wire` — with no store, DB, or HTTP access in
  the function body. `mastodon/translate.rs` already does this and is the
  easiest module in the repo to reason about.
- **Property-test the round trip.** `wire → quads → wire` must be stable for
  every adapter. This is the test that would have prevented `rawJson` from being
  necessary, and its absence is why nobody could delete it.
- Keep the original wire bytes as **content-addressed provenance**, stored
  beside the graph, never read as the source of truth. Signature verification and
  CAR export need the exact bytes; readers must not.
- Accept that lossy mappings exist. Record them explicitly in a mapping table
  that is code, not prose, so "atproto `langs` has no AS2 equivalent" is a
  reviewable line rather than a silently dropped field.

[nk]: Does this choice mean that when I post in BSKY I see that post in Mastodon? Does this give us a bridge?

[claude]: No, not automatically — and I'd argue you don't want it to be. Three separable things get bundled into the word "bridge":

1. **Storage** — the bsky post is readable as triples through any surface. Yes, that's what §2.3 buys you.
2. **Display** — your bsky post shows up in *your* Mastodon client. This is a projection decision entirely under your control and it's easy: the home timeline reads your own store, so include mapped `app.bsky.feed.post` graphs alongside AS2 `Note`s. No federation, no third party — one account with two protocol faces that you own and opted into.
3. **Publication** — the post is *delivered* to remote Mastodon servers as an AP `Create`. That's the actual bridge, and it's a different problem.

(1)+(2) together are safe, local, and a coherent v1. (3) is where the Bridgy Fed baggage lives. Your version is more defensible than most — your own content on your own server, not third parties mirrored without consent — but the hard parts remain:

- **Thread continuity.** A Mastodon user replies over AP; that reply has no atproto identity, so your bsky thread dead-ends unless you synthesise records for remote AP actors. This is where bridges get genuinely hard.
- **Two follow graphs.** `@alice@base` and `alice.base` have separate followers, so a reply reaching one audience won't reach the other.
- **Delete and edit** have to fan out across both.

Recommendation: make publication **explicit and per-write**, defaulting to the surface the write arrived on — which is also what your note on decision 1 implies. Ship (1)+(2) now; treat (3) as an opt-in per-post target later.

[nk]: Good. I wnt them to be different data types that dont automatically collapse into each other without an explicit bridge decision by a user.

### 2.4 Use the query engine, not just the store

**Repo-wide, across source, tests, and tools: `store.query(...)` appears zero
times.** There are 74 `quads_for_pattern` call sites and exactly one
`store.update(...)` — the `application/sparql-update` PATCH at
`mycorriza-solid/src/ldp.rs:1376`. Nothing in this system has ever run a SPARQL
query.

To be precise about what that does and doesn't mean: **the triplestore is fully
used as a store.** Every resource is a named graph, all content is quads, RDF
serialisation is the wire format, and 74 sites read through it. What is unused is
the **query engine**.

The consequence is architectural. `quads_for_pattern(s, p, o, g)` matches a
single pattern — it cannot join. So every join in this codebase is a hand-written
loop, and the shape shows up everywhere:

- `project_profile` (`mycorriza-base/src/profile.rs:21`) is a SPARQL query
  written as a six-branch `if/else` chain over hardcoded predicates. Adding a
  profile field means editing Rust.
- `resource_to_record` iterates quads and buckets them into a `HashMap`.
- Timelines fetch from N stores and merge in application code.

That is RDF-as-document-store. It works — but it undercuts the goal, because
**harmonization is joins.** "Give me everything asserted about this subject,
whichever protocol wrote it" is one query and is miserable to hand-roll; so is
"every graph in my pod referencing this IRI," and so is any projection that ought
to be data rather than code. A shared vocabulary (§2.3) is the *necessary*
condition for harmonization; a query engine is the *sufficient* one. This
codebase has neither — and fixing only the vocabulary would still leave nothing
able to express a join over it.

Nothing decided this. There is no ADR saying "don't use SPARQL" — it accreted.
Pattern matching is genuinely right for LDP `GET` (fetch one graph, no join),
that was the first helper written, and once every subsequent helper followed the
same shape nobody reached for a query again.

**Decided: SPARQL-first.** Use Oxigraph's engine wherever it fits. The operating
rule, so "as much as possible" stays actionable rather than dogmatic:

> **A join, a traversal, or an aggregation is a query. A single-graph fetch or an
> existence check stays a pattern lookup.**

**The two query surfaces this gives you.** Under per-user stores (§2.1) a query
spans one user's data — and that turns out to be exactly the right seam:

| Surface | Contains | Answers |
|---|---|---|
| **Pod store** | one user's data, all protocols | cross-*protocol* joins — the harmonization story |
| **Server-agent store** (§2.2) | pointers + filter keys for *all* users | cross-*user* queries — timelines, search, admin, moderation |

Every query is one or the other, and neither needs cross-store federation. That's
a complete story, and it makes the two-store design *stronger* under SPARQL-first
rather than something to work around. It also upgrades the server index from a
perf structure to the instance's declarative query surface: the public timeline,
search, and admin lists all become queries against it.

**The rewrite inventory.** Concrete places where a query replaces hand-rolled
traversal, in rough order of payoff:

- **WAC.** `agent_matches` (`wac.rs:153`) hand-checks four agent cases including
  `acl:agentGroup` → `vcard:hasMember`, which is a property path; and
  `find_effective_acl` (`:441`) walks the container hierarchy with string
  manipulation plus existence probes. An authorization check is close to a single
  `ASK` with a property path and a `UNION` over the agent cases. This is the
  largest module in the workspace at 1,767 lines and the densest concentration of
  query-shaped code in it. (It is also where a debug `eprintln!` sits inside the
  authorization path at `:450` — see §2.10.)
- **`project_profile`** — a query plus a predicate→field mapping table.
- **`resource_to_record` / `triples_to_json`** — a `HashMap` accumulated in a
  loop is a `GROUP BY` written by hand.
- **Timelines and notifications** — projections over the viewer's own inbox
  graphs, with filtering and ordering pushed into the engine.
- **`collection_members` / containment** — membership and containment walks.

**Where to hold the line.** Oxigraph parses and plans on every call — there are no
prepared statements — so keep the hottest single-graph paths (LDP `GET`, existence
checks) on `quads_for_pattern`. SPARQL-first is about not hand-rolling joins, not
about routing every read through the parser. Measure the LDP `GET` path
specifically before converting it.

**The test of whether you're actually doing this:** adding a profile field should
be a data change — a row in the mapping table — not a code change. If it still
means editing a match arm, the engine isn't doing the work.

**Queries become testable as data.** A fixture suite of query + input graph +
expected solutions is far cheaper than the integration tests currently carrying
this logic, and it runs without Postgres (§2.11).

### 2.5 Normalize IRIs at the store boundary — pick one, enforce it

The AS2 namespace exists in the wild as both `http://www.w3.org/ns/activitystreams#`
and `https://...`. This codebase stores whichever one the sender used. Reader
code in five files now has to match **both** — `lookup.rs`, `storage.rs`,
`relationships.rs`, `timelines.rs`, `statuses.rs` — and the commit
`fix(relationships): find Follow/Like receipts written in the https AS2 namespace`
is exactly this bug reaching production. Nineteen `http://` occurrences and 49
`https://` occurrences of the same namespace coexist in the source.

**Greenfield:** a canonicalization pass on every inbound quad, at exactly one
choke point, with a fixed alias table (AS2 http/https, `w3id.org/security` v1
vs v2, Mastodon's `joinmastodon.org/ns#`). One test asserting that no quad in
the store uses a non-canonical namespace. This is a half-day of work that pays
for itself the first week.

### 2.6 Draw the crate boundaries on day one, not at month three

`mycorriza-core` grew into a kitchen sink, then took a **17-plan series (v0.16)**
to decompose, and the result still isn't clean: `mycorriza-core` depends on every
protocol crate, because `app()` — the router — lives in core. ADR 0010 flags this
as known and deferred.

**Greenfield:** the layout below, enforced by CI from commit one.

```
domain/       canonical vocabulary, quad model, projections. Zero protocol deps.
store/        quadstore + graph-scoped access. Depends on domain.
authz/        WAC evaluation over the whole dataset. Depends on domain + store.
identity/     users, DIDs, WebIDs, keys, sessions.
adapters/
  solid/      LDP + N3 Patch + Solid-OIDC
  atproto/    XRPC + MST/repo + PLC + firehose
  activitypub/ AS2 delivery + inbox + HTTP signatures
  mastodon/   client API — a projection layer, no storage of its own
server/       composes adapters, owns the router. The ONLY crate that
              depends on more than one adapter.
```

The invariant that matters: **`app()` lives in `server/`, never in a shared
crate.** That single rule is what makes the dependency graph stay acyclic.

### 2.7 Design the auth surface once, up front — three protocols collide there

`/oauth/authorize` and `/oauth/token` are contested by ATProto OAuth (PAR + DPoP)
and Mastodon OAuth (PKCE + Bearer), because Mastodon clients hardcode the paths.
The resolution (ADR 0002) is a dispatcher that sniffs request *shape* —
`request_uri` param or `DPoP` header → atproto, else Mastodon — and Solid-OIDC is
parked at `/oidc/*` to stay out of the fight. ADR 0002 explicitly notes that a
third OAuth surface at `/oauth/*` would require extending the dispatcher.

Meanwhile there are four parallel token systems in Postgres (`sessions`,
`solid_*` OIDC tables, `atproto_sessions`, `mastodon_tokens`) and four
independent header-parsing paths.

**Greenfield:** one auth dispatcher module that returns a normalized `Subject`
`{ kind, user_id, did, webid, scope, via }` regardless of which scheme
authenticated. Every handler takes a `Subject`. The path multiplex is designed
in from the start, with a documented precedence table, rather than discovered
when Phanpy fails to log in. The Node port design doc
(`docs/superpowers/specs/2026-04-27-mycomyco-node-port-design.md`) already
sketches this correctly — reuse that design.

### 2.8 Authorization must be one layer under every protocol

WAC is implemented well — 1,767 lines, spec-compliant inherited ACLs — and is
reachable from **only** `mycorriza-solid/src/ldp.rs`. ActivityPub reads, Mastodon
reads, and XRPC reads bypass it entirely. Each surface reimplements visibility
in its own idiom (AS2 `to`/`cc` audience, Mastodon `visibility`, atproto's
nothing-at-all).

That's defensible when the surfaces hold different data. It is **not** defensible
once every protocol reads the same per-user store: the same triple is reachable
through four doors, and only one door checks the lock.

**Greenfield:** WAC (or one chosen model) evaluates on every read path, in the
store layer, against the `Subject` from §2.7 — including the page-level re-check
that §2.2 relies on to keep the server index over-inclusive-but-safe. Protocol-specific audience rules
become *additional* filters layered on top, never the only filter. Write one
conformance test suite that runs the same authorization matrix through all four
surfaces.

### 2.9 Survey the library ecosystem before choosing the language

Hand-rolled here: HTTP Signatures (454 lines), MST (553), atproto OAuth (1,265),
DPoP (851), LDP (1,715), WAC (1,767), the repo/CAR layer, the OIDC provider.
That's a large fraction of ~50k lines spent reimplementing published specs.

The "adopt upstream crates" workstream ran at **month three**
(`docs/plans/2026-05-09-adopt-upstream-research.md`) and largely failed:

- The `rsky-*` ecosystem was unusable — half of it unpublished, the rest pinned
  to a yanked transitive dependency that `cargo-deny` rejects outright.
- The `atrium-*` ecosystem passed all five compatibility probes, but of eleven
  proposed swaps, **four were no-ops** because the verdict table had been built
  from line counts rather than from reading the modules, one needed a full
  rewrite, and **only one actually shipped**. The rest are audited but unexecuted.

**Greenfield:** run the library survey in **week one**, and let the result inform
the language choice rather than the other way round. Two honest options:

- **Stay in Rust.** Adopt `atrium-*` for atproto primitives and
  `activitypub-federation` (0.7.x, which unifies on axum 0.8) for AP from the
  first commit — not as a retrofit. Accept that Solid/LDP/WAC has no Rust
  ecosystem and will be hand-written; budget it explicitly.
- **Move to Node/TS.** `@atproto/*` and `@solid/*` are the reference
  implementations, Fedify covers AP, and CSS's WAC modules can be ported. The
  existing `2026-04-27-mycomyco-node-port-design.md` spec is thorough and already
  costed. The trade is losing Rust's type safety on a codebase that currently has
  418 `unwrap`/`expect` calls outside tests.

I'd lean Rust-with-atrium-from-day-one if the team's Rust fluency is the binding
constraint, and Node if time-to-protocol-conformance is. Either way the decision
should be made against the survey, in week one, in an ADR.

[nk]: honestly the team is more comfortable with node plain JS. Are there significant performance implications in this language change?

[claude]: At your scale the language is not the performance risk. The **store backend** is, and it's a Node-specific problem worth settling on day one of the survey rather than week one.

**Verify this first:** the `oxigraph` npm package is a WASM build, and I believe it does not ship the persistent RocksDB backend the Rust crate has — i.e. in-memory only. Confirm before anything else, because if true it invalidates per-user persistent stores at thousands of users. Fallbacks, in my order of preference:

- **Run Oxigraph as a separate server process and talk SPARQL over HTTP.** Costs a hop per query, but buys persistence, full SPARQL, and — notably — real `SERVICE` federation, which *softens* the §2.1 constraint instead of working around it.
- **`quadstore` on abstract-level** — persistent and JS-native, weaker SPARQL.
- **A Rust sidecar for storage only** — team stays in JS for everything else.

**Where CPU actually goes**, none of it alarming in Node: signature verification on inbound AP (native `node:crypto`), RDF parse/serialise (WASM, fine), CBOR/CAR for the MST (`@atproto/repo`, adequate). Raw JS-vs-Rust throughput is not the binding constraint below 10k users.

**What you gain is large and I'd weight it heavily:** `@atproto/*` and Fedify are reference implementations. That is not convenience, it is *conformance*. The Rust path means hand-rolling MST, CAR, DPoP, and OAuth again — this codebase spent a large share of ~50k lines doing exactly that, and the upstream-adoption effort ran at month three and shipped one swap out of eleven proposed.

**On plain JS specifically:** given this much protocol surface, use JSDoc annotations with `checkJs` in `jsconfig.json`. You write `.js` files and never touch TypeScript syntax, but the editor and CI catch the shape errors this codebase currently spends 418 `unwrap`/`expect` calls on. That satisfies "plain JS" literally while recovering most of what you give up leaving Rust.

[nk]: yeah JSDoc is fine. The Oxigraph processes is _why_ we wnt with rust int he first place. Provisioning isolated oxigraph instances per user on registration and wiring in http with basic auth is honestly kind of a pain the ass. We want to have a single docker image that we turnkey into a community.

[claude]: Fair — and I described that badly. I did **not** mean one Oxigraph process per user; that would be as awful as you're imagining at thousands of users. An Oxigraph *server* holds one dataset with many named graphs, so it's a single sidecar and a new user is a new graph IRI — zero provisioning, no per-user anything, and bound to localhost inside your own container it needs no basic auth at all, since it's IPC rather than an exposed service. Still: that *is* the single-dataset design you already rejected, and rejecting it is defensible on grounds beyond provisioning — you'd lose physical isolation, per-user quota accounting (`on_disk_bytes` becomes a query, not a `du`), blast-radius containment, and `rm -rf`-as-delete. So set it aside.

**The more useful finding: you are barely using Oxigraph.** I measured the actual dependency across the workspace:

- `store.query(...)` — SPARQL SELECT/CONSTRUCT/ASK: **0 call sites.**
- `quads_for_pattern(...)`: **74 call sites.**
- `store.update(...)` — SPARQL Update: **exactly one**, `mycorriza-solid/src/ldp.rs:1376`, serving the `application/sparql-update` PATCH content-type. It is guarded by a string check that rejects any `GRAPH`/`WITH` clause and then wraps the body in `WITH <graph>`.

And you already own the machinery that would replace it: `n3patch.rs` is a complete hand-rolled patch engine — `match_where`, `match_patterns_recursive`, `try_match_term`, a bindings table — implementing delete/insert/where over `quads_for_pattern`, transactionally, for the N3 Patch content-type. The two PATCH formats have the same semantics; one delegates to Oxigraph's SPARQL engine and one doesn't.

So on *current* usage the reason you picked Rust is load-bearing for about one
line of code. **Read that as a finding about the codebase, not a
recommendation** — see §2.4. If the intent is to actually query the triplestore,
this measurement describes what was built, not what you should select against,
and the ranking below flips accordingly.

**Revised order of investigation, assuming SPARQL is load-bearing:**

1. **Engine quality becomes a primary criterion.** That puts Oxigraph (or a peer
   with a real SPARQL 1.1 implementation) back at the top and pushes `quadstore`
   down — its `sparql-engine` binding is materially weaker and slower than
   Oxigraph's, which is acceptable for 74 pattern lookups and not acceptable for
   projections-as-queries.
2. **Embedded Oxigraph via a napi shim** is the strongest Node option: single
   process, single image, per-user persistent stores, full SPARQL, no sidecar.
   **Correcting my earlier estimate** — I called this surface "genuinely small"
   when SPARQL looked vestigial. With SPARQL-first it isn't. Marshalling solution
   sequences across the boundary (term kinds, datatypes, language tags, blank-node
   scoping) is the fiddly part, and it moves from peripheral to central and hot.
   Still tractable, but budget it as a real component you own and benchmark, not a
   weekend binding.
3. **Verify the `oxigraph` npm build** regardless; if it persists per-directory
   under Node it beats the shim on maintenance cost.
4. **Staying in Rust gets a real argument back.** Not the one you started with
   ("Oxigraph is embedded") — that's satisfiable from Node — but that embedded,
   full-SPARQL, per-user, single-process is the exact combination Rust gives you
   for free, and every other path has to reconstruct it. With SPARQL-first
   settled, this is now the strongest technical argument on the Rust side, and it
   should be weighed directly against the conformance argument on the Node side
   (`@atproto/*` and Fedify as reference implementations). Those are the two real
   considerations; everything else is secondary.

**One Node-specific gotcha that has no Rust analogue:** store I/O on the event loop. In Rust you'd `spawn_blocking` a synchronous store call and think no more about it; in Node a synchronous native binding blocks the single JS thread, and at thousands of users with an LRU of open stores that will show up as latency under concurrency long before CPU does. `classic-level` is async by default (good); a napi shim must expose async methods or run in a worker. Decide this at the binding layer, not after profiling.

None of this changes the turnkey requirement: all three options are one image, one process, no per-user provisioning.

### 2.10 Structured logging on day one — retrofitting it doesn't happen

`docs/plans/v0.12/06-structured-logging.md` and
`docs/plans/v0.13/09-structured-logging.md` are both marked `status: done`. The
actual state: `tracing_subscriber` is installed in `main.rs`, and the library
crates contain **238 `eprintln!` calls and zero `tracing::` calls**. Nothing the
server does is observable through the subscriber that was installed for it.

Related: 90 `let _ = …` discards. One of them cost real correctness — the status
fan-out queried the dropped `ap_follows` table, swallowed the error into an empty
vec, and delivered every post to nobody, undetected until a code-inspection pass
in June (`docs/superpowers/specs/2026-06-11-mastodon-p0-correctness-design.md`,
defect #5).

**Greenfield:** `#![deny(clippy::print_stderr, clippy::print_stdout)]` in every
library crate from the first commit. Errors on delivery, federation, and storage
paths get logged with context and a metric, never discarded. This is a lint
config, not a workstream.

### 2.11 Make the integration suite run by default

637 tests, of which **228 are `#[ignore]`d** because they need Postgres. That's a
third of the suite that a developer only runs when they remember to, with the
right env var, at `--test-threads=1`.

**Greenfield:** testcontainers or an equivalent, so `cargo test` / `npm test`
provisions its own database and everything runs on every commit. If a test only
runs when someone opts in, it will eventually stop passing, and you won't find
out from the test.

### 2.12 Docs need the same staleness gate as code

ADR 0009 and `migrations/README.md` both direct developers to
`mycorriza-core/migrations/`. That directory does not exist — migrations moved to
`mycorriza-base/migrations/` during the v0.16 extraction, and the docs weren't
updated. Similarly, ADRs 0001/0005/0006/0007/0011 all cite
`mycorriza-core/src/<protocol>/...` paths that the same decomposition moved.

**Greenfield:** a CI check that every filesystem path mentioned in `docs/` and in
ADRs resolves. Twenty lines of shell; keeps the corpus trustworthy. ADRs are
append-only by design, so add a `Superseded by` / errata line rather than
rewriting — but *do* add it.

---

## 3. Recommended sequencing

The instinct to build protocols in parallel is what produced the four-way
representation split. Build the convergence layer first and prove it with one
protocol before adding the second.

1. **Vocabulary + adapter contract.** Canonical AS2/FOAF vocabulary, the
   `wire ↔ quads` pure-function signature, round-trip property-test harness.
   No HTTP yet.
2. **Store + authz + the server agent.** Per-user stores, IRI canonicalization
   at the boundary, WAC evaluating every read. Stand up the server's own agent
   identity and store alongside them (§2.2) — moderation state, instance
   metadata, the shared inbox, and the instance-wide indexes all need an owner.
   Settle the push-vs-pull read rule here (§2.1) before any timeline exists:
   answer from the viewer's own store by default, server index only for
   genuinely instance-wide queries.
3. **Identity.** Users, WebID, `did:web` for routing + `did:plc` for federation
   (ADR 0007 got this right; adopt it directly and use `did:plc` in *all* wire
   formats from the first commit). One `Subject` type.
4. **Solid first.** It's the least opinionated surface and exercises the store,
   authz, and vocabulary hardest. If Solid LDP reads and writes are clean, the
   foundation is sound.
5. **ActivityPub.** AS2 is now the canonical vocabulary, so this adapter is
   thin. Federation off by default (ADR 0008).
6. **Mastodon.** A pure projection over AP graphs plus the client API surface.
   No storage of its own — enforce this as a lint on the crate's dependencies.
7. **ATProto.** Last, because it's the hardest map onto AS2 and the most
   ecosystem-dependent. Adopt `atrium-*` (or `@atproto/*`) rather than
   hand-rolling MST, CAR, and OAuth.

Steps 1–3 are the whole bet. If they're right, 4–7 are adapters. If they're
wrong, you get this codebase again.

---

## 4. Decisions to make before writing code

These are the forks where I don't think the existing codebase gives a clear
answer, and where guessing wrong is expensive:

1. **Does a Solid LDP write become a public post?** Today: no — the mirror was
   removed deliberately, and cross-protocol publication is the user's problem.
   That is a *product* decision that dictates the whole write path. Decide it
   explicitly and write the ADR before step 1.
   
[nk]: No, “posts” are a single type of content among many peers. If a Solid App _writes data that looks like a post where the posts go_ then it’s a post. Otherwise it’s just something else. Solid LDP is generic CRUD for EVERY OTHER APP thats not ATProto or Mastodon.   

[claude]: Good — that settles decision 1, and it's a better rule than a sync flag because it's declarative and discoverable rather than hidden in config. Two things to pin down so it's implementable:

- **"Where the posts go"** = a designated publication container, *typed* so a Solid app can read that it is a publication surface (the outbox container carries `rdf:type as:OrderedCollection` plus a marker your vocabulary defines). Not a hardcoded path string.
- **"Looks like a post"** = `rdf:type as:Note` or a mapped equivalent. Shape **and** location, both required.

The consequence: the LDP→atproto mirror removed in `v0.16/06a` was right to remove *globally*, and comes back *narrowly* — scoped to the publication container only. That is the version that was always correct.

One risk to make explicit: WAC and publication now interact. Write access to the publication container is effectively "may post as me" — a stronger grant than it looks. Say so in the ACL defaults and in the docs, or someone hands an app Append on the wrong container.
   
2. **Language: Rust + atrium, or Node + `@atproto`/Fedify?** Decide against a
   week-one library survey, not from sunk cost. Note that SPARQL-first (§2.4) is
   now settled and constrains this: the survey must treat embedded full-SPARQL
   per-user stores as a hard requirement, and price the napi shim honestly on the
   Node side.
   
[nk]: We'll run a survey and make an ADR with Pros and Cons.

[claude]: Agreed. For the ADR to be decisive rather than a list, it needs to answer three things:

1. **Does the chosen JS RDF store persist to disk at thousands of stores?** (See my note on §2.9 — this can invalidate the storage design, and nothing else matters until it's settled.)
2. **What conformance do you get for free?** Enumerate what `@atproto/*` + Fedify cover versus what you'd hand-roll in Rust — in modules, not lines.
3. **Spike it, don't survey it.** The v0.19 effort failed precisely because its verdict table was built from line counts instead of reading the modules: four of eleven proposed swaps turned out to be no-ops. Build one throwaway path end to end — sign a commit, write a record, verify an inbound signature — *then* write the ADR.


3. **Where does each instance-wide read live?** Per-user isolation is settled
   (§2.1), so the open question is the *inventory*: enumerate every query that
   cannot be answered from one user's store — public timeline, search, admin
   lists, ID routing, moderation — and assign each to the server agent index up
   front. This list is short and knowable now; discovering it one denormalization
   at a time is what produced four create-then-drop migration pairs. Write it
   down before step 2, along with the rebuild command.

[nk]: instance-wide reads live in the Server Agent Store.

[claude]: Confirmed — that's §2.2. The residual work isn't the decision, it's the **inventory**: write the list down before step 2 (public/local timeline, search, admin lists, ID routing, moderation state) along with the rebuild command. The failure mode isn't choosing wrong, it's discovering the list one denormalization at a time — which is what produced four create-then-drop migration pairs in a single week.

4. **Is `com.mycorriza.rdf.resource` worth keeping?** A custom lexicon that no
   atproto client reads, wrapping arbitrary RDF. It made the pod exportable over
   the firehose and made nothing else possible. If the answer is "no," the
   atproto adapter gets meaningfully simpler.

[nk]: No we dont need that, _assuming_ that when I write to my ATProto storage using ANY lexicon (bsky, leaflet, standard.site, whatever) THAT json gets turned into triples and stored in the pod.

[claude]: Agreed on dropping it, and the reasoning links up: your note on decision 1 makes Solid LDP generic CRUD rather than a publication surface, so there is nothing to publish outward as `com.mycorriza.rdf.resource`. Drop it and the atproto adapter loses its strangest module.

Your assumption is right — it's the faithful layer from your §0 note — but one concrete correction about how it works today. The current code flattens *every* lexicon into one flat namespace: `urn:atproto:field:text` (`translate.rs:19`). That collides. `app.bsky.feed.post#text` and `site.standard.doc#text` become the same predicate, and two unrelated lexicons' fields silently merge in the pod.

**Derive the predicate namespace from the `$type` NSID** so each lexicon gets its own term space — `at://app.bsky.feed.post#text` vs `at://site.standard.doc#text`, or any deterministic NSID→namespace function. That preserves exactly the "any lexicon, no mapping needed" property you want while keeping the triples unambiguous, and it makes the canonical layer a pure addition: mapped lexicons *also* assert onto the shared subject; unmapped ones are still stored, still exported, just not cross-visible. Graceful degradation, no gate on ingest.

5. **Scale target.** ADR 0011's O(users × notes) timelines are fine for tens of
   users and fatal at thousands. Write the number down; it decides §2.1.

[nk]: Scale target is thousands. Less then tens of thousands. 

[claude]: Useful — that number settles several open things:

- **The server-agent index becomes mandatory, not optional.** A public timeline over thousands of users cannot walk stores. §2.2 moves from "recommended" to "step 2."
- **It makes the store-backend question decisive** (my note on §2.9). Thousands of *persistent* per-user stores is a very different ask from thousands of in-memory ones.
- **Home timeline via your own inbox scales flat** — cost is independent of instance size, which is the main reason to prefer it over outbox-walking.
- **The honest tradeoff to record:** push moves fan-out from read to write. A user with 1,000 local followers costs 1,000 inbox writes per post. That's fine — you have a delivery queue, and write cost is amortisable and retryable where read cost is neither — but state it as a design consequence rather than discovering it under load.
- **Per-store overhead is a real budget line.** Thousands of separate RocksDB (or equivalent) instances carry per-instance memtable, file-handle, and disk overhead. Measure open cost and steady-state memory for one store, multiply by the LRU ceiling, size the box from that. `StoreManager` currently caps at 500 open with a 1h idle timeout (`store.rs`) — a reasonable starting point that was never validated against a real number.

---

## 5. Numbers, for calibration

| | |
|---|---|
| Rust source | ~50,700 lines, 8 crates |
| Commits | 461 |
| Migrations | 37 — including 4 create-then-drop pairs inside one week |
| Tests | 637, of which 228 are `#[ignore]`d (need Postgres) |
| Plan docs | ~200 across 25 version folders |
| ADRs | 11 |
| `eprintln!` in library crates | 238 |
| `tracing::` calls in library crates | 0 |
| `unwrap`/`expect` outside tests | 418 |
| Largest hand-rolled modules | WAC 1,767 · LDP 1,715 · translate 1,367 · atproto OAuth 1,265 |
