# Stage 5c: write semantics

<!-- doc-paths: skip -->
<!-- The spec names files and behaviours this stage creates, so not every
     path it cites resolves until it's implemented. -->

**Status:** Implemented, 2026-09-30, in three commits: `be9a909` (`POST`),
`1d8a1f1` (`PATCH`), `85e4f15` (`PUT` and the prefix). Drafted 2026-09-29 and
revised after one adversarial review against LDP, WAC, SPARQL Update, RFC
3986/8288/9110, and the code it cites — every claim in the Problem was
checked against the tree. Stage 5a and 5b were each revised through three
passes before approval; this one was implemented after its first.
**Roadmap:** `docs/specs/2026-09-17-interop-roadmap.md`, stage 5, part c. Parts
a (`docs/specs/2026-09-22-solid-resource-metadata.md`) and b
(`docs/specs/2026-09-23-solid-http-surface.md`) landed the state this part
writes onto. Part d (auxiliary resources and the conformance suite) follows
this one.
**Depends on:** stage 5a (every resource has a kind, a version and containment
no client write can change), stage 5b (per-resource `Allow`, `Accept-*`,
`Link`, 401/403/404 by authentication), ADR 0007 (RDF/XML refused).

## Problem

Stage 5b made what a client can *read* true. What a client can *write*, and
what the server says about a write, is still wrong in six ways, and every one
of them is something a Solid app does on its first day:

1. **`Slug` is never read.** The header appears exactly once in the codebase —
   the CORS allow-list (`server/src/lib.rs:191-192`). No handler, extractor or
   `ldp` function consumes it. `ldp::append_in` mints
   `{container}{uuid::Uuid::new_v4()}` (`adapters/solid/src/ldp.rs:1044-1045`)
   and a client that asked for `Slug: hello` gets
   `/~/public/0f8c3e20-….ttl` and a bookmark it can never reconstruct.
   There is no sanitization, no collision handling and no invalid-slug error,
   because there is no slug.
2. **`POST` cannot create a container.** The minted member IRI never ends in
   `/`, so it is always a document (`Kind::RdfSource` or `Kind::NonRdfSource`;
   `check_kind`, `store/src/resources.rs:1007-1019`). The request `Link`
   header is never read — it is only ever built (`server/src/pod.rs:647-691`).
   Inrupt's `solid-client`, soukai and LDO all create containers by
   `POST` with `Link: <http://www.w3.org/ns/ldp#BasicContainer>; rel="type"`,
   and all of them get a document named after a UUID.
3. **`POST` to a document is a silent non-standard append.** A POST whose
   target has no trailing slash appends the body to the document's own graph
   (`ldp.rs:1065-1066`) and answers **201 with the document's own IRI**
   (`server/src/pod.rs:1011`) — a creation status for something that was not
   created. LDP defines POST as a container method; the append this performs
   is available correctly through `PATCH` (`INSERT`). Stage 5a named this
   "stage 0's append, unchanged until 5c" (`ldp.rs:1016-1017`).
4. **`PATCH` requires Write for inserts.** `ldp::patch_in` checks
   `AccessMode::Write` for both patch forms, insert-only included
   (`ldp.rs:1228-1230`), so a caller holding only `acl:Append` — the mode
   whose WAC definition is "add … but not modify or remove" — cannot insert.
   Stage 5b knew: `Allow` deliberately does not offer `PATCH` to an
   Append-only caller, with the comment "5c owns that change"
   (`server/src/pod.rs:549-553`).
5. **A `PUT` can silently change a resource's kind.** PUT an image over an
   RDF document, or Turtle over a binary, and the resource stops being what
   every client holding its `Link rel="type"` was told it was. Stage 5b
   deferred "refusing to change a resource's type by `PUT`" to this part
   (`docs/specs/2026-09-23-solid-http-surface.md:120-123`).
6. **`/~` answers a 405 with an empty `Allow`**
   (`server/src/pod.rs:1242-1254`), and the comment there defers to this
   part whether it should redirect to `/~/`.

Two smaller items ride along because past specs parked them here: `PATCH` on
a missing resource answers 204 where a creating `PUT` answers 201
(`server/src/pod.rs:1063`; the creation is real —
`adapters/solid/tests/ldp_conformance.rs:873-896`), and a `solid:where`
clause cannot match a container's `ldp:contains` because containment is not
in the scratch graph the patch runs against (`ldp.rs:1249-1250`; 5a:
"5c revisits this if the conformance suite needs it").

## Goals

- **A client names what it creates.** `Slug` is honoured, sanitized, and
  disambiguated on collision — never silently ignored.
- **A client can create a container by `POST`,** the way every Solid library
  does, with `Link rel="type"`.
- **`POST` means creation into a container, nothing else.** The non-standard
  append disappears; insertion remains available through `PATCH`, now under
  the mode WAC defines for it.
- **A caller holding only `acl:Append` can insert.** `Allow` and
  `Accept-Patch` say so honestly.
- **A resource's kind is stable.** No `PUT` or `POST` silently converts an
  RDF source into a binary or back.
- **`/~` redirects to `/~/`,** and `/foo` and `/foo/` stay two resources,
  which is what the whole storage layer already believes
  (`storage::is_container`, `adapters/solid/src/storage.rs:21-23`).

## Non-goals

- **Part 5d's items:** `.meta`, `Link rel="describedby"`, deleting a
  resource's auxiliaries beyond the `.acl` case stage 0 already handles, and
  the conformance suite in CI.
- **Media.** Stage 4 (Solid scope): the content-type allow-list, upload size
  limit, `nosniff`, and read access following a publication.
- **Stage 6's items:** writable WebID profile, type indexes, Client ID
  Documents, `prompt=none`, foreign issuers.
- **Redirects between `/foo` and `/foo/`.** They are distinct IRIs (LDP §4.2.4
  treats the trailing slash as meaningful; our `Kind` system agrees). Only the
  bare `/~` prefix gets a redirect, because it is not a resource at all.
- **A slug that spans segments.** `Slug: a/b` is a request to mint two
  resources; that is refused, not interpreted.

## Design

### H1. `Slug`: honoured, sanitized, disambiguated

`POST` to a container reads `Slug` and uses it as the member name when it
can:

- **Sanitization.** The slug must be a single path segment: non-empty after
  trimming whitespace, no `/`, no `?`, no `#`, no control characters, at most
  128 bytes of UTF-8, and not exactly `.` or `..` — a minted `..` member is
  an IRI whose dot segment any client resolving it walks one container *up*,
  out of the storage root, and `.` is one most normalize away; neither is a
  name. Bytes outside RFC 3986 unreserved are percent-encoded when the
  member IRI is built, `%` included (`%` → `%25`): the slug is raw bytes,
  not a pre-encoded segment, so `Slug: a%20b` yields `a%2520b` — lossless,
  and unambiguous where passing the `%` through would not be. The slug is a
  *hint* (LDP §4.2.3 makes the server's naming final), but a representable
  one.
- **Refusal.** A slug that cannot be made a single safe segment — contains
  `/`, `?`, `#`, or control bytes, is exactly `.` or `..`, or exceeds the cap
  — is a **400** with a body naming the offending slug and the rule. A silent
  UUID is worse than a refusal: the client would build links to a name it was
  never given.
- **Auxiliary suffixes.** A slug ending in `.acl` is a **400**: minting an
  ACL by slug would create access policy for a resource the caller named,
  under a check (`acl:Control` on the governed resource, stage 0 A2) the POST
  never passed. Part 5d extends this to `.meta`.
- **Collision.** If `{container}{slug}` exists, the server disambiguates by
  appending `-1`, `-2`, … before any extension, and answers 201 with the
  `Location` of what it actually minted — the same contract CSS implements
  and `solid-client` depends on. A 409 would make the common
  create-with-preferred-name flow a retry loop.
- **No slug, empty slug, whitespace slug:** today's UUID minting, unchanged.

`Slug` on other methods is ignored, as everywhere else in LDP.

### H2. Container creation by `POST`

`POST` reads the request `Link` header for `rel="type"` naming
`ldp:BasicContainer` or `ldp:Container`. The header is parsed per RFC 8288 —
comma-separated fields, quoted parameters, a `rel` that is itself a
space-separated token list, several `Link` fields on one request — and the
type target is matched **exactly** against the two LDP IRIs, never by
substring: a target that merely *contains* `ldp:BasicContainer`, or a
`rel` that is not `type`, decides nothing. When the match holds and the
body is RDF or empty, the minted member is a container: the IRI is
`{container}{slug}/` —
the trailing slash is appended whatever the slug ended with, because
`check_kind` requires a container's IRI to end in `/`
(`store/src/resources.rs:1007-1019`) — and the content goes through
`Content::Container`, so `container_body`'s containment protections
(`ldp.rs:788-863`) apply to it from birth.

- A container-typed `POST` with a **binary** body is the existing `NotRdf`
  415: containers take RDF.
- The authorization does not change: creating any member requires Append on
  the parent (Write satisfies), which is what `append_in` already checks
  (`ldp.rs:1036-1038`).
- `Link rel="type"` with any other value is ignored — the body's
  content type decides document vs binary, as today. Only the
  container/non-container distinction is the `Link` header's to make,
  because that is the one thing a body cannot express.

### H3. `POST` is a container method

A POST whose target IRI does not end in `/` is a **405 with an `Allow`**
computed exactly as 5b's H4 computes it for the target (for an absent
document-shaped target: `PUT, PATCH, OPTIONS`). The 405 comes before any
`Slug` or `Link` validation — the method is wrong for the target whatever
the slug says. The append moves out of `POST` entirely; the same insertion
is a `PATCH` with `INSERT DATA`, which 5b already serves. Authorization
runs before the 405, so a caller with no mode at all still gets 401/403
per 5b's H1, and the 405 leaks nothing an `OPTIONS` would not: the target's
kind is decided by the IRI's shape.

**The `Allow` builder's `POST` line follows the same shape rule**
(`server/src/pod.rs:544-548`). Today it offers `POST` on any *existing*
target the caller may append to, document-shaped included — after H3 that
would be a lie on documents, and it already is one on missing containers,
which the auto-create rule below makes POSTable. The line becomes: `POST`
is offered iff the target IRI is container-shaped and the caller holds
Append-or-Write on it; existence is irrelevant, the same way it is for
`PUT` and `PATCH`, the other creation methods. The 405's `Allow` comes out
of the same builder, so the two cannot disagree.

`POST` to a *missing* container path (`/~/newdir/`) keeps today's
auto-creation of the intermediate container (`contain`,
`store/src/resources.rs:878-888`) — it matches `PUT`'s behaviour on missing
parents, and WAC still evaluates against the nearest ancestor's
`acl:default`.

### H4. A creating response says what it created

`POST`'s 201 gains the same `Link` set a creating `PUT` sends (5b H6:
`rel="type"` for the minted kind, `rel="acl"`, `rel="storageDescription"`),
not just `Location`. A client that just made a container by H2 learns the
container's ACL IRI in the same response it learns the container's IRI. A
`PATCH` that creates a resource (which `store_patched` → `put` already
performs, `ldp.rs:1244-1247`) answers **201 with `Location` and the `Link`
set** instead of 204; a modifying `PATCH` stays 204. Creation and
modification should not be indistinguishable on the wire.

### H5. `PATCH` access modes: Append for inserts

The patch is parsed **before** the mode is checked, and classified:

| Patch | Modes | Why |
|---|---|---|
| N3 Patch: `solid:inserts` only (with or without `solid:where`) | **Append** | It adds, and WAC's Append is "add … without the right to modify or remove" |
| N3 Patch: any `solid:deletes` | **Write** | Removal is modification |
| SPARQL: `INSERT`/`INSERT DATA` only | **Append** | Same line |
| SPARQL: any `DELETE*` form, or `DELETE/INSERT … WHERE` | **Write** | Same line |
| Either form targeting an `.acl` | **Control** (unchanged) | Stage 0 A2 |

`ldp::patch_in` parses and classifies first, then checks the classified mode
inside the transaction (`ldp.rs:1228-1230` today checks `Write`
unconditionally). **Classification reads the parsed patch, never the raw
bytes** — the N3 structure's presence of `solid:deletes`, the update
algebra's operation kinds — the same discipline as H7's allow-list, and
load-bearing the same way: a `DELETE` hidden inside a comment or a string
literal that a bytes-level classifier misses is an Append-authorized
destroy, and a `DELETE` the classifier sees where none exists merely
refuses an insert. A sequence of operations is as strong as its strongest:
any `DELETE` anywhere in the request checks Write. `Allow` and
`Accept-Patch` then offer `PATCH` to an Append-only caller (removing the
carve-out at `server/src/pod.rs:549-553`), which is the honesty 5b's H4
deferred here. A creating, insert-only `PATCH` on a missing target is
authorized under Append on the effective ACL — consistent with H3's POST
rule that creating in a container is an Append operation.

### H6. `solid:where` sees `ldp:contains`

`apply_scoped` (`adapters/solid/src/patch.rs:235-273`) copies the resource's
content graph into a scratch store as the default graph. For a container
target, the scratch graph additionally receives **everything a `GET` serves
from metadata** (`container_triples`,
`store/src/resources.rs:1131-1206`): the type triples, `ldp:contains`, and
each member's `dcterms:modified`/`stat:size` — the same one call `read_in`
makes, not a `contains`-only subset, because the rule is "match what a
listing shows" and a listing shows all of it; a `where` blind to the types
or the member metadata would be the same defect one blind to the members
is. The write-back path is unchanged: `store_patched` →
`Content::Container` → `container_body`, which already refuses a containment
*change* with 409, drops an exact echo of a served type, and tolerates a
member-metadata echo by value (`ldp.rs:788-863`). The patch can *read* the
members; it still cannot rewrite them. 5a parked this as "5c revisits this
if the conformance suite needs it" — the suite lands in 5d, and a `where`
that cannot see what a `GET` shows is a defect however the suite votes.

### H7. The patch solver does not fetch

`is_graph_safe` (`patch.rs:213-216`) refuses `GRAPH` and `WITH` — by
substring on the uppercased body, so it also refuses a literal that merely
contains "with", and would miss a keyword it never listed. It does not
refuse **`LOAD`**, which SPARQL Update defines as "retrieve an IRI and
insert its contents". Running a member-supplied `LOAD` through the scratch
store makes the pod process fetch an attacker-chosen URL — an SSRF with the
server's network position, reachable by any member with Append. 5c refuses
`LOAD` — and `CLEAR`, `DROP`, `ADD`, `MOVE`, `COPY`, which are either
destructive in ways the H5 classifier does not model or graph-addressing —
with the same 403 `EscapesGraph` mapping, via an explicit allow-list of
update forms — `INSERT`, `DELETE`, `DELETE/INSERT … WHERE` — rather than a
growing deny-list. A deny-list is how `LOAD` got missed.

The allow-list enumerates *forms*, and `GRAPH`/`WITH` are *modifiers* on
the allowed forms — `INSERT DATA { GRAPH <g> { … } }` is an `INSERT` — so
the list alone would drop today's refusal. The rule is both: an update is
safe iff every operation is an allowed form **and** none carries a `GRAPH`
modifier or a `WITH` clause; either refusal is the same 403 `EscapesGraph`.
Both checks read the parsed update, never the raw bytes, which also retires
the substring matcher's false positives: a literal containing "with" stops
being refused as a graph escape.

### H8. A `PUT` cannot change a resource's kind

A `PUT` to an existing resource whose body would change its kind — RDF over
a `Kind::NonRdfSource`, or a binary over `Kind::RdfSource`/`Container` — is
a **422** with a body naming the recorded kind and the incoming content
type. The resource keeps its old representation untouched.

- This is the 422 the 5a/5b non-goals parked here: the request is
  well-formed and the media type is individually acceptable; what it asks
  for is semantically impossible, which is 422's meaning, not 415's (the
  type is supported for other targets) or 409's (no conflict with another
  request).
- `PUT` to a container IRI with a binary body remains the existing `NotRdf`
  415 — that target never accepts binaries at all.
- Replacing a binary with *new bytes* (same kind) is unaffected, and still
  drops the description triples per 5a (`store/src/resources.rs:670-672`)
  until 5d moves them to `.meta`.

### H9. `/~` redirects; `/foo` vs `/foo/` does not

- `GET /~` (and any method on it) answers **308 (Permanent Redirect)** to
  `/~/`, preserving the method and body. The 405 with an empty `Allow`
  (`server/src/pod.rs:1242-1254`) is replaced. 308 rather than 301 so a
  `PUT /~` is not degraded into a `GET /~/` by an over-helpful client. A
  browser does not follow a redirect that answers a CORS preflight, so a
  preflighted script aimed at `/~` fails rather than following — the same
  failure today's 405 already is; the redirect serves the clients that do
  follow (humans, curl, servers).
- `/foo` and `/foo/` remain two resources with no redirect in either
  direction. They are distinct IRIs; the storage layer, the ACL placement
  (`acl_iri`, `ldp.rs:238-243`), and 5a's kind rules already treat them so,
  and a redirect would make two resources one while both may exist.

## What this changes in the code

| File | Change |
|---|---|
| `adapters/solid/src/ldp.rs` | `append_in` takes a slug and a `requested_kind`, sanitizes (H1), mints container IRIs ending `/` (H2), refuses document-shaped POST targets with a new `LdpError::NotAPostTarget` (H3); `patch_in` parses, classifies and checks Append/Write (H5); `put_in` refuses kind change with a new `LdpError::KindChange` (H8); `patch_in` reports created vs modified (H4) |
| `adapters/solid/src/patch.rs` | `is_graph_safe` → an allow-list of update forms plus the `GRAPH`/`WITH` modifier refusal, both on the parsed update (H7); `apply_scoped` seeds a container target's served metadata into the scratch graph (H6); patch classification, from the parse, exported for `ldp` (H5) |
| `server/src/pod.rs` | `post` reads `Slug` and `Link` headers and passes them down (H1, H2); maps `NotAPostTarget` → 405 with 5b's `Allow` builder, whose `POST` line becomes container-shape + Append-or-Write (H3); `KindChange` → 422 (H8); `patch` answers 201/204 by outcome and its `Allow` offers `PATCH` to Append-only callers (H4, H5); `subdomain_fallback`'s `/~` arm becomes a 308 (H9) |
| `store/src/resources.rs` | nothing, except `append` gains the minted-kind path H2 needs if `kind_for_iri` cannot express it (it should — a trailing `/` already selects `Container`) |

**Tests whose expectations change** (rewrite, don't delete): the
`append_permission_does_not_confer_replace` family
(`adapters/solid/tests/ldp_conformance.rs:427-486`) gains insert-only-PATCH
cases; `a_patch_that_creates_a_resource_lists_it` (`:873-896`) asserts 201;
`pod_http.rs`'s `an_append_only_caller_can_discover_that_it_may_post`
(`:2051-2081`) gains the `PATCH`/`Accept-Patch` assertions it currently
forbids; every POST that today receives a UUID `Location` and every
POST-to-document append (`ldp.rs:1065-1067` producers) is rewritten to the
H1–H3 contract. New cases the review adds: `Slug: .` and `Slug: ..` → 400;
a slug carrying `%` round-trips percent-encoded (`a%20b` → `a%2520b`); a
`Link` whose type target merely *contains* `ldp:BasicContainer`, or whose
`rel` is not `type`, decides nothing; an existing document's `Allow` no
longer offers `POST`, and a missing container-shaped target's does; an
insert-only update with the bytes "DELETE" inside a string literal
classifies as Append, and a real `DELETE` inside a comment is still Write;
`LOAD` and a `GRAPH`-modified `INSERT` both 403.

## Chunks

Three, one commit each, each leaving `main` deployable:

1. **`POST`.** Slug sanitization and disambiguation, container creation by
   `Link rel="type"`, 405 for document-shaped targets, the `Link` set on the
   201. *It rewrites the most existing POST tests and owns one new error
   variant; everything else is additive on top of it.*
2. **`PATCH`.** Classification and Append for inserts, the solver allow-list
   (`LOAD` refusal), `where`-sees-`ldp:contains`, 201 on create.
   *The security fix (H7) and the mode change (H5) are one commit because
   both live in `patch_in`'s new parse-classify-check order; splitting them
   would leave a commit where the check runs before a parse the allow-list
   depends on.*
3. **`PUT` and the prefix.** `KindChange` → 422, the `/~` 308, the
   trailing-slash documentation. *Smallest and most mechanical; it carries
   the two decisions most likely to be revisited by 5d's conformance run, so
   it lands last and alone.*

## Decisions

| # | Decision | Why |
|---|---|---|
| H1 | `Slug` sanitized to one safe segment (≤128 bytes, no `/?#` or controls, not `.` or `..`, raw bytes percent-encoded — `%` → `%25`); invalid → 400 naming the rule; `.acl`-suffixed → 400; collision → `-N` disambiguation; absent → UUID | A slug is a hint the client must be able to trust the *response* over; a `..` member is an IRI that walks out of the pod when a client resolves it; minting an ACL by slug would bypass the Control check; CSS's disambiguation is what `solid-client` expects |
| H2 | `Link rel="type"` with `ldp:BasicContainer`/`ldp:Container` on a POST mints a container; IRI gains the trailing slash; RDF-only body; authorization unchanged | It is the one creation fact a body cannot express; every Solid library creates containers this way |
| H3 | POST to a document-shaped IRI → 405 (before slug or `Link` validation) with 5b's `Allow`; the append is deleted from POST; missing container targets still auto-create; the `Allow` builder's `POST` line becomes container-shape + Append-or-Write, existence irrelevant | POST is LDP's create-in-container; a 201 that named something that already existed is a lie; `PATCH INSERT` is the standard append; `Allow` must not offer a method the routing refuses, and must offer the creation methods on absent targets the way `PUT` and `PATCH` already are |
| H4 | Creating POST and PATCH answer 201 + `Location` + the H6 `Link` set; modifying PATCH stays 204 | Creation and modification differ; the client learned the ACL IRI in the same round trip it minted the resource |
| H5 | Insert-only patches (N3 or SPARQL) check **Append**; anything that deletes checks **Write**; classification from the parsed patch, never the bytes, a sequence as strong as its strongest operation; parse-then-check; `Allow`/`Accept-Patch` follow | WAC defines Append as add-without-modify; the current Write-only check refuses the mode's defining operation; a `DELETE` missed by a bytes-level classifier is an Append-authorized destroy |
| H6 | Everything a `GET` serves from metadata — types, `ldp:contains`, member `dcterms:modified`/`stat:size` — is seeded into the patch scratch graph via the same `container_triples` call; write-back protections unchanged | A `where` that cannot see what a `GET` shows is incoherent, and a listing shows more than `contains`; `container_body` already refuses changes and tolerates echoes, so this adds reading, not writing |
| H7 | The solver accepts an allow-list of update forms, and refuses the `GRAPH`/`WITH` modifiers on even the allowed ones; `LOAD` et al. → 403 `EscapesGraph`; both read the parsed update | `LOAD` is a member-triggered server-side fetch — an SSRF; a deny-list is how it got missed, and the list alone would drop the `GRAPH`/`WITH` refusal because they are modifiers, not forms |
| H8 | A `PUT` that would flip RDF↔binary on an existing resource → 422, old representation intact | Kind is a contract `Link rel="type"` made; 422 is "well-formed, semantically impossible" |
| H9 | `/~` → 308 `/~/`; no `/foo`↔`/foo/` redirects | The prefix is not a resource; the two slash forms are, and the whole store already says so |
