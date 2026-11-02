# Stage 5b: the pod's HTTP surface

<!-- doc-paths: skip -->
<!-- The spec names files this stage creates, so not every path it cites
     resolves until it's implemented. -->

**Status:** Implemented, 2026-09-29, in five commits: `013e8c8` (refusals),
`6d36880` (`describe`, `Allow`, `Accept-*`), `459df46` (discovery),
`63ec0ee` (caching and CORS), `854d8f1` (write responses and bodies). Drafted
2026-09-23 and revised after three adversarial reviews against the Solid
Protocol, WAC, Solid-OIDC, LDP, RFC 9110/9449/6750, the CTS feature files, and
axum's own routing source
**Roadmap:** `docs/specs/2026-09-17-interop-roadmap.md`, stage 5, part b. Part a
(`docs/specs/2026-09-22-solid-resource-metadata.md`) landed the state this part
reports. Parts c (write semantics) and d (auxiliary resources and the
conformance suite) build on this one.
**Depends on:** stage 5a (every resource has a kind, a version and a modified
time), ADR 0010 (storage root at `/~/`), ADR 0007 (RDF/XML is refused), and
stage 0's A2 (`.acl` needs `Control`).

## Problem

Stage 5a made the pod's state correct. What a client can *learn* about that
state over HTTP is still mostly wrong, and a Solid app can't work from it.

1. **A client is never told to authenticate.** Every missing, malformed,
   expired or replayed credential is silently downgraded to the anonymous
   subject (`server/src/pod.rs:95-195`), WAC then denies, and a denied read
   becomes 404. The pod never sends 401, never sends `WWW-Authenticate`, and a
   broken token is indistinguishable from no token. An app whose access token
   expired mid-session sees its own resources vanish rather than a challenge it
   can act on. CTS asserts 401 with a challenge for every unauthenticated
   method (`protocol/authentication/header.feature`).
2. **`OPTIONS` answers for a resource it never looked at.** `pod::options`
   (`server/src/pod.rs:529`) takes no state, no path and no credentials. It
   returns one static `Allow` line listing every method and an `Accept-Post`
   for every resource, container or not, readable or not. A client that trusts
   `Allow` — SolidOS decides which edit affordances to draw from it — is told
   it may write resources it cannot.
3. **`Accept-Put` is never sent, and `served_types()` is dead code**
   (`adapters/solid/src/ldp.rs:1014`, zero call sites).
4. **A resource doesn't say what it is.** No `Link rel="type"` is emitted
   anywhere, so a client can't tell a container from a document from a binary
   without parsing the body — which it can't do for a binary. The storage root
   doesn't advertise `pim:Storage` in a header either, only inside its own body
   (`store/src/resources.rs:1103-1113`), which a client has to already be
   reading to find.
5. **`Link rel="acl"` is built by string concatenation** (`pod.rs:337`), so
   `GET /~/x.acl` advertises `</~/x.acl.acl>; rel="acl"`, a resource that must
   never exist.
6. **There is no storage description resource.** The Solid Protocol requires
   every resource in a storage to link one (§4.1). Nothing serves it, nothing
   links it.
7. **`WAC-Allow` has no `public=` component** (`pod.rs:254`). A client can't
   tell whether the resource it is looking at is world-readable — the one thing
   a share UI has to show.
8. **`Vary` is never sent** although `GET` content-negotiates on `Accept`. CTS
   requires `Vary: Origin` too (`protocol/cors/acao-vary.feature`).
9. **One ETag serves every syntax.** 5a's R4 gives a resource one version, and
   `pod.rs:323` decides 304 from the version alone. A client that cached Turtle
   and revalidates asking for JSON-LD is told its Turtle is fresh.
10. **A `PUT` that creates answers 204.** LDP and every Solid client expect 201.
11. **Deleting a non-empty container is 403,** which says "you may not", when
    the truth is "not while it has members" — §5.4 requires 409 *with a body
    describing the error*. Stage 5a left this mapping in place
    (`adapters/solid/src/ldp.rs:106-116`) pending this part.
12. **The storage root's protections are unreachable, and the root ACL has
    none.** `/~/` is registered with `get`/`post`/`options` only
    (`server/src/lib.rs:319-324`), so `DELETE /~/` is answered by axum's
    method-router before any handler runs, and `ldp.rs:877`'s root guard is
    dead over HTTP. `/~/.acl` *does* route, and `delete_in` has no guard for it
    at all: today a caller with `Control` can delete the storage root's ACL,
    which §5.4 forbids with a 405.
13. **Our own 405s carry no `Allow`,** an RFC 9110 §15.5.6 MUST.
    (Axum's generated 405 does carry one; `pod::subdomain_fallback:557`'s does
    not, and it is reachable for the bare path `/~`.)
14. **An authenticated `HEAD` is anonymous.** `subject_for` is handed the
    literal string `"GET"` (`pod.rs:301`), so a DPoP proof whose `htm` claim is
    `HEAD` — what every correct client sends, and what CTS signs — fails
    verification and is downgraded. HEAD then 404s on the member's own
    resource. The `htu` is built from the percent-**decoded** `Path`, so any
    escaped character mismatches too.
15. **A container listing says nothing about its members.** 5a records each
    resource's modified time and size; a listing carries only `ldp:contains`,
    so a file manager has to `HEAD` every member to draw a list.
16. **A body with no `Content-Type` is guessed at.** `pod::put` and `pod::post`
    default to `text/turtle` (`pod.rs:366`, `:399`); Solid §2.1 makes that a
    MUST-400.

## Goals

- **A client that is refused learns which kind of refusal it was,** without the
  refusal disclosing whether the resource exists.
- **The headers a Solid app reads are computed for the resource and the
  caller,** not asserted statically, and every one of them is true.
- **A resource announces its kind, its ACL, and its storage,** in headers, so a
  client knows what it is holding before it parses anything.
- **What is public is visible as public.**
- **Caches, shared and private, cannot serve the wrong syntax or a stale
  affordance.**
- **5a's write path keeps its shape.** Below the HTTP layer this part adds one
  body-free read (`ldp::describe`), splits one error variant, reports whether a
  `PUT` created, and puts member metadata in listings. Nothing else moves.

## Non-goals

Part 5c covers `Slug`, creating containers by `POST`, the `/foo` vs `/foo/`
distinction, PATCH access modes (so `Allow` does **not** promise `PATCH` to an
Append-only caller here — H4), and 422. Part 5d covers `.meta`,
`Link rel="describedby"` (which points at `.meta` and would be a dead link
before it exists), deleting a resource's auxiliaries with it, and CTS in CI.

Also not in scope:

- **Changing how access is decided.** WAC evaluation is untouched; this part
  asks it one more question (the anonymous probe for `public=`) and reports the
  answers differently.
- **Accepting tokens from other issuers.** Stage 6.
- **Media.** Stage 4. A binary is still owner-only by default.
- **Refusing to change a resource's type by `PUT`.** Today a `PUT` of
  `application/pdf` over an RDF document is accepted — `ldp.rs:431` restricts
  the RDF-only rule to containers and ACLs. H5 tells the truth about that
  rather than changing it; whether it *should* change belongs with 5c.

## Design

### H1. Refusals: 401, 403, 404

The rule that makes this safe to change is that **the status depends only on
the caller's effective modes for the target IRI, never on whether the target
exists.** Effective modes come from the nearest ACL up the path, which exists
whether or not the resource does.

For a request needing mode *M* on IRI *R*, where the caller's effective modes
for *R* are *G*:

| Caller | *M* ∈ *G* | Resource exists | Answer |
|---|---|---|---|
| unauthenticated | no | either | **401** + `WWW-Authenticate` |
| authenticated | no | either | **403** |
| either | yes | no | **404** |
| either | yes | yes | proceed |

**Where the decision lives.** `ldp` knows the modes; only `pod.rs` knows
whether a credential was presented and verified. Threading an `authenticated`
flag into `ldp` would put the credential question inside `brolly-solid`, which
has no other reason to know about tokens, and into every one of its entry
points. Instead:

- `ldp` gains **`LdpError::Denied`** — *the caller does not hold the mode* —
  distinct from `NotFound`, which keeps its current meaning: *the caller holds
  the mode and there is nothing there.*
- `pod.rs` maps `Denied` to **401 or 403** from its own knowledge of the
  credential, and `NotFound` to 404.

Every site that refuses for lack of a mode becomes `Denied`:

| `ldp.rs` | Today | Becomes |
|---|---|---|
| `:259` `read_in`, WAC fails | `NotFound` | `Denied` |
| `:262` `read_in`, no metadata | `NotFound` | unchanged |
| `:402` `Target::prepare`, WAC fails | `Forbidden` | `Denied` |
| `:529` `put_in` | `Forbidden` | `Denied` |
| `:771` `append_in` | `Forbidden` | `Denied` |
| `:869` `delete_in` | `Forbidden` | `Denied` |
| `:872` `delete_in`, no metadata | `NotFound` | unchanged |
| `:878` `delete_in`, storage root | `Forbidden` | `Undeletable` (H12's 405) |
| `:883` and `:111` non-empty container | `Forbidden` | `NotEmpty` (H12's 409) |
| `:954` `patch_in` | `Forbidden` | `Denied` |

`:402` is easy to miss and it matters: it is the pre-lock WAC check that only
runs for **non-RDF bodies**, so leaving it as `Forbidden` would make an
anonymous `PUT` answer 403 for a PNG and 401 for Turtle — the status would
depend on the `Content-Type`. It is live and tested
(`adapters/solid/tests/ldp_nonrdf.rs:255`).

After this split `Forbidden` has no producers left, so it is renamed
`Undeletable` for `:878`'s guard, which `pod.rs` maps to 405 rather than 403.

Nothing about `ldp`'s signatures changes, and `Subject::agent()` is never the
basis for the split: a service-auth subject has `webid: None` and reports
`Agent::Anonymous` (`identity/src/subject.rs:103-110`), but it authenticated,
so it gets 403 and not a challenge it has already satisfied. `subject_for`
returns that bit alongside the subject.

This replaces stage 0's A2 refusal rule — *"a caller without the required mode
gets `NotFound`, so existence isn't disclosed"*
(`docs/specs/2026-09-17-security-fixes.md:242`). The disclosure that rule
avoided is preserved: an unauthenticated caller gets 401 for `/~/secret` and
401 for `/~/does-not-exist` and cannot tell them apart; an authenticated caller
gets 403 for both. Only a caller who may read learns the difference, and
learning it is the point. CTS agrees row for row
(`web-access-control/protected-operation/read-access-public.feature`: public →
401, Bob → 403, and a *permitted* caller reading a fictive resource → 404).

**One accepted disclosure.** Stage 0 also made `delete` remove the resource's
`.acl`. So for a resource shared with Bob by a *direct* ACL: while it exists
Bob has Read and sees 200 or 404; once Alice deletes it, the direct ACL is gone
and Bob's modes revert to the ancestor's, so he sees 403. Bob learns the
resource once existed. Under stage 0 both were 404. We accept it: the
alternative is keeping a deleted resource's ACL, which leaves a rule granting
access to an IRI the member believes they erased.

Paths outside the storage root keep today's 404 and its
`Link rel="canonical"` (`pod::subdomain_fallback`). That is a routing answer,
not an access decision.

### H2. Credentials that don't verify are a 401, not anonymity

**Scoped to the `Authorization` header.** A `brolly_session` cookie (now
`__Host-brolly_session`, ADR 0018) is not a presented credential: it is
`SameSite=Lax` (`auth::tests::the_session_cookie_is_hardened`), so a browser
sends it on any top-level navigation, and a logged-out member opening a public
image in their own pod would be met with a challenge for a credential they
never offered. A cookie that doesn't resolve still falls
through to anonymous, and H1 decides. `extract::credential` already prefers the
header when both are present (`identity/src/extract.rs:85`).

For an `Authorization` header, each of these becomes an immediate refusal,
before any WAC evaluation, and the request is *not* retried as anonymous:

| Failure | `error` |
|---|---|
| malformed header, unknown, expired or revoked token | `invalid_token` |
| failed DPoP proof, replayed `jti`, `htu`/`htm` mismatch | `invalid_dpop_proof` |

Three edge cases, settled while planning:

- A header that can't be parsed at all is `invalid_token`, with the `DPoP`
  challenge — the pod's default scheme.
- A token that verifies but names a WebID this instance doesn't host is
  `invalid_token`. Accepting other issuers' tokens is stage 6.
- A database failure while verifying is a **500**, not a 401: the credential
  may be fine, and a challenge would send a correct client to re-authenticate
  for nothing.

The two codes matter. RFC 9449 §7.1 defines `invalid_dpop_proof` precisely
because `invalid_token` tells a client to refresh a token that is fine — it
would refresh, re-sign the same broken proof, and loop. Neither code leaks
anything a correct client doesn't already know.

`error_description` is omitted. It would be the only place in the surface where
a refusal explains itself to an unauthenticated caller, and the values are
either obvious ("expired") or something an attacker would like to know
("replayed").

### H3. `WWW-Authenticate`

On a 401 from an absent credential, or from a DPoP-bearing one:

```
WWW-Authenticate: DPoP algs="ES256", as_uri="https://{apex}"
```

with `, error="…"` appended per H2's table. Solid-OIDC §9.1 makes `as_uri` a
MUST unless the scheme has its own discovery mechanism, and RFC 9449 §7.1's
`DPoP` parameters (`realm`, `scope`, `error`, `error_description`, `algs`)
include none. The value is the instance's apex origin, byte-identical to what
the profile publishes as `solid:oidcIssuer` (`server/src/profile.rs:96`) and to
the `iss` claim (`solid_oidc.rs:94`).

`ES256` is what we verify — `identity/src/dpop.rs:336` and
`adapters/solid/src/oidc/tokens.rs:191` are ES256-only — and advertising more
would be a lie. `realm` is omitted; RFC 6750 §3 and RFC 9449 §7.1 both make it
optional and Solid-OIDC doesn't use it.

**A bearer credential gets a `Bearer` challenge instead.** Mastodon's API
tokens reach pod URLs through `Credential::Bearer` (`pod.rs:175-193`), and a
Mastodon client can do nothing with a `DPoP` challenge. When the refused
credential was a bare bearer token, the challenge is
`Bearer error="invalid_token"`. An absent credential gets `DPoP` only: the pod
is proof-of-possession by default, and offering `Bearer` unprompted invites a
client to send a bare token that will be refused.

### H4. `Allow`, per resource and per caller

`OPTIONS` becomes a real handler: it resolves the pod, authenticates, and
evaluates WAC for the target. So do `GET` and `HEAD`, which carry the same
`Allow` (CTS reads it from a `GET`; SolidOS reads it from whichever it last
made). `OPTIONS` keeps today's **204**, which CTS accepts alongside 200.

Given effective modes *G* and the target's kind:

| Condition | Methods added |
|---|---|
| always | `OPTIONS` |
| `Read` ∈ *G* | `GET`, `HEAD` |
| `Write` ∈ *G* | `PUT`, `DELETE`, `PATCH` |
| `Write` or `Append` ∈ *G* | `POST` |
| target is the storage root, or the storage root's `.acl` | `DELETE` removed |

`POST` is offered for documents as well as containers: `append_in` appends
triples to a document (`ldp.rs:799-801`) and `pod::post` routes it.

`PATCH` is **not** offered to an Append-only caller, even though the protocol
would allow it, because `patch_in` requires `Write` (`ldp.rs:953`) and 5c owns
the change. Advertising it would be exactly the lie H4 exists to stop.

**`OPTIONS` is gated on holding *any* mode, not on `Read`.** An Append-only
caller — the drop-box and inbox pattern, the client that most needs `Allow` to
learn it may `POST` — must be able to ask. A caller with no modes at all still
gets H1's 401 or 403, so `OPTIONS` is not an existence oracle. For the same
reason `OPTIONS` on a **target that doesn't exist** answers 204 with the
`Allow` a creation would have, where `GET` would answer 404: "may I create
here" is the question, and H5's `Accept-Put` is the answer. For a caller with
`Write` that `Allow` is `PUT, PATCH, OPTIONS` — not `GET` or `DELETE`, which
would 404, and not `POST`, which needs something that exists to post into.

A CORS preflight is not an `OPTIONS` request in this sense — the middleware
answers it before routing (`server/src/lib.rs:161`) and it carries no
credentials by definition.

**Authorization comes before method availability.** `DELETE` of the storage
root by a caller without `Write` is H1's 401/403, not H12's 405. A 405 would
tell a caller with no access that the target exists and is special. For that
ordering to be reachable at all, `/~/` has to route the write methods — see
H12.

Only the **root** container and the **root's** ACL are undeletable: Solid
Protocol §5.4 names precisely those two, and adds that servers must exclude
`DELETE` from their `Allow`. Any other `.acl` may be deleted by a caller with
`Control`: WAC §3.2 makes removing the ACL representation the specified way to
revert a resource to inheriting its container's rules, so refusing the delete
would leave no way to un-share short of writing an empty ACL.

### H5. `Accept-Patch`, `Accept-Post`, `Accept-Put`

Each is sent only when the corresponding method is in `Allow`, on `OPTIONS`,
`GET` and `HEAD`. Solid §5.2 states the MUST unconditionally; we narrow it
deliberately, as CSS does, because a header that advertises a method the caller
may not use is the same lie as a wrong `Allow`.

- `Accept-Patch: text/n3, application/sparql-update` — what `patch` parses.
- `Accept-Post` and `Accept-Put` come from **`accepted_write_types()`**
  (`ldp.rs:1009`), the list the parser accepts. Not `served_types()`, which
  includes RDF/XML — a format `refuse_rdf_xml` (`ldp.rs:671`) rejects on every
  write, per ADR 0007. LDP §7.1.2 and Solid §5.2 define these headers as what
  is *allowed*, so advertising RDF/XML would be advertising a guaranteed 415.
- `Accept-Put` is `*/*` for anything that accepts any media type today — a
  binary, an **existing RDF document** (`ldp.rs:431` applies the RDF-only rule
  to containers and ACLs alone), and an absent target at a document path. It
  is the RDF list for a **container or an `.acl`, existing or not** — decided
  by the path, the same way `PUT` decides it — which is 5a's `NotRdf` refusal
  made discoverable. A missing `/~/new/` advertising `*/*` would invite a PUT
  that is guaranteed a 415.

`served_types()` is deleted rather than promoted: it is the *serialization*
list, it duplicates `syntax::negotiate`'s knowledge, and nothing reads it.
Deleting it leaves `WriteFormat` unused in `ldp.rs:32`'s import.

### H6. `Link` headers

On `GET`, `HEAD`, `OPTIONS`, and on the 201 of a `PUT` or `POST` that creates:

| Relation | Value |
|---|---|
| `type` | `<http://www.w3.org/ns/ldp#Resource>`, plus `#RDFSource`, or `#NonRDFSource`, or `#Container` **and** `#BasicContainer` |
| `type` (storage root only) | additionally `<http://www.w3.org/ns/pim/space#Storage>` |
| `acl` | the target's ACL IRI (H7) |
| `http://www.w3.org/ns/solid/terms#storageDescription` | `{base}/.well-known/solid` |
| `http://www.w3.org/ns/solid/terms#owner` (storage root only) | the member's WebID |

`type` is one `Link` header with a value per URI, comma-joined, which is what
LDP's examples show and what every client parser handles.

A container gets both `#Container` and `#BasicContainer`: the Solid Protocol
names `ldp:BasicContainer` and CTS checks for it, while generic LDP clients
match on `ldp:Container`.

`pim:Storage` on the root is a §4.1 MUST — "servers MUST advertise the storage
resource… when responding to storage's request URI". `solid:owner` is a
conditional one: §4.1 constrains the form ("when a server wants to advertise
the owner… the server MUST include the `Link` header field… targeting the root
container"), and advertising it at all is our choice. We do, because H8's
description names an owner anyway and a client that has the root should not
need a second request to learn whose it is. Together they turn problem 4 from a
body a client must already be reading into something discoverable from any
response.

LDP §4.2.1.4 asks for `rel="type"` on *all* responses to an LDPR's URI,
including errors. We narrow it to successful reads and creates deliberately: a
401 or 403 must not imply what kind of resource is behind it, and a 404 must
not imply one is.

### H7. The ACL of an ACL is itself

`acl_iri(target)` lives in `brolly-solid`, beside `governed()`
(`adapters/solid/src/ldp.rs:162`) and `storage::is_container`, because it needs
both notions. It is **not** the inverse of `governed()`, which strips every
trailing `.acl` (`governed("/~/x.acl.acl") == Some("/~/x")`,
tested at `ldp.rs:1036`):

- `target` ends in `.acl` → `target`
- a container `/~/notes/` → `/~/notes/.acl`
- anything else `/~/note` → `/~/note.acl`

An ACL resource is governed by its own `Control` mode (stage 0's A2), so
pointing it at itself is the truth. Today's concatenation produces
`x.acl.acl`, an IRI with no ACL semantics that a client following the link
would create as an ordinary resource. Note that `authz::acl_candidates`
(`authz/src/wac.rs:84-103`) is pure string work and *does* generate
`/~/x.acl.acl` as its first candidate for `/~/x.acl`; it is a lookup order, not
a statement about which ACL governs what, and H7 does not change it.

### H8. The storage description resource

A new protocol resource at `/.well-known/solid` on each pod subdomain. It
serves Turtle, content-negotiated like any pod read:

```turtle
<https://alice.example/.well-known/solid>
    a <http://www.w3.org/ns/pim/space#Storage> ;
    <http://www.w3.org/ns/solid/terms#owner> <https://alice.example/profile#me> .
```

The protocol mandates the `Link` relation, not a path. `/.well-known/solid` is
what CSS uses for the same document, so a client that has seen one server
recognises ours. Our own well-known space is clear: `openid-configuration` is
apex-only (`lib.rs:206-221`), `webfinger` and `nodeinfo` are apex paths
(`lib.rs:283-287`), and ATProto's `oauth-authorization-server` and
`atproto-did` are different names.

It is **world-readable and read-only**. It describes the storage, not its
contents, and a client must be able to read it before it has credentials —
that is how it discovers where to authenticate. `PUT`, `POST`, `PATCH` and
`DELETE` answer 405 with `Allow: GET, HEAD, OPTIONS`.

It is generated, not stored: it holds nothing a member could edit, and storing
it would put a resource inside the storage that describes the storage, which
`ldp:contains` would then list.

The route goes in `app()`, next to `webfinger` and `nodeinfo`. It is **not**
added to `USER_PROTOCOL_RESOURCES` (`identity/src/routing.rs:20`): that list
feeds only `pod::subdomain_fallback`, which axum never reaches once a route
matches, so an entry there would be dead weight the architecture tests would
later have to explain. Because axum routes are not host-scoped, the handler
resolves the subdomain itself the way `profile` and `actor` do, and answers 404
on the apex.

### H9. `WAC-Allow` gains `public=`

```
WAC-Allow: user="read write append control", public="read"
```

`user=` is the caller's effective modes, as today. `public=` is a second
`granted_modes` probe with an anonymous subject. It has to run **inside the
snapshot**: `Pod::read` drops the snapshot when its closure returns
(`store/src/resources.rs:307-315`), so a header builder in `pod.rs` is working
after the store is closed. The probe therefore happens in `read_in` and rides
out on the outcome, which is what guarantees the two components describe the
same ACL. `identity` gains a `Subject::anonymous()` constructor — `pod.rs`
builds one inline and privately today (`pod.rs:101-107`).

WAC §6.1's ABNF allows an empty group, so a caller with nothing gets `user=""`.
On an `.acl`, `granted_modes` is all-or-nothing on `Control`
(`ldp.rs:217-222`), so `public=` there is `""` unless the ACL grants Control to
everyone.

Sent on `GET`, `HEAD` (WAC §6's MUST) and on `OPTIONS`, under H4's any-mode
gate. Not on writes, where the modes a client would read are the ones it just
exercised.

The cost is a second WAC evaluation per read, against the snapshot already open
and the ACL already resolved: four `authorize` calls over an in-memory graph.

### H10. `Vary`, the ETag, and what a 304 carries

**`Vary` is appended to, never replaced** — H14's CORS layer is outermost and
currently `insert`s (`lib.rs:192`), which would drop whatever the handler set.

- `Accept` on a `GET`/`HEAD` of an RDF source, whose body is negotiated. Not on
  a binary, whose bytes are the same for every `Accept`.
- `Origin` on every response, binaries included — CTS checks exactly that
  (`protocol/cors/acao-vary.feature` uses a `.txt`).

**The ETag gains a syntax token:** `"{version}.{syntax}"`, e.g.
`"01J8….ttl"`, `"01J8….jsonld"`, `"01J8….bin"` for a binary.

A conforming private cache already handles problem 9 once `Vary: Accept` is
sent: RFC 9111 §4.1 requires it to key stored responses on the varied header,
so it won't select its Turtle entry for a JSON-LD request and won't send that
tag back. The syntax token is defence in depth against clients that don't, and
against a tag a client stored before this stage. It is worth its cost —
`etag()` gains an argument, tags become parseable, and every cached validator
in the wild is invalidated once — because "reuse Turtle as JSON-LD" fails
silently and produces a parse error a long way from its cause.

**Reads compare the whole tag; writes compare the version.**

- `If-None-Match` on a `GET`/`HEAD` compares the full tag, so a client holding
  `"01J8….ttl"` that revalidates asking for JSON-LD gets a 200. Comparing only
  the version here would re-introduce exactly problem 9.
- `If-Match` and `If-None-Match` on a write compare the version part only. A
  `PUT` replaces the resource, not a representation, and a client that took its
  tag from a `HEAD` negotiated as Turtle must be able to guard a JSON-LD `PUT`
  with it. This is a deliberate deviation from RFC 9110 §13.1.1, which requires
  the strong comparison of §8.8.3.2 — octet-for-octet on the opaque tag. We
  take it because the alternative makes a correct client's conditional write
  fail for a reason it cannot see, and because the version *is* the resource
  state that `If-Match` exists to guard. 5a's R4 is preserved: one version per
  resource, one syntax token per representation.
- `If-Match: *` and `If-None-Match: *` are unaffected — `Condition::Any` carries
  no tag and asks only whether a current representation exists.

**A tag we didn't issue matches nothing.** The version is a ULID, so it never
contains a `.`, and `split_once('.')` is unambiguous. A tag with no `.`, or
with a suffix outside the set we issue, matches no representation and no
version: an `If-Match` carrying one fails closed with 412 and the client
re-`GET`s. That is what a 5a-era cached tag does after deploy, and it is the
right answer for a forged one.

This moves 5a's `conditional.rs` tests that spell tags by hand —
`an_etag_is_the_version_in_quotes` (:487) certainly, and
`if_match_compares_strongly` (:416),
`if_none_match_tags_refuse_the_current_version` (:448) and
`a_read_is_not_modified_when_if_none_match_matches` (:476) under the strict
rule. It moves **no** `pod_http` test: `get_and_head_carry_an_etag_and_last_modified`
(:1057) asserts only that the tag is quoted and non-empty, and nothing there
re-uses a tag across syntaxes.

A 304 carries `ETag` and `Vary`, which RFC 9110 §15.4.5 requires, plus
`Last-Modified`, `Link`, `Allow`, `Accept-*` and `WAC-Allow`. §15.4.5's
SHOULD NOT covers *representation* metadata — `Content-Encoding`,
`Content-Language`, `Content-Length`, `Content-Type`; `Allow`, `Accept-*` and
`WAC-Allow` are control and resource metadata, so those are not a deviation.
`Last-Modified` is: §15.4.5 excuses cache-guiding metadata only "if the
response does not have an ETag field", and ours does. We send it anyway,
because a client that revalidates must not lose the affordances it had.
`Content-Location`, `Cache-Control` and `Expires` are absent because a 200 from
this server doesn't send them either. Today a 304 carries `ETag` alone.

**A 304 carries no `Content-Length`.** Found while implementing: axum stamps
`Content-Length` on every top-level response whose body reports an exact size,
so an ordinary empty 304 went out as `content-length: 0` — since 5a. RFC 9110
§8.6 says a server MUST NOT send `Content-Length` on a 304 unless it equals
what the 200's body would have been, and a cache that honours it overwrites
the length it stored with zero. The 304's body reports no exact size and
reports itself finished, so axum adds nothing and hyper writes neither a
length nor a chunked encoding. That costs one direct dependency, `http-body`,
which axum and hyper already link.

### H11. A `PUT` that creates answers 201

`PUT` returns **201** with `Location` and H6's `Link` set when the target did
not exist, and **204** when it replaced something. 5a's write path knows which
happened (`ldp.rs:531` reads the target's metadata before writing) but returns
`()`; this threads a created/replaced answer out through `put_if`/`put_in`.

`ldp::put` has roughly 55 call sites — `adapters/solid/tests/acl_control.rs`
(23), `ldp_conformance.rs` (16), `ldp_nonrdf.rs` (13), `publication_boundary.rs`
(3), `server/src/mastodon_api.rs:552`, `server/tests/federation_flows.rs:508`.
Most keep compiling because the new payload is ignorable, but every
`matches!` and `let err = …` site needs a look. The plan should size for it.

`POST` keeps 201 + `Location`. `PATCH` and `DELETE` keep 204. No write response
carries an `ETag` — 5a's rule, unchanged: RFC 9110 §9.3.4 forbids the validator
when the stored representation isn't what was sent.

### H12. The storage root, its ACL, and the non-empty container

- `/~/` gains `put`, `patch` and `delete` routes (`server/src/lib.rs:319-324`).
  Without them axum's method-router answers 405 before any handler runs, so
  `ldp.rs:877`'s root guard is unreachable over HTTP and H4's
  authorization-first ordering cannot hold. The handlers run WAC, then refuse.
  These are **new handlers**, not new entries: `pod::get`/`put`/`patch`/`delete`
  all take `Path(String)`, and the `/~/{*path}` wildcard doesn't match an empty
  remainder — which is why `get_root` and `post_root` exist. So `put_root`,
  `patch_root`, `delete_root` and (for H4's stateful `OPTIONS`) `options_root`
  join them, each delegating to the same inner function with an empty path.
- **`DELETE` of the storage root or of `/~/.acl` → 405** with H4's `Allow`, for
  a caller who would otherwise have been allowed. The root ACL needs a new
  guard in `delete_in`; today a caller with `Control` can delete it.
- **`DELETE` of a non-empty container → 409 with a body naming the problem.**
  `StoreError::ContainerNotEmpty` maps to a new `LdpError::NotEmpty`, replacing
  the 403 stage 5a left in place. §5.4 requires the body, not just the status.

### H13. Container listings carry member metadata, and clients can't change it

A container's body gains, for each member, the metadata 5a already records
(Solid Protocol §4.2.1, Contained Resource Metadata):

```turtle
</~/notes/> ldp:contains </~/notes/first> .
</~/notes/first> dcterms:modified "2026-09-23T10:00:00.007Z"^^xsd:dateTime ;
    <http://www.w3.org/ns/posix/stat#mtime> 1790000000 ;
    <http://www.w3.org/ns/posix/stat#size> 214 .
```

§4.2.1 makes the metadata a SHOULD and the protection below a MUST.

`dcterms:modified` and `stat:mtime` are the same instant in the two forms
§4.2.1 names. Both come from the **same normalising path `meta()` uses**
(`store/src/resources.rs:591`, `normalise_modified`), not from the raw quads
`container_triples` reads: commit `9d58082` exists because Oxigraph shortens
`.750Z` to `.75Z` and `.000Z` to `Z` on the way in, so a listing built from raw
quads would disagree with the member's own `Last-Modified` about one write in
ten. `stat:mtime` is derived through `parse_modified` — nothing stores an
integer mtime — and `stat:size` comes from the stored `brolly:byteSize`.

The `stat:` prefix expands to `http://www.w3.org/ns/posix/stat#` — the Solid
Protocol's prefix table omits the `#`, but the vocabulary's terms carry it, and
`statsize` is not a term. Neither term declares a range, so both are
`xsd:integer` by our choice.

`stat:size` is emitted for binaries only: §4.2.1 excuses metadata that is
"inapplicable", and an RDF source's serialized length depends on the syntax the
client asked for, so a number that changes with `Accept` is worse than no
number. §4.2.1's fourth statement, the `rdf:type` naming an IANA media-type
class, is omitted for the same reason — a negotiated resource has no single
one.

**These triples are server-owned, exactly like `ldp:contains`.**
`container_body` (`ldp.rs:596-633`) keeps every quad whose subject isn't the
container, so without a rule a client could `GET` a listing, `PUT` it back, and
have the member metadata stored as content — stale forever, and served beside
the generated version. §4.2.1: "servers MUST NOT allow HTTP POST, PUT and PATCH
to update a container's resource metadata statements; if the server receives
such a request, it MUST respond with a 409 status code."

**An exact echo is not an update.** The rule is per statement, and it compares
*values*, not lexical forms — `1790000000` and `"1790000000"^^xsd:integer` are
the same number, and a client that round-trips a timestamp through JSON-LD may
spell it a third way:

- A statement whose subject is a contained resource and whose predicate is
  `dcterms:modified`, `stat:mtime` or `stat:size` — the three we serve — is
  parsed as a value: milliseconds since the epoch for the first two, an integer
  for the third. It is **dropped** when that value equals the one the server
  would serve, and **409** when it differs or won't parse.
- **`rdf:type` is not on the list,** because we don't serve it. `<…/first> a
  schema:Note` in a container's description is ordinary content, and so is any
  other predicate on a member — `<…/first> rdfs:label "First"` is kept.

Without the echo tolerance a plain read-modify-write of a container would 409,
which is what Inrupt's `solid-client`, LDO and SolidOS all do, and what 5a's
"echoing its listing exactly, succeeds" test asserts.

This is *not* containment's set-wise rule (`ldp.rs:629`: send none and
membership is left alone, send a non-empty set and it must match exactly). It
is per statement, and it has no equivalent of containment's empty-set escape
hatch. It also has a race containment doesn't: a member's `dcterms:modified`
moves on every write to that member, not only on create and delete, so a client
that reads a listing, edits a member, and then writes the container's
description back is refused for metadata it never touched. The 409's body — the
one §5.4 requires anyway — says to re-read and retry.

This is also what makes 5a's R9 observable: `set_description` → `contain` →
`touch(parent)` (`resources.rs:734`, `:878-888`) already moves a container's
version when a member changes, and a client can now see what changed without a
request per member.

### H14. CORS

- Echo the request's `Origin` when one is present, with `Vary: Origin` appended
  (H10). Keep `*` when there is none. Credentials stay disallowed, as
  `server/src/lib.rs:148` explains — with credentials off, echoing and `*`
  grant a browser identical permission, but a named origin is cacheable
  per-origin and CTS checks for it.
- **Preflights echo `Access-Control-Request-Headers`.** Today
  `Access-Control-Allow-Headers` is a fixed list (`lib.rs:174`) that can never
  admit a header it doesn't already name. CTS asserts the response does *not*
  carry `Accept` when the preflight didn't ask for it
  (`protocol/cors/accept-acah.feature`), and Solid §8.1 wants apps able to send
  any combination of headers.
- `Access-Control-Expose-Headers` gains `accept-put`, `www-authenticate` and
  `vary` (not CORS-safelisted, and H10 now sends it), and drops `updates-via`,
  which nothing sends until stage 7.

### H15. An authenticated `HEAD` is authenticated

`subject_for` receives the request's actual method and its **undecoded** URI,
so a DPoP proof binding `htm: HEAD` verifies and an `htu` containing a
percent-escape matches. Today `pod.rs:301` passes the literal `"GET"` and
builds the URL from the decoded `Path`, so a correct client's HEAD silently
loses its identity and gets the anonymous answer. CTS signs `HEAD` proofs
(`read-method-allow.feature`), so nothing in part d passes without this.

The handlers need two more extractors — `axum::http::Method` and
`OriginalUri` — declared **before** `Path`, which must stay last. The
undecoded path is load-bearing: `htu_matches` (`identity/src/dpop.rs:397`) is
exact string equality after stripping query and fragment.

`server/src/activitypub.rs:289` is `subject_for`'s other caller. It keeps its
own rule — the inbox answers 404 to a non-owner, because 403 would confirm the
inbox exists (`activitypub.rs:276`, guarded by `server/tests/pod_http.rs:719`)
— but it picks up H2: a credential that doesn't verify is a 401 there too.

### H16. Our 405s carry `Allow`

RFC 9110 §15.5.6 makes it a MUST. Axum's generated 405 already carries one
(it tracks the methods registered on the route), so the gap is our own:
`pod::subdomain_fallback`'s `UserStorage` arm (`pod.rs:557`, reachable for the
bare path `/~`), H8's read-only storage description, and H12's undeletable
root and root ACL.

### H17. A body without `Content-Type` is a 400

Solid §2.1: "Server MUST reject `PUT`, `POST`, and `PATCH` requests that
contain content but lack the `Content-Type` header field, with a status code of
`400`." `pod::put` and `pod::post` default to `text/turtle` (`pod.rs:366`,
`:399`); that default is removed. `pod::patch` needs the same treatment from
the other side: it defaults to `""`, falls into the `other =>` arm
(`pod.rs:445`) and answers **415** where §2.1 wants 400.

**An empty body with no `Content-Type` is treated as an empty RDF document,**
not refused: §2.1's MUST is about requests that "contain content", and creating
an empty resource this way is what 5a made possible. `ldp::prepare` needs a
content type to reach `Content::Rdf(&[])`, so the default survives for exactly
this case and no other.

## What this changes in the code

| File | Change |
|---|---|
| `adapters/solid/src/ldp.rs` | `LdpError::{Denied, NotEmpty}`, `Forbidden` renamed `Undeletable` (H1, H12); **`describe()`**, a body-free per-resource read returning kind, existence, version, modified, `granted` and `public` (H4, H6, H9, H10); anonymous probe inside `read_in` (H9); `acl_iri` (H7); root-ACL delete guard (H12); `put_if`/`put_in` report created vs replaced (H11); `container_body` drops or refuses member metadata (H13); `served_types` deleted (H5) |
| `server/src/pod.rs` | `subject_for` returns the subject *and* whether a credential verified, takes the real method and undecoded URI (H2, H15); `ldp_error` maps `Denied` → 401/403 and `NotEmpty` → 409 (H1, H12); one `headers_for` over `describe`'s output, shared by GET, HEAD, OPTIONS, 304 and the create responses (H4–H10); stateful `options` (H4); `Content-Type` required (H17); `Allow` on the fallback's 405 (H16) |
| `server/src/lib.rs` | `/~/` gains `put`/`patch`/`delete` (H12); route for `/.well-known/solid` (H8); CORS echo, preflight header echo, expose list (H14) |
| `adapters/solid/src/storage_description.rs` | new: generates H8's document |
| `store/src/resources.rs` | container listings carry member metadata (H13) |
| `domain/src/vocab.rs` | `STAT_SIZE`, `STAT_MTIME`, the LDP type IRIs, `SOLID_OWNER`, `SOLID_STORAGE_DESCRIPTION` (H6, H13) |
| `identity/src/subject.rs` | `Subject::anonymous()` (H9) |
| `server/src/activitypub.rs` | follows `subject_for`'s new signature, keeps its 404 rule (H15) |

**Tests whose expectations change** (rewrite, don't delete):
`server/tests/pod_http.rs` — `an_anonymous_reader_gets_nothing` (:273, 404 →
401), `a_binary_is_invisible_to_a_caller_without_read` (:530, 404 → 401),
`options_advertises_the_patch_formats` (:454, `OPTIONS` is now authenticated
and per-resource), `wac_allow_on_an_acl_names_nothing_for_bob` (:1030, Bob's
404 → 403, and the exact `WAC-Allow` string gains `public=`),
`the_headers_ldp_depends_on_are_exposed` (:847, expose list changes),
`get_and_head_carry_an_etag_and_last_modified` (:1057, the ETag gains a syntax
token). `bob_cannot_delete_an_acl_he_does_not_control` (:1012) does **not**
change: that ACL is `/~/shared/.acl`, not the root's, and Bob is authenticated
without `Control`, so 403 stands.

In `adapters/solid/tests`, H1 inverts an invariant several tests assert
directly: `ldp_conformance.rs:220-221` (both absent *and* refused are
`NotFound` today), `:238`, `:364` (non-empty container → `NotEmpty`),
`ldp_nonrdf.rs:241` and `:255` (`Target::prepare`'s refusal). All fail loudly
through `matches!`; none change silently. Also `server/src/pod.rs:584`'s unit
test, `conditional.rs`'s hand-spelled tags (H10), and the `ldp::put` call sites
in H11. `authz/tests/conformance_matrix.rs` is **not** affected — `brolly-authz`
has no `brolly-solid` dependency and drives `effective_acl`/`authorize` through
its own stubs.

## Chunks

Five, one commit each. (An earlier draft paired chunks 2 and 3; planning showed
chunk 2 stands alone, and separate commits are easier to bisect and revert.)
The plan is `docs/plans/2026-09-23-solid-http-surface.md`.

1. **Credentials and refusals.** `subject_for`'s signature, the real method and
   URI, `LdpError::Denied`, the 401/403/404 table, `WWW-Authenticate` with both
   error codes, `activitypub.rs` keeping its 404. *It changes the meaning of
   every existing refusal and rewrites the most tests; everything else is
   additive on top of it.*
2. **`describe` and the shared header builder.** The body-free description, the
   anonymous probe inside the snapshot, `Subject::anonymous`, stateful
   `OPTIONS`, `Allow`, `Accept-*`, `served_types` deleted. *The missing
   abstraction; nothing after this can be built without it, and it is what
   makes "one `headers_for`" true rather than five.*
3. **Discovery.** `acl_iri`, the `Link` set, `storage_description.rs` and its
   route, `Allow` on our 405s, `/~/` gaining the write methods so H12's rules
   are reachable. *All new surface, no behaviour change to existing paths.*
4. **Caching and CORS.** `public=`, `Vary` appended, the syntax-tagged ETag and
   the fuller 304, origin echo, preflight header echo, expose list. *The only
   chunk whose correctness is judged by a cache rather than a client; isolate
   it so a mistake here doesn't hide inside the header work.*
5. **Write responses and bodies.** 201 on create through `put_if`/`put_in` and
   its call sites, `NotEmpty` → 409 with a body, the root-ACL guard, member
   metadata in listings with the echo-tolerant §4.2.1 refusal, `Content-Type`
   required. *The only chunk that changes what is stored and what writes say;
   it carries the round-trip risk and deserves its own revert boundary.*

## Decisions

| # | Decision | Why |
|---|---|---|
| H1 | Status depends on effective modes and on whether a credential verified, never on existence: unauthenticated+denied → 401, authenticated+denied → 403, permitted+missing → 404. `ldp` reports `Denied` vs `NotFound`; `pod.rs` picks 401 or 403 | Tells a client what to do without becoming an existence oracle; matches CTS row for row; keeps the credential question out of `ldp`'s signatures |
| H2 | An `Authorization` header that doesn't verify is a 401, not anonymity; `invalid_token` for the token, `invalid_dpop_proof` for the proof; a stale cookie still falls through to anonymous | An expired token must look like an expired token; `invalid_token` on a proof failure sends a client into a refresh loop; a `SameSite=Lax` cookie the browser sent unasked is not a presented credential |
| H3 | `WWW-Authenticate: DPoP algs="ES256", as_uri="https://{apex}"`, plus `error=`; a bearer credential gets a `Bearer` challenge | Solid-OIDC §9.1 makes `as_uri` a MUST; a Mastodon client can't act on a DPoP challenge |
| H4 | `Allow` computed from the caller's modes and the target's kind; `POST` on documents too; no `PATCH` for Append-only until 5c; `OPTIONS` gated on *any* mode and answering 204 for an absent target; only the root and the root's ACL are undeletable; authorization decided before method availability | A static `Allow` promises writes that will be refused; an Append-only client must be able to discover `POST`; WAC §3.2 makes deleting an ACL the way to revert to inheritance |
| H5 | `Accept-Patch`/`Accept-Post`/`Accept-Put` sent only when the method is allowed — a deliberate narrowing of §5.2's MUST — sourced from `accepted_write_types()`; `*/*` wherever any type is accepted today; `served_types()` deleted | These headers mean "allowed"; `served_types()` includes RDF/XML, which ADR 0007 always refuses |
| H6 | `Link rel="type"` with the LDP kinds, plus `pim:Storage` and `solid:owner` on the root, `acl`, and `storageDescription`; successful reads and creates only | §4.1 MUSTs the storage links; a 4xx must not imply a resource kind |
| H7 | An ACL's ACL is itself; `acl_iri` lives beside `governed()` in `brolly-solid`, and is not its inverse | Stage 0's A2 governs `.acl` by its own `Control`; `x.acl.acl` is a fiction |
| H8 | Generated, world-readable storage description at `/.well-known/solid`, routed in `app()` and subdomain-scoped by the handler, not listed in `USER_PROTOCOL_RESOURCES` | Solid Protocol §4.1; discovery precedes credentials; a routed path never reaches the fallback that list feeds |
| H9 | `WAC-Allow` gains `public=` from an anonymous probe **inside** the snapshot, carried out on the outcome; sent on GET, HEAD and OPTIONS | A share UI has to show whether a resource is public; `Pod::read` closes the snapshot before any header builder runs |
| H10 | ETag becomes `"{version}.{syntax}"` with preconditions comparing the version only; `Vary` appended, `Accept` on negotiated reads and `Origin` always; a 304 carries every header a 200 would | One validator for every syntax lets a private cache reuse Turtle as JSON-LD; §15.4.5's SHOULD NOT covers representation metadata, which `Allow`/`Accept-*`/`WAC-Allow` are not |
| H11 | `PUT` that creates → 201 + `Location` + `Link`; replace → 204 | LDP, and what clients branch on |
| H12 | `/~/` routes the write methods; root and root ACL `DELETE` → 405 after authorization; non-empty container `DELETE` → 409 **with a body** | §5.4 names both protections and requires the 409's explanation; without the routes neither is reachable and the root ACL is deletable today |
| H13 | Listings carry members' `dcterms:modified`, `stat:mtime` and (binaries only) `stat:size`; a write that *changes* one of those four predicates on a contained resource is a 409, an exact echo is dropped, anything else is kept | §4.2.1 for both the metadata and the refusal; a blanket refusal would break the read-modify-write every Solid client does |
| H14 | CORS echoes `Origin` and the preflight's requested headers; expose list gains `accept-put`, `www-authenticate`, `vary` | Solid §8.1 wants any header combination to be sendable; CTS asserts the echo both ways |
| H15 | `HEAD` authenticates as `HEAD`, with the undecoded URI; the ActivityPub inbox keeps its 404 rule | A correct DPoP proof must not silently downgrade the caller |
| H16 | Our own 405s carry `Allow` | RFC 9110 §15.5.6; axum's generated 405 already does, ours don't |
| H17 | A body with no `Content-Type` is a 400, not Turtle | Solid §2.1; guessing turns a client bug into stored garbage |
