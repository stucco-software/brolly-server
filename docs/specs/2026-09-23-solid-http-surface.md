# Stage 5b: the pod's HTTP surface

<!-- doc-paths: skip -->
<!-- The spec names files this stage creates, so not every path it cites
     resolves until it's implemented. -->

**Status:** Draft (2026-09-23), revised after one adversarial review against the
Solid Protocol, WAC, Solid-OIDC, LDP, RFC 9110 and the Solid
specification-tests (CTS) feature files
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
   (`adapters/solid/src/ldp.rs:1014`).
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
8. **`Vary` is never sent** although `GET` content-negotiates on `Accept`, so
   any cache between the pod and the client may serve Turtle to a client that
   asked for JSON-LD. CTS requires `Vary: Origin` as well
   (`protocol/cors/acao-vary.feature`).
9. **A `PUT` that creates answers 204.** LDP and every Solid client expect 201.
10. **Deleting a non-empty container is 403,** which says "you may not", when
    the truth is "not while it has members" — §5.4 requires 409 with a body
    describing the error. Stage 5a left this mapping in place
    (`adapters/solid/src/ldp.rs:106-116`) pending this part.
11. **An authenticated `HEAD` is anonymous.** `subject_for` is handed the
    literal string `"GET"` (`pod.rs:301`), so a DPoP proof whose `htm` claim is
    `HEAD` — which is what every correct client sends, and what CTS signs —
    fails verification and is downgraded. HEAD then 404s on the member's own
    resource.
12. **A container listing says nothing about its members.** 5a records each
    resource's modified time and size; a listing still carries only
    `ldp:contains`, so a file manager has to `HEAD` every member to draw a list.
13. **405s carry no `Allow`,** which RFC 9110 §15.5.6 makes a MUST. This is
    what a client gets for `PUT /~/` or `DELETE /~/`
    (`server/src/pod.rs:557-560`, and axum's own method-router 405).
14. **A body with no `Content-Type` is guessed at.** `pod::put` and `pod::post`
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
- **Responses are cache-correct:** conditional and negotiated responses carry
  the validators and the `Vary` that RFC 9110 requires.
- **Nothing in 5a's write path changes.** This part reads state and formats
  responses. Below the HTTP layer it changes only which `LdpError` a refusal
  carries, whether a `PUT` reports creating, and what a container's body says
  about its members.

## Non-goals

Part 5c covers `Slug`, creating containers by `POST`, the `/foo` vs `/foo/`
distinction, PATCH access modes (so `Allow` does **not** promise `PATCH` to an
Append-only caller here — see H4), and 422. Part 5d covers `.meta`,
`Link rel="describedby"` (which points at `.meta` and would be a dead link
before it exists), deleting a resource's auxiliaries with it, and CTS in CI.

Also not in scope:

- **Changing how access is decided.** WAC evaluation is untouched; this part
  asks it one more question (the anonymous probe for `public=`) and reports the
  answers differently.
- **Accepting tokens from other issuers.** Stage 6.
- **Media.** Stage 4. A binary is still owner-only by default.
- **Refusing to change a resource's type by `PUT`.** Today a `PUT` of
  `application/pdf` over an RDF document is accepted (`ldp.rs:431` restricts
  the RDF-only rule to containers and ACLs). H5 tells the truth about that
  rather than changing it; whether it *should* change belongs with 5c's write
  semantics.

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

"Authenticated" means **a credential was presented and verified**, not
`Subject::agent()`. A service-auth subject has no WebID and reports
`Agent::Anonymous` (`identity/src/subject.rs:100-108`); challenging it with a
401 it has already satisfied would be a retry loop. The branch is on whether
`subject_for` verified something.

This replaces stage 0's A2 refusal rule — *"a caller without the required mode
gets `NotFound`, so existence isn't disclosed"*
(`docs/specs/2026-09-17-security-fixes.md:242`). The disclosure that rule
avoided is preserved: an unauthenticated caller gets 401 for `/~/secret` and
401 for `/~/does-not-exist` and cannot tell them apart; an authenticated caller
gets 403 for both. Only a caller who may read learns the difference, and
learning it is the point. CTS agrees on every row
(`web-access-control/protected-operation/read-access-public.feature`: public →
401, Bob → 403, and a *permitted* caller reading a fictive resource → 404).

**One accepted disclosure.** Stage 0 also made `delete` remove the resource's
`.acl`. So for a resource shared with Bob by a *direct* ACL: while it exists
Bob has Read and sees 200 or 404; once Alice deletes it, the direct ACL is gone
and Bob's modes revert to the ancestor's, so he sees 403. Bob learns the
resource once existed. Under stage 0 both were 404. We accept this: the
alternative is keeping a deleted resource's ACL, which leaves a rule granting
access to an IRI the member believes they erased.

Paths outside the storage root keep today's 404 and its
`Link rel="canonical"` (`pod::subdomain_fallback`). That is a routing answer,
not an access decision.

### H2. Credentials that don't verify are a 401, not anonymity

**Scoped to the `Authorization` header.** A `brolly_session` cookie is not a
presented credential: it is `SameSite=Lax`, so a browser sends it on any
top-level navigation, and a logged-out member opening a public image in their
own pod would be met with a challenge for a credential they never offered. A
cookie that doesn't resolve still falls through to anonymous, and H1 decides.

For an `Authorization` header, each of these becomes an immediate refusal,
before any WAC evaluation, and the request is *not* retried as anonymous:

- a malformed header, an unknown, expired or revoked token
- a failed DPoP proof, a replayed `jti`, an `htu`/`htm` mismatch

Why not keep downgrading: a client whose token expired is currently told its
resources are gone, with no signal to refresh. RFC 6750 §3 and Solid-OIDC both
make `invalid_token` the answer.

`error_description` is omitted. It would be the only place in the surface where
a refusal explains itself to an unauthenticated caller, and the values are
either obvious ("expired") or something an attacker would like to know
("replayed").

### H3. `WWW-Authenticate`

On a 401 from an absent credential, or from a DPoP-bearing one:

```
WWW-Authenticate: DPoP algs="ES256", as_uri="https://{apex}"
```

with `, error="invalid_token"` appended for H2. Solid-OIDC §9.1 makes `as_uri`
a MUST unless the scheme has its own discovery mechanism, and RFC 9449 §7.1's
`DPoP` parameters (`realm`, `scope`, `error`, `error_description`, `algs`)
include none. `{apex}` is the instance's apex domain, which is where this
server's Solid-OIDC metadata lives (`solid_oidc::apex_only`,
`server/src/lib.rs:206-221`).

`ES256` is what we verify — `identity/src/dpop.rs:336` and
`adapters/solid/src/oidc/tokens.rs:191` are ES256-only — and advertising more
would be a lie. `realm` is omitted; Solid-OIDC doesn't use it.

**A bearer credential gets a `Bearer` challenge instead.** Mastodon's API
tokens reach pod URLs through `Credential::Bearer` (`pod.rs:175-193`), and a
Mastodon client can do nothing with a `DPoP` challenge. When the refused
credential was a bare bearer token, the challenge is
`Bearer error="invalid_token"`. An absent credential gets `DPoP` only: the pod
is proof-of-possession by default, and offering `Bearer` unprompted invites a
client to send a bare token that will be refused.

### H4. `Allow`, per resource and per caller

`OPTIONS` becomes a real handler: it resolves the pod, authenticates, and
evaluates WAC for the target, exactly as `GET` does. So do `GET` and `HEAD`,
which carry the same `Allow` (CTS reads it from a `GET`; SolidOS reads it from
whichever it last made). `OPTIONS` keeps today's **204**, which CTS accepts
alongside 200.

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

Only the **root** container and the **root's** ACL are undeletable (Solid
Protocol §5.4 names precisely those two). Any other `.acl` may be deleted by a
caller with `Control`: WAC §3.2 makes *removing* the ACL representation the
specified way to revert a resource to inheriting its container's rules, so
refusing the delete would leave no way to un-share short of writing an empty
ACL.

A caller with no modes at all never sees this header: H1 has already answered
401 or 403, with *M* = `Read`. An `OPTIONS` that enumerated a resource's
capabilities to a caller with no access would be the existence oracle H1
closes. A CORS preflight is not an `OPTIONS` request in this sense — the
middleware answers it before routing (`server/src/lib.rs:161`) and it carries
no credentials by definition.

**Authorization comes before method availability.** `DELETE` of the root ACL by
a caller without `Control` is H1's 403, not H12's 405. A 405 would tell a
caller with no access that the target exists and is special.

### H5. `Accept-Patch`, `Accept-Post`, `Accept-Put`

Each is sent only when the corresponding method is in `Allow`, on `OPTIONS`,
`GET` and `HEAD`:

- `Accept-Patch: text/n3, application/sparql-update` — what `patch` parses.
- `Accept-Post:` and `Accept-Put:` come from **`accepted_write_types()`**
  (`ldp.rs:1009`), the list the parser accepts. Not `served_types()`, which
  includes RDF/XML — a format `refuse_rdf_xml` (`ldp.rs:671`) rejects on every
  write, per ADR 0007. LDP §7.1.2 and Solid §5.2 define these headers as what
  is *allowed*, so advertising RDF/XML would be advertising a guaranteed 415.
- For a target that is a **binary, or doesn't exist yet**, `Accept-Put` is
  `*/*`: both accept any media type today (`ldp.rs:431`, `Target::prepare` at
  `ldp.rs:390`). For a **container or an `.acl`**, it is the RDF list, which is
  5a's `NotRdf` refusal made discoverable.

`served_types()` is deleted rather than promoted: it is the *serialization*
list, it duplicates `syntax::negotiate`'s knowledge, and nothing reads it.

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

The storage root's `pim:Storage` and `solid:owner` links are Solid Protocol
§4.1 MUSTs ("servers MUST advertise the storage resource… when responding to
storage's request URI"; and the owner link "targeting the root container").
They are what turns problem 4 from a body a client must already be reading
into something discoverable from any response.

LDP §4.2.1.4 asks for `rel="type"` on *all* responses to an LDPR's URI,
including errors. We narrow it to the successful reads and creates
deliberately: a 401 or 403 must not imply what kind of resource is behind it,
and a 404 must not imply one is.

### H7. The ACL of an ACL is itself

`acl_iri(target)` lives in `brolly-solid` beside its inverse, `governed()`
(`adapters/solid/src/ldp.rs:162`), and `storage::is_container` — not in
`identity`, which can't depend on the adapter and would drift from them.

- `target` ends in `.acl` → `target`
- a container `/~/notes/` → `/~/notes/.acl`
- anything else `/~/note` → `/~/note.acl`

which is what `authz::acl_candidates` (`authz/src/wac.rs:84-103`) already
computes. An ACL resource is governed by its own `Control` mode (stage 0's A2),
so pointing it at itself is the truth. Today's concatenation produces
`x.acl.acl`, an IRI with no ACL semantics that a client following the link
would create as an ordinary resource.

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

Two routing facts it has to respect. Adding the path to
`USER_PROTOCOL_RESOURCES` (`identity/src/routing.rs:20`) alone turns today's
404 into a **501** — that list only feeds `pod::subdomain_fallback`. The
serving route goes in `app()`, and **axum routes are not host-scoped**, so the
handler must resolve the subdomain itself the way `profile` and `actor` do; on
the apex it is a 404.

### H9. `WAC-Allow` gains `public=`

```
WAC-Allow: user="read write append control", public="read"
```

`user=` is the caller's effective modes, as today. `public=` is a second
`granted_modes` probe with the anonymous subject against the **same snapshot**,
so the two components can never disagree about the ACL they describe. WAC
§6.1's ABNF allows an empty group, so a caller with nothing gets `user=""`.

On an `.acl`, `granted_modes` is all-or-nothing on `Control`
(`ldp.rs:217-222`), so `public=` there is `""` unless the ACL grants Control to
everyone.

Sent on `GET`, `HEAD` (WAC §6's MUST) and on `OPTIONS`, which now does the same
evaluation. Not on writes, where the modes a client would read are the ones it
just exercised.

The cost is a second WAC evaluation per read, against the snapshot already open
and the ACL already resolved: four `authorize` calls over an in-memory graph.

### H10. `Vary`, and what a 304 carries

`Vary` is **appended to, never replaced** — H14's CORS layer is outermost and
currently `insert`s (`lib.rs:192`), which would drop whatever the handler set.

- `Accept` on a `GET`/`HEAD` of an RDF source, whose body is negotiated. Not on
  a binary, whose bytes are the same for every `Accept`.
- `Origin` on every response, binaries included — CTS checks exactly that
  (`protocol/cors/acao-vary.feature` uses a `.txt`).

A 304 carries `ETag` and `Vary`, which RFC 9110 §15.4.5 requires, and also
`Last-Modified`, `Link`, `Allow`, `Accept-*` and `WAC-Allow`, which §15.4.5
says a sender SHOULD NOT generate. We exceed it knowingly: a client that
revalidates a cached resource would otherwise lose every affordance it had, and
re-fetch to get them back. `Content-Location`, `Cache-Control` and `Expires`
are absent because a 200 from this server doesn't send them either. Today a 304
carries `ETag` alone.

### H11. A `PUT` that creates answers 201

`PUT` returns **201** with `Location` and H6's `Link` set when the target did
not exist, and **204** when it replaced something. 5a's write path knows which
happened (`ldp.rs:531` reads the target's metadata before writing) but returns
`()`; this threads a created/replaced answer out through `put_if`/`put_in` and
their callers — `server/src/mastodon_api.rs:552`,
`server/tests/federation_flows.rs:508`, and the `adapters/solid/tests/acl_control.rs`
call sites.

`POST` keeps 201 + `Location`. `PATCH` and `DELETE` keep 204. No write response
carries an `ETag` — 5a's rule, unchanged: RFC 9110 §9.3.4 forbids the validator
when the stored representation isn't what was sent.

### H12. Deleting a non-empty container is 409

`StoreError::ContainerNotEmpty` maps to a new `LdpError::NotEmpty` → **409**,
replacing the 403 stage 5a left in place, **with a body naming the problem** —
§5.4 requires the body, not just the status. Deleting the storage root or the
root's `.acl` is **405** with H4's `Allow`, and only for a caller who would
otherwise have been allowed (H4's ordering rule).

### H13. Container listings carry member metadata, and clients can't write it

A container's body gains, for each member, the metadata 5a already records
(Solid Protocol §4.2.1, contained resource metadata):

```turtle
</~/notes/> ldp:contains </~/notes/first> .
</~/notes/first> dcterms:modified "2026-09-23T10:00:00Z"^^xsd:dateTime ;
    stat:mtime 1790000000 ;
    stat:size 214 .
```

`dcterms:modified` and `stat:mtime` are the same instant in the two forms §4.2.1
names. `stat:size` is emitted for binaries only: §4.2.1 excuses metadata that is
"inapplicable", and an RDF source's serialized length depends on the syntax the
client asked for, so a number that changes with `Accept` is worse than no
number. The `rdf:type` of an IANA media type is omitted for the same reason.

**These triples are server-owned, exactly like `ldp:contains`.** `container_body`
(`adapters/solid/src/ldp.rs:596-633`) keeps only quads whose subject *is* the
container, so without a change a client could `GET` a listing, `PUT` it back,
and have the member metadata stored as its content — stale forever, and served
next to the generated version. That defeats 5a's R8. Solid §5.3 settles it:
"servers MUST NOT allow HTTP POST, PUT and PATCH to update a container's
resource metadata statements; if the server receives such a request, it MUST
respond with a 409 status code." A write whose body carries a statement about a
contained resource is a **409**, the same `ContainmentChange` shape 5a already
has for `ldp:contains`.

This is what makes 5a's R9 observable: a container's version moves when a member
changes, and a client can now see what changed without a request per member.

### H14. CORS

- Echo the request's `Origin` when one is present, with `Vary: Origin` appended
  (H10). Keep `*` when there is none. Credentials stay disallowed, as
  `server/src/lib.rs:148` explains — with credentials off, echoing and `*` grant
  a browser identical permission, but a named origin is cacheable per-origin and
  CTS checks for it.
- **Preflights echo `Access-Control-Request-Headers`.** Today
  `Access-Control-Allow-Headers` is a fixed list (`lib.rs:174`) that can never
  admit a header it doesn't already name. CTS asserts the response does *not*
  carry `Accept` when the preflight didn't ask for it
  (`protocol/cors/accept-acah.feature`), and Solid §6 wants apps able to send
  any combination of headers.
- `Access-Control-Expose-Headers` gains `accept-put`, `www-authenticate` and
  `vary` (not CORS-safelisted, and H10 now sends it), and drops `updates-via`,
  which nothing sends until stage 7.

### H15. An authenticated `HEAD` is authenticated

`subject_for` receives the request's actual method and actual URL, so a DPoP
proof binding `htm: HEAD` verifies. A bug fix with a security shape: today a
correct client's HEAD silently loses its identity and gets the anonymous
answer. CTS signs `HEAD` proofs (`read-method-allow.feature`), so nothing in
part d passes without this.

`server/src/activitypub.rs:289` is `subject_for`'s other caller. It keeps its
own rule — the inbox answers 404 to a non-owner, because 403 would confirm the
inbox exists (`activitypub.rs:276`, guarded by `server/tests/pod_http.rs:719`)
— but it picks up H2: a credential that doesn't verify is a 401 there too.

### H16. Every 405 carries `Allow`

RFC 9110 §15.5.6 makes it a MUST, and nothing in the server does it today.
Three 405s exist: `pod::subdomain_fallback`'s `UserStorage` arm
(`pod.rs:557`), H8's storage description, and H12's undeletable root. Axum's
own method-router 405 is unreachable here because `Router::fallback` takes
precedence (`lib.rs:327`), so the fallback is the one place that has to compute
it: `GET, HEAD, POST, OPTIONS` for the storage root, `GET, HEAD, OPTIONS` for a
read-only protocol resource.

### H17. A body without `Content-Type` is a 400

Solid §2.1: "Server MUST reject `PUT`, `POST`, and `PATCH` requests that
contain content but lack the `Content-Type` header field, with a status code of
`400`." `pod::put` and `pod::post` default to `text/turtle` (`pod.rs:366`,
`:399`); that default is removed. An empty body with no `Content-Type` is still
fine — that is how a client creates an empty resource, which 5a made possible.

## What this changes in the code

| File | Change |
|---|---|
| `server/src/pod.rs` | `ldp_error` gains 401/403/409; `subject_for` returns `Result<Subject, Response>` (H2, H3), takes the real method and URL (H15); `options` becomes a stateful handler (H4); one `headers_for` builder shared by GET, HEAD, OPTIONS, 304 and the create responses (H4–H10); `Content-Type` required (H17); `Allow` on the fallback's 405 (H16) |
| `adapters/solid/src/ldp.rs` | `LdpError::{Unauthenticated, NotEmpty}`, returned by `read`/`write` in place of `NotFound`/`Forbidden` per H1; `granted_modes` gains the anonymous probe (H9); `put_if`/`put_in` report created vs replaced (H11); `container_body` refuses member metadata (H13); `acl_iri` (H7); `served_types` deleted (H5) |
| `server/src/lib.rs` | CORS echo, preflight header echo, expose list (H14); route for `/.well-known/solid` (H8) |
| `identity/src/routing.rs` | `/.well-known/solid` in `USER_PROTOCOL_RESOURCES` (H8) |
| `adapters/solid/src/storage_description.rs` | new: generates H8's document |
| `store/src/resources.rs` | container listings carry member metadata (H13) |
| `server/src/activitypub.rs` | follows `subject_for`'s new signature, keeps its 404 rule (H15) |

**Tests whose expectations flip** (the plan has to rewrite them, not delete
them): `server/tests/pod_http.rs:273` and `:530` (404 → 401), `:1012` (403 →
405 for the root ACL only), `:1030` (404 → 403), `:1049` (exact `WAC-Allow`
string, now two components), `:454` (`OPTIONS` is authenticated and per
resource), `:847` (`updates-via` dropped, three names added);
`server/src/pod.rs:584`'s unit test; and `adapters/solid/tests/acl_control.rs`
for the `put` arity and `granted_modes`.

## Decisions

| # | Decision | Why |
|---|---|---|
| H1 | Status depends on effective modes and on whether a credential verified, never on existence: unauthenticated+denied → 401, authenticated+denied → 403, permitted+missing → 404 | Tells a client what to do without becoming an existence oracle; matches CTS row for row |
| H2 | An `Authorization` header that doesn't verify is a 401, not anonymity; a stale cookie still falls through to anonymous | An expired token must look like an expired token, not like deletion — but a `SameSite=Lax` cookie the browser sent unasked is not a presented credential |
| H3 | `WWW-Authenticate: DPoP algs="ES256", as_uri="https://{apex}"`, `error="invalid_token"` when something was presented; a bearer credential gets a `Bearer` challenge | Solid-OIDC §9.1 makes `as_uri` a MUST; a Mastodon client can't act on a DPoP challenge |
| H4 | `Allow` computed from the caller's modes and the target's kind; `POST` on documents too; no `PATCH` for Append-only until 5c; only the root and the root's `.acl` are undeletable; authorization decided before method availability | A static `Allow` promises writes that will be refused; WAC §3.2 makes deleting an ACL the way to revert to inheritance |
| H5 | `Accept-Patch`/`Accept-Post`/`Accept-Put` sent only when the method is allowed, sourced from `accepted_write_types()`; `*/*` for a binary or a new resource; `served_types()` deleted | These headers mean "allowed"; `served_types()` includes RDF/XML, which ADR 0007 always refuses |
| H6 | `Link rel="type"` with the LDP kinds, plus `pim:Storage` and `solid:owner` on the root, `acl`, and `storageDescription`; successful reads and creates only | §4.1 MUSTs the storage links; a 4xx must not imply a resource kind |
| H7 | An ACL's ACL is itself; `acl_iri` lives beside `governed()` in `brolly-solid` | Stage 0's A2 governs `.acl` by its own `Control`; `x.acl.acl` is a fiction; splitting the pair from its inverse invites drift |
| H8 | Generated, world-readable storage description at `/.well-known/solid`, subdomain-scoped by the handler | Solid Protocol §4.1; discovery precedes credentials; axum routes aren't host-scoped |
| H9 | `WAC-Allow` gains `public=` from an anonymous probe on the same snapshot; sent on GET, HEAD and OPTIONS | A share UI has to show whether a resource is public |
| H10 | `Vary` appended not replaced: `Accept` on negotiated reads, `Origin` always; a 304 carries every header a 200 would | CTS checks `Vary: Origin` on a binary; a revalidation shouldn't cost a client its affordances (knowingly exceeding §15.4.5's SHOULD NOT) |
| H11 | `PUT` that creates → 201 + `Location` + `Link`; replace → 204 | LDP, and what clients branch on |
| H12 | Non-empty container `DELETE` → 409 **with a body**; root or root ACL → 405 | §5.4 requires both the status and the explanation |
| H13 | Listings carry members' `dcterms:modified`, `stat:mtime` and (binaries only) `stat:size`; a write naming a contained resource is a 409 | §4.2.1 for the metadata, §5.3 for the refusal; without the refusal a round-trip `PUT` would store it as content and defeat 5a's R8 |
| H14 | CORS echoes `Origin` and the preflight's requested headers; expose list gains `accept-put`, `www-authenticate`, `vary` | Solid §6 wants any header combination to be sendable; CTS asserts the echo both ways |
| H15 | `HEAD` authenticates as `HEAD`; the ActivityPub inbox keeps its 404 rule | A correct DPoP proof must not silently downgrade the caller |
| H16 | Every 405 carries `Allow` | RFC 9110 §15.5.6, and no 405 in the server does today |
| H17 | A body with no `Content-Type` is a 400, not Turtle | Solid §2.1; guessing turns a client bug into stored garbage |
