# Stage 6: Solid identity

<!-- doc-paths: skip -->
<!-- The spec names files and a migration this stage creates, so not every
     path it cites resolves until it's implemented. -->

**Status:** Draft (2026-09-29), revised after one adversarial review against
WAC, Solid-OIDC, OIDC Core, RFC 8252/8414/9449, and the code it cites — every
claim in the Problem was checked against the tree. Stage 5a and 5b were each
revised through three passes before approval; this one awaits a second.
**Roadmap:** `docs/specs/2026-09-17-interop-roadmap.md`, stage 6. Closes the
Solid side of the finish line: "The SolidOS data browser and Penny log in
with Solid-OIDC, browse the pod, create containers and documents, edit the
profile, and share a resource with another WebID."
**Depends on:** stage 5a–5d (the pod's write semantics and auxiliary
resources), ADR 0008 (OAuth endpoint layout), ADR 0011 (consent scope
vocabulary), stage 0
(`docs/specs/2026-09-17-security-fixes.md` — client validation rules the
ATProto side already got, and the `.acl`/`Control` rule that makes sharing
work today).

## Problem

Four things stand between this server and "a Solid app can log in and be
useful", all named by the roadmap's survey
(`docs/specs/2026-09-17-interop-roadmap.md:34-39`):

1. **The profile can't be written.** `/profile` is GET-only
   (`server/src/lib.rs:305`); a PUT gets axum's 405. The member's triples
   reach the profile graph only through the dashboard form (five fixed
   predicates, `server/src/account.rs:196-236`) and Mastodon's
   `update_credentials`. The document itself is a projection
   (`adapters/solid/src/profile.rs:189-243`) — correct to read, impossible
   for a Solid app to write, and SolidOS and Penny both edit the WebID
   profile as their first act.
2. **There are no type indexes and no preferences file.** A workspace-wide
   grep for `solid:TypeIndex`, `solid:publicTypeIndex`,
   `solid:privateTypeIndex`, `pim:PreferencesFile`, `solid:ListedDocument`,
   `solid:UnlistedDocument` returns nothing — no vocabulary, no code, no
   tests. Provisioning creates the storage root, its ACL and the ATProto
   identity (`server/src/provision.rs:47-71`, `:104-195`), nothing else.
   SolidOS requires all three to boot a workspace; Penny reads the public
   index to find where an app keeps its data.
3. **`client_id` URLs are rejected.** `find_client` looks the client up in
   `solid_clients` (`server/src/solid_oidc.rs:228-240`), registration only
   mints `urn:uuid:` identifiers (`adapters/solid/src/oidc/store.rs:49`),
   and an `https://` client_id gets "This application is not registered with
   this server" — a 400, before any redirect. Most real Solid apps — Penny
   among them — are Client ID Documents: an RDF file at their `client_id`
   URL. The roadmap parked this here from stage 0
   (`docs/specs/2026-09-17-security-fixes.md:69-71`).
4. **`prompt=none` is ignored, and foreign issuers are refused.**
   `AuthorizeParams` has no `prompt` field
   (`server/src/solid_oidc.rs:172-184`); `serde` silently drops it, a
   session-less request is redirected to `/login`
   (`server/src/solid_oidc.rs:258-265`) instead of the OAuth-correct
   `error=login_required` round trip, and the consent screen is rendered
   every time with no prior-grant check. And on the resource side,
   verification is single-key and local-only: `verify_access` demands our
   own `kid` (`adapters/solid/src/oidc/keys.rs:176-180`), `solid_subject`
   demands a WebID this instance hosts (`server/src/pod.rs:375-395`,
   "Accepting other issuers is stage 6"), and `iss`/`aud` are never
   inspected anywhere. A member can *grant* another member's WebID access
   today (WAC `acl:agent` matching is IRI-based and already works) — but if
   that other member is on a different server, their pod's token cannot
   get them in.

## Goals

- **A Solid app can edit the profile** with `PUT`/`PATCH` on `/profile`,
  under the one authorization rule that makes sense there.
- **A new member's pod boots a SolidOS workspace:** preferences file and
  both type indexes provisioned, linked from the WebID, and the public
  index readable by whoever the member shares it with — which, for a
  *public* index, is everyone.
- **A Solid app with a Client ID Document can log in,** with its redirect
  URIs validated against the document it publishes.
- **`prompt=none` works:** silent re-authorization for remembered consents,
  `error=login_required`/`error=consent_required` for everything else —
  no login-page redirect where the OAuth flow demands an error redirect.
- **A token from another Solid-OIDC issuer verifies,** its WebID becomes an
  authenticated agent under WAC, and sharing across servers works end to
  end.

## Non-goals

- **WebID-OIDC as a *client*** of other servers (we are issuer and resource
  server only; logging *into* other pods with a brolly identity is their
  verifier plus our issuer, which already interops or doesn't
  independently of this stage).
- **`email` scope, claims beyond `webid`, or account metadata in the ID
  token.** ADR 0011's scope vocabulary stays as it is.
- **Consent skipping on the normal flow.** The consent screen renders on
  every interactive authorize; the remembered-consent table exists for
  `prompt=none` and is recorded here as revisitable.
- **Stage 4's media items** (avatars by multipart upload). This stage makes
  the *profile* writable, which makes `foaf:depiction` a triple a Solid app
  can write; the avatar upload path and its public-read mechanics are
  stage 4's.
- **Foreign *refresh* or *authorization* on our token endpoint** — our
  issuer only, always.

## Design

### H1. The profile document becomes writable, by its owner

`PUT` and `PATCH` route on `/profile` (a new entry beside the GET at
`server/src/lib.rs:305`), delegating to the LDP write path with the profile
graph as the target. The routing layer's `USER_PROTOCOL_RESOURCES`
(`identity/src/routing.rs:20-27`) keeps `/profile` a protocol resource —
this is a write handler on a projection, not LDP content under `/~/`.

- **Authorization: the owner, only.** The caller's authenticated WebID must
  be the profile's `foaf:primaryTopic` (the member's own WebID). No WAC
  evaluation, no ACL inheritance: the profile is protocol state outside the
  storage root (the same reasoning `profile::write` already encodes,
  `adapters/solid/src/profile.rs:92-99`), and the member's identity
  document is not shareable infrastructure. Anyone else — anonymous,
  another member, a foreign WebID — gets 401/403 per stage 5b's H1.
- **The five derived triples are reserved, as positions rather than
  predicates.** `foaf:name`, the bio, and every other member triple
  stores verbatim as sent. The five the projection derives (`rdf:type
  foaf:PersonalProfileDocument` and `foaf:primaryTopic` on the document,
  `rdf:type foaf:Person`, `solid:oidcIssuer` and `space:storage` on
  `#me`, `adapters/solid/src/profile.rs:210-226`) become
  server-authoritative: writes are dropped by exact (subject, predicate,
  object) — the positions the projection derives — never by predicate
  alone. `rdf:type` is at once a reserved position and the commonest
  predicate in a hand-written profile; filtering on the predicate would
  drop `<#me> a schema:Person` and every other type a member asserts
  about themselves. The projection derives the five unconditionally
  instead of skipping ones the member already wrote (`profile.rs:228-241`
  today). Today a member can write `space:storage <https://elsewhere/>`
  and every client that trusts the profile follows it; the storage root
  and the issuer are deployment facts, not self-assertions.
- **A `PUT` clears the dashboard's predicates when it omits them, and
  that is owned here.** The graph holds what `profile::write` manages —
  `foaf:name`, `vcard:note`, `as:manuallyApprovesFollowers`,
  `mastodon:bot`, `mastodon:discoverable` — written by the dashboard form
  (`server/src/account.rs:212-228`) and Mastodon's `update_credentials`
  (`server/src/mastodon_api.rs:940-962`), both of which read what is
  stored and merge for exactly this reason. A Solid `PUT` replaces the
  graph, so a client that builds its body by hand instead of editing
  what it read clears all five — and `as:manuallyApprovesFollowers`
  absent reads as *false* (`adapters/solid/src/profile.rs:54`), so a
  locked account comes back unlocked. That is LDP `PUT` semantics, the
  same here as for any resource, and the projection serves the five
  verbatim, so a read-modify-write round trip — what SolidOS and Penny
  both do — carries them. Reserving the five instead would trade a
  hazard a client can see for a `PUT` that silently drops triples it
  accepted, which is a lie about what was stored.
- **`DELETE /profile` and `POST /profile` are 405 with `Allow`**
  (stage 5b's H16 discipline).
- **No conditional requests on `/profile`** in this stage: the profile has
  no `ResourceMeta` (5a's metadata is scoped to the storage root), and
  adding it is machinery this stage doesn't otherwise need. Recorded here
  because Penny sends `If-Match` when it can get an ETag; if it turns out
  to require one, the fix is a metadata record for the profile graph in a
  follow-up, not a hand-rolled ETag.

`PATCH` goes through the same solver as every other patch
(`apply_scoped`), scoped to the profile graph, with 5c's classification and
the reserved-position filter applied to the result.

### H2. Type indexes and the preferences file, provisioned and linked

Provisioning a member (`server/src/provision.rs:47-71`) additionally
creates, inside one `Pod::write` with the storage root:

| Resource | Type | ACL |
|---|---|---|
| `/~/settings/preferences.ttl` | `pim:PreferencesFile` | root (owner-only) |
| `/~/settings/publicTypeIndex.ttl` | `solid:TypeIndex`, `solid:ListedDocument` | owner grant **plus** world Read (`acl:agentClass foaf:Agent`) |
| `/~/settings/privateTypeIndex.ttl` | `solid:TypeIndex`, `solid:UnlistedDocument` | root (owner-only) |

and the profile projection derives three more triples:
`solid:publicTypeIndex`, `solid:privateTypeIndex` (both
`http://www.w3.org/ns/solid/terms#`) and `space:preferencesFile`
(`http://www.w3.org/ns/pim/space#`), pointing at them. They join the five
reserved positions of H1.

- **The public index is world-readable by a deliberate exception** to "WAC
  grants nothing by default" (`server/src/provision.rs:3-5`). A *public*
  type index exists to be read by other people's apps; provisioning it
  owner-only would make the name a lie, and the index contains only what
  the member (or their apps) list there. The private index keeps the
  owner-only default. This is the one place provisioning grants to
  `foaf:Agent`, and the grant is Read on one resource — an addition to
  the ACL, never its whole content. The closest ACL governs to the
  exclusion of every ancestor's: `effective_acl` takes the first
  candidate that exists and never falls through (`authz/src/wac.rs:142-154`,
  and an emptied ACL grants nothing rather than inheriting, `:113-116`),
  so an ACL holding only the world grant would lock the owner out of
  their own index — no Read, no Write, and no `Control` to fix it with.
  The index's ACL therefore carries the owner's grant (Read, Write,
  Control, `acl:accessTo` the index — the root grant's shape,
  `provision.rs:52-63`) *plus* the world's Read, and the world
  authorization carries no `acl:default`: nothing is meant to inherit
  it.
- **No registrations are written.** Apps register their own
  `solid:TypeRegistration` instances; the server seeds the containers
  empty. Inventing registrations nobody asked for is the predecessor's
  habit, not ours.
- **Existing pods upgrade on open** (the 5a/5d upgrade hook): the three
  resources and the public index's ACL are created if absent; nothing
  existing is touched. Idempotent by construction — same content, same
  provisioning path.
- **Vocabulary with pinned IRIs.** The `solid:` type-index terms and
  `space:preferencesFile` go in `domain/src/vocab.rs` with a test
  asserting each full IRI byte-for-byte (the existing pattern,
  `vocab.rs:141-153`). The terms are verified against the source specs
  (the Solid Type Indexes spec and SolidOS's vocabulary) during
  implementation — pinned by test, so a typo is a red build rather than a
  broken workspace on every member's pod.

### H3. Client ID Documents

At `authorize`, an `https://` `client_id` is fetched and validated instead
of looked up:

- **Fetch.** The ATProto client-metadata `Fetcher`
  (`server/src/client_metadata.rs:165-292`) is already protocol-agnostic
  *transport*: 5 s timeout, 64 KiB cap, no redirects, HTTPS-only, DNS
  filtered to public addresses, moka cache with distinct ok/error TTLs
  (`client_metadata.rs:108-118`). It moves (or is parameterized) to serve
  both. What varies with the protocol is everything downstream of the
  bytes: the `Accept` header (`application/json` today; an RDF type here —
  our own `/profile` serves HTML to anything that sounds like a browser,
  `server/src/profile.rs:44-52`, so a fetcher that does not ask for RDF
  gets the page), the content-type check, and the parse (an RDF graph,
  not a JSON document). A Client ID Document is fetched by the same
  transport rules; it is untrusted input fetched from an attacker-chosen
  URL, which is exactly what that machinery was built for.
- **Validate.** A Solid-OIDC Client ID Document must declare itself an
  OAuth/Solid-OIDC client and list its redirect URIs, per the Solid-OIDC
  client spec; the exact predicates are pinned by vocabulary test as in
  H2. Validation is a new `brolly-solid` function (the ATProto
  `validate`, `adapters/atproto/src/client_metadata.rs:289-392`, stays
  ATProto-specific): the document must type the client correctly, and the
  `redirect_uri` must match one of the document's listed
  redirect URIs **exactly** — no prefix, no scheme upgrade, no port
  wildcard. The one exception is the loopback redirect: RFC 8252 §7.3
  (what Solid-OIDC's native clients defer to) requires any port to be
  accepted, so a `redirect_uri` with scheme `http`, host `127.0.0.1` or
  `[::1]`, and a path byte-identical to a loopback URI the document
  lists matches regardless of port. The document must list the loopback
  URI — the exception relaxes the port, never the path, and never
  applies to a non-loopback URI.
- **Refusal.** A fetch failure, an unparseable document, a mistyped client,
  or a `redirect_uri` not listed: the same 400 "This application is not
  registered with this server" prose the unknown `urn:uuid:` gets
  (`server/src/solid_oidc.rs:230-235`) — before any redirect, and
  deliberately indistinguishable across causes so the endpoint is not an
  oracle for which client documents exist on the open web.
- **The grant remembers the document.** `solid_auth_codes` stores the
  `client_id` string it does today; the token endpoint's comparison
  against the grant is unchanged. `client_name`, if the document carries
  one, reaches the consent screen in place of the raw IRI, as registered
  clients' names already do.
- **Dynamic registration (RFC 7591) is unchanged** and remains the other
  supported client kind. The two coexist: `urn:uuid:` → table,
  `https://` → document, anything else → the 400.

### H4. `prompt=none`, and remembered consents

- `AuthorizeParams` gains `prompt`, matched on exact values. `prompt=login`
  forces the login page even with a session (the one useful thing it
  does); `prompt=none` changes the flow's two failure modes:
  - **No session** → an error redirect to the client's `redirect_uri`:
    `error=login_required` (+`state`), not the login page. The client
    asked not to be interacted with; the only correct answer is an error
    it can handle.
  - **Session, no remembered consent covering the request** →
    `error=consent_required`. A session plus a remembered consent that
    covers it → silent success: an auth code is issued and redirected
    exactly as a consent-screen approval would produce.
- **Remembered consents** are a new table (migration
  `20260929…_solid_consents.sql`): `(user_id, client_id, scope,
  redirect_uris, granted_at)`, unique on `(user_id, client_id)`, with the
  scope and the redirect URIs both widened monotonically (a new grant
  replaces the row with the union). Written on every consent-screen
  *allow* (and on every silent success, trivially unchanged).
  **Coverage is subset matching, not string equality:** a request is
  covered when its scope is a subset of the remembered scope and its
  `redirect_uri` is among the remembered URIs. Exact-match scope would
  refuse a remembered `openid webid` consent for a bare `webid` request;
  a superset the other way would silently grant what was never
  approved. The `redirect_uris` column is what keeps a remembered
  consent from outliving the document that earned it: a Client ID
  Document at a reused or taken-over `client_id` URL can change its
  listed redirect URIs, and without the column a `prompt=none` request
  would carry a code silently to a URI the member never saw. With it, a
  changed document falls back to the consent screen once — the
  interactive path's exposure, not more. (Registered clients' URIs are
  fixed at registration, so for them the column is constant.) There is
  no consent revocation surface yet — the dashboard's app list
  (`server/src/account.rs:366-376`) gains it later; recorded here so the
  table is designed to be revocable, not just append-only.
- **The interactive flow is unchanged otherwise**: no session → login
  redirect with `next` (existing behaviour), session → consent screen
  always. The remembered-consent table is consulted only by
  `prompt=none` in this stage; skipping consent for interactive
  re-authorizations is a product decision recorded as revisitable, not
  smuggled in.
- **`prompt` with any other value** (or absent) is today's behaviour —
  except a value combining `none` with anything else, which is a 400
  before any redirect: OIDC Core §3.1.2.1 forbids the combination, and
  honouring the interactive half would quietly break the no-interaction
  contract the `none` half asked for.

### H5. Access tokens from other Solid-OIDC issuers

`subject_for`'s Solid branch (`server/src/pod.rs:291-335`) splits on `iss`
after signature shape, before the local-user gate:

- **Our issuer stays the fast path.** `iss == https://{base}` (or no `iss`,
  as our tokens carry `webid` and our own `kid`): today's verification —
  own key, own `kid`, `cnf.jkt` binding, local WebID, activity check,
  jti spend. Unchanged, and exempt from the issuer binding below: the
  `kid` check already ties the token to this deployment's key, which is
  a stronger binding than the dereference.
- **A foreign `iss`** takes the remote path:
  1. The `iss` must be an HTTPS **origin** — scheme, host, optional
     port, no path. The Solid ecosystem's issuers are origins, and the
     two discovery conventions (OIDC's append, RFC 8414's
     insert-between-host-and-path) disagree on where the well-known goes
     for a path-bearing issuer, so a path-bearing `iss` is a malformed
     token, not a fetch to guess at.
  2. Fetch the issuer's OIDC discovery document
     (`{iss}/.well-known/openid-configuration`) — the hardened fetcher of
     H3, cached per issuer with its ok/error TTLs. `issuer` in the
     document must equal the `iss` claim (discovery cannot be used to
     launder one issuer for another).
  3. Fetch its `jwks_uri` (same transport rules, cached per issuer). The
     token header's `kid` must match a key in the set; an unknown `kid`
     forces exactly one re-fetch (rotation), then refuses.
  4. Verify the token's ES256 signature against that key. **No other
     algorithm is accepted** — `ES256` only, the one we advertise and the
     one Solid-OIDC's ecosystem converged on.
  5. Check `aud` is `solid` (the audience our own tokens use and CSS uses;
     a token minted for some other resource server is not ours to
     accept), `exp`, and that `cnf.jkt` is present. **The remote path has
     no bearer arm:** `verify_access` today accepts a token without
     `cnf.jkt` as `Access::Bearer`, no proof at all
     (`adapters/solid/src/oidc/tokens.rs:152-153`) — unreachable for our
     tokens, since we always mint the binding, but reachable for a
     foreign issuer that doesn't. Solid-OIDC's access tokens are
     DPoP-bound; a foreign token without a binding (or with one and no
     proof) is refused, and "DPoP runs exactly as today" must not import
     the bearer downgrade into the one path where it is reachable.
  6. **Bind the WebID to the issuer.** Dereference the token's `webid`
     (strip the fragment, fetch the profile document with an RDF
     `Accept`, same hardened transport, cached per WebID) and require the
     `iss` to be among the document's `solid:oidcIssuer` values. Without
     this step the remote path verifies the *issuer's* signature and
     then trusts the `webid` claim outright — and anyone who can serve
     HTTPS can publish a discovery document and a JWKS, so "which
     issuers may speak for WebID W" becomes "all of them", and every
     ACL grant to W on any of our pods is redeemable by whoever stands
     up an endpoint. The binding is the WebID's own assertion, read from
     the WebID — exactly what `solid:oidcIssuer` exists for, and the
     symmetric counterpart of the fast path's `kid` check. A WebID that
     does not dereference, or names no such issuer, is a refusal —
     uniform 401, not a fallback: the token's claim of identity is
     unverifiable.
  7. Build the remote subject: `Subject` with `user_id: None` (the shape
     it was designed for, `identity/src/subject.rs:75-77`), the WebID as
     the authenticated agent. DPoP proof verification is issuer-agnostic
     and runs exactly as today (`identity/src/dpop.rs`), including the
     jti spend and the `cnf.jkt`/proof binding of step 5.
- **A foreign token naming a *local* WebID is refused by the binding,
  full stop.** Our profiles publish exactly one `solid:oidcIssuer` —
  this instance's apex — and H1 makes that triple server-authoritative,
  so no foreign issuer can ever be authoritative for a WebID we host.
  Resolving the local user to check their activity instead would be a
  special case shaped like a bypass, preserving a gate the binding
  already closes; and WAC — the only thing the pod surface consults —
  never wanted the local user anyway.
- **WAC needs no changes.** `acl:agent <foreign-webid>` matching is
  IRI-based; `acl:agentGroup` → `vcard:hasMember` walks property paths in
  the *grantor's* store. A member shares with a foreign WebID by writing
  the ACL they can already write.
- **Failures map to 401 `invalid_token`** (stage 5b's H2 vocabulary),
  without distinguishing fetch-failure from bad-signature from
  unbound-WebID: the resource server is not an oracle for which foreign
  issuers are up, or which WebIDs exist.
- **`WWW-Authenticate` stays ours** (`server/src/pod.rs:194-221`):
  `as_uri` advertises our apex, the issuer we accept natively. Advertising
  foreign issuers we merely *tolerate* would be a claim we cannot make.

### H6. The finish-line check

The roadmap's test-infrastructure list wants "a second Solid WebID on
another provider" (`docs/specs/2026-09-17-interop-roadmap.md:121-122`).
This stage's exit criterion for H5 is: a local instance shares a resource
with a WebID hosted by a second instance (a second `BROLLY_BASE_DOMAIN`
deployment, which `docker compose` can stand up alongside the first), and
the second instance's token reads it. CSS-as-the-other-provider is a
stretch goal recorded here, not a gate: two brolly instances prove the
mechanism; interop with a *different* implementation is the ecosystem's
verdict, taken at the finish line with the deployed test instance.

## What this changes in the code

| File | Change |
|---|---|
| `server/src/lib.rs` | `/profile` gains `put`/`patch` (+405-with-`Allow` for the rest) (H1) |
| `server/src/profile.rs` | write handlers delegating to LDP with the profile graph; owner check (H1) |
| `adapters/solid/src/profile.rs` | reserved-position filtering on write; unconditional derivation of the five + three link triples on read (H1, H2) |
| `server/src/provision.rs` | the three settings resources and the public index ACL (H2) |
| `store/src/resources.rs` | upgrade hook provisions settings for existing pods (H2) |
| `domain/src/vocab.rs` | type-index, preferences, and Client ID Document terms, IRI-pinned by test (H2, H3) |
| `server/src/client_metadata.rs` | the fetcher parameterized for Solid-OIDC client documents (H3) |
| `adapters/solid/src/` | new `client_documents.rs` (fetch, validate, loopback rules) (H3); the WebID-document dereference and `solid:oidcIssuer` check (H5) |
| `server/src/solid_oidc.rs` | `prompt` handling, error redirects, silent issuance (H4); Client ID Document branch at `authorize` (H3) |
| `adapters/solid/src/oidc/store.rs` + `migrations/` | `solid_consents` table (scope and remembered `redirect_uris`, both widened monotonically) and accessors (H4) |
| `adapters/solid/src/oidc/tokens.rs` | `iss`-split verification entry point; remote key set handling; the remote path's required `cnf.jkt` (H5) |
| `server/src/pod.rs` | `subject_for`'s iss split and the remote-subject branch, with the local-WebID refusal (H5) |

**Tests whose expectations change:** the "valid token naming a WebID this
instance doesn't host is `invalid_token`" family
(`server/tests/solid_token_access.rs`, stage 5b's plan called this out at
`docs/plans/2026-09-23-solid-http-surface.md:562-566`) splits into
local-webid-foreign-issuer (still 401 — by the issuer binding, since our
profiles name only our own apex) and genuine-remote-webid (now a successful
remote subject). The authorize tests gain `prompt` cases (`none` with and
without coverage, `none` combined with another value, `login`); the consent
tests gain the remembered-consent write and both widenings; the remote path
gains the refusals that make it safe — no `cnf.jkt`, issuer absent from the
WebID's `solid:oidcIssuer`, unknown `kid` after one re-fetch, path-bearing
`iss` — and provisioning gains the public index's owner-plus-world ACL,
asserted grant by grant.

## Chunks

Five, one commit each:

1. **Writable profile.** Routes, owner check, reserved positions, 405s.
   *The smallest independent piece, and the one with no new state.*
2. **Type indexes and preferences.** Vocabulary, provisioning, upgrade,
   the public-index grant. *Touches every existing pod's provisioning;
   isolated so its revert boundary is clean.*
3. **Client ID Documents.** Fetcher parameterization, validation, the
   authorize branch. *A security-sensitive surface (untrusted fetch,
   redirect validation) walled off from the OAuth flow changes.*
4. **`prompt=none`.** The consent table, the migration, the error
   redirects. *Touches the flow users see; carries the only new table.*
5. **Foreign issuers.** Discovery/JWKS fetching and caching, the iss
   split, the WebID dereference and issuer binding, remote subjects.
   *The biggest piece, last, because everything it needs (hardened fetch,
   RDF parsing of fetched documents, 401 vocabulary, subject shape) is by
   then in place and tested.*

## Decisions

| # | Decision | Why |
|---|---|---|
| H1 | `PUT`/`PATCH` on `/profile`, owner-only, the five (+3, H2) derived *positions* reserved by exact (subject, predicate, object) and server-derived; DELETE/POST 405; a `PUT` that omits the dashboard's predicates clears them, recorded as LDP semantics | The profile is the member's identity document but the *deployment's* facts; owner-only because no share semantics exist for it and inventing them is not this stage's job; positions not predicates, because `rdf:type` is reserved *and* ordinary; the wipe is owned because reserving the dashboard's five would make `PUT` silently drop triples it accepted |
| H2 | Preferences + both type indexes provisioned at registration and by upgrade; the public index's ACL is the owner's grant *plus* one deliberate `foaf:Agent` Read, no `acl:default` on the world grant; no seeded registrations; IRIs pinned by test | SolidOS won't boot without them; a "public" index nobody can read is a lie — and an ACL holding only the world grant locks the owner out, since the closest ACL governs to the exclusion of every ancestor; seeded registrations are the predecessor's habit; pinned IRIs make vocabulary typos build failures |
| H3 | `https://` client_ids are fetched (hardened transport; RDF `Accept`, content-type and parse are the per-protocol part), validated (client type + exact `redirect_uri` match + loopback URIs matched on scheme/host/path with any port, per RFC 8252 §7.3), refused indistinguishably from unknown clients, cached; dynamic registration unchanged | Client ID Documents are how real Solid apps identify; the ATProto side already proved the transport; an oracle for which client documents exist is not ours to host |
| H4 | `prompt=none` → silent issuance when a remembered consent covers the request (scope subset, `redirect_uri` remembered), else `error=login_required`/`consent_required` redirect; `none` combined with another `prompt` value is a 400; consents recorded on every allow; interactive flow always shows consent | The OIDC-correct semantics; coverage must be subset-matched both ways or remembered consents refuse valid re-requests or grant what was never approved, and a remembered `redirect_uri` is what keeps a consent from outliving a changed or taken-over client document; the consent screen is the highest-stakes surface (ADR 0011) and stays on every interactive path — skipping it is a revisitable product decision, not a default |
| H5 | Verification splits on `iss`: ours (fast path, unchanged, exempt from the dereference — the `kid` check binds harder) vs foreign (origin-only `iss`, discovery + JWKS fetch, ES256 only, `aud: solid`, `cnf.jkt` required — no bearer arm — WebID dereferenced and `iss` required among its `solid:oidcIssuer`, remote subject with `user_id: None`); failures uniformly 401 | Cross-server sharing is the finish line; without the WebID→issuer binding every issuer speaks for every WebID, and every ACL grant is redeemable by whoever stands up an endpoint; the binding also refuses foreign tokens naming local WebIDs outright; a foreign token without `cnf.jkt` must not inherit a bearer downgrade our own tokens can never reach; uniform failure keeps the RS from being an availability oracle |
| H6 | Exit check is two brolly instances sharing; CSS interop recorded as a stretch goal, not a gate | The mechanism is provable with what we control; a different implementation's verdict belongs to the deployed-instance finish line, not this stage's CI |
