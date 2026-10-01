# Stage 5d: auxiliary resources and the conformance suite

<!-- doc-paths: skip -->
<!-- The spec names files and a CI job this stage creates, so not every path
     it cites resolves until it's implemented. -->

**Status:** Draft (2026-09-29), revised after one adversarial review against the
Solid Protocol (§4.3), WAC, LDP, RFC 6892, and the code it cites — every claim
in the Problem was checked against the tree. Stage 5a and 5b were each
revised through three passes before approval; this one awaits a second.
**Roadmap:** `docs/specs/2026-09-17-interop-roadmap.md`, stage 5, part d —
the last part of stage 5, which closes with the Solid Conformance Test
Harness in CI. Parts a
(`docs/specs/2026-09-22-solid-resource-metadata.md`), b
(`docs/specs/2026-09-23-solid-http-surface.md`) and c
(`docs/specs/2026-09-29-solid-write-semantics.md`) landed the state this part
closes.
**Depends on:** stage 5a (the metadata graph and `Kind`), stage 5b (the
`Link` builder and 5d's H3 extends its set), stage 0 A2
(`docs/specs/2026-09-17-security-fixes.md` — `.acl` requires `acl:Control`,
and deleting a resource deletes its `.acl`).

## Problem

The Solid Protocol's auxiliary resources (§4.3) are half-implemented, and
nothing checks the whole surface:

1. **`.meta` does not exist.** No code mentions it: `is_acl` tests only
   `.acl` (`store/src/resources.rs:1001-1003`), `governed` strips only
   `.acl` (`adapters/solid/src/ldp.rs:216-222`), `kind_for_iri` classifies
   `x.meta` as an ordinary `Kind::RdfSource`
   (`store/src/resources.rs:991-999`). A `PUT /~/x.meta` today creates a
   *contained* ordinary document: it appears in the container listing, its
   `Link rel="acl"` points at the fiction `x.meta.acl`
   (`acl_iri`, `ldp.rs:238-243`), and `DELETE /~/x` orphans it, because
   `PodWrite::remove` forgets only `{resource}.acl`
   (`store/src/resources.rs:764-767`).
2. **`Link rel="describedby"` is never sent.** 5b's H6 set is `type`, `acl`,
   `storageDescription` (and `owner` at the root)
   (`server/src/pod.rs:647-691`). The Solid Protocol §4.3 requires servers
   to advertise auxiliary resources on `GET` and `HEAD` with `Link` — the
   description resource's relation is `describedby`. 5b deferred it here
   because it "would be a dead link before it exists"
   (`docs/specs/2026-09-23-solid-http-surface.md:107-111`).
3. **A binary's description triples live in its own graph, where no client
   can read them.** `set_description` writes `<iri> brolly:altText "…"`
   into the binary's content graph (`store/src/resources.rs:712-736`), and
   `GET` of a binary serves only bytes. 5a said "until `.meta` (5d)"
   (`docs/specs/2026-09-22-solid-resource-metadata.md:119-120`). A Solid
   app — Penny's alt-text editor — has no way to read or write the
   description of an image.
4. **No conformance gate exists.** CI runs fmt, clippy, build, tests and
   cargo-deny (`.github/workflows/ci.yml`). The roadmap's finish line
   requires "the Solid Conformance Test Harness against a containerized
   instance, with each failing test that's accepted listed in the stage spec
   that owns it" (`docs/specs/2026-09-17-interop-roadmap.md:64-68`). The
   tests that exist are home-grown (`ldp_conformance.rs` is our own Phase-4
   suite, not CTS). Stages 5a–5c were verified against our reading of the
   specs, and the only thing that can check that reading is the suite the
   ecosystem actually runs.

## Goals

- **`.meta` is an auxiliary resource** in every layer that knows about
  `.acl`: kind, routing, placement, deletion, `Accept-Put`.
- **Its authorization is the subject's, not `Control`'s** — the Solid
  Protocol §4.3 requires the description resource be authorized "by the
  authorization rule that is used for the subject resource", which is the
  opposite of the `.acl` rule.
- **Every resource points at its `.meta`**, and every `.meta` points back.
- **A binary's description triples move to its `.meta`,** where a Solid app
  can read and write them, with an upgrade for existing pods.
- **CTS runs in CI on every push**, and a failure is red unless it is on a
  checked-in, owner-annotated accepted list.

## Non-goals

- **Access Control Policy** (roadmap: not in scope, WAC stays).
- **Stage 4's media items:** the content-type allow-list, size limits,
  `nosniff`, publication-following read access. `.meta` lands first; stage 4
  builds on it.
- **Stage 6's items:** writable profile, type indexes, Client ID Documents,
  `prompt=none`, foreign issuers.
- **A second auxiliary-creating mechanism.** `.meta` files are created by
  `PUT` to them (the Solid Protocol §"Writing Resources": "When a `PUT` or
  `PATCH` request targets an auxiliary resource, the server MUST create or
  update it") — there is no auto-vivification on first read.
- **Fixing what CTS finds** beyond the accepted list bookkeeping: failures
  discovered by the harness are triaged into the stage spec that owns them;
  this spec only builds the gate.

## Design

### H1. `.meta` joins `.acl` as an auxiliary, and auxiliaries end there

- `meta_iri(resource) = format!("{resource}.meta")` — beside a document
  (`/~/x` → `/~/x.meta`), inside a container (`/~/notes/` →
  `/~/notes/.meta`), exactly the placement rule `acl_iri` already uses for
  `.acl` (`ldp.rs:238-243`).
- `Kind::Auxiliary` covers both suffixes: `is_auxiliary`, `kind_for_iri`,
  and `check_kind` (`store/src/resources.rs:991-1019`) learn `.meta`.
  Auxiliaries stay uncontained and unlisted (5a: "Recorded, never
  contained").
- **No auxiliary of an auxiliary.** A path ending in two auxiliary suffixes
  (`.acl.acl`, `.acl.meta`, `.meta.meta`, `.meta.acl`) is not addressable:
  every method answers **404**. The resource can never exist, so 404 is
  truthful, and it cannot leak anything — the answer is decided by the IRI's
  shape, before any lookup, and the 404 deliberately precedes WAC: the shape
  is syntactic public knowledge, so there is no existence to protect (5b
  H1's auth-before-target rule protects *lookups*, and no lookup happens).
  This extends 5b's H7 (`x.acl`'s ACL is itself) from a `Link` rule to a
  storage rule. The gate lives where the request resolves — before method
  dispatch, so `GET`/`HEAD`/`OPTIONS` answer it too, not only the write
  paths — with the store-layer refusal as defence in depth. Note the change
  of heart for `x.acl.acl`: stage 0 made it reachable and guarded (Control
  over it is Control over `x`, `ldp.rs:210-215`); it is now a fiction, and
  any stray stored doubles are removed by the H6 upgrade hook.
- A `.meta` may exist for a resource that does not (as `.acl` may —
  stage 0, `docs/specs/2026-09-17-security-fixes.md:226-229`).

### H2. A `.meta` is authorized by the subject's rule

`ldp::check` (`ldp.rs:252-271`) today remaps *any* mode on an `.acl` target
to `acl:Control` on the governed resource. For a `.meta` target it remaps to
*the same mode* on the subject resource: reading a `.meta` requires Read on
the subject, writing it requires Write on the subject, deleting it requires
Write on the subject. This is the Solid Protocol §4.3's MUST, quoted in the
problem's terms: a description is as private as what it describes — no more
(the `Control` wall is for policy, not prose) and no less.

The remap is a sibling of the `.acl` rule, not an extension of `governed`:
a `describes(path)` helper strips exactly one trailing `.meta`, and `check`
matches `.acl`-governed → `Control` and `.meta`-described → same mode as
two arms, never composed — a path ending in both suffixes answered 404
before authorization (H1). `governed` keeps its own rule unchanged; folding
`.meta` into it would send `.meta` targets down the `Control` arm.

Consequences, each deliberate:

- A caller with Read on a public image can read its `.meta` — that is how
  Penny shows alt text for shared images.
- A caller with only Append on a container cannot write its `.meta` —
  appending is not describing.
- `granted`/`public` modes reported for a `.meta` (5b's `WAC-Allow`) are the
  caller's and the public's modes **on the subject**, which is now also the
  truthful answer for the `.meta` itself.
- The `Allow` and `Accept-*` computation for a `.meta` target goes through
  the same remapped `check`, so it offers the methods the caller holds on
  the *subject* — the honest answer for the `.meta`, which is authorized by
  exactly those modes.

### H3. The `Link` set gains `describedby` — and `.meta` answers `describes`

- Every non-auxiliary resource's `Link` set (5b's `links`,
  `server/src/pod.rs:647-691`) gains `rel="describedby"` pointing at
  `meta_iri(resource)`, always sent, exists or not — the same contract as
  `rel="acl"`: the client needs the IRI to create it.
- A `.meta`'s own `Link` set sends `rel="describes"` (RFC 6892) pointing at
  the subject, and its `rel="acl"` points at the subject's `acl_iri` — the
  ACL that actually governs it under H2. (An `.acl`'s `rel="acl"` stays
  itself, 5b H7 unchanged.)
- `rel="describedby"` is omitted on auxiliary resources (their described
  target is the subject, announced there), and `rel="type"` for both
  auxiliary kinds stays `ldp:Resource, ldp:RDFSource` — LDP names no
  auxiliary class, and 5b already declined to invent one
  (`server/src/pod.rs:667-669`).

### H4. The HTTP surface treats `.meta` as RDF-only, like `.acl`

`rdf_only` (`ldp.rs:603`) covers `.acl` targets; it covers `.meta` targets
too, so `Accept-Put` advertises the RDF types, a binary body is 415, and
`PUT`/`PATCH`/`DELETE` route through the existing auxiliary paths. 5c's
slug rule already refuses minting `.acl` by slug and is extended to refuse
`.meta`.

### H5. Deleting a resource deletes both auxiliaries

`PodWrite::remove` (`store/src/resources.rs:764-767`) forgets
`{resource}.acl` today; it forgets `{resource}.meta` too, in the same
transaction. The Solid Protocol: "When a subject resource is deleted its
auxiliary resources are also deleted by the server." Direct `DELETE` of a
`.meta` (authorized by H2's Write-on-subject) remains the way to *remove* a
description without removing the resource.

### H6. Description triples move to `.meta`

`set_description` writes the description quads into the `.meta`'s graph
instead of the binary's own graph; `alt_text`
(`server/src/mastodon_api.rs:607-609`) reads them from there. Mastodon's
media API is unchanged on the wire.

- **Alt text survives byte replacement.** Today a `PUT` of new bytes drops
  the description triples (`store/src/resources.rs:670-672`); with the
  description in its own resource, replacing the bytes keeps it. The image
  changed; the member's description of the image is theirs to change
  deliberately (`update_media` still replaces it wholesale). Recorded here
  because it is a behaviour change someone will notice.
- **A member can write their own `.meta`** — arbitrary RDF under the
  subject's Write rule — including a different `brolly:altText`. That is
  the point: the description is member data, and the Mastodon surface
  reading it is a projection, same as the profile.
- **Migration.** Existing pods upgrade on open (the 5a upgrade hook):
  every `Kind::NonRdfSource` with description triples in its own graph gets
  a `.meta` auxiliary carrying them, and the own-graph copies are removed.
  Existing client-created `x.meta` documents (ordinary contained RDF
  sources under the old rules) are un-contained and retyped `Auxiliary`,
  preserving their graphs. Both run inside one transaction per pod; a pod
  that fails to upgrade logs at `error` and answers LDP reads with 404,
  the 5a upgrade contract.

### H7. CTS in CI

A new `conformance` job in `.github/workflows/ci.yml`, running on every
push alongside `check` and `deny`:

- **Server under test.** Build the release binary, run it against the
  testcontainers Postgres already used by `cargo test`, on
  `BROLLY_BASE_DOMAIN=brolly.test` over plain HTTP on `127.0.0.1`, with
  `/etc/hosts` entries mapping `brolly.test` and the seed members'
  subdomains (`alice.brolly.test`, `bob.brolly.test`) to `127.0.0.1`.
  Hosts entries rather than a wildcard: deterministic on GitHub runners,
  where `*.localhost` resolution is not something to depend on. The server
  binds plain HTTP (`server/src/main.rs`); TLS termination is a deployment
  concern (ADR 0016's posture, `docs/deploying.md`), and CTS's HTTP-mode
  target support is verified in the spike below before anything is wired.
- **Accounts.** Two members, created through the real registration door:
  read the bootstrap invite out of the server's stderr (the documented
  zero-account flow, `docs/deploying.md`), register `alice` (admin by
  first-claim), mint one ordinary invite (`brolly-admin` against the same
  environment), register `bob`. No test-only registration path exists and
  none is added.
- **The harness.** Node is installed in the job; the
  `solid/conformance-test-harness` is run against the instance. **The first
  task of the implementing chunk is a spike** — run CTS by hand against
  `docker compose up` locally, discover what its invocation actually
  requires (account bootstrap shape, target flags, HTTP-vs-HTTPS), and only
  then freeze the CI wiring. The roadmap's own lesson from O1 applies to
  this harness too: *spike it, don't survey it* — a written plan for a
  tool nobody has run here yet is a verdict table built from line counts.
- **The accepted list.** A checked-in `tools/cts-accepted-failures.txt`,
  one failure per line, each annotated with the owning stage spec and a
  one-line reason. The job diffs the harness report against the list: a
  failure on the list is reported but green; a failure off it is red; a
  listed failure that *passes* is also red (stale acceptance), so the list
  cannot rot. 5c's items most likely to be retried by the harness (H5's
  mode table, H8's 422, H9's 308) are expected guests on the list until
  triaged.

**Outcome (2026-10-01): deferred — the spike ran, the wiring did not.** The
spike read solid-contrib/conformance-test-harness @ main (= v1.2.2's
behaviour) against brolly @ HEAD; the local compose run was cut short once
the findings were clear, so what follows is source-verified, with no
captured run log. Every finding is independently fatal, and every one of
them is a deliberate, advertised brolly design: brolly is within its
advertised surface in each case, and accommodating the harness would mean
weakening that surface — machine-drivable consent, RS256 acceptance, a
credentials grant — for tooling convenience. Brolly-side concessions shaped
by this tooling are not wanted. The deferral and its re-entry conditions
are O9 (`docs/greenfield-implementation-plan.md` §6).

- **The harness is not what this section assumed.** solid/
  conformance-test-harness redirects to
  solid-contrib/conformance-test-harness: Java/Quarkus/Karate, distributed
  as the Docker image solidproject/conformance-test-harness (v1.2.2,
  amd64-only, embedding specification-tests v0.0.19). There is no npm
  package; "Node is installed in the job" is moot.
- **Authentication is unconditional.** `runTestSuites` → `setupTestHarness`
  → `registerClients` → `AuthManager.authenticate("alice"/"bob")` runs
  before any feature; a failure exits 1 with zero tests and no report.
  `UserCredentials` carries webid/refreshtoken/clientid/clientsecret/idp/
  username/password only — no pre-minted access-token field, no anonymous
  mode.
- **DPoP algorithm mismatch.** The harness signs DPoP proofs RS256/RSA-2048
  (`JwsUtils.generateDpopToken` — ES256 sits commented out as a TODO;
  `createClientKey` generates RSA-2048 per run). Brolly requires ES256/P-256
  (`identity/src/dpop.rs`, the alg check and `verifying_key`) and advertises
  exactly that (`dpop_signing_alg_values_supported`, the discovery document
  in `adapters/solid/src/oidc/tokens.rs`). Every proof the harness can send
  is rejected at the token endpoint, whatever the grant.
- **The auth-code flow cannot cross the consent screen.** The harness's
  `requestAuthorizationCode` follows redirects and recognizes only login
  forms, POSTing email/password to whatever form it finds. Brolly's
  authorize renders a consent form for a logged-in session (request +
  decision=allow, `server/templates/consent.html`) and `decide` 422s
  anything else; brolly's login form wants `username`, not `email`.
- **Refresh tokens cannot be handed over.** Brolly binds every refresh
  token to the minting key's jkt (`issue_refresh(..., Some(jkt))` in both
  grant paths, `server/src/solid_oidc.rs`; the refresh grant refuses a
  different key). The harness's key is generated inside its JVM per run and
  cannot be fixed by config, so out-of-band-minted tokens are refused at
  first use.
- **No client-credentials grant.** The token endpoint supports
  authorization_code and refresh_token only (the discovery document).
- **Plain HTTP cannot work either.** Brolly hardcodes https into the issuer
  (`server/src/solid_oidc.rs:42-44`), the WebIDs and pod bases
  (`server/src/pod.rs:114-115`), and both DPoP `htu` checks; the harness
  validates issuer equality at discovery. TLS termination in front of the
  plain-HTTP server would be needed regardless. (Harness quirk, for the
  record: its `SOLID_IDENTITY_PROVIDER` handling appends "/", which fails
  brolly's exact-issuer match — `USERS_x_IDP` is the usable spelling.)
- **Registration through the real doors is human-fronted by design**
  (bootstrap invite on stderr, invite-gated `/register`). The harness's
  `USER_REGISTRATION_ENDPOINT` posts a CSS-shaped form
  (email/password/confirmPassword/podName/register/createWebId/createPod)
  that brolly rejects. "No test-only registration path exists and none is
  added" stands.

## What this changes in the code

| File | Change |
|---|---|
| `store/src/resources.rs` | `is_auxiliary`/`kind_for_iri`/`check_kind` learn `.meta` (H1); `remove` forgets `{resource}.meta` (H5); `set_description` writes the `.meta` graph (H6); the upgrade hook migrates descriptions and un-contains stray `.meta` documents (H6); two-suffix paths are refused at `put`/`append` (H1) |
| `adapters/solid/src/ldp.rs` | `meta_iri` beside `acl_iri` (H1); `check` maps `.meta` targets to the same mode on the subject (H2); `rdf_only` covers `.meta` (H4); `governed` strips `.meta` for the authorization remap |
| `server/src/pod.rs` | `links` gains `describedby`, `describes` on a `.meta`, and the subject's `acl` on a `.meta` (H3); `.meta` 404s for double-suffix paths (H1) |
| `server/src/mastodon_api.rs` | `alt_text` reads the `.meta` graph (H6) |
| `domain/src/vocab.rs` | `describedby`/`describes` relations |
| `.github/workflows/ci.yml` | the `conformance` job (H7) — **not landed**: H7 deferred after the spike |
| `tools/cts-accepted-failures.txt` | new: the accepted list, seeded by the spike — **not created**: H7 deferred after the spike |

**Tests whose expectations change:** `pod_http.rs`'s `Link` assertions gain
`describedby`; `ldp_conformance.rs`'s delete tests assert the `.meta` dies
with its subject; the Mastodon `mastodon_compose.rs` alt-text tests move
storage location, not wire shape; any test PUTting an `x.meta` as an
ordinary document (none known — the spike will confirm) is rewritten to the
auxiliary contract.

## Chunks

Three, one commit each:

1. **`.meta` the auxiliary.** Store kinds, `meta_iri`, authorization remap,
   `Link` relations, deletion, double-suffix 404s, upgrade. *Everything
   that makes `.meta` addressable, before anything uses it for data.*
2. **Descriptions move.** `set_description`/`alt_text` relocation, the
   description migration, the survives-byte-replacement change.
   *The only chunk that moves existing member data; it deserves its own
   revert boundary and its own volume-snapshot note in `docs/deploying.md`.*
3. **CTS in CI.** The spike, the job, the accepted list, the first green
   run with the list populated. *Last, because everything before it is
   what the harness exercises; landing it earlier would file this stage's
   own gaps against unfinished parts.* **Outcome (2026-10-01): only the
   spike ran; the job, the accepted list and the wiring did not land** —
   every finding is fatal and each is brolly working as designed (H7's
   outcome, above). The deferral is recorded as O9
   (`docs/greenfield-implementation-plan.md` §6).

## Decisions

| # | Decision | Why |
|---|---|---|
| H1 | `.meta` is the second auxiliary suffix; `meta_iri = {resource}.meta`; no auxiliary-of-auxiliary — double-suffix paths 404 | Mirrors `.acl`'s placement exactly (CSS convention); the Solid Protocol leaves the filename to the server but the *relation* is standard; auxiliaries of auxiliaries are fictions |
| H2 | A `.meta` is authorized by the same mode on the subject resource; `Control` stays `.acl`-only | Solid Protocol §4.3 MUST; a description shares its subject's privacy, which is the opposite job from policy |
| H3 | `describedby` always sent on non-auxiliaries; `describes` + the subject's `acl` on a `.meta` | §4.3's advertisement MUST; the client needs the IRI before the resource exists — same contract as `rel="acl"` |
| H4 | `.meta` is RDF-only, minting one by slug is 400 | An auxiliary is an RDF document by definition; the `.acl` rules were right and are reused |
| H5 | `remove` forgets both auxiliaries; direct `DELETE` of a `.meta` takes Write on the subject | §"When a subject resource is deleted its auxiliary resources are also deleted"; removal is a write to the description, not to the bytes |
| H6 | Description triples live in the `.meta`; migration on pod open; alt text survives byte replacement | It is the only place a Solid client can reach them; the Mastodon read becomes a projection like the profile; the survive-change is recorded because it is observable |
| H7 | CTS on every push; failures green only against an owner-annotated accepted list; stale acceptances red; wiring frozen only after a manual spike. **Outcome (2026-10-01): deferred** — the spike ran, the wiring did not; no conformance job, no accepted list, no brolly-side changes to accommodate the harness. Each finding is a deliberate, advertised brolly design; concessions shaped by this tooling are not wanted. Reopens when any one of: the CTH grows ES256 DPoP and consent-screen handling; a credible runner not shaped around Inrupt's stack appears; stage 6 deliberately decides a machine-client auth path (O9, `docs/greenfield-implementation-plan.md` §6) | The roadmap's finish line; a list that can rot is a list that lies; and nobody here has run CTS yet — a plan pretending otherwise would repeat O1's line-count verdict table. The spike bore the caution out: the harness cannot authenticate to brolly at all, and the reasons are brolly's security posture working as intended (H7's findings) |
