# Stage 3: the PDS surface

**Status:** Drafted 2026-11-19, five chunks, not yet reviewed. The roadmap's
finish line items 1–3 ("the Bluesky app logs in and works; a relay indexes the
account; a third-party OAuth app writes its own records") all stop at this
stage's missing surface.
**Roadmap:** `docs/specs/2026-09-17-interop-roadmap.md`, stage 3.
**Depends on:** stage 1
(`docs/specs/2026-10-06-atproto-repo-firehose.md` — the repo, blocks and
firehose this stage reads), stage 2
(`docs/specs/2026-10-09-atproto-auth.md` — the caller every endpoint here
sits behind, and the `getServiceAuth` tokens the proxy attaches), stage 0
(`docs/specs/2026-09-17-security-fixes.md` — the hardened outbound HTTPS
every forwarder here reuses), ADR 0002 (atrium over hand-rolled), D11
(`did:plc` in every wire format; `did:web` for routing only).

## Problem

Stage 2 finished logging in. What a client meets after that is a server that
answers half the lexicons the app expects and nothing else:

- **The repo read surface is half mounted.** `getRecord`, `describeRepo` (a
  stub: `collections` is always `[]`), `getRepo` and `subscribeRepos` exist;
  `listRecords`, `getBlocks`, `getLatestCommit`, `getRepoStatus` and
  `listRepos` do not. A client that wants a member's posts — the finish
  line's "a separate account sees and interacts with those posts" — has no
  way to page through them, and a relay has no way to enumerate the host.
- **Handles do not resolve by the network's own rules.** `resolveHandle`
  does not exist, and neither do `/.well-known/atproto-did` (the
  handle→DID document a subdomain serves) or `/.well-known/did.json` (the
  `did:web` document). The handle is `username.{base}` and the DID is known
  locally, but nothing outside the instance can discover the pairing.
- **bsky.app stops at settings.** `app.bsky.actor.getPreferences` /
  `putPreferences` are not implemented, and every other `app.bsky.*` call
  answers 501 because nothing forwards them to the AppView. The finish
  line's first item — log in, set a display name, post — dies on the first
  `app.bsky.*` call after the profile screen.
- **Relays are not invited.** Nothing sends `requestCrawl` on startup, so
  even a publicly reachable instance is invisible to the relay that the
  finish line's second item requires.

## Goals

- The repo read lexicons a client or relay pages through: `listRecords`, a
  real `describeRepo`, `sync.getBlocks`, `sync.getLatestCommit`,
  `sync.getRepoStatus`, `sync.listRepos`.
- Handle and DID resolution the way the network resolves them:
  `identity.resolveHandle`, `/.well-known/atproto-did` on the member
  subdomain, `/.well-known/did.json` on the member subdomain.
- `app.bsky.actor.getPreferences`/`putPreferences`, stored as a document in
  the member's pod that their Solid apps can discover and read — not
  server-local the way the reference PDS stores them (revised 2026-11-25,
  decision C).
- Unimplemented `app.bsky.*` requests forwarded to a configured AppView
  with `atproto-proxy` and a service-auth token, protected methods refused.
- `requestCrawl` sent to a configured relay on startup.

## Non-goals

- **Blob media** — `uploadBlob`/`getBlob`/`listBlobs`. Stage 4's remainder;
  it waits on this stage's surface and lands after it.
- **`chat.bsky.*` and every other service namespace** — the proxy forwards
  `app.bsky.*` only. Chat is a separate service in the reference world, not
  a hole in ours.
- **Writable preferences as repo records.** The reference PDS keeps
  preferences in actor storage, not the repo: they are per-account UI state,
  not content a relay should index or a member should sign. Storing them in
  the repo would publish them to the firehose and bloat every crawl — a
  behavioural change masquerading as a storage choice.
- **Acting as a relay or AppView** — no inbound `sync` indexing of foreign
  repos, no `app.bsky` serving. This stage is the *client of* those
  services.
- **Account migration endpoints** (`importRepo`, PLC operations from the
  dashboard). Still the paused migration's, per the roadmap.
- **`did:web` as a first-class identity.** D11: `did:plc` in every wire
  format; `did.json` exists for routing and discovery, not as a claim that
  the member's canonical DID is `did:web`.

## Design

### A. The missing repo reads

All five sit on what stage 1 built and none writes anything.

- **`repo.listRecords`** (`repo`, `collection`, `limit` 1–100 default 50,
  `cursor`, `reverse`): the MST already keeps records in key order —
  `Tree::entries_prefixed("{collection}/")` is the ordered stream — so
  listing is a walk, not an index. The cursor is the last `rkey` returned
  (exclusive, in the walk's direction), and `reverse` flips the direction.
  Records are read as DAG-CBOR and converted with the repo module's own
  `ipld_to_json`, so a listed record is byte-identical to the same record
  through `getRecord`. `collection` is validated with atrium's NSID grammar
  and `rkey`s with the record-key grammar, the way the write path already
  validates both — a listing is not a place to accept a path the write path
  would refuse.
- **A real `describeRepo`**: `collections` is the distinct first path
  segments of the MST's keys, in order (the walk is sorted, so the distinct
  prefix list is too). The rest of the document is already correct.
- **`sync.getBlocks`** (`did`, repeatable `cids`): a CAR whose header root
  is the repo's current root and whose body is the requested blocks that
  exist. A missing CID is absent from the CAR, not an error — a block set
  is a set, and `getBlocks` is the "do you have these" primitive a
  resynchronising consumer asks with; the honest answer is the subset.
  CIDs parse with atrium's own `Cid` grammar; unparseable ones are a
  `InvalidRequest`, not a 500.
- **`sync.getLatestCommit`** (`did`): `{commit, rev}` straight off the
  `atproto_repos` row — the state table's whole job. The commit CID is the
  repo's current root; `rev` is the row's own TID, the same 13 characters
  every consumer compares.
- **`sync.getRepoStatus`** (`did`): `{did, active}`, with `active: false`
  and `status: "takendown"` for a disabled account — the same
  `is_active` filter the caller applies, reported instead of enforced,
  because this endpoint exists to *tell* a crawler what happened to a repo
  it used to index. An unknown DID is the lexicon's `RepoNotFound`.
- **`sync.listRepos`** (`limit` 1–1000 default 500, `cursor`): every member
  with a repo, `{did, head, rev}` each. Order is by `did` (the network's
  own identity; the derived `did:web` sorts beside the `did:plc`s it
  actually is), cursor = the last `did` returned, exclusive. The head is
  the root CID. This is the enumeration a relay crawls with; it is also the
  answer to "what does this host hold" — which is why it lists, not pages
  by activity: the firehose is the activity signal, and the cursor is only
  a pagination device.

### B. Handle and DID resolution

- **`identity.resolveHandle`** (`handle`): `{did}`. The handle is
  `{username}.{base}` — the same form `resolve_repo` already accepts for
  the `repo` parameter — and the DID is the member's: `did:plc` when the
  PLC registration happened, the derived `did:web` otherwise (D11's
  fallback, unchanged). An unknown handle is `InvalidRequest` with the
  reference's own message shape ("Unable to resolve handle"), because a
  handle that does not resolve is the endpoint's normal outcome, not a
  server fault.
- **`/.well-known/atproto-did`** on the **member subdomain** (the handle's
  origin — `alice.brolly.test`, never the apex, which is not a handle):
  the bare DID as `text/plain` (not `did=…` — that prefix is the DNS
  method's `_atproto` TXT record; the HTTPS document's body is the DID
  verbatim). This is the atproto handle-resolution document,
  and the subdomain is the whole point: the DNS-less fallback any
  `atproto` client can check. It answers what `resolveHandle` answers, and
  carries `Cache-Control: public, max-age=3600` — the document is stable
  for as long as the member's DID is, and a resolver that re-fetched it
  per request would be a resolver that hammers its targets.
- **`/.well-known/did.json`** on the member subdomain: the W3C DID document
  for the derived `did:web:{username}.{base}` — `id`, `alsoKnownAs`
  (`at://{handle}`), a `verificationMethod` (`#atproto`, the member's repo
  signing key as `did:key`, the same public half the PLC document
  publishes), and a `service` (`#atproto_pds`,
  `AtprotoPersonalDataServer`, `https://{base}` — the PDS is the instance,
  not the pod's origin). Routing only (D11): the document makes the
  derived DID resolvable, with the key that actually signs the member's
  commits — it does not demote `did:plc` from its wire-format place.

### C. Preferences

*Revised 2026-11-25.* The draft stored preferences in a Postgres table, the
reference's own shape. nk: preferences are "on the order of a profile" —
member data with the same interop potential, so a preference set in bsky.app
should be readable from other apps, Solid apps included. That is also the
Postgres-is-admin-only rule: what a member made leaves with their export.

- `app.bsky.actor.getPreferences` returns `{preferences: [...]}`;
  `putPreferences` takes `{preferences: [...]}` and answers 200. Both sit
  behind the caller like every other XRPC procedure — a token's scope
  (`atproto` or `transition:generic`) is enough; the reference asks for
  `transition:generic`.
- **Where:** one RDF document in the member's storage,
  `/~/settings/atproto-preferences.ttl` — beside the preferences file and
  the type indexes, inheriting their owner-only ACL, inside `/~/` because
  it is the member's content, not a server projection (ADR 0010: the root
  is the server's, `/~/` is the member's). Not provisioned: the first
  `putPreferences` creates it ("pods are plain Solid" — nothing appears
  before something writes it).
- **What:** the body encoded by the faithful layer — the same lossless
  JSON ⇄ RDF every ATProto record already takes (D7) — with subject
  `<…/atproto-preferences.ttl#preferences>` and term space
  `app.bsky.actor.getPreferences` (the output lexicon; `defs#preferences`
  carries a fragment and cannot be a term space). A Solid client reads it as
  Turtle; `getPreferences` decodes it back to exactly what was put, unknown
  preference `$type`s included.
- **Discovery:** the first `putPreferences` also registers the document in
  the member's **private type index** — a `solid:TypeRegistration` with
  `solid:forClass <at://app.bsky.actor.defs#preferences>` and
  `solid:instance` the document — the way any Solid app announces a
  document it keeps. Registered once; an existing registration for that
  class is left alone.
- **`putPreferences` replaces the document whole** (`put`, not a patch):
  the lexicon's semantics are "here is the full set". It is an LDP write
  under the pod's lock — new version, new `modified` — not a repo commit,
  and nothing reaches the firehose.
- **The member owns the document**, so the server tolerates what a member
  or app does to it: missing → `getPreferences` answers `[]` (and the next
  put recreates and re-registers it); content that does not decode
  faithfully (triples an app wrote by hand) → `[]`, logged, never a 500. The
  data is theirs to break; the endpoint stays up.
- The body is validated as the lexicon's `app.bsky.actor.defs#preferences`
  shape *structurally*: a JSON array whose every item is an object with a
  string `$type`. Unknown preference `$type`s are stored and returned
  faithfully — a preference type this build has not heard of is a client
  being newer than the server, not an error. The array is capped at 1 MiB
  serialized, the repo's own record cap, and the write counts against the
  member's quota like any other pod write.
- A missing array or a non-object item is `InvalidRequest` — the lexicon's
  own answer to a body that is not preferences.

### D. The AppView proxy

*Revised 2026-11-25, as built* — the draft's protected list, its outbound
`atproto-proxy` header and its silence on cookies and on a client's own
`atproto-proxy` are corrected below.

- **Configuration**: `BROLLY_APPVIEW_URL` (an `https` origin, no path) and
  `BROLLY_APPVIEW_DID` (the AppView's DID, `did:plc:` or `did:web:`, no
  fragment). Both or neither — one alone stops the start. Unset, every
  unimplemented method keeps answering 501 exactly as before, the
  trunk-based rule.
- **What forwards**: an XRPC request whose NSID is **not locally mounted**
  and whose authority is `app.bsky` — the AppView's namespace — on the apex
  only. Everything else unimplemented keeps its 501: `com.atproto.*` is ours
  or nobody's (a PDS that forwards its own namespace is a PDS that has split
  its identity), and other namespaces (`chat.bsky.*` included) are not the
  AppView's to answer.
- **A client's `atproto-proxy`** (bsky.app sends
  `did:web:api.bsky.app#bsky_appview`) is honoured only when its DID is the
  configured AppView's; any other target is a 501 — forwarding it to our
  AppView anyway would answer from the wrong service.
- **Protected methods are never forwarded**: `app.bsky.actor.getPreferences`
  and `putPreferences`, account state the PDS owns (C). Both are mounted, so
  the list is defence in depth: a lost route must not leak them upstream.
  The draft also listed `app.bsky.notification.*`; the reference PDS forwards
  those (bsky.app registers push and marks notifications seen through its
  PDS), so blocking them would break the app.
- **The request**: the AppView's origin plus the same path and query, method
  and body streamed as-is. Request headers forward by allow-list — `accept`,
  `accept-language`, `content-type`, `content-encoding`,
  `atproto-accept-labelers`, `x-bsky-topics` — so the client's
  `Authorization`, `DPoP` and cookies are **never forwarded**: they are
  credentials for *this* server, and a token replayed at the AppView would be
  a token leaked to a third party.
- **Credentials come from `Authorization` only.** With one, the caller is
  authenticated as on any XRPC call (a bad credential is a 401, never a
  downgrade to anonymous), must hold `transition:generic`, and a service
  token goes up in its place — stage 2's `service_auth::issue`, `lxm` the
  method, `aud` the AppView's DID, signed by the **member's** repo key: the
  PDS vouches, the member authorises. Without one, the request forwards
  anonymously — AppView reads are public. The dashboard's session cookie is
  **not** a credential here: a cross-site page must not be able to make the
  member's key vouch for a call they never made.
- No `atproto-proxy` goes upstream: the AppView authenticates the call by
  the service token, verified against the member's DID document; the header
  is a client-to-PDS routing instruction, not a PDS-to-AppView one.
- **The transport** is the same hardened client as every outbound call
  (stage 0, now `client_metadata::hardened_http`): `https` only, no proxies,
  public addresses only, no redirects, a 30 s total timeout. An AppView
  behind localhost is reachable only through `AppView::for_tests`.
- **The answer**: status and body stream back untouched; response headers
  return by allow-list (`content-type`, `content-language`,
  `content-encoding`, `atproto-content-labelers`, `atproto-repo-rev`) — a
  third party's `set-cookie` has no business on our origin — with
  `Vary: Authorization`, and `Cache-Control: private` when a token went up.
  The AppView's errors are the client's business. An unreachable AppView is
  `UpstreamFailure`, a 502, not a silent 501: the difference between "not
  implemented" and "configured but down" is the difference between a client
  that gives up and one that retries.

### E. `requestCrawl` on startup

- Configuration: `BROLLY_RELAY_URL` (an `https` origin). Unset, nothing
  sends — the same trunk-based rule as the proxy.
- On startup, after migrations and before the listener accepts, POST
  `{hostname: base_domain}` to `{relay}/xrpc/com.atproto.identity.requestCrawl`,
  on the hardened transport, no credentials — the endpoint is the relay's
  own invitation to crawl, and the relay authorises by the PDS endpoint
  the crawl then discovers; a service-auth token from a DID the relay has
  never seen would prove nothing.
- A failure logs and retries with backoff, capped at once a minute, for
  as long as the process runs — a relay that is briefly down at boot must
  not cost the instance its place in the crawl queue until a manual
  restart. The first successful send stops the retry loop; a new boot
  starts it again.

## Testing

- **`listRecords`**: pages in key order; `cursor` resumes where the last
  page stopped; `reverse` flips; `limit` is enforced (and 0/negative →
  `InvalidRequest`); an unknown collection is an empty page, not an error;
  the records are identical to `getRecord`'s for the same keys; a bad
  collection NSID is refused.
- **`describeRepo`**: `collections` is the distinct collections in the
  repo, in order, after writing records across three collections; an
  empty repo lists none.
- **`getBlocks`**: the CAR carries the requested blocks that exist and the
  current root in its header; a missing CID is simply absent; an
  unparseable CID is `InvalidRequest`; the bytes are the same block bytes
  `getRepo` serves.
- **`getLatestCommit`**: `{commit, rev}` matches `atproto_repos` — the
  same root a write lands and the same TID the firehose emits.
- **`getRepoStatus`**: active account → `{did, active: true}`; a disabled
  account → `active: false` + `status: "takendown"`; unknown DID →
  `RepoNotFound`.
- **`listRepos`**: lists every member with a repo, ordered by DID, cursor
  resumes, `limit` enforced; members without repos are absent; the head
  matches each repo's root.
- **`resolveHandle`**: a member's handle → their `did:plc` (or the derived
  `did:web`); unknown handle → `InvalidRequest`; a bare username (no
  domain) is refused — a handle is a domain name.
- **The subdomain documents**: `/.well-known/atproto-did` on
  `alice.{base}` answers the bare DID as `text/plain` with the cache header;
  the apex 404s it (it is not a handle); `did.json` on the member
  subdomain carries `id`, `alsoKnownAs`, the member's actual signing key
  and the PDS service at the base origin; the apex 404s it too.
- **Preferences**: `putPreferences` stores and `getPreferences` returns
  the same array; the document exists at `/~/settings/atproto-preferences.ttl`
  as Turtle an owner's Solid client can `GET`, and the private type index
  registers it; a second put replaces (not merges) and does not register
  twice; a deleted document reads as `[]` and the next put recreates it;
  undecodable content reads as `[]`; an anonymous caller and a missing scope are refused;
  a non-array body, a non-object item and a missing `$type` are
  `InvalidRequest`; unknown `$type`s round-trip; an over-cap array is
  refused; a second member's preferences do not leak into the first's.
- **The proxy**: an unimplemented `app.bsky.*` method with the AppView
  configured is forwarded — same path, query and body — and its answer
  streams back untouched; the request carries `atproto-proxy` and, when
  the caller authenticated, a service token whose `lxm` is the method and
  `aud` the AppView DID, minted by the member's key; the client's
  `Authorization`, `DPoP` and cookies are absent from what the AppView
  receives, and its `set-cookie` is absent from what the client receives;
  an anonymous or cookie-only call forwards with no token, a bad credential
  is a 401; a protected method is answered locally, not forwarded; a
  client `atproto-proxy` naming another service is 501; an unconfigured
  AppView keeps today's 501; a non-`app.bsky` unimplemented method is 501
  whether or not the AppView is configured; an AppView that is down is a
  502 `UpstreamFailure`.
- **`requestCrawl`**: a configured relay receives the POST on startup,
  with the instance's hostname as the body, and a relay that refuses is
  retried with backoff; an unconfigured relay receives nothing (the
  default).

## Rollout

- No migration: preferences live in the pod (decision C, revised). No data
  conversion — no preferences exist yet.
- The wire is additive throughout: new read endpoints, two well-known
  documents on subdomains that currently 404, and preferences on a path
  that currently 501s. The one behaviour change on an existing path is
  `describeRepo`'s `collections` ceasing to be empty — a field no client
  today can be depending on for anything but an error path.
- Both forwarders are configuration-gated and default off: without
  `BROLLY_APPVIEW_URL`/`BROLLY_APPVIEW_DID` and `BROLLY_RELAY_URL`,
  nothing changes on the wire. The finish line's deployment sets both.
- The deployed-instance validation the finish line requires — bsky.app
  against a real domain, the relay crawling it — is this stage's exit
  criterion, per the roadmap's finish line: unit tests green is "done
  developing", not "done".

## Chunks

Five, one commit each:

1. **The repo reads.** `listRecords`, the real `describeRepo`,
   `getBlocks`, `getLatestCommit`, `getRepoStatus`, `listRepos` — all
   reads over state stage 1 already owns; the repo module gains the
   listing walk (`entries_prefixed`) and a blocks-by-CID CAR, both on
   atrium's own APIs. *First because it is the largest read surface and
   the one chunks 3–5's clients page through.*
2. **Identity and the subdomain documents.** `resolveHandle`,
   `/.well-known/atproto-did`, `/.well-known/did.json`. *Second because
   it is small and because the proxy (4) and any future relay-facing work
   cite the DID resolution it publishes.*
3. **Preferences.** The pod document, its type-index registration, both
   endpoints. *Third because bsky.app
   needs it and it touches nothing but itself.*
4. **The AppView proxy.** The configuration, the forwarder, the service
   token, the protected list. *Fourth because it consumes chunk 2's DID
   forms, chunk 1's mounted-method list (what "unimplemented" means), and
   stage 2's service-auth mint; and because it is the one piece whose
   failure modes are another server's.*
5. **`requestCrawl`.** The configuration and the startup task. *Last
   because it is the thinnest, because it is only meaningful on a public
   deployment, and because landing it after the proxy means the instance
   that announces itself is one whose surface is already complete.*

## Decisions

| # | Decision | Why |
|---|---|---|
| A | `listRecords` walks the MST (`entries_prefixed`) with an `rkey` cursor, in memory per page; `describeRepo`'s collections are the MST's distinct first path segments | The MST *is* the index — key order is record order — so a listing is a walk, not a second index to keep consistent; a cursor on `rkey` is the reference's own shape, and in-page handling keeps the walk stateless |
| B | `getBlocks` answers the existing subset, root in the CAR header; `getRepoStatus` reports `is_active` rather than enforcing it; unknown DID is `RepoNotFound` | A block set answers "do you have these" with the subset it has; status is a *report* to a crawler that already indexed the repo — the caller filter already enforces what enforcement would |
| C | *(revised 2026-11-25)* Preferences in a pod document (`/~/settings/atproto-preferences.ttl`, faithful RDF, owner-only), registered in the private type index; not repo records, not a table; structural validation (`$type`d objects), unknown `$type`s stored faithfully, 1 MiB cap | Not the repo: a preference is UI state, and publishing it to the firehose would be the behavioural change. Not a table: it is member data with a profile's interop potential (nk), so it leaves with the export and a Solid app can find it through the type index; faithful storage is the same rule the repo gives unmapped lexicons |
| D | *(revised 2026-11-25)* The proxy forwards unmounted `app.bsky.*` only, by header allow-list both ways, drops the client's credentials, attaches a member-key service token (`lxm`=method, `aud`=AppView DID) only for an `Authorization` caller — never for the cookie — streams both ways, and answers `UpstreamFailure` (502) when the AppView is down | The reference's delegation model (`auth-verifier.ts` reads exactly these); forwarding a PDS's own namespace would split its identity; replayed client credentials at a third party are a leak, not a feature; and "configured but down" must be distinguishable from "not implemented" |
| E | `requestCrawl` is unauthenticated, config-gated (`BROLLY_RELAY_URL`), retried with capped backoff until it succeeds | The relay authorises the crawl by the endpoint it discovers, so a token from an unknown DID proves nothing; a boot-time failure must not cost the crawl slot; and the default-off rule keeps the wire unchanged for every existing deployment |
