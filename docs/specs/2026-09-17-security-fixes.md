# Stage 0: security fixes

**Status:** Approved for planning (2026-09-17), after four review passes
**Roadmap:** `docs/specs/2026-09-17-interop-roadmap.md`, stage 0.
**Depends on:** ADR 0008 (OAuth endpoint layout), ADR 0011 (consent scopes),
ADR 0014 (local delivery is in-process).

## Problem

Four holes are exploitable on any running instance. A fifth defect makes one of
the fixes impossible until it's corrected.

1. **Any member can overwrite or wipe any graph in another member's pod,
   including their ACL.** `POST /outbox` keeps the `object` of a `Create`,
   `Delete` or other activity exactly as the author sent it (`as_activity` in
   `server/src/outbox.rs`). `recipients` sends the activity to whichever member
   the object IRI names, and to the author's followers. Local delivery then acts
   on the *recipient's* pod with no authorization check:
   - A `Delete` whose object is `https://alice.<base>/~/.acl` reaches
     `processor::process` (`adapters/activitypub/src/processor.rs`).
     `inbox::remove` clears that graph from Alice's pod. With her root ACL gone,
     `effective_acl` finds nothing and Alice is locked out of her own storage.
   - A `Create` whose embedded object's `id` is that same IRI reaches
     `write_record` (`adapters/activitypub/src/inbox.rs`), which clears the
     graph and writes the attacker's content into it. The attacker can grant
     themselves `acl:Control` over Alice's pod. It reaches any member who follows
     the attacker.
2. **Anyone with Write on a container can take over its permissions.**
   `check` and `granted_modes` in `adapters/solid/src/ldp.rs` treat a `.acl`
   like any other document. A caller with inherited `acl:Write` can PUT, PATCH or
   DELETE the container's `.acl`, or create a new one on any child. A caller with
   inherited Read can read the ACL, which reveals who else has access. WAC
   requires `acl:Control` for all of these.
3. **ATProto OAuth sends authorization codes wherever it's asked.** PAR
   (`server/src/atproto_oauth.rs`) accepts any `client_id` that starts with
   `https://` (`is_valid_client_id`, `adapters/atproto/src/oauth.rs`), never
   fetches the client's metadata, and stores whatever `redirect_uri` the request
   names. Anyone who gets a member to approve the consent screen receives a token
   for that member's repo. It is also an open redirect.
4. **DPoP proofs can be replayed.** `identity/src/dpop.rs` parses `jti` and
   never checks it, so a captured proof works for `MAX_AGE_SECONDS` (60) either
   side of its `iat`.
5. **The server can't make HTTPS requests.** `reqwest` is declared with
   `default-features = false, features = ["json"]` in `server/Cargo.toml` and
   `adapters/atproto/Cargo.toml`, and no TLS backend is enabled for production.
   Every https fetch fails. That already means `BROLLY_PLC_SUBMIT` can never
   reach plc.directory, and hole 3's fix needs https to fetch client metadata.

## Goals

- An activity can only write or remove graphs its own actor owns.
- `.acl` resources are readable and writable only by someone holding
  `acl:Control` on the resource they govern.
- ATProto OAuth accepts a client only after fetching its metadata and checking
  it against the ATProto OAuth spec. The requested `redirect_uri` and scope must
  both be allowed by that metadata.
- Each DPoP proof can be used once. The type system enforces this, so a new call
  site can't forget.
- Outbound HTTPS works.

## Non-goals

- **DPoP nonces, protected-resource metadata, confidential clients
  (`private_key_jwt`) and scope checks on XRPC.** All are stage 2. Until then
  confidential clients are refused explicitly.
- **The `htu` check in `server/src/xrpc.rs`.** It compares against a hardcoded
  `https://{base}/xrpc/` and `POST`, which refuses too much, not too little, so
  it waits for stage 2.
- **Solid-OIDC client validation.** Solid's authorize handler already checks
  `redirect_uri` against the registered client (`server/src/solid_oidc.rs`).
  Client ID Documents are stage 6.
- **Any change to how WAC evaluates ordinary resources.**

## Design

### A1. An activity only touches graphs its actor owns

**The rule.** The *origin* of an IRI is its scheme, host and port. An activity's
own graph and the graph of any object embedded in it, together with every graph
it removes, index entry it forgets, or note pointer it records, must have the
same origin as the activity's `actor`. Writing containment and sort keys into
the recipient's inbox graph is the recipient's own bookkeeping and isn't covered
by the rule. For a local member that origin is
`https://<username>.<base>`, which is also where every note, activity and media
IRI they own lives. This is the same-origin rule ActivityPub servers apply to
inbound activities, and applying it to local delivery now means it's already in
place when federation arrives (ADR 0016).

The rule is enforced in two places, which between them cover every way an
activity reaches a pod:
- **`processor::process`** handles every *recipient's* copy, whether the
  activity came through local delivery or, later, from another server.
- **`outbox::deliver`** handles the *author's* own copy, which it writes with
  `inbox::deliver` directly, and every caller of `outbox::deliver`. That includes
  Mastodon compose (`server/src/mastodon_api.rs`), which doesn't go through
  `as_activity`.

**In `adapters/activitypub/src/processor.rs` and `inbox.rs`:**
- A pure `fn same_origin(a: &str, b: &str) -> bool`, which parses both with
  `url`. It is false if either doesn't parse.
- Before `process` writes anything into the recipient's pod, it rejects the
  activity with a new `ProcessError::ForeignObject` if:
  - `activity.id` isn't same-origin with `activity.actor`, or
  - an embedded object carries an `id` that isn't same-origin with
    `activity.actor`.

  A string `object`, meaning a reference, is still allowed to name someone
  else's IRI. A `Like` or `Follow` has to.
- **`Delete` removes only what delivery put there.** The target graph is
  removed only if both of these hold:
  - `same_origin(target, actor)`, and
  - the target is the **embedded object** of some member of this pod's
    **inbox or outbox** collection that is itself same-origin with the actor.
    The check reads each member with `read_activity` and requires `object` to be
    a JSON object whose `id` equals the target. It doesn't reuse
    `processor::object_id`, which treats a string reference and an embedded
    object the same. `Recipient::Member` gains the pod's outbox IRI so the check
    can read both collections.
    Merely being named by a member isn't enough, because a `Create` whose
    `object` is a plain string IRI names a graph that delivery never wrote. This
    check widens the existing sweep to both collections. The author's own copy of a `Create` is
    an outbox member (`server/src/outbox.rs` writes it with
    `webid::outbox`), while a recipient's copy is an inbox member, and a
    delete has to clear both.

  A legitimate delete always satisfies both: the note arrived embedded in its
  `Create`, which is a member on the author's origin, in the recipient's inbox or
  the author's outbox. Requiring membership
  of the note itself would break that, because a note's graph is written beside
  its activity and isn't a member. Origin alone isn't enough, though. The owner's
  own pod receives the owner's own activities, so a `Delete` of their own `.acl`
  sent through the outbox would pass an origin check and clear it without WAC
  ever seeing the request. Pod resources written through LDP are never the
  embedded object of a delivered activity, so a `Delete` can't reach them. The
  outbox rule below makes sure of that.
- `write_record` is only called with IRIs the checks above have allowed. It
  keeps its clear-and-replace behaviour for those.
- **The public index follows the same rule.**
  - `process_for_instance` calls `index::forget_note(target)` only if
    `same_origin(target, actor)`, so Bob can't make Alice's post disappear from
    the public timeline.
  - A **`Create`** is indexed only when its note is same-origin with the actor.
  - An **`Announce`** names someone else's note by definition, so it is indexed
    as today, with the announcer as actor. But `index::record_note` never adds
    a second author triple to a pointer that already exists; the author is fixed
    by whoever created the note. The existing test
    `an_announce_is_indexed_like_a_create`
    (`adapters/activitypub/tests/processor.rs`) keeps passing.
- **Foreign embedded objects are rejected now, not ignored.** Some servers embed
  the announced note inside an `Announce`. Whether to drop the embedded object
  and keep the activity is a federation question, decided when ADR 0016's switch
  is revisited.

**In `server/src/outbox.rs`:**
- **The server chooses embedded object ids.** On the author's origin,
  same-origin alone would let an author's `Create` carry an embedded object whose
  `id` is one of their own LDP resources, such as `/~/.acl`. `write_record` would
  then clear and replace it, and a later `Delete` could remove it, all without
  WAC.
  - **`Create` and wrapped bare objects:** `as_activity` overwrites any embedded
    object `id` the client supplied with a freshly minted `/~/notes/<ULID>`, the
    same id a bare object already gets.
  - **Every other type** (`Delete`, `Undo`, `Like`, `Follow`, `Announce`):
    `as_activity` turns an embedded object into its `id` string before
    anything is stored. A `Delete` of an embedded `Tombstone` or an `Undo` of an
    embedded `Follow` then means exactly what it says, because `object` names the
    existing thing, and `write_record` never runs on an id the client chose.
  - **`outbox::deliver` refuses**, with an error the HTTP handlers turn into
    `400`:
    - any activity whose `id` isn't under the author's `/~/activities/`
    - a `Create` whose embedded object `id` isn't under the author's `/~/notes/`
    - any other type that still carries an embedded object
  - Mastodon compose already mints ids in both places, and it also goes through
    `outbox::deliver`, so every publishing path is covered.
- `follows::record` and `record_request` still run first. They record the
  author's own follow and a pending request on the target, which is what a
  `Follow` is for. The rule constrains which graphs an activity names, not the
  follow bookkeeping.
- Delivery of an activity that `process` rejects is logged at `warn`. Delivery to
  other recipients carries on.

### A2. ACL resources require Control

**The rule.** A path is an *ACL resource* when it ends in `.acl`. The resource
it *governs* is the path with every trailing `.acl` removed:

| Path | Governs |
|---|---|
| `/~/notes/.acl` | `/~/notes/` |
| `/~/notes/first.acl` | `/~/notes/first` |
| `/~/x.acl.acl` | `/~/x` |
| `/~/notes` | not an ACL resource |
| `/~/x.aclx` | not an ACL resource |

For an ACL resource, **every** requested mode requires `acl:Control` on the
governed resource, whether that comes from the governed resource's own ACL or an
ancestor's `acl:default`.

**Where it goes:**
- `check` and `granted_modes` in `adapters/solid/src/ldp.rs`. Every LDP read,
  PUT, POST, PATCH (`may_write`) and DELETE passes through these two, including
  pod writes from other protocols made through `brolly_solid::ldp`, such as
  Mastodon media upload.
- A pure `pub fn governed(path: &str) -> Option<&str>`.
- `authz/src/wac.rs` doesn't change. `ldp.rs` just asks it about the governed
  resource.

**Other pod writes.** Every other direct pod write is owner-scoped and has no
path a non-owner can reach:
- Mastodon alt text (`server/src/mastodon_api.rs`)
- profile writes
- account export
- XRPC ingest (`at://` graphs)
- provisioning

Activity delivery was the exception, and A1 closes it.

**`WAC-Allow` on an ACL resource.** `granted_modes` reports all four modes if the
caller holds Control on the governed resource, and none otherwise.

**Containment.** ACL resources are auxiliary resources and are not contained by
their container (Solid Protocol §4.3).
- `put` and `append` stop calling `storage::add_containment` for ACL resources.
- So writing `/~/newdir/.acl` no longer creates `/~/newdir/` as a side effect.
  An ACL may exist for a resource that hasn't been created yet, and WAC applies
  it once that resource exists.
- Existing `ldp:contains` triples that point at `.acl` resources are removed by
  a `brolly-admin` command (see Rollout).

**Deleting a resource deletes its ACL.** Today a container that has an ACL
can't be deleted, because the ACL is one of its members. Once ACLs aren't
contained, a container can be deleted with its ACL still in place, and
recreating the container would silently bring the old grants back. So `delete`
also clears the `.acl` graph of the resource it deletes (Solid Protocol §5.4:
deleting a resource deletes its auxiliary resources). This applies to documents
and containers alike.

**Refusals** look the same as today: a caller without the required mode gets
`NotFound`, so existence isn't disclosed, and a write gets the existing refusal.

### B0. Outbound HTTPS

reqwest 0.13.4 has two TLS features, `rustls` and `rustls-no-provider`. Neither
has a ring or webpki-roots option: `rustls` pulls in aws-lc-rs, which would add
a C build, and both use `rustls-platform-verifier` for root certificates.

- **Features.** `server` and `adapters/atproto` add `rustls-no-provider` to
  reqwest. `server` also takes a direct `rustls = { version = "0.23",
  default-features = false, features = ["ring", "std"] }`. It resolves to the
  same rustls copy reqwest already uses. ring 0.17 is already in `Cargo.lock`.
- **Crypto provider.** With `rustls-no-provider`, building a reqwest client
  panics unless a provider is installed. server/src/tls.rs (new) has
  `install_crypto_provider()`, which calls
  `rustls::crypto::ring::default_provider().install_default()` and ignores
  "already installed", so calling it twice is harmless. It is called first thing
  in `main.rs`, in `server/src/bin/admin.rs`, and in the setup of every test that builds a
  reqwest client.
- **Roots.** The platform verifier reads the OS store, which the runtime image
  already populates with `ca-certificates` (`Dockerfile`).
- **`cargo deny check` must pass** with `rustls-platform-verifier` and its
  dependencies added to the lock.
- **Test.** Nothing may be `#[ignore]`d (plan §0), so the test runs a TLS
  handshake against a local `rustls` server whose certificate comes from a test
  CA. The client for it is built with `tls_certs_only([test CA])` inside a
  `#[cfg(test)]` unit test in server/src/tls.rs. A second test builds a
  `reqwest::Client` after `install_crypto_provider()` and checks it doesn't
  panic.
- **Its own commit.** It also fixes PLC submission, and the commit message says
  so.

### B. ATProto OAuth validates clients

#### Rules: adapters/atproto/src/client_metadata.rs (new)

Pure functions. Each rule quotes the ATProto OAuth specification
(atproto.com/specs/oauth).

**`parse_client_id(&str) -> Result<ClientId, ClientError>`**
- **Discoverable client:**
  - an `https` URL, well-formed
  - no port, no userinfo, no fragment
  - the host is a domain name, never an IP literal. hyper connects to IP
    literals without resolving them, so they would bypass `PublicOnly`. (The
    spec's sentence "IP addresses (`127.0.0.1`, etc) are not supported" is
    about the localhost `client_id`, so it isn't the authority for this rule.)
- **Loopback client:**
  - scheme `http`, host exactly `localhost`, no port, path `/`, no fragment
  - the query may carry `redirect_uri` (repeatable) and `scope`
  - every `redirect_uri` given must be an `http` URL whose host is exactly
    `127.0.0.1` or `[::1]`. Anything else is `InvalidClientId`. Without this
    check the loopback exception would reopen hole 3.

**`loopback_metadata(&ClientId) -> ClientMetadata`**
- `redirect_uris` come from the query, defaulting to `http://127.0.0.1/` and
  `http://[::1]/`
- `scope` from the query, defaulting to `atproto`
- `token_endpoint_auth_method: none`, `dpop_bound_access_tokens: true`,
  `application_type: native`

**`validate(&ClientId, content_type: &str, body: &[u8]) -> Result<ClientMetadata, ClientError>`**
requires:
- `content_type`'s media type is `application/json`
- the body is a JSON object
- `client_id` equals the fetch URL, as an exact string
- `dpop_bound_access_tokens` is `true`
- `grant_types` contains `authorization_code`, and `response_types` contains
  `code`
- `scope`, split on spaces, contains `atproto`
- `token_endpoint_auth_method` is absent or `none`. `private_key_jwt` gets
  `ConfidentialUnsupported`.
- `application_type` is absent (meaning `web`), `web` or `native`
- `redirect_uris` is non-empty, and every entry passes the rule for its type:
  - **`web`:** an `https` URL.
  - **`native`:** a custom scheme that "must match the `client_id` hostname in
    reverse-domain order" (`app.example.com` → `com.example.app:`), or an
    `https` URL with the same origin as the `client_id`.

  `http://127.0.0.1` and `http://[::1]` redirects belong only to loopback
  clients. The spec's native-client text also allows loopback redirects for
  native apps. brolly refuses them for now, a known and deliberate divergence
  that stage 2 revisits.

**`check_request(&ClientMetadata, redirect_uri: &str, scope: &str) -> Result<(), ClientError>`**
- **Redirect URI:** `redirect_uri` equals one of the metadata's `redirect_uris`
  exactly. For a loopback client, `127.0.0.1` and `[::1]` redirects instead
  match on scheme, host and path, with the port ignored ("path component matched
  but port numbers ignored").
- **Scope:** `scope` contains `atproto` ("Must include `atproto`"), and every
  requested scope is in the metadata's scope ("must be a subset").

`is_valid_client_id` is removed.

#### Looking up metadata: server/src/client_metadata.rs (new)

`AppState` gets one new field, `clients: Arc<dyn ClientLookup>`, where
`ClientLookup: Send + Sync` so it can live in axum state. `async fn`
in a trait can't be used through `dyn`, so the trait's one method returns a boxed
future:
`fn fetch<'a>(&'a self, url: &'a Url) -> Pin<Box<dyn Future<Output = Result<ClientMetadata, LookupError>> + Send + 'a>>`.
There are two implementations:

- **`Fetcher`:** what `main.rs` builds.
- **`StaticClients`:** a fixed map used by integration tests. It skips fetching,
  not validation: entries are built by passing a JSON body through `validate`,
  so a test can't register a client that production would refuse. Tests that
  need to count lookups wrap it in their own `ClientLookup`, so the production
  types carry no counters.

Loopback IDs never hit the network. PAR calls a free function,
`lookup_client(clients: &dyn ClientLookup, id: &ClientId)`, which sends loopback
IDs to `loopback_metadata` and only passes discoverable IDs to `fetch`. It's a
free function rather than a default trait method so no implementation can
override that branch. Every test file that builds `AppState` by hand (15 files
under `server/tests/`, plus `main.rs`) gets the new field. The plan does this as
a single mechanical step.

**`Fetcher`:**
- One `reqwest::Client`, built once:
  - `redirect(Policy::none())`
  - `.no_proxy()`, so an environment proxy can't do DNS resolution the filter
    below never sees
  - 5-second total timeout
  - `dns_resolver(PublicOnly)`
- **`PublicOnly` implements reqwest's `Resolve`.** It resolves the host with
  tokio's resolver, then drops every address that is loopback, private (RFC 1918
  / RFC 4193), link-local, unspecified, multicast, broadcast, CGNAT
  (100.64.0.0/10), documentation or benchmarking ranges, or an IPv4-mapped IPv6
  form of any of those. If no address survives, resolution fails.
  - Filtering at resolution, rather than checking the address first and then
    connecting, leaves no DNS-rebinding window.
  - IP-literal hosts never reach a resolver (hyper connects to them directly),
    which is why `parse_client_id` rejects them.
  - The code never calls `ClientBuilder::resolve` or `resolve_to_addrs`, because
    those overrides are applied on top of the custom resolver.
- **The request:**
  - only status `200` is accepted, anything else fails
  - `Content-Type` is passed to `validate`
  - the body is read with `Response::chunk` and fails once it passes 64 KiB
- **Cache:** `moka` (add `moka = { version = "0.12.16", features = ["future"] }`
  to `server`).
  - Successful lookups are kept 10 minutes; failures are kept 60 seconds, so a
    bad or slow client can't make every PAR fetch again.
  - At most 1,000 entries.
- **Layers.** `lookup_client` turns the `ClientId` into a URL and calls
  `fetch(&Url)`. The unit tests call `Fetcher::fetch` directly with a local
  `http://127.0.0.1:PORT` URL, which `parse_client_id` would rightly reject.
- **Test-only constructor.** `#[cfg(test)] Fetcher::for_tests(allow_loopback, allow_http, ok_ttl, err_ttl)`
  takes the cache lifetimes as arguments, so the negative-cache test uses
  milliseconds and doesn't sleep for a minute. It exists only in the `server`
  crate's own unit tests. Integration tests are a separate crate and can't see
  it; they use `StaticClients`.

**Errors.** `LookupError` separates `Invalid(ClientError)`, which is safe to
describe, from `Unreachable`. `Unreachable` covers DNS refusal, connection
failure, timeout, TLS failure, a non-200 status and an oversized body, and they
all get **one** description, so PAR can't be used to map which internal hosts
exist or answer.

#### PAR

In `server/src/atproto_oauth.rs::par`, in this order:
1. **DPoP proof**, as today, spent (C).
2. **The request's own checks, which cost nothing:** `redirect_uri` present,
   `response_type=code`, a PKCE challenge using S256. They now run *before* any
   fetch.
3. `parse_client_id`, then `state.clients.lookup`.
4. `check_request(meta, redirect_uri, scope)`. `scope` is `form.scope`, or
   `atproto` if it's absent.
5. Only then `push_request`.

**Failures** return JSON `400` and never redirect:
- `invalid_client` for a bad client ID, an unreachable client, or invalid
  metadata. The description names the rule that failed, or says "client metadata
  could not be retrieved" for `Unreachable`.
- `invalid_request` for a `redirect_uri` the client didn't declare.
- `invalid_scope` for a scope it didn't declare, or one without `atproto`.

`authorize` and `decide` already redirect only to the stored `redirect_uri`,
which is now validated. The token endpoint already requires `client_id` and
`redirect_uri` to match the grant.

#### Consent screen

Today `authorize` passes the full `client_id` URL to `consent::render_consent`
as the app name. It passes the `client_id`'s **host** instead, and
`localhost (development)` for loopback clients. The full `client_id` still
appears where the template shows it. The spec says not to show self-asserted
`client_name` or `logo_uri` for clients the operator hasn't vetted, and brolly
has no vetted list, so neither is fetched for display.

### C. DPoP proofs are single-use

#### Types: `identity/src/dpop.rs`

- **`Unspent<T>`** wraps a value that must not be used until its proof has been
  recorded. Its fields are private: `value: T`, `jkt`, `jti` and `iat`.
  - `spend(self, pool: &PgPool, now: i64) -> Result<T, DpopError>` records the
    `jti` and returns `value`.
  - `replace<U>(self, value: U) -> Unspent<U>` swaps the wrapped value for a new
    one, keeping the proof. It drops `T` without exposing it, which is what
    `verify_access` needs: it turns `Unspent<VerifiedProof>` into
    `Unspent<AccessClaims>`, and the claims come from the token, not the proof.
    There's no `map`, because a closure could copy `T` out.
  - `bound_to(&self, jkt: &str) -> bool` compares the proof's key to an expected
    thumbprint without revealing it.

  There is no other way to get `T` out.
- **`verify`** keeps its checks and signature, but returns
  `Unspent<VerifiedProof>`.
- **New errors: `DpopError::Replayed`, and `DpopError::Storage(String)`** for a
  database failure. `DpopError` derives `Clone` and `Eq`, so it keeps the
  message, not the `sqlx::Error`.
- **A storage failure fails closed.**
  - The Solid token endpoint answers `500` `server_error`.
  - The ATProto endpoints answer `400` `invalid_dpop_proof` and log the failure
    at `error`, because `proof_thumbprint` returns only `Option`.
  - Resource requests treat the caller as anonymous.
- **Existing unit tests in `identity/src/dpop.rs` that read `.thumbprint` from
  `verify`** are rewritten to use `bound_to` with a thumbprint they compute
  themselves.
- **A proof is spent as soon as it's verified, even if the request later fails**
  (for example a PAR refused for its client metadata). RFC 9449 counts a `jti`
  as used once it's presented. The doc comment on `spend` says so, so nobody
  "fixes" it later.

#### Storage

**Migration:** `migrations/<timestamp>_dpop_jti.sql`.

```sql
CREATE TABLE dpop_jti (
    jkt        TEXT        NOT NULL,
    jti        TEXT        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (jkt, jti)
);
CREATE INDEX dpop_jti_expires ON dpop_jti (expires_at);
```

**`spend`** runs a single statement, passing the **application's** clock, not
the database's, for both expiry and pruning. The application's clock is what
decides freshness (`MAX_AGE_SECONDS`), so pruning by the database's clock would
reopen replay if the two drift apart.

```sql
WITH pruned AS (DELETE FROM dpop_jti WHERE expires_at < to_timestamp($4))
INSERT INTO dpop_jti (jkt, jti, expires_at)
VALUES ($1, $2, to_timestamp($3))
ON CONFLICT DO NOTHING
RETURNING jti
```

- **Parameters:** `$3 = iat + MAX_AGE_SECONDS`, `$4 = now - MAX_AGE_SECONDS`.
- **No row returned** means `Replayed`.
- **Why `(jkt, jti)`:** keying on the pair means one client's choice of `jti`
  can't cause another client's proofs to be refused.

#### Call sites

- **`server/src/solid_oidc.rs` token endpoint:** spends, then uses the
  thumbprint.
- **`server/src/atproto_oauth.rs::proof_thumbprint`** (PAR and token): becomes
  `async` and spends.
- **`server/src/xrpc.rs::token_caller`:** spends.
- **`adapters/solid/src/oidc/tokens.rs::verify_access`** stays synchronous. It
  returns an enum:
  - `Access::Bearer(AccessClaims)` for a token without `cnf.jkt`, which is
    unchanged behaviour
  - `Access::Bound(Unspent<AccessClaims>)`

  The holder check moves to `bound_to`, so `WrongHolder` is still decided in
  `verify_access`, and its unit tests stay synchronous and database-free.
  `server/src/pod.rs::subject_for` spends a `Bound` before building the
  `Subject`. `subject_for` is also the entry point for the ActivityPub inbox GET
  (`server/src/activitypub.rs`), so that path is covered too.

**Replay refusals:**
- token endpoints: `invalid_dpop_proof` (400)
- resource requests: the same response as any other invalid proof

## Testing

All of this runs under the existing testcontainers harness.

**A1: `server/tests/federation_flows.rs`**
- **`Delete`:** Mallory sends one whose `object` is Alice's `/~/.acl`. Alice's
  ACL is unchanged, and she can still read her storage root.
- **`Create`:** Mallory, whom Alice follows, sends one whose embedded object `id`
  is Alice's `/~/.acl`. Over HTTP the outbox replaces that id with a minted
  note id, so the post is accepted and Alice's ACL is untouched. Calling
  `outbox::deliver` directly with the foreign id is refused. Delivering it
  straight to `processor::process` returns `ForeignObject` and leaves the graph
  untouched.
- **References still work:** a `Like` and a `Follow` whose `object` names another
  member still arrive.
- **Legitimate deletes still work:** a `Delete` of Mallory's own note removes it
  from Alice's inbox, from Mallory's **own** pod (her outbox copy), and from the
  public index.
- **Boosts still work:** `an_announce_is_indexed_like_a_create` passes, and an
  `Announce` of an already-indexed note leaves exactly one author triple.
- **The owner can't skip WAC:**
  - a `Delete` Alice sends through her own outbox naming her own `/~/.acl`
    leaves it in place
  - so does a `Create` whose `object` is the string `/~/.acl`, followed by a
    `Delete` of it
  - a `Create` whose embedded object claims `id` `/~/.acl` gets a minted note
    id instead, and her ACL is untouched
  - `outbox::deliver` called directly with an embedded id outside `/~/notes/`
    is refused
- **Delete and Undo keep working:** a `Delete` whose object is an embedded
  `Tombstone` for Alice's note removes the note everywhere, and an `Undo`
  embedding a `Follow` reaches its target with `object` as a string.
- **The index is protected:** a public `Delete` from Mallory naming Alice's note
  leaves it on the public timeline, and an `Announce` from Mallory naming it
  doesn't add a second author.
- **Every publishing path is covered:** Mastodon compose and the ActivityPub
  outbox both refuse a foreign embedded object id when writing the author's
  copy.
- **Unit tests for `same_origin`:** differing ports, schemes and hosts, and
  unparseable IRIs.

**A2**
- **Adapter level, adapters/solid/tests/acl_control.rs (new):** `bob` holds
  Read and Write as `acl:default` on `/~/shared/`, but not Control.
  - `bob` can't `read`, `put` or `delete` `/~/shared/.acl`; `may_write` is false
    for it.
  - `bob` can't `put` `/~/shared/doc.acl`, and can't `read` `/~/shared/doc.acl.acl`.
  - `bob` can still read and write `/~/shared/doc`.
  - The owner can do all of the above.
  - `LdpOutcome.granted` for `/~/shared/.acl` is empty for `bob` and has all four
    modes for the owner.
  - After `put` or `append` of an ACL, the container's listing doesn't contain
    it, and putting `/~/newdir/.acl` doesn't create `/~/newdir/`.
  - Deleting `/~/shared/doc` clears `/~/shared/doc.acl`. Deleting and then
    recreating `/~/shared/` doesn't bring its old grants back.
- **HTTP level, `server/tests/pod_http.rs`:** PATCH of `/~/shared/.acl` by `bob`
  is refused, and the `WAC-Allow` header on it is empty for `bob`.
- **Unit test for `governed`:** covers the table above.

**B0.** The local TLS handshake test described under B0.

**B**
- **`client_metadata.rs` unit tests:** a passing and a failing case for every
  rule, including:
  - `client_id` values with a port, userinfo, a fragment, or an IP host
  - a loopback `redirect_uri` query pointing at an external host
  - a `client_id` mismatch
  - the wrong `Content-Type`
  - missing `dpop_bound_access_tokens`
  - `private_key_jwt`
  - a web client with an `http` redirect
  - a native client with a scheme that doesn't match
  - a loopback redirect on a different port (accepted) and a different path
    (refused)
  - a requested scope that lacks `atproto`
  - a scope escalation
- **server/src/client_metadata.rs unit tests,** using `Fetcher::for_tests`
  against a local http server:
  - a `302` fails
  - a `201` fails
  - a body over 64 KiB fails
  - a slow server hits the timeout
  - `text/html` fails
  - a valid body is cached
  - a failure is cached for its lifetime (a few milliseconds in the test) and
    then retried
- **`PublicOnly` unit tests:** every refused range, and a public address
  allowed.
- **`server/tests/atproto_oauth.rs`:** `AppState` uses `StaticClients` holding the existing
  `https://app.example/client-metadata.json` client, built through `validate`.
  - The existing end-to-end tests keep passing.
  - **Refusals:**
    - an unknown client gets `invalid_client`
    - an undeclared `redirect_uri` gets `invalid_request`
    - a scope without `atproto` gets `invalid_scope`
    - a loopback `client_id` naming an external redirect gets `invalid_client`
  - **Ordering:** a PAR missing PKCE is refused before any lookup, which a
    counting wrapper around `StaticClients` confirms.
  - **Consent page:** shows `app.example`.

**C**
- **Doctests on `Unspent`:** a `compile_fail` doctest shows `T` can't be reached
  without `spend`. A passing doctest shows it can with `spend`, so the failing
  one is known to fail for that reason and not a typo.
- **Proof replayed twice, refused the second time:**
  - at the Solid token endpoint
  - at ATProto PAR
  - on a Solid resource GET
  - on an XRPC write. There are no DPoP XRPC tests yet, so this one builds the
    full token flow and signs the hardcoded `htu` that stage 2 will fix.
- **Isolation:** two different keys can each use the same `jti`.
- **Pruning:** a row older than the window is removed by the next spend, using
  the application clock passed in.

## Rollout

Six commits on `main`, in this order, each deployable with its tests:

1. **A1** (activity origin) is first because it is the worst hole.
2. **A2** (ACL Control), plus `brolly-admin acl-uncontain`, an idempotent
   command that removes `ldp:contains` triples pointing at `.acl` resources.
   Operators run it once after deploying, with the server stopped, because
   Oxigraph opens each store exclusively. It's a command rather than a startup
   task because it opens every pod, which would slow startup and churn the store
   cache on large instances.
3. **C**, with the migration.
4. **B0** (HTTPS).
5. **`ClientLookup` threaded through `AppState` and every test**, with no
   behaviour change yet.
6. **B.**

**No gates.** These close holes, and a fix gated off leaves the hole open.

**Effect on existing sessions:**
- Nothing is invalidated by A1, A2, B0 or C.
- B refuses new PARs from clients whose metadata doesn't validate. Tokens already
  issued stay valid until they expire. Stage 2 brings token lifetimes within the
  spec's limits.

## Decisions

| # | Decision | Why |
|---|---|---|
| S1 | Check activity origin in the inbox processor, not only the outbox. | The inbox is where every activity enters, local or remote. Checking only in the outbox would leave the hole open the day federation is switched on. |
| S2 | Enforce ACL protection in `ldp.rs`, not `wac.rs`. | `wac.rs` answers questions about a resource. Which resource to ask about is a path rule, and every LDP operation already goes through `check`. |
| S3 | Filter addresses in the DNS resolver, reject IP-literal client IDs, and turn off proxies. | Checking before the request leaves a rebinding window. IP literals and proxies bypass the resolver, so each bypass is closed where it happens. |
| S4 | Keep one error description for every kind of unreachable client. | Otherwise PAR tells an unauthenticated caller which internal hosts exist and answer. |
| S5 | Show the client's host as the app name. | brolly has no list of vetted clients, and the spec says not to display a client's self-asserted name without one. |
| S6 | Refuse confidential clients until stage 2. | Accepting `private_key_jwt` without verifying the client assertion would be worse than refusing it. |
| S7 | Make `jti` single use through `Unspent<T>`, stored in Postgres, keyed by `(jkt, jti)`, pruned by the application clock. | The type makes skipping it a compile error. Postgres makes it hold across processes and restarts. The key keeps clients independent. The application clock is the one that decides freshness. |
| S8 | Use a static client list in integration tests rather than a TLS test server. | It still goes through validation, so it can't hold a client production would refuse, and the fetch path gets its own unit tests. |
