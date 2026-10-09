# Stage 2: ATProto auth

<!-- doc-paths: skip -->
<!-- The spec names files and tables this stage creates, so not every path it
     cites resolves until it's implemented. -->

**Status:** Draft, 2026-10-09, five chunks. Drafted 2026-10-09 and revised the
same day after one adversarial review against the ATProtocol OAuth and HTTP API
(XRPC) specifications (atproto.com, as of this date), the `com.atproto.server`
lexicons (`createSession`, `getSession`, `refreshSession`, `deleteSession`,
`createAppPassword`, `listAppPasswords`, `revokeAppPassword`, `getServiceAuth`)
from the reference `bluesky-social/atproto` repository as of this date, RFC 9449
(DPoP), `draft-ietf-oauth-resource-metadata`, the reference PDS's
`auth-verifier.ts`, and `@atproto/oauth-scopes`' `ScopeMissingError`. The
review corrected the scope-failure answer (403 `ScopeMissingError`, the
reference's own wire name — not a 401, and not an invented name), the nonce
window (the profile's 5-minute cap bounds how long a value is *served*;
accepting the previous bucket is its separate "recently-stale" allowance —
the first draft conflated the two and claimed the ±60 s `iat` bound keeps
acceptance inside 5 minutes, which the worst case disproves), the
session-lifetime reading (the profile
caps "overall session lifetime **and** individual refresh tokens" for public
clients — rotation alone would make sessions unlimited, so a copied-forward
anchor is required), the CORS half of the nonce work (`www-authenticate` is
already exposed (`server/src/lib.rs:259-260`); `dpop-nonce` is not — a browser
client that cannot read the header must reject every response per the profile),
and `createSession`'s `allowTakendown` (ignoring it is the safe direction: the
flag only *widens* access for taken-down accounts, and brolly has no
reactivation endpoint for a narrow token to call).
**Roadmap:** `docs/specs/2026-09-17-interop-roadmap.md`, stage 2. Finish-line
item 1 stops at "logs in" without this stage; item 3's "third-party app that
uses OAuth with DPoP logs in and writes its own lexicon's records" is this
stage's OAuth half end to end. Stage 3's `atproto-proxy` forwarding presents
the `getServiceAuth` tokens this stage starts minting, and its surface rides
the caller this stage reworks.
**Depends on:** stage 0
(`docs/specs/2026-09-17-security-fixes.md` — S6 assigns confidential clients
here, S7's `dpop_jti` store is the pattern two more single-use stores copy,
S4/S5 are the display rules the session endpoints inherit), stage 1
(`docs/specs/2026-10-06-atproto-repo-firehose.md` — the XRPC write endpoints
whose auth this stage reworks, and the repo signing key it loads),
ADR 0008 (auth surfaces keep separate tables), ADR 0011 (the consent screen's
one vocabulary).

## Problem

The roadmap's survey named the auth gaps
(`docs/specs/2026-09-17-interop-roadmap.md:24-27`); stage 0 closed the
exploitable ones and explicitly deferred the rest here
(`docs/specs/2026-09-17-security-fixes.md:63-68`). Against the current tree:

1. **bsky.app cannot log in.** No `com.atproto.server.*` session endpoint
   exists: the route table (`server/src/xrpc.rs:1561-1582`) serves
   `describeServer` and the repo/sync methods, and every other NSID answers
   501 at the wildcard (`xrpc.rs:1552-1557`). There is no app-password table,
   no creation endpoint, nothing to enter. Finish-line item 1 is blocked at
   its first word.
2. **The XRPC token check verifies a proof against a request no client
   made.** `token_caller` checks the DPoP proof against
   `https://{base}/xrpc/` and `POST` — hardcoded, not this request's method
   and URI (`server/src/xrpc.rs:128-129`). A real client signs the method and
   URL it is *calling* (RFC 9449 `htm`/`htu`), which never equals the
   fabricated pair, so every genuine OAuth client fails authentication on
   every XRPC call. Stage 0 knew and deferred it: it "refuses too much, not
   too little" (`docs/specs/2026-09-17-security-fixes.md:66-68`).
3. **The proof is spent after the grant is read — by convention.**
   `token_caller` resolves the token — learning the `user_id` — before it
   looks at the proof (`xrpc.rs:120-146`), and only then spends it. The
   `Unspent` type forces spend-before-read *within* a proof, not *around* one;
   `identity/src/dpop.rs:31-35` flags exactly this as a stage 2 follow-up.
4. **DPoP nonces — mandatory in the atproto profile — do not exist.** The
   proof `Claims` have no `nonce` field (`identity/src/dpop.rs:120-127`); the
   PAR 201 (`server/src/atproto_oauth.rs:291-295`) and the token 200
   (`atproto_oauth.rs:559-578`) carry no `DPoP-Nonce` header; no call site
   could check one. "Server-provided DPoP nonces are mandatory"
   (`atproto.com/specs/oauth`, DPoP section).
5. **Protected-resource metadata is missing.** There is no
   `/.well-known/oauth-protected-resource` route
   (`atproto_oauth.rs:704-710`), so a client starting from a hostname — the
   profile's second login path — cannot discover the authorization server,
   and a 401 has no `resource_metadata` to point at.
6. **The authorization-server metadata is missing required fields and
   advertises an incomplete auth surface.** `metadata`
   (`atproto_oauth.rs:167-181`) lacks `authorization_response_iss_parameter_supported`
   (required `true` — and the redirect already carries `iss`,
   `atproto_oauth.rs:513-515`, so the field declares existing behaviour) and
   `token_endpoint_auth_signing_alg_values_supported` (required, must include
   `ES256`, must not include `none`). `token_endpoint_auth_methods_supported`
   is `["none"]` because confidential clients are refused
   (`adapters/atproto/src/client_metadata.rs:95-97`) — a refusal stage 0
   assigned to this stage (S6).
7. **Token lifetimes exceed the profile.** `ACCESS_TTL_SECONDS` is 3600
   (`adapters/atproto/src/oauth.rs:25`) where the profile says "less than 30
   minutes in all situations"; `REFRESH_TTL_SECONDS` is 90 days
   (`oauth.rs:26`) where public clients — brolly's only kind today — are
   capped at 2 weeks. And because refresh tokens rotate
   (`oauth.rs:223-233`) with no memory of when the session began, every
   session is unlimited, which the profile permits only for confidential
   clients.
8. **No scope is ever checked on XRPC.** `Grant.scope`
   (`adapters/atproto/src/oauth.rs:163-169`) travels nowhere past
   `verify_token`; a token granted `atproto` alone — the profile's
   authentication-only case — can write records today. PAR checks the request
   against the *client's* declared scope
   (`client_metadata.rs:476-484`) but never against what the *server*
   supports: `scopes_supported` (`atproto_oauth.rs:179`) is not enforced
   anywhere.
9. **`getServiceAuth` has no endpoint.** The signing machinery exists and is
   tested — ES256K, `lxm`-bound, 60-second tokens
   (`adapters/atproto/src/service_auth.rs`), the repo key it signs with
   (`adapters/atproto/src/keys.rs:17`, `user_keys`' `atproto_signing` slot) —
   and nothing serves it. Stage 3's `atproto-proxy` forwards with exactly
   these tokens.
10. **The authorization request's bindings go unchecked.** `login_hint` is
    stored with the pushed request (`adapters/atproto/src/oauth.rs:37`) and
    never compared at the decision (`server/src/atproto_oauth.rs:421-520`):
    whichever member happens to be logged in consents, and the client
    discovers the mismatch only when `sub` is not the account it bound. And
    `code_challenge` reuse across sessions is never prevented — a "must" in
    the profile's PKCE section.

## Goals

- **bsky.app logs in.** `createSession` accepts a handle, a DID, or an email
  with the primary password or an app password; `getSession`,
  `refreshSession`, `deleteSession` behave as their lexicons define; app
  passwords are created, listed and revoked, with the privilege reduction the
  HTTP API spec describes.
- **A proof verifies against the request it arrived on.** Real `htm`/`htu`
  from the actual request, a real nonce, and the proof spent before anything
  is learned from the token.
- **The profile's discovery is complete.** Protected-resource metadata, the
  missing authorization-server fields, and nonce headers a browser client can
  read.
- **Lifetimes within the profile.** Short access tokens, capped refresh
  tokens, and an anchored session for public clients; confidential clients
  supported, with their longer refresh lifetime and key-bound sessions.
- **Every authenticated XRPC method checks what the credential grants** —
  scope for OAuth tokens, privilege for legacy sessions — with the reference's
  own failure shape.
- **`getServiceAuth` serves stage 3:** `aud`/`lxm`/`exp`, signed by the
  member's repo key, the exact JWT `service_auth.rs` already builds.

## Non-goals

- **Stage 3's surface** — `atproto-proxy` forwarding, `getPreferences`,
  `identity.resolveHandle`, `/.well-known/atproto-did`, `sync.listRepos`,
  `requestCrawl` (`docs/specs/2026-09-17-interop-roadmap.md`, stage 3 row).
  This stage mints the service-auth tokens; that stage spends them.
- **`transition:chat.bsky` and `transition:email`.** There is no chat surface
  and no mail path here. PAR refuses both (they are not in
  `scopes_supported`); the consent vocabulary keeps its rows
  (`identity/src/consent.rs:88-91`) for the day they exist. `getSession`
  reports `emailConfirmed` from what is stored, for sessions allowed to see
  the email at all (roadmap, "Not in scope").
- **Account management over XRPC.** The app-password endpoints are as far as
  it goes — no `changeHandle`, no email change, no account deletion over
  XRPC; the dashboard owns those. `createSession`'s `allowTakendown` is
  accepted and ignored, which is the safe direction: the flag only *widens*
  access for taken-down accounts, and there is no reactivation endpoint for a
  narrow token to call.
- **The dashboard's session management UI.** The OAuth spec's "view active
  OAuth sessions and delete them" interface is a follow-up for the dashboard
  spec; this stage wires the revocation (`change_password` revokes ATProto
  tokens — it currently revokes browser sessions only, and
  `oauth::revoke_all_for_user` (`adapters/atproto/src/oauth.rs:235-244`) has
  no caller at all), it does not render it.
- **Entryway separation.** brolly is both authorization server and resource
  server; the profile explicitly allows one nonce stream for that case.
- **2FA.** `authFactorToken` is accepted and ignored; `emailAuthFactor` is
  never emitted. There is no mail path.
- **`didDoc` in session responses.** Optional in every session lexicon; no
  known client needs it; the DID document is stage 3's `describeRepo` to
  answer.
- **Token introspection or revocation endpoints** (RFC 7662/7009). Not in the
  atproto profile.

## Design

### A. Legacy sessions are opaque token pairs in their own table

The lexicon names the tokens `accessJwt`/`refreshJwt`; the HTTP API spec says
clients "should treat the tokens as opaque string tokens" and that JWT shape
"is not a stable part of the specification". So they are opaque secrets here
— 32 random bytes, hex, stored SHA-256-hashed (`hash_secret`,
`identity/src/db.rs:89-99`) like every other credential in the tree — in a
new `atproto_legacy_tokens` table: `token_hash` PK, `kind` (`access` /
`refresh`), `user_id`, `app_password_id` (nullable — the provenance that
carries privilege, B), `session_id` (UUID — the pair and every rotation of it
share one id), `expires_at`, `revoked_at`, `created_at`. Its own table,
because `atproto_tokens` is `dpop_jkt NOT NULL` and `client_id NOT NULL`
(`migrations/20260826000003_atproto_oauth.sql:46-56`) — two NOT NULLs a
legacy token can never fill, and ADR 0008's rule is that surfaces which
disagree get separate tables, not mostly-null columns.

The domain separation the spec asks for — `typ: at+jwt` vs `refresh+jwt` — is
a JWT-implementation concern; brolly's equivalent is the `kind` column *inside
the lookup*, the same way `verify_token` does it
(`adapters/atproto/src/oauth.rs:202-220`): a refresh token presented as an
access token fails the query, not a check after it.

- **`createSession`** resolves `identifier` in every form brolly can name:
  handle (`username.{base}`), `did:plc` (stored), `did:web:{username}.{base}`
  (derived), or email — DID forms first, then handle, then email, for the
  same suffix reason `resolve_repo` orders DID first
  (`server/src/xrpc.rs:169-170`: a `did:web` handle ends in the base domain
  too, so a handle check run first would claim it). The password check runs
  the app-password table first
  (an indexed SHA-256 lookup, `atproto_app_passwords`), then Argon2 against
  `users.password_hash` (`identity/src/db.rs:162-180`) — and a missing user
  still runs one Argon2 verify, the timing pattern `authenticate` already
  established. Bad credentials answer 401 `AuthenticationRequired`; a
  disabled account answers 401 `AccountTakedown`, the lexicon's own error —
  brolly's `disabled` maps to the spec's `takendown`, the moderation reading
  of the two. Success returns `accessJwt`, `refreshJwt`, `handle`, `did`,
  `active: true`, and `email`/`emailConfirmed` only for sessions allowed to
  see the email (B). `status` is omitted: a disabled member's credentials
  stop resolving on their next request — the moderation stance every other
  surface already takes.
- **`getSession`** answers from the same fields, for the bearer *access*
  token.
- **`refreshSession`** authenticates with the *refresh* token, rotates the
  pair (revoke the old rows, issue a new pair under the same `session_id`),
  and answers the `createSession` shape. Unknown/revoked token → 401
  `InvalidToken`; expired → 401 `ExpiredToken` — both names are the
  lexicon's.
- **`deleteSession`** authenticates with the refresh token and revokes every
  row sharing its `session_id` — the access token dies with the session, not
  at expiry.

Legacy TTLs: access matches the OAuth one (900 s, G); refresh is 2 weeks,
rolling — a new pair on every refresh, so a bsky.app that stays signed in
stays signed in, and an idle one re-enters its password after a fortnight.

### B. App passwords: created once, shown once, revoked by row

A new `atproto_app_passwords` table: `id` UUID PK, `user_id`, `name`,
`password_hash`, `privileged BOOLEAN NOT NULL DEFAULT false`, `created_at`,
`UNIQUE (user_id, name)`. The password is 16 characters from `[a-z0-9]` in
four dash-separated groups — `xxxx-xxxx-xxxx-xxxx`, the HTTP API spec's own
format, ~82 bits, hashed with SHA-256 like the other high-entropy secrets
(Argon2 is for human-chosen strings; this is not one). The hash carries a
UNIQUE index — 82 random bits make a collision a formality — because it is
the lookup `createSession`'s first check reads (A).

- `createAppPassword` (`name`, optional `privileged`) answers the full
  `appPassword` object — the plaintext password appears exactly once, here.
- `listAppPasswords` answers without the password; the lexicon's list schema
  omits it.
- `revokeAppPassword` deletes the row. Revocation is *immediate*: the
  session rows carry `app_password_id ON DELETE CASCADE`, so the sessions die
  with the row. (The reference's app-password sessions are self-asserting
  JWTs, so its revocation waits for refresh — opaque rows do not have that
  gap.)

**Privilege** follows the HTTP API spec's sentence: app passwords "grant
slightly restricted permissions… preventing destructive actions like account
or changes to authentication settings (including app passwords themselves)".
The rule reads `app_password_id` off the session: a session with
`app_password_id IS NULL` (primary password) may manage app passwords and
sees `email`/`emailConfirmed`; an app-password session may not manage app
passwords (403) and sees the email fields only if its app password is
`privileged`. OAuth tokens may not manage app passwords at all — the
profile's `transition:generic` explicitly excludes "account management
actions".

### C. DPoP nonces: HMAC time buckets from an instance secret

RFC 9449's nonce is a value the server hands out and later demands; the
atproto profile makes it mandatory, caps rotation at 5 minutes, and asks
servers to "accept recently-stale (old) nonces to make rotation smoother for
clients with multiple concurrent requests in-flight".

**The nonce is `base64url(HMAC-SHA256(secret, bucket))` with `bucket =
unix_seconds / 300`.** The current bucket's value is the nonce handed out;
proofs carrying the current *or previous* bucket's value verify. Rotation is
automatic at each bucket boundary — no value is *served* for more than 5
minutes, the profile's rotation cap — and accepting the previous bucket's
value is its separate "recently-stale" allowance: a proof minted at second
299 with bucket *N*'s nonce stays verifiable through second 599, so every
in-flight request survives the boundary. The two windows are not the same
one, and the review made this spec stop claiming they were: the worst case
is a client that received a nonce in the first second of bucket *N* and
returns at the end of bucket *N+1* — a nonce ~10 minutes from first serving,
one generation stale, exactly the shape "should accept recently-stale (old)
nonces" exists to permit. The existing ±60 s `iat` window
(`identity/src/dpop.rs:49`, `:373-375`) bounds the *proof*, not its nonce:
two independent checks, both of which must pass.

**The secret is one row, generated on first start.** A new
`dpop_nonce_secrets` table (single row, `CHECK (id = 1)`), loaded once at
startup into `AppState` through the `load_or_create` pattern the instance
actor already established (`identity/src/instance.rs:44-54`: insert with `ON
CONFLICT DO NOTHING`, read back, so two processes starting together converge
on one secret). No database read on the hot path, and a second server process
verifies the same nonces — the any-process stance stage 1 (G) set for events,
applied to auth.

`dpop::verify` gains a nonce parameter: `None` means this protocol does not
use them (Solid-OIDC today — unchanged), `Some(accepted)` means required, and
a missing or non-matching `nonce` claim is a new `DpopError` variant. `Claims`
gains the field (`identity/src/dpop.rs:120-127`). Nonces are a DPoP concern,
not an atproto one — that is why the check lives in `dpop.rs` and the secret
is not named "atproto".

**Issued and demanded where RFC 9449 puts them:**

- PAR 201 and token 200 carry `DPoP-Nonce` (the profile: "The server returns
  a `request_uri` token to the client, including a DPoP nonce via HTTP
  header").
- A proof without a valid nonce at PAR or token → 400
  `{error: "use_dpop_nonce"}` plus a fresh `DPoP-Nonce` — the AS-side shape
  the reference's `UseDpopNonceError` builds.
- On XRPC → 401 with `WWW-Authenticate: DPoP error="use_dpop_nonce",
  error_description="…"` plus the header — the RS-side shape
  (`toWwwAuthenticateError()`).
- The CORS expose list gains `dpop-nonce` (`server/src/lib.rs:259-260`).
  `www-authenticate` is already there; a browser client that cannot read the
  nonce header "must reject responses missing a `DPoP-Nonce` header" per the
  profile — unreadable is missing, so without the expose the whole mechanism
  breaks exactly one class of client: the browser one.

brolly is both AS and RS, so one nonce stream serves both — the profile
explicitly allows this.

### D. The caller is the request

`token_caller` (`server/src/xrpc.rs:109-153`) is rebuilt, in this order:

1. **The proof first.** Verify and spend the DPoP proof *before* the token
   grant is read — the proof is verified against the presented token
   *string* (the `ath` claim), which the `Authorization` header already
   carries, so nothing needs the grant first. An unknown token still spends
   its proof: fail-closed, the rule PAR already states
   (`server/src/atproto_oauth.rs:72-75`). This closes the ordering hole
   `identity/src/dpop.rs:31-35` flagged — the spend is no longer by
   convention.
2. **The real `htm`/`htu`.** The handlers pass their method and path in (the
   write handlers are `POST`s; `getServiceAuth` is a `GET` — the bug's
   sharpest case, since the hardcoded `POST` at `xrpc.rs:129` could never
   have matched it). The URL is `https://{base}{path}`; `htu_matches`
   (`identity/src/dpop.rs:397-402`) already strips query and fragment per
   RFC 9449.
3. **The nonce** (C). Then the grant: `verify_token`, `bound_to(jkt)`,
   `is_active`.
4. **The bearer arm.** A `Bearer` credential resolves against
   `atproto_legacy_tokens` (kind `access`) — the atproto profile's other
   half, on the same caller. The cookie fallback stays last, for the browser
   dashboard and the tests, as today (`xrpc.rs:97-107`).

**The 401 shape.** Every 401 from an auth-requiring XRPC method carries
`WWW-Authenticate` (the XRPC spec: "There should be a `WWW-Authenticate`
header"), in the two shapes the underlying specs define: a missing
credential gets the draft's own challenge — `WWW-Authenticate: Bearer
resource_metadata="https://{base}/.well-known/oauth-protected-resource"`
(`draft-ietf-oauth-resource-metadata` §3.1, which is how a client starting
from a hostname finds the AS); a presented-but-refused DPoP credential gets
RFC 9449's — `WWW-Authenticate: DPoP error="use_dpop_nonce"` (or
`invalid_dpop_proof`), `error_description`, and the fresh `DPoP-Nonce` (C).
The two headers can coexist (RFC 7235 allows one challenge per scheme). The
XRPC *body* stays coarse —
`AuthenticationRequired` (`xrpc.rs:46-52`) — rather than copying the
reference, which puts the OAuth error name in the body: RFC 9449 puts the
machine-readable detail in the header, and one body name keeps the surface
learnable. Authenticated responses carry `Cache-Control: private` and
`Vary: Authorization`, so no shared cache hands one member's authorized
response to another.

**The scope gate.** `caller` returns the credential's grants — the scope
set, and for legacy sessions the privilege (B) — and each authenticated
method asserts what it needs:

| Method class | OAuth | Legacy session |
|---|---|---|
| repo writes, `getServiceAuth` | `transition:generic` | any (primary or app password) |
| `getSession` | `atproto` | any (email fields per privilege, B) |
| `refreshSession`, `deleteSession` | — (OAuth refreshes at `/oauth/atproto/token`) | the refresh token |
| `createAppPassword`, `listAppPasswords`, `revokeAppPassword` | refused | primary password only |

A scope failure answers **403 with `error: "ScopeMissingError"` and
`Missing required scope "transition:generic"`** — the reference's own wire
shape: `@atproto/oauth-scopes` throws `ScopeMissingError` (403, exposed,
that exact message) and the XRPC layer maps an exposed error's name through.
Not a 401 — the credential is authenticated; it is the *grant* that is
missing.

**`getServiceAuth`** (here rather than in a section of its own: it is one
route over the caller this section rebuilds): a
`GET`, params `aud` (required — a DID, optionally `did#serviceId`, validated
with atrium's `Did` type the way stage 1 validated NSIDs), `lxm` (optional,
NSID), `exp` (optional integer; the default is 60 s out, the token lifetime
`service_auth.rs` already fixes). An `exp` in the past or further than 5
minutes out answers `BadExpiration`, the lexicon's own error —
`service_auth.rs::issue` gains the `exp` parameter. The token is signed with
the member's `atproto_signing` key (`user_keys`, loaded the way stage 1's
write path loads it), `iss` is the member's DID, and the output is exactly
the `{"token": …}` the lexicon defines. A service-auth JWT presented *back*
to brolly as a bearer token matches no hash — opaque tokens cannot be
confused with JWTs by construction, which is the concern the reference's
`lxm`-in-a-bearer check (`auth-verifier.ts`) exists to answer.

### E. Discovery completed

- **`/.well-known/oauth-protected-resource`** (base domain only, behind the
  same `wrong_host` check every OAuth endpoint has): `{"resource":
  "https://{base}", "authorization_servers": ["https://{base}"]}` — a single
  origin URL, no path, per the draft's requirements.
- **The authorization-server metadata gains** `authorization_response_iss_parameter_supported:
  true` (declaring the `iss` the redirect already emits,
  `atproto_oauth.rs:513-515`) and `token_endpoint_auth_signing_alg_values_supported:
  ["ES256"]`; with F, `token_endpoint_auth_methods_supported` becomes
  `["none", "private_key_jwt"]`. `require_request_uri_registration` stays
  implicit — the profile's default is `true` and "does not need to be set
  explicitly"; omitting is compliance, adding is decoration.
- **PAR checks the requested scope against the server too**: requested ⊆
  client-declared (today, `client_metadata.rs:476-484`) *and* ⊆
  `scopes_supported` (`atproto` + `transition:generic`). A scope the server
  does not grant is refused `invalid_scope` at push time, not echoed in a
  token response.
- **CORS is already whole-server** (`server/src/lib.rs:229-291`, outermost
  layer, origin echoed, `dpop` in the allow list) — the AS-side requirement
  the profile makes for browser apps is met by posture, needing only C's
  `dpop-nonce` expose.

### F. Confidential clients

Stage 0 refused them rather than accept an unverified assertion (S6); this
stage verifies the assertion.

- **Metadata**: `token_endpoint_auth_method: private_key_jwt` is accepted
  when `jwks` or `jwks_uri` is present (`https` only, through the hardened
  fetch stage 0 built); keys must be EC P-256 — `ES256` is the one algorithm
  the profile currently requires. Either `jwks` or `jwks_uri`, never both,
  per the client-metadata spec.
- **PAR**: a confidential client carries `client_assertion_type=
  urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and a
  `client_assertion` JWT — `alg: ES256`, `aud` = brolly's issuer, `iat`, a
  `jti` that is single-use (one more `(key, jti)` store, S7's pattern,
  pruned by the same pass), signed by a key in the client's JWKS. The
  key's thumbprint is stored with the pushed request and rides to the code
  and the tokens: **the session is bound to the client key**.
- **Token** (code and refresh): the same assertion, the same key — a
  different key is a different client instance, answered `invalid_grant`.
  On refresh, the client metadata is re-fetched (a cache-bypassing fetch,
  the same one `issuer_jwks` does for a Solid key rotation) and the session
  is revoked if the key has left the JWKS — the profile's "must revoke the
  session… if the client authentication key becomes absent".
- **Lifetimes**: confidential refresh tokens live up to 180 days and the
  session is uncapped (G's anchor applies to public clients only) — the
  profile's trade: an authenticated, key-bound, remotely-revocable client
  earns the longer session.

A public client sending an assertion, or a confidential client not sending
one, is refused `invalid_client`.

### G. Token lifetimes and the session anchor

- **Access: 3600 s → 900 s.** The profile's hard cap is 30 minutes and its
  recommendation 5; brolly can revoke individual rows (`revoked_at` is in the
  `verify_token` query, `adapters/atproto/src/oauth.rs:212-220`), so the
  15-minute maximum for non-revocable servers does not bind — but the only
  revocation *wired* today is revoke-all, so a stolen token realistically
  lives its full TTL. 900 s is the conservative end that keeps refresh
  chatter low (one refresh per quarter hour, not per five minutes).
- **Refresh: 90 days → 2 weeks for public clients, 180 days for confidential
  (F).** And `atproto_tokens` gains `anchored_at TIMESTAMPTZ NOT NULL`, set
  at the code grant, copied forward on every rotation. A public client's
  refresh is refused when `now > anchored_at + 2 weeks` — the profile caps
  "overall session lifetime **and** the lifetime of individual refresh
  tokens", and rotation alone caps only the second: without the anchor, a
  public session is exactly as unlimited as the confidential one the profile
  reserves that property for. Existing rows anchor at the migration
  timestamp.
- **Legacy mirrors the access TTL and the refresh TTL** (A), with no
  overall cap: the legacy scheme's own specification — the HTTP API spec —
  sets none, and a bsky.app session is expected to survive weeks. What the
  legacy pair has instead is the `session_id`: every rotation shares one, so
  `deleteSession` and app-password revocation (B) end the whole line at
  once. The 2-week *overall* cap is the OAuth profile's rule for OAuth
  public clients; applying it to legacy would sign bsky.app users out on a
  schedule the legacy scheme never promised.

`change_password` additionally calls `revoke_all_for_user` for the ATProto
tables (OAuth and legacy — the function exists unconnected,
`adapters/atproto/src/oauth.rs:235-244`): a member who changes a password
has asked to end other sessions, and today only the browser ones end.
Disable needs no revocation, the same way the admin spec found it needed
none for cookies: `caller` filters `is_active`, so the credentials stop
resolving on their next request.

### H. The authorization request's bindings

- **`login_hint` is enforced.** `decide` compares the pushed `login_hint`
  against the consenting member — any of their identifiers (username, handle,
  DID, email) satisfies it. A mismatch does not render the consent screen;
  it redirects to `/login` with the same `next` an anonymous arrival gets:
  the member must authenticate *as the hinted account*, which is the
  profile's "should only allow the user to authenticate with that account".
  Consenting as someone else would only surface later as the client's `sub`
  verification failure — a flow that completes and then breaks, rather than
  one that never misleads.
- **`code_challenge` reuse is refused within 24 hours.** A new
  `atproto_used_code_challenges` table (the challenge value is itself a
  SHA-256, so it is its own PK), checked at PAR, pruned by the same pass
  that prunes `dpop_jti` (S7). The profile's PKCE section says servers
  "must prevent reuse of `code_challenge` values across sessions (at least
  within some reasonable time frame, such as a 24 hour period)" — defense in
  depth against a challenge-carrying interceptor, and one indexed insert.

## Testing

- **The legacy flow, end to end.** `createSession` with each identifier form
  (handle, `did:plc`, derived `did:web`, email); with the primary password;
  with an app password; wrong password → 401 `AuthenticationRequired`;
  disabled account → 401 `AccountTakedown`; a missing user costs an Argon2
  verify (timing parity). `getSession`'s email visibility matrix (primary /
  privileged / unprivileged). `refreshSession` rotates: the old refresh is
  dead, the new pair lives, expired → `ExpiredToken`, unknown →
  `InvalidToken`. `deleteSession` kills both rows of the `session_id`.
- **App passwords.** The format matches `^[a-z0-9]{4}(-[a-z0-9]{4}){3}$`; the
  plaintext appears in `createAppPassword` and never in `listAppPasswords`;
  an app-password session cannot manage app passwords (403); revoking one
  kills its sessions *immediately* (the opaque-token property the reference
  cannot have); a revoked app password cannot log in.
- **The nonce matrix.** No `nonce` claim → 400 `use_dpop_nonce` + a fresh
  header at PAR/token, 401 + the `WWW-Authenticate` DPoP challenge on XRPC;
  current bucket verifies; previous bucket verifies; two buckets old fails;
  a nonce from a different secret fails; the same nonce serves PAR, token
  and XRPC; two processes converge on one secret (the `load_or_create` race
  `instance.rs` already tests for its own key); a proof whose `iat` is fresh
  but whose nonce is stale-by-two still fails (`iat` freshness does not
  launder a nonce).
- **The caller.** A proof signed for the actual method and URL passes; for
  another method (GET vs POST, the `getServiceAuth` case), another path, or
  another token's `ath`, fails; an unknown token's proof is spent anyway
  (replaying it with a valid token fails — the ordering fix, made testable).
- **The scope gate.** An `atproto`-only token writes → 403
  `ScopeMissingError` with the reference's message; `transition:generic`
  writes; a legacy session writes; OAuth on app-password management → 403;
  `scopes_supported` is enforced at PAR (a client declaring
  `transition:email` is refused at push, not granted it).
- **Confidential clients.** PAR without an assertion → `invalid_client`;
  with a wrong-`aud`, replayed-`jti`, or wrong-key assertion → refused; the
  bound key must re-appear at the token endpoint (a different key →
  `invalid_grant`); a refresh after the key left the JWKS revokes the
  session; the refresh TTL is 180 days and unanchored.
- **Lifetimes.** The constants, asserted with `black_box` the way
  `service_auth.rs`'s TTL test does; a public refresh past 2 weeks from
  `anchored_at` → `invalid_grant`; `change_password` revokes ATProto tokens
  (both tables) alongside browser sessions.
- **`getServiceAuth`.** The token verifies against the member's published
  `did:key` (the PLC document key); `lxm` binds (a token for one method
  does not authorize another — `service_auth.rs` tests the primitive; this
  tests the endpoint); `exp` in the past or > 5 minutes out →
  `BadExpiration`; the default is 60 s; the `did#serviceId` fragment
  survives into `aud`.
- **Discovery.** The protected-resource document's shape (single origin
  element, no path); the two new AS metadata fields; `dpop-nonce` joins
  `www-authenticate` in the CORS expose, so a browser client can read the
  nonce header at all (the expose assertions the stage 5b CORS tests
  established).
- **The bindings.** A `login_hint` naming another member redirects to
  login, never renders consent; a matching hint (by any identifier form)
  consents; a re-pushed `code_challenge` within 24 h is refused.

## Rollout

- **Migrations**, all additive: `atproto_app_passwords`,
  `atproto_legacy_tokens`, `dpop_nonce_secrets`,
  `atproto_used_code_challenges`, and two columns on `atproto_tokens`
  (`anchored_at` with `DEFAULT now()` — existing sessions anchor at the
  migration and are capped from there; `client_jkt`, nullable, confidential
  sessions only). No data conversion: there are no legacy tokens yet, and
  OAuth rows carry their own anchor going forward.
- **Already-issued tokens** outlive the new constants (a test instance
  holds them; they expire on their own TTLs — re-login is the cost, on
  `test.brolly.cc` only, per stage 1's rollout).
- **The nonce cutover is the designed dance, not a break.** The secret is
  generated on first boot; the first proof any client sends lacks the nonce
  claim, gets the 400/401 with a fresh `DPoP-Nonce`, and retries — which is
  RFC 9449's own flow and the reason clients are required to be resilient
  to it.
- **The wire is additive**: new endpoints, new headers, and one new error
  body (`ScopeMissingError` 403) on a path that previously always
  succeeded — the only callers affected are ones holding a token granted
  *less* than a method requires, which is the test instance and no one. The
  one behaviour change to existing callers is the XRPC 401 gaining headers.

## Chunks

Five, one commit each:

1. **Legacy sessions and app passwords.** The two tables, the seven
   `com.atproto.server.*` endpoints (four session, three app-password), the
   bearer arm of `caller`, the privilege matrix, the `change_password`
   revocation wiring. *First because
   it is the largest new surface and the one the finish line's first item is
   blocked on; it touches nothing the OAuth work depends on, and every later
   chunk's caller behaviour needs its privilege model in place.*
2. **DPoP nonces.** The `Claims`/`verify` change, the secret table and
   `AppState` load, issuance and enforcement at PAR/token, the XRPC 401
   nonce, the CORS expose entry. *Second because it changes `dpop::verify`'s
   signature — every proof path after this compiles against the nonce
   parameter — and because chunk 3's PAR checks and chunk 4's caller both
   sit on proof paths it redefines.*
3. **Discovery, lifetimes, and bindings.** The protected-resource route, the
   AS metadata fields, the TTL constants and `anchored_at`, the
   server-side scope allowlist at PAR, `login_hint` enforcement,
   `code_challenge` reuse. *Third because it is documents, constants, and
   checks — self-contained, riding nothing new, and the caller in chunk 4
   points its `resource_metadata` at the route this lands.*
4. **The caller is the request.** Real `htm`/`htu`, spend-before-grant, the
   401 `WWW-Authenticate` shape, `Cache-Control`/`Vary`, the scope gate with
   the reference's 403, and `getServiceAuth`. *Fourth because it consumes
   chunk 2's nonce parameter and chunk 1's privilege model, and because it
   is the one chunk that rewrites the caller path the earlier chunks also
   touch — landing it after them keeps those diffs single-purpose, and
   nothing after it touches the caller again.*
5. **Confidential clients.** `private_key_jwt` at PAR and token, the JWKS
   fetch and validation, the session key binding, the re-fetch-and-revoke on
   refresh, the 180-day refresh. *Last because it is the most intricate
   OAuth piece, it reworks PAR/token paths chunks 2–4 already reshaped, its
   metadata fields land with it, and nothing downstream depends on it —
   stage 3's proxy works with public clients' tokens identically.*

## Decisions

| # | Decision | Why |
|---|---|---|
| A | Legacy tokens are opaque secrets in their own `atproto_legacy_tokens` table (SHA-256-hashed, `kind` in the lookup, `session_id` linking every rotation, `app_password_id` carrying provenance) | The HTTP API spec says clients must treat them as opaque and that JWT shape is not stable — so brolly stores what it controls. `atproto_tokens` has two NOT NULLs (`dpop_jkt`, `client_id`) a legacy token can never fill; ADR 0008's own rule is separate tables for disagreeing surfaces. The `kind`-in-lookup is the domain separation the spec's `typ` headers approximate, and it is the pattern `verify_token` already proved. `session_id` is what makes `deleteSession` kill the access token too. |
| B | App passwords: 4×4 `[a-z0-9]`, shown once at creation, `UNIQUE (user_id, name)`, `ON DELETE CASCADE` from the password row to the session rows; privilege = `app_password_id IS NULL OR privileged` | The format is the spec's own, and clients use it to warn off primary-password logins. The cascade is the whole point of opaque tokens: the reference's JWT sessions outlive revocation until refresh; rows do not. The privilege rule is the HTTP API spec's sentence, read off one column, with the reference's `allowsEmailAccess` semantics for the email fields. |
| C | Nonces = `base64url(HMAC-SHA256(secret, bucket))`, 300 s buckets, current+previous accepted, secret one row generated on first start, loaded once per process | Rotation at ≤5 min and one stale generation are the profile's own two sentences, and time-bucketed HMACs give both with no hot-path storage and no rotation job — any process verifies, the stage 1 (G) property. Serving and acceptance are different windows, and conflating them either breaks in-flight requests at every boundary or rotates slower than the cap; the `iat` window bounds the proof, independently of its nonce. `dpop.rs` owns the check because RFC 9449 nonces are a DPoP concern — Solid can adopt them without a new mechanism. |
| D | The caller verifies and spends the proof against the real request before reading the grant; 401s carry `WWW-Authenticate` (the draft's `resource_metadata` challenge for a missing credential, RFC 9449's DPoP challenge for a refused one); scope failures answer 403 `ScopeMissingError` | The current order learns the user before the proof is spent — the exact hole `dpop.rs`'s module doc assigns here — and the hardcoded `htu`/`htm` refuses every real client. The 403/name/message are the reference's own wire shape (`ScopeMissingError`, exposed, mapped by name); inventing a different one is protocol fork. The XRPC body stays coarse because RFC 9449 puts the detail in the header, and one body name keeps the surface learnable. |
| E | `/.well-known/oauth-protected-resource` with a single origin; AS metadata gains the two required fields; PAR enforces the server's `scopes_supported` | The draft and the profile make all three required. `scopes_supported` is the server's declaration of what it grants — a token response echoing a scope outside it is the metadata lying, and a lie granted is worse than a refusal at push. `require_request_uri_registration` stays implicit because the profile's default is already the required value. |
| F | Confidential clients verified, not refused: ES256 JWT client assertions at PAR and token, JWKS from metadata, session bound to the client key, re-fetch-and-revoke on refresh | S6 refused them because accepting an unverified assertion is worse than refusing it — verified, that argument inverts: the profile *requires* `private_key_jwt` in `token_endpoint_auth_methods_supported`, and confidential clients are the only ones the profile trusts with long sessions. The key binding is the profile's anti-session-theft rule, and the revoke-on-refetch is what makes key removal a kill switch. |
| G | Access 900 s; refresh 2 weeks (public, anchored) / 180 days (confidential); `anchored_at` copied forward on rotation; `change_password` revokes ATProto tokens | All three lifetimes are the profile's own numbers, and the anchor is the difference between capping "individual refresh tokens" and capping "overall session lifetime **and** individual refresh tokens" — rotation without an anchor caps only the second, granting public clients the unlimited session the profile reserves for confidential ones. The revocation wiring closes a promise the dashboard already makes ("changing your password ends every other session") for the two ATProto token tables it currently doesn't reach. |
| H | `getServiceAuth`: `aud`/`lxm`/`exp` per the lexicon, `exp` bounded to now+300 s, signed by the `atproto_signing` key | The crypto exists and is tested (`service_auth.rs`); the endpoint is the lexicon's shape and nothing more. The 5-minute `exp` bound is the only addition — an unbounded server-signed `lxm`-scoped token is a replay surface the lexicon explicitly leaves to the server ("may enforce certain time bounds"), and 60 s default / 300 s ceiling is the same scale `service_auth.rs` already committed to. |
| I | `login_hint` enforced at `decide` (mismatch → login redirect, never consent); `code_challenge` reuse refused within 24 h | Both are the profile's own bindings: the hint is the account the *client* bound the session to, and letting another member consent builds a flow that completes and then fails at `sub` — misleading rather than refusing. Challenge-reuse refusal is a "must" in the PKCE section; the store is one indexed table on S7's pruning pattern. |
