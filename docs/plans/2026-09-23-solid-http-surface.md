# Stage 5b: The Pod's HTTP Surface — Implementation Plan

<!-- doc-paths: skip -->
<!-- A plan cites the files it is about to create, so the paths it names
     are not expected to resolve until it has been executed. -->

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** What a Solid client learns over HTTP becomes true and complete.
Refusals say whether to authenticate without disclosing existence. `Allow`,
`Accept-*`, `Link` and `WAC-Allow` are computed per resource and per caller.
The storage announces itself. Caches can't serve the wrong syntax. Writes
report what they did.

**Architecture:** `pod.rs` learns whether a credential verified and maps
`ldp`'s new `Denied` refusal to 401 or 403. A body-free `ldp::describe` reads a
resource's metadata and the caller's and the public's modes inside one
snapshot, and one header builder in `pod.rs` turns that description into
`Allow`, `Accept-*`, `Link`, `WAC-Allow` and `Vary` for `GET`, `HEAD`,
`OPTIONS`, 304 and 201 alike. A generated storage description is served at
`/.well-known/solid`. ETags carry the syntax they were issued for. Container
listings carry member metadata, and a write that changes it is refused.

**Tech Stack:** Rust, axum 0.8, oxigraph 0.5.9, sqlx and testcontainers.

**Spec:** [`docs/specs/2026-09-23-solid-http-surface.md`](../specs/2026-09-23-solid-http-surface.md)
**Roadmap:** [`docs/specs/2026-09-17-interop-roadmap.md`](../specs/2026-09-17-interop-roadmap.md), stage 5b.

---

## Commits

Five, one per chunk. Every chunk leaves `main` deployable on its own, so each
is its own revert boundary. (The spec's draft paired chunks 2 and 3 in one
commit; chunk 2 turns out to stand alone, and separate commits are easier to
bisect.)

| Commit | Chunk | Contents |
|---|---|---|
| 1 | 1 | Credentials and refusals: 401/403/404, `WWW-Authenticate`, `HEAD` authenticated as `HEAD`. |
| 2 | 2 | `ldp::describe` and the header builder: stateful `OPTIONS`, `Allow`, `Accept-*`. |
| 3 | 3 | Discovery: `Link` headers, `acl_iri`, the storage description, root write routes, root-ACL guard, `Allow` on our 405s. |
| 4 | 4 | Caching and CORS: `WAC-Allow public=`, syntax-tagged ETags, `Vary`, the fuller 304, origin and header echo. |
| 5 | 5 | Write responses and bodies: 201 on create, 409 for a non-empty container, member metadata in listings, `Content-Type` required. |

Each commit is verified from a clean checkout. Clean checkouts run one at a
time, never alongside another test run, because parallel Docker runs cause
false failures. **Never pipe a verification run through `grep` or `tail`**: the
pipeline's exit code is the filter's, not cargo's, and a stage 5a sweep once
reported success after silently skipping ten test binaries. Redirect to a file,
check `$?`, and reconcile the number of `test result:` lines against
`cargo test --workspace -- --list`.

## Reconciling the chunks

The five chunks were written in parallel, each against assumed interfaces for
the chunks before it. **Execute them in order, and treat the code the previous
chunk actually landed as authoritative**: where a later chunk names something
differently, use the landed name and keep the later chunk's behaviour. Known
points:

- **`ldp_error`.** Chunk 1 makes it `ldp_error(error, authenticated, apex)` and
  gives `PodRequest` `authenticated` and `apex` fields. Chunks 2, 3 and 5 write
  `ldp_error(e)` in places; spell every call the way `pod::get` does after
  chunk 1: `ldp_error(e, req.authenticated, &req.apex)`.
- **Extractors.** Chunk 1 adds `Method` and `OriginalUri` to every pod handler,
  before `Path`. Chunk 3's `put_root`/`patch_root`/`delete_root` already take
  them; chunk 2's `options_root(state, headers)` was written without them.
  **Every root handler takes the same extractors as its wildcard twin** and
  passes them through — otherwise `OPTIONS /~/` reintroduces, for exactly the
  resource a client probes first, the downgrade-to-anonymous bug chunk 1
  fixes.
- **`LdpError::NotEmpty` already exists after chunk 1.** Chunk 1 adds it (and
  `Undeletable`) so that chunk 3's 405 can't briefly apply to deleting a
  populated container. Both answer 403 until their owning chunk remaps them.
  Chunk 5's Task 4 therefore skips its "fails to compile: no variant
  `NotEmpty`" step and its enum edit; it changes only `ldp_error`'s mapping to
  409 and adds the body.
- **`Undeletable`.** Chunk 3 builds the 405 in `pod::delete` (its `Allow`
  depends on the caller's modes) and turns `ldp_error`'s `Undeletable` arm
  into a logged 500, so a future producer that bypasses `pod::delete` shows up
  rather than sending a 405 without `Allow`.
- **The header builder.** Chunk 2 names its pieces `allowed`, `undeletable`,
  `accept_put`, `affordances` and `apply`, over a `Description`. Chunk 3 writes
  of `headers_for`, `allow` and `describe` and adds `links`; chunk 4 adds
  `WAC-Allow public=` and `Vary`. They are all the same builder: add `Link`,
  `WAC-Allow` and `Vary` to chunk 2's `affordances`, and don't create a second
  one. `links(...)` and `allowed(...)` helpers that take a `HeaderMap` in
  chunk 3's text are **test** helpers in `pod_http.rs`, not the builder.
- **`Description`.** Chunk 2 defines it as `meta: Option<ResourceMeta>` plus
  `granted` and `public`, with `exists()`, `kind()`, `is_container()` and
  `holds()` derived from `meta`. Chunk 3's `Option<Kind>` is
  `description.kind()`; chunk 4's public modes are `description.public`.
- **Three answers chunk 1 chose that the spec left open,** now in the spec: a
  database failure during credential verification is a 500; an `Authorization`
  header that can't be parsed is `invalid_token` in the `DPoP` form; a valid
  token naming a WebID this instance doesn't host is `invalid_token`.
- **Two corrections chunk 2 made to the spec,** now in the spec: `Accept-Put`
  for an absent target follows the path the way `PUT` does, so a missing
  container path advertises the RDF types rather than `*/*`; and the creation
  `Allow` for an absent target is `PUT, PATCH, OPTIONS` — no `POST`, which
  needs something to post into.
- **Tests the spec's change list missed.** `server/tests/solid_token_access.rs`
  has eight tests asserting today's silent 404 for bad or absent credentials;
  `acl_control.rs` and `ldp_conformance.rs` have about ten more assertions of
  the old refusals. Chunk 1 rewrites them all.

---

## Chunk 1: Credentials and refusals

Spec `docs/specs/2026-09-23-solid-http-surface.md`, decisions **H1**, **H2**,
**H3**, and the half of **H15** that is `subject_for`'s signature. This is the
first of 5b's four commits. Nothing in chunks 2–5 can be built on top of it
until it has landed: it changes the meaning of every existing refusal, and
everything after it is additive.

**Goal:** a client that is refused learns which kind of refusal it was, without
the refusal disclosing whether the resource exists. An `Authorization` header
that doesn't verify stops being silent anonymity. A `HEAD` signed as `HEAD`
authenticates.

**What this chunk does *not* do,** although the same decisions touch them:
`ldp::describe`, the `Allow` and `Accept-*` headers, the `Link` set, the
storage description, `WAC-Allow`'s `public=`, `Vary`, the syntax-tagged ETag,
201 on create, the 409s, container listings, and CORS. `OPTIONS` stays the
static, stateless handler it is today — chunk 2 makes it real. `Undeletable`'s
405 is chunk 3 and `NotEmpty`'s 409 is chunk 5; both keep answering 403 here,
deliberately, so this chunk changes no answer it didn't set out to change.

**What changes:**

| File | Change |
|---|---|
| `server/src/pod.rs` | `Caller` and `Refused`; `subject_for` returns `Result<Caller, Refused>` and takes a `&Method` and the undecoded URL; `dpop_challenge` and `unauthorized`; `PodRequest` gains `authenticated` and `apex`; every handler gains the `Method` and `OriginalUri` extractors; `ldp_error` takes the credential facts and maps `Denied` to 401 or 403 |
| `server/src/activitypub.rs` | `inbox_collection` follows the new signature, picks up H2's 401, and keeps its own 404 rule |
| `adapters/solid/src/ldp.rs` | `LdpError::Denied` split from `NotFound`; `Forbidden` renamed `Undeletable`; `LdpError::NotEmpty` takes over the non-empty-container producers |
| `server/tests/pod_http.rs` | three rewrites, seven new tests |
| `server/tests/solid_token_access.rs` | eight rewrites, two new tests |
| `adapters/solid/tests/{ldp_conformance,ldp_nonrdf,acl_control}.rs` | fifteen assertions move to the new variants, one new test |
| `docs/specs/2026-09-17-security-fixes.md` | a line saying H1 replaces stage 0's A2 refusal rule |

**Gates, before the commit:**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
./tools/check-doc-paths.sh
cargo deny check
cargo test --workspace
```

**Run one test suite at a time.** These tests spin up Postgres in Docker, and
parallel runs of two suites cause false failures. Never run a per-crate command
alongside `cargo test --workspace`, and never run the clean-checkout
verification while anything else is testing.

**Trunk-based.** This chunk ends in one commit to `main`. No branch, no PR.
Tasks 1, 2 and 5 leave the workspace green. Task 3 deliberately leaves
`brolly-server` not compiling — that is the guarantee the `Forbidden` rename
buys — and Task 4 is what fixes it. Don't commit between 3 and 4.

### Interfaces this chunk delivers

Chunks 2–5 build on exactly these.

- `server/src/pod.rs`:
  - `pub(crate) struct Caller { pub subject: Subject, pub authenticated: bool }`
  - `pub(crate) enum Refused { Token, Proof, Bearer, Unavailable }`
  - `pub(crate) async fn subject_for(&AppState, &HeaderMap, &Method, &str) -> Result<Caller, Refused>`
  - `pub(crate) fn unauthorized(Refused, apex: &str) -> Response`
  - `fn dpop_challenge(apex: &str, error: Option<&str>) -> String`
  - `fn ldp_error(LdpError, authenticated: bool, apex: &str) -> Response`
  - `PodRequest` gains `pub authenticated: bool` and `pub apex: String`, where
    `apex` is the full origin `https://{base_domain}`, not a bare hostname.
  - Every handler's extractor order is `State`, `Method`, `OriginalUri`,
    `HeaderMap`, then `Path` (then the body, where there is one). **`Path`
    stays last among the non-body extractors**; chunk 2's `options` and chunk
    3's `put_root`/`patch_root`/`delete_root`/`options_root` keep that order.
- `adapters/solid/src/ldp.rs`: `LdpError::{Denied, NotEmpty, Undeletable}`;
  `Forbidden` is gone. `NotFound` keeps its narrowed meaning — *the caller
  holds the mode and there is nothing there*. No `ldp` function signature
  changes.

---

### Task 1: The credential outcome, and H2's immediate 401

**Files:**
- Modify: `server/src/pod.rs` — `PodRequest` (`:25-33`), `resolve` (`:39-89`),
  `subject_for` (`:95-195`), new items between them, `mod tests` (`:578-599`)
- Modify: `server/src/activitypub.rs:280-292`
- Modify: `server/tests/solid_token_access.rs`

After this task an `Authorization` header that doesn't verify is a 401 with a
challenge. An absent credential, and a cookie that doesn't resolve, are still
anonymous and still get today's 404 — H1 turns that into a 401 in Task 4.

- [ ] **Step 1: Write the failing unit tests**

In `server/src/pod.rs`, replace the whole `#[cfg(test)] mod tests` block with:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// The `WWW-Authenticate` on the response `refused` produces.
    fn challenge_of(refused: Refused, apex: &str) -> String {
        let response = unauthorized(refused, apex);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        response.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap()
            .to_string()
    }

    /// 5a uses the codes `pod.rs` already has; 5b revisits them.
    #[test]
    fn the_new_ldp_refusals_have_status_codes() {
        assert_eq!(
            ldp_error(LdpError::NotRdf).status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            ldp_error(LdpError::ContainmentChange).status(),
            StatusCode::CONFLICT,
            "Solid Protocol §5.3"
        );
        assert_eq!(
            ldp_error(LdpError::BlobMissing).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    /// H3's challenge is the only thing a refused client can act on, so its
    /// exact shape is load-bearing: a Solid client reads `as_uri` to find the
    /// issuer and refuses to authenticate against one it wasn't configured
    /// for. The failure this guards is a challenge naming an algorithm we do
    /// not verify, or an issuer that disagrees with the one the profile
    /// publishes as `solid:oidcIssuer`.
    #[test]
    fn the_challenge_names_es256_and_the_apex() {
        assert_eq!(
            dpop_challenge("https://brolly.test", None),
            r#"DPoP algs="ES256", as_uri="https://brolly.test""#
        );
    }

    /// RFC 9449 §7.1 defines `invalid_dpop_proof` precisely because
    /// `invalid_token` tells a client to refresh a token that is fine — it
    /// would refresh, re-sign the same broken proof, and loop. Collapsing the
    /// two codes is the failure this guards.
    #[test]
    fn a_broken_proof_and_a_broken_token_are_told_apart() {
        assert_eq!(
            challenge_of(Refused::Token, "https://brolly.test"),
            r#"DPoP algs="ES256", as_uri="https://brolly.test", error="invalid_token""#
        );
        assert_eq!(
            challenge_of(Refused::Proof, "https://brolly.test"),
            r#"DPoP algs="ES256", as_uri="https://brolly.test", error="invalid_dpop_proof""#
        );
    }

    /// Mastodon's API tokens reach pod URLs as bare bearers, and a Mastodon
    /// client can do nothing with a `DPoP` challenge — it has no key to sign
    /// a proof with and would loop on a challenge it cannot satisfy.
    #[test]
    fn a_bare_bearer_gets_a_bearer_challenge() {
        assert_eq!(
            challenge_of(Refused::Bearer, "https://brolly.test"),
            r#"Bearer error="invalid_token""#
        );
    }

    /// A database failure while verifying is ours, not the caller's. Blaming
    /// the credential would have a client throw away a perfectly good token
    /// and re-run a login flow over an outage.
    #[test]
    fn a_failure_to_verify_is_not_blamed_on_the_credential() {
        assert_eq!(
            unauthorized(Refused::Unavailable, "https://brolly.test").status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-server --lib pod::`

Expected: compile failure, `error[E0433]`/`error[E0425]`: cannot find type
`Refused`, cannot find function `unauthorized`, cannot find function
`dpop_challenge` in this scope.

- [ ] **Step 3: Implement the credential outcome**

In `server/src/pod.rs`, add `pub authenticated: bool` and `pub apex: String` to
`PodRequest`, with the doc comments:

```rust
/// Everything a pod request needs once the host and credential are resolved.
pub struct PodRequest {
    pub user: User,
    pub subject: Subject,
    /// A credential was presented and verified. H1 turns a refusal into 401
    /// or 403 from this alone, never from whether the target exists.
    pub authenticated: bool,
    pub pod: Arc<Pod>,
    /// This pod's binary storage, for LDP-NR.
    pub blobs: brolly_store::BlobStore,
    pub base: String,
    /// The instance's apex origin, for `WWW-Authenticate`'s `as_uri` (H3).
    pub apex: String,
    pub storage_root: String,
}
```

Replace `resolve`'s last four lines (from `let base = …`) with:

```rust
    let base = format!("https://{username}.{}", state.base_domain);
    let apex = format!("https://{}", state.base_domain);
    // The pod is resolved before the credential, so a bad credential sent to a
    // pod that doesn't exist is still 404. That is a routing answer, not an
    // access decision, like `subdomain_fallback`'s.
    let caller = match subject_for(state, headers, method, &format!("{base}{path}")).await {
        Ok(caller) => caller,
        Err(refused) => return Err(unauthorized(refused, &apex)),
    };
    Ok(PodRequest {
        storage_root: routing::storage_root(&username, &state.base_domain),
        base,
        apex,
        user,
        subject: caller.subject,
        authenticated: caller.authenticated,
        pod,
        blobs,
    })
}
```

Then replace `subject_for` and everything up to `solid_subject` with:

```rust
/// Who is calling, and whether they proved it.
pub(crate) struct Caller {
    pub subject: Subject,
    /// A credential was presented **and** verified.
    ///
    /// Not `Subject::agent()`: a service-auth subject has `webid: None` and
    /// reports `Agent::Anonymous` (`identity/src/subject.rs:103-110`), but it
    /// authenticated, so H1 owes it a 403 rather than a challenge it has
    /// already satisfied. False for no credential at all, and for a session
    /// cookie that no longer resolves.
    pub authenticated: bool,
}

impl Caller {
    /// Nobody in particular. WAC decides whether that is enough, so a public
    /// resource is readable without a credential.
    fn anonymous() -> Caller {
        Caller {
            subject: Subject {
                user_id: None,
                did: None,
                webid: None,
                scope: Scope::default(),
                via: Via::Session,
            },
            authenticated: false,
        }
    }
}

/// A subject that came from a credential we verified.
fn verified(subject: Subject) -> Caller {
    Caller {
        subject,
        authenticated: true,
    }
}

/// Why a presented credential produced no subject (H2).
///
/// **Only an `Authorization` header gets here.** A `brolly_session` cookie is
/// `SameSite=Lax` (`server/tests/auth_flow.rs:249`), so a browser sends it on
/// any top-level navigation: a logged-out member opening a public image in
/// their own pod never offered it, and meeting them with a challenge for a
/// credential they did not present would be wrong. A cookie that doesn't
/// resolve falls through to [`Caller::anonymous`] and H1 decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    /// The token: a header we couldn't parse, or a token that is unknown,
    /// expired, revoked, or carries a WebID this instance doesn't host.
    /// RFC 6750 §3.1's `invalid_token`.
    Token,
    /// The proof: not signed by the token's key, the wrong `htm` or `htu`,
    /// outside the freshness window, or a replayed `jti`. RFC 9449 §7.1's
    /// `invalid_dpop_proof`.
    Proof,
    /// A bare bearer token that resolved to nobody.
    Bearer,
    /// We could not tell — a database failure while verifying. Ours, not the
    /// caller's, so it is a 500 and not a challenge to retry.
    Unavailable,
}

/// `WWW-Authenticate` for a caller who has to authenticate (H3).
///
/// `as_uri` is a Solid-OIDC §9.1 MUST: the scheme has no discovery mechanism
/// of its own, and RFC 9449 §7.1's `DPoP` parameters (`realm`, `scope`,
/// `error`, `error_description`, `algs`) include none. `apex` is the
/// instance's apex origin, byte-identical to what the profile publishes as
/// `solid:oidcIssuer` (`server/src/profile.rs:96`) and to the `iss` claim
/// (`server/src/solid_oidc.rs:43`).
///
/// `algs` names ES256 alone, because that is all we verify
/// (`identity/src/dpop.rs:336`, `adapters/solid/src/oidc/tokens.rs:191`) and
/// advertising more would be a lie. `realm` is omitted: RFC 6750 §3 and
/// RFC 9449 §7.1 both make it optional and Solid-OIDC doesn't use it.
/// `error_description` is omitted because it would be the only place in this
/// surface where a refusal explains itself to an unauthenticated caller, and
/// its values are either obvious ("expired") or something an attacker would
/// like to know ("replayed").
fn dpop_challenge(apex: &str, error: Option<&str>) -> String {
    let mut challenge = format!("DPoP algs=\"ES256\", as_uri=\"{apex}\"");
    if let Some(error) = error {
        challenge.push_str(&format!(", error=\"{error}\""));
    }
    challenge
}

/// Answer a refused credential: 401 with a challenge, or 500 when the failure
/// was ours.
///
/// An absent credential is **not** routed through here — it has no `error` to
/// report, and it is `ldp_error` that discovers it was refused at all. It gets
/// `dpop_challenge(apex, None)`.
pub(crate) fn unauthorized(refused: Refused, apex: &str) -> Response {
    let challenge = match refused {
        Refused::Token => dpop_challenge(apex, Some("invalid_token")),
        Refused::Proof => dpop_challenge(apex, Some("invalid_dpop_proof")),
        // Mastodon's API tokens reach pod URLs through `Credential::Bearer`,
        // and a Mastodon client can do nothing with a `DPoP` challenge. An
        // *absent* credential still gets `DPoP` only: the pod is
        // proof-of-possession by default, and offering `Bearer` unprompted
        // invites a client to send a bare token that will be refused.
        Refused::Bearer => "Bearer error=\"invalid_token\"".to_string(),
        Refused::Unavailable => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    challenge_response(challenge)
}

/// 401 carrying `challenge`.
fn challenge_response(challenge: String) -> Response {
    match HeaderValue::from_str(&challenge) {
        Ok(value) => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, value)],
            "unauthorized",
        )
            .into_response(),
        // Unreachable: every part of the challenge is a constant or a hostname
        // we built. A 401 without a challenge still beats a 200.
        Err(_) => (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
    }
}

/// Turn whatever credential the request carried into a [`Caller`].
///
/// An absent credential is anonymous rather than rejected: WAC decides whether
/// anonymous is enough, so public resources work without one. An
/// `Authorization` header that doesn't verify is a [`Refused`], **not**
/// anonymity (H2), and the request is not retried without it: an expired token
/// must look like an expired token, or an app whose session lapsed mid-edit
/// sees its own resources vanish instead of a challenge it can act on.
pub(crate) async fn subject_for(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    url: &str,
) -> Result<Caller, Refused> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());
    let cookie = headers.get(header::COOKIE).and_then(|h| h.to_str().ok());

    let Some(credential) = extract::credential(authorization, cookie) else {
        // An `Authorization` header we could not parse is still a presented
        // credential; no header at all is anonymity. The key is tested rather
        // than the parsed value, so bytes that aren't UTF-8 count as presented
        // too.
        if headers.contains_key(header::AUTHORIZATION) {
            return Err(Refused::Token);
        }
        return Ok(Caller::anonymous());
    };
    // The proof travels in its own header, so it is attached separately.
    let proof = headers.get("dpop").and_then(|h| h.to_str().ok());
    let credential = extract::with_proof(credential, proof);

    match credential {
        Credential::Session(token) => match db::user_for_session(&state.pool, &token).await {
            Ok(Some(user)) => Ok(verified(Subject::local(
                user.id,
                user.did_plc.clone().unwrap_or_default(),
                webid::webid(&user.username, &state.base_domain),
                Scope::parse("webid"),
                Via::Session,
            ))),
            // A cookie is not a presented credential (H2), so a stale one is
            // anonymity and not a challenge.
            _ => Ok(Caller::anonymous()),
        },
        Credential::Dpop { token, proof } => {
            // Token and proof are verified together or not at all: a token
            // whose `cnf.jkt` does not match the proof was not presented by
            // its holder, and a bound token with no proof is refused rather
            // than downgraded to bearer semantics.
            //
            // A bound token's claims arrive `Unspent`. Spending records the
            // proof so it can't be sent again.
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
                        return Err(Refused::Unavailable);
                    }
                    // A replayed `jti` lands here, and it is a proof failure:
                    // the token is fine and refreshing it would not help.
                    Err(e) => {
                        tracing::warn!(error = %e, "Solid access token proof refused");
                        return Err(Refused::Proof);
                    }
                },
                Err(e @ tokens::TokenError::Jwt(_)) => {
                    tracing::debug!(error = %e, "Solid access token rejected");
                    return Err(Refused::Token);
                }
                // `Dpop`, `WrongHolder` and `ProofRequired`. Each says the
                // token was readable and the proof was not good enough for it.
                Err(e) => {
                    tracing::debug!(error = %e, "Solid access token proof rejected");
                    return Err(Refused::Proof);
                }
            };
            // A token we minted whose WebID this instance doesn't host
            // resolves to nobody, so it is the token that is wrong. Accepting
            // other issuers is stage 6.
            solid_subject(state, claims)
                .await
                .map(verified)
                .ok_or(Refused::Token)
        }
        // Mastodon's bearer tokens. Note what is *not* happening here: a
        // Solid access token presented as a bearer does not resolve, because
        // this looks the token up in Mastodon's own table rather than trying
        // to verify it as a JWT. Accepting a DPoP-bound token without its
        // proof is what would make the binding decorative.
        Credential::Bearer(token) => {
            match brolly_mastodon::oauth::verify_token(&state.pool, &token).await {
                Ok(Some(grant)) => match db::find_by_id(&state.pool, grant.user_id).await {
                    Ok(Some(user)) if user.is_active() => Ok(verified(Subject::local(
                        user.id,
                        user.did_plc.clone().unwrap_or_default(),
                        webid::webid(&user.username, &state.base_domain),
                        Scope::parse(&grant.scopes),
                        Via::MastodonBearer,
                    ))),
                    Ok(_) => Err(Refused::Bearer),
                    Err(e) => {
                        tracing::error!(error = %e, "a bearer grant's user lookup failed");
                        Err(Refused::Unavailable)
                    }
                },
                Ok(None) => Err(Refused::Bearer),
                Err(e) => {
                    tracing::error!(error = %e, "bearer token lookup failed");
                    Err(Refused::Unavailable)
                }
            }
        }
    }
}
```

- [ ] **Step 4: Run the unit tests and watch them pass**

Run: `cargo test -p brolly-server --lib pod::`
Expected: 5 passed.

- [ ] **Step 5: Follow the signature into `activitypub.rs`**

Run: `cargo check -p brolly-server`
Expected: `error[E0308]` in `server/src/activitypub.rs:290`: `subject.user_id`
— no field `user_id` on `Result<Caller, Refused>`.

In `server/src/activitypub.rs`, replace `:288-292` with:

```rust
    let inbox = webid::inbox(&username, &state.base_domain);
    let caller = match crate::pod::subject_for(&state, &headers, "GET", &inbox).await {
        Ok(caller) => caller,
        // H2 reaches here too. Without it, a client whose token expired is
        // downgraded to anonymous, this handler's owner check then fails, and
        // the member is told their own inbox does not exist.
        Err(refused) => {
            return crate::pod::unauthorized(refused, &format!("https://{}", state.base_domain));
        }
    };
    // Stage 0's rule stands: a caller who is not the owner gets 404, because
    // 403 would confirm both that the inbox exists and that the caller found a
    // real member. H1's table is about WAC on pod resources; this collection
    // is not one (H15).
    if caller.subject.user_id != Some(user.id) {
        return not_found();
    }
```

Run: `cargo check -p brolly-server`
Expected: clean.

- [ ] **Step 6: Rewrite the token tests to the new statuses**

`server/tests/solid_token_access.rs` is where every "a credential that doesn't
verify" case already lives, and every one of them asserts today's silent
downgrade. They all move.

Add, after the existing `send` helper (`:122-129`):

```rust
/// A request's status and its `WWW-Authenticate`, for H3's assertions. The
/// header is the only thing a refused client can act on, so asserting the
/// status alone would let the two error codes collapse into one unnoticed.
async fn challenged(harness: &Harness, request: Request<Body>) -> (StatusCode, String) {
    let response = harness.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    (status, challenge)
}

const INVALID_TOKEN: &str = r#"error="invalid_token""#;
const INVALID_PROOF: &str = r#"error="invalid_dpop_proof""#;
```

Then rewrite each of the following. Keep every name and every existing
comment; change the assertion and add the sentence that says why the code is
the one it is.

`a_token_without_its_proof_is_not_accepted`:

```rust
    let (status, challenge) =
        challenged(&harness, read_note(Some(&format!("DPoP {token}")), None)).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an unproven token must not read the pod"
    );
    // The token is fine; the proof is missing. `invalid_token` would send the
    // client to refresh a good token and present the same absent proof again.
    assert!(challenge.contains(INVALID_PROOF), "got: {challenge}");
```

`a_stolen_token_proven_with_the_wrong_key_is_not_accepted`,
`a_proof_for_another_request_is_not_accepted` and
`a_proof_without_the_token_hash_is_not_accepted`: the same two assertions,
keeping each test's own message on the status.

`a_solid_token_presented_as_a_bearer_is_not_accepted`:

```rust
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // A bare bearer gets a `Bearer` challenge: whatever sent it has no key to
    // sign a proof with, and a `DPoP` challenge would loop.
    assert_eq!(challenge, r#"Bearer error="invalid_token""#, "got: {challenge}");
```

`a_forged_token_is_not_accepted`:

```rust
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // The signature is the token's, not the proof's.
    assert!(challenge.contains(INVALID_TOKEN), "got: {challenge}");
```

`a_resource_proof_is_good_for_one_request`: the second request becomes

```rust
    let (status, challenge) =
        challenged(&harness, read_note(Some(&authorization), Some(&proof))).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a replayed proof must be refused, not silently downgraded"
    );
    assert!(challenge.contains(INVALID_PROOF), "got: {challenge}");
```

and its doc comment gains: *"Refused with `invalid_dpop_proof`, so the client
signs a fresh proof rather than refreshing a token that never expired."*

**Leave `an_anonymous_request_still_gets_the_default_deny` alone.** No
credential was presented, so nothing was refused; H1 turns it into a 401 in
Task 4 and that is where it changes.

- [ ] **Step 7: Run them and watch them pass**

Run: `cargo test -p brolly-server --test solid_token_access`
Expected: 9 passed.

- [ ] **Step 8: Format, then the workspace**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: green. Nothing outside `solid_token_access` presents a credential
that fails to verify — `pod_http`, `auth_flow` and `federation_flows` all
authenticate with a session cookie, which this task does not change.

- [ ] **Step 9: Stage, don't commit**

```bash
git add server/src/pod.rs server/src/activitypub.rs server/tests/solid_token_access.rs
```

---

### Task 2: The real method, and the undecoded URI

**Files:**
- Modify: `server/src/pod.rs` — imports, `resolve`, `subject_for`, `get`, `put`,
  `post`, `patch`, `delete`, `get_root`, `post_root`
- Modify: `server/src/activitypub.rs` — `inbox_collection`'s signature
- Modify: `server/tests/solid_token_access.rs` — the harness seed, two new tests

H15's half. `subject_for` is handed the literal `"GET"` and a URL built from
the percent-**decoded** `Path`, so a DPoP proof whose `htm` is `HEAD` — what
every correct client sends, and what CTS signs — fails verification, and any
escaped character in the path fails too. Both are silent: the caller is
downgraded to anonymous and gets the anonymous answer.

- [ ] **Step 1: Write the failing tests**

In `server/tests/solid_token_access.rs`, add beside the existing consts:

```rust
/// A resource whose path a client must percent-encode. `+` is a sub-delimiter,
/// so an encoding client sends `%2B` and a decoding server sees `+`; the two
/// spellings are both legal IRIs and they are not equal, which is what makes
/// this a test rather than a coincidence.
const DRAFT: &str = "https://alice.brolly.test/~/note+draft";
const DRAFT_PATH: &str = "/~/note%2Bdraft";
const DRAFT_URL: &str = "https://alice.brolly.test/~/note%2Bdraft";
```

and seed it in `harness()`, inside the existing `pod.write(…)` closure, after
`w.put(NOTE, …)`:

```rust
        let draft = [t(
            DRAFT,
            DRAFT,
            "https://example.org/title",
            "https://example.org/b",
        )];
        w.put(DRAFT, Content::Rdf(&draft))?;
```

Then append the two tests:

```rust
/// A correct client signs `htm: HEAD` on a HEAD. Handing the verifier the
/// literal `"GET"` made that proof fail, the caller was downgraded to
/// anonymous, and the member's own resource answered as if it did not exist —
/// so `HEAD` was unusable for exactly the cache revalidation it exists for.
/// CTS signs HEAD proofs (`read-method-allow.feature`).
#[tokio::test]
async fn a_head_is_authenticated_as_a_head() {
    let harness = harness().await;
    let key = client_key();
    let token = access_token(&harness, &key).await;

    let proof = dpop_proof(
        &key,
        "HEAD",
        NOTE,
        Some(&B64.encode(Sha256::digest(token.as_bytes()))),
    );
    let request = Request::builder()
        .method("HEAD")
        .uri("/~/note")
        .header(header::HOST, POD_HOST)
        .header(header::AUTHORIZATION, format!("DPoP {token}"))
        .header("DPoP", proof)
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&harness, request).await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body.is_empty(), "HEAD sent a body: {body}");
}

/// `htu_matches` is exact string equality after stripping query and fragment
/// (`identity/src/dpop.rs:397`), so the URL the proof is checked against has to
/// be the one the client signed. Building it from the decoded `Path` made
/// every escaped character in a path a silent authentication failure.
#[tokio::test]
async fn a_proof_is_checked_against_the_undecoded_path() {
    let harness = harness().await;
    let key = client_key();
    let token = access_token(&harness, &key).await;

    let proof = dpop_proof(
        &key,
        "GET",
        DRAFT_URL,
        Some(&B64.encode(Sha256::digest(token.as_bytes()))),
    );
    let request = Request::builder()
        .method("GET")
        .uri(DRAFT_PATH)
        .header(header::HOST, POD_HOST)
        .header(header::AUTHORIZATION, format!("DPoP {token}"))
        .header("DPoP", proof)
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&harness, request).await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body.contains("example.org/b"), "got: {body}");
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-server --test solid_token_access a_head_is a_proof_is_checked`

Expected: both fail with
`assertion `left == right` failed: left: 401, right: 200`. Task 1 is what makes
the failure loud: before it, both were a silent 404.

If `a_proof_is_checked_against_the_undecoded_path` **passes** here, axum is not
percent-decoding the wildcard `Path` in this version and the URL was already
raw; check `cargo tree -p axum` and say so in the commit message, but keep the
test — it pins the behaviour either way.

- [ ] **Step 3: Implement**

In `server/src/pod.rs`, extend the imports:

```rust
use axum::extract::{OriginalUri, Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
```

`resolve` takes the request's method and its original URI instead of a string
and a decoded path:

```rust
/// Resolve the subdomain to a user, and the credential to a [`Caller`].
///
/// Handlers never see a header. This is the only path from an HTTP request to
/// a `Subject` on the pod surface.
///
/// `uri` is the request's **original** URI, before axum's `Path` extractor
/// percent-decodes anything: `htu_matches` is exact string equality
/// (`identity/src/dpop.rs:397`), so a URL rebuilt from the decoded path fails
/// against a proof the client signed correctly (H15).
async fn resolve(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
) -> Result<PodRequest, Response> {
```

and inside it, the line that was `format!("{base}{path}")` becomes
`format!("{base}{}", uri.path())`.

`subject_for` takes a `&Method`, not a `&str`, so no caller can pass a literal
again — the whole of H15 is that one call site lying:

```rust
pub(crate) async fn subject_for(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    url: &str,
) -> Result<Caller, Refused> {
```

and the `verify_access` call passes `method.as_str()`.

Each of `get`, `put`, `post`, `patch` and `delete` gains two extractors,
**declared before `Path`**, which must stay last among the non-body ones, and
drops the literal method. `get`, in full:

```rust
pub async fn get(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Response {
    let path = format!("/~/{path}");
    let request = match resolve(&state, &headers, &method, &uri).await {
        Ok(r) => r,
        Err(response) => return response,
    };
```

`put`, `post` and `patch` keep `body: axum::body::Bytes` last of all. `delete`
matches `get`.

The root handlers pass theirs through:

```rust
pub async fn get_root(
    state: State<AppState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
) -> Response {
    get(state, method, uri, headers, Path(String::new())).await
}

pub async fn post_root(
    state: State<AppState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    post(state, method, uri, headers, Path(String::new()), body).await
}
```

`pod::options` is untouched: it takes no state and no path, and chunk 2 is what
makes it a real handler.

In `server/src/activitypub.rs`, `inbox_collection` takes the method too, for
the same reason — a `HEAD /inbox` carrying a correct proof must not be
downgraded either:

```rust
pub async fn inbox_collection(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
) -> Response {
```

with `use axum::http::Method;` added to its imports, and the call becoming
`crate::pod::subject_for(&state, &headers, &method, &inbox).await`. The inbox's
URL stays `webid::inbox(…)`, which is the canonical IRI a client signs; there
is no path parameter here to decode.

- [ ] **Step 4: Run them and watch them pass**

Run: `cargo test -p brolly-server --test solid_token_access`
Expected: 11 passed.

- [ ] **Step 5: Format, then the workspace**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: green.

- [ ] **Step 6: Stage, don't commit**

```bash
git add -u
```

---

### Task 3: `brolly-solid` splits its refusals

**Files:**
- Modify: `adapters/solid/src/ldp.rs` — `LdpError` (`:45-116`), `read`/`read_in`
  (`:232-263`), `Target::prepare` (`:402`), `put_in` (`:529`), `append_in`
  (`:771`), `delete_in` (`:869-884`), `patch_in` (`:954`)
- Modify: `adapters/solid/tests/ldp_conformance.rs`,
  `adapters/solid/tests/ldp_nonrdf.rs`, `adapters/solid/tests/acl_control.rs`

`ldp` knows the caller's modes; only `pod.rs` knows whether a credential was
presented and verified. Threading an `authenticated` flag into `ldp` would put
the credential question inside `brolly-solid`, which has no other reason to
know about tokens, and into every one of its entry points. So `ldp` reports
*which kind* of refusal it is and `pod.rs` picks the status. No `ldp` signature
changes.

**This task ends with `brolly-server` not compiling.** That is the point of
renaming `Forbidden` rather than repurposing it: every site that answered 403
for "no grant" is now a compile error instead of a silently-wrong status. Task
4 fixes it. Do not commit in between.

**The table, row for row** (line numbers as the file stands at `e7fe4f6`):

| `ldp.rs` | Today | Becomes |
|---|---|---|
| `:259` `read_in`, WAC fails | `NotFound` | `Denied` |
| `:262` `read_in`, no metadata | `NotFound` | unchanged |
| `:402` `Target::prepare`, WAC fails | `Forbidden` | `Denied` |
| `:529` `put_in` | `Forbidden` | `Denied` |
| `:771` `append_in` | `Forbidden` | `Denied` |
| `:869` `delete_in` | `Forbidden` | `Denied` |
| `:872` `delete_in`, no metadata | `NotFound` | unchanged |
| `:878` `delete_in`, storage root | `Forbidden` | `Undeletable` |
| `:883` and `:111` non-empty container | `Forbidden` | `NotEmpty` |
| `:954` `patch_in` | `Forbidden` | `Denied` |

`:402` is the one that is easy to miss and the one that matters most. It is the
pre-lock WAC check that runs for **non-RDF bodies only**, so leaving it as
`Forbidden` would make an anonymous `PUT` answer 403 for a PNG and 401 for
Turtle: the status would depend on the `Content-Type`. It is live and tested
(`adapters/solid/tests/ldp_nonrdf.rs:255`).

**Why `NotEmpty` is here and not in chunk 5.** The spec says `Undeletable`'s
only producer is the storage-root guard, and chunk 3 maps `Undeletable` to 405.
If `:883` and `:111` still produced `Undeletable` then, deleting a non-empty
container would answer 405 for the two commits between chunk 3 and chunk 5.
Introducing the variant now, mapped to today's 403, avoids that window. **The
409 and its required body are still chunk 5's**; this task changes no status.

- [ ] **Step 1: Move the assertions to the new variants**

Fifteen sites. Each is a `matches!` or an `assert_eq!` on an `Err`, so none of
them can pass by accident once the variant is renamed.

`adapters/solid/tests/ldp_conformance.rs`:

- `an_unauthorized_reader_cannot_tell_the_resource_exists` (`:220-221`): both
  become `Err(LdpError::Denied)`, and the comment becomes:

  ```rust
      // Identical responses, so probing cannot enumerate a pod. `Denied` for
      // both: the stranger holds no Read on either IRI, and H1 decides the
      // status from the modes alone, never from whether the target is there.
      assert!(matches!(missing, Err(LdpError::Denied)));
      assert!(matches!(forbidden, Err(LdpError::Denied)));
  ```

- `anonymous_writes_are_refused` (`:238`) → `LdpError::Denied`.
- `a_non_empty_container_cannot_be_deleted` (`:366`) → `LdpError::NotEmpty`.
- `append_permission_does_not_confer_replace` (`:427`) → `LdpError::Denied`.
- `a_container_with_members_cannot_be_emptied_by_put_and_then_deleted`
  (`:686`) → `LdpError::NotEmpty`.
- `the_storage_root_cannot_be_deleted` (`:696`) → `LdpError::Undeletable`.

`adapters/solid/tests/ldp_nonrdf.rs`, both inside
`wac_governs_a_binary_exactly_as_it_governs_a_graph`:

- `:241` → `Err(LdpError::Denied)`.
- `:255` → `Err(LdpError::Denied)`, with the comment
  `// The pre-lock check for a non-RDF body. If this stayed Forbidden the status would depend on the Content-Type.`

`adapters/solid/tests/acl_control.rs`, all → `LdpError::Denied`:

- `bob_cannot_read_rewrite_or_delete_the_containers_acl`: `:177` (read),
  `:192` (put), `:205` (append), `:213` (delete).
- `bob_cannot_create_the_acl_of_a_document_he_can_write`: `:255`.
- `bob_cannot_read_an_acl_of_an_acl`: `:280`.
- `an_empty_acl_governs_and_grants_nothing`: `:680`.

Then add, after `an_unauthorized_reader_cannot_tell_the_resource_exists` in
`ldp_conformance.rs`, the row of H1's table that has never had a test — the one
that makes the split worth making:

```rust
/// The third row of H1's table, and the only reason to distinguish the two
/// refusals at all: a caller who *may* read learns that there is nothing
/// there. Without this, `Denied` could quietly swallow every missing resource
/// and the owner of a pod could never tell an empty path from a broken one.
#[test]
fn a_permitted_reader_of_a_missing_resource_is_told_it_is_missing() {
    let (_m, _d, store) = pod();
    let absent = ldp::read(&store, None, BASE, "/~/does-not-exist", &alice(), None);
    assert!(matches!(absent, Err(LdpError::NotFound)), "got {absent:?}");
}
```

(`LdpOutcome` has no `Debug`, so if `{absent:?}` doesn't compile, drop the
message rather than deriving one.)

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-solid`

Expected: compile failure, `error[E0599]`: no variant or associated item named
`Denied` / `NotEmpty` / `Undeletable` found for enum `LdpError`.

- [ ] **Step 3: Split the enum**

In `adapters/solid/src/ldp.rs`, replace the `Forbidden` variant with three:

```rust
#[derive(Debug)]
pub enum LdpError {
    /// The caller does not hold the mode this operation needs.
    ///
    /// Deliberately distinct from [`LdpError::NotFound`], which now means only
    /// *the caller holds the mode and there is nothing there*. `pod.rs` turns
    /// this into 401 or 403 from its own knowledge of the credential, which is
    /// the one thing this crate has no reason to know (spec 5b, H1).
    ///
    /// **It never depends on whether the resource exists.** Effective modes
    /// come from the nearest ACL up the path, which exists whether or not the
    /// resource does, so an unauthenticated caller sees the same refusal for
    /// `/~/secret` and `/~/does-not-exist` and cannot tell them apart.
    Denied,
    /// The caller holds the mode and there is nothing at this IRI.
    NotFound,
    Syntax(SyntaxError),
    Store(String),
    /// A write inside `/~/` that is not addressed to the storage root.
    OutsideStorage,
    /// The target takes RDF only: a container, an ACL, a PATCH of a binary,
    /// or a POST appending to a document.
    NotRdf,
    /// A container PUT whose `ldp:contains` triples don't name exactly the
    /// container's current members. Membership changes only by creating or
    /// deleting members (Solid Protocol §5.3).
    ContainmentChange,
    /// The storage root, which a pod cannot be without. Solid Protocol §5.4
    /// names it and the root's own ACL as the two resources a server must
    /// refuse to delete. 5b's chunk 3 answers it 405 with an `Allow`; until
    /// then it keeps stage 0's 403.
    Undeletable,
    /// A container that still has members. Not "you may not" — "not while it
    /// has members". 5b's chunk 5 answers it 409 *with a body describing the
    /// error*, which §5.4 requires; until then it keeps stage 0's 403.
    NotEmpty,
    /// A binary's bytes vanished between `prepare` and the write: a
    /// concurrent delete released identical bytes. Prepare again and retry
    /// once (spec 5a, R12).
    BlobMissing,
    /// An `If-Match` or `If-None-Match` didn't hold (412). Evaluated after WAC,
    /// so only a caller holding the needed mode can see it.
    PreconditionFailed,
}
```

In the `Display` impl, replace the `Forbidden` arm with:

```rust
            LdpError::Denied => write!(f, "no grant for this operation"),
            LdpError::Undeletable => write!(f, "this resource cannot be deleted"),
            LdpError::NotEmpty => write!(f, "this container still has members"),
```

In `From<StoreError>` (`:111`):

```rust
            // Stage 0's answer to a populated container, until 5b's chunk 5
            // turns it into a 409 with a body.
            StoreError::ContainerNotEmpty => LdpError::NotEmpty,
```

- [ ] **Step 4: Move each refusal site**

`read` and `read_in`'s doc comment (`:232-236`) becomes:

```rust
/// `GET` / `HEAD` an LDP resource, from one snapshot.
///
/// A caller without Read gets [`LdpError::Denied`], not `NotFound`: telling
/// them the resource exists would be a disclosure, and so would telling them
/// it doesn't. `pod.rs` answers both with the same status for the same caller,
/// so the two are indistinguishable from outside (spec 5b, H1).
```

Then, in order: `:259` → `LdpError::Denied`; `:402` → `LdpError::Denied`;
`:529` → `LdpError::Denied`; `:771` → `LdpError::Denied`; `:954` →
`PatchError::Ldp(LdpError::Denied)`.

In `delete_in`, the two guards after the precondition:

```rust
    // Without its root a pod has nowhere to put anything, and only
    // provisioning records one. Solid Protocol §5.4; chunk 3 answers 405.
    if resource == storage_root {
        return Err(LdpError::Undeletable);
    }
    // Refusing to delete a non-empty container is LDP's rule, and it is the
    // difference between removing a resource and silently orphaning a subtree.
    // Chunk 5 answers 409 with the body §5.4 requires.
    if matches!(meta.kind, Kind::Container) && !w.members(&resource)?.is_empty() {
        return Err(LdpError::NotEmpty);
    }
```

with `:869` (the WAC check above them) → `LdpError::Denied`.

Also update `granted_modes`' and `Target::prepare`'s doc comments where they
say "Forbidden": `Target::prepare`'s third bullet becomes *"WAC is checked
against the committed store before any bytes land, so a caller who may not
write leaves nothing in the blob store and gets `Denied` whatever the body's
type."*

- [ ] **Step 5: Run the adapter tests and watch them pass**

Run: `cargo test -p brolly-solid`
Expected: green, including the new
`a_permitted_reader_of_a_missing_resource_is_told_it_is_missing`.

- [ ] **Step 6: See the server fail loudly**

Run: `cargo check -p brolly-server`

Expected: `error[E0599]: no variant named `Forbidden` found for enum
`LdpError`` at `server/src/pod.rs:223`, and a non-exhaustive-match error for
the three new variants. This is the whole reason the variant was renamed rather
than reused. Task 4 is next; **do not commit here.**

- [ ] **Step 7: Stage, don't commit**

```bash
git add -u
```

---

### Task 4: `pod.rs` answers 401, 403 and 404

**Files:**
- Modify: `server/src/pod.rs` — `ldp_error` (`:218-252`), its five call sites,
  `mod tests`
- Modify: `server/tests/pod_http.rs` — `an_anonymous_reader_gets_nothing`
  (`:273`), `a_binary_is_invisible_to_a_caller_without_read` (`:530`),
  `wac_allow_on_an_acl_names_nothing_for_bob` (`:1030`), plus seven new tests
- Modify: `server/tests/solid_token_access.rs` —
  `an_anonymous_request_still_gets_the_default_deny`

H1's table, at the only place that knows both halves:

| Caller | *M* ∈ *G* | Resource exists | Answer |
|---|---|---|---|
| unauthenticated | no | either | **401** + `WWW-Authenticate` |
| authenticated | no | either | **403** |
| either | yes | no | **404** |
| either | yes | yes | proceed |

- [ ] **Step 1: Write the failing tests**

First, in `server/src/pod.rs`'s `mod tests`, change
`the_new_ldp_refusals_have_status_codes` to the three-argument `ldp_error` and
append four more:

```rust
    /// 5a uses the codes `pod.rs` already has; 5b revisits them.
    #[test]
    fn the_new_ldp_refusals_have_status_codes() {
        let apex = "https://brolly.test";
        assert_eq!(
            ldp_error(LdpError::NotRdf, true, apex).status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            ldp_error(LdpError::ContainmentChange, true, apex).status(),
            StatusCode::CONFLICT,
            "Solid Protocol §5.3"
        );
        assert_eq!(
            ldp_error(LdpError::BlobMissing, true, apex).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    /// H1's table at the only place that knows both halves. The failure this
    /// guards is a `Denied` answered 403 to a caller who never presented a
    /// credential: they are told "no" with nothing they can do about it, which
    /// is exactly the state an app with an expired token is in.
    #[test]
    fn a_denial_is_401_or_403_by_whether_the_caller_authenticated() {
        let apex = "https://brolly.test";
        assert_eq!(
            ldp_error(LdpError::Denied, false, apex).status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ldp_error(LdpError::Denied, true, apex).status(),
            StatusCode::FORBIDDEN
        );
    }

    /// Nothing was presented, so nothing was found fault with: RFC 6750 §3.1
    /// defines `error` only for a credential that *was* sent. An `error` here
    /// would tell an anonymous prober something about a credential it never
    /// had.
    #[test]
    fn the_challenge_on_a_denial_names_no_error() {
        let response = ldp_error(LdpError::Denied, false, "https://brolly.test");
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            r#"DPoP algs="ES256", as_uri="https://brolly.test""#
        );
    }

    /// The disclosure boundary, from the other side: `NotFound` is the only
    /// variant that may become a 404, because it is the only one `ldp` emits
    /// after the caller has been allowed to know.
    #[test]
    fn only_a_permitted_caller_can_be_told_a_resource_is_missing() {
        let apex = "https://brolly.test";
        assert_eq!(
            ldp_error(LdpError::NotFound, false, apex).status(),
            StatusCode::NOT_FOUND
        );
        assert_ne!(
            ldp_error(LdpError::Denied, true, apex).status(),
            StatusCode::NOT_FOUND
        );
    }

    /// Chunk 3 makes the first a 405 with an `Allow`, and chunk 5 makes the
    /// second a 409 with a body. Pinned at today's answer so this chunk is
    /// provably a no-op for them — if either moves early, a `DELETE` of a
    /// populated container starts claiming the method isn't allowed.
    #[test]
    fn the_undeletable_root_and_the_populated_container_still_answer_403() {
        let apex = "https://brolly.test";
        assert_eq!(
            ldp_error(LdpError::Undeletable, true, apex).status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            ldp_error(LdpError::NotEmpty, true, apex).status(),
            StatusCode::FORBIDDEN
        );
    }
```

Then, in `server/tests/pod_http.rs`, rewrite the three tests H1 moves. Keep
their names: each is still true, and the history of each assertion is easier to
follow under one name.

`an_anonymous_reader_gets_nothing` (`:272-284`):

```rust
/// The failure this guards is a member's own resource vanishing when it should
/// ask them to authenticate. An app whose access token expired mid-session used
/// to get a 404 and conclude the note had been deleted. H1 answers 401, with a
/// challenge it can act on.
///
/// Stage 0's A2 rule gave 404 so that existence wasn't disclosed. That
/// guarantee still holds, and
/// `an_anonymous_refusal_is_the_same_for_a_real_and_a_fictive_resource` pins
/// it. The 401 is the same whether the resource is there or not.
#[tokio::test]
async fn an_anonymous_reader_gets_nothing() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (status, body, headers) = h.send("GET", "/~/note", None, false).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!body.contains("Written over HTTP"), "got: {body}");
    let challenge = headers[header::WWW_AUTHENTICATE].to_str().unwrap();
    assert!(challenge.starts_with("DPoP "), "got: {challenge}");
    assert!(
        challenge.contains(r#"as_uri="https://brolly.test""#),
        "Solid-OIDC §9.1 makes as_uri a MUST: {challenge}"
    );
    assert!(
        !challenge.contains("error="),
        "nothing was presented, so nothing was refused: {challenge}"
    );
}
```

`a_binary_is_invisible_to_a_caller_without_read` (`:529-544`): the final
assertion becomes

```rust
    let (status, body, _) = h.send("GET", "/~/private.pdf", None, false).await;
    // 401, not the bytes. The same refusal as for a graph: a binary is not a
    // side door around WAC.
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!body.contains("%PDF"), "the bytes leaked: {body}");
```

`wac_allow_on_an_acl_names_nothing_for_bob` (`:1029-1050`): only Bob's half
changes. Rewrite it and give the test a doc comment:

```rust
/// Bob has authenticated and lacks Control, so he gets 403 (H1). A 401 would
/// ask him for a credential he has already presented. What must never happen
/// is a mode appearing in `WAC-Allow` on an ACL he can't read, because that
/// would be an edit affordance the next request refuses.
#[tokio::test]
async fn wac_allow_on_an_acl_names_nothing_for_bob() {
    let h = harness().await;
    share_with_bob(&h);
    let bob = member_session(&h, "bob").await;

    let (status, _, headers) = send_as(&h, &bob, "GET", "/~/shared/.acl", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        headers.get(header::WWW_AUTHENTICATE).is_none(),
        "Bob has already authenticated"
    );
```

Leave the rest of that test alone. That includes the `WAC-Allow` assertions and
the owner's exact `user="read write append control"`. Chunk 4 adds `public=` to
that string.

**These do not change.** `bob_cannot_patch_an_acl_he_does_not_control`,
`bob_cannot_put_an_acl_he_does_not_control` and
`bob_cannot_delete_an_acl_he_does_not_control` already assert 403, and Bob
remains an authenticated caller without Control, so 403 is still correct.
`an_anonymous_caller_cannot_read_an_inbox` (`:719`) stays at 404, because the
inbox keeps its own rule (Task 1, Step 5). It now guards that rule against
H1's table. The two docstrings that say "`ldp::put` refuses with `Forbidden`"
(`:972-973`) and "`ldp::delete` refuses with `Forbidden` before it looks for
the resource" (`:1008-1010`) should say `Denied` instead. The behaviour they
describe is unchanged.

Next, append the new tests after `wac_allow_on_an_acl_names_nothing_for_bob`
under a section header:

```rust
// --- refusals (stage 5b, H1–H3) -------------------------------------------------

/// This is the core of H1's safety argument: the status depends on the
/// caller's effective modes, never on whether the target exists. If these two
/// responses ever differed, the pod would be an existence oracle for anyone on
/// the internet.
#[tokio::test]
async fn an_anonymous_refusal_is_the_same_for_a_real_and_a_fictive_resource() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (real, real_body, real_headers) = h.send("GET", "/~/note", None, false).await;
    let (fictive, fictive_body, fictive_headers) =
        h.send("GET", "/~/no-such-note", None, false).await;

    assert_eq!(real, StatusCode::UNAUTHORIZED);
    assert_eq!(fictive, StatusCode::UNAUTHORIZED);
    assert_eq!(real_body, fictive_body);
    assert_eq!(
        real_headers.get(header::WWW_AUTHENTICATE),
        fictive_headers.get(header::WWW_AUTHENTICATE)
    );
}

/// The same argument for a caller who *did* authenticate: 403, and again the
/// same answer whether the resource exists or not. CTS checks this
/// (`read-access-public.feature`: public → 401, Bob → 403).
#[tokio::test]
async fn a_member_without_access_is_forbidden_rather_than_challenged() {
    let h = harness().await;
    let bob = member_session(&h, "bob").await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    for path in ["/~/note", "/~/no-such-note"] {
        let (status, _, headers) = send_as(&h, &bob, "GET", path, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert!(
            headers.get(header::WWW_AUTHENTICATE).is_none(),
            "{path}: a challenge Bob has already satisfied"
        );
    }
}

/// This is why the split exists. Only a caller who may read learns the
/// difference between empty and refused, and that is the information they
/// need. CTS: a *permitted* caller reading a fictive resource gets 404.
#[tokio::test]
async fn a_permitted_reader_of_a_missing_resource_gets_a_404() {
    let h = harness().await;
    let (status, _, headers) = h.send("GET", "/~/no-such-note", None, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(headers.get(header::WWW_AUTHENTICATE).is_none());
}

/// The status must not depend on the `Content-Type`. `Target::prepare`'s WAC
/// check runs only for a non-RDF body. If it still returned `Forbidden`, an
/// anonymous PNG would get 403 while anonymous Turtle got 401. That second
/// code path is easy to miss, so this pins both paths.
#[tokio::test]
async fn an_anonymous_write_is_challenged_whatever_its_body() {
    let h = harness().await;
    for (content_type, body) in [("text/turtle", NOTE), ("application/pdf", PDF)] {
        let (status, _, headers) = h
            .send("PUT", "/~/anonymous", Some((content_type, body)), false)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{content_type}");
        assert!(
            headers.contains_key(header::WWW_AUTHENTICATE),
            "{content_type}"
        );
    }
}

/// H2 applies only to the `Authorization` header. `brolly_session` is
/// `SameSite=Lax`, so a browser sends it on any top-level navigation. A
/// logged-out member opening a public image in their own pod would otherwise be
/// challenged for a credential they never offered. The missing `error=` shows
/// that the stale cookie was treated as no credential at all.
#[tokio::test]
async fn a_stale_cookie_falls_through_to_anonymous() {
    let h = harness().await;
    let (status, _, headers) = run(
        h.router.clone(),
        conditional_request("GET", "/~/note", None, Some("not-a-session"), &[]),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let challenge = headers[header::WWW_AUTHENTICATE].to_str().unwrap();
    assert!(
        !challenge.contains("error="),
        "a cookie the browser sent unasked is not a presented credential: {challenge}"
    );
}

/// The other side of that line: an `Authorization` header *is* a presented
/// credential, so one we can't parse is refused rather than ignored. This
/// guards against a client with a broken header looking exactly like a client
/// with none, and never learning why it sees nothing. A session cookie sent
/// alongside the header does not rescue it, because the explicit header is
/// the one the client meant (`extract::credential`'s precedence).
#[tokio::test]
async fn an_authorization_header_we_cannot_parse_is_refused() {
    let h = harness().await;
    let (status, _, headers) = run(
        h.router.clone(),
        conditional_request(
            "GET",
            "/~/note",
            None,
            Some(h.session.as_str()),
            &[("authorization", "Basic cGxlYXNl")],
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let challenge = headers[header::WWW_AUTHENTICATE].to_str().unwrap();
    assert!(challenge.contains(r#"error="invalid_token""#), "got: {challenge}");
}

/// H2 applies to the inbox too. Without it, a client whose credential no
/// longer verifies is downgraded to anonymous, fails the owner check, and is
/// told its member's inbox does not exist.
#[tokio::test]
async fn a_broken_credential_on_the_inbox_is_challenged_not_hidden() {
    let h = harness().await;
    let request = Request::builder()
        .method("GET")
        .uri("/inbox")
        .header(header::HOST, HOST)
        .header(header::ACCEPT, "application/activity+json")
        .header(header::AUTHORIZATION, "DPoP not-a-token")
        .body(Body::empty())
        .unwrap();
    let response = h.router.clone().oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let challenge = response.headers()[header::WWW_AUTHENTICATE]
        .to_str()
        .unwrap();
    assert!(challenge.contains(r#"error="invalid_token""#), "got: {challenge}");
}
```

`a_broken_credential_on_the_inbox_is_challenged_not_hidden` already passes
after Task 1. It is added here, with the rest of H1–H3's HTTP tests, so the
refusal tests live in one place in `pod_http.rs`.

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-server --lib pod::`

Expected: compile failure. `error[E0599]`: no variant named `Forbidden` found
for enum `LdpError` at `server/src/pod.rs:223`. `error[E0004]`: non-exhaustive
patterns: `LdpError::Denied`, `LdpError::Undeletable` and `LdpError::NotEmpty`
not covered. `error[E0061]`: `ldp_error` takes 1 argument but 3 were supplied.

`pod_http` can't run until `brolly-server` compiles, so its failures appear
after Step 3 if anything is wrong. Do not skip Step 4.

- [ ] **Step 3: Implement `ldp_error`**

Replace `ldp_error`'s signature and its first two arms:

```rust
/// Turn a refusal from `ldp` into a response.
///
/// `authenticated` and `apex` are what this layer knows and `ldp` doesn't:
/// whether a credential was presented and verified, and where to send a
/// caller who has to get one. Together with [`LdpError::Denied`], they give
/// H1's table:
///
/// | Caller | Holds the mode | Exists | Answer |
/// |---|---|---|---|
/// | unauthenticated | no | either | 401 + `WWW-Authenticate` |
/// | authenticated | no | either | 403 |
/// | either | yes | no | 404 |
///
/// The status never depends on whether the target exists. That replaces
/// stage 0's A2 rule, "a caller without the required mode gets `NotFound`",
/// while keeping what that rule protected. An unauthenticated caller gets 401
/// for `/~/secret` and for `/~/does-not-exist` and can't tell them apart. An
/// authenticated one gets 403 for both.
fn ldp_error(error: LdpError, authenticated: bool, apex: &str) -> Response {
    match error {
        LdpError::Denied if authenticated => {
            (StatusCode::FORBIDDEN, "forbidden").into_response()
        }
        // No credential, or a cookie that no longer resolves. Credentials that
        // were presented and failed were refused in `resolve`, before WAC ran,
        // with their own `error=` (H2).
        LdpError::Denied => challenge_response(dpop_challenge(apex, None)),
        // Only a caller who holds the mode ever gets here; see `ldp::read`.
        LdpError::NotFound => (StatusCode::NOT_FOUND, "not found").into_response(),
        // Stage 0's 403, unchanged by this chunk. 5b's chunk 3 makes this 405
        // with an `Allow` (H12, H16).
        LdpError::Undeletable => (
            StatusCode::FORBIDDEN,
            "the storage root cannot be deleted",
        )
            .into_response(),
        // Stage 0's 403, unchanged by this chunk. 5b's chunk 5 makes this 409
        // with a body describing the problem, which Solid Protocol §5.4
        // requires.
        LdpError::NotEmpty => (
            StatusCode::FORBIDDEN,
            "a container with members cannot be deleted",
        )
            .into_response(),
```

The remaining arms (`OutsideStorage` through `Store`) stay as they are.

Then update the call sites. There are five of them, in `get`, `put`, `post`,
`delete` and `patch`'s `PatchError::Ldp` arm:

```rust
        Err(e) => return ldp_error(e, request.authenticated, &request.apex),
```

(or without `return`, as each site already has it). In `get`, the comment
above the ETag also changes, because it describes the old refusal:

```rust
    // After `read` succeeded, so after the Read check, and against the version
    // from the same snapshot as the body. A caller without Read was refused
    // above, 401 or 403, whatever they sent.
```

`patch`'s own `PatchError::EscapesGraph` arm keeps its 403. It isn't a WAC
decision: a PATCH that names a `GRAPH` or `WITH` is refused whoever sends it.
H1's table doesn't cover it.

- [ ] **Step 4: Run them and watch them pass**

Run: `cargo test -p brolly-server --lib pod::`
Expected: 9 passed.

Run: `cargo test -p brolly-server --test pod_http`
Expected: all pass, including the seven new tests.

- [ ] **Step 5: The anonymous token test**

In `server/tests/solid_token_access.rs`, rewrite
`an_anonymous_request_still_gets_the_default_deny`. Its old 404 was stage 0's
disclosure rule, and it is now H1's first row:

```rust
/// Without a credential, a resource that isn't public gets a challenge. The
/// member's note is still not disclosed: the challenge is identical for a note
/// that doesn't exist (`pod_http.rs`,
/// `an_anonymous_refusal_is_the_same_for_a_real_and_a_fictive_resource`).
#[tokio::test]
async fn an_anonymous_request_still_gets_the_default_deny() {
    let harness = harness().await;
    let (status, challenge) = challenged(&harness, read_note(None, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        challenge,
        format!(r#"DPoP algs="ES256", as_uri="https://{BASE_DOMAIN}""#)
    );
}
```

The module docstring (`:1-8`) says `subject_for` "mapped every Bearer and DPoP
credential to anonymous and an app with a perfectly good token got a 404". Add
a sentence after it: *"Since 5b, a credential that doesn't verify is a 401
naming what was wrong with it (H2), not a quiet downgrade."*

Run: `cargo test -p brolly-server --test solid_token_access`
Expected: 11 passed.

- [ ] **Step 6: Format, then the workspace**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: green. If anything outside the files this chunk lists fails on a 404
that is now a 401 or 403, it is an anonymous or unauthorized pod read that the
survey missed. Move it to the H1 row it belongs to, and give it a doc comment
explaining which row that is. Don't loosen it to accept either status.

- [ ] **Step 7: Stage, don't commit**

```bash
git add -u
```

---

### Task 5: The stage 0 rule, the gates, and the commit

**Files:**
- Modify: `docs/specs/2026-09-17-security-fixes.md:240-241`

- [ ] **Step 1: Say where stage 0's refusal rule went**

Stage 0's A2 says *"a caller without the required mode gets `NotFound`, so
existence isn't disclosed"*. After this commit that is no longer true, and a
reader who trusts it will write a test that fails. Leave the paragraph as it
is, because it records what stage 0 decided, and add one line after it:

```markdown
**Superseded in stage 5b** (`docs/specs/2026-09-23-solid-http-surface.md`,
H1): a caller without the mode gets 401 if unauthenticated and 403 if not,
the same for a resource that exists and one that doesn't. Existence is still
not disclosed; only a caller who holds the mode can get a 404.
```

- [ ] **Step 2: The gates, one at a time**

Run each command separately, waiting for each to finish. **Never run two
test suites at once**: the Postgres containers collide, and the failures look
real.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
./tools/check-doc-paths.sh
cargo deny check
cargo test --workspace
```

Expected: all five pass. No `Cargo.toml` changes, so `cargo deny check` should
report exactly what it reported at `e7fe4f6`. It is run anyway because the
chunk's gate list names it.

- [ ] **Step 3: Check what's staged**

```bash
git add -u
git status
```

Expected, and nothing else:

```
modified:   adapters/solid/src/ldp.rs
modified:   adapters/solid/tests/acl_control.rs
modified:   adapters/solid/tests/ldp_conformance.rs
modified:   adapters/solid/tests/ldp_nonrdf.rs
modified:   docs/specs/2026-09-17-security-fixes.md
modified:   server/src/activitypub.rs
modified:   server/src/pod.rs
modified:   server/tests/pod_http.rs
modified:   server/tests/solid_token_access.rs
```

- [ ] **Step 4: Commit to `main`**

```bash
git commit -F - <<'MSG'
feat(solid): 401 and 403 instead of silent anonymity and 404

A refusal now depends on the caller's effective modes and on whether a
credential verified, never on whether the resource exists. The results:
unauthenticated and denied is 401 with a WWW-Authenticate challenge;
authenticated and denied is 403; permitted and missing is 404. Existence
is still not disclosed: an anonymous caller gets the same 401 for a
secret and for nothing at all. This replaces stage 0's A2 rule, which
answered every refusal 404.

ldp reports which refusal it was. LdpError::Denied (the caller lacks
the mode) is split from NotFound (the caller holds it and there's
nothing there), and pod.rs picks 401 or 403, because only pod.rs knows
whether a credential was presented. Forbidden is renamed Undeletable,
for the storage root. NotEmpty takes over the populated-container
refusal. Both still answer 403. Their 405 and 409 come later in 5b.

An Authorization header that doesn't verify is refused on the spot
instead of being retried as anonymous. The error is invalid_token for
the token and invalid_dpop_proof for the proof, so a client with a good
token and a bad proof doesn't loop on refreshes. A bare bearer that
resolves to nobody gets a Bearer challenge. The DPoP challenge carries
algs="ES256" and as_uri, the instance's issuer. A session cookie that
no longer resolves is still anonymous, since a SameSite=Lax cookie the
browser sent unasked is not a presented credential.

subject_for is given the request's real method and its undecoded URI.
A HEAD signed as HEAD authenticates, and an htu with a percent-escape
matches. Before this, both were silently anonymous.

The ActivityPub inbox keeps its 404 for a non-owner, but a credential
that doesn't verify is a 401 there too.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
MSG
```

- [ ] **Step 5: Verify from a clean checkout**

Run this only when nothing else is testing:

```bash
rm -rf /tmp/verify && git worktree add --detach /tmp/verify HEAD
cd /tmp/verify && cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && ./tools/check-doc-paths.sh && cargo deny check && cargo test --workspace
cd - && git worktree remove /tmp/verify --force
```

The commit isn't done until that passes.

### Notes for the reviewer

- **The spec's list of tests that change is short.** It names `pod_http.rs`
  and five sites in `adapters/solid/tests`. This chunk also moves
  `server/tests/solid_token_access.rs`, where eight tests assert today's silent
  404 for a bad or absent credential, and `acl_control.rs`, where seven sites
  match on `Forbidden` or `NotFound` for a refused read or write. It also
  moves `ldp_conformance.rs:427`, `:686` and `:696`. All of these fail loudly
  (renamed variant, or a status assertion), so none of them could have been
  missed quietly.
- **`NotEmpty` lands here, not in chunk 5.** The spec's chunk list puts it
  with the 409. But the brief says `Undeletable`'s only remaining producer is
  the root guard, and chunk 3 maps `Undeletable` to 405. Leaving the
  non-empty-container sites on `Undeletable` would make them 405 for the two
  commits between chunk 3 and chunk 5. The variant arrives here mapped to 403.
  The 409 and its body are still chunk 5's.
- **A database failure while verifying is a 500** (`Refused::Unavailable`).
  The spec doesn't cover it. Today it is silent anonymity. 401 would tell a
  client its good token is bad, and anonymity would give it the anonymous
  answer to a question it asked with a credential.
- **An `Authorization` header we can't parse** (`Basic …`, no space, not
  UTF-8) is `invalid_token` in the `DPoP` form. H2's table puts "malformed
  header" under `invalid_token`. The `DPoP` scheme follows from H3's rule that
  only a bare *bearer* gets a `Bearer` challenge.
- **A valid token for a WebID we don't host** is `invalid_token`. It used to
  fall through to anonymous. Stage 6 accepts other issuers and revisits this.
- **The pod is resolved before the credential,** so a bad credential sent to a
  subdomain with no member is 404, not 401. That is a routing answer, like
  `subdomain_fallback`'s.
- **The inbox takes `Method` too.** H15 names only `subject_for`'s signature
  there. Passing the literal `"GET"` would repeat the bug H15 fixes, for
  `HEAD /inbox`. It needs no `OriginalUri`: its URL is the canonical inbox IRI,
  with no path parameter to decode.
- **A browser can't read `WWW-Authenticate` yet.** It isn't CORS-safelisted,
  and adding it to `Access-Control-Expose-Headers` is chunk 4's H14. Until
  then a cross-origin app sees the 401 but not the challenge.
- **`OPTIONS` is still static and unauthenticated.** Chunk 2 makes it a real
  handler with H4's any-mode gate.
- **`PATCH` with `GRAPH`/`WITH` stays 403 whoever sends it.** That is a
  refusal of the request's shape, not a WAC decision, so H1's table doesn't
  cover it.

---

## Chunk 2: `describe` and the shared header builder

Spec `docs/specs/2026-09-23-solid-http-surface.md`, decisions **H4**
(`Allow`, per resource and per caller) and **H5** (`Accept-Patch`,
`Accept-Post`, `Accept-Put`), plus the two pieces of the change table that H6,
H9 and H10 will build on: **`ldp::describe`** and **`Subject::anonymous()`**.

This is **one commit on `main`**, on top of chunk 1. Chunk 1 has landed:
`LdpError::Denied` exists, `subject_for` reports whether a credential
verified, and `pod.rs` answers 401 or 403 from that. Nothing here changes a
status code; it changes what a 2xx *says*.

Four tasks, one commit (Task 4 commits). Tasks 1 and 2 leave the workspace
green. Task 3 adds HTTP tests that fail until Task 4, so don't commit before
then.

**What changes:**

| File | Change |
|---|---|
| `identity/src/subject.rs` | `Subject::anonymous()`, replacing the inline construction `pod.rs` makes privately |
| `adapters/solid/src/ldp.rs` | `Description` and `describe` / `describe_in`: a body-free per-resource read carrying existence, kind, version, modified time, `granted` and `public`. The anonymous probe runs inside the snapshot. `read_in` is rebuilt on it, and `LdpOutcome` carries the `Description` instead of its own `granted` and `is_container`. `served_types()` deleted, and `WriteFormat` leaves the import |
| `server/src/pod.rs` | `allowed`, `undeletable`, `accept_put`, `affordances`, `apply`: H4's `Allow` and H5's `Accept-*`, built once and used by `OPTIONS`, `GET` and `HEAD`. `options` becomes a stateful handler; `options_root` joins `get_root` and `post_root` |
| `server/src/lib.rs` | `/~/` routes `OPTIONS` to `pod::options_root` |
| `adapters/solid/tests/ldp_conformance.rs`, `ldp_nonrdf.rs`, `acl_control.rs` | `out.granted` → `out.description.granted`, `out.is_container` → `out.description.is_container()`; new tests for `describe` |
| `server/tests/pod_http.rs` | the H4 and H5 tests; `options_advertises_the_patch_formats` rewritten |

**Not in this chunk.** The 401/403 split (chunk 1, landed). `Link` headers,
`acl_iri`, the storage description, `Allow` on our own 405s, `/~/` gaining the
write methods (chunk 3). `WAC-Allow`'s `public=` actually being *emitted*,
`Vary`, the syntax-tagged ETag, the fuller 304, CORS (chunk 4) — but
`Description` already carries `public`, and `LdpOutcome` already carries the
`Description`, so chunk 4 is a `pod.rs`-only change. 201 on create, 409s,
container listings, `Content-Type` required (chunk 5).

### Interfaces assumed from chunk 1

This was written without chunk 1 in view. Before editing `server/src/pod.rs`,
open it and confirm these, and adapt **names, not behaviour**:

1. `LdpError::Denied` exists and means *the caller does not hold the mode*.
   `LdpError::NotFound` still means *the caller holds the mode and there is
   nothing there*.
2. `pod.rs` has one function that turns an `LdpError` into a `Response` and
   knows whether a credential verified. At f564eb6 it was
   `fn ldp_error(error: LdpError) -> Response`; chunk 1 gives it access to that
   bit, whether by a second parameter, by taking `&PodRequest`, or by a method
   on `PodRequest`. **This chunk calls it exactly the way `pod::get` calls
   it**, so wherever this plan writes `ldp_error(e)` or
   `ldp_error(LdpError::Denied)`, spell it the way `get`'s
   `Err(e) => return ldp_error(e)` arm is spelled after chunk 1.
3. `resolve` still returns `Result<PodRequest, Response>` and `PodRequest`
   still has `pod`, `subject`, `base` and `storage_root`. Chunk 1 changed how
   it is *called* (H15: the real method, the undecoded URI, so the handlers
   gained `axum::http::Method` and `OriginalUri` extractors declared before
   `Path`). **The new `options` handler copies `get`'s extractor list and its
   `resolve` call verbatim, changing only the method it reports.** If chunk 1
   left `get` taking `method: Method`, `options` takes it too; if chunk 1
   hard-codes the method string per handler, `options` passes `"OPTIONS"`.
4. `wac_allow(&[AccessMode]) -> String` is unchanged and still emits only
   `user="…"`. Chunk 4 gives it `public=`.

Nothing in chunk 1 touches `adapters/solid/src/ldp.rs`'s `read_in` beyond
turning its two WAC refusals into `Denied`, so Task 2 applies as written.

### Task 1: `Subject::anonymous()`

**Files:**
- Modify: `identity/src/subject.rs`: the `impl Subject` block (`:86-109`), the
  test module (`:111-146`)
- Modify: `server/src/pod.rs`: `subject_for`'s inline `anonymous` (`:101-107`)

- [ ] **Step 1: Write the failing tests**

In `identity/src/subject.rs`, add to `mod tests`:

```rust
    /// The pod, the ActivityPub inbox and `ldp::describe`'s `public=` probe
    /// each need "nobody". Three private copies of this struct literal is how
    /// one of them ends up with a `webid` of `Some("")`, which `authorize`
    /// would then match against `acl:agent`.
    #[test]
    fn an_anonymous_subject_authorizes_as_nobody() {
        let nobody = Subject::anonymous();
        assert_eq!(nobody.agent(), brolly_authz::Agent::Anonymous);
        assert_eq!(nobody.webid, None, "a WebID is what grants match on");
        assert_eq!(nobody.user_id, None);
        assert_eq!(nobody.did, None);
        assert!(nobody.scope.as_slice().is_empty(), "no scope is granted");
    }
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p brolly-identity --lib subject::tests::an_anonymous_subject_authorizes_as_nobody`

Expected: compile failure, `error[E0599]`: no function or associated item
named `anonymous` found for struct `Subject`.

- [ ] **Step 3: Implement**

In `identity/src/subject.rs`, add to `impl Subject`, above `agent()`:

```rust
    /// Nobody: no credential was presented, or the one that was did not
    /// resolve to a person.
    ///
    /// `via` is `Via::Session` because it has to be something; it is kept for
    /// audit and for the few decisions that differ by scheme, and an anonymous
    /// subject makes none of them. What matters is `webid: None`, which makes
    /// [`Subject::agent`] `Agent::Anonymous`, so only
    /// `acl:agentClass foaf:Agent` can grant it anything.
    ///
    /// Used twice for different reasons: `pod.rs` falls back to it when a
    /// request carries no credential, and `ldp::describe` probes with it to
    /// find out what the *public* may do with a resource (spec 5b, H9).
    pub fn anonymous() -> Self {
        Self {
            user_id: None,
            did: None,
            webid: None,
            scope: Scope::default(),
            via: Via::Session,
        }
    }
```

- [ ] **Step 4: Run it and watch it pass**

Run: `cargo test -p brolly-identity --lib subject::tests`
Expected: 4 passed.

- [ ] **Step 5: Use it in `pod.rs`**

In `server/src/pod.rs::subject_for`, replace the inline literal (`:101-107`):

```rust
    let anonymous = Subject {
        user_id: None,
        did: None,
        webid: None,
        scope: Scope::default(),
        via: Via::Session,
    };
```

with:

```rust
    let anonymous = Subject::anonymous();
```

Chunk 1 may have moved this block or renamed the binding; replace whatever
literal it left, keeping its name. `Scope` and `Via` may now be unused in
`pod.rs`'s import list (`:14`) — if clippy says so, drop them; if chunk 1's
code still names them, keep them.

- [ ] **Step 6: Gates**

```bash
cargo fmt --all
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings
cargo test -p brolly-identity
```

- [ ] **Step 7: Stage, don't commit**

```bash
git add identity/src/subject.rs server/src/pod.rs
```

### Task 2: `ldp::describe`, and `read` rebuilt on it

**Files:**
- Modify: `adapters/solid/src/ldp.rs`: the import list (`:32`, `:35-37`),
  `LdpOutcome` (`:133-148`), `read_in` (`:249-315`), `served_types` (`:1013-1023`)
- Modify: `adapters/solid/tests/ldp_conformance.rs` (`:148`, `:462`, `:471`,
  and a new section at the end)
- Modify: `adapters/solid/tests/acl_control.rs` (`:302`, `:396`, `:399`)
- Modify: `adapters/solid/tests/ldp_nonrdf.rs` (a new test at the end)

**Why `describe` has to exist.** `Pod::read` drops its transaction when the
closure returns (`store/src/resources.rs:307-315`). A header builder in
`pod.rs` therefore runs *after* the snapshot is closed: every question it asks
— does this exist, what kind is it, what may the public do with it — would be
asked of a different pod than the one whose body it is describing. So the
questions are asked inside the snapshot and the answers ride out together.

**Why it isn't a second `read_in`.** `describe_in` is exactly `read_in` minus
the Read check, minus the body and minus the blob store; `read_in` then calls
it and takes the metadata from what it returns. Neither function reads a
resource's metadata twice, and there is one place where `granted` and `public`
are computed.

- [ ] **Step 1: Write the failing tests**

Append to `adapters/solid/tests/ldp_conformance.rs`:

```rust
// --- stage 5b: describe --------------------------------------------------------

/// `OPTIONS` has to answer "may I create here?", which means describing an
/// IRI with nothing behind it. A `describe` that refused like `read` does
/// would make that question unanswerable, and H5's `Accept-Put` is the answer.
#[test]
fn describing_an_absent_target_reports_what_a_creation_could_do() {
    let (_m, _d, store) = pod();

    let d = ldp::describe(&store, BASE, "/~/not-yet", &alice()).unwrap();
    assert!(!d.exists(), "nothing has been written there");
    assert_eq!(d.kind(), None);
    assert!(d.holds(AccessMode::Write), "Alice may create it");
}

/// The kind, the version and the modified time all come from one snapshot, so
/// a header set built from them can't describe a state the body never had.
#[test]
fn a_description_reports_the_kind_and_the_validators_of_what_is_there() {
    let (_m, _d, store) = pod();
    ldp::put(&store, None, BASE, "/~/note", &alice(), NOTE, "text/turtle", ROOT).unwrap();

    let note = ldp::describe(&store, BASE, "/~/note", &alice()).unwrap();
    assert!(note.exists());
    assert_eq!(note.kind(), Some(Kind::RdfSource));
    assert!(!note.is_container());
    let recorded = meta(&store, &format!("{ROOT}note")).unwrap();
    let described = note.meta.expect("the resource exists");
    assert_eq!(described.version, recorded.version);
    assert_eq!(described.modified, recorded.modified);

    let root = ldp::describe(&store, BASE, "/~/", &alice()).unwrap();
    assert_eq!(root.kind(), Some(Kind::Container));
    assert!(root.is_container(), "the storage root is a container");

    let acl = ldp::describe(&store, BASE, "/~/.acl", &alice()).unwrap();
    assert_eq!(acl.kind(), Some(Kind::Auxiliary), "an ACL is not an RDF source");
}

/// H9: `WAC-Allow`'s `public=`. A share UI has to show whether the thing it is
/// looking at is world-readable, and the probe has to run against the same ACL
/// as `granted` — a second pass in `pod.rs` would run after the snapshot
/// closed and could report a different pod.
#[test]
fn a_description_says_what_the_public_may_do_as_well_as_the_caller() {
    let (_m, _d, store) = pod();
    ldp::put(&store, None, BASE, "/~/public", &alice(), NOTE, "text/turtle", ROOT).unwrap();
    ldp::put(&store, None, BASE, "/~/private", &alice(), NOTE, "text/turtle", ROOT).unwrap();

    let g = format!("{ROOT}public.acl");
    let everyone = format!("{g}#everyone");
    let owner = format!("{g}#owner");
    grant(
        &store,
        &g,
        &[
            t(&g, &everyone, &format!("{ACL}accessTo"), &format!("{ROOT}public")),
            t(&g, &everyone, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &everyone, &format!("{ACL}agentClass"), &format!("{FOAF}Agent")),
            t(&g, &owner, &format!("{ACL}accessTo"), &format!("{ROOT}public")),
            t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(&g, &owner, &format!("{ACL}agent"), "https://alice.brolly.id/profile#me"),
        ],
    );

    let public = ldp::describe(&store, BASE, "/~/public", &alice()).unwrap();
    assert_eq!(public.public, vec![AccessMode::Read], "world-readable");
    assert!(public.holds(AccessMode::Write), "and Alice can still edit it");

    let private = ldp::describe(&store, BASE, "/~/private", &alice()).unwrap();
    assert!(private.public.is_empty(), "nothing is granted to everyone");
    assert!(private.holds(AccessMode::Write));
}

/// `describe` reports; it does not refuse. The gate is H4's, in
/// `pod::options`, which answers 401 or 403 to a caller holding no mode at all
/// — `options_refuses_a_caller_who_holds_no_mode_at_all` in
/// `server/tests/pod_http.rs` is what keeps this off the wire. Refusing here
/// instead would collapse "you may create here" and "this already exists" into
/// one answer, and H4 needs both.
#[test]
fn a_description_is_a_report_and_not_a_decision() {
    let (_m, _d, store) = pod();
    ldp::put(&store, None, BASE, "/~/secret", &alice(), NOTE, "text/turtle", ROOT).unwrap();

    let d = ldp::describe(&store, BASE, "/~/secret", &stranger()).unwrap();
    assert!(d.granted.is_empty(), "the stranger holds nothing");
    assert!(d.public.is_empty());
    // Whereas `read` refuses outright.
    assert!(ldp::read(&store, None, BASE, "/~/secret", &stranger(), None).is_err());
}

/// `read` is built on `describe`, so `GET` and `OPTIONS` cannot disagree about
/// what a caller may do. The failure this guards: two code paths computing
/// modes, and a client drawing an edit affordance from the one that is wrong.
#[test]
fn a_read_carries_the_description_describe_would_have_given() {
    let (_m, _d, store) = pod();
    ldp::put(&store, None, BASE, "/~/note", &alice(), NOTE, "text/turtle", ROOT).unwrap();

    let out = ldp::read(&store, None, BASE, "/~/note", &alice(), None).unwrap();
    let described = ldp::describe(&store, BASE, "/~/note", &alice()).unwrap();
    assert_eq!(out.description.granted, described.granted);
    assert_eq!(out.description.public, described.public);
    assert_eq!(out.description.kind(), described.kind());
    assert_eq!(out.version, described.meta.expect("it exists").version);
}
```

`FOAF` and `ACL` are the constants already at the top of that file, and
`grant` adds to an ACL graph rather than replacing it.

Append to `adapters/solid/tests/ldp_nonrdf.rs`:

```rust
/// `describe` takes no `BlobStore` — that is the point. `OPTIONS` on a 40 MB
/// video must cost what `OPTIONS` on a note costs, and the signature is what
/// makes reading the bytes impossible rather than merely unlikely. Everything
/// a header needs about a binary is in its recorded `BlobMeta`.
#[test]
fn describing_a_binary_never_asks_for_its_bytes() {
    let pod = pod();
    ldp::put(
        &pod.store,
        Some(&pod.blobs),
        BASE,
        "/~/avatar.png",
        &alice(),
        PNG,
        "image/png",
        ROOT,
    )
    .unwrap();

    let d = ldp::describe(&pod.store, BASE, "/~/avatar.png", &alice()).unwrap();
    assert_eq!(d.kind(), Some(Kind::NonRdfSource));
    let blob = d.meta.expect("it exists").blob.expect("a binary has bytes");
    assert_eq!(blob.media_type, "image/png");
    assert_eq!(blob.byte_size, PNG.len() as u64);
}
```

`Kind` is already imported in that file (`:13`).

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-solid --test ldp_conformance describ`
Expected: compile failure, `error[E0425]`: cannot find function `describe` in
module `ldp`, and `error[E0609]`: no field `description` on type `LdpOutcome`.

- [ ] **Step 3: Implement `Description`, `describe` and `describe_in`**

In `adapters/solid/src/ldp.rs`, drop `WriteFormat` from the `syntax` import
(`:32`) and add `ResourceMeta` to the `resources` one (`:35-37`):

```rust
use brolly_domain::syntax::{self, ReadFormat, SyntaxError};
use brolly_domain::vocab;
use brolly_identity::Subject;
use brolly_store::resources::{
    self, BlobMeta, Content, Kind, Pod, PodRead, PodWrite, ResourceMeta, ResourceRead,
};
```

Immediately after `granted_modes` (so it ends at `:230`) and before `read`,
add:

```rust
/// What a resource is, and what a caller may do with it — without its body.
///
/// The body-free half of [`read`], and the only thing the HTTP surface needs
/// to build `Allow`, `Accept-*`, `Link` and `WAC-Allow` (spec 5b, H4–H10).
/// `OPTIONS` needs it because it answers for resources the caller may not
/// read and for targets that do not exist yet; `GET` and `HEAD` take the same
/// value so the affordances a client reads cannot depend on which method it
/// read them from.
///
/// **Every field comes from one snapshot.** `Pod::read` drops its transaction
/// when the closure returns (`store/src/resources.rs:307-315`), so anything
/// that asks these questions afterwards is asking a different pod. That is why
/// the anonymous probe for `public` runs in here and rides out on the value,
/// and it is what guarantees `WAC-Allow`'s two components describe one ACL.
pub struct Description {
    /// The resource's metadata, or `None` when nothing is recorded at the IRI.
    /// Existence, kind, version and modified time all come from here, so they
    /// cannot disagree with each other.
    pub meta: Option<ResourceMeta>,
    /// Modes the caller holds. Empty means no access of any kind, which is
    /// what `pod.rs` turns into H1's 401 or 403.
    pub granted: Vec<AccessMode>,
    /// Modes an anonymous caller holds: `WAC-Allow`'s `public=`. A share UI
    /// has to be able to show whether a resource is world-readable, and
    /// failing at it is the only other way to find out.
    pub public: Vec<AccessMode>,
}

impl Description {
    /// Is there a resource at this IRI? Existence is one metadata triple
    /// (5a, R2), never a graph that happens to have triples in it.
    pub fn exists(&self) -> bool {
        self.meta.is_some()
    }

    /// What it is, or `None` when it isn't there.
    pub fn kind(&self) -> Option<Kind> {
        self.meta.as_ref().map(|meta| meta.kind)
    }

    /// A container by its *recorded* kind. Not the same question as
    /// [`storage::is_container`], which reads a trailing slash off an IRI and
    /// so answers for targets that don't exist.
    pub fn is_container(&self) -> bool {
        matches!(self.kind(), Some(Kind::Container))
    }

    /// Does the caller hold `mode`?
    pub fn holds(&self, mode: AccessMode) -> bool {
        self.granted.contains(&mode)
    }
}

/// Describe `path` without reading it: [`read`]'s metadata and modes, no body.
///
/// Takes no [`BlobStore`] on purpose. A binary is described from the
/// `BlobMeta` already in its metadata — kind, media type, size — and its bytes
/// are never fetched, so `OPTIONS` on a 40 MB video costs what `OPTIONS` on a
/// note costs.
///
/// Unlike [`read`] it does **not** check Read, and it does not refuse: it
/// reports, and the caller decides. `pod::options` refuses a caller holding no
/// mode at all (5b, H4), which is what keeps this from becoming an existence
/// oracle. Collapsing the two here would make "you may create here" and "this
/// already exists" the same answer, and `OPTIONS` needs to tell them apart.
pub fn describe(
    pod: &Pod,
    base: &str,
    path: &str,
    subject: &Subject,
) -> Result<Description, LdpError> {
    pod.read(|r| Ok(describe_in(r, base, path, subject)))?
}

/// [`describe`] against a snapshot the caller already holds.
pub fn describe_in(
    r: &impl PodRead,
    base: &str,
    path: &str,
    subject: &Subject,
) -> Result<Description, LdpError> {
    let resource = format!("{base}{path}");
    Ok(Description {
        meta: r.meta(&resource)?,
        granted: granted_modes(r, base, path, subject),
        // Inside the snapshot, against the ACL `granted` just resolved, so the
        // two can never describe different states of the pod.
        public: granted_modes(r, base, path, &Subject::anonymous()),
    })
}
```

- [ ] **Step 4: Rebuild `LdpOutcome` and `read_in` on it**

Replace `LdpOutcome` (`:133-148`) with:

```rust
/// A successful read.
pub struct LdpOutcome {
    pub body: Vec<u8>,
    /// Owned: a binary's type comes from the pod, not from a fixed list.
    pub media_type: String,
    /// The target as [`describe`] reports it, from the same snapshot as
    /// `body`: existence, kind, and both sets of modes. `Allow`, `Accept-*`
    /// and `WAC-Allow` are all built from this one value, on `GET`, `HEAD` and
    /// `OPTIONS` alike, so those three cannot disagree.
    pub description: Description,
    /// `brolly:version` from that snapshot: the `ETag`. Not an `Option` like
    /// the one inside `description`, because [`read`] returns only for a
    /// resource that is there — which makes the missing case unrepresentable
    /// rather than something `pod.rs` has to unwrap.
    pub version: String,
    /// `dcterms:modified` from that snapshot, as stored (`xsd:dateTime`): the
    /// `Last-Modified`.
    pub modified: String,
}
```

Replace the head of `read_in` (from `let resource = …` down to the
`let modified = …` line, `:257-268`) with:

```rust
    let resource = format!("{base}{path}");
    if !check(r, base, path, subject, AccessMode::Read)? {
        return Err(LdpError::Denied);
    }
    // One description, from this snapshot, carried out on the outcome. The
    // Read check stays separate: it propagates a broken ACL as a store error,
    // where `granted_modes` reports an empty set, and a pod that can't be
    // evaluated must not look like a pod that denies.
    let description = describe_in(r, base, path, subject)?;
    let Some(meta) = description.meta.clone() else {
        return Err(LdpError::NotFound);
    };
    // The validators come from this snapshot's metadata, the one the body is
    // read from, so an `ETag` always describes the bytes it goes out with.
    let version = meta.version.clone();
    let modified = meta.modified.clone();
```

Keep chunk 1's spelling of the first refusal if it differs.

Then in both `Ok(LdpOutcome { … })` literals (the binary one at `:281-288`,
the RDF one at `:307-314`), replace `granted,` and `is_container,` with
`description,`:

```rust
        return Ok(LdpOutcome {
            body: bytes,
            media_type: blob.media_type,
            description,
            version,
            modified,
        });
```

```rust
    Ok(LdpOutcome {
        body: syntax::serialize(&quads, format)?,
        media_type: format.media_type().to_string(),
        description,
        version,
        modified,
    })
```

`is_container` is still needed *locally* in the RDF branch, to decide whether
to extend the quads with the listing — leave `let is_container = matches!(meta.kind, Kind::Container);`
where it is (`:300`) and let it be a local.

- [ ] **Step 5: Delete `served_types`**

Remove `served_types` (`:1013-1023`) entirely. It is the *serialization* list,
it duplicates `syntax::negotiate`'s knowledge, and it has zero call sites; H5
sources `Accept-Post` and `Accept-Put` from `accepted_write_types()`, the list
the parser accepts, because RDF/XML is in `served_types` and `refuse_rdf_xml`
(`:671`) rejects it on every write (ADR 0007). Advertising it would be
advertising a guaranteed 415.

Also extend `accepted_write_types`'s doc comment, which now names three
headers:

```rust
/// The media types a write body may carry: `Accept-Post`, `Accept-Put` and,
/// for a container or an ACL, the only types a `PUT` to it will be accepted
/// in. What the parser takes, which is deliberately narrower than what
/// `syntax::negotiate` serves — RDF/XML is served and never parsed (ADR 0007).
pub fn accepted_write_types() -> &'static str {
```

- [ ] **Step 6: Fix the call sites the rename breaks**

Six lines, all compile errors, none silent:

| File | Was | Becomes |
|---|---|---|
| `adapters/solid/tests/ldp_conformance.rs:148` | `out.granted.contains(&AccessMode::Write)` | `out.description.holds(AccessMode::Write)` |
| `adapters/solid/tests/ldp_conformance.rs:462` | `out.granted` | `out.description.granted` |
| `adapters/solid/tests/ldp_conformance.rs:471` | `out.is_container` | `out.description.is_container()` |
| `adapters/solid/tests/acl_control.rs:302` | `out.granted` | `out.description.granted` |
| `adapters/solid/tests/acl_control.rs:396` | `owner.granted` | `owner.description.granted` |
| `adapters/solid/tests/acl_control.rs:399` | `carol.granted` | `carol.description.granted` |

`server/src/pod.rs:334`'s `wac_allow(&outcome.granted)` becomes
`wac_allow(&outcome.description.granted)` — Task 4 rewrites that block anyway,
but fix it now so the workspace compiles at the end of this task.

- [ ] **Step 7: Run the tests and watch them pass**

One suite at a time — parallel Docker runs give false failures.

```bash
cargo test -p brolly-solid --test ldp_conformance
cargo test -p brolly-solid --test ldp_nonrdf
cargo test -p brolly-solid --test acl_control
```

Expected: all pass, including the five new `describe` tests and
`describing_a_binary_never_asks_for_its_bytes`.

- [ ] **Step 8: Gates**

```bash
cargo fmt --all
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Clippy is the one that matters here: if `WriteFormat` is still imported after
`served_types` is gone, `-D warnings` catches it.

- [ ] **Step 9: Stage, don't commit**

```bash
git add adapters/solid/src/ldp.rs adapters/solid/tests server/src/pod.rs
```

### Task 3: The HTTP tests, failing

**Files:**
- Modify: `server/tests/pod_http.rs`: `options_advertises_the_patch_formats`
  (`:453-460`) rewritten in place; helpers and new tests appended at the end
  of the file, after the conditional-requests section

These use `harness()`, `h.send`, `send_as`, `member_session`,
`share_with_bob`, `t`, `NOTE`, `ROOT`, `BASE` and `ACL`, all already in the
file. The status codes on refusals are chunk 1's (H1: authenticated and
denied → 403, unauthenticated and denied → 401).

- [ ] **Step 1: Rewrite `options_advertises_the_patch_formats`**

Replace the test at `:453-460` with:

```rust
/// Rewritten for 5b. `OPTIONS` used to answer one static line for every
/// resource and every caller; now it is authenticated and per-resource, so the
/// PATCH formats go to a caller who may PATCH and to nobody else. What this
/// guards: an `Accept-Patch` offered to someone whose every PATCH is refused.
#[tokio::test]
async fn options_advertises_the_patch_formats() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (status, _, headers) = h.send("OPTIONS", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let patch = header_of(&headers, "accept-patch");
    assert!(patch.contains("text/n3") && patch.contains("sparql-update"));

    // An anonymous caller holds nothing here, so it is told nothing.
    let (status, _, headers) = h.send("OPTIONS", "/~/note", None, false).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(headers.get("accept-patch").is_none(), "advertised to nobody");
}
```

- [ ] **Step 2: Add the helpers**

Append to the end of `server/tests/pod_http.rs`:

```rust
// --- what a caller may do (stage 5b, H4 and H5) --------------------------------

/// `foaf:Agent`, WAC's "everyone, signed in or not".
const EVERYONE: &str = "http://xmlns.com/foaf/0.1/Agent";

/// A header's value, or a panic naming the header that was missing.
fn header_of(headers: &axum::http::HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .unwrap_or_else(|| panic!("no {name} header"))
        .to_str()
        .unwrap()
        .to_string()
}

/// Write `quads` as the ACL at `graph`, replacing whatever was there.
///
/// A direct ACL replaces the root's `acl:default` for its own resource, so a
/// test that needs the owner to keep a mode has to name her here too.
fn set_acl(h: &Harness, graph: &str, quads: &[Quad]) {
    let pod = h.stores.pod(h.user).unwrap();
    pod.write(|w| w.put(graph, Content::Auxiliary(quads)).map(|_| ()))
        .unwrap();
}
```

- [ ] **Step 3: Write the tests**

Append after the helpers:

```rust
/// What a static `Allow` breaks: SolidOS picks its edit affordances from it,
/// so one line promising every method to every caller draws a save button
/// whose every press is refused.
#[tokio::test]
async fn options_tells_this_caller_what_it_may_do_with_this_resource() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (status, _, headers) = h.send("OPTIONS", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "CTS accepts 204 or 200");
    assert_eq!(
        header_of(&headers, "allow"),
        "GET, HEAD, PUT, POST, PATCH, DELETE, OPTIONS"
    );
    // Each Accept-* is sent because its method is in Allow.
    assert_eq!(
        header_of(&headers, "accept-patch"),
        "text/n3, application/sparql-update"
    );
    let post = header_of(&headers, "accept-post");
    assert!(post.contains("text/turtle"), "got: {post}");
    // ADR 0007: RDF/XML is served and never parsed, so advertising it as a
    // write body would be advertising a guaranteed 415.
    assert!(!post.contains("rdf+xml"), "got: {post}");
    assert_eq!(
        header_of(&headers, "accept-put"),
        "*/*",
        "a document's PUT takes any media type today"
    );
}

/// "May I create here?" is what `OPTIONS` on a missing target asks, and
/// `Accept-Put` is the answer. A `GET` of the same path is a 404, so an
/// `Allow` offering `GET` would be the very lie H4 exists to stop.
#[tokio::test]
async fn options_offers_creation_where_nothing_exists_yet() {
    let h = harness().await;

    let (status, _, headers) = h.send("OPTIONS", "/~/not-yet", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "a writer may ask");
    assert_eq!(header_of(&headers, "allow"), "PUT, PATCH, OPTIONS");
    assert_eq!(header_of(&headers, "accept-put"), "*/*");
    assert!(
        headers.get("accept-post").is_none(),
        "there is nothing to post into"
    );

    let (status, _, _) = h.send("GET", "/~/not-yet", None, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "asking created nothing");
}

/// Solid Protocol §5.4 names exactly two resources a server must refuse to
/// delete, and requires `DELETE` to be missing from their `Allow`. What this
/// guards: a client invited to remove the pod's root, leaving the member
/// nowhere to put anything.
#[tokio::test]
async fn the_storage_root_and_its_own_acl_are_never_offered_for_deletion() {
    let h = harness().await;
    // The harness grants Alice Read and Write. An ACL answers only to Control.
    let g = format!("{ROOT}.acl");
    let a = format!("{g}#owner");
    set_acl(
        &h,
        &g,
        &[
            t(&g, &a, &format!("{ACL}default"), ROOT),
            t(&g, &a, &format!("{ACL}accessTo"), ROOT),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Control")),
            t(&g, &a, &format!("{ACL}agent"), &format!("{BASE}/profile#me")),
        ],
    );

    for path in ["/~/", "/~/.acl"] {
        let (status, _, headers) = h.send("OPTIONS", path, None, true).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{path}");
        let allow = header_of(&headers, "allow");
        assert!(!allow.contains("DELETE"), "{path} offered DELETE: {allow}");
        assert!(allow.contains("PUT"), "{path}: {allow}");
        // 5a's NotRdf refusal, made discoverable: both take RDF and only RDF.
        let put = header_of(&headers, "accept-put");
        assert!(!put.contains("*/*"), "{path} accepts anything: {put}");
        assert_eq!(put, header_of(&headers, "accept-post"), "{path}");
    }

    // Any other ACL may be deleted by a caller with Control. WAC §3.2 makes
    // removing it the way to put a resource back on its container's rules.
    share_with_bob(&h);
    let (_, _, headers) = h.send("OPTIONS", "/~/shared/.acl", None, true).await;
    assert!(header_of(&headers, "allow").contains("DELETE"));
}

/// A reader is offered reading. What this guards: a viewer shown an editor,
/// and a client trying a `PUT` it was promised and getting a 403 it had no way
/// to predict.
#[tokio::test]
async fn a_public_reader_is_offered_reading_and_nothing_else() {
    let h = harness().await;
    h.send("PUT", "/~/public", Some(("text/turtle", NOTE)), true)
        .await;
    let g = format!("{ROOT}public.acl");
    let a = format!("{g}#everyone");
    set_acl(
        &h,
        &g,
        &[
            t(&g, &a, &format!("{ACL}accessTo"), &format!("{ROOT}public")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &a, &format!("{ACL}agentClass"), EVERYONE),
        ],
    );

    let (status, _, headers) = h.send("OPTIONS", "/~/public", None, false).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(header_of(&headers, "allow"), "GET, HEAD, OPTIONS");
    for absent in ["accept-patch", "accept-post", "accept-put"] {
        assert!(headers.get(absent).is_none(), "{absent} offered to a reader");
    }
}

/// The drop-box and inbox pattern, and why H4 gates `OPTIONS` on holding
/// *any* mode rather than Read. An append-only client most needs `Allow` to
/// tell it that it may `POST`, and has no other way to learn it: it can't
/// read the container.
#[tokio::test]
async fn an_append_only_caller_can_discover_that_it_may_post() {
    let h = harness().await;
    h.send("PUT", "/~/drop/", Some(("text/turtle", "")), true)
        .await;
    let g = format!("{ROOT}drop/.acl");
    let a = format!("{g}#everyone");
    set_acl(
        &h,
        &g,
        &[
            t(&g, &a, &format!("{ACL}accessTo"), &format!("{ROOT}drop/")),
            t(&g, &a, &format!("{ACL}default"), &format!("{ROOT}drop/")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Append")),
            t(&g, &a, &format!("{ACL}agentClass"), EVERYONE),
        ],
    );

    let (status, _, headers) = h.send("OPTIONS", "/~/drop/", None, false).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "Append is a mode");
    assert_eq!(header_of(&headers, "allow"), "POST, OPTIONS");
    assert!(header_of(&headers, "accept-post").contains("text/turtle"));
    // PATCH needs Write (`ldp::patch_in`) until 5c.
    assert!(headers.get("accept-patch").is_none());
    assert!(headers.get("accept-put").is_none());

    // And the promise holds.
    let (status, _, _) = h
        .send("POST", "/~/drop/", Some(("text/turtle", NOTE)), false)
        .await;
    assert_eq!(status, StatusCode::CREATED);
}

/// `OPTIONS` must not become the existence oracle the rest of the surface
/// refuses to be. A caller holding nothing gets H1's refusal, the same one
/// whether or not the target is there, and no `Allow` with it.
#[tokio::test]
async fn options_refuses_a_caller_who_holds_no_mode_at_all() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let bob = member_session(&h, "bob").await;

    for path in ["/~/note", "/~/not-yet"] {
        let (status, _, headers) = send_as(&h, &bob, "OPTIONS", path, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: signed in, denied");
        assert!(headers.get("allow").is_none(), "{path}: Allow leaked to Bob");

        let (status, _, headers) = h.send("OPTIONS", path, None, false).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}: no credential");
        assert!(headers.get("allow").is_none(), "{path}: Allow leaked");
    }
}

/// CTS reads `Allow` from a `GET`, and SolidOS from whichever method it made
/// last. Two builders would drift apart, so there is one.
#[tokio::test]
async fn get_and_head_carry_the_same_affordances_as_options() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (_, _, options) = h.send("OPTIONS", "/~/note", None, true).await;
    for method in ["GET", "HEAD"] {
        let (status, _, headers) = h.send(method, "/~/note", None, true).await;
        assert_eq!(status, StatusCode::OK, "{method}");
        for name in ["allow", "accept-patch", "accept-post", "accept-put"] {
            assert!(options.get(name).is_some(), "OPTIONS sent no {name}");
            assert_eq!(
                headers.get(name),
                options.get(name),
                "{method} and OPTIONS disagree about {name}"
            );
        }
    }
}
```

`Quad` and `Content` are already imported at the top of the file (`:9`,
`:11`). HEAD reaches the GET handler because axum routes it there and drops
the body, so it gets the headers without further work.

- [ ] **Step 4: Run them and watch them fail**

Run: `cargo test -p brolly-server --test pod_http -- options_ affordances append_only public_reader storage_root_and_its_own`

Expected:
- **Fail:** `options_tells_this_caller_what_it_may_do_with_this_resource`
  panics with `no accept-put header`. The static handler's `Allow` happens to
  match Alice's modes on an existing note; `Accept-Put` is what it never
  sends. `options_offers_creation_where_nothing_exists_yet`,
  `a_public_reader_is_offered_reading_and_nothing_else` and
  `an_append_only_caller_can_discover_that_it_may_post` fail the `allow`
  `assert_eq!` with `left: "GET, HEAD, PUT, POST, PATCH, DELETE, OPTIONS"`.
  `the_storage_root_and_its_own_acl_are_never_offered_for_deletion` fails
  with `/~/ offered DELETE`. `options_refuses_a_caller_who_holds_no_mode_at_all`
  fails with `left: 204, right: 403`. `options_advertises_the_patch_formats`
  passes its first half and fails the anonymous half with
  `left: 204, right: 401`. `get_and_head_carry_the_same_affordances_as_options`
  fails with `GET and OPTIONS disagree about allow`.
- **Pass already, and must still pass after Task 4:**
  `a_preflight_admits_the_headers_a_solid_client_sends` (`:809`, matched by
  none of the filters; run it on its own with
  `cargo test -p brolly-server --test pod_http a_preflight_admits`). It is the
  guard that a stateful `OPTIONS` handler doesn't swallow CORS preflights,
  which `lib.rs`'s middleware answers before routing.

Don't run the gates or stage in this task. The tree has failing tests until
Task 4.

### Task 4: `pod.rs`: one header builder, a stateful `OPTIONS`, then commit

**Files:**
- Modify: `server/src/pod.rs`: imports (`:8-20`), new functions after
  `wac_allow` (`:254-266`), `get` (`:295-352`), `options` (`:528-548`), a new
  `options_root` after `post_root` (`:519-526`), the test module (`:578-599`).
  All of these are as chunk 1 left them.
- Modify: `server/src/lib.rs`: the `/~/` route (`:319-324`)

Before editing, re-read **Interfaces assumed from chunk 1** above. The
handler code below is written in f564eb6's shape (`State`, `HeaderMap`,
`Path`, and `resolve(&state, &headers, "GET", &path)`). Where chunk 1 changed
`get`'s extractors, its `resolve` call or its refusal mapper, give `options`
and `options_root` exactly what `get` and `get_root` have now, and change only
the lines this task names.

- [ ] **Step 1: Write the failing unit tests**

The `Allow` table and the `Accept-*` rule are pure functions of a
`Description` and two IRIs, so they are tested here, without Docker, for
every row. The HTTP tests from Task 3 cover the wiring.

In `server/src/pod.rs`, add to `mod tests` (keep
`the_new_ldp_refusals_have_status_codes`, which chunk 1 has probably changed):

```rust
    use brolly_authz::AccessMode::{Append, Control, Read, Write};
    use brolly_store::resources::{Kind, ResourceMeta};

    const ROOT: &str = "https://alice.brolly.test/~/";
    const DOC: &str = "https://alice.brolly.test/~/note";
    const ALL: [AccessMode; 4] = [Read, Write, Append, Control];

    /// A description, as `ldp::describe` would give it, for `kind` (`None`:
    /// nothing there) and a caller holding `granted`.
    fn described(kind: Option<Kind>, granted: &[AccessMode]) -> Description {
        Description {
            meta: kind.map(|kind| ResourceMeta {
                kind,
                modified: "2026-09-23T10:00:00.000Z".into(),
                version: "01J8Z3T5V7W9X1Y3Z5A7B9C1D3".into(),
                blob: None,
            }),
            granted: granted.to_vec(),
            public: Vec::new(),
        }
    }

    fn allow_line(kind: Option<Kind>, granted: &[AccessMode], resource: &str) -> String {
        allowed(&described(kind, granted), resource, ROOT).join(", ")
    }

    fn value_of<'a>(headers: &'a [(header::HeaderName, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(n, _)| n.as_str() == name)
            .map(|(_, v)| v.as_str())
    }

    /// H4's table, row by row, on a document that exists. What this guards is
    /// a method promised to a caller whose mode `ldp` will refuse it for.
    #[test]
    fn allow_names_only_what_the_modes_permit() {
        let doc = Some(Kind::RdfSource);
        assert_eq!(
            allow_line(doc, &ALL, DOC),
            "GET, HEAD, PUT, POST, PATCH, DELETE, OPTIONS"
        );
        assert_eq!(allow_line(doc, &[Read], DOC), "GET, HEAD, OPTIONS");
        // POST appends to a document as well as minting a container's member.
        // PATCH needs Write in `ldp::patch_in`, so an appender isn't offered it.
        assert_eq!(allow_line(doc, &[Append], DOC), "POST, OPTIONS");
        assert_eq!(allow_line(doc, &[Read, Append], DOC), "GET, HEAD, POST, OPTIONS");
        // Control governs the resource's ACL, not the resource.
        assert_eq!(allow_line(doc, &[Control], DOC), "OPTIONS");
    }

    /// Nothing there: what a creation could do. `GET` would 404 and `DELETE`
    /// would 404, and there is no container to `POST` into.
    #[test]
    fn an_absent_target_is_offered_creation_and_not_reading() {
        assert_eq!(allow_line(None, &ALL, DOC), "PUT, PATCH, OPTIONS");
        assert_eq!(allow_line(None, &[Read, Append], DOC), "OPTIONS");
    }

    /// Solid Protocol §5.4 names exactly two undeletable resources. Any other
    /// ACL, and any other container, stays deletable: WAC §3.2 makes deleting
    /// an ACL the way to revert to inheritance.
    #[test]
    fn only_the_root_and_its_own_acl_are_never_offered_delete() {
        let container = Some(Kind::Container);
        let acl = Some(Kind::Auxiliary);
        let root_acl = format!("{ROOT}.acl");
        assert!(!allow_line(container, &ALL, ROOT).contains("DELETE"));
        assert!(!allow_line(acl, &ALL, &root_acl).contains("DELETE"));
        assert!(allow_line(container, &ALL, &format!("{ROOT}notes/")).contains("DELETE"));
        assert!(allow_line(acl, &ALL, &format!("{ROOT}notes/.acl")).contains("DELETE"));
        assert!(allow_line(acl, &ALL, &format!("{DOC}.acl")).contains("DELETE"));
    }

    /// H5: each `Accept-*` goes out only when its method is in `Allow`. A
    /// header advertising a method the caller can't use is as wrong as an
    /// `Allow` that lists it.
    #[test]
    fn each_accept_header_follows_its_method() {
        let doc = Some(Kind::RdfSource);

        let full = affordances(&described(doc, &ALL), DOC, ROOT);
        assert_eq!(value_of(&full, "accept-patch"), Some(ACCEPT_PATCH));
        assert_eq!(value_of(&full, "accept-post"), Some(ldp::accepted_write_types()));
        assert_eq!(value_of(&full, "accept-put"), Some("*/*"));

        let reader = affordances(&described(doc, &[Read]), DOC, ROOT);
        assert_eq!(value_of(&reader, "allow"), Some("GET, HEAD, OPTIONS"));
        for name in ["accept-patch", "accept-post", "accept-put"] {
            assert_eq!(value_of(&reader, name), None, "{name} offered to a reader");
        }

        let appender = affordances(&described(doc, &[Append]), DOC, ROOT);
        assert!(value_of(&appender, "accept-post").is_some());
        assert_eq!(value_of(&appender, "accept-patch"), None);
        assert_eq!(value_of(&appender, "accept-put"), None);
    }

    /// The rule is `ldp::put_if`'s own `rdf_only`: a container or an ACL takes
    /// RDF, anything else takes whatever it's sent. A drift between the two
    /// would promise a 415.
    #[test]
    fn a_container_and_an_acl_take_rdf_only_on_put() {
        let rdf = ldp::accepted_write_types();
        assert_eq!(accept_put(ROOT), rdf);
        assert_eq!(accept_put(&format!("{ROOT}notes/")), rdf, "even before it exists");
        assert_eq!(accept_put(&format!("{ROOT}.acl")), rdf);
        assert_eq!(accept_put(&format!("{DOC}.acl.acl")), rdf);
        assert_eq!(accept_put(DOC), "*/*");
        assert_eq!(accept_put(&format!("{ROOT}photo.png")), "*/*");
        assert!(!rdf.contains("rdf+xml"), "ADR 0007");
    }
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-server --lib pod::tests`

Expected: compile failure, `error[E0425]`: cannot find function `allowed`,
`affordances`, `accept_put` in this scope, cannot find value `ACCEPT_PATCH`,
and `error[E0412]`: cannot find type `Description`.

- [ ] **Step 3: Implement the builder**

In `server/src/pod.rs`, change the imports: `ldp`'s gains `Description`,
and `AccessMode` and `storage` join:

```rust
use brolly_authz::AccessMode;
use brolly_solid::ldp::{self, Description, LdpError};
use brolly_solid::storage;
```

After `wac_allow`, add:

```rust
/// What [`patch`] matches on, and so what `Accept-Patch` advertises. A third
/// syntax here would advertise a 415.
const ACCEPT_PATCH: &str = "text/n3, application/sparql-update";

/// H4: the methods this caller may use on this target, in a fixed order.
///
/// Computed from the caller's modes and whether the target exists. Nothing is
/// decided by kind: `POST` is offered on documents too, because `append_in`
/// appends to one and [`post`] routes it.
fn allowed(description: &Description, resource: &str, storage_root: &str) -> Vec<&'static str> {
    let exists = description.exists();
    let write = description.holds(AccessMode::Write);
    let mut methods = Vec::new();
    if exists && description.holds(AccessMode::Read) {
        methods.extend(["GET", "HEAD"]);
    }
    if write {
        methods.push("PUT");
    }
    // Needs an existing target: there is no container to mint a member in,
    // and no document to append to.
    if exists && (write || description.holds(AccessMode::Append)) {
        methods.push("POST");
    }
    // Not offered to an Append-only caller, though the protocol would allow
    // it: `ldp::patch_in` requires Write, and 5c owns that change.
    if write {
        methods.push("PATCH");
    }
    // Authorization is decided before this: a caller without Write gets H1's
    // refusal, not a 405 telling them the target is special.
    if write && exists && !undeletable(resource, storage_root) {
        methods.push("DELETE");
    }
    methods.push("OPTIONS");
    methods
}

/// The storage root and the storage root's own ACL: the two resources Solid
/// Protocol §5.4 forbids deleting, and whose `Allow` must not list `DELETE`.
fn undeletable(resource: &str, storage_root: &str) -> bool {
    resource == storage_root || resource == format!("{storage_root}.acl")
}

/// H5: what a `PUT` to this target may carry.
///
/// The condition is `ldp::put_if`'s own `rdf_only`, spelled the same way on
/// purpose, and it reads the IRI, not the metadata: `put_if` refuses a binary
/// for `/~/new/` whether or not `/~/new/` exists yet.
fn accept_put(resource: &str) -> &'static str {
    if storage::is_container(resource) || ldp::governed(resource).is_some() {
        ldp::accepted_write_types()
    } else {
        "*/*"
    }
}

/// H4 and H5: `Allow`, and an `Accept-*` for each write method it names.
///
/// One builder for `OPTIONS`, `GET` and `HEAD`. CTS reads `Allow` from a
/// `GET`, SolidOS from whichever it made last, and two builders would drift.
///
/// Each `Accept-*` goes out only when its method is allowed. Solid §5.2
/// states the MUST unconditionally; we narrow it, as CSS does, because
/// advertising a method the caller can't use is the same lie as a wrong
/// `Allow`.
fn affordances(
    description: &Description,
    resource: &str,
    storage_root: &str,
) -> Vec<(header::HeaderName, String)> {
    let methods = allowed(description, resource, storage_root);
    let mut out = vec![(header::ALLOW, methods.join(", "))];
    if methods.contains(&"PATCH") {
        out.push((
            header::HeaderName::from_static("accept-patch"),
            ACCEPT_PATCH.to_string(),
        ));
    }
    if methods.contains(&"POST") {
        out.push((
            header::HeaderName::from_static("accept-post"),
            ldp::accepted_write_types().to_string(),
        ));
    }
    if methods.contains(&"PUT") {
        out.push((
            header::HeaderName::from_static("accept-put"),
            accept_put(resource).to_string(),
        ));
    }
    out
}

/// Put built headers onto a response.
///
/// A value that isn't a legal header value is dropped, not panicked on. None
/// of ours can be illegal: they are ASCII lists built here and `ldp`'s own
/// constants.
fn apply(response: &mut Response, headers: Vec<(header::HeaderName, String)>) {
    for (name, value) in headers {
        if let Ok(value) = HeaderValue::from_str(&value) {
            response.headers_mut().insert(name, value);
        }
    }
}
```

If `wac_allow` still spells its parameter `&[brolly_authz::AccessMode]`,
leave it. The new import doesn't conflict, and `wac_allow` belongs to
chunk 4.

- [ ] **Step 4: Run the unit tests and watch them pass**

Run: `cargo test -p brolly-server --lib pod::tests`
Expected: 5 new tests pass, plus whatever chunk 1 left in the module.

Clippy will call `affordances`, `apply` and `ACCEPT_PATCH` dead code until
Step 5 uses them. That's expected, so don't run clippy yet.

- [ ] **Step 5: A stateful `OPTIONS`, and `options_root`**

Replace `options` (`:528-548`) with:

```rust
/// `OPTIONS /~/*path`: what *this* caller may do with *this* resource.
///
/// Resolves the pod, authenticates and evaluates WAC like any other method.
/// The handler this replaces took no state, no path and no credential, and
/// gave every resource in every pod the same `Allow`. Answers 204, which CTS
/// accepts as well as 200, with H4's `Allow` and H5's `Accept-*`.
///
/// A CORS preflight never gets here. `lib.rs`'s middleware answers an
/// `OPTIONS` carrying `Access-Control-Request-Method` before routing, and a
/// preflight carries no credentials by definition.
pub async fn options(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Response {
    let path = format!("/~/{path}");
    let request = match resolve(&state, &headers, "OPTIONS", &path).await {
        Ok(r) => r,
        Err(response) => return response,
    };
    let description = match ldp::describe(&request.pod, &request.base, &path, &request.subject) {
        Ok(description) => description,
        Err(e) => return ldp_error(e),
    };
    // H4: gated on holding *any* mode, not on Read. An Append-only caller,
    // the drop box and the inbox, is the one that most needs to learn it may
    // POST. A caller with nothing gets H1's 401 or 403, the same whether or
    // not the target exists, so this is not an existence oracle. A caller
    // with a mode on a target that doesn't exist gets 204 and the `Allow` a
    // creation would have.
    if description.granted.is_empty() {
        return ldp_error(LdpError::Denied);
    }
    let resource = format!("{}{path}", request.base);
    let mut response = StatusCode::NO_CONTENT.into_response();
    apply(
        &mut response,
        affordances(&description, &resource, &request.storage_root),
    );
    response
}
```

As **Interfaces assumed from chunk 1** says, give it `get`'s extractors and
`resolve` call, reporting the method `OPTIONS`, and spell both `ldp_error`
calls the way `get` spells its own.

After `post_root`, add:

```rust
/// `OPTIONS /~/`: the storage root itself. A wildcard route doesn't match
/// an empty remainder (see [`get_root`]), and without this the root would get
/// no per-caller `Allow`, which is the one place `DELETE` must be left out.
pub async fn options_root(state: State<AppState>, headers: HeaderMap) -> Response {
    options(state, headers, Path(String::new())).await
}
```

If chunk 1 gave `get_root` more parameters, give `options_root` the same
ones and forward them the way `get_root` does.

In `server/src/lib.rs`, route the root's `OPTIONS` to it (`:319-324`):

```rust
        .route(
            "/~/",
            get(pod::get_root)
                .post(pod::post_root)
                .options(pod::options_root),
        )
```

The `/~/{*path}` route keeps `.options(pod::options)`. Its signature changed,
but it's still a handler. Chunk 3 adds `put_root`, `patch_root` and
`delete_root` to this same entry.

- [ ] **Step 6: The same headers on `GET` and `HEAD`**

In `get`, the `wac_allow(...)` entry in the 200's header array becomes (if
Task 2, Step 6 didn't already do it):

```rust
                wac_allow(&outcome.description.granted),
```

and right after `.into_response();` closes the 200, before the
`Last-Modified` block, add:

```rust
    // H4/H5: the same builder `OPTIONS` uses, over the description `read`
    // took from the body's own snapshot.
    let resource = format!("{}{path}", request.base);
    apply(
        &mut response,
        affordances(&outcome.description, &resource, &request.storage_root),
    );
```

`outcome.body` has moved into the tuple by now. That's a partial move, and
`outcome.description` and `outcome.modified` can still be used after it:
`LdpOutcome` doesn't implement `Drop`, which is why the existing
`Last-Modified` block already compiles.

Leave the 304 carrying only its `ETag`. Chunk 4 (H10) makes it carry
`Allow`, `Accept-*`, `WAC-Allow`, `Vary` and `Last-Modified`, and `apply`
over `affordances` is the call it adds.

HEAD gets all of this for free: axum sends HEAD to the GET handler and drops
the body.

- [ ] **Step 7: Run the tests and watch them pass**

One suite at a time:

```bash
cargo test -p brolly-server --lib pod::tests
cargo test -p brolly-server --test pod_http
```

Expected: all pass, including Task 3's eight tests and
`a_preflight_admits_the_headers_a_solid_client_sends`.

- [ ] **Step 8: Format and gates**

```bash
cargo fmt --all
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings
./tools/check-doc-paths.sh
cargo deny check
cargo test --workspace
```

No `Cargo.toml` changes. `cargo deny check` is here because the gate list
says so, and it should report nothing new. `cargo test --workspace` runs the
test binaries one after another. Don't start another suite in a second
terminal while it runs.

Clippy should catch two leftovers if they survived: `WriteFormat` in
`ldp.rs`'s import, and `Scope`/`Via` in `pod.rs`'s import if nothing else
there names them.

- [ ] **Step 9: Commit**

```bash
git add server/src/pod.rs server/src/lib.rs server/tests/pod_http.rs
git add -u
git status   # subject.rs, ldp.rs, pod.rs, lib.rs, pod_http.rs, and the three adapters/solid/tests files; nothing else
git commit -F - <<'MSG'
feat(solid): Allow and Accept-* computed for the resource and the caller

OPTIONS was a stateless handler that gave every resource in every pod the
same Allow and Accept-Post, so a client drawing edit affordances from it
was promised writes it would then be refused. It now resolves the pod,
authenticates and evaluates WAC. Allow is built from the caller's modes:
GET and HEAD for Read; PUT, PATCH and DELETE for Write; POST for Write or
Append on a target that exists; never PATCH for an Append-only caller
until 5c; and never DELETE on the storage root or its own ACL (Solid
Protocol 5.4). A caller holding no mode gets the ordinary 401 or 403.
Append-only is enough to ask, so a drop box can find out it may POST. A
target that doesn't exist answers 204 with what a creation could do.

Accept-Patch, Accept-Post and the new Accept-Put go out only when their
method is in Allow. Post and Put come from accepted_write_types(), so
RDF/XML (ADR 0007) is never offered. Accept-Put is */* except for a
container or an ACL, which take RDF only. GET and HEAD carry the same
headers from the same builder. /~/ gets its own options_root, because the
wildcard route doesn't match an empty remainder.

Underneath: ldp::describe, a body-free read of one resource's metadata,
the caller's modes and the public's modes, all from one snapshot. It
never touches the blob store. read_in is rebuilt on it, and LdpOutcome
carries the Description, so GET and OPTIONS can't disagree. The public
probe runs inside the snapshot, ready for WAC-Allow's public= in a later
commit. Subject::anonymous() replaces the struct literal pod.rs built
inline. served_types(), which had no callers and listed RDF/XML, is gone.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
MSG
```

- [ ] **Step 10: Verify from a clean checkout**

```bash
rm -rf /tmp/verify && git worktree add --detach /tmp/verify HEAD
cd /tmp/verify && cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && ./tools/check-doc-paths.sh && cargo deny check && cargo test --workspace
cd - && git worktree remove /tmp/verify --force
```

The commit isn't done until that passes. Trunk-based: it lands on `main`,
with no branch and no PR.

### Notes for the reviewer

- **The shape of `Description`.** It holds `meta: Option<ResourceMeta>` plus
  `granted` and `public`. It doesn't have flat `kind`/`version`/`modified`
  fields. `exists()`, `kind()`, `is_container()` and `holds()` read from
  `meta`. So existence, kind and validators come from one struct and can't
  disagree, and `read_in` can take the `ResourceMeta` it needs, `blob`
  included, without a second `meta()` call. `kind` is the store's own `Kind`,
  with `None` meaning absent. That keeps `Auxiliary` distinct, which chunk 3
  needs for `Link rel="type"` (an ACL is an RDF source, not a container).
- **`LdpOutcome` keeps `version` and `modified` as plain `String`s** as well as
  the `Description`. That's deliberate duplication. `read` returns only for a
  resource that exists, and the workspace denies `expect`/`unwrap`, so the
  non-optional copies make "no version on a 200" impossible to represent
  instead of an unwrap in `pod.rs`. `granted` and `is_container` did move off
  the outcome. Six test lines change for it (Task 2, Step 6), all as compile
  errors.
- **How `describe` avoids duplicating `read_in`.** `describe_in` is `read_in`
  without the Read check, the body and the blob store. `read_in` calls it and
  takes its metadata from the result. Neither function calls `meta()` twice,
  and modes are computed in exactly one place. `read_in` keeps its own
  `check(Read)` rather than testing `granted.contains(Read)`. The two agree
  on every ACL that evaluates, but `granted_modes` turns a store error into
  an empty set, while `check` propagates it. Switching would make a broken
  pod look like a denial (a 401 to an anonymous caller) instead of a 500.
- **The cost of a read goes from five `authorize` calls to nine**: the Read
  check, then four each for the caller and for the public. All of them run
  against the snapshot already open and the ACL already resolved. The spec
  prices this (H9). The `public` probe runs on every read from this commit
  on, though nothing emits it until chunk 4.
- **`describe` reports and doesn't refuse.** The any-mode gate is in
  `pod::options`, where the 401/403 decision already lives.
  `a_description_is_a_report_and_not_a_decision` pins that contract, and
  `options_refuses_a_caller_who_holds_no_mode_at_all` pins the gate over the
  wire.
- **The absent-target `Allow` is my reading of the spec's "the `Allow` a
  creation would have".** H4's table has no row for existence. Applied
  literally, it would offer `GET` and `DELETE` on something that 404s, which
  is what H4 exists to stop. So an absent target gets `OPTIONS`, plus `PUT`
  and `PATCH` for Write (`patch_in` creates). `POST` is left out: it needs an
  existing container or document. As a result, an Append-only caller on an
  absent path gets `Allow: OPTIONS` and nothing else. That's true, but a
  reviewer may prefer the spec to say so.
- **`Accept-Put` reads the IRI, not the metadata**, so an absent `/~/new/`
  advertises the RDF list, not `*/*`. H5 says "`*/*` for… a target that
  doesn't exist", but `put_if`'s `rdf_only` is decided by the trailing slash
  whether the target exists or not, so `*/*` there would promise a 415.
  `accept_put` copies `put_if`'s expression word for word, and
  `a_container_and_an_acl_take_rdf_only_on_put` pins it. Worth one line in
  the spec.
- **The 304 is unchanged.** It still carries only the `ETag`. Chunk 4 adds
  the rest (H10), with the same `apply(&mut response, affordances(…))` call
  this chunk puts on the 200.
- **`Accept-Put` isn't in CORS's expose list yet**, so a browser script can't
  read it until chunk 4 (H14) adds it. Server-side clients and CTS read it
  today.
- **`Allow` has a fixed order**: `GET, HEAD, PUT, POST, PATCH, DELETE,
  OPTIONS`, the old static line's order. The tests compare exact strings, so
  a reordering has to be deliberate.
- **Written without chunk 1 in view.** Every handler shape this chunk
  assumes is listed up front. Line numbers cited are at f564eb6 and chunk 1
  moves them.

---

## Chunk 3: Discovery

<!-- doc-paths: skip -->
<!-- This chunk creates `adapters/solid/src/storage_description.rs`, so not
     every path it names resolves until it has been executed. -->

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development
> (if subagents available) or superpowers:executing-plans to implement this
> chunk. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A resource says what it is, where its rules are, and which storage it
belongs to, in headers a client reads before it parses anything; the storage
itself has a description a client can read before it has a credential; and the
storage root's own protections become reachable over HTTP.

**Spec:** [`docs/specs/2026-09-23-solid-http-surface.md`](../specs/2026-09-23-solid-http-surface.md),
decisions **H6** (the `Link` set), **H7** (`acl_iri`), **H8** (the storage
description), **H12**'s routing half (`/~/` gains the write methods, the root
ACL guard, `Undeletable` → 405) and **H16** (our 405s carry `Allow`). This is
the spec's chunk 3.

**Lands on top of chunks 1 and 2, in one commit to `main`.** Trunk-based, no
PR. Chunk 1 owns the 401/403 split and `LdpError::{Denied, Undeletable}`;
chunk 2 owns `ldp::describe`, the shared header builder, `Allow` and the
`Accept-*` family. Nothing here changes either — this chunk is all new surface,
plus one bug fix (`pod.rs`'s concatenated ACL link) and one missing guard (the
root ACL).

**What changes:**

| File | Change |
|---|---|
| `domain/src/vocab.rs` | `SOLID_OWNER`, `SOLID_STORAGE_DESCRIPTION` |
| `adapters/solid/src/ldp.rs` | `acl_iri()` beside `governed()`; the root-ACL guard in `delete_in` |
| `adapters/solid/src/storage_description.rs` (new) | the generated §4.1 document, its path and its IRI |
| `adapters/solid/src/lib.rs` | `pub mod storage_description;` |
| `server/src/pod.rs` | `PodRequest.webid`; `links()`, H6's full set, into chunk 2's header builder; `storage_description` handler; `put_root`/`patch_root`/`delete_root`; `Undeletable` → 405 with `Allow`; `Allow` on the fallback's `UserStorage` arm |
| `server/src/lib.rs` | `/.well-known/solid` routed; `/~/` gains `put`/`patch`/`delete` |
| `server/tests/pod_http.rs` | the HTTP tests for all of the above |

**Not in this chunk:** the 401/403 split and `WWW-Authenticate` (chunk 1);
`describe`, `Allow`, `Accept-Patch`/`Post`/`Put` and stateful `OPTIONS`
(chunk 2); `WAC-Allow public=`, `Vary`, the syntax-tagged ETag, the fuller 304
and CORS (chunk 4); 201 on create, the non-empty-container 409, container
listings and the required `Content-Type` (chunk 5).

### Assumed from chunks 1 and 2

Written without chunks 1 and 2 in view. Where a name below differs from what
they actually landed, **use theirs and keep the behaviour described here.**
Every test in this chunk is at the HTTP surface or is a pure unit test, so none
of them depends on the spelling.

1. **`LdpError::Undeletable` exists** (chunk 1 renamed `Forbidden` to it), and
   `delete_in`'s storage-root guard at `adapters/solid/src/ldp.rs:877` returns
   it. `pod.rs::ldp_error` maps it to **403** today; Task 5 moves it to 405.
2. **`LdpError::Denied` exists** and `pod.rs` answers 401 for an
   unauthenticated caller and 403 for an authenticated one. Task 5's first test
   asserts the 401 for `DELETE /~/`; if chunk 1 spells the challenge
   differently, assert chunk 1's status and header, not this text's.
3. **`ldp::describe(pod, base, path, subject)`** returns a description carrying
   at least the target's **kind** and whether it **exists**. This chunk needs
   exactly one thing from it: `Option<Kind>` — the kind when the target exists,
   `None` when it doesn't. If chunk 2 models that as `exists: bool` beside a
   non-optional `kind`, write `d.exists.then_some(d.kind)` at the call sites
   below and change nothing else.
4. **One header builder in `pod.rs`**, over `describe`'s output, shared by
   `GET`, `HEAD`, `OPTIONS` (and chunk 4's 304). This text calls it
   `headers_for(request, path, description)`. Task 3 replaces one entry in it.
   If chunk 2 left the `Link` line in `get` instead, move it into the builder:
   one builder is chunk 2's whole point, and H6's set must be identical on
   `GET`, `HEAD` and `OPTIONS`.
5. **An `Allow` string is computable from a description** — chunk 2's H4 work.
   This text calls it `allow(&description) -> String`. Task 5 needs it for the
   405. H4's table already removes `DELETE` for the storage root and the root's
   ACL; if chunk 2 didn't implement that removal, Task 5's
   `the_owner_cannot_delete_the_storage_root` fails on the `Allow` assertion
   and the removal belongs there, not here.
6. **`options_root` exists** (chunk 2 needed it when `OPTIONS` became
   stateful). Task 5 adds `put_root`, `patch_root` and `delete_root` beside it.
7. **The handlers take `Method` and `OriginalUri` before `Path`** (chunk 1's
   H15). Task 5's new root handlers copy `get_root`'s signature *exactly as
   chunk 1 left it*, adding `body: axum::body::Bytes` for `put_root` and
   `patch_root`.

Line numbers cited below are at `e7fe4f6` (5a's last commit); chunks 1 and 2
move them.

---

### Task 1: The discovery relations

**Files:**
- Modify: `domain/src/vocab.rs` (append after `BROLLY_BYTE_SIZE`, `:104`, and
  add one test to the existing `mod tests`)

- [ ] **Step 1: Write the failing test**

Add to `domain/src/vocab.rs`'s `mod tests`:

```rust
    /// These two IRIs are what a `Link` header's `rel=` carries **verbatim**
    /// — Solid has no registered short name for either — so a typo is a link
    /// relation no client recognises, not a compile error.
    #[test]
    fn the_discovery_relations_are_solid_terms() {
        for term in [SOLID_OWNER, SOLID_STORAGE_DESCRIPTION] {
            assert!(term.starts_with(SOLID), "{term}");
        }
        assert_eq!(SOLID_OWNER, "http://www.w3.org/ns/solid/terms#owner");
        assert_eq!(
            SOLID_STORAGE_DESCRIPTION,
            "http://www.w3.org/ns/solid/terms#storageDescription"
        );
    }
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p brolly-domain --lib vocab::tests::the_discovery_relations_are_solid_terms`

Expected: the build fails with ``error[E0425]: cannot find value `SOLID_OWNER`
in this scope`` and the same for `SOLID_STORAGE_DESCRIPTION`.

- [ ] **Step 3: Add the terms**

Insert into `domain/src/vocab.rs` between `BROLLY_BYTE_SIZE` (`:104`) and
`#[cfg(test)]`:

```rust
// --- discovery (stage 5b, H6 and H8) ---------------------------------------
//
// The link relations a pod read advertises. The LDP classes above are the
// `rel="type"` *values*; these two are relation IRIs, which is what `rel=`
// carries when no short name is registered.

/// `Link rel="…#owner"` on the storage root, and the predicate the storage
/// description uses for the same statement. Solid Protocol §4.1.
pub const SOLID_OWNER: &str = "http://www.w3.org/ns/solid/terms#owner";
/// `Link rel="…#storageDescription"` on every resource in a storage
/// (Solid Protocol §4.1). Points at the generated document
/// `brolly_solid::storage_description` serves.
pub const SOLID_STORAGE_DESCRIPTION: &str =
    "http://www.w3.org/ns/solid/terms#storageDescription";
```

- [ ] **Step 4: Run it and watch it pass**

Run: `cargo test -p brolly-domain --lib vocab`

Expected: `test result: ok. 3 passed`.

- [ ] **Step 5: Format**

Run: `cargo fmt --all`

---

### Task 2: `acl_iri`, so an ACL's ACL is itself

**Files:**
- Modify: `adapters/solid/src/ldp.rs` (after `governed()`, `:162-168`, and its
  `mod tests`, `:1025-1053`)

- [ ] **Step 1: Write the failing tests**

In `adapters/solid/src/ldp.rs`'s `mod tests`, change the import to

```rust
    use super::{acl_iri, governed};
```

and append:

```rust
    /// H7's first case. The failure this guards is `pod.rs`'s concatenation:
    /// a GET of `/~/x.acl` advertised `</~/x.acl.acl>; rel="acl"`, an IRI no
    /// ACL governs and that a client following the link would create as an
    /// ordinary document.
    #[test]
    fn an_acl_is_its_own_acl() {
        assert_eq!(acl_iri("/~/x.acl"), "/~/x.acl");
        assert_eq!(acl_iri("/~/notes/.acl"), "/~/notes/.acl");
        // Including the fiction itself, if one ever gets written.
        assert_eq!(acl_iri("/~/x.acl.acl"), "/~/x.acl.acl");
    }

    /// A container's ACL lives *inside* it and a document's beside it. Both
    /// are `{target}.acl`, and they agree with `authz::acl_candidates`' first
    /// candidate — which is the resource WAC will actually read.
    #[test]
    fn a_containers_acl_is_inside_it_and_a_documents_is_beside_it() {
        assert_eq!(acl_iri("/~/notes/"), "/~/notes/.acl");
        assert_eq!(acl_iri("/~/notes/first"), "/~/notes/first.acl");
        assert_eq!(
            acl_iri("https://alice.brolly.id/~/"),
            "https://alice.brolly.id/~/.acl"
        );
    }

    /// `acl_iri` is not [`governed`] run backwards, and the two answer
    /// different questions: `governed` asks whose `Control` guards this,
    /// `acl_iri` asks which IRI holds the rules. Collapsing them is how the
    /// `.acl.acl` link got written in the first place.
    #[test]
    fn acl_iri_is_not_the_inverse_of_governed() {
        assert_eq!(governed("/~/x.acl.acl"), Some("/~/x"));
        assert_eq!(acl_iri("/~/x.acl.acl"), "/~/x.acl.acl");
        assert_eq!(acl_iri(governed("/~/x.acl").unwrap()), "/~/x.acl");
    }
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-solid --lib ldp::tests`

Expected: the build fails with ``error[E0432]: unresolved import
`super::acl_iri` ``.

- [ ] **Step 3: Add `acl_iri`**

Insert into `adapters/solid/src/ldp.rs` immediately after `governed()`
(`:168`):

```rust
/// The IRI of the ACL that holds `target`'s access rules.
///
/// **Not the inverse of [`governed`].** `governed` strips *every* trailing
/// `.acl`, because `Control` at the bottom of the chain is what guards the
/// whole of it (stage 0's A2). This answers a different question — which IRI a
/// client fetches or writes to change `target`'s rules — and for an ACL
/// resource that is the ACL itself, because an `.acl` is governed by its own
/// `Control`.
///
/// Everything else gets `.acl` appended. That is one expression and two cases:
/// a container's ACL lives *inside* it (`/~/notes/` → `/~/notes/.acl`, since
/// the IRI already ends in `/`) and a document's beside it (`/~/note` →
/// `/~/note.acl`). Both agree with `authz::acl_candidates`' most specific
/// candidate, which is the graph WAC actually reads. `storage::is_container`
/// is the notion that makes the container case true; it is not branched on,
/// because a branch producing the same string fails
/// `clippy::if_same_then_else`. The tests hold both cases down.
pub fn acl_iri(target: &str) -> String {
    match governed(target) {
        Some(_) => target.to_string(),
        None => format!("{target}.acl"),
    }
}
```

- [ ] **Step 4: Run them and watch them pass**

Run: `cargo test -p brolly-solid --lib ldp::tests`

Expected: `test result: ok. 6 passed` — the three new ones and the three
`governed` tests, which must be untouched.

- [ ] **Step 5: Format and lint**

```bash
cargo fmt --all
cargo clippy -p brolly-solid --all-targets -- -D warnings
```

Expected: clean. If `if_same_then_else` or `needless_return` fires, the `match`
above was rewritten into an `if`; put it back.

---

### Task 3: H6's `Link` set

`GET`, `HEAD` and `OPTIONS` say what the resource is, where its rules are,
which storage it belongs to, and — on the root — whose it is.

**Files:**
- Modify: `server/src/pod.rs`: imports (`:8-22`), `PodRequest` (`:25-33`),
  `resolve` (`:39-89`), a new `links()` beside `wac_allow` (`:254-266`), chunk
  2's header builder, and `mod tests` (`:578-599`)
- Modify: `server/tests/pod_http.rs`: two helpers and four tests

- [ ] **Step 1: Write the failing unit tests**

Append to `server/src/pod.rs`'s `mod tests`:

```rust
    const TEST_BASE: &str = "https://alice.brolly.test";
    const TEST_ROOT: &str = "https://alice.brolly.test/~/";
    const TEST_OWNER: &str = "https://alice.brolly.test/profile#me";

    fn links_for(resource: &str, kind: Option<Kind>) -> String {
        links(TEST_BASE, resource, TEST_ROOT, TEST_OWNER, kind)
    }

    /// The failure this guards: no `rel="type"` anywhere, so a client had to
    /// parse the body to tell a container from a document — which it cannot do
    /// at all for a binary.
    #[test]
    fn a_resource_announces_its_ldp_kinds() {
        let document = links_for(&format!("{TEST_ROOT}note"), Some(Kind::RdfSource));
        assert!(
            document.contains("<http://www.w3.org/ns/ldp#Resource>; rel=\"type\""),
            "{document}"
        );
        assert!(
            document.contains("<http://www.w3.org/ns/ldp#RDFSource>; rel=\"type\""),
            "{document}"
        );

        let binary = links_for(&format!("{TEST_ROOT}paper.pdf"), Some(Kind::NonRdfSource));
        assert!(binary.contains("ldp#NonRDFSource>; rel=\"type\""), "{binary}");

        // Both classes: Solid and CTS name `ldp:BasicContainer`, generic LDP
        // clients match `ldp:Container`, and one of the two audiences goes
        // blind if only one goes out.
        let container = links_for(&format!("{TEST_ROOT}notes/"), Some(Kind::Container));
        assert!(container.contains("ldp#Container>; rel=\"type\""), "{container}");
        assert!(
            container.contains("ldp#BasicContainer>; rel=\"type\""),
            "{container}"
        );

        // An `.acl` is an RDF source like any other document. Nothing in LDP
        // names an auxiliary class, and inventing one would be a lie a client
        // would have to special-case.
        let acl = links_for(&format!("{TEST_ROOT}notes/.acl"), Some(Kind::Auxiliary));
        assert!(acl.contains("ldp#RDFSource>; rel=\"type\""), "{acl}");
    }

    /// §4.1's MUST. Without it a client that walks up from a resource never
    /// learns where the storage begins, and 5a stated it only inside a body
    /// the client had to already be reading.
    #[test]
    fn only_the_storage_root_is_a_storage_and_has_an_owner() {
        let root = links_for(TEST_ROOT, Some(Kind::Container));
        assert!(
            root.contains("<http://www.w3.org/ns/pim/space#Storage>; rel=\"type\""),
            "{root}"
        );
        assert!(
            root.contains(
                "<https://alice.brolly.test/profile#me>; \
                 rel=\"http://www.w3.org/ns/solid/terms#owner\""
            ),
            "{root}"
        );

        let inside = links_for(&format!("{TEST_ROOT}notes/"), Some(Kind::Container));
        assert!(!inside.contains("space#Storage"), "{inside}");
        assert!(!inside.contains("terms#owner"), "{inside}");
    }

    /// H7 over the wire. The old concatenation pointed a client at
    /// `x.acl.acl`, which it would then create as an ordinary resource.
    #[test]
    fn the_acl_link_is_the_acl_that_governs_the_target() {
        let document = links_for(&format!("{TEST_ROOT}note"), Some(Kind::RdfSource));
        assert!(
            document.contains("<https://alice.brolly.test/~/note.acl>; rel=\"acl\""),
            "{document}"
        );

        let acl = links_for(&format!("{TEST_ROOT}note.acl"), Some(Kind::Auxiliary));
        assert!(
            acl.contains("<https://alice.brolly.test/~/note.acl>; rel=\"acl\""),
            "{acl}"
        );
        assert!(!acl.contains(".acl.acl"), "{acl}");
    }

    /// Every resource in a storage links its description (§4.1), whatever kind
    /// it is and whether or not it exists.
    #[test]
    fn every_resource_points_at_the_storage_description() {
        for (resource, kind) in [
            (format!("{TEST_ROOT}note"), Some(Kind::RdfSource)),
            (TEST_ROOT.to_string(), Some(Kind::Container)),
            (format!("{TEST_ROOT}nothing-here"), None),
        ] {
            let link = links_for(&resource, kind);
            assert!(
                link.contains(
                    "<https://alice.brolly.test/.well-known/solid>; \
                     rel=\"http://www.w3.org/ns/solid/terms#storageDescription\""
                ),
                "{resource}: {link}"
            );
        }
    }

    /// An `OPTIONS` asking "may I create here?" (H4) gets an answer that
    /// claims no kind: a target that doesn't exist has none, and implying one
    /// would make the header an existence oracle.
    #[test]
    fn a_target_that_does_not_exist_claims_no_kind() {
        let link = links_for(&format!("{TEST_ROOT}nothing-here"), None);
        assert!(!link.contains("rel=\"type\""), "{link}");
        assert!(
            link.contains("<https://alice.brolly.test/~/nothing-here.acl>; rel=\"acl\""),
            "{link}"
        );
    }
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-server --lib pod::tests`

Expected: the build fails with ``error[E0425]: cannot find function `links` in
this scope`` and ``error[E0433]: … use of undeclared type `Kind` ``.

- [ ] **Step 3: The member's WebID, resolved once**

In `server/src/pod.rs`, add a field to `PodRequest` (`:25-33`):

```rust
    /// The member's WebID: `solid:owner` on the storage root (H6), and the
    /// only place in a pod response that names the person rather than the pod.
    pub webid: String,
```

and set it in `resolve`, beside `base` (`:79-88`):

```rust
    let webid = webid::webid(&username, &state.base_domain);
```

then add `webid,` to the `PodRequest { … }` literal. `webid::webid` is already
imported (`:14`); deriving the value here rather than by `format!` in the
header builder keeps one definition of the WebID in the workspace.

- [ ] **Step 4: Write `links`**

Add to `server/src/pod.rs`'s imports:

```rust
use brolly_domain::vocab;
use brolly_solid::storage_description;
use brolly_store::resources::{Kind, Pod};
```

`Pod` is already imported on `:19`, so add `Kind` beside it. `mod tests`
picks `Kind` up through its existing `use super::*;`.

Insert after `wac_allow` (`:266`):

```rust
/// H6's `Link` set: what this resource is, where its rules are, which storage
/// it belongs to, and — on the root — whose it is.
///
/// One `Link` field with a value per link, comma-joined. `type` repeats its
/// relation for each class rather than listing several URIs under one `rel=`,
/// because that is the only form RFC 8288 defines and the only one every
/// client parser handles; it is also what LDP's own examples show.
///
/// `kind` is `None` when the target doesn't exist — an `OPTIONS` asking "may I
/// create here?" (H4). Then no `rel="type"` goes out at all: LDP §4.2.1.4 asks
/// for one on every response to an LDPR's URI, and we narrow it deliberately,
/// because a response about a resource that isn't there must not imply what
/// kind of thing would be. The `acl` and `storageDescription` links still go:
/// both exist whether or not the target does, and the ACL link is what a
/// client needs to *create* the rules for what it is about to write.
fn links(
    base: &str,
    resource: &str,
    storage_root: &str,
    owner: &str,
    kind: Option<Kind>,
) -> String {
    let is_root = resource == storage_root;
    let mut values: Vec<String> = Vec::new();

    if let Some(kind) = kind {
        let mut types = vec![vocab::LDP_RESOURCE];
        match kind {
            // Solid and CTS name `ldp:BasicContainer`; generic LDP clients
            // match `ldp:Container`. Sending one of them blinds the other.
            Kind::Container => {
                types.push(vocab::LDP_CONTAINER);
                types.push(vocab::LDP_BASIC_CONTAINER);
            }
            Kind::NonRdfSource => types.push(vocab::LDP_NON_RDF_SOURCE),
            // An `.acl` is an RDF source like any other document: LDP names no
            // auxiliary class, and inventing one would be ours alone.
            Kind::RdfSource | Kind::Auxiliary => types.push(vocab::LDP_RDF_SOURCE),
        }
        if is_root {
            // Solid Protocol §4.1: the storage MUST say so on its own URI.
            types.push(vocab::PIM_STORAGE);
        }
        values.extend(types.into_iter().map(|t| format!("<{t}>; rel=\"type\"")));
    }

    values.push(format!("<{}>; rel=\"acl\"", ldp::acl_iri(resource)));
    values.push(format!(
        "<{}>; rel=\"{}\"",
        storage_description::iri(base),
        vocab::SOLID_STORAGE_DESCRIPTION
    ));
    if is_root {
        // §4.1 constrains the form and leaves the choice to us. We advertise
        // it because the description names an owner anyway, and a client
        // holding the root shouldn't need a second request to learn whose.
        values.push(format!("<{owner}>; rel=\"{}\"", vocab::SOLID_OWNER));
    }
    values.join(", ")
}
```

`storage_description::iri` doesn't exist yet — Task 4 writes it. Until then use
`format!("{base}/.well-known/solid")` and change it back in Task 4, Step 5, or
do Task 4's Steps 3-4 first. Either order works; don't leave the `format!`
behind.

- [ ] **Step 5: Run the unit tests and watch them pass**

Run: `cargo test -p brolly-server --lib pod::tests`

Expected: `test result: ok. 6 passed` — the five new ones and 5a's
`the_new_ldp_refusals_have_status_codes`.

- [ ] **Step 6: Put the set into the shared builder**

In chunk 2's `headers_for`, replace the `Link` entry — 5a's was

```rust
            (
                header::LINK,
                format!("<{}{path}.acl>; rel=\"acl\"", request.base),
            ),
```

— with

```rust
            (
                header::LINK,
                links(
                    &request.base,
                    &format!("{}{path}", request.base),
                    &request.storage_root,
                    &request.webid,
                    description.kind,
                ),
            ),
```

using chunk 2's names for the builder's parameters. If chunk 2 kept the old
`format!` inside `get` rather than in the builder, move it: `GET`, `HEAD` and
`OPTIONS` must send the same set, because SolidOS draws its affordances from
whichever it last made.

- [ ] **Step 7: Write the HTTP tests**

The unit tests drove `links`, and these pin it to the wire. They follow the
implementation, so to see them fail first, run
`a_read_says_what_kind_of_resource_it_returned` with Step 6 stashed and
expect `assertion failed: document.contains("<http://www.w3.org/ns/ldp#Resource>; rel=\"type\"")`.

In `server/tests/pod_http.rs`, add two helpers next to `holds` (`:19-29`):

```rust
/// The `Link` field, as one string.
///
/// Several link values may arrive on one line or on several; RFC 9110 §5.3
/// says they mean the same thing, and a test that asks whether a link is there
/// shouldn't care which way the handler spelled it.
fn links(headers: &axum::http::HeaderMap) -> String {
    headers
        .get_all(header::LINK)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The target of the first link with this relation.
fn link_target(headers: &axum::http::HeaderMap, rel: &str) -> String {
    let all = links(headers);
    let marker = format!("; rel=\"{rel}\"");
    let end = all
        .find(&marker)
        .unwrap_or_else(|| panic!("no rel={rel} in {all}"));
    let start = all[..end].rfind('<').expect("a link target");
    all[start + 1..end - 1].to_string()
}
```

and, in the ACL section (after `wac_allow_on_an_acl_names_nothing_for_bob`,
`:1053`), the tests:

```rust
// --- discovery (stage 5b) ---------------------------------------------------

#[tokio::test]
async fn a_read_says_what_kind_of_resource_it_returned() {
    // The failure mode: nothing emitted `Link rel="type"`, so a client had to
    // parse the body to tell a container from a document, and had no way at
    // all to classify a binary.
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    h.send("PUT", "/~/paper.pdf", Some(("application/pdf", PDF)), true)
        .await;

    let (status, _, headers) = h.send("GET", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::OK);
    let document = links(&headers);
    assert!(
        document.contains("<http://www.w3.org/ns/ldp#Resource>; rel=\"type\""),
        "{document}"
    );
    assert!(document.contains("ldp#RDFSource>; rel=\"type\""), "{document}");
    assert!(!document.contains("ldp#Container"), "{document}");

    // HEAD is the request a file manager makes, and it must learn the same.
    let (_, _, headers) = h.send("HEAD", "/~/paper.pdf", None, true).await;
    assert!(
        links(&headers).contains("ldp#NonRDFSource>; rel=\"type\""),
        "{:?}",
        links(&headers)
    );

    let (_, _, headers) = h.send("GET", "/~/", None, true).await;
    let container = links(&headers);
    assert!(container.contains("ldp#Container>; rel=\"type\""), "{container}");
    assert!(
        container.contains("ldp#BasicContainer>; rel=\"type\""),
        "{container}"
    );
}

#[tokio::test]
async fn the_storage_root_advertises_itself_and_its_owner() {
    // §4.1's MUST, and the fix for problem 4: before this, `pim:Storage` was
    // stated only inside the root's own body, which a client had to already be
    // reading to find.
    let h = harness().await;
    let (status, _, headers) = h.send("GET", "/~/", None, true).await;
    assert_eq!(status, StatusCode::OK);
    let root = links(&headers);
    assert!(
        root.contains("<http://www.w3.org/ns/pim/space#Storage>; rel=\"type\""),
        "{root}"
    );
    assert!(
        root.contains(&format!(
            "<{BASE}/profile#me>; rel=\"http://www.w3.org/ns/solid/terms#owner\""
        )),
        "{root}"
    );

    // Only the root. A resource inside a storage is not itself one.
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let (_, _, headers) = h.send("GET", "/~/note", None, true).await;
    let note = links(&headers);
    assert!(!note.contains("space#Storage"), "{note}");
    assert!(!note.contains("terms#owner"), "{note}");
}

#[tokio::test]
async fn an_acl_links_itself_rather_than_a_fiction() {
    // `pod.rs` built this link by concatenation, so a GET of an `.acl`
    // advertised `<…/.acl.acl>` — an IRI with no ACL semantics that a client
    // following the link would create as an ordinary resource.
    let h = harness().await;
    share_with_bob(&h);

    let (status, _, headers) = h.send("GET", "/~/shared/.acl", None, true).await;
    assert_eq!(status, StatusCode::OK);
    let link = links(&headers);
    assert!(
        link.contains(&format!("<{ROOT}shared/.acl>; rel=\"acl\"")),
        "{link}"
    );
    assert!(!link.contains(".acl.acl"), "{link}");
}

#[tokio::test]
async fn options_carries_the_same_links_as_a_get() {
    // SolidOS reads its affordances from whichever of the two it made last.
    // Two answers for one resource is two different UIs for one resource.
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (_, _, read) = h.send("GET", "/~/note", None, true).await;
    let (status, _, options) = h.send("OPTIONS", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(links(&options), links(&read));
}

#[tokio::test]
async fn options_on_a_target_that_does_not_exist_claims_no_kind() {
    // "May I create here?" is a fair question (H4), and the answer must not
    // say what kind of thing is — or isn't — already there.
    let h = harness().await;
    let (status, _, headers) = h.send("OPTIONS", "/~/nothing-here", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let link = links(&headers);
    assert!(!link.contains("rel=\"type\""), "{link}");
    assert!(
        link.contains(&format!("<{ROOT}nothing-here.acl>; rel=\"acl\"")),
        "{link}"
    );
}
```

- [ ] **Step 8: Run them and watch them pass**

Run the five by name:

```bash
cargo test -p brolly-server --test pod_http a_read_says_what_kind_of_resource_it_returned
cargo test -p brolly-server --test pod_http the_storage_root_advertises_itself_and_its_owner
cargo test -p brolly-server --test pod_http an_acl_links_itself_rather_than_a_fiction
cargo test -p brolly-server --test pod_http options_carries_the_same_links_as_a_get
cargo test -p brolly-server --test pod_http options_on_a_target_that_does_not_exist_claims_no_kind
```

Expected: `test result: ok. 1 passed` each time. They need Docker for the
Postgres container, and one suite at a time — parallel container runs cause
false failures.

If `options_carries_the_same_links_as_a_get` fails with two different strings,
chunk 2's `OPTIONS` isn't going through the shared builder. Fix that rather
than duplicating the `Link` line.

- [ ] **Step 9: Run the whole suite**

Run: `cargo test -p brolly-server --test pod_http`

Expected: all pass. In particular `bob_cannot_delete_an_acl_he_does_not_control`
(`:1012`) still answers 403 — that ACL is `/~/shared/.acl`, not the root's, and
Bob is authenticated without `Control`.

- [ ] **Step 10: Format and lint**

```bash
cargo fmt --all
cargo clippy -p brolly-server --all-targets -- -D warnings
```

---

### Task 4: The storage description

A generated, world-readable, read-only document at `/.well-known/solid` on
every pod subdomain.

**Files:**
- Create: `adapters/solid/src/storage_description.rs`
- Modify: `adapters/solid/src/lib.rs` (`:11-17`)
- Modify: `server/src/pod.rs` (module doc `:1-6`, imports, a new handler)
- Modify: `server/src/lib.rs` (imports `:13`, the route beside `nodeinfo`
  `:283-288`)
- Modify: `server/tests/pod_http.rs`

- [ ] **Step 1: Write the failing unit tests**

Create `adapters/solid/src/storage_description.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use brolly_domain::vocab;

    const BASE: &str = "https://alice.brolly.test";
    const OWNER: &str = "https://alice.brolly.test/profile#me";

    /// A client reads `pim:Storage` here to confirm what it found. Solid
    /// Protocol §4.1 makes the link mandatory; a document at the end of it
    /// that types nothing answers no question.
    #[test]
    fn the_description_types_itself_as_a_storage() {
        let quads = document(BASE, OWNER);
        assert!(
            quads.iter().any(|q| {
                q.predicate.as_str() == vocab::RDF_TYPE
                    && q.object.to_string() == format!("<{}>", vocab::PIM_STORAGE)
            }),
            "{quads:?}"
        );
    }

    /// Without this a client that has the storage still has to fetch the root
    /// and read *its* header to learn whose it is.
    #[test]
    fn the_description_names_its_owner() {
        let quads = document(BASE, OWNER);
        assert!(
            quads.iter().any(|q| {
                q.predicate.as_str() == vocab::SOLID_OWNER
                    && q.object.to_string() == format!("<{OWNER}>")
            }),
            "{quads:?}"
        );
    }

    /// Everything is said about the IRI the document is served from. A
    /// description whose subject is some other IRI is a document about
    /// something else, and a client following `rel="storageDescription"` has
    /// no way to notice.
    #[test]
    fn the_description_describes_the_iri_it_is_served_from() {
        assert_eq!(iri(BASE), format!("{BASE}/.well-known/solid"));
        let subject = format!("<{}>", iri(BASE));
        for quad in document(BASE, OWNER) {
            assert_eq!(quad.subject.to_string(), subject, "{quad}");
            assert_eq!(quad.graph_name.to_string(), subject, "{quad}");
        }
    }
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-solid --lib storage_description`

Expected: ``error[E0583]: file not found for module `storage_description` ``
until the module is declared; once it is,
``error[E0425]: cannot find function `document` in this scope``.

- [ ] **Step 3: Write the document**

Prepend to `adapters/solid/src/storage_description.rs`:

```rust
//! The storage description (Solid Protocol §4.1).
//!
//! **Generated, never stored.** It holds nothing a member could edit, and
//! storing it would put a resource *inside* the storage that describes the
//! storage, which `ldp:contains` would then list.
//!
//! **World-readable, and no ACL governs it.** It describes the storage, not
//! its contents, and a client has to be able to read it *before* it has a
//! credential — that is how it discovers where to authenticate. There is no
//! WAC exemption to write, because there is no stored resource here for an ACL
//! to be about: everything below is derived from the routing table.

use brolly_domain::vocab;
use oxigraph::model::{GraphName, NamedNode, NamedOrBlankNode, Quad, Term};

/// Where it is served, on every pod subdomain.
///
/// The protocol mandates the `Link` relation, not a path. This is the path CSS
/// uses for the same document, so a client that has seen one server recognises
/// ours, and our own well-known space stays clear: `openid-configuration` is
/// apex-only, `webfinger` and `nodeinfo` are apex paths, and ATProto's
/// `oauth-authorization-server` and `atproto-did` are different names.
pub const PATH: &str = "/.well-known/solid";

/// The description's own IRI on `base` (`https://alice.brolly.id`).
///
/// The one place this string is built. `pod::links` advertises it and
/// `pod::storage_description` serves it; if they ever disagree, the link goes
/// to a 404 and discovery stops there.
pub fn iri(base: &str) -> String {
    format!("{base}{PATH}")
}

fn n(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

/// This storage, and whose it is.
///
/// Two triples, both about the description's own IRI, in its own graph — the
/// shape `brolly_solid::profile` uses, so a serializer that keeps graphs
/// (TriG, N-Quads) names the document rather than the default graph.
pub fn document(base: &str, owner: &str) -> Vec<Quad> {
    let subject = n(&iri(base));
    let graph = GraphName::NamedNode(subject.clone());
    [
        (vocab::RDF_TYPE, vocab::PIM_STORAGE),
        (vocab::SOLID_OWNER, owner),
    ]
    .into_iter()
    .map(|(predicate, object)| {
        Quad::new(
            NamedOrBlankNode::NamedNode(subject.clone()),
            n(predicate),
            Term::NamedNode(n(object)),
            graph.clone(),
        )
    })
    .collect()
}
```

and declare it in `adapters/solid/src/lib.rs`, after `pub mod storage;`:

```rust
pub mod storage_description;
```

- [ ] **Step 4: Run them and watch them pass**

Run: `cargo test -p brolly-solid --lib storage_description`

Expected: `test result: ok. 3 passed`.

- [ ] **Step 5: Point `links` at the real IRI**

If Task 3, Step 4 left `format!("{base}/.well-known/solid")` in `pod::links`,
replace it with `storage_description::iri(base)` now.

Run: `cargo test -p brolly-server --lib pod::tests`

Expected: `test result: ok. 6 passed`, unchanged.

- [ ] **Step 6: Write the failing HTTP tests**

Append to the discovery section of `server/tests/pod_http.rs`:

```rust
#[tokio::test]
async fn the_advertised_storage_description_resolves() {
    // The link and the route drifting apart is the failure: §4.1 requires the
    // relation, and a client that follows it to a 404 has no other way to
    // discover the storage. So follow it, rather than asserting the path.
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let (_, _, headers) = h.send("GET", "/~/note", None, true).await;
    let target = link_target(
        &headers,
        "http://www.w3.org/ns/solid/terms#storageDescription",
    );
    let path = target
        .strip_prefix(BASE)
        .unwrap_or_else(|| panic!("the description is on the pod's own origin: {target}"));

    // Anonymously: discovery precedes credentials.
    let (status, body, headers) = h.send("GET", path, None, false).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/turtle"),
        "{headers:?}"
    );
    assert!(
        body.contains("http://www.w3.org/ns/pim/space#Storage"),
        "{body}"
    );
    assert!(body.contains(&format!("{BASE}/profile#me")), "{body}");
}

#[tokio::test]
async fn the_storage_description_negotiates_like_a_pod_read() {
    // A JSON-LD client (Inrupt's, LDO) asks for JSON-LD everywhere. Answering
    // Turtle regardless is a parse error a long way from its cause.
    let h = harness().await;
    let request = Request::builder()
        .method("GET")
        .uri("/.well-known/solid")
        .header(header::HOST, HOST)
        .header(header::ACCEPT, "application/ld+json")
        .body(Body::empty())
        .unwrap();
    let (status, body, headers) = run(h.router.clone(), request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("application/ld+json"),
        "{headers:?}"
    );
}

#[tokio::test]
async fn the_storage_description_is_read_only() {
    // It is generated from the routing table, so there is nothing a write
    // could change. The failure is a write that *looks* accepted — or a 405
    // with no `Allow`, which RFC 9110 §15.5.6 makes a MUST (H16).
    let h = harness().await;
    for method in ["PUT", "POST", "PATCH", "DELETE"] {
        let (status, _, headers) = h
            .send(
                method,
                "/.well-known/solid",
                Some(("text/turtle", NOTE)),
                true,
            )
            .await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
        assert_eq!(headers[header::ALLOW], "GET, HEAD, OPTIONS", "{method}");
    }

    let (status, _, headers) = h.send("OPTIONS", "/.well-known/solid", None, false).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(headers[header::ALLOW], "GET, HEAD, OPTIONS");

    // HEAD is GET without the body, and anonymous like GET.
    let (status, body, _) = h.send("HEAD", "/.well-known/solid", None, false).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty(), "HEAD sent a body: {body}");
}

#[tokio::test]
async fn the_apex_has_no_storage_description() {
    // Routes aren't host-scoped, so the handler decides. The apex is not a
    // storage, and a description there would describe nobody's pod. Every
    // method gets the 404 — a 405 would say the resource exists.
    let h = harness().await;
    for method in ["GET", "OPTIONS", "PUT"] {
        let request = Request::builder()
            .method(method)
            .uri("/.well-known/solid")
            .header(header::HOST, "brolly.test")
            .body(Body::empty())
            .unwrap();
        let (status, _, _) = run(h.router.clone(), request).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method}");
    }
}

#[tokio::test]
async fn an_unknown_pod_has_no_storage_description() {
    // A description naming a member who doesn't exist would be a storage
    // that isn't there.
    let h = harness().await;
    let request = Request::builder()
        .method("GET")
        .uri("/.well-known/solid")
        .header(header::HOST, "nobody.brolly.test")
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = run(h.router.clone(), request).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
```

- [ ] **Step 7: Run them and watch them fail**

Run: `cargo test -p brolly-server --test pod_http storage_description`

Expected: five tests run and three fail on the status. `the_advertised…` and
`…negotiates…` fail with `left: 404, right: 200`, because the path falls
through to `subdomain_fallback`'s `NotFound` arm, and `…is_read_only` fails
with `left: 404, right: 405`. `the_apex_has_no_storage_description` and
`an_unknown_pod_has_no_storage_description` already pass. They are there to
stay green once the route exists.

- [ ] **Step 8: The handler**

In `server/src/pod.rs`, extend the imports:

```rust
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use brolly_domain::syntax;
```

(if chunk 1 already imports `Method` for H15, only `syntax` is new).

Add a sentence to the module doc (`:3-6`), after "the protocol resources are
explicit routes;":

```rust
//! the storage description (`/.well-known/solid`) is one of them, generated
//! here rather than stored;
```

and add the handler after `subdomain_fallback`:

```rust
/// `/.well-known/solid` — the storage description (Solid Protocol §4.1, H8).
///
/// World-readable and read-only, and WAC never enters into it. It says what a
/// client needs to know *before* it has a credential — which storage this is
/// and whose — and it is generated from the routing table, so there is no
/// stored resource for an ACL to govern.
///
/// Routed in `app()` beside `webfinger` and `nodeinfo`, so it never reaches
/// [`subdomain_fallback`] and has no entry in `USER_PROTOCOL_RESOURCES`, which
/// feeds only that fallback. Routes aren't host-scoped, so the subdomain is
/// resolved here, as `/profile` resolves it, and the apex 404s.
///
/// Every method is routed here (`any`), so this decides: the apex and an
/// unknown pod are 404 whatever the method — a 405 there would say the
/// resource exists — and on a pod anything but a read is 405 with our own
/// `Allow` (H16).
pub async fn storage_description(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    const ALLOW: &str = "GET, HEAD, OPTIONS";

    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let Some(username) = extract::subdomain_user(host, &state.base_domain) else {
        return (StatusCode::NOT_FOUND, "no such pod").into_response();
    };
    match db::find_by_username(&state.pool, &username).await {
        Ok(Some(user)) if user.is_active() => {}
        Ok(_) => return (StatusCode::NOT_FOUND, "no such pod").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "pod lookup failed serving a storage description");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    match method {
        // Axum strips the body from a HEAD at the top-level route, whichever
        // method router endpoint answered it.
        Method::GET | Method::HEAD => {}
        Method::OPTIONS => {
            return (StatusCode::NO_CONTENT, [(header::ALLOW, ALLOW)]).into_response();
        }
        _ => {
            return (
                StatusCode::METHOD_NOT_ALLOWED,
                [(header::ALLOW, ALLOW)],
                "the storage description is generated, and read-only",
            )
                .into_response();
        }
    }

    let base = format!("https://{username}.{}", state.base_domain);
    let quads = brolly_solid::storage_description::document(
        &base,
        &webid::webid(&username, &state.base_domain),
    );
    let format = syntax::negotiate(headers.get(header::ACCEPT).and_then(|h| h.to_str().ok()));
    match syntax::serialize(&quads, format) {
        Ok(body) => (
            [(header::CONTENT_TYPE, format.media_type().to_string())],
            body,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "serialising a storage description failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
```

The handler never opens the pod. Both IRIs come from the username and the
base domain, and the user lookup is what makes an unknown or suspended pod
404.

- [ ] **Step 9: The route**

In `server/src/lib.rs`, change `:13` to

```rust
use axum::routing::{any, get, post};
```

and add, immediately after the `/.well-known/nodeinfo` route (`:284-287`):

```rust
        // The storage description (Solid Protocol §4.1). Served on every pod
        // subdomain; the handler resolves the host itself, as `/profile`
        // does, and 404s on the apex. `any`, not `get`: the method router's
        // own 405 would answer on the apex too, where the resource doesn't
        // exist, and the handler's 405 carries an `Allow` we chose.
        .route("/.well-known/solid", any(pod::storage_description))
```

The CORS layer answers a preflight before routing (`lib.rs:161`), so a
preflight `OPTIONS` never reaches `any`; a bare `OPTIONS` does and gets 204.

- [ ] **Step 10: Run them and watch them pass**

Run: `cargo test -p brolly-server --test pod_http storage_description`

Expected: `test result: ok. 5 passed`.

- [ ] **Step 11: The routing rules still hold**

The new route is outside `/~/` and outside `USER_PROTOCOL_RESOURCES`. Neither
list changes, and these must stay green unchanged:

```bash
cargo test -p brolly-identity --lib routing
cargo test -p brolly-server --test pod_http an_unmatched_subdomain_path_does_not_fall_through_to_ldp
cargo test -p brolly-server --test pod_http oauth_paths_on_a_subdomain_are_not_pod_writes
```

Expected: `ok. 9 passed`, then `ok. 1 passed` twice.

- [ ] **Step 12: Format and lint**

```bash
cargo fmt --all
cargo clippy -p brolly-solid -p brolly-server --all-targets -- -D warnings
```

---

### Task 5: `/~/` routes the write methods, and its 405s carry `Allow`

`/~/` is registered with `get`, `post` and `options` only
(`server/src/lib.rs:319-324`). So axum's method router answers `DELETE /~/`
before any handler runs: `ldp.rs:877`'s root guard is dead over HTTP, and an
anonymous caller is told "405" — the target exists and is special — where H4
says it must be told to authenticate. This task adds the routes, then gives
the 405s this server generates itself an `Allow`.

**Files:**
- Modify: `server/src/lib.rs` (the `/~/` route, `:319-324`)
- Modify: `server/src/pod.rs`: new root handlers beside `get_root`/`post_root`
  (`:511-526`), `ldp_error`, `delete`, `subdomain_fallback` (`:554-576`)
- Modify: `server/tests/pod_http.rs`

- [ ] **Step 1: Write the failing tests**

Add a helper to `server/tests/pod_http.rs`, beside `links`:

```rust
/// The methods an `Allow` field names. Axum's own 405 joins them with `,` and
/// ours with `, `; a test asking whether a method is offered shouldn't care.
fn allowed(headers: &axum::http::HeaderMap) -> Vec<String> {
    headers
        .get(header::ALLOW)
        .expect("a 405 without Allow breaks RFC 9110 §15.5.6")
        .to_str()
        .unwrap()
        .split(',')
        .map(|m| m.trim().to_string())
        .filter(|m| !m.is_empty())
        .collect()
}
```

and append to the discovery section:

```rust
// --- the storage root (stage 5b, H12 and H16) --------------------------------

#[tokio::test]
async fn an_anonymous_delete_of_the_storage_root_is_a_challenge_not_a_405() {
    // Authorization comes before method availability (H4). Axum's generated
    // 405 answered this before any handler ran, which told a caller with no
    // access at all that the target exists and is special.
    let h = harness().await;
    let (status, _, headers) = h.send("DELETE", "/~/", None, false).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        headers.contains_key(header::WWW_AUTHENTICATE),
        "a 401 tells the client how to authenticate: {headers:?}"
    );
}

#[tokio::test]
async fn the_owner_cannot_delete_the_storage_root() {
    // §5.4's first undeletable resource. Without its root a pod has nowhere to
    // put anything, and only provisioning records one. The 405 must list what
    // the owner *can* do, which is everything but this.
    let h = harness().await;
    let (status, _, headers) = h.send("DELETE", "/~/", None, true).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let allow = allowed(&headers);
    assert!(!allow.iter().any(|m| m == "DELETE"), "{allow:?}");
    for method in ["GET", "PUT", "PATCH", "POST"] {
        assert!(
            allow.iter().any(|m| m == method),
            "the owner holds Write, so {method} is on offer: {allow:?}"
        );
    }

    let (status, _, _) = h.send("GET", "/~/", None, true).await;
    assert_eq!(status, StatusCode::OK, "the refused DELETE landed");
}

#[tokio::test]
async fn the_storage_root_takes_a_put_and_a_patch() {
    // A member may describe their own storage root like any other container.
    // With no route, both were axum's 405, whatever the caller's modes.
    let h = harness().await;
    let (status, body, _) = h
        .send(
            "PUT",
            "/~/",
            Some(("text/turtle", r#"<> <https://example.org/title> "Home" ."#)),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let (status, body, _) = h
        .send(
            "PATCH",
            "/~/",
            Some((
                "application/sparql-update",
                r#"INSERT DATA { <https://alice.brolly.test/~/> <https://example.org/note> "Mine" }"#,
            )),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let (status, root, _) = h.send("GET", "/~/", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(root.contains("Home") && root.contains("Mine"), "{root}");
}

#[tokio::test]
async fn the_bare_storage_path_answers_its_405_with_an_allow() {
    // RFC 9110 §15.5.6 makes `Allow` a MUST on a 405, and
    // `subdomain_fallback`'s storage arm sent none. `/~` without its slash is
    // the one path that still reaches it (H16).
    let h = harness().await;
    for method in ["GET", "DELETE"] {
        let (status, _, headers) = h.send(method, "/~", None, true).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
        assert!(headers.contains_key(header::ALLOW), "{method}: {headers:?}");
    }
}
```

The PUT's body carries no `ldp:contains`, so `container_body`
(`adapters/solid/src/ldp.rs:596`) leaves membership alone and keeps the title.
The 5a harness's root ACL grants Alice `acl:accessTo` the root with Read and
Write, which is what both writes need.

- [ ] **Step 2: Run them and watch them fail**

```bash
cargo test -p brolly-server --test pod_http an_anonymous_delete_of_the_storage_root_is_a_challenge_not_a_405
cargo test -p brolly-server --test pod_http the_owner_cannot_delete_the_storage_root
cargo test -p brolly-server --test pod_http the_storage_root_takes_a_put_and_a_patch
cargo test -p brolly-server --test pod_http the_bare_storage_path_answers_its_405_with_an_allow
```

Expected, in order:
- `assertion `left == right` failed` with `left: 405`, `right: 401`: axum's
  method router.
- `the owner holds Write, so PUT is on offer: ["GET", "HEAD", "POST",
  "OPTIONS"]`: that is axum's `Allow`, built from the three registered
  methods. The status already matches, which is why the test asserts the
  `Allow`.
- `left: 405`, `right: 204` on the PUT.
- `assertion failed: headers.contains_key(header::ALLOW)` with `GET: {…}`:
  the status is already 405, and the header is missing.

- [ ] **Step 3: The root handlers**

In `server/src/pod.rs`, after `post_root` (`:526`), add three handlers. Each
copies `get_root`'s signature **exactly as chunk 1 left it**, with `Method`
and `OriginalUri` before everything else and `body` last for the two that take
one. Each delegates to the wildcard handler with an empty path, as `get_root`
and `post_root` already do:

```rust
/// `PUT /~/`.
///
/// The wildcard route doesn't match an empty remainder (see [`get_root`]).
/// Without these entries, axum's method router answered every write to the
/// root with its own 405, before any handler ran. `ldp`'s root protections
/// were unreachable over HTTP, and a caller with no access was told the
/// target is special (H12). Each one delegates, so WAC runs first and
/// refuses in the ordinary way.
pub async fn put_root(
    state: State<AppState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    put(state, method, uri, headers, Path(String::new()), body).await
}

/// `PATCH /~/`. See [`put_root`].
pub async fn patch_root(
    state: State<AppState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    patch(state, method, uri, headers, Path(String::new()), body).await
}

/// `DELETE /~/`. Always refused: after the Write check, `ldp::delete_in`
/// answers `Undeletable`, which is a 405 (§5.4). See [`put_root`].
pub async fn delete_root(
    state: State<AppState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
) -> Response {
    delete(state, method, uri, headers, Path(String::new())).await
}
```

`OriginalUri` is `axum::extract::OriginalUri`. Chunk 1 imports it for H15. If
chunk 1 ordered the extractors differently, follow `get_root`: `Path` has to
come last before the body, and the root handlers pass their arguments in the
wildcard handler's order.

- [ ] **Step 4: The routes**

In `server/src/lib.rs`, replace the `/~/` route (`:319-324`) with:

```rust
        // The storage root. The wildcard above doesn't match an empty
        // remainder, so the root needs every method of its own. That includes
        // the ones it always refuses: without a route, axum answers 405 before
        // WAC runs, and the root's protections are unreachable (5b, H12).
        .route(
            "/~/",
            get(pod::get_root)
                .put(pod::put_root)
                .post(pod::post_root)
                .patch(pod::patch_root)
                .delete(pod::delete_root)
                .options(pod::options_root),
        )
```

`pod::options_root` is chunk 2's. If chunk 2 named it differently, use its
name.

- [ ] **Step 5: Run them and watch two pass**

```bash
cargo test -p brolly-server --test pod_http an_anonymous_delete_of_the_storage_root_is_a_challenge_not_a_405
cargo test -p brolly-server --test pod_http the_storage_root_takes_a_put_and_a_patch
cargo test -p brolly-server --test pod_http the_owner_cannot_delete_the_storage_root
```

Expected: `ok. 1 passed`, `ok. 1 passed`, then the third fails with
`left: 403`, `right: 405`. The route reaches `delete_in`, whose root guard
answers `Undeletable`, and chunk 1 still maps that to 403.

- [ ] **Step 6: `Undeletable` is a 405, with the caller's `Allow`**

A 405 needs an `Allow`, and H4's `Allow` depends on the caller's modes. So
`ldp_error`, which sees only the error, can't build it, and `delete` handles
the refusal itself. In `server/src/pod.rs`, after `ldp_error`, add:

```rust
/// A 405 for a resource that exists and can't be deleted: the storage root, or
/// its ACL (Solid Protocol §5.4).
///
/// Only reached after `ldp` has authorized the DELETE. A caller without the
/// mode got 401 or 403 before `Undeletable` could be returned (H4:
/// authorization before method availability). So the `Allow` here, from the
/// same description `OPTIONS` would give, tells the caller nothing it couldn't
/// have asked for. H4's table already leaves `DELETE` out for these two
/// targets. No `Link` goes out: H6 is for successful reads and creates.
fn undeletable(request: &PodRequest, path: &str) -> Response {
    let description = match ldp::describe(&request.pod, &request.base, path, &request.subject) {
        Ok(description) => description,
        Err(e) => return ldp_error(e),
    };
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(header::ALLOW, allow(&description))],
        "the storage root and its ACL can't be deleted",
    )
        .into_response()
}
```

Call `ldp::describe` and `allow` the way chunk 2's `options` calls them. If
`describe` takes more arguments, such as the blob store, pass what `options`
passes.

In `delete`, handle it before the catch-all:

```rust
    match ldp::delete_if(
        // …unchanged…
    ) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(LdpError::Undeletable) => undeletable(&request, &path),
        Err(e) => ldp_error(e),
    }
```

In `ldp_error`, replace the `Undeletable` arm chunk 1 wrote (a 403) with:

```rust
        // `delete` answers this itself, with the caller's `Allow`: a 405
        // without one breaks RFC 9110 §15.5.6. Nothing else produces it, so
        // reaching here means a new producer that needs the same treatment.
        LdpError::Undeletable => {
            tracing::error!("Undeletable reached ldp_error; its caller must build the 405");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
```

If chunk 1 added a unit test in `pod.rs`'s `mod tests` asserting
`ldp_error(LdpError::Undeletable)` is 403, delete that assertion. The HTTP
tests now carry the status.

- [ ] **Step 7: Run it and watch it pass**

Run: `cargo test -p brolly-server --test pod_http the_owner_cannot_delete_the_storage_root`

Expected: `test result: ok. 1 passed`. If it fails on the `DELETE` assertion,
chunk 2's `Allow` doesn't remove `DELETE` for the storage root. H4's table
requires that, so add it to chunk 2's builder.

- [ ] **Step 8: `Allow` on the fallback's storage arm**

In `subdomain_fallback` (`server/src/pod.rs:557-560`), replace the
`UserStorage` arm with:

```rust
        SubdomainRoute::UserStorage => (
            // Every method under `/~/` is routed now, and a method axum
            // doesn't route there gets axum's own 405, which carries its own
            // `Allow`. So this arm serves the bare `/~` alone: the storage
            // prefix without its slash, which no route matches and which
            // supports no method. RFC 9110 §15.5.6 requires `Allow` on a 405
            // (H16), and §10.2.1 lets it be empty, which is the true answer
            // here. Whether `/~` should redirect to `/~/` belongs to 5c's
            // `/foo` vs `/foo/` work.
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, "")],
            "user storage lives under /~/",
        )
            .into_response(),
```

- [ ] **Step 9: Run it and watch it pass**

Run: `cargo test -p brolly-server --test pod_http the_bare_storage_path_answers_its_405_with_an_allow`

Expected: `test result: ok. 1 passed`. `allowed()` filters out empty entries,
so the test checks only that the header is there, not what it names.

- [ ] **Step 10: Format and lint**

```bash
cargo fmt --all
cargo clippy -p brolly-server --all-targets -- -D warnings
```

---

### Task 6: The storage root's ACL can't be deleted

Solid Protocol §5.4 names two undeletable resources: the storage root and the
root's ACL. `delete_in` guards the first (`ldp.rs:877`) and has no guard for
the second. WAC §3.2 makes deleting an ACL the way a resource falls back to its
container's rules, but the root has no container. Delete its ACL and
`effective_acl` finds nothing above any resource, so the whole pod refuses its
own member. Only provisioning writes a root ACL, so nothing over HTTP can put
it back.

The test comes first as a **characterization**: it proves today's behaviour
over the wire before it is turned around.

**Files:**
- Modify: `server/tests/pod_http.rs`
- Modify: `adapters/solid/src/ldp.rs` (`delete_in`, `:856-889`)

- [ ] **Step 1: Pin today's behaviour**

Add a helper to `server/tests/pod_http.rs`, after `share_with_bob` (`:937`):

```rust
/// Rewrite the root ACL so Alice holds `Control` there as well. The harness's
/// ACL grants only Read and Write, so that no other test can touch an `.acl` by
/// accident. This one has to be able to.
fn control_at_the_root(h: &Harness) {
    let pod = h.stores.pod(h.user).unwrap();
    let g = format!("{ROOT}.acl");
    let a = format!("{g}#owner");
    let grant = [
        t(&g, &a, &format!("{ACL}default"), ROOT),
        t(&g, &a, &format!("{ACL}accessTo"), ROOT),
        t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")),
        t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Write")),
        t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Control")),
        t(
            &g,
            &a,
            &format!("{ACL}agent"),
            &format!("{BASE}/profile#me"),
        ),
    ];
    pod.write(|w| w.put(&g, Content::Auxiliary(&grant)).map(|_| ()))
        .unwrap();
}
```

and, in the storage-root section, the characterization:

```rust
/// **Characterization, turned around in Step 3.** Today a caller holding
/// `Control` at the root can delete `/~/.acl`, and the pod is then shut to its
/// own member: with no ACL anywhere up the path, WAC grants nothing.
#[tokio::test]
async fn the_storage_roots_acl_cannot_be_deleted() {
    let h = harness().await;
    control_at_the_root(&h);

    let (status, _, _) = h.send("DELETE", "/~/.acl", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "today's behaviour");

    let (status, _, _) = h.send("GET", "/~/", None, true).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "today: the member is locked out of their own pod"
    );
}
```

The name is the one the test keeps after Step 3. It names the behaviour it
will guard, and this step only proves that behaviour is missing.

- [ ] **Step 2: Run it and watch it pass**

Run: `cargo test -p brolly-server --test pod_http the_storage_roots_acl_cannot_be_deleted`

Expected: `test result: ok. 1 passed`. That green result is the finding.
`/~/.acl` already routes through the `/~/{*path}` wildcard. `check()` reads
the `.acl` through `governed()` and asks for Control on `/~/`, which the
helper grants. Its kind is `Auxiliary`, not `Container`, so neither existing
guard fires and `w.remove` runs.

If it fails with 403 on the DELETE, the helper didn't grant `Control`: check
that `w.put` replaced the root ACL rather than adding a second one. If it fails
with 405, the guard is already there, and this task is the test alone.

- [ ] **Step 3: Turn it around**

Replace the test with:

```rust
/// Solid Protocol §5.4 names two undeletable resources, the storage root and
/// its ACL, and until 5b the second one could be deleted by anyone holding
/// `Control`. That shuts the pod to its own member. Deleting an ACL is how a
/// resource falls back to its container's rules (WAC §3.2), the root has no
/// container, so no rule is left anywhere, and only provisioning ever writes a
/// root ACL.
#[tokio::test]
async fn the_storage_roots_acl_cannot_be_deleted() {
    let h = harness().await;
    control_at_the_root(&h);

    // Authorization first (H4). A caller without Control is refused for that
    // reason, and learns nothing about the resource being special.
    let (status, _, _) = h.send("DELETE", "/~/.acl", None, false).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _, headers) = h.send("DELETE", "/~/.acl", None, true).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let allow = allowed(&headers);
    assert!(!allow.iter().any(|m| m == "DELETE"), "{allow:?}");
    assert!(
        allow.iter().any(|m| m == "PUT"),
        "Control still lets the member rewrite their root's rules: {allow:?}"
    );

    let pod = h.stores.pod(h.user).unwrap();
    assert!(
        pod.read(|r| r.meta(&format!("{ROOT}.acl")))
            .unwrap()
            .is_some(),
        "the refused DELETE landed"
    );
    let (status, _, _) = h.send("GET", "/~/", None, true).await;
    assert_eq!(status, StatusCode::OK, "the member can still read their pod");
}
```

- [ ] **Step 4: Run it and watch it fail**

Run: `cargo test -p brolly-server --test pod_http the_storage_roots_acl_cannot_be_deleted`

Expected: the anonymous assertion passes (401 from chunk 1). The owner's fails
with `assertion `left == right` failed`, `left: 204`, `right: 405`.

- [ ] **Step 5: The guard**

In `adapters/solid/src/ldp.rs`'s `delete_in`, directly after the storage-root
guard (`:877-879`, which returns `Undeletable` since chunk 1), add:

```rust
    // The root's ACL is undeletable too (§5.4). Deleting an ACL is how a
    // resource falls back to its container's rules (WAC §3.2), and the root
    // has no container: the pod would be left with no rule anywhere, and only
    // provisioning writes one. Only this ACL. Every other `.acl` may be
    // deleted by a caller with Control, because that is how a member un-shares.
    if resource == acl_iri(storage_root) {
        return Err(LdpError::Undeletable);
    }
```

The guard sits where the root's does: after the WAC check, the not-found
check and the preconditions. A caller without `Control` gets `Denied`, a
missing root ACL gets `NotFound`, and a stale `If-Match` gets 412. Only a
caller who would otherwise have deleted it sees the 405.

Also update the comment on the root guard just above, which still says "5b
answers 405 here". It does now, so the comment becomes:

```rust
    // Without its root a pod has nowhere to put anything, and only
    // provisioning records one. `pod.rs` answers 405 (§5.4).
```

- [ ] **Step 6: Run it and watch it pass**

Run: `cargo test -p brolly-server --test pod_http the_storage_roots_acl_cannot_be_deleted`

Expected: `test result: ok. 1 passed`.

- [ ] **Step 7: Every other ACL is still deletable, and still guarded**

The guard must not reach any other `.acl`. Two existing tests pin its edges:

```bash
cargo test -p brolly-server --test pod_http bob_cannot_delete_an_acl_he_does_not_control
cargo test -p brolly-solid --test acl_control
```

Expected: `ok. 1 passed` for the first. It still answers **403**:
`/~/shared/.acl` is not the root's ACL, and Bob is authenticated without
`Control`, so `Denied` fires before the guard is reached. Then the whole
`acl_control` suite passes, including its deletes of container ACLs by a
caller with `Control`, which WAC §3.2 relies on.

If `bob_cannot_delete_…` now answers 405, the guard was placed before the WAC
check. Move it below.

- [ ] **Step 8: The adapter's own suites**

`delete_in` changed, so run the suites that drive it directly, one at a time:

```bash
cargo test -p brolly-solid --lib
cargo test -p brolly-solid --test ldp_conformance
cargo test -p brolly-solid --test ldp_nonrdf
```

Expected: all pass. None of them deletes `/~/.acl`. If one does, it was
asserting the bug. Rewrite it to expect `LdpError::Undeletable`, and say so in
the commit message.

- [ ] **Step 9: Format and lint**

```bash
cargo fmt --all
cargo clippy -p brolly-solid -p brolly-server --all-targets -- -D warnings
```

---

### Task 7: The workspace gates, then commit

- [ ] **Step 1: The whole `pod_http` suite**

Run: `cargo test -p brolly-server --test pod_http`

Expected: all pass. That covers the fifteen tests this chunk adds (five from
Task 3, five from Task 4, four from Task 5 and one from Task 6), every test
chunks 1 and 2 rewrote, and `bob_cannot_delete_an_acl_he_does_not_control` at
403.

- [ ] **Step 2: Gates**

Run them one at a time, never alongside another test run: parallel Docker
runs cause false failures.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
./tools/check-doc-paths.sh
cargo deny check
cargo test --workspace
```

Expected: each is clean. This chunk changes no `Cargo.toml`, so `cargo deny
check` confirms nothing moved. `check-doc-paths.sh` skips `docs/plans/`, but
it does read the spec, and the spec cites
`adapters/solid/src/storage_description.rs`, which now exists.

- [ ] **Step 3: Commit**

Per the spec's Chunks section, chunks 2 and 3 are staged separately and
committed together. Check what's staged:

```bash
git add domain/src/vocab.rs adapters/solid/src/ldp.rs \
  adapters/solid/src/storage_description.rs adapters/solid/src/lib.rs \
  server/src/pod.rs server/src/lib.rs server/tests/pod_http.rs
git status   # this chunk's seven files, plus chunk 2's if it staged without committing; nothing else
```

If chunk 2 is staged, put its paragraph (from chunk 2's plan) first in the
message below and use the subject line chunk 2's plan gives for the combined
commit. If chunk 2 is already committed, commit this chunk alone:

```bash
git commit -F - <<'MSG'
feat(solid): discovery links, the storage description, an undeletable root

GET, HEAD and OPTIONS on the pod send Link rel="type" with the
resource's LDP classes (Container and BasicContainer together for a
container, pim:Storage as well on the storage root), rel="acl", and the
solid:storageDescription relation on every resource. The storage root
also links solid:owner to the member's WebID. A target that doesn't
exist claims no type. The ACL link comes from ldp::acl_iri, which makes
an ACL its own ACL, where the old string concatenation advertised
x.acl.acl.

/.well-known/solid on each pod subdomain serves a generated storage
description (pim:Storage and solid:owner), content-negotiated,
world-readable and read-only. Writes get 405 with Allow: GET, HEAD,
OPTIONS. The apex and unknown pods get 404 for every method. It is
never stored and no ACL governs it.

/~/ now routes PUT, PATCH and DELETE, so WAC runs before the storage
root's protections: an anonymous DELETE /~/ is 401, not axum's 405.
DELETE of the storage root, and now of the root's ACL, which a caller
with Control could delete until now and lock the member out of their
own pod, is 405 with the caller's Allow. The bare /~ path's 405 also
carries an Allow.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
MSG
```

Trunk-based: this goes straight to `main`, with no branch or PR.

- [ ] **Step 4: Verify from a clean checkout**

```bash
rm -rf /tmp/verify && git worktree add --detach /tmp/verify HEAD
cd /tmp/verify && cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && ./tools/check-doc-paths.sh && cargo deny check && cargo test --workspace
cd - && git worktree remove /tmp/verify --force
```

Run nothing else while it runs. The commit isn't done until this passes.

### Notes for the reviewer

- **The storage description needs no WAC exemption.** Its handler never opens
  the pod. Both IRIs it states come from the username and the base domain,
  and the only lookup is the user row that makes an unknown or suspended pod
  404. No stored resource exists for an ACL to govern, so there is nothing to
  exempt, and `ldp`'s rule that every pod read checks WAC still has no
  exceptions. If a later stage stores anything the description reports, such
  as quota, that changes, and it would need a real decision.
- **The root handlers share code by delegating, not by a new inner
  function.** `put_root`, `patch_root` and `delete_root` call the wildcard
  handlers with `Path(String::new())`, as `get_root` and `post_root` already
  do. The spec's "same inner function" is the wildcard handler itself. No
  logic is duplicated: each root handler is one line, and `format!("/~/{path}")`
  gives `/~/` for the empty path. The price is that every root handler
  repeats the wildcard's extractor list, and chunk 1's H15 extractors have to
  appear in both places.
- **`/.well-known/solid` is routed with `any`, not `get`.** With `get`, axum's
  own 405 would answer `PUT` on the **apex**, which would say the resource
  exists there. With `any`, the handler resolves the host first, so the apex
  is 404 for every method, and a pod's 405 carries an `Allow` we chose (H16).
  Axum strips the body of a `HEAD` at the top-level route whatever endpoint
  served it (`axum-0.8.9/src/routing/route.rs:169`), so `HEAD` works through
  `any`.
- **The bare `/~` answers `Allow:` with an empty value.** RFC 9110 §10.2.1
  allows that, and it is the truthful answer, because every method on `/~` is
  405. Listing `/~/`'s methods would be the lie H4 exists to stop. A redirect
  to `/~/` would be friendlier, and 5c owns `/foo` vs `/foo/`.
- **`ldp_error`'s `Undeletable` arm is now a 500 with a log line.** Only
  `delete` produces the variant, and it builds the 405 itself. It needs the
  caller's `Allow`, which `ldp_error` can't compute. A 405 without `Allow`
  would re-open H16, so a future producer shows up as a logged 500 rather
  than a quiet protocol break.
- **The undeletable 405 carries no `Link`.** H6 narrows the `Link` set to
  successful reads and creates.
- **`acl_iri` has one branch, not three.** The spec names three cases.
  The container and document cases produce the same string, and writing them
  as separate branches fails `clippy::if_same_then_else`. The tests assert all
  three, and the doc comment explains why the container case holds.
- **The root-ACL guard compares against `acl_iri(storage_root)`,** not
  `governed(resource) == storage_root`. The latter would also make
  `/~/.acl.acl` undeletable, which is a fiction, and fictions shouldn't get
  protections.
- **`PodRequest` gains `webid`,** computed in `resolve` with `webid::webid`,
  so the header builder doesn't rebuild the WebID with `format!`.
- **The storage description has no `Link` headers of its own.** It is not an
  LDP resource in the storage, and H6 is about those. Nothing in §4.1 asks
  for them.
- **Test counts** (`ok. 6 passed` for `ldp::tests` and `pod::tests`) assume
  chunks 1 and 2 added no tests to those modules. If they did, expect their
  count plus this chunk's.
- **No ldp-level test for the root-ACL guard.** It is tested over HTTP, where
  it became reachable, and `acl_control` covers the "other ACLs are still
  deletable" edge. An `adapters/solid/tests/acl_control.rs` case calling
  `ldp::delete` on `/~/.acl` would be cheap to add if a reviewer wants the
  guard pinned below the HTTP layer too.


---

## Chunk 4: Caching and CORS

Spec `docs/specs/2026-09-23-solid-http-surface.md`, decisions **H9**, **H10**
and **H14**. One commit to `main`, on top of chunks 1–3. Trunk-based: no
branch, no PR.

This is the chunk whose correctness is judged by a cache rather than by a
client, which is why it is on its own. Everything it touches is a header, and
every header it touches is one a private cache, a shared cache or a browser's
CORS check reads without anyone looking. A mistake here is silent: the wrong
bytes served from a cache, a script that can't read a response it was given.

**What changes:**

| File | Change |
|---|---|
| `adapters/solid/src/conditional.rs` | the `ETag` gains a syntax token: `etag(version, syntax)`, `token(WriteFormat)`, `BINARY`, the `TOKENS` set. `EntityTag` learns to split a tag it issued. `not_modified` compares the whole tag; `check_write` compares the version half (H10, and its RFC 9110 §13.1.1 deviation) |
| `adapters/solid/src/ldp.rs` | `LdpOutcome` gains `syntax`, the token of the representation in `body` (H10) |
| `server/src/pod.rs` | `wac_allow` gains `public=` (H9); `get` tags with the syntax, appends `Vary: Accept` on a negotiated read, and answers a 304 carrying every header its 200 would (H10) |
| `server/src/lib.rs` | CORS echoes the request `Origin` and appends `Vary: Origin`; a preflight echoes `Access-Control-Request-Headers`; the expose list gains `accept-put`, `www-authenticate` and `vary`, and drops `updates-via` (H14) |
| `server/tests/pod_http.rs` | the caching and CORS tests; four existing expectations change |

**Tests whose expectations change** (rewrite, don't delete). Line numbers are
at `e7fe4f6`; chunks 1–3 move them, so find them by name:

- `adapters/solid/src/conditional.rs`'s own unit tests that spell tags by hand
  — `an_etag_is_the_version_in_quotes` (:487), `if_match_compares_strongly`
  (:416), `if_none_match_tags_refuse_the_current_version` (:448),
  `a_read_is_not_modified_when_if_none_match_matches` (:476).
- `server/tests/pod_http.rs::a_webid_is_readable_cross_origin` (:771) — it
  sends an `Origin` and asserts `Access-Control-Allow-Origin: *`, which H14
  turns into the echo. **The spec's "what this changes" table does not name
  this one; it breaks anyway.**
- `server/tests/pod_http.rs::the_headers_ldp_depends_on_are_exposed` (:847) —
  the expose list.
- `server/tests/pod_http.rs::wac_allow_on_an_acl_names_nothing_for_bob`
  (:1030) — the exact `WAC-Allow` strings, both halves of the test. Its
  *status* assertions belong to chunk 1; leave them as chunk 1 left them.

`get_and_head_carry_an_etag_and_last_modified` does **not** change: it asserts
only that the tag is quoted and non-empty (spec H10). Nothing else in the
workspace re-uses a tag across syntaxes — `grep -rn 'conditional::etag'` finds
one call site, `server/src/pod.rs:322`.

Seven tasks, **one commit** (Task 7 commits). Tasks 1 and 2 leave the tree
red — Task 1 on purpose, Task 2 because `etag()`'s signature changes under
`pod.rs` — so don't run the workspace gates or stage before Task 3.

### Reconciling with chunks 1–3

This chunk was written without chunks 1–3 in view; they were being written in
parallel. Before starting Task 3, open `server/src/pod.rs`,
`adapters/solid/src/ldp.rs` and `server/src/lib.rs` as chunks 1–3 left them
and confirm the shapes below. **Adapt names, not behaviour.**

1. **`ldp::describe`** (chunk 2) returns a per-resource, body-free description
   carrying at least: the target's kind, whether it exists, its version and
   modified time, the caller's `granted` modes and the anonymous probe's
   `public` modes. Note its type name and its field names; this chunk reads
   `granted` and `public` out of it and nothing else.
2. **`pod.rs::headers_for`** (chunk 2) is the one builder over that
   description, shared by `GET`, `HEAD`, `OPTIONS` and the create responses.
   Note its signature and what it returns — a `HeaderMap`, a `Vec<(name,
   value)>`, or something it applies to a `Response`. Task 5 makes the 304 use
   it too, and Task 4 changes `wac_allow`, which it calls.
3. **`ldp::read`/`read_in`** still return an `LdpOutcome` (or whatever chunk 2
   renamed it) holding `body`, `media_type`, `version` and `modified`. If
   chunk 2 folded the description into it, `granted` and `public` come from
   there and Task 4's call site changes accordingly.
4. **`pod.rs::get`** still calls `ldp::read`, still builds the `ETag` from
   `outcome.version` through `conditional::etag`, and still decides the 304
   with `preconditions(&headers).not_modified(..)` **after** `read` returns.
   Chunk 2 may have moved the 200's headers into `headers_for`; keep that and
   change only the lines these tasks name.
5. **`pod.rs::wac_allow`** still takes a `&[brolly_authz::AccessMode]` and
   returns the field value as a `String`. If chunk 2 moved it inside
   `headers_for`, Task 4 edits it where it now lives.
6. **`server/src/lib.rs::cors`** is still the hand-rolled middleware, still
   distinguishes a preflight by `Access-Control-Request-Method`, and still
   `insert`s its five headers in one loop. Its doc comment still explains why
   it is not `tower_http::cors`. Task 6 keeps both.
7. **`ldp::accepted_write_types()`** exists and chunk 2 sends `Accept-Put`
   from it. Task 6's expose list names `accept-put`; if chunk 2 spelled the
   header differently, use its spelling.

If any of these is materially different — `describe` doesn't carry `public`,
or there is no `headers_for` — **stop and reconcile with the chunk that owns
it** rather than rebuilding it here. H9's probe and the shared builder are
chunk 2's deliverables; this chunk consumes them.

### Task 1: Characterization — today, a Turtle tag revalidates JSON-LD

**Files:**
- Modify: `server/tests/pod_http.rs` — append after the last test

This is spec problem 9 and it is the risky part of the chunk. Write the test
that *proves the bug* before changing anything, so the fix has something to
flip and so a reviewer can see exactly what moved.

- [ ] **Step 1: Write the test that passes today**

Append to the end of `server/tests/pod_http.rs`:

```rust
// --- caching (stage 5b, H10) ---------------------------------------------------

/// The bug this chunk fixes, asserted as it stands so the fix has something to
/// flip (spec problem 9).
///
/// One version serves every syntax, and the 304 is decided from the version
/// alone, so a client that cached Turtle and revalidates asking for JSON-LD is
/// told its Turtle is fresh — and then parses Turtle as JSON-LD, a long way
/// from the cause. Task 3 inverts every assertion below.
#[tokio::test]
async fn a_turtle_tag_revalidates_a_json_ld_read() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (status, _, headers) = h
        .send_if("GET", "/~/note", None, &[("accept", "text/turtle")])
        .await;
    assert_eq!(status, StatusCode::OK);
    let turtle_tag = headers[header::ETAG].to_str().unwrap().to_string();

    let (status, body, headers) = h
        .send_if(
            "GET",
            "/~/note",
            None,
            &[
                ("accept", "application/ld+json"),
                ("if-none-match", turtle_tag.as_str()),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::NOT_MODIFIED, "today: the tag is reused");
    assert!(body.is_empty());
    assert_eq!(
        headers[header::ETAG].to_str().unwrap(),
        turtle_tag,
        "today: one tag for every syntax"
    );

    // And the unconditional JSON-LD read carries that same tag, which is what
    // makes the reuse look legitimate to a cache.
    let (status, _, headers) = h
        .send_if("GET", "/~/note", None, &[("accept", "application/ld+json")])
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/ld+json");
    assert_eq!(headers[header::ETAG].to_str().unwrap(), turtle_tag);
}
```

`send_if` and `Harness::etag` are 5a's helpers, already in this file after the
`impl Harness` block. `send_if` authenticates as the owner.

- [ ] **Step 2: Run it and watch it pass**

Run: `cargo test -p brolly-server --test pod_http a_turtle_tag_revalidates_a_json_ld_read`

Expected: `test result: ok. 1 passed`. If it *fails*, the bug is not what the
spec says it is — stop, and re-read `pod.rs::get`'s 304 decision before going
on. A failure here means Task 3 has nothing to flip and the rest of this
chunk's premise is wrong.

Don't stage. The tree is green but this test is scaffolding.

### Task 2: `conditional` learns the syntax token

**Files:**
- Modify: `adapters/solid/src/conditional.rs` — the module doc (`:1-19`),
  `EntityTag` (`:21-41`), `check_write`'s doc table (`:197-236`),
  `not_modified` (`:238-248`), `etag` (`:251-254`), and four unit tests

The rule, from H10: **reads compare the whole tag, writes compare the version
part only.** The read rule is what fixes problem 9. The write rule is a
deliberate deviation from RFC 9110 §13.1.1, and the doc comments have to carry
that reasoning or the next reader will "fix" it back.

- [ ] **Step 1: Rewrite the four hand-spelled tests, and add three**

In `adapters/solid/src/conditional.rs`, add to the test module's imports:

```rust
    use brolly_domain::syntax::WriteFormat;
```

Replace `if_match_compares_strongly` with:

```rust
    #[test]
    fn if_match_compares_strongly_and_only_the_version() {
        let p = with(Some(r#""old.ttl", "v.ttl""#), None);
        for method in ALL {
            assert_eq!(p.check_write(method, Some("v")), Ok(()));
            assert_eq!(p.check_write(method, Some("new")), Err(PreconditionFailed));
            assert_eq!(p.check_write(method, None), Err(PreconditionFailed));
        }
        // A weak tag never matches, even with the right version.
        assert_eq!(
            with(Some(r#"W/"v.ttl""#), None).check_write(Method::Put, Some("v")),
            Err(PreconditionFailed)
        );
        // A field with nothing usable in it holds for nothing: fail closed.
        assert_eq!(
            with(Some("v.ttl"), None).check_write(Method::Put, Some("v")),
            Err(PreconditionFailed)
        );
    }
```

Replace `if_none_match_tags_refuse_the_current_version` with the same tags
spelled with a token:

```rust
    #[test]
    fn if_none_match_tags_refuse_the_current_version() {
        let p = with(None, Some(r#""old.ttl", "v.ttl""#));
        for method in [Method::Put, Method::Patch, Method::Delete] {
            assert_eq!(p.check_write(method, Some("v")), Err(PreconditionFailed));
            assert_eq!(p.check_write(method, Some("new")), Ok(()));
            assert_eq!(p.check_write(method, None), Ok(()));
        }
        // Not in the spec's table for POST.
        assert_eq!(p.check_write(Method::Post, Some("v")), Ok(()));
        // RFC 9110 §13.1.2: If-None-Match uses the weak comparison.
        assert_eq!(
            with(None, Some(r#"W/"v.ttl""#)).check_write(Method::Put, Some("v")),
            Err(PreconditionFailed)
        );
    }
```

Replace `a_read_is_not_modified_when_if_none_match_matches` with:

```rust
    /// The read rule, and spec problem 9 in one line: a cached Turtle tag must
    /// not confirm a JSON-LD read. `*` still matches any representation.
    #[test]
    fn a_read_is_not_modified_only_for_the_representation_it_cached() {
        assert!(with(None, Some(r#""v.ttl""#)).not_modified("v", "ttl"));
        assert!(with(None, Some(r#""old.ttl", W/"v.ttl""#)).not_modified("v", "ttl"));
        assert!(with(None, Some("*")).not_modified("v", "ttl"));
        assert!(!with(None, Some(r#""old.ttl""#)).not_modified("v", "ttl"));
        // Problem 9. Comparing the version alone here would re-introduce it.
        assert!(!with(None, Some(r#""v.ttl""#)).not_modified("v", "jsonld"));
        assert!(!with(None, Some(r#""v.jsonld""#)).not_modified("v", "ttl"));
        // A binary's bytes are the same for every Accept, so one token serves.
        assert!(with(None, Some(r#""v.bin""#)).not_modified("v", BINARY));
        // If-Match isn't evaluated on a read.
        assert!(!with(Some(r#""old.ttl""#), None).not_modified("v", "ttl"));
    }
```

Replace `an_etag_is_the_version_in_quotes` with:

```rust
    #[test]
    fn an_etag_is_the_version_and_the_syntax_in_quotes() {
        let v = "01J8Z3T5V7W9X1Y3Z5A7B9C1D3";
        assert_eq!(
            etag(v, token(WriteFormat::Turtle)),
            r#""01J8Z3T5V7W9X1Y3Z5A7B9C1D3.ttl""#
        );
        assert_eq!(
            etag(v, token(WriteFormat::JsonLd)),
            r#""01J8Z3T5V7W9X1Y3Z5A7B9C1D3.jsonld""#
        );
        assert_eq!(etag(v, BINARY), r#""01J8Z3T5V7W9X1Y3Z5A7B9C1D3.bin""#);
    }
```

Then add three tests after it:

```rust
    /// H10's deviation from RFC 9110 §13.1.1, which wants the strong
    /// comparison of §8.8.3.2 — octet-for-octet on the opaque tag. A client
    /// that took its tag from a Turtle `HEAD` must be able to guard a JSON-LD
    /// `PUT` with it: a `PUT` replaces the resource, not a representation, and
    /// the version *is* the state `If-Match` exists to guard. Comparing the
    /// whole tag here would fail a correct client's conditional write for a
    /// reason it cannot see.
    #[test]
    fn a_write_condition_ignores_the_syntax_half() {
        for syntax in ["ttl", "nt", "nq", "trig", "jsonld", "rdfxml", "bin"] {
            let field = format!("\"v.{syntax}\"");
            assert_eq!(
                with(Some(field.as_str()), None).check_write(Method::Put, Some("v")),
                Ok(()),
                "If-Match {syntax}"
            );
            assert_eq!(
                with(None, Some(field.as_str())).check_write(Method::Put, Some("v")),
                Err(PreconditionFailed),
                "If-None-Match {syntax}"
            );
        }
    }

    /// A 5a-era cached tag has no `.` at all; a forged one may carry a suffix
    /// we never issue. Neither names a version, so `If-Match` fails closed
    /// with a 412 the client answers by re-`GET`ting, and `If-None-Match` lets
    /// the write through. The version is a ULID, so it never contains a `.`
    /// and the split is unambiguous.
    #[test]
    fn a_tag_we_did_not_issue_names_no_version() {
        for opaque in ["v", "v.png", "v.TTL", "v.ttl.ttl", ".ttl", "v."] {
            let field = format!("\"{opaque}\"");
            assert_eq!(
                with(Some(field.as_str()), None).check_write(Method::Put, Some("v")),
                Err(PreconditionFailed),
                "If-Match {opaque}"
            );
            assert_eq!(
                with(None, Some(field.as_str())).check_write(Method::Put, Some("v")),
                Ok(()),
                "If-None-Match {opaque}"
            );
            assert!(
                !with(None, Some(field.as_str())).not_modified("v", "ttl"),
                "not_modified {opaque}"
            );
        }
    }

    /// Every syntax we can serve needs a token, no token may contain the `.`
    /// the split depends on, and no two may collide — a collision would let a
    /// tag confirm the wrong representation, which is the bug this is for.
    #[test]
    fn every_syntax_has_a_distinct_token_we_recognise() {
        const EVERY: [WriteFormat; 6] = [
            WriteFormat::Turtle,
            WriteFormat::NTriples,
            WriteFormat::NQuads,
            WriteFormat::TriG,
            WriteFormat::JsonLd,
            WriteFormat::RdfXml,
        ];
        for format in EVERY {
            let issued = token(format);
            assert!(TOKENS.contains(&issued), "{format:?}: {issued} is not issued");
            assert!(!issued.contains('.'), "{format:?}: {issued} has a dot");
        }
        let mut seen = TOKENS.to_vec();
        seen.sort_unstable();
        let unique = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), unique, "two representations share a token");
    }
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-solid --lib conditional`

Expected: compile failure. `error[E0425]`: cannot find value `TOKENS`,
`BINARY` in this scope; cannot find function `token` in this scope.
`error[E0061]`: `etag` takes 1 argument but 2 were supplied; `not_modified`
takes 2 arguments but 3 were supplied.

- [ ] **Step 3: The token vocabulary**

In `adapters/solid/src/conditional.rs`, add at the top:

```rust
use brolly_domain::syntax::WriteFormat;
```

and, just above `pub fn etag`, the vocabulary:

```rust
/// The syntax token in a binary's `ETag`.
///
/// A binary's bytes are the same whatever the client asked for, so there is
/// nothing to negotiate and one token serves every `Accept`.
pub const BINARY: &str = "bin";

/// The token for a serialization: the second half of its `ETag`.
///
/// Short, stable, and free of the `.` the split depends on. Deliberately not
/// media types: an `ETag` is opaque to everyone but us, and spelling
/// `text/turtle` inside one would invite a client to parse it and then to
/// depend on it.
pub fn token(format: WriteFormat) -> &'static str {
    match format {
        WriteFormat::Turtle => "ttl",
        WriteFormat::NTriples => "nt",
        WriteFormat::NQuads => "nq",
        WriteFormat::TriG => "trig",
        WriteFormat::JsonLd => "jsonld",
        WriteFormat::RdfXml => "rdfxml",
    }
}

/// Every token this server issues.
///
/// A suffix outside this set names no representation we could have served, so
/// a tag carrying one matches nothing: not the whole tag on a read, and not
/// the version on a write. That is what a tag cached before this stage does —
/// it has no `.` at all — and it is the right answer for a forged one.
///
/// Kept beside [`token`] so adding a syntax that misses this list fails
/// `every_syntax_has_a_distinct_token_we_recognise` rather than failing a
/// client's revalidation.
const TOKENS: [&str; 7] = ["ttl", "nt", "nq", "trig", "jsonld", "rdfxml", BINARY];
```

- [ ] **Step 4: `EntityTag` learns to split a tag it issued**

Replace the `impl EntityTag` block (`:30-41`) with:

```rust
impl EntityTag {
    /// The two halves of a tag *this server* issued: the version and the
    /// syntax token.
    ///
    /// `None` for anything else — a tag with no `.`, or with a suffix outside
    /// [`TOKENS`]. The version is a ULID, so it never contains a `.` and
    /// `split_once` is unambiguous.
    fn split(&self) -> Option<(&str, &str)> {
        let (version, token) = self.opaque.split_once('.')?;
        TOKENS.contains(&token).then_some((version, token))
    }

    /// Strong comparison against a *version*, for a write.
    ///
    /// Ours are always strong, so a `W/` tag never matches.
    fn strong_eq_version(&self, version: &str) -> bool {
        !self.weak && self.split().map(|(v, _)| v) == Some(version)
    }

    /// Weak comparison against a version, for a write. The prefix is ignored.
    fn weak_eq_version(&self, version: &str) -> bool {
        self.split().map(|(v, _)| v) == Some(version)
    }

    /// Weak comparison against a whole tag, for a read: both halves must
    /// match, so a tag cached as Turtle cannot confirm a JSON-LD read.
    fn weak_eq_representation(&self, version: &str, syntax: &str) -> bool {
        self.split() == Some((version, syntax))
    }
}
```

In `check_write`, change the two comparisons to the version forms:

```rust
                (Condition::Tags(tags), Some(version)) => {
                    tags.iter().any(|tag| tag.strong_eq_version(version))
                }
```

and

```rust
                (Condition::Tags(tags), Some(version)) => {
                    method != Method::Post && tags.iter().any(|tag| tag.weak_eq_version(version))
                }
```

Extend `check_write`'s doc comment, after its table:

```rust
    /// A write's tags are compared on their **version half only**. A `PUT`
    /// replaces the resource, not a representation, so a client that took its
    /// tag from a `HEAD` negotiated as Turtle must be able to guard a JSON-LD
    /// `PUT` with it.
    ///
    /// This is a deliberate deviation from RFC 9110 §13.1.1, which requires
    /// the strong comparison of §8.8.3.2 — octet-for-octet on the opaque tag.
    /// We take it because the alternative makes a correct client's conditional
    /// write fail for a reason it cannot see, and because the version *is* the
    /// resource state `If-Match` exists to guard. One version per resource,
    /// one syntax token per representation (5a's R4, preserved).
    ///
    /// A tag we didn't issue matches no version, so an `If-Match` carrying one
    /// fails closed with a 412 the client answers by re-`GET`ting.
    /// `If-Match: *` and `If-None-Match: *` are unaffected: `Condition::Any`
    /// carries no tag and asks only whether a current representation exists.
```

Replace `not_modified` with:

```rust
    /// Should a GET or HEAD answer 304?
    ///
    /// `version` and `syntax` describe the representation that *would* be
    /// sent, and both must match: a read compares the **whole tag**. A client
    /// holding `"01J8….ttl"` that revalidates asking for JSON-LD gets a 200.
    /// Comparing only the version here would re-introduce the bug the syntax
    /// token exists for — a cache reusing Turtle as JSON-LD, which fails
    /// silently and produces a parse error a long way from its cause.
    ///
    /// Only `If-None-Match` counts on a read. `If-Match` on a GET is ignored,
    /// as in the spec's table.
    pub fn not_modified(&self, version: &str, syntax: &str) -> bool {
        match &self.if_none_match {
            None => false,
            Some(Condition::Any) => true,
            Some(Condition::Tags(tags)) => tags
                .iter()
                .any(|tag| tag.weak_eq_representation(version, syntax)),
        }
    }
```

Replace `etag` with:

```rust
/// The `ETag` for a representation: `"{version}.{syntax}"`, strong.
///
/// `syntax` is [`token`] of the serialization, or [`BINARY`]. The token is
/// defence in depth behind `Vary: Accept` (H10): a conforming private cache
/// already keys its stored responses on the varied header (RFC 9111 §4.1) and
/// won't offer its Turtle entry for a JSON-LD request, but plenty don't, and
/// a tag stored before this stage doesn't know it should.
pub fn etag(version: &str, syntax: &str) -> String {
    format!("\"{version}.{syntax}\"")
}
```

Finally, amend the module doc's third paragraph (`:5-8`), which still says the
tag is the version alone:

```rust
//! Transport-free like the rest of this crate. It takes header *values* and a
//! resource's current version, and says whether a request may go ahead. The
//! version is the `brolly:version` the pod's metadata keeps, a fresh ULID on
//! every change, and the `ETag` is that version and the representation's
//! syntax token in quotes — `"01J8….ttl"` (5a's R4, 5b's H10). There is one
//! version per resource whatever the representation, so every tag the server
//! issues is strong.
//!
//! **Reads compare the whole tag; writes compare the version.** See
//! [`Preconditions::not_modified`] and [`Preconditions::check_write`], which
//! carry the reasoning and the RFC 9110 §13.1.1 deviation.
```

- [ ] **Step 5: Run them and watch them pass**

Run: `cargo test -p brolly-solid --lib conditional`

Expected: `test result: ok. 17 passed` (5a's 14, minus none, plus three).

`cargo build -p brolly-server` still fails here: `etag` and `not_modified`
take an argument `pod.rs` doesn't pass yet. That is Task 3. Don't run the
workspace gates and don't stage.

### Task 3: The representation's syntax reaches the header, and the bug flips

**Files:**
- Modify: `server/tests/pod_http.rs` — the characterization test from Task 1
- Modify: `adapters/solid/src/ldp.rs` — `LdpOutcome` (`:132-148` at `e7fe4f6`)
  and its two construction sites in `read_in` (`:272-283`, `:298-305`)
- Modify: `server/src/pod.rs` — `get` (`:319-326` at `e7fe4f6`)

Do the reconcile pass from **Reconciling with chunks 1–3** before this step.

- [ ] **Step 1: Flip the characterization test**

Replace the test Task 1 added with the behaviour H10 wants. Same shape, every
assertion inverted, and a doc comment that names what it guards rather than
what it records:

```rust
/// Spec problem 9: one ETag served every syntax, and the 304 was decided from
/// the version alone, so a client that cached Turtle and revalidated asking
/// for JSON-LD was told its Turtle was fresh — and then parsed Turtle as
/// JSON-LD, a parse error a long way from its cause.
#[tokio::test]
async fn a_turtle_tag_does_not_revalidate_a_json_ld_read() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (status, _, headers) = h
        .send_if("GET", "/~/note", None, &[("accept", "text/turtle")])
        .await;
    assert_eq!(status, StatusCode::OK);
    let turtle_tag = headers[header::ETAG].to_str().unwrap().to_string();
    assert!(turtle_tag.ends_with(".ttl\""), "got {turtle_tag}");

    // The Turtle tag confirms the Turtle representation.
    let (status, _, _) = h
        .send_if(
            "GET",
            "/~/note",
            None,
            &[
                ("accept", "text/turtle"),
                ("if-none-match", turtle_tag.as_str()),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::NOT_MODIFIED, "its own syntax");

    // It confirms nothing else.
    let (status, _, headers) = h
        .send_if(
            "GET",
            "/~/note",
            None,
            &[
                ("accept", "application/ld+json"),
                ("if-none-match", turtle_tag.as_str()),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "a Turtle tag confirmed JSON-LD");
    assert_eq!(headers[header::CONTENT_TYPE], "application/ld+json");
    let json_tag = headers[header::ETAG].to_str().unwrap().to_string();
    assert!(json_tag.ends_with(".jsonld\""), "got {json_tag}");
    assert_ne!(json_tag, turtle_tag);

    // The version half is the same resource state either way, which is what
    // makes a write guarded by either tag work (H10).
    assert_eq!(
        turtle_tag.trim_end_matches(".ttl\""),
        json_tag.trim_end_matches(".jsonld\"")
    );
}

/// A binary's bytes are the same for every `Accept`, so its tag says so and
/// one token serves. Nothing negotiates, so nothing can be confirmed wrongly.
#[tokio::test]
async fn a_binary_is_tagged_as_a_binary() {
    let h = harness().await;
    h.send("PUT", "/~/paper.pdf", Some(("application/pdf", PDF)), true)
        .await;

    let (status, _, headers) = h
        .send_if("GET", "/~/paper.pdf", None, &[("accept", "*/*")])
        .await;
    assert_eq!(status, StatusCode::OK);
    let tag = headers[header::ETAG].to_str().unwrap().to_string();
    assert!(tag.ends_with(".bin\""), "got {tag}");

    // Asking for JSON-LD doesn't change the bytes, so the tag still holds.
    let (status, _, _) = h
        .send_if(
            "GET",
            "/~/paper.pdf",
            None,
            &[
                ("accept", "application/ld+json"),
                ("if-none-match", tag.as_str()),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
}

/// H10's deviation from RFC 9110 §13.1.1, over the wire. A client that read a
/// resource as Turtle and writes it back as JSON-LD guards the write with the
/// tag it has, and must not be refused for a syntax it never claimed.
#[tokio::test]
async fn a_tag_from_one_syntax_guards_a_write_in_another() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (_, _, headers) = h
        .send_if("GET", "/~/note", None, &[("accept", "text/turtle")])
        .await;
    let turtle_tag = headers[header::ETAG].to_str().unwrap().to_string();

    let json = r#"[{"@id":"https://alice.brolly.test/~/note",
        "https://example.org/title":[{"@value":"Edited"}]}]"#;
    let (status, body, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("application/ld+json", json)),
            &[("if-match", turtle_tag.as_str())],
        )
        .await;
    assert!(status.is_success(), "{status}: {body}");

    // And a tag for a version that has moved on is still refused.
    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("text/turtle", EDITED)),
            &[("if-match", turtle_tag.as_str())],
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "a stale version");
}

/// A tag cached before this stage has no syntax token, so it names no version
/// and no representation. `If-Match` fails closed and the client re-`GET`s;
/// `If-None-Match` is a full response rather than a wrong 304.
#[tokio::test]
async fn a_tag_from_before_this_stage_matches_nothing() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let current = h.etag("/~/note").await;
    let bare = format!("\"{}\"", current.trim_matches('"').trim_end_matches(".ttl"));
    assert_ne!(bare, current, "the tag has no token to strip");

    let (status, _, _) = h
        .send_if("GET", "/~/note", None, &[("if-none-match", bare.as_str())])
        .await;
    assert_eq!(status, StatusCode::OK, "a 5a-era tag confirmed a read");

    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("text/turtle", EDITED)),
            &[("if-match", bare.as_str())],
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "fail closed");
    assert_eq!(h.etag("/~/note").await, current, "the refused PUT landed");
}
```

`EDITED` and `PDF` are constants already in this file.

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-server --test pod_http a_turtle_tag a_binary_is_tagged a_tag_from`

Expected: a compile failure first — `error[E0061]`: `etag` takes 2 arguments
but 1 was supplied, in `server/src/pod.rs`. That is Task 2's half of the
change landing on an unchanged `pod.rs`, and it is what Step 3 fixes.

- [ ] **Step 3: `LdpOutcome` carries the syntax**

In `adapters/solid/src/ldp.rs`, add a field to `LdpOutcome`, after
`media_type`:

```rust
    /// The syntax token of the representation in `body`: the second half of
    /// the `ETag` (H10). `conditional::BINARY` for a binary, whose bytes are
    /// the same for every `Accept`; otherwise the negotiated format's token.
    ///
    /// It comes from the same negotiation that produced `body`, so an `ETag`
    /// always names the bytes it goes out with.
    pub syntax: &'static str,
```

In `read_in`, the binary arm's `LdpOutcome { .. }` gains:

```rust
            syntax: conditional::BINARY,
```

and the RDF arm's, below `let format = syntax::negotiate(accept);`:

```rust
        syntax: conditional::token(format),
```

Note the shadowing: `ldp.rs` imports `brolly_domain::syntax` as a module *and*
now has a field called `syntax`. The field initializer `syntax:
conditional::token(format)` is unambiguous, and `crate::conditional` is
already imported at `:41`. If the shadowing reads badly where chunk 2 left the
function, qualify the module as `brolly_domain::syntax::negotiate(accept)` at
that one call rather than renaming the field — the field name is what `pod.rs`
reads.

- [ ] **Step 4: `pod.rs` tags with it**

In `server/src/pod.rs::get`, replace the two lines that build the tag and
decide the 304:

```rust
    // After `read` succeeded, so after the Read check, and against the version
    // and syntax from the same snapshot and negotiation as the body.
    let etag = conditional::etag(&outcome.version, outcome.syntax);
    if preconditions(&headers).not_modified(&outcome.version, outcome.syntax) {
```

Leave the 304's body alone; Task 5 rewrites it.

Extend `get`'s doc comment, replacing the `ETag` sentence:

```rust
/// Sends `ETag` — the resource's version and the representation's syntax,
/// `"{version}.{syntax}"` — and `Last-Modified`, and answers 304 to an
/// `If-None-Match` naming the representation it would have sent. A tag for
/// another syntax is a full response (H10). Only here: a write's response
/// carries no `ETag`, because the server transforms what it stores
/// (RFC 9110 §9.3.4).
```

- [ ] **Step 5: Run them and watch them pass**

Run: `cargo test -p brolly-server --test pod_http a_turtle_tag a_binary_is_tagged a_tag_from`

Expected: `test result: ok. 4 passed`.

Then the 5a conditional suite, which must be untouched by this:

Run: `cargo test -p brolly-server --test pod_http if_ etag precondition`

Expected: all pass. If `if_match_needs_the_current_strong_tag` or
`if_none_match_with_the_current_tag` fails, the version/whole-tag split is
inverted somewhere: those tests take a tag from a `GET` and hand it straight
to a write, which only works because writes compare the version half.

### Task 4: `WAC-Allow` gains `public=`

**Files:**
- Modify: `server/tests/pod_http.rs` — a new test, and
  `wac_allow_on_an_acl_names_nothing_for_bob`'s two exact strings
- Modify: `server/src/pod.rs` — `wac_allow` (`:254-266` at `e7fe4f6`) and its
  call site(s)

Spec problem 7, decision H9. The probe itself is chunk 2's: `describe` already
carries the anonymous subject's modes, evaluated **inside** the snapshot so
both components describe the same ACL. This task is the field value.

- [ ] **Step 1: Write the failing tests**

Add a helper next to `share_with_bob` in `server/tests/pod_http.rs`:

```rust
/// Grant the world Read on a resource, the way a member's share UI would.
///
/// A direct ACL replaces the inherited one rather than adding to it, so
/// Alice's own grants have to be restated here or she loses them — which is
/// WAC working, not a bug in the helper.
fn make_public(h: &Harness, path: &str) {
    let resource = format!("{ROOT}{path}");
    let g = format!("{resource}.acl");
    let owner = format!("{g}#owner");
    let public = format!("{g}#public");
    let quads = [
        t(&g, &owner, &format!("{ACL}accessTo"), &resource),
        t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Read")),
        t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Write")),
        t(
            &g,
            &owner,
            &format!("{ACL}agent"),
            &format!("{BASE}/profile#me"),
        ),
        t(&g, &public, &format!("{ACL}accessTo"), &resource),
        t(&g, &public, &format!("{ACL}mode"), &format!("{ACL}Read")),
        t(
            &g,
            &public,
            &format!("{ACL}agentClass"),
            "http://xmlns.com/foaf/0.1/Agent",
        ),
    ];
    let pod = h.stores.pod(h.user).unwrap();
    pod.write(|w| w.put(&g, Content::Auxiliary(&quads)).map(|_| ()))
        .unwrap();
}
```

and append the test:

```rust
// --- WAC-Allow (stage 5b, H9) --------------------------------------------------

/// Spec problem 7: a share UI has to show whether what it is looking at is
/// world-readable, and it cannot learn that by asking as itself. `public=` is
/// a second `granted_modes` probe with an anonymous subject, run inside the
/// same snapshot so both components describe the same ACL.
#[tokio::test]
async fn wac_allow_names_what_the_public_holds() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    h.send("PUT", "/~/open", Some(("text/turtle", NOTE)), true)
        .await;
    make_public(&h, "open");

    // The harness's root ACL grants Alice Read and Write, and Write satisfies
    // Append (`AccessMode::satisfying`), so she holds three modes on both.
    let (status, _, headers) = h.send("GET", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers["wac-allow"],
        "user=\"read write append\", public=\"\"",
        "a private resource still reports an empty public group"
    );

    let (status, _, headers) = h.send("GET", "/~/open", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers["wac-allow"],
        "user=\"read write append\", public=\"read\""
    );

    // And HEAD carries it too (WAC §6's MUST).
    let (status, _, headers) = h.send("HEAD", "/~/open", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers["wac-allow"],
        "user=\"read write append\", public=\"read\""
    );
}

/// An anonymous reader of a public resource sees the same `public=` group it
/// is a member of, and a `user=` group that is the same thing said twice.
#[tokio::test]
async fn an_anonymous_reader_of_a_public_resource_sees_both_groups() {
    let h = harness().await;
    h.send("PUT", "/~/open", Some(("text/turtle", NOTE)), true)
        .await;
    make_public(&h, "open");

    let (status, _, headers) = h.send("GET", "/~/open", None, false).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["wac-allow"], "user=\"read\", public=\"read\"");
}
```

WAC §6.1's ABNF allows an empty group, which is why `public=""` is spelled out
rather than omitted: a client that reads the header has to be able to tell
"not public" from "the server didn't say".

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-server --test pod_http wac_allow_names an_anonymous_reader_of_a_public`

Expected: both fail `assert_eq!` with
`left: "user=\"read write append\""`,
`right: "user=\"read write append\", public=\"\""` — the field has no
`public=` component at all.

- [ ] **Step 3: Implement**

In `server/src/pod.rs`, replace `wac_allow` with:

```rust
/// One `WAC-Allow` field value (WAC §6.1).
///
/// `granted` is the caller's effective modes; `public` is a second
/// `granted_modes` probe with an anonymous subject, run by `ldp` **inside the
/// read's snapshot** so both components describe the same ACL — a builder out
/// here would be working after `Pod::read` closed it.
///
/// Both groups are always spelled, empty or not: §6.1's ABNF allows an empty
/// group, and a client has to be able to tell "not public" from "the server
/// didn't say". On an `.acl`, `granted_modes` is all-or-nothing on Control
/// (`ldp.rs`), so `public=` there is empty unless the ACL grants Control to
/// everyone.
fn wac_allow(
    granted: &[brolly_authz::AccessMode],
    public: &[brolly_authz::AccessMode],
) -> String {
    format!(
        "user=\"{}\", public=\"{}\"",
        mode_names(granted),
        mode_names(public)
    )
}

fn mode_names(modes: &[brolly_authz::AccessMode]) -> String {
    use brolly_authz::AccessMode::*;
    modes
        .iter()
        .map(|m| match m {
            Read => "read",
            Write => "write",
            Append => "append",
            Control => "control",
        })
        .collect::<Vec<_>>()
        .join(" ")
}
```

Then pass the probe at the call site. Where chunk 2 left `headers_for`, that
is `wac_allow(&description.granted, &description.public)`; if `get` still
builds its own array, it is `wac_allow(&outcome.granted, &outcome.public)`.
The names come from the reconcile pass; nothing else changes.

- [ ] **Step 4: Run them and watch them pass**

Run: `cargo test -p brolly-server --test pod_http wac_allow_names an_anonymous_reader_of_a_public`

Expected: `test result: ok. 2 passed`.

- [ ] **Step 5: Fix the one existing expectation**

`wac_allow_on_an_acl_names_nothing_for_bob` spells the field twice. Change
only the strings; leave the status assertions as chunk 1 left them.

The refusal half's tolerated values become:

```rust
    assert!(
        matches!(
            allowed.as_deref(),
            None | Some("user=\"\", public=\"\"")
        ),
        "got {allowed:?}"
    );
```

and the owner's 200:

```rust
    assert_eq!(
        headers["wac-allow"],
        "user=\"read write append control\", public=\"\""
    );
```

`/~/shared/.acl` is an ACL resource, so `granted_modes` is all-or-nothing on
Control: Alice holds it and gets all four, the anonymous probe doesn't and
gets none.

Run: `cargo test -p brolly-server --test pod_http wac_allow`

Expected: all pass, including `wac_allow_on_an_acl_names_nothing_for_bob`.

### Task 5: `Vary: Accept`, and a 304 that carries what the 200 did

**Files:**
- Modify: `server/tests/pod_http.rs` — two new tests
- Modify: `server/src/pod.rs` — `get`'s 304 and 200

Two halves of H10. `Vary: Accept` is what makes a *conforming* cache correct
on its own (RFC 9111 §4.1 keys stored responses on the varied header); the
syntax token from Task 3 is defence in depth behind it. The fuller 304 is so
that a client which revalidates doesn't lose the affordances it had.

`Vary: Origin` is Task 6's, in the CORS layer, and the two must compose — the
CORS layer is outermost and must **append**, not insert, or it drops what the
handler set here. Task 6 asserts that; this task only sets `Accept`.

- [ ] **Step 1: Write the failing tests**

Append to `server/tests/pod_http.rs`:

```rust
/// All the `Vary` field lines as one value. A repeated field line means the
/// same as one line joined with commas (RFC 9110 §5.3), and this chunk sets
/// the header from two places: the handler and the CORS layer.
fn vary_of(headers: &axum::http::HeaderMap) -> String {
    headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(", ")
        .to_ascii_lowercase()
}

/// Spec problem 8: `GET` negotiates on `Accept` and never said so, so a shared
/// cache could hand a client asking for JSON-LD the Turtle it stored for
/// someone else. A binary gets no `Vary: Accept`: its bytes are the same for
/// every `Accept`, and claiming otherwise fragments a cache for nothing.
#[tokio::test]
async fn a_negotiated_read_varies_on_accept_and_a_binary_does_not() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    h.send("PUT", "/~/paper.pdf", Some(("application/pdf", PDF)), true)
        .await;

    for path in ["/~/note", "/~/"] {
        for method in ["GET", "HEAD"] {
            let (status, _, headers) = h.send(method, path, None, true).await;
            assert_eq!(status, StatusCode::OK, "{method} {path}");
            assert!(
                vary_of(&headers).contains("accept"),
                "{method} {path}: {}",
                vary_of(&headers)
            );
        }
    }

    let (status, _, headers) = h.send("GET", "/~/paper.pdf", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !vary_of(&headers).contains("accept"),
        "a binary varied on Accept: {}",
        vary_of(&headers)
    );
}

/// RFC 9110 §15.4.5 requires `ETag` and `Vary` on a 304. We send more: a
/// client that revalidates must not lose the affordances it had, so `Allow`,
/// `Accept-*` and `WAC-Allow` — control and resource metadata, not the
/// representation metadata §15.4.5's SHOULD NOT covers — ride along, and so
/// does `Link`. `Last-Modified` is the one deviation, and it is deliberate.
#[tokio::test]
async fn a_304_carries_what_the_200_carried() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (status, _, ok) = h
        .send_if("GET", "/~/note", None, &[("accept", "text/turtle")])
        .await;
    assert_eq!(status, StatusCode::OK);
    let tag = ok[header::ETAG].to_str().unwrap().to_string();

    let (status, body, not_modified) = h
        .send_if(
            "GET",
            "/~/note",
            None,
            &[("accept", "text/turtle"), ("if-none-match", tag.as_str())],
        )
        .await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty(), "a 304 has no body: {body}");

    for name in [
        "etag",
        "last-modified",
        "link",
        "allow",
        "accept-patch",
        "accept-post",
        "accept-put",
        "wac-allow",
    ] {
        let on_200 = ok.get_all(name).iter().collect::<Vec<_>>();
        let on_304 = not_modified.get_all(name).iter().collect::<Vec<_>>();
        assert!(!on_200.is_empty(), "{name} missing from the 200");
        assert_eq!(on_304, on_200, "{name} differs on the 304");
    }
    assert_eq!(vary_of(&not_modified), vary_of(&ok), "Vary differs");

    // §15.4.5's SHOULD NOT: representation metadata stays off.
    for name in [header::CONTENT_TYPE, header::CONTENT_LENGTH] {
        assert!(
            not_modified.get(&name).is_none(),
            "{name} on a 304: representation metadata"
        );
    }
}
```

The `Accept-*` names in the first loop are chunk 2's, and chunk 2 sends each
only when the matching method is in `Allow` (H5). Alice holds Write on
`/~/note`, so all three are present. If chunk 2 spelled a header differently,
use its spelling; if it decided `Accept-Put` is absent for a case this test
hits, drop that entry rather than changing chunk 2.

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-server --test pod_http a_negotiated_read_varies a_304_carries`

Expected:
- `a_negotiated_read_varies_on_accept_and_a_binary_does_not` fails the first
  `assert!` with `GET /~/note: ` and an empty value — nothing sends `Vary`.
- `a_304_carries_what_the_200_carried` fails `assert_eq!` on `last-modified`
  with `left: []`, `right: [...]` — today's 304 carries `ETag` alone.

- [ ] **Step 3: One header set for the 200 and the 304**

The 200 and the 304 differ in exactly two things: the status and the
representation metadata. Make that true in the code rather than by keeping two
lists in step.

In `server/src/pod.rs`, add after `preconditions`:

```rust
/// Everything a `GET` or `HEAD` answers with **except** the representation:
/// no `Content-Type`, no body.
///
/// The 200 and the 304 share it. RFC 9110 §15.4.5 requires `ETag` and `Vary`
/// on a 304; the rest is control and resource metadata — `Allow`, `Accept-*`,
/// `WAC-Allow`, `Link` — which its SHOULD NOT does not cover, and a client
/// that revalidates must not lose the affordances it had.
///
/// `Last-Modified` *is* a deviation: §15.4.5 excuses cache-guiding metadata
/// only "if the response does not have an ETag field", and ours does. We send
/// it anyway, for the same reason. `Content-Location`, `Cache-Control` and
/// `Expires` are absent because a 200 from this server doesn't send them
/// either.
fn read_headers(response: &mut Response, request: &PodRequest, path: &str, outcome: &LdpOutcome) {
    // Chunk 2's builder: Link, Allow, Accept-*, WAC-Allow, per resource and
    // per caller.
    headers_for(response, request, path, outcome);

    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&conditional::etag(
        &outcome.version,
        outcome.syntax,
    )) {
        headers.insert(header::ETAG, value);
    }
    // Omitted rather than wrong if the stored time isn't one we can render.
    if let Some(date) = conditional::http_date(&outcome.modified)
        && let Ok(value) = HeaderValue::from_str(&date)
    {
        headers.insert(header::LAST_MODIFIED, value);
    }
    // Appended, never inserted: the CORS layer is outermost and adds `Origin`
    // to this same field (H10, H14). A binary is not negotiated — its bytes
    // are the same for every `Accept` — so claiming it varies would fragment
    // a cache for nothing.
    if outcome.syntax != conditional::BINARY {
        headers.append(header::VARY, HeaderValue::from_static("Accept"));
    }
}
```

Adapt the `headers_for` call to whatever chunk 2 named and however it applies
its headers — if it returns a `HeaderMap`, `headers.extend(headers_for(..))`;
if it returns a `Vec<(HeaderName, HeaderValue)>`, loop and `insert`. The one
thing to preserve is that `Vary` is **appended after** it, so nothing chunk 2
sets can clobber it and it cannot clobber the CORS layer.

Then in `get`, replace the 304 arm and the 200's construction:

```rust
    if preconditions(&headers).not_modified(&outcome.version, outcome.syntax) {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        read_headers(&mut response, &request, &path, &outcome);
        return response;
    }

    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, outcome.media_type.clone())],
        outcome.body.clone(),
    )
        .into_response();
    read_headers(&mut response, &request, &path, &outcome);
    response
}
```

`outcome.body.clone()` is there only because `read_headers` borrows
`&outcome`. Avoid the copy by destructuring the body out first
(`let body = std::mem::take(&mut outcome.body);` on a `mut outcome`) — a pod
read can be megabytes and this is the one place a needless copy of it would
hide.

Delete the old `Last-Modified` block at the end of `get`; `read_headers` owns
it now.

- [ ] **Step 4: Run them and watch them pass**

Run: `cargo test -p brolly-server --test pod_http a_negotiated_read_varies a_304_carries`

Expected: `test result: ok. 2 passed`.

Then the whole file, which is now the first point all of chunks 1–4's HTTP
expectations are meant to hold together:

Run: `cargo test -p brolly-server --test pod_http`

Expected: everything passes except the three CORS tests Task 6 owns —
`a_webid_is_readable_cross_origin` and
`the_headers_ldp_depends_on_are_exposed` still assert the old CORS posture and
are untouched so far, so they pass here too. If anything else is red, it is a
chunk 1–3 interaction; fix it before Task 6 rather than after.

### Task 6: CORS echoes the origin and the preflight's headers

**Files:**
- Modify: `server/tests/pod_http.rs` — `a_webid_is_readable_cross_origin`,
  `the_headers_ldp_depends_on_are_exposed`, and three new tests
- Modify: `server/src/lib.rs` — `cors` (`:160-195` at `e7fe4f6`)

H14, and H10's `Vary: Origin`.

- [ ] **Step 1: Rewrite the two expectations and add the new tests**

`a_webid_is_readable_cross_origin` asserts `Access-Control-Allow-Origin: *`
while sending an `Origin`. Replace its assertion:

```rust
    assert_eq!(status, StatusCode::OK);
    // Echoed, not `*`. With credentials disallowed the two grant a browser
    // identical permission, but a named origin is cacheable per-origin, and
    // CTS checks for the echo (`protocol/cors/acao-vary.feature`).
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://app.example")
    );
```

`the_headers_ldp_depends_on_are_exposed` gains the three new names and loses
one:

```rust
    for wanted in [
        "location",
        "link",
        "etag",
        "wac-allow",
        "accept-put",
        "www-authenticate",
        "vary",
    ] {
        assert!(exposed.contains(wanted), "{wanted} not exposed: {exposed}");
    }
    // Nothing sends it until stage 7, and an expose list is a promise.
    assert!(
        !exposed.contains("updates-via"),
        "still exposing updates-via: {exposed}"
    );
```

Then append the new tests, next to the other CORS ones:

```rust
/// CTS `protocol/cors/acao-vary.feature`: a response whose `Allow-Origin`
/// depends on the request's `Origin` must say so, or a shared cache serves one
/// origin's response to another. It uses a `.txt`, so this has to hold for a
/// binary too — the one response with nothing else to vary on.
#[tokio::test]
async fn every_response_varies_on_origin_binaries_included() {
    let h = harness().await;
    h.send("PUT", "/~/paper.pdf", Some(("application/pdf", PDF)), true)
        .await;

    for path in ["/profile", "/~/paper.pdf", "/~/nothing-here"] {
        let (_, headers) = headers_of(&h, "GET", path, &[("origin", "https://app.example")]).await;
        assert!(
            vary_of(&headers).contains("origin"),
            "{path}: {}",
            vary_of(&headers)
        );
    }
}

/// The handler sets `Vary: Accept` and the CORS layer is outermost. If it
/// `insert`s rather than appends, the negotiated read silently stops
/// advertising that it negotiates, and a shared cache serves Turtle to a
/// JSON-LD request — problem 8 restored by the layer meant to fix it.
#[tokio::test]
async fn the_cors_layer_adds_to_vary_rather_than_replacing_it() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let request = conditional_request(
        "GET",
        "/~/note",
        None,
        Some(h.session.as_str()),
        &[("origin", "https://app.example"), ("accept", "text/turtle")],
    );
    let (status, _, headers) = run(h.router.clone(), request).await;
    assert_eq!(status, StatusCode::OK);

    let vary = vary_of(&headers);
    assert!(vary.contains("accept"), "the handler's Accept was lost: {vary}");
    assert!(vary.contains("origin"), "no Origin: {vary}");
}

/// With no `Origin` there is no origin to echo, and `*` is the only answer
/// that lets a `file://` page or a curl-style client read the response.
#[tokio::test]
async fn a_request_with_no_origin_still_gets_a_wildcard() {
    let h = harness().await;
    let (status, headers) = headers_of(&h, "GET", "/profile", &[]).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*")
    );
    assert!(headers.get("access-control-allow-credentials").is_none());
}

/// Solid §8.1 wants an app able to send any combination of headers. A fixed
/// `Allow-Headers` list can never admit one it doesn't already name, so a
/// client sending a header we haven't thought of is blocked by the browser
/// before the request is made. CTS also asserts the response does *not* carry
/// `Accept` when the preflight didn't ask for it
/// (`protocol/cors/accept-acah.feature`).
#[tokio::test]
async fn a_preflight_is_answered_with_the_headers_it_asked_for() {
    let h = harness().await;
    let (status, headers) = headers_of(
        &h,
        "OPTIONS",
        "/~/notes/first",
        &[
            ("origin", "https://app.example"),
            ("access-control-request-method", "PUT"),
            ("access-control-request-headers", "x-invented-by-the-app"),
        ],
    )
    .await;

    assert!(status.is_success(), "preflight rejected: {status}");
    let allowed = headers
        .get("access-control-allow-headers")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(allowed.contains("x-invented-by-the-app"), "got: {allowed}");
    assert!(
        !allowed.contains("accept"),
        "named a header the preflight didn't ask for: {allowed}"
    );
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-server --test pod_http cross_origin exposed varies_on_origin cors_layer no_origin a_preflight`

Expected:
- `a_webid_is_readable_cross_origin` fails `assert_eq!` with `left:
  Some("*")`, `right: Some("https://app.example")`.
- `the_headers_ldp_depends_on_are_exposed` fails with
  `accept-put not exposed: …`.
- `every_response_varies_on_origin_binaries_included` fails with
  `/profile: ` — nothing adds `Origin` to `Vary`.
- `the_cors_layer_adds_to_vary_rather_than_replacing_it` fails with
  `no Origin: accept`.
- `a_preflight_is_answered_with_the_headers_it_asked_for` fails with
  `got: authorization, dpop, content-type, accept, slug, link, if-match,
  if-none-match` — the fixed list, which both omits what was asked for and
  names `accept`, which wasn't.
- **Passes already:** `a_request_with_no_origin_still_gets_a_wildcard` and
  `cors_never_allows_credentials`. Both are guards that must still pass after
  Step 3 — the first is why the echo can't simply replace the wildcard.

`a_preflight_admits_the_headers_a_solid_client_sends` (the existing preflight
test) asks for `authorization,dpop,content-type` and asserts the answer names
`dpop` and `authorization`. The echo satisfies it unchanged; don't touch it.

- [ ] **Step 3: Implement**

In `server/src/lib.rs`, replace the body of `cors` with:

```rust
async fn cors(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let preflight = request.method() == Method::OPTIONS
        && request
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD);

    // Read what the answer depends on before the request is consumed.
    let origin = request.headers().get(header::ORIGIN).cloned();
    let requested = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .cloned();

    let mut response = if preflight {
        axum::http::StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(request).await
    };

    // The fallback for a response that isn't answering a preflight, where the
    // field means nothing to a browser but has always been sent. `dpop` and
    // `slug` are not on the CORS safelist, so any request carrying one is
    // preflighted and fails unless named.
    const ALLOW_HEADERS: &str =
        "authorization, dpop, content-type, accept, slug, link, if-match, if-none-match";
    // A script sees only safelisted response headers unless they are exposed.
    // `location` after a POST and `link` for the ACL are load-bearing in LDP;
    // `www-authenticate` is how a client learns to re-authenticate (H3) and
    // `vary` is how it learns what the answer depended on (H10). `updates-via`
    // is gone: nothing sends it until stage 7, and an expose list is a promise.
    const EXPOSE_HEADERS: &str = "location, link, etag, allow, accept-patch, \
         accept-post, accept-put, wac-allow, www-authenticate, vary";

    let headers = response.headers_mut();
    for (name, value) in [
        (
            header::ACCESS_CONTROL_ALLOW_METHODS,
            "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS",
        ),
        (header::ACCESS_CONTROL_EXPOSE_HEADERS, EXPOSE_HEADERS),
        (header::ACCESS_CONTROL_MAX_AGE, "86400"),
    ] {
        headers.insert(name, axum::http::HeaderValue::from_static(value));
    }
    // Echoed when there is one to echo. With credentials disallowed this and
    // `*` grant a browser identical permission, but a named origin is
    // cacheable per-origin and CTS checks for it. A request with no `Origin`
    // — curl, a `file://` page — still needs the wildcard to read anything.
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        origin.unwrap_or(axum::http::HeaderValue::from_static("*")),
    );
    // A preflight is answered with what it asked for. A fixed list can never
    // admit a header it doesn't already name, and Solid §8.1 wants an app able
    // to send any combination; CTS also checks we don't name headers the
    // preflight didn't ask for.
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        requested.unwrap_or(axum::http::HeaderValue::from_static(ALLOW_HEADERS)),
    );
    // Appended, never inserted: the handler sets `Vary: Accept` on a
    // negotiated read (H10) and this layer is outermost, so an `insert` here
    // would drop it. On every response, binaries and refusals included —
    // `Allow-Origin` depends on `Origin` whatever the status.
    headers.append(
        header::VARY,
        axum::http::HeaderValue::from_static("Origin"),
    );
    response
}
```

Then extend the doc comment. The paragraph beginning **"`Allow-Origin: *` with
no `Allow-Credentials`…"** still says the wildcard is what we send; replace
its first sentence and keep the rest, which is the security-critical half and
is unchanged:

```rust
/// **The origin is echoed, with no `Allow-Credentials`, and the omission is
/// the security-critical half.** Echoing the origin *with* credentials would
/// let any site on the web make cookie-authenticated requests to the dashboard
/// and read the answers. Solid authenticates with a `DPoP` or `Authorization`
/// header the calling script must already hold, never with our cookie, so the
/// echo costs nothing and grants nothing: a cross-origin script with no token
/// is anonymous, and WAC treats it accordingly. With credentials disallowed,
/// echoing and `*` grant a browser identical permission; the echo is for
/// caches, which can key on it, and for CTS, which checks for it. A request
/// with no `Origin` keeps the wildcard.
```

and add one paragraph after it:

```rust
/// **A preflight is answered with the headers it asked for**, rather than from
/// a fixed list that can never admit one it doesn't already name (Solid §8.1).
/// The echoed value is a `HeaderValue` the `http` crate already parsed out of
/// the request, so it cannot carry a newline into the response.
```

- [ ] **Step 4: Run them and watch them pass**

Run: `cargo test -p brolly-server --test pod_http cross_origin exposed varies_on_origin cors_layer no_origin a_preflight credentials`

Expected: `test result: ok. 8 passed`.

Then the file:

Run: `cargo test -p brolly-server --test pod_http`

Expected: all pass.

### Task 7: Gates, then commit

- [ ] **Step 1: Format**

Run: `cargo fmt --all`

- [ ] **Step 2: The gates, one at a time**

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
./tools/check-doc-paths.sh
cargo deny check
```

No `Cargo.toml` changes in this chunk, so `cargo deny check` should be a
no-op; run it anyway because the gate list says so.

Then the test suites, one at a time — the workspace run is the last thing, not
a substitute for having watched each suite:

```bash
cargo test -p brolly-solid --lib conditional
cargo test -p brolly-server --test pod_http
cargo test --workspace
```

Expected: green throughout. If `adapters/solid/tests/*` are red, they are
chunk 1–3's territory (the `LdpError` split, `describe`); if
`server/tests/auth_flow.rs` or `federation_flows.rs` are red, look first at
the CORS expose list — those suites read response headers.

- [ ] **Step 3: Commit**

```bash
git add -u
git status   # conditional.rs, ldp.rs, pod.rs, lib.rs, pod_http.rs; nothing else
git commit -F - <<'MSG'
feat(solid): syntax-tagged ETags, Vary, public= and a CORS echo

WAC-Allow gains public=, a second granted_modes probe with an anonymous
subject that ldp runs inside the read's snapshot, so both components
describe the same ACL. A share UI can now see whether what it is looking
at is world-readable. Both groups are always spelled; WAC 6.1 allows an
empty one.

The ETag becomes "{version}.{syntax}" — "01J8....ttl", "01J8....jsonld",
"01J8....bin" for a binary. Reads compare the whole tag, so a client that
cached Turtle and revalidates asking for JSON-LD gets a 200 instead of
being told its Turtle is fresh. Writes compare the version part only: a
PUT replaces the resource, not a representation, and a client that took
its tag from a Turtle HEAD must be able to guard a JSON-LD PUT with it.
That is a deliberate deviation from RFC 9110 13.1.1, and the doc comments
say so. A tag with no dot, or with a suffix we never issue, matches
nothing: an If-Match carrying one fails closed with 412 and the client
re-GETs, which is what a tag cached before this stage does.

GET and HEAD send Vary: Accept on a negotiated read and not on a binary,
and the CORS layer appends Vary: Origin to every response, binaries and
refusals included. It appends rather than inserts, because it is
outermost and an insert would drop what the handler set. A 304 now
carries ETag, Vary, Last-Modified, Link, Allow, Accept-* and WAC-Allow —
everything the 200 carries but the representation metadata RFC 9110
15.4.5 asks us to leave off — so a client that revalidates does not lose
the affordances it had.

CORS echoes the request's Origin, keeping * when there is none, and
answers a preflight with the headers it asked for rather than from a
fixed list that could never admit a new one. Credentials stay
disallowed. Access-Control-Expose-Headers gains accept-put,
www-authenticate and vary, and drops updates-via, which nothing sends.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

- [ ] **Step 4: Verify from a clean checkout**

```bash
rm -rf /tmp/verify && git worktree add --detach /tmp/verify HEAD
cd /tmp/verify && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && ./tools/check-doc-paths.sh && cargo deny check && cargo test --workspace
cd - && git worktree remove /tmp/verify --force
```

The commit isn't done until that passes.

### Notes for the reviewer

- **Written without chunks 1–3 in view.** They were being written in parallel,
  so **Reconciling with chunks 1–3** lists every shape this chunk assumes of
  them — `describe` carrying `public`, `headers_for` as the one builder,
  `get` still calling `ldp::read` and deciding the 304 after it — and tells
  the implementer to adapt names, not behaviour. Line numbers cited are at
  `e7fe4f6`; chunks 1–3 move them.
- **The token set is this chunk's invention.** H10 spells `ttl`, `jsonld` and
  `bin` and leaves the rest open. Task 2 picks `nt`, `nq`, `trig` and `rdfxml`
  for the other three `WriteFormat` variants. Nothing outside `conditional.rs`
  depends on the spelling — a tag is opaque to everyone but us — but changing
  it later invalidates every cached validator again, so it is worth disliking
  now rather than in 5c. `every_syntax_has_a_distinct_token_we_recognise` is
  what stops a seventh syntax arriving without one.
- **A binary's tag is `"{version}.bin"`.** H10 says so directly, and the
  alternative — no token at all for a binary — would make a 5a-era tag and a
  binary's tag indistinguishable, so one of the two rules would have to give.
  `a_binary_is_tagged_as_a_binary` guards that a binary still revalidates
  whatever the `Accept`, which is the point of giving it a fixed token.
- **`rdfxml` is in `TOKENS` although a client can never `PUT` one.** ADR 0007
  refuses RDF/XML on every write but `negotiate` serves it, so a `GET` with
  `Accept: application/rdf+xml` gets a representation and therefore needs a
  tag. That tag can then appear in an `If-Match` on a write, where the version
  half is all that is compared — which is exactly why the write rule compares
  the version.
- **The write rule deviates from RFC 9110 §13.1.1** and the doc comment on
  `check_write` says so in full. A reviewer who reads only the code will want
  to "fix" it; the reasoning has to survive in the comment, not only here.
- **`If-Match: *` and `If-None-Match: *` are untouched.** `Condition::Any`
  carries no tag and asks only whether a current representation exists, so
  5a's tests for them don't move and neither does their behaviour.
- **Two `Vary` field lines, not one.** The handler appends `Accept`, the CORS
  layer appends `Origin`, so a negotiated read goes out with two lines.
  RFC 9110 §5.3 makes that identical to one comma-joined line, and every cache
  implementation combines them. Merging them in the CORS layer would mean
  parsing and rewriting a field on every response to save nothing; `vary_of`
  in the tests joins them so the assertions don't care.
- **`Vary: Origin` goes in the CORS layer, not the handler.** It has to be on
  *every* response — a 401, a 404, `/profile`, a binary — and the CORS layer
  is the only thing all of those pass through. It is also the thing that makes
  `Allow-Origin` depend on `Origin`, so the two belong together.
- **`a_webid_is_readable_cross_origin` is a test the spec doesn't list.** The
  spec's "what this changes" table names `the_headers_ldp_depends_on_are_exposed`
  and `wac_allow_on_an_acl_names_nothing_for_bob` for this chunk. This third
  one sends an `Origin` and asserts `*`, so H14's echo breaks it. It is a
  rewrite, not a deletion: the assertion it makes — a cross-origin script can
  read a WebID — is still the thing worth guarding.
- **`a_request_with_no_origin_still_gets_a_wildcard` is new and passes before
  the change.** It is the guard that stops the echo being implemented as
  "always echo, and send nothing when there's no `Origin`", which would break
  curl, `file://` pages and anything reading a WebID without a browser.
- **The 304 is decided after the body is serialized**, as it was in 5a:
  `ldp::read` negotiates and serializes, then `pod.rs` compares. Deciding
  before serializing would save the work, but it needs the syntax token, which
  needs the negotiation — and `ldp::read`'s snapshot is what guarantees the
  tag describes the bytes. 5c or a later pass can move `negotiate` out ahead
  of the body without changing any of this chunk's rules.
- **Nothing here touches the write path's precondition evaluation.** `put_in`,
  `append_in`, `delete_in` and `patch_in` still pass the resource's raw
  version to `check_write`; the suffix handling is entirely on the client's
  tag, inside `EntityTag::split`. That is why Task 3 changes no `_in`
  function, and why 5a's write-precondition HTTP tests pass unchanged.
- **`public=` costs a second WAC evaluation per read.** Four `authorize` calls
  over an in-memory graph, against the snapshot already open and the ACL
  already resolved (spec H9). It is chunk 2's cost, not this chunk's; this
  chunk only spends it.
- **`make_public` restates Alice's grants.** A direct ACL replaces the
  inherited one rather than adding to it, so a helper that wrote only the
  public authorization would silently take the owner's access away and the
  test would be asserting something else. The helper's doc comment says so,
  because it is the sort of thing that gets "simplified" later.
- **The harness's root ACL grants Read and Write, not Control**, and
  `AccessMode::Append.satisfying()` makes Write satisfy Append
  (`authz/src/wac.rs:53-58`). So Alice's `user=` on an ordinary resource is
  `"read write append"`, and the `"read write append control"` in
  `wac_allow_on_an_acl_names_nothing_for_bob` comes from `granted_modes`'
  all-or-nothing rule for `.acl` resources, not from her grants.
- **`Access-Control-Allow-Headers` still has a static fallback** for responses
  that aren't answering a preflight. A browser ignores the field there, and
  keeping it preserves today's behaviour for everything that isn't a
  preflight while the echo covers the case that matters.
- **Echoing a header back is safe here.** The value is a `HeaderValue` the
  `http` crate parsed out of the request, so it cannot contain CR or LF, and
  no response splitting is possible. With `Allow-Credentials` absent, echoing
  an attacker-chosen origin grants that origin exactly what `*` already did.

---

## Chunk 5: Write responses and bodies

Spec decisions **H11**, **H12**'s refusal half, **H13** and **H17**
(`docs/specs/2026-09-23-solid-http-surface.md`). This is the last of 5b's five
chunks and its **own commit**, on top of chunks 1–4. It is the only chunk that
changes what is *stored* and what a *write* says, so it gets its own revert
boundary: reverting it leaves chunks 1–4's headers, refusals and caching intact
and puts listings, `PUT` statuses and the `Content-Type` rule back to 5a.

Six tasks, **one commit** (Task 6 commits). Tasks 1 and 3–5 each leave the
workspace green. Task 2 is the only one that can't: its first step makes 5a's
`a_container_put_echoing_its_listing_succeeds` fail, and that failure is the
point — Task 1 puts member metadata into the listing, Task 2 teaches the write
path to drop an echo of it.

**What changes:**

| File | Change |
|---|---|
| `domain/src/vocab.rs` | `STAT`, `STAT_MTIME`, `STAT_SIZE`, and their namespace test (H13) |
| `store/src/resources.rs` | `container_triples` carries each member's `dcterms:modified`, `stat:mtime` and (binaries only) `stat:size`, read through `meta()`; `parse_modified` gets a public wrapper, `modified_ms` (H13) |
| `store/src/lib.rs` | `modified_ms` and `container_triples` in the crate-root re-export list |
| `adapters/solid/src/ldp.rs` | `Written`; `put_if`/`put_in` return it (H11); `LdpError::{NotEmpty, MemberMetadata}` (H12, H13); `container_body` drops an echoed member statement and refuses a changed one (H13) |
| `server/src/pod.rs` | `put` answers 201 + `Location` + chunk 3's `Link` set on a create, 204 on a replace (H11); `ldp_error` maps `NotEmpty` and `MemberMetadata` to 409 with a body (H12, H13); `put`, `post` and `patch` require a `Content-Type` for a non-empty body (H17) |
| `adapters/solid/tests/ldp_conformance.rs` | `put_turtle`'s signature; `NotEmpty` in two `matches!`; the H13 tests |
| `store/tests/resources.rs` | the listing's member metadata, and the Oxigraph-respelling guard |
| `server/tests/pod_http.rs` | 201 on create; the 409 bodies; the round trip, the altered listing and the race; H17's four refusals |

`server/src/mastodon_api.rs:552`, `server/tests/federation_flows.rs:508`,
`adapters/solid/tests/{acl_control,ldp_nonrdf,publication_boundary}.rs` and the
rest of `ldp_conformance.rs` keep compiling unchanged — see Task 3.

### Assumed from chunks 1–4

This chunk consumes them and changes none of them. If a name below differs from
what chunks 1–4 actually landed, **use theirs and keep this chunk's behaviour**.

- `LdpError::Denied` (chunk 1) and `LdpError::Undeletable` (chunks 1 and 3), the
  latter already carrying the storage root's and the root ACL's `DELETE` guards
  in `delete_in`. `LdpError::Forbidden` no longer exists. This chunk adds two
  variants beside them and touches neither.
- `/~/` routes `put`, `patch` and `delete` through `pod::put_root`,
  `pod::patch_root` and `pod::delete_root` (chunk 3), so `DELETE /~/` and
  `DELETE /~/.acl` reach a handler. Chunk 5 writes no new routes.
- `ldp::describe(pod, base, path, subject) -> Result<Description, LdpError>`
  (chunk 2): a body-free per-resource read giving kind, existence, version,
  modified, `granted` and `public`.
- One header builder in `pod.rs` over `describe`'s output (chunks 2–4), shared
  by `GET`, `HEAD`, `OPTIONS`, the 304 and the create responses. This chunk
  calls it from `pod::put`'s 201 arm and adds nothing to it. If chunk 3 exposed
  only a `Link`-set function rather than a whole builder, call that.
- `POST`'s 201 already carries `Location` and chunk 3's `Link` set. Chunk 5 does
  **not** touch `pod::post`'s success arm; only its `Content-Type` handling.
- `conditional::Preconditions` and the `_if` write functions (5a, chunk 5 of
  that stage), unchanged here except for `put_if`'s return type.

### Where the member metadata is generated, and what it is compared against

Two questions decide this chunk's shape, and the spec answers both.

**Generation lives in `store`.** `container_triples`
(`store/src/resources.rs:1107`) is already the one place that says what a GET of
a container serves from metadata, and H13's triples are metadata. Putting them
in `ldp` instead would mean `ldp` re-deriving `modified` from raw quads, which is
precisely what commit `9d58082` proves is wrong: Oxigraph shortens a stored
`xsd:dateTime` on the way in, so `.750Z` reads back as `.75Z` and `.000Z` as
`Z`. `read_meta` (`:586`) launders that through `normalise_modified`, so a
listing built from `meta()` and a member's own `Last-Modified` agree about every
write; a listing built from raw quads disagrees about one in ten.

So `container_triples` calls `PodRead::meta` once per member and emits:

- `dcterms:modified` — `meta.modified` verbatim, already fixed width;
- `stat:mtime` — `modified_ms(&meta.modified) / 1000`, because nothing stores an
  integer mtime;
- `stat:size` — `meta.blob.byte_size`, and only when there is a blob.

**The comparison reaches the server's own value through the read
`container_body` already does.** `container_body`
(`adapters/solid/src/ldp.rs:596`) opens with
`let served = resources::container_triples(r, container)?` — the same call, on
the same transaction, that a GET would make. Once Task 1 lands, `served` *is*
the set of statements the server would serve, member metadata included. So the
§4.2.1 rule needs no second read and cannot drift from what a GET says: it
indexes `served` by (member, predicate) and compares the client's statement
against that.

The comparison is **by value, per predicate**. Both sides are reduced by the
same function, so `1790000000`, `"1790000000"^^xsd:integer` and `" +1790000000"`
are one number, and `2026-09-23T10:00:00.007Z` and `2026-09-23T10:00:00.0070+00:00`
are one instant. `dcterms:modified` needs a date parse to do that, and
`brolly-solid`'s `time` has `formatting` but not `parsing` — which is why
`conditional::http_date` (5a) formats by hand. Rather than widen that feature,
`store` exports `modified_ms`, a public wrapper over the `parse_modified` that
commit `9d58082` made RFC 3339-tolerant. One parser, shared, and the "same
normalising path" H13 asks for is literally the same function.

**Only a contained resource's statements are policed.** The container's own
`dcterms:modified`, and any of the three predicates on a subject that isn't a
member, are ordinary content and are kept. `rdf:type` on a member is kept too:
we don't serve it, so a client isn't echoing us (H13). What is refused is
narrow, and the 409 says to re-read.

---

### Task 1: The listing carries its members' metadata

**Files:**
- Modify: `domain/src/vocab.rs` (append after `BROLLY_BYTE_SIZE`, `:104`, and
  extend the `resource_terms_live_in_their_namespaces` test)
- Modify: `store/src/resources.rs` (`normalise_modified`/`parse_modified` at
  `:1062-1079`; `container_triples` at `:1107`)
- Modify: `store/src/lib.rs:32-35` (the re-export list)
- Modify: `store/tests/resources.rs` (new tests after
  `modified_moves_past_a_stored_time_oxigraph_shortened`, `:999`)

- [ ] **Step 1: The vocabulary, and its failing test**

In `domain/src/vocab.rs`, add to the stage-5a block's tests first — inside
`resource_terms_live_in_their_namespaces`, after the `BROLLY` loop:

```rust
        // The Solid Protocol's prefix table writes `stat:` without the `#`,
        // but the vocabulary's terms carry it: `statsize` is not a term.
        assert_eq!(STAT, "http://www.w3.org/ns/posix/stat#");
        for term in [STAT_MTIME, STAT_SIZE] {
            assert!(term.starts_with(STAT), "{term}");
        }
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p brolly-domain --lib vocab`
Expected: compile failure, `error[E0425]`: cannot find value `STAT`,
`STAT_MTIME`, `STAT_SIZE` in this scope.

- [ ] **Step 3: Implement the terms**

After `BROLLY_BYTE_SIZE` (`:104`):

```rust
/// POSIX file metadata, which Solid Protocol §4.2.1 uses to describe a
/// container's members. Neither term declares a range, so both are written as
/// `xsd:integer` by our choice.
pub const STAT: &str = "http://www.w3.org/ns/posix/stat#";
/// A member's modified time in seconds since the epoch: the same instant as
/// its `dcterms:modified`, in the second form §4.2.1 names.
pub const STAT_MTIME: &str = "http://www.w3.org/ns/posix/stat#mtime";
/// A binary member's length in bytes. Not served for an RDF source, whose
/// serialized length depends on the syntax the client asked for.
pub const STAT_SIZE: &str = "http://www.w3.org/ns/posix/stat#size";
```

- [ ] **Step 4: Run it and watch it pass**

Run: `cargo test -p brolly-domain --lib vocab`
Expected: 2 passed.

- [ ] **Step 5: Write the failing store tests**

In `store/tests/resources.rs`, after
`modified_moves_past_a_stored_time_oxigraph_shortened` (`:999`), add a helper
and three tests. `container_triples` is reached as
`brolly_store::resources::container_triples`, so add it to the `use` at `:12-14`
via `brolly_store::resources::container_triples` on its own line.

```rust
// --- a container's listing (5b, H13) -------------------------------------------

/// The object of `<member> <predicate>` in `container`'s listing, as stored.
fn listed(pod: &Pod, container: &str, member: &str, predicate: &str) -> Option<Term> {
    container_triples(&pod.read_store(), container)
        .unwrap()
        .into_iter()
        .find(|q| q.subject.to_string() == format!("<{member}>") && q.predicate.as_str() == predicate)
        .map(|q| q.object)
}

/// Solid Protocol §4.2.1: a file manager draws a listing without a `HEAD` per
/// member. Without this it has to make one request per row, and a container of
/// a hundred notes costs a hundred round trips.
#[test]
fn a_listing_carries_each_members_modified_time_and_mtime() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    pod.write(|w| w.put(&at("c/m"), Content::Rdf(&[]))).unwrap();

    let own = pod.read_store().meta(&at("c/m")).unwrap().unwrap();
    assert_eq!(
        listed(&pod, &at("c/"), &at("c/m"), brolly_domain::vocab::DCTERMS_MODIFIED),
        Some(Term::Literal(Literal::new_typed_literal(
            own.modified.clone(),
            node(brolly_domain::vocab::XSD_DATE_TIME),
        ))),
        "the listing must agree with the member's own modified time",
    );
    let ms = brolly_store::resources::modified_ms(&own.modified).unwrap();
    assert_eq!(
        listed(&pod, &at("c/"), &at("c/m"), brolly_domain::vocab::STAT_MTIME),
        Some(Term::Literal(Literal::new_typed_literal(
            (ms / 1000).to_string(),
            node(brolly_domain::vocab::XSD_INTEGER),
        ))),
        "stat:mtime is the same instant in seconds",
    );
}

/// §4.2.1 excuses inapplicable metadata. An RDF source's serialized length
/// changes with the `Accept` header, so a `stat:size` on one would be a number
/// that contradicts `Content-Length` on most reads.
#[test]
fn only_a_binary_member_is_listed_with_a_size() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    let blob = blob(&pod, b"0123456789");
    pod.write(|w| {
        w.put(&at("c/doc"), Content::Rdf(&[]))?;
        w.put(&at("c/pic.png"), Content::Binary(blob.clone()))?;
        Ok(())
    })
    .unwrap();

    assert_eq!(
        listed(&pod, &at("c/"), &at("c/pic.png"), brolly_domain::vocab::STAT_SIZE),
        Some(Term::Literal(Literal::new_typed_literal(
            "10",
            node(brolly_domain::vocab::XSD_INTEGER),
        ))),
    );
    assert_eq!(
        listed(&pod, &at("c/"), &at("c/doc"), brolly_domain::vocab::STAT_SIZE),
        None,
        "an RDF source has no one length to report",
    );
}

/// Oxigraph normalises an `xsd:dateTime` on the way in, so a listing built
/// from the raw quads would say `.75Z` where the member's own `Last-Modified`
/// says `.750Z` — about one write in ten (commit 9d58082). The listing has to
/// go through the same `meta()` path every other reader does.
#[test]
fn a_listed_modified_time_is_the_fixed_width_one_meta_returns() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    pod.write(|w| w.put(&at("c/m"), Content::Rdf(&[]))).unwrap();

    // Plant the shortened form Oxigraph produces, in place of what was stored.
    let subject = NamedOrBlankNode::NamedNode(node(&at("c/m")));
    let predicate = node(brolly_domain::vocab::DCTERMS_MODIFIED);
    let graph = GraphName::NamedNode(node(METADATA_GRAPH));
    let raw = pod.raw_store();
    let stale: Vec<Quad> = raw
        .quads_for_pattern(
            Some((&subject).into()),
            Some(predicate.as_ref()),
            None,
            Some(graph.as_ref()),
        )
        .map(Result::unwrap)
        .collect();
    for quad in &stale {
        raw.remove(quad).unwrap();
    }
    raw.insert(&Quad::new(
        subject,
        predicate,
        Term::Literal(Literal::new_typed_literal(
            "2999-01-01T00:00:00.75Z",
            node(brolly_domain::vocab::XSD_DATE_TIME),
        )),
        graph,
    ))
    .unwrap();

    let listed = listed(&pod, &at("c/"), &at("c/m"), brolly_domain::vocab::DCTERMS_MODIFIED);
    let Some(Term::Literal(value)) = listed else {
        panic!("no modified time in the listing: {listed:?}");
    };
    assert_eq!(
        value.value(),
        "2999-01-01T00:00:00.750Z",
        "the listing must not serve the shortened form",
    );
    assert_eq!(
        value.value(),
        pod.read_store().meta(&at("c/m")).unwrap().unwrap().modified,
        "the listing and meta() must not disagree",
    );
}
```

- [ ] **Step 6: Run them and watch them fail**

Run: `cargo test -p brolly-store --test resources listing`
and `cargo test -p brolly-store --test resources a_listed_modified`
Expected: compile failure, `error[E0432]`/`E0425`: unresolved import
`brolly_store::resources::container_triples` is fine, but
`brolly_store::resources::modified_ms` is not found. Once that resolves, the
three tests fail with `assertion \`left == right\` failed: left: None`.

- [ ] **Step 7: Implement `modified_ms` and the listing**

In `store/src/resources.rs`, give `parse_modified` a public face beside it
(`:1062`):

```rust
/// A stored `dcterms:modified` as milliseconds since the epoch, or `None` if
/// it isn't a time we wrote.
///
/// Public because `ldp` compares a client's echo of a member's modified time
/// against the one we serve, and must compare *values*: `.007Z` and
/// `.0070+00:00` are one instant. `brolly-solid`'s `time` has `formatting` but
/// not `parsing`, so this is the one parser, and it is the same one `meta()`
/// normalises through.
pub fn modified_ms(modified: &str) -> Option<i64> {
    parse_modified(modified)
}
```

Then replace `container_triples` (`:1107-1140`). Keep the existing types and
containment loop exactly as it is, and add the member pass after it:

```rust
/// What a GET of `container` serves from metadata, in the container's own
/// graph: its types (`ldp:Resource`, `ldp:Container`, `ldp:BasicContainer`,
/// and `pim:Storage` at the root), one `ldp:contains` per member, and each
/// member's server-managed metadata (Solid Protocol §4.2.1).
///
/// Member metadata is `dcterms:modified`, `stat:mtime`, and `stat:size` for a
/// binary. All three come from [`PodRead::meta`], not from the raw quads: a
/// stored `xsd:dateTime` reads back shortened (`.750Z` as `.75Z`), and a
/// listing that disagreed with the member's own `Last-Modified` would be worse
/// than no listing. `stat:size` is omitted for an RDF source, whose length
/// depends on the syntax negotiated.
///
/// One `meta()` per member, which is six indexed lookups each. `ldp` reuses
/// this one call for both the body it serves and the §4.2.1 check on a write,
/// so a container is read once either way.
///
/// `ldp::read_in` adds these to the container's content graph, and a container
/// PUT is checked against them, so the echo of a GET round-trips.
pub fn container_triples(r: &impl PodRead, container: &str) -> Result<Vec<Quad>, StoreError> {
    // … the existing SERVED_TYPES / node / graph / metadata / loop, unchanged,
    // building `out` …

    // §4.2.1, for every member `out` now names.
    let members: Vec<NamedNode> = out
        .iter()
        .filter(|q| q.predicate.as_str() == vocab::LDP_CONTAINS)
        .filter_map(|q| match &q.object {
            Term::NamedNode(member) => Some(member.clone()),
            _ => None,
        })
        .collect();
    for member in members {
        let Some(meta) = read_meta(r, member.as_str())? else {
            // Listed but with no record: a broken pod, not a reason to refuse
            // the whole listing. The `ldp:contains` still goes out.
            continue;
        };
        let subject = NamedOrBlankNode::NamedNode(member);
        let mut say = |predicate: &str, object: Term| {
            out.push(Quad::new(
                subject.clone(),
                iri(predicate),
                object,
                graph.clone(),
            ));
        };
        say(
            vocab::DCTERMS_MODIFIED,
            Term::Literal(Literal::new_typed_literal(
                meta.modified.clone(),
                iri(vocab::XSD_DATE_TIME),
            )),
        );
        if let Some(ms) = parse_modified(&meta.modified) {
            say(
                vocab::STAT_MTIME,
                Term::Literal(Literal::new_typed_literal(
                    (ms / 1000).to_string(),
                    iri(vocab::XSD_INTEGER),
                )),
            );
        }
        if let Some(blob) = &meta.blob {
            say(
                vocab::STAT_SIZE,
                Term::Literal(Literal::new_typed_literal(
                    blob.byte_size.to_string(),
                    iri(vocab::XSD_INTEGER),
                )),
            );
        }
    }
    Ok(out)
}
```

The closure borrows `out` mutably while `subject` and `graph` are cloned per
statement; if borrowck objects to `say` capturing `out` alongside the iteration,
collect the three statements into a local `Vec` and `out.extend(..)` after —
same result, no closure.

In `store/src/lib.rs:32-35`, add `container_triples` and `modified_ms` to the
`pub use resources::{…}` list so a caller can name them without spelling the
module. `ldp` already imports `resources::{self, …}` and can keep doing so.

- [ ] **Step 8: Run them and watch them pass**

Run: `cargo test -p brolly-store --test resources`
Expected: every test in the file passes, the three new ones included.

- [ ] **Step 9: The rest of the store's tests still hold**

Run: `cargo test -p brolly-store`
Expected: green. `a_put_into_a_large_container_keeps_every_member`
(`store/tests/resources.rs:1005`) is the one to watch — it builds a container
with many members, and `container_triples` now does per-member work.

- [ ] **Step 10: Format and stage**

```bash
cargo fmt --all
git add domain/src/vocab.rs store/src/resources.rs store/src/lib.rs store/tests/resources.rs
```

Don't commit: the workspace is green but `ldp` now stores an echoed listing,
which Task 2 fixes.

---

### Task 2: A container write drops the echo and refuses the change

**Files:**
- Modify: `adapters/solid/src/ldp.rs` (`LdpError` at `:46-116`; `container_body`
  at `:596-643`)
- Modify: `adapters/solid/tests/ldp_conformance.rs` (new tests after
  `a_container_put_echoing_its_listing_succeeds`, `:601`)

- [ ] **Step 1: Watch 5a's round trip break**

Nothing to write yet. Task 1 put member metadata in the listing, and
`container_body` keeps every quad whose subject isn't the container — so a
client that GETs a listing and PUTs it back now stores the metadata as content,
stale forever and served beside the generated version.

Run: `cargo test -p brolly-solid --test ldp_conformance a_container_put_echoing_its_listing_succeeds`
Expected: **fails**, `assertion failed: own.is_empty()`, with the panic message
`the echoed types and containment are the server's, not stored:` followed by the
member's `dcterms:modified` and `stat:mtime` quads. That is §4.2.1's MUST,
observed.

This is the test the round trip hangs on, and it is 5a's, not new. Leave it
exactly as it is.

- [ ] **Step 2: Write the failing tests for the refusal and the race**

In `adapters/solid/tests/ldp_conformance.rs`, after
`a_container_put_echoing_its_listing_succeeds` (`:601`):

```rust
/// The listing a client reads back, with one statement altered — the shape of
/// a client that "fixed up" a timestamp, or of a stale description written
/// after someone else's edit. §4.2.1 makes it a 409, not a silent store of a
/// number the server will contradict on the next GET.
#[test]
fn a_container_put_that_changes_a_members_modified_time_is_refused() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/c/m", NOTE).unwrap();
    let listing = ntriples(&store, "/~/c/");
    let own = meta(&store, &format!("{ROOT}c/m")).unwrap().modified;
    let altered = listing.replace(&own, "1999-01-01T00:00:00.000Z");
    assert_ne!(altered, listing, "setup: the listing carries the time");

    let err = put_turtle(&store, "/~/c/", altered.as_bytes()).unwrap_err();
    assert!(matches!(err, LdpError::MemberMetadata), "got {err:?}");
    assert_eq!(
        meta(&store, &format!("{ROOT}c/m")).unwrap().modified,
        own,
        "a refused PUT moved a member's modified time",
    );
    assert!(
        own_graph(&store, &format!("{ROOT}c/")).is_empty(),
        "a refused PUT stored something",
    );
}

/// The same rule for the other two predicates, so a client can't reach one of
/// them by picking a different one of §4.2.1's four statements.
#[test]
fn a_container_put_that_changes_a_members_mtime_or_size_is_refused() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/c/m", NOTE).unwrap();
    let member = format!("{ROOT}c/m");

    for (predicate, object) in [
        (vocab::STAT_MTIME, "0"),
        // We serve no size for an RDF source, so any value differs from ours.
        (vocab::STAT_SIZE, "4096"),
    ] {
        let body = format!("<{member}> <{predicate}> {object} .");
        let err = put_turtle(&store, "/~/c/", body.as_bytes()).unwrap_err();
        assert!(matches!(err, LdpError::MemberMetadata), "{predicate}: {err:?}");
    }
}

/// The rule is per statement and by value. A client that round-trips a
/// listing through JSON-LD or a date library respells the literal; refusing
/// that would refuse every read-modify-write Inrupt's solid-client, LDO and
/// SolidOS do.
#[test]
fn a_member_statement_respelled_but_unchanged_is_still_an_echo() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/c/m", NOTE).unwrap();
    let member = format!("{ROOT}c/m");
    let modified = meta(&store, &member).unwrap().modified;
    // The same instant with an explicit zero offset, and the same integer
    // with a leading `+` and no datatype.
    let respelled = modified.replace('Z', "+00:00");
    let seconds = brolly_store::resources::modified_ms(&modified).unwrap() / 1000;
    let body = format!(
        "<{member}> <{}> \"{respelled}\"^^<{}> ; <{}> \"+{seconds}\"^^<{}> .",
        vocab::DCTERMS_MODIFIED,
        vocab::XSD_DATE_TIME,
        vocab::STAT_MTIME,
        vocab::XSD_INTEGER
    );

    put_turtle(&store, "/~/c/", body.as_bytes()).unwrap();
    assert!(
        own_graph(&store, &format!("{ROOT}c/")).is_empty(),
        "an echo was stored as content",
    );
}

/// `rdf:type` is not on the list, because we don't serve it: `<…/m> a
/// schema:Note` in a container's description is the client's own data, and so
/// is any other predicate on a member. A blanket "nothing about a member" rule
/// would make a container's description useless.
#[test]
fn ordinary_statements_about_a_member_are_kept() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/c/m", NOTE).unwrap();
    let member = format!("{ROOT}c/m");
    let body = format!(
        "<{member}> <{}> <https://schema.org/Note> ; <http://www.w3.org/2000/01/rdf-schema#label> \"First\" .",
        vocab::RDF_TYPE
    );

    put_turtle(&store, "/~/c/", body.as_bytes()).unwrap();
    let served = ntriples(&store, "/~/c/");
    assert!(served.contains("schema.org/Note"), "{served}");
    assert!(served.contains("\"First\""), "{served}");
}

/// The race §4.2.1's rule creates, and the reason the 409 has to carry a body.
/// A member's `dcterms:modified` moves on every write to that member, not only
/// on create and delete — so a client that reads a listing, edits a member, and
/// then writes the container's own description back is refused for metadata it
/// never touched. The answer is to re-read, which the body has to say.
#[test]
fn a_description_written_after_a_member_changed_is_refused_until_a_re_read() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/c/m", NOTE).unwrap();
    let stale = ntriples(&store, "/~/c/");

    // The client edits the member, then writes back the description it read
    // before the edit.
    put_turtle(&store, "/~/c/m", br#"<> <https://example.org/title> "Edited" ."#).unwrap();
    let err = put_turtle(&store, "/~/c/", stale.as_bytes()).unwrap_err();
    assert!(matches!(err, LdpError::MemberMetadata), "got {err:?}");

    // Re-reading and retrying is the resolution, and it succeeds.
    let fresh = ntriples(&store, "/~/c/");
    put_turtle(&store, "/~/c/", fresh.as_bytes()).unwrap();
}
```

`ldp_conformance.rs` doesn't depend on `brolly-store`'s `resources` module by
name today; it already has `brolly_store::resources::{…}` in its `use` at `:13`,
so `brolly_store::resources::modified_ms` resolves without a new dependency.

- [ ] **Step 3: Run them and watch them fail**

Run: `cargo test -p brolly-solid --test ldp_conformance a_container_put_that_changes`
Expected: compile failure, `error[E0599]`: no variant named `MemberMetadata`
found for enum `LdpError`.

- [ ] **Step 4: Implement the variant**

In `adapters/solid/src/ldp.rs`, add to `LdpError` beside `ContainmentChange`:

```rust
    /// A write named one of the server-managed statements a container's
    /// listing carries about a contained resource — `dcterms:modified`,
    /// `stat:mtime` or `stat:size` — with a value other than the one we serve
    /// (409, Solid Protocol §4.2.1). An exact echo is dropped instead, so a
    /// read-modify-write of a container still works.
    MemberMetadata,
```

and its `Display` arm:

```rust
            LdpError::MemberMetadata => write!(
                f,
                "a contained resource's modified time and size are the server's; \
                 re-read this container and send its current description"
            ),
```

The message is the one §5.4 requires a 409 to carry, and Task 6 asserts a client
can read it off the wire.

- [ ] **Step 5: Implement the rule in `container_body`**

Replace `container_body`'s doc comment and body (`:586-633`). The containment
and echoed-type rules are unchanged; the member pass is new.

```rust
/// The part of a container's body that is the client's to store.
///
/// - **Containment.** `<container> ldp:contains ?x` triples must name exactly
///   the current members, so a GET-edit-PUT round trip works. A body with none
///   leaves membership alone. Any other set is `ContainmentChange` (Solid
///   Protocol §5.3). Either way none of them is stored: containment lives in
///   metadata.
/// - **Echoed server types** are dropped: `ldp:Resource`, `ldp:Container`,
///   `ldp:BasicContainer`, and `pim:Storage` at the root.
/// - **A member's server-managed metadata** — `dcterms:modified`, `stat:mtime`
///   and `stat:size` on a contained resource (§4.2.1) — is dropped when its
///   value equals what we would serve and `MemberMetadata` when it differs or
///   won't parse. Per statement, and by value: `1790000000` and
///   `"1790000000"^^xsd:integer` are one number, and a timestamp a client
///   round-tripped through JSON-LD may be spelled a third way. Without the echo
///   tolerance every read-modify-write of a container would 409.
///   `rdf:type` is **not** on the list, because we don't serve it; nor is any
///   other predicate on a member, nor any of the three on a subject that isn't
///   a member. Both stay ordinary content.
/// - **The rest** is kept.
fn container_body(
    r: &impl PodRead,
    container: &str,
    quads: Vec<Quad>,
) -> Result<Vec<Quad>, LdpError> {
    let node = NamedOrBlankNode::NamedNode(iri(container));
    // What a GET serves from metadata: the types, the listing, and each
    // member's metadata. One read, shared by the two rules below, so the check
    // cannot disagree with what a GET would say.
    let served = resources::container_triples(r, container)?;
    let members: BTreeSet<String> = served
        .iter()
        .filter(|q| q.predicate.as_str() == vocab::LDP_CONTAINS)
        .map(|q| q.object.to_string())
        .collect();
    let member_iris: BTreeSet<&str> = served
        .iter()
        .filter(|q| q.predicate.as_str() == vocab::LDP_CONTAINS)
        .filter_map(|q| match &q.object {
            Term::NamedNode(member) => Some(member.as_str()),
            _ => None,
        })
        .collect();
    // (member, predicate) -> the value we serve, reduced the same way the
    // client's will be.
    let ours: BTreeMap<(&str, &str), i64> = served
        .iter()
        .filter(|q| member_iris.contains(subject_iri(&q.subject).unwrap_or("")))
        .filter_map(|q| {
            let predicate = q.predicate.as_str();
            let value = member_value(predicate, &q.object)?;
            Some(((subject_iri(&q.subject)?, predicate), value))
        })
        .collect();
    let is_root = served
        .iter()
        .any(|q| matches!(&q.object, Term::NamedNode(t) if t.as_str() == vocab::PIM_STORAGE));

    let mut named = BTreeSet::new();
    let mut kept = Vec::new();
    for quad in quads {
        let about_it = quad.subject == node;
        if about_it && quad.predicate.as_str() == vocab::LDP_CONTAINS {
            named.insert(quad.object.to_string());
            continue;
        }
        // An echo of a type the server serves isn't the client's to store.
        let echoed = about_it
            && quad.predicate.as_str() == vocab::RDF_TYPE
            && is_served_type(&quad.object, is_root);
        if echoed {
            continue;
        }
        // §4.2.1: a member's metadata is ours. An exact echo is not an update.
        let predicate = quad.predicate.as_str();
        if MANAGED_MEMBER_PREDICATES.contains(&predicate)
            && let Some(subject) = subject_iri(&quad.subject)
            && member_iris.contains(subject)
        {
            let sent = member_value(predicate, &quad.object);
            let mine = ours.get(&(subject, predicate)).copied();
            if sent.is_some() && sent == mine {
                continue;
            }
            return Err(LdpError::MemberMetadata);
        }
        kept.push(quad);
    }
    if !named.is_empty() && named != members {
        return Err(LdpError::ContainmentChange);
    }
    Ok(kept)
}

/// The statements a container's listing makes about each member, which §4.2.1
/// forbids a client to change. `rdf:type` is absent deliberately: we serve none
/// for a member, so a client naming one isn't echoing us.
const MANAGED_MEMBER_PREDICATES: [&str; 3] = [
    vocab::DCTERMS_MODIFIED,
    vocab::STAT_MTIME,
    vocab::STAT_SIZE,
];

fn subject_iri(subject: &NamedOrBlankNode) -> Option<&str> {
    match subject {
        NamedOrBlankNode::NamedNode(node) => Some(node.as_str()),
        NamedOrBlankNode::BlankNode(_) => None,
    }
}

/// One of [`MANAGED_MEMBER_PREDICATES`] reduced to a number, so two spellings
/// of one value compare equal.
///
/// `dcterms:modified` becomes milliseconds since the epoch through `store`'s
/// own parser — the same one `meta()` normalises through, and the only RFC 3339
/// parser this workspace has (`brolly-solid`'s `time` has `formatting` but not
/// `parsing`). The two `stat:` terms are integers. Every comparison is between
/// two values of the *same* predicate, so both sides are always reduced the
/// same way. `None` means "not a value we can compare", which the caller treats
/// as a change rather than an echo: failing closed here refuses a body we
/// couldn't check, and the client re-reads.
fn member_value(predicate: &str, object: &Term) -> Option<i64> {
    let Term::Literal(literal) = object else {
        return None;
    };
    let text = literal.value().trim();
    match predicate {
        vocab::DCTERMS_MODIFIED => resources::modified_ms(text),
        vocab::STAT_MTIME | vocab::STAT_SIZE => text.parse().ok(),
        _ => None,
    }
}
```

Add `BTreeMap` to the `use std::collections::…` at `:29`.

`ours` borrows from `served`, and the loop over `quads` doesn't touch it, so the
borrows don't overlap. If the `.filter(..).filter_map(..)` pair over `served`
reads badly once written out, collect it with a plain `for` loop — the shape
matters less than reading `served` exactly once.

- [ ] **Step 6: Run the H13 tests and watch them pass**

Run: `cargo test -p brolly-solid --test ldp_conformance a_container_put`
Expected: 5 passed (5a's three, plus the two new `a_container_put_that_changes…`).

Run: `cargo test -p brolly-solid --test ldp_conformance`
Expected: green, including `a_container_put_echoing_its_listing_succeeds`
— the round trip Step 1 broke — and the respelling, ordinary-statement and race
tests.

- [ ] **Step 7: A PATCH is covered by the same rule**

No new code: `store_patched` (`:976`) routes a patched container through
`container_body`, and §4.2.1 names POST, PUT *and* PATCH. Confirm it, so the
coverage is deliberate rather than accidental. Append to
`adapters/solid/tests/patch_conformance.rs`:

```rust
/// §4.2.1 names PATCH as well as PUT and POST. `store_patched` routes a
/// container through the same `container_body`, so the rule holds for the verb
/// a client is most likely to reach for when editing one statement.
#[test]
fn a_patch_cannot_rewrite_a_members_modified_time() {
    // … seed `/~/c/m`, then INSERT DATA a `dcterms:modified` for it into
    // `/~/c/`, and assert `PatchError::Ldp(LdpError::MemberMetadata)`.
}
```

Fill it in against that file's own fixture and helpers.

Run: `cargo test -p brolly-solid --test patch_conformance`
Expected: green.

- [ ] **Step 8: The adapter's other suites still hold**

Run: `cargo test -p brolly-solid`
Expected: green. Watch `ldp_nonrdf.rs` — a binary member now contributes a
`stat:size` to its container's listing.

- [ ] **Step 9: Format and stage**

```bash
cargo fmt --all
git add adapters/solid/src/ldp.rs adapters/solid/tests/ldp_conformance.rs adapters/solid/tests/patch_conformance.rs
```

---

### Task 3: `PUT` reports whether it created

**Files:**
- Modify: `adapters/solid/src/ldp.rs` (`put_if` at `:419-453`, `put_in` at
  `:515-576`)
- Modify: `adapters/solid/tests/ldp_conformance.rs` (`put_turtle` at `:491`, and
  one new test)
- Modify: `server/src/pod.rs` (`put`'s success arm, `:382`)

`ldp::put` has roughly 55 call sites, and almost all of them survive untouched:
`ldp::put(..).unwrap();` and `.ok();` discard a value of any type, and
`.unwrap_err()` and `matches!(result, Err(..))` don't name the `Ok` type.
The compiler finds the exceptions; there are two.

- [ ] **Step 1: Write the failing test**

In `adapters/solid/tests/ldp_conformance.rs`, after
`put_then_get_round_trips` (`:129`):

```rust
/// LDP and every Solid client branch on 201 vs 204, and the only place that
/// knows which happened is the write itself: `put_in` already reads the
/// target's metadata for its preconditions, so the answer is free. Deriving it
/// in `pod.rs` from a read before or after the write would race.
#[test]
fn a_put_says_whether_it_created_or_replaced() {
    let (_m, _d, store) = pod();
    assert_eq!(put_turtle(&store, "/~/note", NOTE).unwrap(), ldp::Written::Created);
    assert_eq!(put_turtle(&store, "/~/note", NOTE).unwrap(), ldp::Written::Replaced);

    // A container and an ACL answer the same way.
    assert_eq!(put_turtle(&store, "/~/c/", b"").unwrap(), ldp::Written::Created);
    assert_eq!(put_turtle(&store, "/~/c/", b"").unwrap(), ldp::Written::Replaced);

    // An intermediate container a PUT created on the way is not the target.
    assert_eq!(put_turtle(&store, "/~/d/e", NOTE).unwrap(), ldp::Written::Created);
    assert_eq!(put_turtle(&store, "/~/d/", b"").unwrap(), ldp::Written::Replaced);
}
```

and widen the helper at `:491`:

```rust
fn put_turtle(store: &Pod, path: &str, body: &[u8]) -> Result<ldp::Written, LdpError> {
    ldp::put(store, None, BASE, path, &alice(), body, "text/turtle", ROOT)
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p brolly-solid --test ldp_conformance a_put_says_whether`
Expected: compile failure, `error[E0412]`: cannot find type `Written` in module
`ldp`.

- [ ] **Step 3: Implement `Written`**

In `adapters/solid/src/ldp.rs`, after `LdpOutcome` (`:148`):

```rust
/// What a `PUT` did. LDP answers 201 for one and 204 for the other, and a
/// client that creates with `If-None-Match: *` branches on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Written {
    Created,
    Replaced,
}
```

In `put_in` (`:515`), the target's metadata is already read for the
precondition at `:531`. Reuse it rather than reading again:

```rust
    let current = w.meta(&resource)?.map(|meta| meta.version);
    preconditions.check_write(conditional::Method::Put, current.as_deref())?;
    // The same read the precondition used, so nothing can land between them.
    let written = match current {
        Some(_) => Written::Replaced,
        None => Written::Created,
    };
```

Change the signature to `-> Result<Written, LdpError>`, and each of the three
`return Ok(())` / `Ok(())` at `:537`, `:543` and `:575` to `Ok(written)`. Note
that `:546`'s `let previous = w.meta(&resource)?` and the `let current` at
`:550` are a *different* `current` (a blob digest); rename the new binding if
it shadows confusingly — `written` above avoids it.

`put_if` (`:419`) becomes `-> Result<Written, LdpError>`; its inner
`let attempt = || -> Result<(), LdpError>` becomes
`|| -> Result<Written, LdpError>`, and `put` (`:456`) follows. `release_refused_bytes`
is already generic in `T`, so it needs nothing.

Extend `put_in`'s doc comment with:

> Answers [`Written::Created`] when the target had no metadata before this
> write and [`Written::Replaced`] when it did, from the same read the
> precondition uses. A container this write created on the way to the target is
> not the target: only the resource addressed decides.

- [ ] **Step 4: Run it and watch it pass**

Run: `cargo test -p brolly-solid --test ldp_conformance a_put_says_whether`
Expected: 1 passed.

- [ ] **Step 5: Sweep the call sites the compiler names**

Run: `cargo test --workspace --no-run`
Expected: exactly one error left, in `server/src/pod.rs:382`:
`error[E0308]`: mismatched types, expected `Written`, found `()` in the
`Ok(()) =>` arm of `pod::put`.

If anything else appears — a `matches!(.., Ok(()))`, a closure with an
annotated return type, a `let x: Result<(), LdpError>` — fix it in place and
note it here. `server/src/mastodon_api.rs:552` uses `put_in(..).map_err(..)?;`,
which discards a `Written` as a statement and compiles unchanged;
`server/tests/federation_flows.rs:508` ends in `.ok();` and does too.

- [ ] **Step 6: `pod::put` answers 201 on a create**

In `server/src/pod.rs`, replace `put`'s success arm (`:382`):

```rust
        // LDP's rule, and what every Solid client branches on. The `Link` set
        // is H6's, built by the same helper GET uses — a client that creates a
        // resource learns its kind without a second request.
        Ok(ldp::Written::Created) => {
            let location = format!("{}{path}", request.base);
            let mut response = (StatusCode::CREATED, [(header::LOCATION, location)])
                .into_response();
            if let Ok(description) = ldp::describe(
                &request.pod,
                &request.base,
                &path,
                &request.subject,
            ) {
                // Chunk 3's builder. A description that fails to read doesn't
                // undo the write: the 201 and its `Location` still go out.
                response
                    .headers_mut()
                    .extend(link_headers(&description, &request, &path));
            }
            response
        }
        Ok(ldp::Written::Replaced) => StatusCode::NO_CONTENT.into_response(),
```

Use whatever chunk 3 actually named the builder and whatever shape it returns;
the only requirements are that the 201 carries `Location` and the same `Link`
set a `GET` of that resource would, and that a failure to describe still leaves
a 201.

**No `ETag` on either arm.** 5a's rule (R4, RFC 9110 §9.3.4) is unchanged and
`a_write_response_carries_no_etag_and_the_etag_moves`
(`server/tests/pod_http.rs:1111`) already guards it on both.

- [ ] **Step 7: Run the HTTP suite and see what moved**

Run: `cargo test -p brolly-server --test pod_http`
Expected: three failures, each an `assertion \`left == right\`` with
`left: 201 Created`, `right: 204 No Content`:
`put_then_get_over_http` (`:245`),
`a_binary_put_and_got_over_http_keeps_its_bytes_and_its_type` (`:518`),
`a_binary_refused_by_a_precondition_leaves_no_bytes_behind` (`:1217`). Each is a
PUT of a resource that did not exist, so each is now a 201. Change the three
`assert_eq!(status, StatusCode::NO_CONTENT)` to `StatusCode::CREATED` and leave
the rest of each test alone — the other PUT assertions in the file already use
`status.is_success()`.

Re-run: `cargo test -p brolly-server --test pod_http`
Expected: green.

- [ ] **Step 8: Format and stage**

```bash
cargo fmt --all
git add adapters/solid/src/ldp.rs adapters/solid/tests/ldp_conformance.rs server/src/pod.rs server/tests/pod_http.rs
```

---

### Task 4: A non-empty container is 409, with a body

**Files:**
- Modify: `adapters/solid/src/ldp.rs` (`LdpError`, the `From<StoreError>` arm at
  `:111`, `delete_in` at `:882`)
- Modify: `adapters/solid/tests/ldp_conformance.rs` (`:364`, `:684`)
- Modify: `server/src/pod.rs` (`ldp_error`, and its unit test at `:584`)

Chunk 3 already made `DELETE /~/` and `DELETE /~/.acl` reachable and answered
them with `Undeletable` → 405. This task is only the third of §5.4's three
refusals: the populated container, which is today a 403 saying "you may not"
where the truth is "not while it has members".

- [ ] **Step 1: Write the failing unit test**

In `server/src/pod.rs`'s `tests` module, extend
`the_new_ldp_refusals_have_status_codes`:

```rust
        // §5.4 requires the status *and* a body describing the error, so the
        // client can tell "empty it first" from "you may not".
        assert_eq!(
            ldp_error(LdpError::NotEmpty).status(),
            StatusCode::CONFLICT,
            "Solid Protocol §5.4"
        );
        assert_eq!(
            ldp_error(LdpError::MemberMetadata).status(),
            StatusCode::CONFLICT,
            "Solid Protocol §4.2.1"
        );
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p brolly-server --lib pod::tests`
Expected: compile failure, `error[E0599]`: no variant named `NotEmpty` found
for enum `LdpError`. (`MemberMetadata` already exists from Task 2.)

- [ ] **Step 3: Implement `NotEmpty`**

In `adapters/solid/src/ldp.rs`, add beside `MemberMetadata`:

```rust
    /// A `DELETE` of a container that still has members (409, Solid Protocol
    /// §5.4). Distinct from a refusal of access: the caller may delete this
    /// container, once it is empty.
    NotEmpty,
```

with the `Display` arm §5.4's body is built from:

```rust
            LdpError::NotEmpty => write!(
                f,
                "this container still has members; delete them first, \
                 then re-read the container and retry"
            ),
```

Point `From<StoreError>`'s `ContainerNotEmpty` arm (`:111`) at it, dropping
5a's "until 5b's 409" comment:

```rust
            // Solid Protocol §5.4. `delete_in` refuses first, so this is the
            // same refusal reached by a caller composing its own transaction.
            StoreError::ContainerNotEmpty => LdpError::NotEmpty,
```

and `delete_in`'s guard (`:882`):

```rust
    // Refusing to delete a non-empty container is LDP's rule, and it is the
    // difference between removing a resource and silently orphaning a subtree.
    // 409, not 403: the caller holds Write, and emptying it is the way through.
    if matches!(meta.kind, Kind::Container) && !w.members(&resource)?.is_empty() {
        return Err(LdpError::NotEmpty);
    }
```

- [ ] **Step 4: Map it in `pod.rs`**

In `ldp_error`, beside `ContainmentChange`:

```rust
        // §5.4 and §4.2.1 both require the body, not just the status: a client
        // that gets a bare 409 has nothing to act on.
        LdpError::NotEmpty | LdpError::MemberMetadata => {
            (StatusCode::CONFLICT, error.to_string()).into_response()
        }
```

`error.to_string()` is the `Display` text written above, so the body and the
error have one source. That means the match has to bind `error` before moving
it — keep the arm as `ref` or reorder so `to_string()` runs on the borrow.

- [ ] **Step 5: Run it and watch it pass**

Run: `cargo test -p brolly-server --lib pod::tests`
Expected: 1 passed.

- [ ] **Step 6: Fix the two adapter tests that assert the old variant**

Run: `cargo test -p brolly-solid --test ldp_conformance`
Expected: two failures, both `assertion failed: matches!(..)`:
`a_non_empty_container_cannot_be_deleted` (`:364`) and
`a_container_with_members_cannot_be_emptied_by_put_and_then_deleted` (`:684`).
Change each `LdpError::Forbidden` to `LdpError::NotEmpty`, and update the first
one's message to say what the status now means:

```rust
    assert!(
        matches!(err, LdpError::NotEmpty),
        "deleting a populated container would orphan its subtree, and §5.4 \
         makes that a 409 rather than a refusal of access: {err:?}"
    );
```

If chunk 1 already rewrote these to `LdpError::Denied`, they fail the same way
and take the same fix.

Re-run: `cargo test -p brolly-solid --test ldp_conformance`
Expected: green.

- [ ] **Step 7: Format and stage**

```bash
cargo fmt --all
git add adapters/solid/src/ldp.rs adapters/solid/tests/ldp_conformance.rs server/src/pod.rs
```

---

### Task 5: A body with no `Content-Type` is a 400

**Files:**
- Modify: `server/src/pod.rs` (`put` at `:366`, `post` at `:399`, `patch` at
  `:432`)
- Modify: `server/tests/pod_http.rs` (a helper, and two tests)

Solid §2.1 makes this a MUST-400. Today `put` and `post` guess `text/turtle`,
which turns a client bug into stored garbage, and `patch` defaults to `""`,
falls into its `other =>` arm (`:445`) and answers 415 — the code that tells a
client its `text/n3` was unsupported, when it never said `text/n3` at all.

**The refusal comes after `resolve`.** Chunk 1 made `resolve` answer 401 for a
credential that doesn't verify, and CTS expects the challenge on every
unauthenticated method. A 400 before it would pre-empt that for anyone who
forgot a header. It discloses nothing either way, so it goes where the current
check is.

- [ ] **Step 1: Write the failing tests**

In `server/tests/pod_http.rs`, add a helper beside `send_if` (`:209`) — the
existing ones can't send a body without a `Content-Type`, because they derive
one from the body tuple:

```rust
    /// A request with a body and **no** `Content-Type`, as the owner. The
    /// tuple-shaped helpers above always send one, so §2.1 can't be tested
    /// through them.
    async fn send_untyped(
        &self,
        method: &str,
        path: &str,
        body: &str,
    ) -> (StatusCode, String, axum::http::HeaderMap) {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, HOST)
            .header(header::COOKIE, format!("brolly_session={}", self.session))
            .body(Body::from(body.to_string()))
            .unwrap();
        run(self.router.clone(), request).await
    }
```

and two tests at the end of the file:

```rust
/// Solid §2.1: a server MUST reject a PUT, POST or PATCH that contains content
/// but lacks `Content-Type`. Guessing `text/turtle` turns a client bug into
/// stored garbage that parses, and PATCH's 415 tells a client its media type
/// was unsupported when it never sent one — the wrong thing to retry.
#[tokio::test]
async fn a_body_without_a_content_type_is_refused() {
    let h = harness().await;
    for (method, path) in [
        ("PUT", "/~/note"),
        ("POST", "/~/"),
        ("PATCH", "/~/note"),
    ] {
        let (status, body, _) = h.send_untyped(method, path, NOTE).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{method}: {body}");
        assert!(
            body.to_lowercase().contains("content-type"),
            "{method}: the 400 must name the missing header: {body}",
        );
    }
    // Nothing was guessed into the pod.
    let (status, _, _) = h.send("GET", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A PATCH with a type we don't parse is still a 415: the client sent one,
    // and it is the media type that's wrong.
    let (status, _, _) = h
        .send("PATCH", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

/// §2.1's MUST is about requests that "contain content". An empty body is how
/// a client creates an empty resource, which 5a made possible, and refusing it
/// would take that away — `ldp::prepare` still needs a type to reach
/// `Content::Rdf(&[])`, so the default survives for exactly this case.
#[tokio::test]
async fn an_empty_body_without_a_content_type_creates_an_empty_resource() {
    let h = harness().await;
    let (status, body, _) = h.send_untyped("PUT", "/~/empty", "").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body, _) = h.send("GET", "/~/empty", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.trim().is_empty(), "got: {body}");

    // A container, the same way.
    let (status, body, _) = h.send_untyped("PUT", "/~/c/", "").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-server --test pod_http a_body_without_a_content_type`
Expected: fails on the first iteration, `assertion \`left == right\` failed:
PUT: left: 204 No Content, right: 400 Bad Request` — today's guess accepted it.
(`204` and not `201` only if Task 3 isn't staged yet; it is, so `201`.)

Run: `cargo test -p brolly-server --test pod_http an_empty_body_without`
Expected: passes already. Keep it: it is the regression guard for Step 3, and
its failure mode is that the fix overreaches.

- [ ] **Step 3: Implement the rule**

In `server/src/pod.rs`, add one helper above `get` (`:289`):

```rust
/// The request's `Content-Type`, or Solid §2.1's 400.
///
/// `empty_is_rdf` is true for `PUT` and `POST`, where a body with no bytes is
/// an empty RDF document — the way a client creates an empty resource (5a), and
/// the one case `ldp::prepare` still needs a default for. It is false for
/// `PATCH`: there is no empty patch, so a PATCH with no type is refused
/// whatever its length.
///
/// A header that isn't valid UTF-8 is treated as absent. It can't name a media
/// type we parse, so the alternative is a 415 for a header the client would
/// have to guess at.
fn content_type<'h>(
    headers: &'h HeaderMap,
    body: &[u8],
    empty_is_rdf: bool,
) -> Result<&'h str, Response> {
    match headers.get(header::CONTENT_TYPE).and_then(|h| h.to_str().ok()) {
        Some(value) => Ok(value),
        None if empty_is_rdf && body.is_empty() => Ok("text/turtle"),
        None => Err((
            StatusCode::BAD_REQUEST,
            "a request with a body needs a Content-Type header (Solid Protocol §2.1)",
        )
            .into_response()),
    }
}
```

Then in `put` (`:366`) and `post` (`:399`), replace the `.unwrap_or("text/turtle")`
with:

```rust
    let content_type = match content_type(&headers, &body, true) {
        Ok(value) => value,
        Err(response) => return response,
    };
```

and in `patch` (`:432`) the `.unwrap_or_default()` with the same call passing
`false`. `patch`'s existing `match content_type.split(';')…` is unchanged: its
`other =>` arm keeps its 415, which is now only reached by a type the client
actually sent.

- [ ] **Step 4: Run them and watch them pass**

Run: `cargo test -p brolly-server --test pod_http a_body_without_a_content_type`
Expected: 1 passed.

Run: `cargo test -p brolly-server --test pod_http content_type`
Expected: 2 passed.

- [ ] **Step 5: Nothing else sent a body without a type**

Run: `cargo test -p brolly-server`
Expected: green. `patch_refuses_a_body_it_cannot_parse`
(`server/tests/pod_http.rs:362-366`) sends `text/turtle` explicitly, so it keeps
its 415; `federation_flows.rs` and `mastodon_profile_flags.rs` post JSON with a
type. If anything 400s, it was relying on the guess and the test is the bug.

- [ ] **Step 6: Format and stage**

```bash
cargo fmt --all
git add server/src/pod.rs server/tests/pod_http.rs
```

---

### Task 6: The HTTP surface, the gates, and the commit

**Files:**
- Modify: `server/tests/pod_http.rs` (tests at the end of the file)

Everything below this point is behaviour already implemented; these tests pin it
where a client sees it, over the wire, rather than through `ldp`.

- [ ] **Step 1: The create response**

```rust
/// LDP and every Solid client expect 201 from a PUT that creates, and a
/// `Location` they can follow. Before 5b a create and a replace were both 204,
/// so a client had to GET to find out whether it had just made something.
#[tokio::test]
async fn a_put_that_creates_answers_201_with_a_location_and_its_kinds() {
    let h = harness().await;

    let (status, _, headers) = h
        .send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(headers[header::LOCATION], format!("{BASE}/~/note"));
    let link = headers[header::LINK].to_str().unwrap();
    assert!(link.contains("ldp#Resource"), "got: {link}");
    assert!(link.contains("rel=\"acl\""), "got: {link}");

    // The same PUT again replaced something, and says so.
    let (status, _, headers) = h
        .send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(headers.get(header::LOCATION).is_none(), "204 with a Location");
}
```

If chunk 3's `Link` set is spelled differently, assert against what it emits —
the load-bearing part is that the 201 carries the same kinds a `GET` would.

Run: `cargo test -p brolly-server --test pod_http a_put_that_creates`
Expected: 1 passed.

- [ ] **Step 2: The 409 bodies**

```rust
/// Solid Protocol §5.4 requires the status *and* a body describing the error.
/// Before 5b this was a 403, which says "you may not" when the truth is "not
/// while it has members" — a client can act on the second and not the first.
#[tokio::test]
async fn deleting_a_non_empty_container_is_a_409_that_says_what_to_do() {
    let h = harness().await;
    h.send("PUT", "/~/c/m", Some(("text/turtle", NOTE)), true)
        .await;

    let (status, body, _) = h.send("DELETE", "/~/c/", None, true).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(!body.is_empty(), "§5.4 requires a body");
    assert!(body.contains("members"), "the body must name the problem: {body}");

    // Emptying it is the way through, and the caller had the access all along.
    h.send("DELETE", "/~/c/m", None, true).await;
    let (status, _, _) = h.send("DELETE", "/~/c/", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}
```

Run: `cargo test -p brolly-server --test pod_http deleting_a_non_empty`
Expected: 1 passed.

- [ ] **Step 3: The round trip, over HTTP**

This is the one a Solid client does constantly, and the one this chunk most
risks breaking. `ldp_conformance.rs` covers it under the adapter; this covers it
through content negotiation, which is where a respelled literal comes from.

```rust
/// The read-modify-write every Solid client does on a container. Inrupt's
/// solid-client, LDO and SolidOS all GET a listing, change one triple and PUT
/// the whole thing back; §4.2.1's protection has to tolerate the echo or none
/// of them can edit a container's description at all.
#[tokio::test]
async fn a_container_listing_put_back_unchanged_is_accepted() {
    let h = harness().await;
    h.send("PUT", "/~/c/m", Some(("text/turtle", NOTE)), true)
        .await;

    for accept in ["text/turtle", "application/ld+json", "application/n-triples"] {
        let (status, listing, _) = h
            .send_if("GET", "/~/c/", None, &[("accept", accept)])
            .await;
        assert_eq!(status, StatusCode::OK, "{accept}: {listing}");
        assert!(listing.contains("modified"), "{accept}: no member metadata");

        let (status, body, _) = h
            .send("PUT", "/~/c/", Some((accept, listing.as_str())), true)
            .await;
        assert!(status.is_success(), "{accept}: the echo was refused: {body}");
    }

    // And the listing still comes from metadata rather than from what was
    // stored: the member is listed once, not twice.
    let (_, listing, _) = h
        .send_if("GET", "/~/c/", None, &[("accept", "application/n-triples")])
        .await;
    let member = format!("{ROOT}c/m");
    assert_eq!(
        listing.matches(&format!("<{member}> <http://purl.org/dc/terms/modified>")).count(),
        1,
        "an echoed statement was stored beside the generated one: {listing}",
    );
}
```

`send_if` takes an `Accept` through `extra` and a body's type through the tuple;
the PUT above reuses the negotiated type as the request's `Content-Type`, which
is what a client does.

Run: `cargo test -p brolly-server --test pod_http a_container_listing_put_back`
Expected: 1 passed.

- [ ] **Step 4: The altered listing, and the race**

```rust
/// §4.2.1's MUST. Without it a client could GET a listing, change a member's
/// modified time, PUT it back, and have the wrong number stored as content —
/// served beside the generated one, stale forever, with no way to remove it
/// except by finding it.
#[tokio::test]
async fn changing_a_members_modified_time_in_a_listing_is_a_409() {
    let h = harness().await;
    h.send("PUT", "/~/c/m", Some(("text/turtle", NOTE)), true)
        .await;
    let (_, listing, _) = h
        .send_if("GET", "/~/c/", None, &[("accept", "application/n-triples")])
        .await;
    let altered = listing.replace(
        &h.modified("/~/c/m").await,
        "1999-01-01T00:00:00.000Z",
    );
    assert_ne!(altered, listing, "setup: the listing carries the time");

    let (status, body, _) = h
        .send(
            "PUT",
            "/~/c/",
            Some(("application/n-triples", altered.as_str())),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(
        body.contains("re-read"),
        "the 409 must tell the client how to resolve it: {body}",
    );
}

/// The race §4.2.1's rule creates, which containment's set-wise rule doesn't
/// have: a member's modified time moves on *every* write to it, not only on
/// create and delete. So a client that reads a listing, saves a member, and
/// then writes the container's own description back is refused for metadata it
/// never touched — and the only thing it can do is re-read. That is why the
/// 409 carries a body and why the body says so.
#[tokio::test]
async fn a_listing_written_back_after_a_member_changed_is_a_409_the_client_re_reads() {
    let h = harness().await;
    h.send("PUT", "/~/c/m", Some(("text/turtle", NOTE)), true)
        .await;
    let (_, stale, _) = h
        .send_if("GET", "/~/c/", None, &[("accept", "text/turtle")])
        .await;

    // The client edits the member it was listing.
    h.send("PUT", "/~/c/m", Some(("text/turtle", EDITED)), true)
        .await;

    let (status, body, _) = h
        .send("PUT", "/~/c/", Some(("text/turtle", stale.as_str())), true)
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // Re-reading and retrying is the resolution, and it works.
    let (_, fresh, _) = h
        .send_if("GET", "/~/c/", None, &[("accept", "text/turtle")])
        .await;
    let (status, body, _) = h
        .send("PUT", "/~/c/", Some(("text/turtle", fresh.as_str())), true)
        .await;
    assert!(status.is_success(), "the retry was refused too: {body}");
}
```

`h.modified(path)` is a small helper beside `h.etag` (`:224`) returning the
`Last-Modified`-backed `dcterms:modified` — simplest is to read it out of the
pod directly, `h.stores.pod(h.user).unwrap().read_store().meta(&iri).unwrap()
.unwrap().modified`, so the test doesn't depend on the header format.

Run: `cargo test -p brolly-server --test pod_http changing_a_members_modified`
Run: `cargo test -p brolly-server --test pod_http a_listing_written_back_after`
Expected: 1 passed each.

- [ ] **Step 5: The whole HTTP suite**

Run: `cargo test -p brolly-server --test pod_http`
Expected: green.

- [ ] **Step 6: The gates, one suite at a time**

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
./tools/check-doc-paths.sh
cargo deny check
```

No `Cargo.toml` changed in this chunk, so `cargo deny check` is a formality —
run it anyway, it is cheap and the habit is the point.

Then the workspace's tests, which run Docker-backed Postgres and must not
overlap another run:

```bash
cargo test --workspace
```

Expected: green. Clippy is the one to expect work from: `container_body` grew,
and `too_many_lines` or `cognitive_complexity` may fire. Split out a
`member_metadata_rule(..) -> Result<Keep, LdpError>` helper rather than
`#[allow]`-ing it.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit
```

with:

```
feat(solid): 201 on create, 409 with a body, and member metadata in listings

A PUT that creates answers 201 with a Location and the Link set, not the
204 a replace gets: put_if and put_in report which happened, from the
read the precondition already makes. Deleting a populated container is
409 with the body §5.4 requires, not a 403 that says "you may not" when
the truth is "not while it has members".

A container's listing now carries each member's dcterms:modified,
stat:mtime and, for a binary, stat:size (§4.2.1), built through the same
meta() path every other reader uses — Oxigraph respells a stored
xsd:dateTime, so a listing off the raw quads would contradict the
member's own Last-Modified about one write in ten (9d58082). Those
statements are the server's: a container write drops an exact echo of
one, compared by value rather than by spelling, and answers 409 when the
value differs, so a read-modify-write still round-trips.

A PUT, POST or PATCH carrying a body with no Content-Type is 400 (§2.1),
where PUT and POST used to guess text/turtle and PATCH answered 415 for a
media type the client never sent. An empty body with no Content-Type is
still an empty RDF document, which is how a client creates an empty
resource.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
```

### Notes for the reviewer

- **`stat:size` on an RDF-source member is a 409, not content.** We serve no
  size for one, so any value a client sends differs from ours. The alternative —
  treating it as ordinary content because we happen not to serve it — would let
  a client store a `stat:size` that a later `PUT` of the same member as a binary
  would then contradict. It costs nothing: a client that echoes a listing never
  sends one.
- **A statement about the container itself is untouched.** §4.2.1 is about
  *contained* resources, and `<container> dcterms:modified` is not one. It is
  kept as ordinary content, exactly as 5a kept it.
- **`member_value` returning `None` is a 409, not a drop.** A body we couldn't
  parse is a body we couldn't check, and storing it would put an unparseable
  timestamp beside a generated one. Failing closed sends the client back to a
  re-read, which is the same resolution the race has.
- **The listing's cost.** `container_triples` now makes one `meta()` call per
  member, six indexed lookups each, on every GET of a container *and* on every
  write to one — but only once per operation, because `container_body` reuses
  the same call. `a_put_into_a_large_container_keeps_every_member`
  (`store/tests/resources.rs:1005`) is the test that would notice if a future
  change made it quadratic.
- **What this chunk deliberately did not do.** The root ACL's `DELETE` guard is
  listed under chunk 5 in the spec's Chunks section but under chunk 3's
  "`/~/` gaining the write methods so H12's rules are reachable"; it is taken as
  landed there, with `Undeletable`. If it isn't, add the guard to `delete_in`
  beside the storage-root one before Task 4 and say so in the commit.
- **Reverting.** This commit is self-contained: nothing in chunks 1–4 reads
  `Written`, `NotEmpty`, `MemberMetadata`, `modified_ms` or the `stat:` terms.
  Reverting it puts listings, `PUT` statuses and the `Content-Type` rule back to
  5a and leaves 5b's headers, refusals and caching in place.
