# 0020 — client_credentials for linked WebIDs

**Status:** Accepted (2026-11-16)

## Context

Pushbroom's collector authenticates as the agent WebID
`https://pushbroom.co/agent#it` — the CSS `client_credentials` model, because
an agent has no browser, no redirect, and no session. Its old issuer (a CSS at
`login.stucco.software`) is dead; its new one is brolly, which spoke only
`authorization_code` and `refresh_token`. Collection is down until brolly can
serve the grant, unchanged on the consumer side: discovery, then
`Authorization: Basic`, a DPoP proof, `grant_type=client_credentials&scope=webid`,
and a JWT whose `webid` claim names the linked WebID exactly — customer pods'
access control grants access to that WebID.

CSS's model has three parts: an account, a WebID linked to it (typically one
the issuer does not host, whose own document names the issuer in
`solid:oidcIssuer`), and id/secret pairs minted against the link.

## Decision

1. **The grant exists, and mints exactly the interactive grants' token shape**
   (`issue_access`, DPoP-bound, `aud: solid`), with `webid` set to the linked
   WebID and `client_id` to the credential id. No ID token, no refresh token
   (RFC 6749 §4.4.3): the credential is itself the renewal. The scope is
   `webid`, explicit or defaulted; anything else is refused as `invalid_scope`
   rather than half-honoured.

2. **Linking requires the WebID's own assertion.** The WebID's document,
   dereferenced live over the same hardened transport the remote verification
   path uses, must name this issuer in `solid:oidcIssuer`. The comparison
   ignores trailing slashes — an apex issuer is written both ways, and a
   document's spelling convention must not decide whether a token verifies.

3. **Linking is the operator's act** (`brolly-admin link-webid`), not an HTTP
   surface: there is no session an agent WebID could log in with, which is the
   reason the grant exists. A WebID this instance hosts — a member's, or the
   instance's own — cannot be linked: its issuer triple is written by this
   instance, so the dereference would always pass, and the link would let one
   account mint tokens naming another's identity.

4. **One WebID, one account; the unlink is the kill switch.** Credentials
   reference the link and cascade with it, so removing a compromised WebID's
   link retires its pairs at once rather than at the last token's expiry.

5. **Credentials are id/secret pairs, the secret stored as SHA-256** — the
   same posture as codes and refresh tokens: high-entropy values, looked up by
   hash, so a database read yields nothing usable. The token endpoint takes
   the id and the hash in one statement, so an unknown id and a wrong secret
   are the same answer — no oracle for which ids exist. Basic (RFC 7617), with
   both halves percent-encoded before the join (RFC 6749 §2.3.1), is the one
   accepted auth method for this grant.

6. **The operator path is the CLI** (`agent-account`, `link-webid`,
   `agent-credentials`), because the handle `pushbroom` is on the front end's
   reserved list and cannot be created through signup or the service API. The
   account is the same substance every signup gets — `provision::account`,
   shared with the web signup path — with a generated password printed once.

A registration-token check like CSS's `solid:oidcIssuerRegistrationToken` was
considered and left out: the issuer triple is the required minimum, and the
operator gate (linking is CLI-only) already stands where the token would.

## Consequences

- Discovery advertises `client_credentials` and `client_secret_basic` (beside
  `none`, which the public clients keep). The minted pairs are the only
  clients with secrets, and the only ones using Basic.
- Cross-instance verification of these tokens works through the existing
  remote path unchanged: the token's `iss` fetches our discovery and key set,
  and the WebID's document — the same triple the link checked — binds it.
  The pushbroom document must therefore name `https://id.stucco.software`
  (slash or not) for cross-pod access, not the dead `login.` issuer.
- Multiple pairs may be minted for one WebID (rotation by minting); retiring
  them all at once is the unlink. Per-pair revocation is not built.
- `names()`' slash tolerance applies to the remote verification path too — a
  widening, not a change: exact spellings still match.
