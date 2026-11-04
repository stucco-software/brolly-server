# 0019 — The owner always has full access

**Status:** Accepted (2026-11-03)
**Scopes:** stage 0 (A2, an ACL needs Control), spec 5b (H1, H4, H9), spec 5d
(H2), spec 6 (H5, the remote path).

## Context

In production a member, `nikolas`, got 403 on
`PUT /~/thoughtloom-sites/stucco-works/index.html` from a Solid app logged
in as nikolas. The likely cause: a folder `.acl` written to make a site
public named the world and left the member out. Its `acl:default` carried
that to everything inside the folder, so by WAC the member could read their
own site like any stranger and do nothing else.

WAC has no owner rule. `ldp::check` and `ldp::granted_modes` evaluate the
nearest ACL and nothing else, so an ACL that forgets the owner locks them
out. The lockout also can't be undone through the protocol, because
rewriting an `.acl` needs `acl:Control` on what it governs (stage 0, A2),
which is the mode the owner just lost. The only fix was an operator editing
the store directly.

The Community Solid Server has the precedent: its `OwnerPermissionReader`
gives a pod's owner `acl:Control` on everything in the pod, so they can
always repair an ACL. That is enough to recover, but it leaves the owner
needing a second write to get back into their own storage, and it still
lets a client reasonably believe it may restrict the member. The operator
chose to go further on purpose.

## Decision

**A pod's owner holds Read, Write, Append and Control on every resource in
their own pod, whatever the ACLs say.** That covers every document,
container, `.acl` and `.meta` under the storage root `/~/`.

**The owner** is a `Subject` that both:

- was authenticated **by this instance**, so `user_id` is `Some`. That means
  a session, our own Solid-OIDC DPoP token, a Mastodon token, or ATProto. A
  remote-issuer subject (`Subject::remote`, `user_id: None`) is never the
  owner, *even when it names a local WebID*. The issuer binding already
  refuses such a token, because our profiles name only this instance as
  `solid:oidcIssuer`. This rule is the second wall behind that one, so a
  regression in the binding would leave WAC in charge and could not hand
  out full control.
- has exactly the pod's own WebID, `https://<user>.<base>/profile#me`. That
  is `identity::webid::webid_at(base)`, the same derivation `webid::webid`
  uses to mint the subject's WebID. It is an exact string comparison, so near
  misses (another fragment, a nested subdomain, `http:`) do not count.

The predicate is `Subject::owns(pod_origin)` in `identity/src/subject.rs`.
It is applied in exactly one module, `adapters/solid/src/ldp.rs`, through a
private `owner(base, path, subject)`. That function also requires the path to
be inside `/~/`. It is consulted first by `check` and `granted_modes`, the
only two functions in the tree that call `brolly_authz::authorize` or
`effective_acl`. Every surface that decides access to pod content goes
through them:

- the LDP operations
- `OPTIONS`, `Allow` and `WAC-Allow`, via `describe_in`
- the profile page's depiction check
- Mastodon's media upload (`put_in`)

So no surface can grant the owner a mode that another refuses. The rule
stays in the Solid adapter rather than in `brolly-authz` because `authz`
sees an `Agent` (a WebID or nobody), and the rule needs to know whether
this instance authenticated the caller. Only a `Subject` knows that.

The bypass is reported truthfully. The `user=` component of `WAC-Allow`
names all four modes for the owner, and `Allow` follows. `public=` is
unchanged, because it describes an anonymous caller, and an anonymous
caller is never the owner.

## Consequences

- **An ACL can no longer restrict the owner.** A member can't use an ACL to
  make something read-only to themselves, and an app can't lock its user out
  of anything. A member who wants protection against their own apps needs a
  different mechanism, such as consent scopes, not WAC.
- Lockouts like nikolas's are fixed without a data migration. The broken
  `.acl` stays as it is and stops mattering to the owner, who can now read
  and rewrite it.
- `WAC-Allow` on any resource in the owner's own pod now reads
  `user="read write append control"`. Tests that pinned the owner's
  ACL-derived modes (`"read write append"` under the harness's root ACL)
  now pin the owner's full set.
- A pod whose ACLs cannot be evaluated (a store error) answers the owner
  without consulting them. The owner is the one caller who can repair it.
- Nothing changes for anyone else. Another member, an anonymous caller, and
  a remote WebID each hold exactly what WAC grants them. A remote subject
  naming the owner's WebID included: `server/tests/solid_token_access.rs`
  stubs a foreign issuer bound to the owner's WebID and shows it gets Read
  from a public ACL and a 403 on `PUT`.
- The undeletable storage root and root ACL (Solid Protocol §5.4) stay
  undeletable. That refusal is about the resource, not about access, and the
  owner gets 405 as before.
