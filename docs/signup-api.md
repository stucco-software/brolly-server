# Signing people up from your own app

An instance can hand its signup to another app: your site sells or explains
the product, takes the signup, and creates the account on brolly through a
server-to-server API. brolly keeps login, consent, security settings,
connected apps and export. This is how `coop.stucco.software` (StuccoID)
works in front of `id.stucco.software`.

The reference for every variable and status code is
[deploying.md](deploying.md), under "An app in front". This page is the
walkthrough.

## What you need

- A running instance with its admin claimed. Register the first admin with
  the bootstrap invite **before** setting `BROLLY_SIGNUP_URL`. Once that's
  set, `/register` redirects to your app and the invite has nowhere to go.
- A server-side component in your app. The service token creates and deletes
  accounts, so it must never reach a browser.

## 1. Configure the instance

Generate a token (`openssl rand -hex 32`, at least 32 characters) and set it
on **both** sides:

| On brolly | Value |
|---|---|
| `BROLLY_SERVICE_TOKEN` | the token. Mounts the API at `https://<instance>/internal/v1/`. |
| `BROLLY_SIGNUP_URL` | your signup page, e.g. `https://example.org/join`. `/register` redirects there and the public signup API is switched off. |
| `BROLLY_HOME_URL` | optional: the instance's `/` redirects to your site instead of showing the login form. |
| `BROLLY_ACCOUNT_HOME` | optional: brolly's profile and delete-account pages redirect to your app. |

Set the URLs only once your app can actually create accounts. Until then,
nobody can sign up. Each URL must be absolute `http(s)`, or the server
refuses to start and logs why.

On Railway, set these as variables on the brolly-server service. The service
redeploys on save.

In your app, keep the API base and token as server-only secrets:

```
BROLLY_API=https://id.example.org/internal/v1/
BROLLY_SERVICE_TOKEN=<the same token>
```

## 2. The calls

Every request carries `Authorization: Bearer <token>`. JSON in, JSON out. A
wrong or missing token is `401 {"error": "unauthorized"}`.

### Check a username as the user types

```
GET /internal/v1/usernames/alice
→ 200 {"available": true}
→ 200 {"available": false, "reason": "reserved" | "invalid" | "taken"}
```

Usernames become subdomains (`alice.id.example.org`): 2–32 characters of
lowercase letters, digits and hyphens, not starting or ending with a hyphen.
Infrastructure names like `admin`, `www`, `mail` and `support` are reserved.
Check here rather than copying the rules into your app.

### Create the account

```
POST /internal/v1/accounts
{"username": "alice", "email": "alice@example.com", "password": "at least 12 characters"}

→ 201 {"username": "alice", "email": "alice@example.com",
       "webId": "https://alice.id.example.org/profile#me",
       "storage": "https://alice.id.example.org/"}
→ 409 {"error": "username_taken" | "email_taken"}
→ 422 {"error": "validation", "field": "username" | "email" | "password" | "body", "reason": "…"}
```

No invite is needed, whatever `BROLLY_PUBLIC_REGISTRATION` says: holding the
token is the admission. The account is a full member with a pod, an
ActivityPub actor and an ATProto identity. The `reason` on a 422 is written
for people and can go straight onto your form.

No session is created. Send the new member to log in (below).

### Log people in

Logging in happens on brolly, not through the API. Your app is a Solid-OIDC
client of the instance: register it with a Client ID Document (a public JSON
file your app serves) and send people to the instance to sign in. They type
their password on brolly's page, so your app never sees it.

A minimal client document, served at `https://example.org/client.json`:

```json
{
  "@context": ["https://www.w3.org/ns/solid/oidc-context.jsonld"],
  "client_id": "https://example.org/client.json",
  "client_name": "Example",
  "redirect_uris": ["https://example.org/auth/callback"],
  "post_logout_redirect_uris": ["https://example.org"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scope": "openid webid offline_access",
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "application_type": "web"
}
```

The issuer is `https://id.example.org`. Any Solid-OIDC library works, for
example `@inrupt/solid-client-authn-browser`. The session gives you the
member's WebID. Turn that back into an account with:

```
GET /internal/v1/accounts?webId=https%3A%2F%2Falice.id.example.org%2Fprofile%23me
→ 200 {"username", "email", "webId", "storage"}
→ 404
```

### Confirm a password before something drastic

For a "type your password to delete your account" step:

```
POST /internal/v1/accounts/alice/verify-password
{"password": "…"}
→ 204                                  correct
→ 401 {"error": "bad_credentials"}     wrong (a bad token is also 401, but says "unauthorized")
→ 429                                  past 10 attempts per username per 15 minutes
```

### Delete an account

```
DELETE /internal/v1/accounts/alice
→ 204, or 404 if there was no such account
```

This removes the account and its pod. It can't be undone.

### Password resets

brolly sends no email. Your app asks for a link and sends it:

```
POST /internal/v1/password-resets
{"email": "alice@example.com"}
→ 201 {"resetUrl": "https://id.example.org/reset?token=…", "expiresAt": "…"}
→ 204   unknown email, or a link was already issued in the last five minutes
```

Treat 201 and 204 the same way in your UI ("if that address has an account,
we've sent a link") so the form doesn't reveal who has an account. A link
works once, for an hour. Setting a new password ends all of the member's
sessions, then sends them to `BROLLY_ACCOUNT_HOME` (or `/login`).

## 3. A minimal client

StuccoID's whole integration is one server-side module. The core of it:

```js
const BASE = process.env.BROLLY_API          // https://id.example.org/internal/v1/
const TOKEN = process.env.BROLLY_SERVICE_TOKEN

async function brolly(method, path, body) {
  const res = await fetch(new URL(path, BASE), {
    method,
    headers: {
      Authorization: `Bearer ${TOKEN}`,
      Accept: 'application/json',
      ...(body && { 'Content-Type': 'application/json' })
    },
    body: body && JSON.stringify(body)
  })
  const data = res.status === 204 ? null : await res.json().catch(() => null)
  return { status: res.status, data }
}

// await brolly('GET', 'usernames/alice')
// await brolly('POST', 'accounts', { username, email, password })
```

Note there's no leading slash on the path: `new URL('accounts', BASE)` keeps
`/internal/v1/`, while `new URL('/accounts', BASE)` drops it.

## 4. Check it works

```sh
curl -H "Authorization: Bearer $BROLLY_SERVICE_TOKEN" \
  https://id.example.org/internal/v1/usernames/alice
```

`{"available": true}` means the token and the API are both live. A 404 means
the token isn't set on brolly, or you're calling a member's subdomain instead
of the instance's own host. A 401 means the two sides have different tokens.
