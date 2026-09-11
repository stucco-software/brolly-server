# Running brolly locally

Verified end to end on 2026-09-10. Every command below was run; the things that
do **not** work are called out rather than omitted.

For putting an instance on a real domain, see [deploying.md](deploying.md).

---

## Start

```fish
docker compose up -d --build
```

Then `https://brolly.local`. That is the whole setup.

No certificates to generate, no `/etc/hosts` entries, no reverse proxy to
configure. **This depends on OrbStack**, which issues a trusted certificate for
a container's declared domains — wildcards included — and proxies with the
`Host` header intact. That last part is what makes it work at all: brolly's
router branches on `Host` to tell the instance from a member's pod, so a proxy
that rewrote it would collapse every member onto the apex.

On Docker Desktop or plain Docker Engine there is no such proxy. See
*Without OrbStack* below.

---

## Why HTTPS is not optional

Two independent reasons, both deliberate, and both bite immediately over
`http://`:

- The session cookie is `Secure` (`server/src/auth.rs`), so no browser and no
  correctly-behaved client will store or return it. Login silently does
  nothing.
- Every URL the server constructs is `https://` — WebIDs, actor IRIs, the
  issuer in both OAuth metadata documents, and the `htu` a DPoP proof is
  checked against. A client arriving over `http://` computes a different `htu`,
  and every proof fails.

`BROLLY_BASE_DOMAIN` must match the domains in the compose labels for the same
reason. A mismatch fails every proof and every identity while the server
otherwise looks perfectly healthy.

## Before running the test suite

```fish
docker compose down
```

The suite provisions its own Postgres through testcontainers and competes with
this stack for the Docker daemon. On a constrained machine that produces nine
tests failing with `WaitContainer(StartupTimeout)`, which reads exactly like a
real regression and is not.

---

## Claim the instance

Registration is invite-only and invites come from an admin, so a brand new
instance has a cycle to break. It breaks itself: **on every start with zero
accounts, the server mints a single-use admin invite and logs it.**

```fish
docker compose logs brolly | grep "no accounts yet"
```

```
{"level":"WARN","fields":{"invite":"83205a57…","message":"no accounts yet — register
with this invite to claim the instance; it grants admin, is good for one use, and
is shown on every start until somebody registers"}}
```

Take the code to `https://brolly.local/register`. The account you create is an
admin. If you miss the line, `docker compose restart brolly` mints another —
they stop the moment anybody registers, and never resume.

**`admin` and `root` are reserved usernames**, along with `api`, `oauth`, `www`,
`mail`, `support` and `brolly`. A username becomes a subdomain, so the
reservation is routing rather than taste.

Registration provisions everything a member needs in one step: the pod's
storage root and owner ACL, an ActivityPub actor key, two secp256k1 keys, a
`did:plc`, and a repository with a genesis commit. Skipping any of it produces
an account that looks fine and cannot participate.

```fish
docker compose exec -T brolly brolly-admin whoami alice
```

```
username   alice
id         3118267c-fab9-4ef7-b84b-71a48fc0b67b
status     active
role       admin
webid      https://alice.brolly.local/profile#me
actor      https://alice.brolly.local/actor
did        did:plc:ylf7hczdo6omuzr2hakvpl6m
repo       bafyreig44asvrh5ykbifiltvkyxx3jwola4rrs36ztankgrv4z6sijwb7m (rev 0)
plc        pending — run `brolly-admin plc-retry`
```

`plc pending` is the normal local state. `BROLLY_PLC_SUBMIT` is `0` in compose,
so a development instance does not publish test identities to the real
directory. Identities are still minted and are valid; they simply are not
public yet (ADR 0016).

## Invite everyone else

```fish
set CODE (docker compose exec -T brolly brolly-admin invite --uses 5)
curl -s -c /tmp/jar.txt \
  -d "invite=$CODE&username=bob&email=&password=correct-horse-battery" \
  https://brolly.local/register
```

`--admin` mints a single-use invite that grants admin instead, which is how an
instance is handed to someone without also handing them the database password.
It refuses `--uses`, because a reusable admin invite is a mistake rather than an
intent.

## The admin console

`https://brolly.local/admin`, linked from the account overview when you are an
admin. It reports the member list and the two facts about an instance that were
previously only discoverable by reading the source: whether ActivityPub
federation is delivering, and whether `did:plc` operations reach the directory.

A member who is not an admin gets **404**, not 403 — a 403 would confirm the
surface exists to someone who has just been told they may not use it. So
`/admin` returning 404 while you are logged in means your account is not an
admin, not that the route is missing.

```fish
docker compose exec -T brolly brolly-admin promote bob
docker compose exec -T brolly brolly-admin demote alice
```

Both take effect on sessions that are already open — the role is resolved per
request, not cached in the cookie. `demote` refuses the last active admin, since
an instance with no admin cannot be recovered from the web at all.

---

## Poke at it

Each member is on their own host, which is what the wildcard domain is for.

```fish
# The instance
curl -s https://brolly.local/.well-known/nodeinfo
curl -s https://brolly.local/api/v2/instance
curl -s "https://brolly.local/.well-known/webfinger?resource=acct:alice@brolly.local"

# A member, on their own subdomain
curl -s -H "Accept: application/activity+json" https://alice.brolly.local/actor

# JSON all the way down, including the 404 — the P0 defect that used to hand
# clients RDF from the LDP router
curl -s https://brolly.local/api/v1/zzz
```

### Mastodon

```fish
curl -s -d "client_name=Dev&redirect_uris=urn:ietf:wg:oauth:2.0:oob&scopes=read+write+follow" \
  https://brolly.local/api/v1/apps
```

Then `/oauth/authorize` in a browser to see the consent screen, approve, and
exchange the code at `/oauth/token`. Those bare paths are Mastodon's by
ADR 0008, because its clients hardcode them. With the token:

```fish
curl -s -H "Authorization: Bearer $TOKEN" \
  https://brolly.local/api/v1/accounts/verify_credentials

curl -s -H "Authorization: Bearer $TOKEN" -d "status=hello&visibility=public" \
  https://brolly.local/api/v1/statuses
```

A post fans out through the Phase 5 delivery path — the author's outbox, local
followers' inboxes, and the server index — which is what makes it appear on
`/api/v1/timelines/public`.

### ATProtocol

XRPC is on the apex with the repo named by parameter, matching what the PLC
document advertises:

```fish
curl -s "https://brolly.local/xrpc/com.atproto.repo.describeRepo?repo=alice.brolly.local"

# The repo as a CAR — the sync primitive and the data export are the same bytes
curl -s "https://brolly.local/xrpc/com.atproto.sync.getRepo?did=alice.brolly.local" \
  -o repo.car
```

The firehose is a websocket at
`wss://brolly.local/xrpc/com.atproto.sync.subscribeRepos?cursor=0`.

### Solid

```fish
curl -s https://brolly.local/.well-known/openid-configuration
curl -s -b /tmp/jar.txt https://alice.brolly.local/~/
```

---

## Operating it

```fish
docker compose logs -f brolly           # JSON on stdout
docker compose exec -T brolly brolly-admin --help
docker compose exec -T brolly brolly-admin plc-retry --dry-run
docker compose restart brolly           # after a rebuild
docker compose down -v                  # -v drops the database and pods too
```

`RUST_LOG` is set in compose; `debug` for more.

---

## Working on the code

The image is a release build, so it is the wrong loop for iterating. Run the
server on the host against the containerised Postgres instead:

```fish
docker compose up -d postgres
env DATABASE_URL="postgres://postgres:postgres@localhost:5544/brolly" \
    BROLLY_BASE_DOMAIN="brolly.test" \
    BROLLY_DATA_DIR="/tmp/brolly-dev-data" \
    cargo run --bin brolly-server
```

Nothing about the instance is baked into the build. `BROLLY_INSTANCE_NAME` and
`BROLLY_INSTANCE_DESCRIPTION` are what make one image serve several deployments;
the name falls back to `BROLLY_BASE_DOMAIN`, which is never wrong. The full list
is in [deploying.md](deploying.md).

`BROLLY_SOURCE_URL`, `BROLLY_TERMS_URL` and `BROLLY_PRIVACY_URL` are the
footer's fine print. The first has a compiled-in default because AGPL-3.0 §13
means an instance owes its users the source; the other two simply do not render
when unset.

To see the first-run path without touching your existing data, point the server
at a database of its own:

```fish
docker compose exec -T postgres createdb -U postgres brolly_fresh
env DATABASE_URL="postgres://postgres:postgres@localhost:5544/brolly_fresh" \
    BROLLY_BASE_DOMAIN="brolly.test" BROLLY_INSTANCE_NAME="Fresh" \
    BROLLY_DATA_DIR="/tmp/brolly-fresh-data" BROLLY_PORT=3777 \
    cargo run --bin brolly-server
```

The bootstrap invite is in that server's log. `docker compose down -v` would
reach the same state for the compose stack, at the cost of every pod in it.

`brolly.test` rather than `brolly.local`, because nothing is proxying to the
host — so this is the HTTP-only surface, and the authenticated half will not
work. Reach it with an explicit `Host`:

```fish
curl -s -H "Host: brolly.test" http://localhost:3000/api/v2/instance
```

Postgres is published on 5544 so `brolly-admin` and `psql` reach it from the
host. Not 5432: a developer machine usually already has a Postgres, and
silently connecting to the wrong one is a bad afternoon.

---

## Without OrbStack

Docker Desktop and Docker Engine have no equivalent domain proxy. You need
wildcard TLS and name resolution yourself:

1. `mkcert -cert-file cert.pem -key-file key.pem "brolly.test" "*.brolly.test"`
2. A reverse proxy on 443 forwarding to the `brolly` container — Caddy's
   `reverse_proxy` with `header_up Host {host}`, which is **not** optional.
3. `/etc/hosts` lines for the apex and each member; it has no wildcard support.
4. `BROLLY_BASE_DOMAIN=brolly.test` to match.

That is the setup this document described before OrbStack replaced it, and it
worked — it is simply three moving parts instead of none.

---

## Rough edges

**`POST /outbox` cannot be reached with a browser session.** The outbox lives
on a member subdomain and is session-authenticated, but the cookie is set at
the apex without a `Domain` attribute, so it is never sent to
`alice.brolly.local`. Verified with a request trace: zero `Cookie` headers, and
the handler answers `401 log in to publish`.

The integration tests do not catch this because they inject the `Cookie` header
directly with an explicit `Host`, which sidesteps browser scoping entirely.

The obvious fix — `Domain=.brolly.local` — is probably the wrong one: it would
send every member's session cookie to every member's subdomain, and members
control content on their own subdomain. That is precisely why per-user
subdomains are usually treated as separate origins. The likelier answers are to
accept a token at `/outbox` (it already accepts Solid DPoP elsewhere), or to
publish through an apex endpoint. **A design decision, not a bug fix.**

**`target/` reached 96 GB** before a `cargo clean`. `Cargo.toml`'s
`[profile.dev.package."*"] debug = false` only strips dependency debug info;
workspace crates keep theirs, and there are ~25 test binaries. It will refill.
`debug = "line-tables-only"` on workspace crates would cap it.
