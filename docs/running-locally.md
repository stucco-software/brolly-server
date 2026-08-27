# Running brolly locally

Verified end to end on 2026-08-27 against the commit that closed Phase 7.
Every command below was run; the things that do **not** work are called out
rather than omitted.

---

## The one thing that will surprise you

**You cannot exercise the authenticated surface over plain HTTP.** Two
independent reasons, both deliberate:

- The session cookie is `Secure` (`server/src/auth.rs`), so no browser and no
  correctly-behaved HTTP client will store or return it over `http://`.
- Every URL the server constructs is `https://` — WebIDs, actor IRIs, the
  issuer in both OAuth metadata documents, and the `htu` a DPoP proof is
  checked against. A client that reaches the server over `http://` computes a
  different `htu` and every proof fails.

So local work splits in two:

| Surface | Needs TLS? |
|---|---|
| NodeInfo, WebFinger, actor documents, instance metadata, OAuth discovery, public timeline, unknown-path 404s | **No** — `curl` against `localhost:3000` with a `Host:` header is enough |
| Login, the dashboard, all three OAuth flows, Mastodon writes, XRPC writes, anything token-bound | **Yes** |

---

## 1. Postgres

There is no `docker-compose.yml` in this repo. The test suite provisions its
own Postgres through testcontainers, so nothing needed one until now.

```bash
docker run -d --name brolly-dev-pg \
  -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=brolly \
  -p 5544:5432 postgres:16
```

Port 5544 to stay clear of anything already on 5432. Migrations run on boot, so
there is no separate migrate step.

## 2. The server

```bash
cd brolly-server
DATABASE_URL="postgres://postgres:postgres@localhost:5544/brolly" \
BROLLY_BASE_DOMAIN="brolly.test" \
BROLLY_DATA_DIR="/tmp/brolly-dev-data" \
BROLLY_PORT=3000 \
cargo run --bin brolly-server
```

Logs are JSON on stdout. `RUST_LOG=debug` for more; the default is `info`.

First boot creates the Solid provider signing key and the instance actor, both
of which persist and are never regenerated.

## 3. Check the unauthenticated surface

No TLS needed. The `Host` header is what selects apex versus member subdomain —
the router branches on it, so getting it wrong silently gives you a different
answer.

```bash
curl -s -H "Host: brolly.test" http://localhost:3000/.well-known/nodeinfo
curl -s -H "Host: brolly.test" http://localhost:3000/api/v2/instance
curl -s -H "Host: brolly.test" http://localhost:3000/.well-known/oauth-authorization-server
curl -s -H "Host: brolly.test" http://localhost:3000/.well-known/openid-configuration

# JSON all the way down, including the 404 — this is the P0 defect that used to
# hand clients RDF from the LDP router.
curl -s -H "Host: brolly.test" http://localhost:3000/api/v1/zzz
```

## 4. Make an invite

The instance is invite-only and **there is no CLI to mint an invite**. Codes
are stored as `sha256` hex, so this goes in by hand:

```bash
HASH=$(printf 'devinvite' | shasum -a 256 | cut -d' ' -f1)
docker exec brolly-dev-pg psql -U postgres -d brolly \
  -c "INSERT INTO invites (code_hash, max_uses) VALUES ('$HASH', 10)"
```

The code is then `devinvite`. See *Rough edges* below.

## 5. TLS, for everything else

`mkcert` issues a locally-trusted wildcard; Caddy terminates and forwards to
the server with the original `Host` preserved — which the router depends on.

```bash
mkdir -p /tmp/brolly-tls && cd /tmp/brolly-tls
mkcert -cert-file cert.pem -key-file key.pem "brolly.test" "*.brolly.test"

cat > Caddyfile <<'EOF'
{
	auto_https off
	admin off
}
:443 {
	tls /tls/cert.pem /tls/key.pem
	reverse_proxy host.docker.internal:3000 {
		header_up Host {host}
	}
}
EOF

docker run -d --name brolly-dev-tls -p 8443:443 \
  -v /tmp/brolly-tls:/tls:ro \
  -v /tmp/brolly-tls/Caddyfile:/etc/caddy/Caddyfile:ro \
  caddy:2
```

`header_up Host {host}` is not optional. Without it the proxy rewrites the
`Host` and every member subdomain resolves to the apex.

### Resolving the names

For `curl`, `--resolve` avoids touching DNS:

```bash
CA="$(mkcert -CAROOT)/rootCA.pem"
curl --cacert "$CA" --resolve "brolly.test:8443:127.0.0.1" https://brolly.test:8443/...
```

Note `--resolve` takes **one** host per flag; repeat it, and it cannot be
folded into a shell variable alongside `--cacert` (curl parses the combined
string as a single option and fails).

For a browser, add the hosts you need to `/etc/hosts` — it has no wildcard
support, so one line per member:

```
127.0.0.1 brolly.test alice.brolly.test bob.brolly.test
```

Then browse `https://brolly.test:8443`. mkcert has already installed its root
in the system trust store, so there is no warning to click through.

## 6. Register and log in

```bash
CA="$(mkcert -CAROOT)/rootCA.pem"
curl -s --cacert "$CA" --resolve "brolly.test:8443:127.0.0.1" \
  -c /tmp/jar.txt \
  -d "invite=devinvite&username=alice&email=&password=correct-horse-battery" \
  https://brolly.test:8443/register

# 200 means the session stuck.
curl -s -o /dev/null -w "%{http_code}\n" --cacert "$CA" \
  --resolve "brolly.test:8443:127.0.0.1" -b /tmp/jar.txt \
  https://brolly.test:8443/account/profile
```

Registration provisions the pod's storage root and the owner ACL. Without that
the member's first write is refused by WAC, which is what the
`registering_provisions_a_pod_the_member_can_write_to` test pins.

## 7. Drive the Mastodon API

```bash
# Register an app (returns client_id and the only sight of client_secret)
curl -s --cacert "$CA" --resolve "brolly.test:8443:127.0.0.1" \
  -d "client_name=Dev&redirect_uris=urn:ietf:wg:oauth:2.0:oob&scopes=read+write+follow" \
  https://brolly.test:8443/api/v1/apps
```

Then `/oauth/authorize` in a browser (it renders the consent screen), approve,
and exchange the code at `/oauth/token`. The bare paths are Mastodon's by
ADR 0008, because its clients hardcode them.

With the bearer token:

```bash
curl -s --cacert "$CA" --resolve "brolly.test:8443:127.0.0.1" \
  -H "Authorization: Bearer $TOKEN" \
  https://brolly.test:8443/api/v1/accounts/verify_credentials

curl -s --cacert "$CA" --resolve "brolly.test:8443:127.0.0.1" \
  -H "Authorization: Bearer $TOKEN" \
  -d "status=hello&visibility=public" \
  https://brolly.test:8443/api/v1/statuses
```

That post fans out through the Phase 5 delivery path, so it lands in the
author's outbox, in local followers' inboxes, and in the server index — which
is what makes it appear on `/api/v1/timelines/public`.

## 8. Drive ATProtocol

XRPC lives on the **apex** with the repo named by parameter, matching what the
PLC document advertises:

```bash
curl -s --cacert "$CA" --resolve "brolly.test:8443:127.0.0.1" \
  "https://brolly.test:8443/xrpc/com.atproto.repo.describeRepo?repo=alice.brolly.test"

# The repo as a CAR — the sync primitive and the data export, same bytes
curl -s --cacert "$CA" --resolve "brolly.test:8443:127.0.0.1" \
  "https://brolly.test:8443/xrpc/com.atproto.sync.getRepo?did=alice.brolly.test" \
  -o /tmp/repo.car
```

Writes need either a session or a DPoP-bound ATProto token, and a repo has to
exist first — see *Rough edges*.

The firehose is a websocket:

```
wss://brolly.test:8443/xrpc/com.atproto.sync.subscribeRepos?cursor=0
```

## 9. Tear down

```bash
docker rm -f brolly-dev-pg brolly-dev-tls
rm -rf /tmp/brolly-dev-data /tmp/brolly-tls
```

The data directory holds every pod, its blobs and its repo blocks. Deleting it
is the whole reset.

---

## Rough edges

Found by actually doing this. None are blockers for reading the code; all of
them are friction for exercising it.

**1. `POST /outbox` cannot be reached with a browser session.**
The outbox lives on a member subdomain and is session-authenticated, but the
session cookie is set at the apex without a `Domain` attribute, so it is never
sent to `alice.brolly.test`. Verified with a request trace: zero `Cookie`
headers, and the handler answers `401 log in to publish`.

The integration tests do not catch this because they inject the `Cookie` header
directly with an explicit `Host`, which sidesteps browser scoping entirely.

The obvious fix — `Domain=.brolly.test` — is probably the wrong one: it would
send every member's session cookie to every member's subdomain, and members
control content on their own subdomain. That is precisely why per-user
subdomains are usually treated as separate origins. The likelier answers are to
accept a token at `/outbox` (it already accepts Solid DPoP elsewhere), or to
publish through an apex endpoint. **This is a design decision, not a bug fix.**

**2. There is no way to create an invite except SQL.**
Invite-only is enforced, and nothing mints codes. A `tools/` command would make
the first five minutes of local setup much less strange.

**3. There is no way to provision an ATProtocol repo except code.**
Registration creates the pod and its ACL, but not the secp256k1 signing key,
the `did:plc`, or the genesis commit — so XRPC writes fail on a freshly
registered member. Every piece exists (`adapters/atproto/src/keys.rs`,
`plc.rs`, `repo.rs`, `identity.rs`); nothing calls them at signup.

**4. No `docker-compose.yml`.** Tests bring their own Postgres via
testcontainers, so nothing needed one, but running the server does.

**5. `target/` reached 96 GB** before a `cargo clean`. `Cargo.toml`'s
`[profile.dev.package."*"] debug = false` only strips dependency debug info;
workspace crates keep theirs, and there are ~25 test binaries. It will refill.
`debug = "line-tables-only"` on workspace crates would cap it.
