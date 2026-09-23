# Deploying an instance

One image, many instances. Everything that differs between `brolly.id`, a Solid
provider on somebody else's domain, and a community on a subdomain is an
environment variable. Nothing is baked into the build.

For running it on your laptop instead, see [running-locally.md](running-locally.md).

## The two hard requirements

Both of these are load-bearing, and both fail in ways that look like something
else. Read them before provisioning anything.

### 1. A wildcard domain, with the `Host` header intact

Every member lives on their own host. `alice` on an instance based at
`example.org` is `alice.example.org`, and that hostname is how the router tells
a member's pod from the instance itself. So you need **both**:

```
example.org        A/CNAME → the service
*.example.org      A/CNAME → the same service
```

and a wildcard TLS certificate covering `*.example.org`.

A proxy that rewrites or drops `Host` collapses every member onto the apex — the
server will start, serve the landing page, and be quietly broken for every
account on it. Verify with an explicit header before trusting it:

```fish
curl -s -o /dev/null -w "%{http_code}\n" https://alice.example.org/actor
```

**A wildcard certificate covers one level only.** `*.brolly.community` covers
`acme.brolly.community` but *not* `alice.acme.brolly.community`. An instance
based at `acme.brolly.community` therefore needs its own
`*.acme.brolly.community` certificate, per community.

### 2. A persistent volume

Pods are RocksDB stores on disk, not rows in Postgres. `BROLLY_DATA_DIR` —
`/var/lib/brolly` in the image — must be a real volume. A container that
restarts onto empty storage has lost every member's data while Postgres still
insists the accounts exist, which is a worse failure than losing both.

Postgres holds operational state only: users, sessions, invites, OAuth,
repository heads, the PLC log.

## Configuration

| Variable | Required | Default | Notes |
|---|---|---|---|
| `DATABASE_URL` | **yes** | — | Postgres. Migrations run at startup. |
| `BROLLY_BASE_DOMAIN` | **yes** | `brolly.test` | The apex. Baked into every WebID, DID document, actor IRI, OAuth issuer and DPoP `htu`. |
| `BROLLY_INSTANCE_NAME` | no | the base domain | What the instance calls itself in titles and headings. |
| `BROLLY_INSTANCE_DESCRIPTION` | no | `A private community server.` | One line, shown by Mastodon clients. |
| `BROLLY_SOURCE_URL` | no | the upstream repository | Where this instance's source can be obtained. AGPL-3.0 §13 — point it at your fork if you run one. |
| `BROLLY_TERMS_URL` | no | — | Linked in the footer and on the door. Omitted entirely when unset. |
| `BROLLY_PRIVACY_URL` | no | — | Same. |
| `BROLLY_DATA_DIR` | no | `/var/lib/brolly` in the image | Must be the volume mount. |
| `BROLLY_PORT` | no | `3000` | |
| `BROLLY_STATIC_DIR` | no | `/srv/static` in the image | |
| `BROLLY_PLC_SUBMIT` | no | off | `1` publishes `did:plc` operations to the real directory. |
| `RUST_LOG` | no | `info` | JSON on stdout. |

### `BROLLY_BASE_DOMAIN` is effectively permanent

It is not a display setting. Every identity the instance has ever minted embeds
it, so changing it after members exist orphans all of them: their WebIDs stop
resolving, their DID documents point at a host that no longer serves them, and
every issued token fails its audience check. Decide it before the first
registration, not after.

### `BROLLY_PLC_SUBMIT`

Leave it off until the instance is reachable at its real hostname. Identities
are still minted and held locally; `brolly-admin plc-retry` submits them once
the directory can verify the domain. Publishing a `did:plc` that points at a
host you do not control yet is not easily undone.

This is the only ATProtocol behaviour that is gated. Everything else — keys,
DIDs, repositories, XRPC, the firehose — is unconditional by ADR 0016.

## Claiming a new instance

Registration is invite-only and invites come from an admin, so a brand new
instance has a cycle to break. It breaks itself:

**On every start with zero accounts, the server mints a single-use admin invite
and logs it at `warn`.**

```
{"level":"WARN","fields":{"invite":"a9d8ce…","message":"no accounts yet — register
with this invite to claim the instance; it grants admin, is good for one use, and
is shown on every start until somebody registers"}}
```

Copy the code, open `https://<your-domain>/register`, and use it. The account
you create is an admin, and the console is at `/admin`.

If you miss the line, restart — a new one is minted every start until somebody
registers, and then never again.

**`admin` and `root` are reserved usernames**, along with `api`, `oauth`, `www`,
`mail`, `support` and `brolly`. Usernames become subdomains, so the reservation
is routing, not taste. Pick a real name.

### Afterwards

```fish
brolly-admin invite --uses 5            # ordinary invites
brolly-admin invite --admin             # hands someone else the instance
brolly-admin promote <username>
brolly-admin demote <username>          # refuses the last active admin
```

`brolly-admin invite --admin` is the one to reach for when handing an instance
to an operator who should not also have the database password: it is a one-time
credential that is spent on redemption, which a `DATABASE_URL` never is.

## Deploying on Railway

Railway supports wildcard custom domains and volumes, which is both hard
requirements met.

1. **Postgres**: add the managed database, and point `DATABASE_URL` at it with a
   reference variable — `${{Postgres.DATABASE_URL}}`.
2. **Service**: deploy this repository. The `Dockerfile` is a release build and
   is what you want; it produces both binaries.
3. **Volume**: mount one at `/var/lib/brolly`. Do this *before* the first boot —
   adding it later starts the instance over.
4. **Domains**: add both the apex and the wildcard as custom domains on the
   service, each targeting port 3000. Railway terminates TLS and forwards `Host`
   unchanged.
5. **Variables**: `BROLLY_BASE_DOMAIN` must match the domains exactly.
6. **Claim it**: read the bootstrap invite out of the deploy logs and register.

`brolly-admin` runs as a one-off command against the same environment, so the
CLI is available without a shell on the container.

## Upgrading

### Stage 5a (resource metadata): snapshot first, forward-only

From stage 5a on, each pod records what the server knows about its resources
(whether each one exists, its container, its version and its binary) in a
graph of its own, where no client write can reach it. A pod upgrades itself
the first time the server opens it after the deploy. There's no command to run,
and new pods start on the new layout.

**This is the first change that redeploying the old image can't undo.** The
upgrade moves containment out of each container's own graph, and the old code
reads it only from there. So:

1. **Snapshot the data volume before you deploy.** On Railway, back up the
   service's volume. With docker compose, stop the server and copy the data
   directory (`/var/lib/brolly` in the image, or wherever `BROLLY_DATA_DIR`
   points).
2. Deploy. Pods upgrade as members use them.
3. **To go back, restore the snapshot**, then deploy the old image. Anything
   written after the snapshot is lost.

If the upgrade can't find a pod's storage root, it writes nothing, leaves the
pod as it was and logs at `error`. That pod's LDP reads then answer 404. Only a
pod that was never provisioned can get there.

`brolly-admin acl-uncontain` is gone. The upgrade never lists an `.acl` as a
member, so a pod that was never swept needs nothing more.

### Activities stored before `865cc98`

From `865cc98` on, the server chooses the id of every object a member
publishes, and a `Delete` can only remove a graph that arrived embedded in one
of its author's own activities. Activities stored before that commit may embed
object ids the client chose. If one of them embeds a member's own LDP resource,
such as their `/~/.acl`, that member's own `Delete` can still remove it without
a WAC check.

Nobody else can reach it: removal still requires the target and the stored
activity to be on the deleting member's own origin. So this only matters on an
instance where someone already tried the hole on their own account, and no
data migration is shipped for it.

### ATProto OAuth requests pushed before `f2f1982`

From `f2f1982` on, a pushed authorization request is only accepted if the
client's metadata declares its `redirect_uri` and scope. Requests pushed before
the upgrade were never checked, and one can still be approved for up to five
minutes after the deploy, which is how long a pushed request lives. Nothing
needs doing: they expire on their own.

## Before pointing a live domain at it

- **`FEDERATION_ENABLED` is `false`.** ActivityPub delivery to remote inboxes is
  off (`adapters/activitypub/src/federation.rs`, ADR 0016). Local delivery works
  and every member has a full identity. Solid and ATProtocol are unaffected —
  this gate is ActivityPub-only. Flipping it is a one-line commit and a redeploy.
- **The typeface is a trial licence.** `server/static/fonts/` ships
  `SerrifCondensed-TRIAL-*`, copied from the marketing site. Fine for a private
  instance; a public deployment needs the licensed cut, and the `@font-face`
  block in `server/static/brolly.css` names the files.
- **There is no email path.** Password reset is not wired to anything, so an
  account whose password is lost needs `brolly-admin` and a database.
