# Octothorpes relay: a brolly instance as an OP server

<!-- doc-paths: skip -->
<!-- The spec names a crate, store and routes this work creates, and cites
     files in the sibling octothorp.es repository. -->

**Status:** Drafted 2026-11-19. Brainstormed with the operator the same day;
the decisions taken are recorded under Decisions.
**Scope:** Umbrella. It sets the finish line and orders the work into five
stages. Each stage gets its own plan.
**Reference implementation:** the `octothorpes` npm package
(`octothorp.es/packages/core`) and the SvelteKit relay around it
(`octothorp.es/src/routes`). Where this spec and the JS disagree on protocol
behaviour, the JS wins and this spec is wrong.

## Problem

An Octothorpe Protocol (OP) relay indexes pages on independent websites —
their hashtags ("octothorpes"), links, bookmarks and webrings — and answers
queries about them over `/get/[what]/[by]/[[as]]`. Today the only relay is
octothorp.es: SvelteKit plus a standalone Oxigraph. brolly-server already runs
Oxigraph, already has an admin console, a hardened public-only fetcher and an
instance-config model. A brolly instance should be able to serve as an OP
relay without a second deployment.

## Finish line

Done when:

1. octothorp.es's `npm run api-smoketest`, run against a deployed relay host
   on a real domain (`tags.brolly.id`), reports **zero errors and zero 5xx**
   across all five sections (`shared`, `grammar`, `negative`, `match`,
   `publishers`).
2. The same api-smoketest runs green in brolly's CI against a fresh container.
3. Every oracle fixture passes (see Testing): each vendored harmonizer and
   handler produces the JS core's output on the fixture documents.

Order: CI (2, 3) goes green with the relay enabled in tests; the constant
`OP_RELAY_ENABLED` flips (see Gating); the build deploys with
`BROLLY_OP_HOST=tags.brolly.id`; then (1) runs against it. If (1) fails, the
flip is reverted. Flipping is low-risk on its own: no instance serves a relay
until its operator also sets `BROLLY_OP_HOST`. `empty` rows are acceptable
everywhere; only errors and 5xx fail.

**Accepted gap: the golden indexing smoketest.** octothorp.es's
`smoketest.js` needs direct SPARQL access, to pass its preflight and to
insert verified origins. `production-smoke.js` is HTTP-only but compares
against production's goldens. `golden/smoke/profile-resolved.json` pins
octothorp.es's own identity, which an unbranded instance can't reproduce. The
operator chose (2026-11-19) not to build a harness or expose SPARQL. Content
parity rests on the oracle fixtures and integration tests, and API-surface
parity on the api-smoketest.

**Out of scope:** the relay's HTML UI (`~/[thorpe]` pages, domain and webring
browsers, docs, ethos, flyer), the public `/register` form and its email
verification, the JS `/admin` (replaced by brolly's console), RDFa
extraction, and importing an existing octothorp.es store.

## Decisions

- **D-OP1. Native Rust, as a brolly adapter.** `adapters/octothorpes`
  (`brolly-octothorpes`), free to depend on `brolly-domain` and `brolly-store`
  like the other adapters. Not a standalone reusable crate.
- **D-OP2. Port the logic, vendor the data, leave octothorp.es untouched.**
  Everything the JS core already expresses as data is vendored at a pinned
  octothorp.es commit. The grammar tables the JS still expresses as code are
  hand-mirrored in Rust. No upstream changes are made to make the port easier.
- **D-OP3. A dedicated relay store.** Not pods (member data only) and not the
  server-agent store (pointers and filter keys only, D5).
- **D-OP4. Its own host.** Configured by `BROLLY_OP_HOST`, e.g.
  `tags.brolly.id`. OP's paths collide with pod storage (`/~/`) and the WebID
  document (`/profile`); a separate host gives exact path parity instead.
- **D-OP5. Policies are editable in the admin console**, stored in Postgres.
  Config enables the relay and seeds defaults; the console owns them after.
- **D-OP6. No RDFa.** Harmonizers read HTML through selectors; that's enough.
- **D-OP7. No golden-smoketest parity.** No SPARQL endpoint and no brolly-side
  harness. See the accepted gap under Finish line.

## Architecture

### Crates and files

- `adapters/octothorpes/` — the protocol: grammar, `Sparql` facade, handler
  registry, harmonizer engine, indexer, deleter, reifier, query builders,
  publishers, profile resolution. No HTTP framework types.
- `adapters/octothorpes/vendor/` — the shared contract, at a pinned commit
  recorded in `vendor/SOURCE`:
  - `harmonizers/*.json` (default, ghost, keywords, openGraph, rss,
    schema-org, standardSite, vevent)
  - `profile.schema.json`, `harmonizer.schema.json`, `ld/context.json`
  - `publishers/*/resolver.json`
  - **rendered, not copied:** the SPARQL prefixes (`ld/prefixes.js` exports a
    string) and the vocabulary as ttl and jsonld (generated from
    `vocabulary.js` by route handlers in the JS). The vendor script runs the JS
    to emit them as files.
  - `oracle/` — expected outputs recorded from the JS core (see Testing)
- `tools/vendor-octothorpes.sh` — refreshes `vendor/` from a given
  octothorp.es commit, renders the generated files, and re-records the oracle
  outputs. The only place Node runs; never in brolly's build or runtime.
- `server/src/octothorpes.rs` — axum handlers, the host guard, `/profile.json`
  assembly.
- `server/src/admin.rs` + `server/templates/admin/relay/` — the Relay tab.

### Hand-mirrored tables

`linkTypes.js`, and `apiGrammar.js`'s `WHAT_GROUPS`, `GET_PARAMS` and
`MATCH_VALUES`, become Rust constants. Each carries a comment naming its JS
source file and the pinned commit. The api-smoketest's `grammar` section is
the drift alarm: it walks every `what × by` and `as` the target advertises.

### Gating

- `BROLLY_OP_HOST` unset: no relay, no routes, no relay store opened, no Relay
  tab.
- `BROLLY_OP_HOST` set: the relay answers on that host. If the host is a
  subdomain of the apex, its label is reserved:
  - `RESERVED_USERNAMES` is a `const` behind a stateless
    `is_reserved_username(&str)` (`server/src/auth.rs`). It becomes a check
    that also takes the configured relay label, threaded through every caller:
    signup, `internal_api.rs`, and the `brolly-admin` CLI.
  - If a member already owns the label, startup refuses with an error naming
    the conflict, rather than shadowing their pod.
- **Changing `BROLLY_OP_HOST` orphans the relay store.** Term IRIs and
  term-ban keys embed the instance origin. A host change means wipe and
  re-crawl; the operator docs say so.
- Until the finish line, everything is additionally dormant behind
  `pub const OP_RELAY_ENABLED: bool = false` in `brolly-octothorpes`, the
  `FEDERATION_ENABLED` pattern. Tests construct the router with the relay
  enabled.

### Host guard

A layer in front of brolly's router matches the request host against
`BROLLY_OP_HOST`. On the relay host only the OP router answers; pod storage,
`/profile`, XRPC, OAuth and the door are unreachable. Off the relay host, no
OP path answers. OP paths are served verbatim (`/~/[thorpe]/rss`,
`/profile.json`, `/get/…`, `/index`).

### Outbound fetches

The adapter can't depend on `server`, and client metadata's `Fetcher` is the
wrong shape for crawling: HTTPS-only, a 64 KiB cap, a 5 s timeout, a response
cache, and generic over a single `Document`. So:

- **Interface.** `brolly-octothorpes` defines a `PageFetcher` trait:
  `fetch(url) -> Result<Fetched { final_url, status, content_type, headers,
  body }, FetchError>`. The indexer and the remote-harmonizer loader take it
  as a dependency, and tests pass a fake.
- **Implementation.** It lives in `server/src/octothorpes.rs`, on its own
  `reqwest::Client` built with the same `PublicOnly` resolver (proxies off,
  IP literals refused). `PublicOnly` is already `pub`; it's reused, not
  copied.
- **Differences from client metadata:**
  - http and https, both still bounded by `allows.schemes`
  - redirects followed manually, each hop re-checked against `PublicOnly`,
    at most 5 hops
  - a 5 MiB body cap and a 10 s timeout, constants in the adapter
  - **no response cache**: `cooldown` and re-indexing need fresh fetches
- **Tests** use a loopback-permitting constructor, as client metadata's do.

## Storage and state

| State | Where | Why |
|---|---|---|
| Indexed pages, terms, mentions, webrings, aliases, `octo:indexed` timestamps | relay store, default graph | protocol data; queried by the ported SPARQL |
| Verified, banned origins; banned terms | relay store, default graph | the gates and query builders `ASK` against them; one source of truth with the console |
| `policies` | Postgres, `op_policies` (one JSONB row) | instance administration, edited live |
| Per-origin request rate limit, remote-harmonizer cache | memory | ephemeral, as in the JS |

### Relay store

`StoreManager` opens one more Oxigraph store at `<data>/relay/`, next to
`users/<uuid>` and `instance/`, when the relay is enabled. Its rule, stated in
the module docs as D5 is for the instance store: **public, third-party, rebuildable by re-crawl; holds no member data.**
Deleting the directory and re-indexing is a supported operation.

All writes go to the default graph, as the JS does. Every page's writes —
statements, deleter reconciliation, alias changes, the `octo:indexed` stamp —
commit in one Oxigraph transaction.

### `Sparql` facade

Three calls with the JS `sparqlClient` shape: `query_array`, `query_boolean`,
`update`. It prepends the vendored prefixes, runs in-process, and returns
SPARQL-JSON-shaped results, so the ported query builders read like their JS
sources.

**No string-built IRIs.** The JS interpolates raw URLs into SPARQL
(`<${url}>`). The port accepts only validated IRI values (`NamedNode` /
`brolly-domain::iri`) and escaped literals at every interpolation point.
Crawled content can't inject SPARQL. The JS's class IRIs, such as
`<octo:Origin>`, are absolute IRIs with the scheme `octo`, so they pass
validation and the stored data stays identical to the JS's.

### Policies

`op_policies` holds the `policies` object: `commercial`, `labels`,
`indexing.{mode, cooldown, deletion, maxBatchSize}`,
`access.{registration, submissions, badge, blocks.{domains, terms},
allows.{domains, terms, schemes}, endorsement.sources}`. Every save validates
against the vendored `profile.schema.json`. First enable seeds the schema
defaults.

### `/profile.json`

Assembled per request, in the shape of `profile.schema.json`:
- `identity` from instance config: the relay host, `BROLLY_INSTANCE_NAME`,
  `BROLLY_INSTANCE_DESCRIPTION`. Optional identity fields with no brolly
  config (contact, social handles, feeds, images, rules) are omitted, not
  invented. No hardcoded OP or brolly branding.
- `policies` from `op_policies`.
- `api.routes`, `api.linkTypes`, `api.documentRecord`,
  `api.publishers.available`, `api.harmonizers.available` and
  `api.handlers.available`, generated from the same Rust tables the routes
  dispatch on, so advertised and accepted can't diverge.
- `vocabulary` and `federation` as the JS resolver emits them for an instance
  with no overrides.

`/debug/identity` returns `{ "instance": <relay origin> }`. The api-smoketest's
preflight reads it to confirm it's talking to the target it was pointed at.

## Indexing

Routes: `/index` (GET, POST) and `/index/batch` (capped by `maxBatchSize`).
A request carries a URL, or a pushed blobject allowed by `submissions`.

In `createIndexer`'s order:

1. **Parse** — normalize the URI; check `allows.schemes`.
2. **Gates** — origin `blocks`/`allows`; `originBanned`; the `registration`
   gate (`open`, `registered` = `octo:verified` ASK across `originVariants`,
   `closed`); anchor auth (requesting origin vs page origin); endorsers from
   `endorsement.sources`; per-origin rate limit; `cooldown` from
   `octo:indexed`.
3. **Fetch** — the public-only transport; `detectBlockedFetch`. Gone,
   withdrawn and unreachable pages go to the deleter, which applies
   `deletion` (soft tombstone or hard purge); a returning page is restored.
4. **Handle** — a registry by content type: html (`scraper`), xml/RSS
   (`quick-xml`), markdown (`pulldown-cmark`), calendar (an iCal parser),
   json and blobject (`serde_json`).
5. **Policy** — `resolveIndexPolicy`: robots directives, opt-in.
6. **Harmonize** — one engine interprets the vendored harmonizer JSON. A
   remote harmonizer is fetched only if `isHarmonizerAllowed` passes, is
   validated against `harmonizer.schema.json`, and is cached.
7. **Write** — `checkIndexingPolicy`; term blocks and allows; `handleThorpe`,
   `handleMention`, `handleWebring`; reifier aliases behind the consent gate;
   `deleter.reconcilePage`.

`indexing.mode: active` schedules nothing (`indexer.js`, the `active` branch
of the per-URI handler). It skips the registration gate, while the gate's
other stages still run, and outside a policy check it treats the URI's own
origin as the requester. Robots directives then bind via
`resolveIndexPolicy`. The port does the same, with no background crawler.

**Rate limits.** The OP per-origin index limit (10 requests per 60 s in the
JS) applies on the relay host. brolly's own limiter covers login, signup and
password change and service passwords only, so it doesn't touch relay traffic. The api-smoketest is
read-only, so the index limit doesn't affect it.

## Queries and publishing

### `/get/[what]/[by]/[[as]]`

- `what` dispatches by group through `WHAT_GROUPS`; `by` through the
  link-type table, including `?st=` ad-hoc subtypes.
- An unknown `what`, `by`, `match` or `as`, and an unbounded
  `everything/posted`, get the same readable 4xx the JS returns. Params are
  read the way `src/lib/converters.js` `getQueryOptions` reads them,
  including `not-s`→`notS` and `not-o`→`notO`. Params outside `GET_PARAMS`
  get whatever the JS does with them; the stage 3 plan confirms that by
  reading `getQueryOptions` and does not invent a rejection.
- Params become a `MultiPass` (`buildMultiPass`); the query builders turn it
  into SPARQL. Kept textually close to `queryBuilders.js` and `multipass.js`.
- Responses follow `envelope.js` and `errors.js`. `limit`/`offset` pages are
  disjoint.

### Built-in envelopes and publishers (`as`)

`debug` and `multipass` are built-in envelopes, not registry publishers. The
JS special-cases them outside the publisher registry (`api.js`, `client.js`).
`debug` returns the results alongside the MultiPass and the query, and every
api-smoketest `/get` probe uses it, so both ship in stage 3.

The publishers are rss2, ics, bluesky (`app.bsky.feed.post`: grapheme-safe truncation via
`unicode-segmentation`, UTF-8 byte-offset facets) and standardSiteDocument.
Each resolver is vendored; each renderer is ported. Item shaping (`rssify`,
the `feed*` params) is shared.

### Other routes on the relay host

`/profile.json`, `/debug/identity`, `/profile.schema.json`,
`/harmonizer.schema.json`, `/harmonizer/[id]`, `/vocabulary.ttl`, `/vocabulary.jsonld`, `/rss`,
`/~/[thorpe]/rss`, the machine-readable forms of `/domains`, `/webrings`,
`/backlinks`, `/bookmarks`, `/discover`, and `/badge`. Under the `/debug/`
path tree, only `/debug/identity` exists. HTML paths 404.

## Admin console: the Relay tab

On the apex, under `/admin/relay/`, only when the relay is enabled. Uses
`require_admin`, `SAME_ORIGIN_FORMS` (every new form listed, as the
ui_invariants test requires), GET-confirm/POST-act, and the existing card
styling. Never served on the relay host.

- **Overview** (`/admin/relay`) — the relay host; page, term and origin
  counts; the current gate in one sentence ("Registered origins only; 12
  verified").
- **Policies** (`/admin/relay/policies`) — one form for every policy field.
  Enums as radio groups, lists as one-per-line textareas. Validated against
  `profile.schema.json`, saved to `op_policies`. Typed confirm for the two
  changes that widen exposure: `registration → open` and `deletion → hard`.
- **Origins** (`/admin/relay/origins`) — add as verified (stands in for
  `/register` for now), ban, unban. Any spelling in, canonical stored
  (`originVariants`); writes `octo:verified` / `octo:banned` triples. A detail
  page per origin: page count, last indexed.
- **Terms** (`/admin/relay/terms`) — ban, unban, and a term-users view of
  which origins use a term before banning it.

## Testing

1. **Unit tests** per ported module, with cases carried over from
   octothorp.es's vitest suites where they exist. Query builders are tested on
   results against fixture graphs, not on SPARQL text.
2. **Oracle fixtures.** `tools/vendor-octothorpes.sh` runs the `octothorpes`
   package over fixture documents (HTML, RSS, markdown, ics, json) with every
   vendored harmonizer and handler, recording the expected blobjects under
   `vendor/oracle/`. Rust tests assert identical output. Re-vendoring re-records
   them, so a behaviour change upstream shows up as a failing Rust test.
   The fixture documents are authored in brolly under
   `adapters/octothorpes/tests/fixtures/`, starting from saved copies of the
   devdemo pages listed in octothorp.es's `test-urls.yaml`. One copy feeds
   both the oracle and the loopback page server, so no test depends on live
   third-party pages.
3. **Integration tests** in `server/tests` (testcontainers Postgres, a
   loopback page server): index → query → publish; every gate and policy;
   deleter soft and hard; the host guard in both directions; the admin forms.
4. **Parity gate in CI.** Check out octothorp.es at the vendored commit,
   start a fresh brolly container with the relay enabled, and run
   `node scripts/api-smoketest.js --instance=<container>`. Its preflight
   needs no SPARQL (`requireSparql: false`); it checks the target's
   self-identity through `/debug/identity`. Fail the job on any error or 5xx;
   `empty` rows on a fresh store are expected. If the preflight still refuses
   a brolly target, stop and take it to the operator rather than working
   around D-OP2.

## Stages

Each stage gets its own plan, lands trunk-based, and leaves `main` deployable.

| # | Stage | Contents | Done when |
|---|---|---|---|
| 1 | Foundation | crate; relay store; `Sparql` facade; vendor script and first vendor; `BROLLY_OP_HOST` + host guard + reserved label; `op_policies`; `/profile.json`; `/debug/identity`; admin Overview + Policies | `/profile.json` validates against the schema; the policies form round-trips; the api-smoketest preflight passes against a container |
| 2 | Indexing core | `PageFetcher` + its public-only implementation; gates; html handler; harmonizer engine + `default`; writes; deleter; cooldown; admin Origins | a loopback fixture site indexes on a container in CI, after its origin is added as verified through Origins (the seeded gate is `registration: registered`); oracle fixtures pass for `default` on html |
| 3 | Query core | `/get` grammar; MultiPass; query builders; envelope and errors; `debug` and `multipass` envelopes; match modes | api-smoketest `grammar`, `negative` and `match` sections have zero errors as JSON; integration tests query an indexed fixture site |
| 4 | Breadth | remaining handlers and harmonizers; remote harmonizers; reifier and aliases; webrings; batch; submissions; `active` mode; admin Terms | oracle fixtures pass for every harmonizer and handler |
| 5 | Publishers and remaining routes | rss2, ics, bluesky, standardSiteDocument; remaining read routes; CI parity gate | **api-smoketest: zero errors in all five sections**; flip `OP_RELAY_ENABLED` |

## Open items

- **Unknown `/get` params** — confirm the JS behaviour in stage 3 (see
  Queries).
- **Relay HTML UI** — a later spec. It needs a decision on how a relay's
  public pages reconcile with brolly shipping unbranded.
