# 0021 — Agent provisioning lives in the admin console

**Status:** Accepted (2026-11-16). Supersedes the "CLI-only linking" clause of
[0020](0020-client-credentials-for-linked-webids.md) decision 3; every other
clause of 0020 stands.

## Context

ADR 0020 shipped agent provisioning as three CLI commands. One of them —
`agent-account` — opens the pod stores, and a running server holds their
RocksDB locks, so the operator path read: *stop the server, run the command
against the server's own data dir and database, restart the server.* On a
single-host deployment that is downtime for a signup; on Railway it is a
scale-to-zero dance with a volume re-attach. For a task an admin does with a
browser open, that is the wrong shape.

The server itself is the one process that already holds the stores' locks and
creates accounts while running on every signup. And the console already has
the exact security posture this surface needs: `require_admin`, the
same-origin form guard, and the quota form's refusal shape (400 re-render
with the submitted values kept).

## Decision

Agent provisioning moves into the admin console, as an **Agents** tab:

- `GET /admin/agents` lists every linked WebID — whose account, since when,
  how many credential pairs, when one last answered.
- `POST /admin/agents/account` creates the service account
  (`provision::account`, the same substance every signup gets) with a
  generated password rendered **once**, on the POST's own response,
  `no-store`.
- `POST /admin/agents/link` links a WebID, running the same `link_webid`
  verification the CLI does — dereferencing the WebID's own document through
  `state.webid_documents`, the same transport and cache the remote
  verification path reads, so the console and the CLI cannot disagree about
  what a WebID says.
- `POST /admin/agents/credentials` mints a pair, rendered once, `no-store`.
- `POST /admin/agents/unlink` is the kill switch.

All five are admin-gated (members get the console's 404, anonymous visitors
the login redirect) and in `SAME_ORIGIN_FORMS`. The CLI commands remain as
the scriptable path, unchanged; nothing about the grant, the linking
verification, or the credential model changes — only where an operator
stands while running it.

## Consequences

- Nothing in the agent path requires stopping the server. The CLI's
  `agent-account` still does (it is a second process opening the stores);
  the console's does not, and is the primary surface.
- A refresh after a mint re-submits the form and mints a *new* pair — the
  shown-once secret is never re-fetchable, at the cost of an accidental
  extra pair on a careless refresh. Pairs are independent; the unlink
  retires them all. Acceptable, and stated on the page.
- The console page renders two kinds of secret (a generated password, a
  minted secret). Both ride exactly one response with `no-store` and never a
  log line; the store holds only hashes.
