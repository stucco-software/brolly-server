-- Remembered consents (spec 6, H4): what each member has allowed each
-- client, consulted only by `prompt=none` — the interactive flow always
-- shows the consent screen.
--
-- One row per (user_id, client_id), replaced — never appended to — on every
-- consent-screen allow, with the scope and the redirect URIs both widened
-- monotonically (the write stores the union), so the row is the current
-- state of the member's approval, not its history. That is what makes the
-- table revocable rather than append-only: the dashboard's revocation
-- surface (a later chunk of this stage) is a DELETE on the row, and a fresh
-- grant after a revocation is a fresh INSERT.
--
-- `client_id` carries no foreign key, deliberately: document clients (H3)
-- have no row in `solid_clients` — their client_id is the URL of the
-- document fetched and validated at authorize time — and the grant tables
-- made the same move in 20260929000000_solid_client_id_documents.sql.
--
-- `redirect_uris` is load-bearing security, not bookkeeping: a Client ID
-- Document at a reused or taken-over client_id URL can change its listed
-- redirect URIs, and without this column a `prompt=none` request would
-- carry a code silently to a URI the member never saw. With it, a changed
-- document falls back to the consent screen once — the interactive path's
-- exposure, not more. (Registered clients' URIs are fixed at registration,
-- so for them the column only ever accumulates the URIs actually granted
-- through.)

CREATE TABLE solid_consents (
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id     TEXT NOT NULL,
    scope         TEXT NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    granted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The spec's "unique on (user_id, client_id)": one consent per member
    -- per client, replaced on every allow.
    PRIMARY KEY (user_id, client_id)
);
