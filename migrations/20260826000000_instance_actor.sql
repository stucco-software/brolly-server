-- The instance as an agent (D4).
--
-- The server owns a shared inbox, the cross-user index, moderation state and
-- instance metadata. All of that belonged to nobody before this table; the
-- learnings call it "five tables' worth of homeless state".
--
-- Singleton by construction. `id` is a boolean that must be true and is the
-- primary key, so a second row is a duplicate-key error rather than a
-- possibility nobody noticed — two instance keypairs would mean the one that
-- signs depends on whichever row a query happens to order first.
CREATE TABLE instance_actor (
    id              BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),

    -- Canonical federation identity (D11). Null until Phase 7 registers with
    -- PLC — the row has to exist before the network call that fills this in.
    did_plc         TEXT UNIQUE,

    -- RSA, for cavage-09 HTTP signatures. PEM rather than DER because that is
    -- what the ActivityPub framework takes and returns, and re-encoding on
    -- every request to store a tidier shape would buy nothing.
    private_key_pem TEXT NOT NULL,
    public_key_pem  TEXT NOT NULL,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
