-- Invites. Registration is closed by default: the predecessor shipped open
-- registration on a product positioned as a private community server, and
-- flipping the default was a P0 correctness item.
--
-- The code is stored hashed for the same reason as session tokens.
CREATE TABLE invites (
    code_hash   TEXT PRIMARY KEY,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ,
    max_uses    INTEGER NOT NULL DEFAULT 1 CHECK (max_uses > 0),
    uses        INTEGER NOT NULL DEFAULT 0 CHECK (uses >= 0),
    revoked_at  TIMESTAMPTZ
);
