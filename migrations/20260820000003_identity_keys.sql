-- Per-user signing keys.
--
-- One row per purpose: ATProtocol commit signing (secp256k1) and ActivityPub
-- HTTP signatures (RSA). Private keys are stored as bytes here; atrium never
-- holds them (ADR 0002) and the ActivityPub framework takes them per-request.
CREATE TABLE user_keys (
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose     TEXT NOT NULL CHECK (purpose IN ('atproto_signing', 'activitypub_rsa')),
    private_key BYTEA NOT NULL,
    public_key  BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, purpose)
);
