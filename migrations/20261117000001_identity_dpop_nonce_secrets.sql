-- The instance's DPoP nonce secret (stage 2, C).
--
-- One row, one secret: the HMAC key behind the time-bucketed nonces RFC 9449
-- hands out and the ATProtocol profile makes mandatory. Generated on first
-- start and never rotated — rotation would invalidate every nonce in flight,
-- which is survivable (the client retries the nonce dance) but pointless. The
-- `CHECK (id = 1)` makes a second secret a schema error rather than a race
-- outcome: two processes starting together converge through
-- `ON CONFLICT DO NOTHING` and the read-back, the `instance_actor` pattern.
CREATE TABLE dpop_nonce_secrets (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    secret  BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
