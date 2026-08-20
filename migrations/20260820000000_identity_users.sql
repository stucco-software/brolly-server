-- Users. Operational state only — no user content, ever (D2/D5).
--
-- Note what is NOT here: display name, bio, avatar. Those live in the user's
-- pod and are projected. The predecessor migrated them out on principle and
-- then added profile_display_name back seven weeks later with a backfill,
-- because its admin list could not open 500 stores to render a table. That
-- read now has a legitimate home in the server-agent index (ADR 0005 R5).
CREATE TABLE users (
    id              UUID PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    email           TEXT UNIQUE,
    email_verified  BOOLEAN NOT NULL DEFAULT FALSE,
    password_hash   TEXT NOT NULL,

    -- Canonical federation identity (D11). Nullable only between account
    -- creation and PLC registration; every wire format reads this column.
    did_plc         TEXT UNIQUE,

    role            TEXT NOT NULL DEFAULT 'member'
                    CHECK (role IN ('member', 'admin')),
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'disabled')),

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at   TIMESTAMPTZ
);

CREATE INDEX users_did_plc_idx ON users (did_plc) WHERE did_plc IS NOT NULL;
