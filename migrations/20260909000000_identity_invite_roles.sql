-- An invite may carry the role it grants.
--
-- Handing over an instance previously meant handing over a database
-- credential: `role` could only be changed by someone who could already write
-- to `users`. An invite is the credential that fits the job — one-time, scoped,
-- and useless the moment it is redeemed.
--
-- NULL means the invite grants the default, which is what every existing
-- invite does. The CHECK mirrors `users.role` rather than referencing it,
-- because Postgres has no way to share a domain constraint across two columns
-- without a type, and a third state here would be a bug either way.
ALTER TABLE invites
    ADD COLUMN grants_role TEXT
        CHECK (grants_role IS NULL OR grants_role IN ('member', 'admin'));
