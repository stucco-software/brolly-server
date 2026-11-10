-- One address in any case. Emails are stored lowercased, by Postgres's own
-- lower() on every write and lookup, so the existing users_email_key is
-- case-insensitive in effect. The CHECK holds the rule in the database, not
-- only in the code that writes today. Existing rows are lowercased first; a
-- pair that collides once lowercased fails here, loudly, rather than
-- silently keeping two accounts for one address.
UPDATE users SET email = lower(email)
 WHERE email IS NOT NULL AND email <> lower(email);

ALTER TABLE users
    ADD CONSTRAINT users_email_lowercase CHECK (email = lower(email));
