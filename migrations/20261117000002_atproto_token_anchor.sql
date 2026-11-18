-- The session anchor (stage 2, G).
--
-- `anchored_at` is set at the code grant and copied forward on every rotation,
-- so a public client's overall session lifetime is capped however much it
-- refreshes: rotation alone would cap only the individual refresh tokens,
-- granting public clients the unlimited session the profile reserves for
-- confidential ones. DEFAULT now() anchors existing rows at the migration
-- timestamp — the spec's rollout rule: they are capped from there.
ALTER TABLE atproto_tokens ADD COLUMN anchored_at TIMESTAMPTZ NOT NULL DEFAULT now();
