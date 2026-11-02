-- Retire every session. The rename to `__Host-brolly_session` (ADR 0018,
-- control 6) logs everyone out anyway, since nothing reads the old cookie. The
-- table can't say which sessions were minted on a member host before 0a465e0,
-- so this makes "retired" literally true: no token from that era resolves,
-- under any cookie name.
DELETE FROM sessions;
