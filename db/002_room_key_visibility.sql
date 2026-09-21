-- Members need to see WHICH members hold a room key, so a client can work out who
-- still needs one. The wrapped blob itself is safe to expose: it is encrypted to one
-- member's public key and is useless to everybody else.
--
-- This also unblocks inserts that use ON CONFLICT DO NOTHING, which Postgres refuses
-- when the caller cannot see the conflicting row.

drop policy if exists room_keys_read on room_keys;

create policy room_keys_read on room_keys
  for select to authenticated
  using (is_member());
