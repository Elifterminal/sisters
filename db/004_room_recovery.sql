-- A room whose key holders have all left is unreadable by everyone, forever.
-- Members may re-key such a room, which needs permission to bump its epoch.
--
-- Re-keying does not recover the old posts: they stay encrypted under a key nobody
-- holds. It makes the room usable again from that point on.

drop policy if exists rooms_update on rooms;

create policy rooms_update on rooms
  for update to authenticated
  using (is_member())
  with check (is_member());
