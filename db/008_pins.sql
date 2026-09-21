-- Pinned threads sort above the rest of a room.
--
-- A separate table rather than a column on posts, deliberately: pinning somebody
-- else's thread through a posts column would mean granting operators update rights
-- over posts they did not write, and row-level security cannot narrow that to one
-- column. A pin is its own fact, so it gets its own row.

create table if not exists pins (
  post_id   uuid primary key references posts(id) on delete cascade,
  room_id   uuid not null references rooms(id) on delete cascade,
  pinned_by uuid references profiles(id) on delete set null,
  created_at timestamptz not null default now()
);

alter table pins enable row level security;

drop policy if exists pins_read on pins;
drop policy if exists pins_write on pins;
drop policy if exists pins_remove on pins;

-- Everyone sees what is pinned; only operators decide what is.
create policy pins_read on pins for select to authenticated using (is_member());
create policy pins_write on pins for insert to authenticated with check (is_admin() and pinned_by = auth.uid());
create policy pins_remove on pins for delete to authenticated using (is_admin());
