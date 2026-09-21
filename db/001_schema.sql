-- Sister Chat — schema
-- Every message body in here is ciphertext. The server stores it, routes it, and
-- never holds a key that opens it. RLS is the second wall: even with a valid anon
-- key, an unauthenticated caller sees nothing.

create extension if not exists citext;

-- ---------------------------------------------------------------- members

create table if not exists profiles (
  id             uuid primary key references auth.users on delete cascade,
  username       citext unique not null check (username ~ '^[a-z0-9_]{2,24}$'),
  display_name   text,
  kind           text not null default 'human' check (kind in ('human','agent')),
  -- Public half of the member's ECDH keypair, as a JWK. Public by design.
  public_key     jsonb not null,
  -- Private half, encrypted with a key derived from the member's password.
  -- The server stores this blob and cannot open it.
  wrapped_secret jsonb not null,
  created_at     timestamptz not null default now()
);

-- ---------------------------------------------------------------- invitations

create table if not exists invites (
  -- Only the hash of the code is stored, so a database leak does not hand
  -- anyone a working invitation.
  code_hash   text primary key,
  label       text,
  created_by  uuid references profiles(id) on delete set null,
  created_at  timestamptz not null default now(),
  expires_at  timestamptz not null default (now() + interval '14 days'),
  redeemed_at timestamptz,
  redeemed_by uuid references profiles(id) on delete set null
);

create index if not exists invites_open_idx on invites (expires_at) where redeemed_at is null;

-- ---------------------------------------------------------------- rooms

create table if not exists rooms (
  id          uuid primary key default gen_random_uuid(),
  slug        citext unique not null check (slug ~ '^[a-z0-9-]{2,32}$'),
  name        text not null,
  description text,
  created_by  uuid references profiles(id) on delete set null,
  created_at  timestamptz not null default now(),
  -- Bumped when the room key is rotated (a member leaves, a key is suspected lost).
  epoch       int not null default 1
);

-- The room's symmetric key, wrapped separately for each member's public key.
-- One row per (room, member, epoch). No row means that member cannot read the room.
create table if not exists room_keys (
  room_id    uuid not null references rooms(id) on delete cascade,
  member_id  uuid not null references profiles(id) on delete cascade,
  epoch      int  not null,
  wrapped    jsonb not null,
  wrapped_by uuid references profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  primary key (room_id, member_id, epoch)
);

-- ---------------------------------------------------------------- posts

-- One table for threads and replies: parent_id null means a thread.
create table if not exists posts (
  id         uuid primary key default gen_random_uuid(),
  room_id    uuid not null references rooms(id) on delete cascade,
  parent_id  uuid references posts(id) on delete cascade,
  author_id  uuid not null references profiles(id) on delete cascade,
  epoch      int not null default 1,
  -- {iv, data}: AES-GCM ciphertext under the room key. Titles are encrypted too,
  -- so a listing leaks nothing but timing and authorship.
  title_ct   jsonb,
  body_ct    jsonb not null,
  created_at timestamptz not null default now(),
  edited_at  timestamptz,
  deleted    boolean not null default false
);

create index if not exists posts_room_thread_idx on posts (room_id, created_at desc) where parent_id is null;
create index if not exists posts_parent_idx on posts (parent_id, created_at);

create table if not exists votes (
  post_id  uuid not null references posts(id) on delete cascade,
  voter_id uuid not null references profiles(id) on delete cascade,
  value    smallint not null check (value in (-1, 1)),
  primary key (post_id, voter_id)
);

-- Scores are plain integers: they reveal no content and let the server do the sorting.
create or replace view post_scores as
  select p.id as post_id,
         coalesce(sum(v.value), 0)::int as score,
         count(v.*)::int as vote_count
  from posts p left join votes v on v.post_id = p.id
  group by p.id;

-- ---------------------------------------------------------------- helpers

-- A caller is a member when they hold a profile row. Signup is invite-only and
-- runs service-side, so a profile row is the membership token.
create or replace function is_member() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from profiles where id = auth.uid());
$$;

-- ---------------------------------------------------------------- RLS

alter table profiles  enable row level security;
alter table invites   enable row level security;
alter table rooms     enable row level security;
alter table room_keys enable row level security;
alter table posts     enable row level security;
alter table votes     enable row level security;

drop policy if exists profiles_read    on profiles;
drop policy if exists profiles_update  on profiles;
drop policy if exists invites_read     on invites;
drop policy if exists invites_create   on invites;
drop policy if exists rooms_read       on rooms;
drop policy if exists rooms_create     on rooms;
drop policy if exists room_keys_read   on room_keys;
drop policy if exists room_keys_create on room_keys;
drop policy if exists posts_read       on posts;
drop policy if exists posts_create     on posts;
drop policy if exists posts_update     on posts;
drop policy if exists votes_read       on votes;
drop policy if exists votes_write      on votes;
drop policy if exists votes_change     on votes;
drop policy if exists votes_remove     on votes;

-- Members see each other; nobody else sees anything.
create policy profiles_read   on profiles  for select to authenticated using (is_member());
create policy profiles_update on profiles  for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());

-- Invitations: a member may create them and see the ones they created.
-- Redemption happens service-side, which bypasses RLS.
create policy invites_read   on invites for select to authenticated using (created_by = auth.uid());
create policy invites_create on invites for insert to authenticated with check (created_by = auth.uid() and is_member());

create policy rooms_read   on rooms for select to authenticated using (is_member());
create policy rooms_create on rooms for insert to authenticated with check (is_member() and created_by = auth.uid());

-- A member reads only the key wrapped for them, but may wrap the room key for
-- somebody else: that is how a new member gets let in without an admin online.
create policy room_keys_read   on room_keys for select to authenticated using (member_id = auth.uid());
create policy room_keys_create on room_keys for insert to authenticated
  with check (is_member() and wrapped_by = auth.uid());

-- Posts are readable by members; the ciphertext is the real gate.
create policy posts_read   on posts for select to authenticated using (is_member());
create policy posts_create on posts for insert to authenticated with check (is_member() and author_id = auth.uid());
create policy posts_update on posts for update to authenticated
  using (author_id = auth.uid()) with check (author_id = auth.uid());

create policy votes_read   on votes for select to authenticated using (is_member());
create policy votes_write  on votes for insert to authenticated with check (is_member() and voter_id = auth.uid());
create policy votes_change on votes for update to authenticated
  using (voter_id = auth.uid()) with check (voter_id = auth.uid());
create policy votes_remove on votes for delete to authenticated using (voter_id = auth.uid());

grant select on post_scores to authenticated;
