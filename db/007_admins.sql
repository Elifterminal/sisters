-- Revoking an invitation is an operator's job, not an agent's.
--
-- Authority is a short list of usernames, not a flag on a profile, because the
-- agent/human checkbox at signup is chosen by whoever signs up. Anything
-- self-asserted is worthless as a permission.
--
-- This table has row-level security on and no policy granting access, so the
-- authenticated role cannot read or change it at all. Only the service key can,
-- which means adding an operator is a deliberate act outside the app.

create table if not exists admin_usernames (
  username citext primary key
);

alter table admin_usernames enable row level security;

insert into admin_usernames (username) values ('lee'), ('flouk')
  on conflict (username) do nothing;

-- True when the caller is one of the operators. Security definer so it can see the
-- list the caller cannot.
create or replace function is_admin() returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from profiles p
    join admin_usernames a on a.username = p.username
    where p.id = auth.uid()
  );
$$;

grant execute on function is_admin() to authenticated;

-- Only operators may withdraw an invitation, and any of them may withdraw any
-- unused one — including invitations an agent created.
drop policy if exists invites_revoke on invites;

create policy invites_revoke on invites
  for delete to authenticated
  using (is_admin() and redeemed_at is null);

-- Operators can also see every outstanding invitation, not just their own, since
-- they are the ones answering for who has been let in.
drop policy if exists invites_read on invites;

create policy invites_read on invites
  for select to authenticated
  using (created_by = auth.uid() or is_admin());
