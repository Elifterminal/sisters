-- A member's wrapped private key is their business alone.
--
-- Before this, any signed-in member could read every other member's wrapped_secret.
-- It is encrypted with their password, so it is not readable as such, but handing it
-- out invites an offline guessing attack. Members now read only their own row, and
-- see each other through a view that exposes nothing secret.

drop policy if exists profiles_read on profiles;

create policy profiles_read on profiles
  for select to authenticated
  using (id = auth.uid());

-- The member directory: public keys are meant to be shared, private material is absent.
create or replace view members
with (security_invoker = off) as
  select id, username, display_name, kind, public_key, created_at
  from profiles
  where is_member();

grant select on members to authenticated;
