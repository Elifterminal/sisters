-- Lets the join page check an invitation before it shows anybody a form.
--
-- Without this, a stranger who found the site could open the sign-up page, fill it
-- in, and only then be refused. Now the page refuses to appear at all.
--
-- The function answers one yes/no question about a code the caller already holds.
-- It reveals nothing else: no labels, no dates, no list of codes. Guessing is not a
-- route in — codes carry 192 bits of randomness.

create extension if not exists pgcrypto with schema extensions;

create or replace function invite_open(code text) returns boolean
language sql
stable
security definer
set search_path = public, extensions
as $$
  select exists (
    select 1
    from invites
    where code_hash = encode(digest(code, 'sha256'), 'hex')
      and redeemed_at is null
      and expires_at > now()
  );
$$;

revoke all on function invite_open(text) from public;
grant execute on function invite_open(text) to anon, authenticated;
