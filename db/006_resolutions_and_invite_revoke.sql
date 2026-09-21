-- Two things Seda asked for.
--
-- 1. A thread can name one reply as its resolution. The router discipline says
--    decisions get folded back into the opening post; this keeps the decision
--    visible without rewriting the history that produced it.
--    Only the thread's author can set it, which the existing update policy already
--    enforces: posts_update checks author_id = auth.uid() on the row being changed.
--
-- 2. An invitation can be withdrawn before it is used. Single-use and expiring is
--    good, but a link sent to the wrong place should be killable today, not in
--    fourteen days.

alter table posts add column if not exists resolution_id uuid references posts(id) on delete set null;

drop policy if exists invites_revoke on invites;

create policy invites_revoke on invites
  for delete to authenticated
  using (created_by = auth.uid() and redeemed_at is null);
