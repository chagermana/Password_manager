-- Run this in Supabase Dashboard > SQL Editor.
-- One encrypted vault row per Supabase Auth user.
create table if not exists public.vaults (
  user_id uuid primary key references auth.users (id) on delete cascade,
  vault_data jsonb not null,
  updated_at timestamptz not null default now()
);

alter table public.vaults enable row level security;

revoke all on table public.vaults from anon, authenticated;
grant select, insert, update, delete on table public.vaults to authenticated;

drop policy if exists "Users can read their own vault" on public.vaults;
create policy "Users can read their own vault"
  on public.vaults for select to authenticated
  using ((select auth.uid()) = user_id);

drop policy if exists "Users can create their own vault" on public.vaults;
create policy "Users can create their own vault"
  on public.vaults for insert to authenticated
  with check ((select auth.uid()) = user_id);

drop policy if exists "Users can update their own vault" on public.vaults;
create policy "Users can update their own vault"
  on public.vaults for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

drop policy if exists "Users can delete their own vault" on public.vaults;
create policy "Users can delete their own vault"
  on public.vaults for delete to authenticated
  using ((select auth.uid()) = user_id);
