-- ============================================================
-- CyberShield AI — Alert Engine Migration (Phase 6)
-- Run this in Supabase SQL Editor
-- ============================================================

-- Step 1: Create alerts table
create table if not exists public.alerts (
  id uuid default uuid_generate_v4() primary key,
  alert_type text not null,
  severity text check (severity in ('Low', 'Medium', 'High', 'Critical')) not null,
  title text not null,
  message text not null,
  user_email text,
  trigger_value numeric,          -- e.g. failed_count=7, risk_score=94
  trigger_threshold numeric,      -- e.g. threshold=5, threshold=80
  is_read boolean default false,
  is_dismissed boolean default false,
  metadata jsonb default '{}',
  created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Step 2: Enable RLS
alter table public.alerts enable row level security;

-- Step 3: Drop any stale policies
drop policy if exists "Admins full access to alerts" on public.alerts;
drop policy if exists "Users view own alerts" on public.alerts;
drop policy if exists "Allow all inserts for alerts" on public.alerts;
drop policy if exists "Allow authenticated updates for alerts" on public.alerts;

-- Step 4: Admin sees all
create policy "Admins full access to alerts" on public.alerts
  for all using (
    (auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin'
    OR (auth.jwt() -> 'app_metadata' ->> 'role') = 'Admin'
  );

-- Step 5: Authenticated users can see all alerts (for dashboard display)
create policy "Authenticated users view alerts" on public.alerts
  for select using (auth.uid() is not null);

-- Step 6: Allow anon inserts so pre-auth events (like failed logins) can fire alerts
create policy "Allow all inserts for alerts" on public.alerts
  for insert with check (true);

-- Step 7: Allow authenticated users to mark alerts as read/dismissed
create policy "Allow authenticated alert updates" on public.alerts
  for update using (auth.uid() is not null);

-- Step 8: Index for fast unread count queries
create index if not exists idx_alerts_is_read on public.alerts (is_read, created_at desc);
create index if not exists idx_alerts_severity on public.alerts (severity, created_at desc);
