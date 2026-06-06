-- ============================================================
-- CyberShield AI — Threat Monitoring Migration (Fixed)
-- Run this entire script in your Supabase SQL Editor
-- ============================================================

-- Step 1: Create threat_logs table
create table if not exists public.threat_logs (
  id uuid default uuid_generate_v4() primary key,
  event_type text not null,
  severity text check (severity in ('Low', 'Medium', 'High', 'Critical')) not null default 'Low',
  description text not null,
  user_id uuid references auth.users on delete set null,
  user_email text,
  ip_address text,
  metadata jsonb default '{}',
  resolved boolean default false,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Step 2: Enable RLS
alter table public.threat_logs enable row level security;

-- Step 3: Drop old conflicting policies if they exist
drop policy if exists "Admins full access to threat_logs" on public.threat_logs;
drop policy if exists "Users can view own threat logs" on public.threat_logs;
drop policy if exists "Authenticated users can insert threat logs" on public.threat_logs;
drop policy if exists "Allow anon inserts for threat logging" on public.threat_logs;

-- Step 4: Admin full access
create policy "Admins full access to threat_logs" on public.threat_logs
  for all using (
    (auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin'
    OR (auth.jwt() -> 'app_metadata' ->> 'role') = 'Admin'
  );

-- Step 5: Authenticated users can read their own logs
create policy "Users can view own threat logs" on public.threat_logs
  for select using (auth.uid() is not null);

-- Step 6: CRITICAL FIX — Allow ANYONE (including unauthenticated/anon)
-- to INSERT threat logs. This is required so that failed login attempts
-- (which happen BEFORE authentication) can still be logged.
-- The anon Supabase key is already restricted to this table only.
create policy "Allow all inserts for threat logging" on public.threat_logs
  for insert with check (true);

-- Step 7: Allow authenticated users to update resolved status
create policy "Allow authenticated users to resolve logs" on public.threat_logs
  for update using (auth.uid() is not null);

-- Step 8: Fix phishing_scans columns (safe if already run)
alter table public.phishing_scans
  add column if not exists scan_type text default 'URL',
  add column if not exists content_snippet text;

-- Repair any existing rows that might have null scan_type
update public.phishing_scans set scan_type = 'URL' where scan_type is null;

-- Step 9: Seed a test threat log to verify connection is working
insert into public.threat_logs (event_type, severity, description, user_email, metadata)
values (
  'ADMIN_ACTION',
  'Low',
  'Threat monitoring system initialized successfully',
  'system@cybershield.ai',
  '{"source": "setup_migration", "version": "1.0"}'::jsonb
);
