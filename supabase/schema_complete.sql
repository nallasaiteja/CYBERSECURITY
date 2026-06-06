-- =============================================================================
-- CyberShield AI — Consolidated Database Schema & Seeds (Phases 1-7 Complete)
-- Run this entire file in your Supabase SQL Editor to initialize the database
-- =============================================================================

-- Enable UUID extension
create extension if not exists "uuid-ossp";

-- ─── 1. USER PROFILES ────────────────────────────────────────────────────────

create table if not exists public.profiles (
  id uuid references auth.users on delete cascade primary key,
  email text not null,
  role text check (role in ('Admin', 'User')) not null default 'User',
  is_suspended boolean default false not null,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  updated_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable RLS
alter table public.profiles enable row level security;

-- ─── 2. PHISHING SCANS ───────────────────────────────────────────────────────

create table if not exists public.phishing_scans (
  id uuid default gen_random_uuid() primary key,
  target_url text not null,
  result text check (result in ('Clean', 'Suspicious', 'Malicious')) not null,
  confidence_score integer not null, -- percentage 0-100
  scan_type text default 'URL' check (scan_type in ('URL', 'Email', 'SMS')) not null,
  content_snippet text,
  scanned_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable RLS
alter table public.phishing_scans enable row level security;

-- ─── 3. FAILED LOGINS REGISTER ───────────────────────────────────────────────

create table if not exists public.failed_logins (
  id uuid default gen_random_uuid() primary key,
  email text not null,
  ip_address text,
  attempted_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable RLS
alter table public.failed_logins enable row level security;

-- ─── 4. SECURITY THREAT LOGS ─────────────────────────────────────────────────

create table if not exists public.threat_logs (
  id uuid default uuid_generate_v4() primary key,
  event_type text not null,
  severity text check (severity in ('Low', 'Medium', 'High', 'Critical')) not null default 'Low',
  description text not null,
  user_id uuid references auth.users on delete set null,
  user_email text,
  ip_address text,
  metadata jsonb default '{}'::jsonb,
  resolved boolean default false not null,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable RLS
alter table public.threat_logs enable row level security;

-- ─── 5. SECURITY SYSTEM ALERTS ───────────────────────────────────────────────

create table if not exists public.alerts (
  id uuid default uuid_generate_v4() primary key,
  alert_type text not null,
  severity text check (severity in ('Low', 'Medium', 'High', 'Critical')) not null,
  title text not null,
  message text not null,
  user_email text,
  trigger_value numeric,
  trigger_threshold numeric,
  is_read boolean default false not null,
  is_dismissed boolean default false not null,
  metadata jsonb default '{}'::jsonb,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable RLS
alter table public.alerts enable row level security;

-- Indexing for alerts optimization
create index if not exists idx_alerts_is_read on public.alerts (is_read, created_at desc);
create index if not exists idx_alerts_severity on public.alerts (severity, created_at desc);

-- ─── 6. LEGACY THREAT ALERTS ─────────────────────────────────────────────────

create table if not exists public.threat_alerts (
  id uuid default gen_random_uuid() primary key,
  title text not null,
  severity text check (severity in ('Low', 'Medium', 'High', 'Critical')) not null,
  source_ip text not null,
  status text check (status in ('Active', 'Investigating', 'Resolved')) default 'Active' not null,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable RLS
alter table public.threat_alerts enable row level security;


-- =============================================================================
-- FUNCTIONS, TRIGGERS & PROCEDURES (SECURITY DEFINERS)
-- =============================================================================

-- Trigger: Handle new user profile creation upon authentication signup
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, email, role)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'role', 'User')
  );
  return new;
end;
$$ language plpgsql security definer;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();


-- Trigger: Prevent privilege escalation (non-admins cannot edit roles/suspension)
create or replace function public.preserve_role_on_update()
returns trigger as $$
begin
  if (coalesce(auth.jwt() -> 'user_metadata' ->> 'role', '') != 'Admin') then
    if (new.role is distinct from old.role or new.is_suspended is distinct from old.is_suspended) then
      raise exception 'Unauthorized: Only administrators can modify user roles or suspension status';
    end if;
  end if;
  return new;
end;
$$ language plpgsql security definer;

drop trigger if exists on_profile_role_update on public.profiles;
create trigger on_profile_role_update
  before update on public.profiles
  for each row execute procedure public.preserve_role_on_update();


-- Function: RPC for Admins to delete user accounts safely
create or replace function public.delete_user(target_user_id uuid)
returns void as $$
begin
  -- Enforce only Admin execution
  if (coalesce(auth.jwt() -> 'user_metadata' ->> 'role', '') != 'Admin') then
    raise exception 'Unauthorized: Only administrators can delete operator accounts';
  end if;

  -- Block self deletion
  if (auth.uid() = target_user_id) then
    raise exception 'Conflict: You cannot delete your own active administrator session';
  end if;

  -- Delete from auth.users (cascades to profiles)
  delete from auth.users where id = target_user_id;
end;
$$ language plpgsql security definer;


-- =============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- =============================================================================

-- Profiles Policies
drop policy if exists "Users can view their own profile, admins can view all" on public.profiles;
create policy "Users can view their own profile, admins can view all"
  on public.profiles for select
  to authenticated
  using (auth.uid() = id or (auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin');

drop policy if exists "Users can update their own profile" on public.profiles;
create policy "Users can update their own profile"
  on public.profiles for update
  to authenticated
  using (auth.uid() = id)
  with check (auth.uid() = id);

drop policy if exists "Admins can update any profile" on public.profiles;
create policy "Admins can update any profile"
  on public.profiles for update
  to authenticated
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin')
  with check ((auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin');

drop policy if exists "Admins can delete any profile" on public.profiles;
create policy "Admins can delete any profile"
  on public.profiles for delete
  to authenticated
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin');


-- Phishing Scans Policies
drop policy if exists "Phishing scans are viewable by authenticated users" on public.phishing_scans;
create policy "Phishing scans are viewable by authenticated users"
  on public.phishing_scans for select
  to authenticated
  using (true);

drop policy if exists "Phishing scans can be inserted by authenticated users" on public.phishing_scans;
create policy "Phishing scans can be inserted by authenticated users"
  on public.phishing_scans for insert
  to authenticated
  with check (true);


-- Failed Logins Policies
drop policy if exists "Failed logins are viewable by authenticated users" on public.failed_logins;
create policy "Failed logins are viewable by authenticated users"
  on public.failed_logins for select
  to authenticated
  using (true);

drop policy if exists "Failed logins can be inserted by anyone" on public.failed_logins;
create policy "Failed logins can be inserted by anyone"
  on public.failed_logins for insert
  to anon, authenticated
  with check (true);


-- Threat Logs Policies
drop policy if exists "Admins full access to threat_logs" on public.threat_logs;
create policy "Admins full access to threat_logs" on public.threat_logs
  for all using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin' or (auth.jwt() -> 'app_metadata' ->> 'role') = 'Admin');

drop policy if exists "Users can view own threat logs" on public.threat_logs;
create policy "Users can view own threat logs" on public.threat_logs
  for select using (auth.uid() is not null);

drop policy if exists "Allow all inserts for threat logging" on public.threat_logs;
create policy "Allow all inserts for threat logging" on public.threat_logs
  for insert with check (true);

drop policy if exists "Allow authenticated users to resolve logs" on public.threat_logs;
create policy "Allow authenticated users to resolve logs" on public.threat_logs
  for update using (auth.uid() is not null);


-- Alerts Policies
drop policy if exists "Admins full access to alerts" on public.alerts;
create policy "Admins full access to alerts" on public.alerts
  for all using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin' or (auth.jwt() -> 'app_metadata' ->> 'role') = 'Admin');

drop policy if exists "Authenticated users view alerts" on public.alerts;
create policy "Authenticated users view alerts" on public.alerts
  for select using (auth.uid() is not null);

drop policy if exists "Allow all inserts for alerts" on public.alerts;
create policy "Allow all inserts for alerts" on public.alerts
  for insert with check (true);

drop policy if exists "Allow authenticated alert updates" on public.alerts;
create policy "Allow authenticated alert updates" on public.alerts
  for update using (auth.uid() is not null);


-- Legacy Threat Alerts Policies
drop policy if exists "Threat alerts are viewable by authenticated users" on public.threat_alerts;
create policy "Threat alerts are viewable by authenticated users"
  on public.threat_alerts for select
  to authenticated
  using (true);

drop policy if exists "Threat alerts can be managed by Admin users" on public.threat_alerts;
create policy "Threat alerts can be managed by Admin users"
  on public.threat_alerts for all
  to authenticated
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin');


-- =============================================================================
-- SYSTEM DEVELOPMENT SEED DATA
-- =============================================================================

-- Seed Legacy Threat Alerts
insert into public.threat_alerts (title, severity, source_ip, status)
values
  ('SQL Injection Attempt Blocked', 'High', '185.220.101.4', 'Resolved'),
  ('Suspicious API Token Generation', 'Medium', '92.40.12.189', 'Active'),
  ('Multiple Failed Admin Login Attempts', 'Critical', '103.245.72.6', 'Active'),
  ('Port Scan Detected on SSH Port 22', 'Low', '198.51.100.12', 'Investigating'),
  ('Outbound High Traffic volume to Unknown IP', 'High', '192.168.1.105', 'Active')
on conflict do nothing;

-- Seed Phishing Scans
insert into public.phishing_scans (target_url, result, confidence_score, scan_type, content_snippet, scanned_at)
values
  ('https://secure-login-paypal-verify.com', 'Malicious', 98, 'URL', null, now() - interval '2 hours'),
  ('https://github-auth-token-refresh.net', 'Suspicious', 74, 'URL', null, now() - interval '5 hours'),
  ('https://google.com', 'Clean', 100, 'URL', null, now() - interval '1 day'),
  ('https://microsoft-support-ticket-382.co', 'Malicious', 92, 'URL', null, now() - interval '2 days'),
  ('https://amazon-rewards-claim.info', 'Malicious', 89, 'URL', null, now() - interval '3 days'),
  ('https://wikipedia.org', 'Clean', 100, 'URL', null, now() - interval '4 days')
on conflict do nothing;

-- Seed Failed Logins
insert into public.failed_logins (email, ip_address, attempted_at)
values
  ('admin@cybershield.ai', '198.51.100.45', now() - interval '1 hour'),
  ('root@cybershield.ai', '103.245.72.6', now() - interval '3 hours'),
  ('operator@cybershield.ai', '185.220.101.4', now() - interval '12 hours'),
  ('guest@cybershield.ai', '92.40.12.189', now() - interval '1 day')
on conflict do nothing;

-- Seed Threat Logs
insert into public.threat_logs (event_type, severity, description, user_email, metadata)
values 
  ('ADMIN_ACTION', 'Low', 'Threat monitoring system initialized successfully', 'system@cybershield.ai', '{"source": "setup_migration", "version": "1.0"}'::jsonb),
  ('FAILED_LOGIN', 'Low', 'Failed login attempt for account: user@company.com', 'user@company.com', '{"ip": "72.14.204.99"}'::jsonb)
on conflict do nothing;
