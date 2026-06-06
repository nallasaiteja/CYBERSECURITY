-- ============================================================
-- CyberShield AI — Role-Based Security Migration (Phase 8)
-- Run this in your Supabase SQL Editor
-- ============================================================

-- Step 1: Add user_id to phishing_scans table
alter table public.phishing_scans
  add column if not exists user_id uuid references auth.users on delete cascade;

-- Step 2: Add user_id to alerts table
alter table public.alerts
  add column if not exists user_id uuid references auth.users on delete cascade;

-- Step 3: Reconfigure RLS for phishing_scans
alter table public.phishing_scans enable row level security;

drop policy if exists "Phishing scans are viewable by authenticated users" on public.phishing_scans;
drop policy if exists "Phishing scans can be inserted by authenticated users" on public.phishing_scans;

create policy "Users view own scans, admins view all"
  on public.phishing_scans for select
  to authenticated
  using (
    auth.uid() = user_id 
    or (auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin'
  );

create policy "Users can insert own scans"
  on public.phishing_scans for insert
  to authenticated
  with check (
    auth.uid() = user_id
  );

-- Step 4: Reconfigure RLS for threat_logs
alter table public.threat_logs enable row level security;

drop policy if exists "Users can view own threat logs" on public.threat_logs;
drop policy if exists "Admins full access to threat_logs" on public.threat_logs;
drop policy if exists "Allow all inserts for threat logging" on public.threat_logs;
drop policy if exists "Allow authenticated users to resolve logs" on public.threat_logs;

create policy "Users view own threat logs, admins view all"
  on public.threat_logs for select
  to authenticated
  using (
    auth.uid() = user_id
    or user_email = (select email from public.profiles where id = auth.uid() limit 1)
    or (auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin'
  );

create policy "Allow all inserts for threat logging"
  on public.threat_logs for insert
  with check (true);

create policy "Allow updates for threat resolution"
  on public.threat_logs for update
  to authenticated
  using (
    auth.uid() = user_id 
    or user_email = (select email from public.profiles where id = auth.uid() limit 1)
    or (auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin'
  );

-- Step 5: Reconfigure RLS for alerts
alter table public.alerts enable row level security;

drop policy if exists "Authenticated users view alerts" on public.alerts;
drop policy if exists "Admins full access to alerts" on public.alerts;
drop policy if exists "Allow all inserts for alerts" on public.alerts;
drop policy if exists "Allow authenticated alert updates" on public.alerts;

create policy "Users view own alerts, admins view all"
  on public.alerts for select
  to authenticated
  using (
    auth.uid() = user_id
    or user_email = (select email from public.profiles where id = auth.uid() limit 1)
    or (auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin'
  );

create policy "Allow all inserts for alerts"
  on public.alerts for insert
  with check (true);

create policy "Allow updates for alert read status"
  on public.alerts for update
  to authenticated
  using (
    auth.uid() = user_id
    or user_email = (select email from public.profiles where id = auth.uid() limit 1)
    or (auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin'
  );

-- Step 6: Reconfigure RLS for failed_logins
alter table public.failed_logins enable row level security;

drop policy if exists "Failed logins are viewable by authenticated users" on public.failed_logins;
drop policy if exists "Failed logins can be inserted by anyone" on public.failed_logins;
drop policy if exists "Failed logins can be inserted by anyone (to log failures)" on public.failed_logins;

create policy "Users view own failed logins, admins view all"
  on public.failed_logins for select
  to authenticated
  using (
    email = (select email from public.profiles where id = auth.uid() limit 1)
    or (auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin'
  );

create policy "Allow all inserts for failed logins"
  on public.failed_logins for insert
  with check (true);

-- Step 7: Automatic user_id resolution trigger from profile email
create or replace function public.resolve_user_id_from_email()
returns trigger as $$
begin
  if new.user_id is null and new.user_email is not null then
    select id into new.user_id
    from public.profiles
    where email = new.user_email
    limit 1;
  end if;
  return new;
end;
$$ language plpgsql security definer;

-- Trigger for threat_logs
drop trigger if exists on_threat_log_insert_resolve_user on public.threat_logs;
create trigger on_threat_log_insert_resolve_user
  before insert on public.threat_logs
  for each row execute procedure public.resolve_user_id_from_email();

-- Trigger for alerts
drop trigger if exists on_alert_insert_resolve_user on public.alerts;
create trigger on_alert_insert_resolve_user
  before insert on public.alerts
  for each row execute procedure public.resolve_user_id_from_email();

