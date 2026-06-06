-- Enable UUID extension
create extension if not exists "uuid-ossp";

-- 1. Create profiles table
create table if not exists public.profiles (
  id uuid references auth.users on delete cascade primary key,
  email text not null,
  role text check (role in ('Admin', 'User')) not null default 'User',
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  updated_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable RLS on profiles
alter table public.profiles enable row level security;

-- Profiles RLS Policies (Safe from recursion)
drop policy if exists "Users can view their own profile, admins can view all" on public.profiles;
create policy "Users can view their own profile, admins can view all"
  on public.profiles for select
  to authenticated
  using (
    auth.uid() = id OR 
    (auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin'
  );

drop policy if exists "Users can update their own profile" on public.profiles;
create policy "Users can update their own profile"
  on public.profiles for update
  to authenticated
  using (auth.uid() = id)
  with check (auth.uid() = id);

-- 2. Create threat_alerts table
create table if not exists public.threat_alerts (
  id uuid default gen_random_uuid() primary key,
  title text not null,
  severity text check (severity in ('Low', 'Medium', 'High', 'Critical')) not null,
  source_ip text not null,
  status text check (status in ('Active', 'Investigating', 'Resolved')) default 'Active' not null,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable RLS on threat_alerts
alter table public.threat_alerts enable row level security;

-- Threat Alerts RLS Policies
drop policy if exists "Threat alerts are viewable by authenticated users" on public.threat_alerts;
create policy "Threat alerts are viewable by authenticated users"
  on public.threat_alerts for select
  to authenticated
  using (true);

drop policy if exists "Threat alerts can be managed by Admin users" on public.threat_alerts;
create policy "Threat alerts can be managed by Admin users"
  on public.threat_alerts for all
  to authenticated
  using (
    (auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin'
  );

-- 3. Create phishing_scans table
create table if not exists public.phishing_scans (
  id uuid default gen_random_uuid() primary key,
  target_url text not null,
  result text check (result in ('Clean', 'Suspicious', 'Malicious')) not null,
  confidence_score integer not null,
  scanned_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable RLS on phishing_scans
alter table public.phishing_scans enable row level security;

-- Policies for phishing_scans
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

-- 4. Create failed_logins table
create table if not exists public.failed_logins (
  id uuid default gen_random_uuid() primary key,
  email text not null,
  ip_address text not null,
  attempted_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable RLS on failed_logins
alter table public.failed_logins enable row level security;

-- Policies for failed_logins
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

-- 5. Trigger function to handle user profile creation upon signup
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

-- Trigger configuration
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- Seed data
insert into public.threat_alerts (title, severity, source_ip, status)
values
  ('SQL Injection Attempt Blocked', 'High', '185.220.101.4', 'Resolved'),
  ('Suspicious API Token Generation', 'Medium', '92.40.12.189', 'Active'),
  ('Multiple Failed Admin Login Attempts', 'Critical', '103.245.72.6', 'Active'),
  ('Port Scan Detected on SSH Port 22', 'Low', '198.51.100.12', 'Investigating'),
  ('Outbound High Traffic volume to Unknown IP', 'High', '192.168.1.105', 'Active')
on conflict do nothing;

insert into public.phishing_scans (target_url, result, confidence_score, scanned_at)
values
  ('https://secure-login-paypal-verify.com', 'Malicious', 98, now() - interval '2 hours'),
  ('https://github-auth-token-refresh.net', 'Suspicious', 74, now() - interval '5 hours'),
  ('https://google.com', 'Clean', 100, now() - interval '1 day'),
  ('https://microsoft-support-ticket-382.co', 'Malicious', 92, now() - interval '2 days'),
  ('https://amazon-rewards-claim.info', 'Malicious', 89, now() - interval '3 days'),
  ('https://wikipedia.org', 'Clean', 100, now() - interval '4 days')
on conflict do nothing;

insert into public.failed_logins (email, ip_address, attempted_at)
values
  ('admin@cybershield.ai', '198.51.100.45', now() - interval '1 hour'),
  ('root@cybershield.ai', '103.245.72.6', now() - interval '3 hours'),
  ('operator@cybershield.ai', '185.220.101.4', now() - interval '12 hours'),
  ('guest@cybershield.ai', '92.40.12.189', now() - interval '1 day')
on conflict do nothing;
