-- Create phishing_scans table
create table if not exists public.phishing_scans (
  id uuid default gen_random_uuid() primary key,
  target_url text not null,
  result text check (result in ('Clean', 'Suspicious', 'Malicious')) not null,
  confidence_score integer not null, -- percentage 0-100
  scanned_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable RLS on phishing_scans
alter table public.phishing_scans enable row level security;

-- Policies for phishing_scans
create policy "Phishing scans are viewable by authenticated users"
  on public.phishing_scans for select
  to authenticated
  using (true);

create policy "Phishing scans can be inserted by authenticated users"
  on public.phishing_scans for insert
  to authenticated
  with check (true);

-- Create failed_logins table
create table if not exists public.failed_logins (
  id uuid default gen_random_uuid() primary key,
  email text not null,
  ip_address text not null,
  attempted_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable RLS on failed_logins
alter table public.failed_logins enable row level security;

-- Policies for failed_logins
create policy "Failed logins are viewable by authenticated users"
  on public.failed_logins for select
  to authenticated
  using (true);

create policy "Failed logins can be inserted by anyone (to log failures)"
  on public.failed_logins for insert
  to anon, authenticated
  with check (true);

-- Seed data for phishing_scans
insert into public.phishing_scans (target_url, result, confidence_score, scanned_at)
values
  ('https://secure-login-paypal-verify.com', 'Malicious', 98, now() - interval '2 hours'),
  ('https://github-auth-token-refresh.net', 'Suspicious', 74, now() - interval '5 hours'),
  ('https://google.com', 'Clean', 100, now() - interval '1 day'),
  ('https://microsoft-support-ticket-382.co', 'Malicious', 92, now() - interval '2 days'),
  ('https://amazon-rewards-claim.info', 'Malicious', 89, now() - interval '3 days'),
  ('https://wikipedia.org', 'Clean', 100, now() - interval '4 days')
on conflict do nothing;

-- Seed data for failed_logins
insert into public.failed_logins (email, ip_address, attempted_at)
values
  ('admin@cybershield.ai', '198.51.100.45', now() - interval '1 hour'),
  ('root@cybershield.ai', '103.245.72.6', now() - interval '3 hours'),
  ('operator@cybershield.ai', '185.220.101.4', now() - interval '12 hours'),
  ('guest@cybershield.ai', '92.40.12.189', now() - interval '1 day')
on conflict do nothing;
