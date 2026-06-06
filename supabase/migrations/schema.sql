-- Enable UUID extension if not enabled
create extension if not exists "uuid-ossp";

-- Create profiles table
create table if not exists public.profiles (
  id uuid references auth.users on delete cascade primary key,
  email text not null,
  role text check (role in ('Admin', 'User')) not null default 'User',
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  updated_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable Row Level Security on profiles
alter table public.profiles enable row level security;

-- Profiles RLS Policies (Safe from recursion by using JWT metadata for Admin checks)
create policy "Users can view their own profile, admins can view all"
  on public.profiles for select
  to authenticated
  using (
    auth.uid() = id OR 
    (auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin'
  );

create policy "Users can update their own profile"
  on public.profiles for update
  to authenticated
  using (auth.uid() = id)
  with check (auth.uid() = id);

-- Create threat_alerts table
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
create policy "Threat alerts are viewable by authenticated users"
  on public.threat_alerts for select
  to authenticated
  using (true);

create policy "Threat alerts can be managed by Admin users"
  on public.threat_alerts for all
  to authenticated
  using (
    (auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin'
  );

-- Function to handle new auth user signup and link to profiles
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

-- Trigger to execute handle_new_user function on auth signup
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- Seed Threat Alerts
insert into public.threat_alerts (title, severity, source_ip, status)
values
  ('SQL Injection Attempt Blocked', 'High', '185.220.101.4', 'Resolved'),
  ('Suspicious API Token Generation', 'Medium', '92.40.12.189', 'Active'),
  ('Multiple Failed Admin Login Attempts', 'Critical', '103.245.72.6', 'Active'),
  ('Port Scan Detected on SSH Port 22', 'Low', '198.51.100.12', 'Investigating'),
  ('Outbound High Traffic volume to Unknown IP', 'High', '192.168.1.105', 'Active')
on conflict do nothing;
