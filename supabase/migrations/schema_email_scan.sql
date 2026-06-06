-- Add scan_type and content_snippet columns to phishing_scans
alter table public.phishing_scans 
  add column if not exists scan_type text check (scan_type in ('URL', 'Email')) not null default 'URL',
  add column if not exists content_snippet text;
