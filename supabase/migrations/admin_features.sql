-- ============================================================
-- CyberShield AI — Admin Panel Migration (Phase 7)
-- Run this entire script in your Supabase SQL Editor
-- ============================================================

-- Step 1: Add is_suspended column to profiles
alter table public.profiles
  add column if not exists is_suspended boolean default false not null;

-- Step 2: Trigger function to prevent non-admins from updating roles/suspension
create or replace function public.preserve_role_on_update()
returns trigger as $$
begin
  -- Enforce that only Admin can modify sensitive fields (role and is_suspended)
  if (coalesce(auth.jwt() -> 'user_metadata' ->> 'role', '') != 'Admin') then
    if (new.role is distinct from old.role or new.is_suspended is distinct from old.is_suspended) then
      raise exception 'Unauthorized: Only administrators can modify user roles or suspension status';
    end if;
  end if;
  return new;
end;
$$ language plpgsql security definer;

-- Register trigger on public.profiles
drop trigger if exists on_profile_role_update on public.profiles;
create trigger on_profile_role_update
  before update on public.profiles
  for each row execute procedure public.preserve_role_on_update();

-- Step 3: RPC function for Admins to delete a user
create or replace function public.delete_user(target_user_id uuid)
returns void as $$
begin
  -- Enforce that only Admin can execute this function
  if (coalesce(auth.jwt() -> 'user_metadata' ->> 'role', '') != 'Admin') then
    raise exception 'Unauthorized: Only administrators can delete operator accounts';
  end if;

  -- Prevent deleting oneself
  if (auth.uid() = target_user_id) then
    raise exception 'Conflict: You cannot delete your own active administrator session';
  end if;

  -- Perform delete on auth.users which cascades to profiles
  delete from auth.users where id = target_user_id;
end;
$$ language plpgsql security definer;

-- Step 4: Ensure Admins have policies to update and delete profiles
drop policy if exists "Admins can update any profile" on public.profiles;
create policy "Admins can update any profile"
  on public.profiles for update
  to authenticated
  using (
    (auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin'
  )
  with check (
    (auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin'
  );

drop policy if exists "Admins can delete any profile" on public.profiles;
create policy "Admins can delete any profile"
  on public.profiles for delete
  to authenticated
  using (
    (auth.jwt() -> 'user_metadata' ->> 'role') = 'Admin'
  );
