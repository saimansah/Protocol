-- ====================================================================
-- PROTOCOL 594: CLASSIFIED EPHEMERAL COMMS DATABASE ARCHITECTURE
-- Run this migration in your Supabase SQL Editor
-- 
-- FEATURES:
-- - Custom 10-digit numeric room code chosen by user (or auto-generated)
-- - Server-side bcrypt hashing for cipher-locked rooms
-- - RLS policies for anonymous/authenticated agents
-- - In-memory ephemeral message guarantee (Zero database logs)
-- ====================================================================

-- 1. Enable cryptographic functions
create extension if not exists pgcrypto;

-- 2. Create Rooms Table
create table if not exists public.rooms (
  id uuid primary key default gen_random_uuid(),
  created_by uuid null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '24 hours'),
  access_type text not null default 'open' check (access_type in ('open', 'password')),
  password_hash text null,
  code text null
);

-- Ensure all columns exist on pre-existing rooms table
alter table public.rooms 
  add column if not exists access_type text not null default 'open' check (access_type in ('open', 'password')),
  add column if not exists password_hash text null,
  add column if not exists code text null;

-- Remove strict foreign key and not-null constraint to support ephemeral / anonymous sessions
-- and eliminate both "violates foreign key constraint rooms_created_by_fkey" and
-- "violates not-null constraint" errors.
alter table public.rooms alter column created_by drop not null;
alter table public.rooms drop constraint if exists rooms_created_by_fkey;

-- Fast lookup index on room code
create index if not exists rooms_code_idx on public.rooms (code);

-- 3. Create Room Members Table
create table if not exists public.room_members (
  room_id uuid references public.rooms(id) on delete cascade,
  user_id uuid not null,
  joined_at timestamptz not null default now(),
  primary key (room_id, user_id)
);

alter table public.room_members drop constraint if exists room_members_user_id_fkey;

-- 4. Enable Row Level Security
alter table public.rooms enable row level security;
alter table public.room_members enable row level security;

-- Policies: Non-recursive policies for rooms and room members
drop policy if exists "Members can view their rooms" on public.rooms;
drop policy if exists "Rooms select policy" on public.rooms;
create policy "Rooms select policy" 
  on public.rooms for select 
  using (true);

drop policy if exists "Users can view their own memberships" on public.room_members;
drop policy if exists "Members select policy" on public.room_members;
create policy "Members select policy" 
  on public.room_members for select 
  using (auth.uid() = user_id);

-- Drop older function signatures to prevent PostgREST overloading cache collisions
drop function if exists public.create_classified_room(text, text);
drop function if exists public.create_classified_room(text, text, text);
drop function if exists public.verify_and_join_classified_room(uuid, text);
drop function if exists public.verify_and_join_classified_room(text, text);
drop function if exists public.get_room_entry_spec(uuid);
drop function if exists public.get_room_entry_spec(text);

-- 5. RPC: Create Classified Room (Allows custom 10-digit room code)
create or replace function public.create_classified_room(
  p_access_type text,
  p_password text default null,
  p_room_code text default null
)
returns json
language plpgsql
security definer
as $$
declare
  v_room_id uuid;
  v_code text := trim(coalesce(p_room_code, ''));
  v_hash text := null;
  v_expires timestamptz;
  v_channel_secret text := null;
  v_creator uuid := coalesce(auth.uid(), gen_random_uuid());
begin
  if auth.uid() is null then
    raise exception 'Unauthenticated terminal session.';
  end if;

  -- Validate or auto-generate 10-digit numeric room code
  if v_code <> '' then
    -- Must be a numeric string up to 10 digits
    if not (v_code ~ '^[0-9]{1,10}$') then
      raise exception 'Room code must be a number with up to 10 digits.';
    end if;

    -- Check if active room with this code already exists
    if exists (select 1 from public.rooms where code = v_code and expires_at > now()) then
      raise exception 'Room code % is currently in use. Please choose another code.', v_code;
    end if;
  else
    -- Auto-generate a random unique 10-digit number
    loop
      v_code := lpad(floor(random() * 9000000000 + 1000000000)::text, 10, '0');
      exit when not exists (select 1 from public.rooms where code = v_code and expires_at > now());
    end loop;
  end if;

  if p_access_type = 'password' then
    if p_password is null or length(p_password) < 8 then
      raise exception 'Security Cipher must contain at least 8 characters.';
    end if;
    v_hash := crypt(p_password, gen_salt('bf', 10));
  end if;

  insert into public.rooms (created_by, access_type, password_hash, code)
  values (v_creator, p_access_type, v_hash, v_code)
  returning id, expires_at into v_room_id, v_expires;

  begin
    insert into public.room_members (room_id, user_id)
    values (v_room_id, auth.uid());
  exception when foreign_key_violation then
    null;
  end;

  if p_access_type = 'password' then
    v_channel_secret := substr(encode(digest(v_room_id::text || ':' || v_hash, 'sha256'), 'hex'), 1, 16);
  end if;

  return json_build_object(
    'room_id', v_room_id,
    'code', v_code,
    'expires_at', v_expires,
    'access_type', p_access_type,
    'channel_secret', v_channel_secret
  );
end;
$$;

-- 6. RPC: Verify and Join Room (Accepts 10-digit room code or UUID)
create or replace function public.verify_and_join_classified_room(
  p_room_id text,
  p_password text default null
)
returns json
language plpgsql
security definer
as $$
declare
  v_room record;
  v_channel_secret text := null;
begin
  if auth.uid() is null then
    return json_build_object('success', false, 'error', 'Unauthenticated connection.');
  end if;

  select * into v_room 
  from public.rooms 
  where (code = p_room_id or id::text = p_room_id) 
    and expires_at > now()
  order by created_at desc
  limit 1;

  if v_room.id is null then
    return json_build_object('success', false, 'error', 'Invalid Room ID or Security Cipher.');
  end if;

  if v_room.access_type = 'password' then
    if p_password is null or v_room.password_hash != crypt(p_password, v_room.password_hash) then
      return json_build_object('success', false, 'error', 'Invalid Room ID or Security Cipher.');
    end if;
    v_channel_secret := substr(encode(digest(v_room.id::text || ':' || v_room.password_hash, 'sha256'), 'hex'), 1, 16);
  end if;

  begin
    insert into public.room_members (room_id, user_id)
    values (v_room.id, auth.uid())
    on conflict (room_id, user_id) do nothing;
  exception when foreign_key_violation then
    null;
  end;

  return json_build_object(
    'success', true,
    'room_id', v_room.id,
    'code', v_room.code,
    'access_type', v_room.access_type,
    'expires_at', v_room.expires_at,
    'channel_secret', v_channel_secret
  );
end;
$$;

-- 7. RPC: Check Room Access Requirements by 10-digit code or UUID
create or replace function public.get_room_entry_spec(p_room_id text)
returns json
language plpgsql
security definer
as $$
declare
  v_room record;
  v_is_member boolean := false;
  v_channel_secret text := null;
begin
  select * into v_room 
  from public.rooms 
  where (code = p_room_id or id::text = p_room_id) 
    and expires_at > now()
  order by created_at desc
  limit 1;

  if v_room.id is null then
    return json_build_object('exists', false);
  end if;

  if auth.uid() is not null then
    select exists (
      select 1 from public.room_members 
      where room_id = v_room.id and user_id = auth.uid()
    ) into v_is_member;
  end if;

  -- Only grant channel secret if the user is verified in room_members
  if v_is_member and v_room.access_type = 'password' then
    v_channel_secret := substr(encode(digest(v_room.id::text || ':' || v_room.password_hash, 'sha256'), 'hex'), 1, 16);
  end if;

  return json_build_object(
    'exists', true,
    'room_id', v_room.id,
    'code', v_room.code,
    'access_type', v_room.access_type,
    'expires_at', v_room.expires_at,
    'is_member', v_is_member,
    'channel_secret', v_channel_secret
  );
end;
$$;

-- 8. Permissions & Schema Cache Reload
grant usage on schema public to anon, authenticated;
grant all on table public.rooms to anon, authenticated;
grant all on table public.room_members to anon, authenticated;

grant execute on function public.create_classified_room(text, text, text) to anon, authenticated;
grant execute on function public.verify_and_join_classified_room(text, text) to anon, authenticated;
grant execute on function public.get_room_entry_spec(text) to anon, authenticated;

-- Force PostgREST to immediately refresh its schema cache
notify pgrst, 'reload schema';
