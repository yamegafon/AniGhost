-- AniGhost Stage 2 — Supabase schema
-- Run this whole file in Supabase Dashboard → SQL Editor.
-- Frontend uses the publishable/anon key only. Never expose service_role keys.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique check (username ~ '^[A-Za-z0-9_]{3,24}$'),
  bio text not null default '' check (char_length(bio) <= 240),
  avatar_url text,
  updated_at timestamptz not null default now()
);
create unique index if not exists profiles_username_lower_unique on public.profiles (lower(username));

create table if not exists public.favorites (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  anime_title text not null,
  created_at timestamptz not null default now(),
  unique (user_id, anime_title)
);

create table if not exists public.anime_watchlists (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  anime_title text not null,
  status text not null check (status in ('watched','later','dropped','planned','watching')),
  updated_at timestamptz not null default now(),
  unique (user_id, anime_title)
);

create table if not exists public.episode_history (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  anime_title text not null,
  season integer not null default 1 check (season > 0),
  episode integer not null check (episode > 0),
  watched boolean not null default false,
  opened_at timestamptz not null default now(),
  unique (user_id, anime_title, season, episode)
);

create table if not exists public.friend_requests (
  id uuid primary key default gen_random_uuid(),
  requester_id uuid not null references auth.users(id) on delete cascade,
  receiver_id uuid not null references auth.users(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending','accepted')),
  created_at timestamptz not null default now(),
  constraint friend_requests_not_self check (requester_id <> receiver_id)
);
create unique index if not exists friend_requests_pair_unique
  on public.friend_requests (least(requester_id, receiver_id), greatest(requester_id, receiver_id));

-- Foundation for the achievements system; the UI/achievement rules can be added later.
create table if not exists public.user_achievements (
  user_id uuid not null references auth.users(id) on delete cascade,
  achievement_key text not null,
  unlocked_at timestamptz not null default now(),
  metadata jsonb not null default '{}'::jsonb,
  primary key (user_id, achievement_key)
);

-- Create a starter profile after email registration. Username can be edited in the profile page.
create or replace function public.handle_new_anighost_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  base_name text;
  candidate text;
  suffix integer := 0;
begin
  base_name := coalesce(nullif(new.raw_user_meta_data ->> 'username', ''), split_part(coalesce(new.email, 'anime_fan'), '@', 1), 'anime_fan');
  base_name := regexp_replace(lower(base_name), '[^a-z0-9_]', '_', 'g');
  base_name := trim(both '_' from base_name);
  if char_length(base_name) < 3 then base_name := 'anime_fan'; end if;
  base_name := left(base_name, 24);
  candidate := base_name;
  while exists (select 1 from public.profiles p where p.username = candidate) loop
    suffix := suffix + 1;
    candidate := left(base_name, 24 - char_length(suffix::text) - 1) || '_' || suffix::text;
  end loop;
  insert into public.profiles (id, username)
  values (new.id, candidate)
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_anighost on auth.users;
create trigger on_auth_user_created_anighost
after insert on auth.users
for each row execute procedure public.handle_new_anighost_user();

alter table public.profiles enable row level security;
alter table public.favorites enable row level security;
alter table public.anime_watchlists enable row level security;
alter table public.episode_history enable row level security;
alter table public.friend_requests enable row level security;
alter table public.user_achievements enable row level security;

drop policy if exists "profiles readable by signed-in users" on public.profiles;
create policy "profiles readable by signed-in users" on public.profiles
  for select to authenticated using (true);
drop policy if exists "users insert own profile" on public.profiles;
create policy "users insert own profile" on public.profiles
  for insert to authenticated with check (id = (select auth.uid()));
drop policy if exists "users update own profile" on public.profiles;
create policy "users update own profile" on public.profiles
  for update to authenticated using (id = (select auth.uid())) with check (id = (select auth.uid()));

drop policy if exists "users read own favorites" on public.favorites;
create policy "users read own favorites" on public.favorites
  for select to authenticated using (user_id = (select auth.uid()));
drop policy if exists "users manage own favorites" on public.favorites;
create policy "users manage own favorites" on public.favorites
  for all to authenticated using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

drop policy if exists "watchlists readable by signed-in users" on public.anime_watchlists;
create policy "watchlists readable by signed-in users" on public.anime_watchlists
  for select to authenticated using (true);
drop policy if exists "users manage own watchlists" on public.anime_watchlists;
create policy "users manage own watchlists" on public.anime_watchlists
  for all to authenticated using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

drop policy if exists "users read own episode history" on public.episode_history;
create policy "users read own episode history" on public.episode_history
  for select to authenticated using (user_id = (select auth.uid()));
drop policy if exists "users manage own episode history" on public.episode_history;
create policy "users manage own episode history" on public.episode_history
  for all to authenticated using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

drop policy if exists "participants read friend requests" on public.friend_requests;
create policy "participants read friend requests" on public.friend_requests
  for select to authenticated using (requester_id = (select auth.uid()) or receiver_id = (select auth.uid()));
drop policy if exists "users send friend requests" on public.friend_requests;
create policy "users send friend requests" on public.friend_requests
  for insert to authenticated with check (requester_id = (select auth.uid()) and receiver_id <> (select auth.uid()) and status = 'pending');
drop policy if exists "receiver accepts friend requests" on public.friend_requests;
create policy "receiver accepts friend requests" on public.friend_requests
  for update to authenticated using (receiver_id = (select auth.uid()) and status = 'pending') with check (receiver_id = (select auth.uid()) and status = 'accepted');
drop policy if exists "participants remove friend requests" on public.friend_requests;
create policy "participants remove friend requests" on public.friend_requests
  for delete to authenticated using (requester_id = (select auth.uid()) or receiver_id = (select auth.uid()));

drop policy if exists "users read own achievements" on public.user_achievements;
create policy "users read own achievements" on public.user_achievements
  for select to authenticated using (user_id = (select auth.uid()));

grant usage on schema public to authenticated;
grant select, insert, update on public.profiles to authenticated;
grant select, insert, update, delete on public.favorites to authenticated;
grant select, insert, update, delete on public.anime_watchlists to authenticated;
grant select, insert, update, delete on public.episode_history to authenticated;
grant select, insert, delete on public.friend_requests to authenticated;
revoke update on public.friend_requests from authenticated;
grant update (status) on public.friend_requests to authenticated;
grant select on public.user_achievements to authenticated;


-- AniGhost Stage 4: background images and profile media storage.
alter table public.profiles add column if not exists background_url text;
alter table public.profiles add column if not exists avatar_url text;

-- Public read bucket for profile avatars/backgrounds; authenticated users can only upload into their own UID folder.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('profile-media', 'profile-media', true, 5242880, array['image/jpeg','image/png','image/webp','image/gif'])
on conflict (id) do update set public = true, file_size_limit = 5242880, allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "profile media public read" on storage.objects;
create policy "profile media public read" on storage.objects for select using (bucket_id = 'profile-media');
drop policy if exists "users upload own profile media" on storage.objects;
create policy "users upload own profile media" on storage.objects for insert to authenticated with check (bucket_id = 'profile-media' and (storage.foldername(name))[1] = (select auth.uid())::text);
drop policy if exists "users update own profile media" on storage.objects;
create policy "users update own profile media" on storage.objects for update to authenticated using (bucket_id = 'profile-media' and (storage.foldername(name))[1] = (select auth.uid())::text) with check (bucket_id = 'profile-media' and (storage.foldername(name))[1] = (select auth.uid())::text);
drop policy if exists "users delete own profile media" on storage.objects;
create policy "users delete own profile media" on storage.objects for delete to authenticated using (bucket_id = 'profile-media' and (storage.foldername(name))[1] = (select auth.uid())::text);
