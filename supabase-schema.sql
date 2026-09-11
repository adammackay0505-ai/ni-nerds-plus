
-- IMPORTANT: Supabase Auth email confirmation is an Auth setting, not a Postgres setting.
-- For NI Nerds+ no-confirmation signup, open Supabase Dashboard -> Authentication ->
-- Providers -> Email and turn OFF 'Confirm email'. Do not try to configure this with SQL.
-- NI Nerds+ cloud database
-- Run in Supabase SQL Editor before using the website.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique,
  display_name text not null,
  avatar_url text,
  location text default '',
  bio text default '',
  interests text default '',
  status text not null default 'Online',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  discord_id text,
  discord_username text,
  discord_avatar_url text
);

-- Discord linking fields for existing installations.
alter table public.profiles add column if not exists discord_id text;
alter table public.profiles add column if not exists discord_username text;
alter table public.profiles add column if not exists discord_avatar_url text;

create table if not exists public.posts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  content text not null default '',
  media_url text,
  media_type text,
  created_at timestamptz not null default now()
);

-- Add photo fields to existing installations without destroying posts.
alter table public.posts add column if not exists media_url text;
alter table public.posts add column if not exists media_type text;
alter table public.posts alter column content set default '';
alter table public.posts drop constraint if exists posts_content_check;
alter table public.posts add constraint posts_content_check check (char_length(content) between 0 and 5000 and (char_length(content) > 0 or media_url is not null));

create table if not exists public.comments (
  id uuid primary key default gen_random_uuid(),
  post_id uuid not null references public.posts(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  content text not null check (char_length(content) between 1 and 1000),
  created_at timestamptz not null default now()
);

create table if not exists public.post_likes (
  post_id uuid not null references public.posts(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (post_id,user_id)
);

create table if not exists public.friend_requests (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid not null references public.profiles(id) on delete cascade,
  receiver_id uuid not null references public.profiles(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending','accepted','declined')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check(sender_id <> receiver_id)
);
create unique index if not exists friend_requests_pending_pair on public.friend_requests(sender_id,receiver_id) where status='pending';

create table if not exists public.friendships (
  user_id uuid not null references public.profiles(id) on delete cascade,
  friend_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key(user_id,friend_id),
  check(user_id <> friend_id)
);

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid not null references public.profiles(id) on delete cascade,
  receiver_id uuid not null references public.profiles(id) on delete cascade,
  content text not null check(char_length(content) between 1 and 5000),
  created_at timestamptz not null default now(),
  check(sender_id <> receiver_id)
);
create index if not exists messages_pair_idx on public.messages(sender_id,receiver_id,created_at);
create index if not exists messages_receiver_idx on public.messages(receiver_id,created_at);

create or replace function public.set_updated_at() returns trigger language plpgsql as $$
begin new.updated_at=now(); return new; end; $$;
drop trigger if exists profiles_updated_at on public.profiles;
create trigger profiles_updated_at before update on public.profiles for each row execute function public.set_updated_at();
drop trigger if exists requests_updated_at on public.friend_requests;
create trigger requests_updated_at before update on public.friend_requests for each row execute function public.set_updated_at();

create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$
declare base_username text; candidate text; n int:=0;
begin
  base_username:=lower(regexp_replace(coalesce(new.raw_user_meta_data->>'username',split_part(new.email,'@',1)),'[^a-zA-Z0-9_]','','g'));
  if base_username='' then base_username:='nerd'; end if;
  candidate:=left(base_username,24);
  while exists(select 1 from public.profiles where username=candidate) loop
    n:=n+1; candidate:=left(base_username,18)||'_'||substr(replace(new.id::text,'-',''),1,6)||case when n>1 then '_'||n else '' end;
  end loop;
  insert into public.profiles(id,username,display_name) values(new.id,candidate,coalesce(new.raw_user_meta_data->>'display_name',candidate)) on conflict(id) do nothing;
  return new;
end; $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();


-- Make the RPC functions callable through Supabase REST/PostgREST.
grant usage on schema public to anon, authenticated;

-- Account/profile bootstrap helpers. These make account creation reliable even if the
-- auth trigger is delayed or a project was configured after the user signed up.
create or replace function public.is_username_available(requested_username text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(
    requested_username is not null
    and requested_username = lower(requested_username)
    and requested_username ~ '^[a-z0-9_]{3,30}$'
    and not exists (
      select 1 from public.profiles
      where lower(username) = requested_username
    ), false
  );
$$;

create or replace function public.ensure_my_profile()
returns void
language plpgsql
security definer
set search_path=public
as $$
declare
  uid uuid := auth.uid();
  base_username text;
  candidate text;
  n int := 0;
  display_name text;
begin
  if uid is null then raise exception 'Not authenticated'; end if;
  if exists(select 1 from public.profiles where id=uid) then return; end if;

  select lower(regexp_replace(coalesce(raw_user_meta_data->>'username',split_part(email,'@',1)),'[^a-zA-Z0-9_]','','g')),
         coalesce(raw_user_meta_data->>'display_name','Nerd')
    into base_username, display_name
    from auth.users where id=uid;

  if base_username is null or base_username='' then base_username:='nerd'; end if;
  candidate:=left(base_username,24);
  while exists(select 1 from public.profiles where username=candidate) loop
    n:=n+1;
    candidate:=left(base_username,17)||'_'||substr(replace(uid::text,'-',''),1,7)||case when n>1 then '_'||n else '' end;
  end loop;

  insert into public.profiles(id,username,display_name)
  values(uid,candidate,left(coalesce(display_name,candidate),50))
  on conflict(id) do nothing;
end;
$$;

revoke all on function public.is_username_available(text) from public;
revoke all on function public.ensure_my_profile() from public;
grant execute on function public.is_username_available(text) to anon,authenticated;
grant execute on function public.ensure_my_profile() to authenticated;

-- Secure friend-request operations. These prevent users from spoofing another account.
create or replace function public.accept_friend_request(request_id uuid)
returns void language plpgsql security definer set search_path = public as $$
declare r public.friend_requests;
begin
  select fr.* into r from public.friend_requests fr
  where fr.id=accept_friend_request.request_id and fr.receiver_id=auth.uid() and fr.status='pending'
  for update;
  if not found then raise exception 'Friend request not found or already handled'; end if;
  update public.friend_requests fr set status='accepted', updated_at=now() where fr.id=r.id;
  insert into public.friendships(user_id,friend_id) values(r.sender_id,r.receiver_id),(r.receiver_id,r.sender_id) on conflict do nothing;
end; $$;

create or replace function public.decline_friend_request(request_id uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  update public.friend_requests fr set status='declined', updated_at=now() where fr.id=decline_friend_request.request_id and fr.receiver_id=auth.uid() and fr.status='pending';
  if not found then raise exception 'Friend request not found or already handled'; end if;
end; $$;

create or replace function public.cancel_friend_request(request_id uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  delete from public.friend_requests fr where fr.id=cancel_friend_request.request_id and fr.sender_id=auth.uid() and fr.status='pending';
  if not found then raise exception 'Friend request not found or already handled'; end if;
end; $$;

create or replace function public.remove_friend(other_id uuid)
returns void language plpgsql security invoker as $$
begin
  delete from public.friendships where (user_id=auth.uid() and friend_id=other_id) or (user_id=other_id and friend_id=auth.uid());
end; $$;

-- RLS
alter table public.profiles enable row level security;
alter table public.posts enable row level security;
alter table public.comments enable row level security;
alter table public.post_likes enable row level security;
alter table public.friend_requests enable row level security;
alter table public.friendships enable row level security;
alter table public.messages enable row level security;

-- profiles
drop policy if exists "profiles readable by authenticated" on public.profiles;
drop policy if exists "own profile insert" on public.profiles;
drop policy if exists "own profile update" on public.profiles;
create policy "profiles readable by authenticated" on public.profiles for select to authenticated using(true);
create policy "own profile insert" on public.profiles for insert to authenticated with check(auth.uid()=id);
create policy "own profile update" on public.profiles for update to authenticated using(auth.uid()=id) with check(auth.uid()=id);

-- posts/comments/likes
drop policy if exists "posts readable" on public.posts;
drop policy if exists "own posts insert" on public.posts;
drop policy if exists "own posts delete" on public.posts;
drop policy if exists "comments readable" on public.comments;
drop policy if exists "own comments insert" on public.comments;
drop policy if exists "own comments delete" on public.comments;
drop policy if exists "likes readable" on public.post_likes;
drop policy if exists "own likes insert" on public.post_likes;
drop policy if exists "own likes delete" on public.post_likes;
create policy "posts readable" on public.posts for select to authenticated using(true);
create policy "own posts insert" on public.posts for insert to authenticated with check(auth.uid()=user_id);
create policy "own posts delete" on public.posts for delete to authenticated using(auth.uid()=user_id);
create policy "comments readable" on public.comments for select to authenticated using(true);
create policy "own comments insert" on public.comments for insert to authenticated with check(auth.uid()=user_id);
create policy "own comments delete" on public.comments for delete to authenticated using(auth.uid()=user_id);
create policy "likes readable" on public.post_likes for select to authenticated using(true);
create policy "own likes insert" on public.post_likes for insert to authenticated with check(auth.uid()=user_id);
create policy "own likes delete" on public.post_likes for delete to authenticated using(auth.uid()=user_id);

-- requests: involved users can read; direct insert must be sender.
drop policy if exists "involved requests readable" on public.friend_requests;
drop policy if exists "send own request" on public.friend_requests;
create policy "involved requests readable" on public.friend_requests for select to authenticated using(auth.uid()=sender_id or auth.uid()=receiver_id);
create policy "send own request" on public.friend_requests for insert to authenticated with check(auth.uid()=sender_id and sender_id<>receiver_id);
-- Updates/deletes are deliberately not exposed; RPCs enforce sender/receiver ownership.

-- friendships: users can see their own relationship rows. Mutations happen through RPCs.
drop policy if exists "own friendships readable" on public.friendships;
create policy "own friendships readable" on public.friendships for select to authenticated using(auth.uid()=user_id or auth.uid()=friend_id);

-- messages: only sender/receiver can read. Only a friend can receive a new message.
drop policy if exists "participants read messages" on public.messages;
drop policy if exists "friends can send messages" on public.messages;
drop policy if exists "own sent messages delete" on public.messages;
create policy "participants read messages" on public.messages for select to authenticated using(auth.uid()=sender_id or auth.uid()=receiver_id);
create policy "friends can send messages" on public.messages for insert to authenticated with check(
  auth.uid()=sender_id and exists(select 1 from public.friendships f where f.user_id=auth.uid() and f.friend_id=receiver_id)
);
create policy "own sent messages delete" on public.messages for delete to authenticated using(auth.uid()=sender_id);

-- RPC permissions
revoke all on function public.accept_friend_request(uuid) from public;
revoke all on function public.decline_friend_request(uuid) from public;
revoke all on function public.cancel_friend_request(uuid) from public;
revoke all on function public.remove_friend(uuid) from public;
grant execute on function public.accept_friend_request(uuid) to authenticated;
grant execute on function public.decline_friend_request(uuid) to authenticated;
grant execute on function public.cancel_friend_request(uuid) to authenticated;
grant execute on function public.remove_friend(uuid) to authenticated;

grant select,insert,update on public.profiles to authenticated;
grant select,insert,delete on public.posts to authenticated;
grant select,insert,delete on public.comments to authenticated;
grant select,insert,delete on public.post_likes to authenticated;
grant select,insert on public.friend_requests to authenticated;
grant select on public.friendships to authenticated;
grant select,insert,delete on public.messages to authenticated;

-- Avatar storage
insert into storage.buckets(id,name,public) values('avatars','avatars',true) on conflict(id) do update set public=true;
drop policy if exists "avatar upload own folder" on storage.objects;
drop policy if exists "avatar update own folder" on storage.objects;
drop policy if exists "avatar delete own folder" on storage.objects;
create policy "avatar upload own folder" on storage.objects for insert to authenticated with check(bucket_id='avatars' and (storage.foldername(name))[1]=auth.uid()::text);
create policy "avatar update own folder" on storage.objects for update to authenticated using(bucket_id='avatars' and (storage.foldername(name))[1]=auth.uid()::text) with check(bucket_id='avatars' and (storage.foldername(name))[1]=auth.uid()::text);
create policy "avatar delete own folder" on storage.objects for delete to authenticated using(bucket_id='avatars' and (storage.foldername(name))[1]=auth.uid()::text);

-- Post photo storage. Photos are public so feed/profile images can render on GitHub Pages.
insert into storage.buckets(id,name,public) values('post-images','post-images',true) on conflict(id) do update set public=true;
drop policy if exists "post image upload own folder" on storage.objects;
drop policy if exists "post image update own folder" on storage.objects;
drop policy if exists "post image delete own folder" on storage.objects;
create policy "post image upload own folder" on storage.objects for insert to authenticated with check(bucket_id='post-images' and (storage.foldername(name))[1]=auth.uid()::text);
create policy "post image update own folder" on storage.objects for update to authenticated using(bucket_id='post-images' and (storage.foldername(name))[1]=auth.uid()::text) with check(bucket_id='post-images' and (storage.foldername(name))[1]=auth.uid()::text);
create policy "post image delete own folder" on storage.objects for delete to authenticated using(bucket_id='post-images' and (storage.foldername(name))[1]=auth.uid()::text);

-- Optional realtime for live DMs/feed. Enable these in Supabase if your project doesn't already have them.
do $$
begin
  if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='messages') then
    alter publication supabase_realtime add table public.messages;
  end if;
  if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='friend_requests') then
    alter publication supabase_realtime add table public.friend_requests;
  end if;
end $$;

-- Refresh PostgREST so newly created RPC functions are immediately available to the website.
notify pgrst, 'reload schema';

-- Reliable direct-message RPCs. The website uses these functions so messages
-- are persisted in public.messages and loaded consistently across devices.
create or replace function public.get_conversation_messages(other_user_id uuid)
returns table (
  id uuid,
  sender_id uuid,
  receiver_id uuid,
  content text,
  created_at timestamptz
)
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then
    raise exception 'You must be logged in.';
  end if;

  if not exists (
    select 1 from public.friendships f
    where f.user_id = auth.uid()
      and f.friend_id = other_user_id
  ) then
    raise exception 'You can only view messages with friends.';
  end if;

  return query
  select m.id, m.sender_id, m.receiver_id, m.content, m.created_at
  from public.messages m
  where (m.sender_id = auth.uid() and m.receiver_id = other_user_id)
     or (m.sender_id = other_user_id and m.receiver_id = auth.uid())
  order by m.created_at asc;
end;
$$;

create or replace function public.send_message(recipient_id uuid, message_content text)
returns public.messages
language plpgsql
security definer
set search_path = public
as $$
declare
  new_message public.messages;
  clean_content text;
begin
  if auth.uid() is null then
    raise exception 'You must be logged in.';
  end if;

  clean_content := btrim(message_content);

  if clean_content is null or char_length(clean_content) = 0 then
    raise exception 'Message cannot be empty.';
  end if;

  if char_length(clean_content) > 5000 then
    raise exception 'Message is too long.';
  end if;

  if recipient_id = auth.uid() then
    raise exception 'You cannot message yourself.';
  end if;

  if not exists (
    select 1 from public.friendships f
    where f.user_id = auth.uid()
      and f.friend_id = recipient_id
  ) then
    raise exception 'You can only message friends.';
  end if;

  insert into public.messages(sender_id, receiver_id, content)
  values(auth.uid(), recipient_id, clean_content)
  returning * into new_message;

  return new_message;
end;
$$;

revoke all on function public.get_conversation_messages(uuid) from public;
revoke all on function public.send_message(uuid,text) from public;
grant execute on function public.get_conversation_messages(uuid) to authenticated;
grant execute on function public.send_message(uuid,text) to authenticated;

notify pgrst, 'reload schema';

-- NI Nerds+ live updates: publish app tables to Supabase Realtime.
-- Safe to run repeatedly; each table is only added if it is not already present.
do $$
declare
  t text;
begin
  foreach t in array array['profiles','posts','comments','post_likes','friend_requests','friendships','messages'] loop
    if not exists (
      select 1
      from pg_publication_tables
      where pubname = 'supabase_realtime'
        and schemaname = 'public'
        and tablename = t
    ) then
      execute format('alter publication supabase_realtime add table public.%I', t);
    end if;
  end loop;
end $$;

notify pgrst, 'reload schema';

-- NI Nerds+ group chats
create table if not exists public.group_chats (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(btrim(name)) between 1 and 80),
  creator_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.group_chat_members (
  group_id uuid not null references public.group_chats(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  role text not null default 'member' check (role in ('owner','member')),
  joined_at timestamptz not null default now(),
  primary key (group_id,user_id)
);

create table if not exists public.group_messages (
  id uuid primary key default gen_random_uuid(),
  group_id uuid not null references public.group_chats(id) on delete cascade,
  sender_id uuid not null references public.profiles(id) on delete cascade,
  content text not null check (char_length(btrim(content)) between 1 and 5000),
  created_at timestamptz not null default now()
);

create index if not exists group_members_user_idx on public.group_chat_members(user_id,group_id);
create index if not exists group_messages_group_idx on public.group_messages(group_id,created_at);

alter table public.group_chats enable row level security;
alter table public.group_chat_members enable row level security;
alter table public.group_messages enable row level security;

drop policy if exists "members can read groups" on public.group_chats;
create policy "members can read groups" on public.group_chats for select to authenticated
using (exists(select 1 from public.group_chat_members m where m.group_id=id and m.user_id=auth.uid()));

create or replace function public.is_group_member(group_id_input uuid,user_id_input uuid)
returns boolean
language sql
security definer
set search_path=public
stable
as $$
  select exists(select 1 from public.group_chat_members where group_id=group_id_input and user_id=user_id_input);
$$;
revoke all on function public.is_group_member(uuid,uuid) from public;
grant execute on function public.is_group_member(uuid,uuid) to authenticated;

drop policy if exists "members can read group members" on public.group_chat_members;
create policy "members can read group members" on public.group_chat_members for select to authenticated
using (public.is_group_member(group_chat_members.group_id,auth.uid()));

drop policy if exists "members can read group messages" on public.group_messages;
create policy "members can read group messages" on public.group_messages for select to authenticated
using (exists(select 1 from public.group_chat_members m where m.group_id=group_messages.group_id and m.user_id=auth.uid()));

drop policy if exists "members can delete own group messages" on public.group_messages;
create policy "members can delete own group messages" on public.group_messages for delete to authenticated
using (sender_id=auth.uid());

-- Group creation is server-side and only permits groups containing the creator's friends.
create or replace function public.create_group_chat(group_name text, member_ids uuid[])
returns public.group_chats
language plpgsql
security definer
set search_path=public
as $$
declare
  new_group public.group_chats;
  clean_name text;
  selected_count int;
  friend_count int;
begin
  if auth.uid() is null then raise exception 'You must be logged in.'; end if;
  clean_name:=btrim(group_name);
  if clean_name is null or char_length(clean_name)=0 then raise exception 'Group name cannot be empty.'; end if;
  if char_length(clean_name)>80 then raise exception 'Group name is too long.'; end if;
  if coalesce(array_length(member_ids,1),0)<1 then raise exception 'Choose at least one friend.'; end if;

  select count(distinct x) into selected_count from unnest(member_ids) x where x<>auth.uid();
  select count(distinct x) into friend_count
  from unnest(member_ids) x
  where x<>auth.uid()
    and exists(select 1 from public.friendships f where f.user_id=auth.uid() and f.friend_id=x);

  if selected_count<>friend_count then raise exception 'You can only add friends to a group.'; end if;

  insert into public.group_chats(name,creator_id) values(clean_name,auth.uid()) returning * into new_group;
  insert into public.group_chat_members(group_id,user_id,role) values(new_group.id,auth.uid(),'owner') on conflict do nothing;
  insert into public.group_chat_members(group_id,user_id,role)
  select new_group.id,x,'member' from unnest(member_ids) x where x<>auth.uid() on conflict do nothing;
  return new_group;
end;
$$;

-- Group message RPCs enforce membership regardless of frontend controls.
create or replace function public.get_group_messages(group_id_input uuid)
returns table(id uuid,sender_id uuid,group_id uuid,content text,created_at timestamptz)
language plpgsql
security definer
set search_path=public
as $$
begin
  if auth.uid() is null then raise exception 'You must be logged in.'; end if;
  if not exists(select 1 from public.group_chat_members where group_chat_members.group_id=group_id_input and user_id=auth.uid()) then
    raise exception 'You are not a member of this group.';
  end if;
  return query select m.id,m.sender_id,m.group_id,m.content,m.created_at
  from public.group_messages m where m.group_id=group_id_input order by m.created_at asc;
end;
$$;

create or replace function public.send_group_message(group_id_input uuid,message_content text)
returns public.group_messages
language plpgsql
security definer
set search_path=public
as $$
declare new_message public.group_messages; clean_content text;
begin
  if auth.uid() is null then raise exception 'You must be logged in.'; end if;
  clean_content:=btrim(message_content);
  if clean_content is null or char_length(clean_content)=0 then raise exception 'Message cannot be empty.'; end if;
  if char_length(clean_content)>5000 then raise exception 'Message is too long.'; end if;
  if not exists(select 1 from public.group_chat_members where group_chat_members.group_id=group_id_input and user_id=auth.uid()) then
    raise exception 'You are not a member of this group.';
  end if;
  insert into public.group_messages(group_id,sender_id,content) values(group_id_input,auth.uid(),clean_content) returning * into new_message;
  return new_message;
end;
$$;

revoke all on function public.create_group_chat(text,uuid[]) from public;
revoke all on function public.get_group_messages(uuid) from public;
revoke all on function public.send_group_message(uuid,text) from public;
grant execute on function public.create_group_chat(text,uuid[]) to authenticated;
grant execute on function public.get_group_messages(uuid) to authenticated;
grant execute on function public.send_group_message(uuid,text) to authenticated;
grant select on public.group_chats to authenticated;
grant select on public.group_chat_members to authenticated;
grant select,delete on public.group_messages to authenticated;

-- Admin stickers: the exact account @bluie is the only account allowed to grant/revoke them.
create table if not exists public.admin_stickers (
  member_id uuid primary key references public.profiles(id) on delete cascade,
  granted_by uuid not null references public.profiles(id) on delete cascade,
  granted_at timestamptz not null default now()
);

alter table public.admin_stickers enable row level security;
drop policy if exists "admin stickers readable" on public.admin_stickers;
create policy "admin stickers readable" on public.admin_stickers for select to authenticated using(true);

create or replace function public.is_ni_nerds_admin()
returns boolean
language sql
security definer
set search_path=public
stable
as $$
  select lower(coalesce((select username from public.profiles where id=auth.uid()),''))='bluie';
$$;

create or replace function public.grant_admin_sticker(target_user_id uuid)
returns boolean
language plpgsql
security definer
set search_path=public
as $$
begin
  if auth.uid() is null or not public.is_ni_nerds_admin() then raise exception 'Only @bluie can manage admin stickers.'; end if;
  if target_user_id=auth.uid() then raise exception 'You cannot apply an admin sticker to yourself.'; end if;
  if not exists(select 1 from public.profiles where id=target_user_id) then raise exception 'Member not found.'; end if;
  insert into public.admin_stickers(member_id,granted_by) values(target_user_id,auth.uid()) on conflict(member_id) do update set granted_by=excluded.granted_by,granted_at=now();
  return true;
end;
$$;

create or replace function public.remove_admin_sticker(target_user_id uuid)
returns boolean
language plpgsql
security definer
set search_path=public
as $$
begin
  if auth.uid() is null or not public.is_ni_nerds_admin() then raise exception 'Only @bluie can manage admin stickers.'; end if;
  delete from public.admin_stickers where member_id=target_user_id;
  return true;
end;
$$;

revoke all on function public.is_ni_nerds_admin() from public;
revoke all on function public.grant_admin_sticker(uuid) from public;
revoke all on function public.remove_admin_sticker(uuid) from public;
grant execute on function public.is_ni_nerds_admin() to authenticated;
grant execute on function public.grant_admin_sticker(uuid) to authenticated;
grant execute on function public.remove_admin_sticker(uuid) to authenticated;
grant select on public.admin_stickers to authenticated;

-- Live updates for groups and admin stickers.
do $$
declare t text;
begin
  foreach t in array array['group_chats','group_chat_members','group_messages','admin_stickers'] loop
    if not exists(select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename=t) then
      execute format('alter publication supabase_realtime add table public.%I',t);
    end if;
  end loop;
end $$;

notify pgrst, 'reload schema';

-- ============================================================
-- NERD JUMP
-- All authenticated members can read. Only users with an admin
-- sticker (or @bluie, the sticker manager) can send text/images.
-- ============================================================
create table if not exists public.nerd_jump_messages (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  content text not null default '',
  media_url text,
  media_type text,
  created_at timestamptz not null default now(),
  constraint nerd_jump_content_check check (length(trim(content)) > 0 or media_url is not null)
);

alter table public.nerd_jump_messages enable row level security;
drop policy if exists "nerd jump readable by members" on public.nerd_jump_messages;
create policy "nerd jump readable by members" on public.nerd_jump_messages
for select to authenticated using (true);

-- Admin-only inserts go through the security-definer RPC below.
drop policy if exists "nerd jump direct insert" on public.nerd_jump_messages;

create or replace function public.is_nerd_jump_admin()
returns boolean
language sql
security definer
set search_path=public
stable
as $$
  select exists(select 1 from public.admin_stickers where member_id=auth.uid())
      or lower(coalesce((select username from public.profiles where id=auth.uid()),''))='bluie';
$$;

create or replace function public.send_nerd_jump_message(message_content text, image_url text default null, image_type text default null)
returns public.nerd_jump_messages
language plpgsql
security definer
set search_path=public
as $$
declare row_out public.nerd_jump_messages;
begin
  if auth.uid() is null or not public.is_nerd_jump_admin() then
    raise exception 'Only members with an admin sticker can post in Nerd Jump.';
  end if;
  if length(trim(coalesce(message_content,'')))=0 and image_url is null then
    raise exception 'Add a message or image.';
  end if;
  insert into public.nerd_jump_messages(user_id,content,media_url,media_type)
  values(auth.uid(),coalesce(message_content,''),image_url,image_type)
  returning * into row_out;
  return row_out;
end;
$$;

revoke all on function public.is_nerd_jump_admin() from public;
revoke all on function public.send_nerd_jump_message(text,text,text) from public;
grant execute on function public.is_nerd_jump_admin() to authenticated;
grant execute on function public.send_nerd_jump_message(text,text,text) to authenticated;
grant select on public.nerd_jump_messages to authenticated;

-- Nerd Jump images: public viewing, admin-only uploads/updates/deletes.
insert into storage.buckets (id,name,public)
values ('nerd-jump-images','nerd-jump-images',true)
on conflict (id) do update set public=true;

drop policy if exists "Nerd Jump admin upload" on storage.objects;
create policy "Nerd Jump admin upload" on storage.objects
for insert to authenticated
with check (
  bucket_id='nerd-jump-images'
  and (storage.foldername(name))[1]=auth.uid()::text
  and public.is_nerd_jump_admin()
);

drop policy if exists "Nerd Jump admin update" on storage.objects;
create policy "Nerd Jump admin update" on storage.objects
for update to authenticated
using (bucket_id='nerd-jump-images' and (storage.foldername(name))[1]=auth.uid()::text and public.is_nerd_jump_admin())
with check (bucket_id='nerd-jump-images' and (storage.foldername(name))[1]=auth.uid()::text and public.is_nerd_jump_admin());

drop policy if exists "Nerd Jump admin delete" on storage.objects;
create policy "Nerd Jump admin delete" on storage.objects
for delete to authenticated
using (bucket_id='nerd-jump-images' and (storage.foldername(name))[1]=auth.uid()::text and public.is_nerd_jump_admin());

do $$
begin
  if not exists(select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='nerd_jump_messages') then
    alter publication supabase_realtime add table public.nerd_jump_messages;
  end if;
end $$;

notify pgrst, 'reload schema';

-- ============================================================
-- PUBLIC CHAT
-- Every authenticated member can read and send messages.
-- Messages are not restricted by friendship status.
-- ============================================================
create table if not exists public.public_chat_messages (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  content text not null,
  created_at timestamptz not null default now(),
  constraint public_chat_content_check check (length(trim(content)) > 0 and length(content) <= 2000)
);

create index if not exists public_chat_messages_created_idx on public.public_chat_messages(created_at);

alter table public.public_chat_messages enable row level security;
drop policy if exists "public chat readable by members" on public.public_chat_messages;
create policy "public chat readable by members" on public.public_chat_messages
for select to authenticated using (true);

drop policy if exists "public chat own messages delete" on public.public_chat_messages;
create policy "public chat own messages delete" on public.public_chat_messages
for delete to authenticated using (auth.uid()=user_id);

-- Sending goes through an RPC so length/blank-message checks are enforced server-side.
drop policy if exists "public chat direct insert" on public.public_chat_messages;

create or replace function public.send_public_chat_message(message_content text)
returns public.public_chat_messages
language plpgsql
security definer
set search_path=public
as $$
declare row_out public.public_chat_messages; clean_content text;
begin
  if auth.uid() is null then raise exception 'You must be logged in.'; end if;
  clean_content:=btrim(message_content);
  if clean_content is null or char_length(clean_content)=0 then raise exception 'Message cannot be empty.'; end if;
  if char_length(clean_content)>2000 then raise exception 'Message is too long.'; end if;
  insert into public.public_chat_messages(user_id,content)
  values(auth.uid(),clean_content)
  returning * into row_out;
  return row_out;
end;
$$;

revoke all on function public.send_public_chat_message(text) from public;
grant execute on function public.send_public_chat_message(text) to authenticated;
grant select,delete on public.public_chat_messages to authenticated;

do $$
begin
  if not exists(select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='public_chat_messages') then
    alter publication supabase_realtime add table public.public_chat_messages;
  end if;
end $$;

notify pgrst, 'reload schema';
