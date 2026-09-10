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
  updated_at timestamptz not null default now()
);

create table if not exists public.posts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  content text not null check (char_length(content) between 1 and 5000),
  created_at timestamptz not null default now()
);

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

-- Secure friend-request operations. These prevent users from spoofing another account.
create or replace function public.accept_friend_request(request_id uuid)
returns void language plpgsql security invoker as $$
declare r public.friend_requests;
begin
  select * into r from public.friend_requests where id=request_id and receiver_id=auth.uid() and status='pending' for update;
  if not found then raise exception 'Friend request not found'; end if;
  update public.friend_requests set status='accepted' where id=r.id;
  insert into public.friendships(user_id,friend_id) values(r.sender_id,r.receiver_id),(r.receiver_id,r.sender_id) on conflict do nothing;
end; $$;

create or replace function public.decline_friend_request(request_id uuid)
returns void language plpgsql security invoker as $$
begin
  update public.friend_requests set status='declined' where id=request_id and receiver_id=auth.uid() and status='pending';
  if not found then raise exception 'Friend request not found'; end if;
end; $$;

create or replace function public.cancel_friend_request(request_id uuid)
returns void language plpgsql security invoker as $$
begin
  delete from public.friend_requests where id=request_id and sender_id=auth.uid() and status='pending';
  if not found then raise exception 'Friend request not found'; end if;
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
create policy "profiles readable by authenticated" on public.profiles for select to authenticated using(true);
create policy "own profile insert" on public.profiles for insert to authenticated with check(auth.uid()=id);
create policy "own profile update" on public.profiles for update to authenticated using(auth.uid()=id) with check(auth.uid()=id);

-- posts/comments/likes
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
create policy "involved requests readable" on public.friend_requests for select to authenticated using(auth.uid()=sender_id or auth.uid()=receiver_id);
create policy "send own request" on public.friend_requests for insert to authenticated with check(auth.uid()=sender_id and sender_id<>receiver_id);
-- Updates/deletes are deliberately not exposed; RPCs enforce sender/receiver ownership.

-- friendships: users can see their own relationship rows. Mutations happen through RPCs.
create policy "own friendships readable" on public.friendships for select to authenticated using(auth.uid()=user_id or auth.uid()=friend_id);

-- messages: only sender/receiver can read. Only a friend can receive a new message.
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
create policy "avatar upload own folder" on storage.objects for insert to authenticated with check(bucket_id='avatars' and (storage.foldername(name))[1]=auth.uid()::text);
create policy "avatar update own folder" on storage.objects for update to authenticated using(bucket_id='avatars' and (storage.foldername(name))[1]=auth.uid()::text) with check(bucket_id='avatars' and (storage.foldername(name))[1]=auth.uid()::text);
create policy "avatar delete own folder" on storage.objects for delete to authenticated using(bucket_id='avatars' and (storage.foldername(name))[1]=auth.uid()::text);

-- Optional realtime for live DMs/feed. Enable these in Supabase if your project doesn't already have them.
alter publication supabase_realtime add table public.messages;
alter publication supabase_realtime add table public.friend_requests;
