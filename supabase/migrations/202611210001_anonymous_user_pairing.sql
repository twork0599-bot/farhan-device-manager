-- Anonymous User App pairing and device-token protected RPCs.
revoke execute on function public.claim_pairing_code(text,text,text,text,text,text) from anon, public;
grant execute on function public.claim_pairing_code(text,text,text,text,text,text) to authenticated;
-- User devices never receive Supabase Auth sessions or direct table access.
alter table public.devices add column if not exists device_token_hash text;
create index if not exists devices_device_token_hash_idx on public.devices(device_token_hash);
create table if not exists public.device_pair_attempts (
  id bigint generated always as identity primary key,
  ip inet not null,
  attempted_at timestamptz not null default now()
);
alter table public.device_pair_attempts enable row level security;
revoke all on public.device_pair_attempts from anon, authenticated;

create or replace function public.claim_pairing_code_anon(
  p_code_hash text, p_device_key text, p_device_token_hash text,
  p_device_name text, p_model text, p_android_version text, p_app_version text
) returns uuid language plpgsql security definer set search_path=public,pg_temp as $$
declare v_invite public.pairing_invites%rowtype; v_device_id uuid; v_ip inet;
begin
 if length(coalesce(p_code_hash,''))<>64 or length(coalesce(p_device_token_hash,''))<>64
 or length(coalesce(p_device_key,''))<16 or length(p_device_key)>100 then raise exception 'Invalid pairing request'; end if;
 v_ip:=nullif(split_part(coalesce(current_setting('request.headers',true)::json->>'x-forwarded-for',''),',',1),'')::inet;
 if v_ip is not null then
  delete from public.device_pair_attempts where attempted_at<now()-interval '1 hour';
  if (select count(*) from public.device_pair_attempts where ip=v_ip and attempted_at>now()-interval '1 minute')>=10 then raise exception 'Too many pairing attempts. Try again later.'; end if;
  insert into public.device_pair_attempts(ip) values(v_ip);
 end if;
 select * into v_invite from public.pairing_invites where code_hash=p_code_hash and claimed_at is null and expires_at>now() for update;
 if not found then raise exception 'Invalid or expired pairing code'; end if;
 insert into public.devices(owner_id,device_key,device_token_hash,device_name,model,android_version,app_version,status,last_seen_at)
 values(v_invite.owner_id,p_device_key,p_device_token_hash,p_device_name,p_model,p_android_version,p_app_version,'online',now()) returning id into v_device_id;
 update public.pairing_invites set claimed_at=now(),claimed_device_id=v_device_id where id=v_invite.id;
 return v_device_id;
end; $$;

create or replace function public.user_device_heartbeat(p_device_id uuid,p_device_token_hash text)
returns boolean language plpgsql security definer set search_path=public,pg_temp as $$
begin update public.devices set status='online',last_seen_at=now() where id=p_device_id and device_token_hash=p_device_token_hash and status<>'revoked'; return found; end; $$;

create or replace function public.user_device_next_action(p_device_id uuid,p_device_token_hash text)
returns jsonb language plpgsql security definer set search_path=public,pg_temp as $$
declare v_action public.action_requests%rowtype;
begin
 if not exists(select 1 from public.devices where id=p_device_id and device_token_hash=p_device_token_hash and status<>'revoked') then raise exception 'Device authentication failed'; end if;
 select * into v_action from public.action_requests where device_id=p_device_id and status='pending' and expires_at>now() order by requested_at asc limit 1;
 if not found then return null; end if;
 return jsonb_build_object('id',v_action.id,'action_type',v_action.action_type,'payload',v_action.payload);
end; $$;

create or replace function public.user_device_action_response(p_device_id uuid,p_device_token_hash text,p_action_id uuid,p_status text)
returns boolean language plpgsql security definer set search_path=public,pg_temp as $$
begin
 if p_status not in ('approved','denied','completed') then raise exception 'Invalid status'; end if;
 if not exists(select 1 from public.devices where id=p_device_id and device_token_hash=p_device_token_hash and status<>'revoked') then raise exception 'Device authentication failed'; end if;
 update public.action_requests set status=p_status,consented_at=case when p_status='approved' then now() else consented_at end,completed_at=case when p_status='completed' then now() else completed_at end
 where id=p_action_id and device_id=p_device_id and ((p_status in ('approved','denied') and status='pending') or (p_status='completed' and status='approved'));
 return found;
end; $$;

create or replace function public.user_device_unpair(p_device_id uuid,p_device_token_hash text)
returns boolean language plpgsql security definer set search_path=public,pg_temp as $$
begin update public.devices set status='revoked',revoked_at=now() where id=p_device_id and device_token_hash=p_device_token_hash and status<>'revoked'; return found; end; $$;

revoke all on function public.claim_pairing_code_anon(text,text,text,text,text,text,text) from public,authenticated;
revoke all on function public.user_device_heartbeat(uuid,text) from public,authenticated;
revoke all on function public.user_device_next_action(uuid,text) from public,authenticated;
revoke all on function public.user_device_action_response(uuid,text,uuid,text) from public,authenticated;
revoke all on function public.user_device_unpair(uuid,text) from public,authenticated;
grant execute on function public.claim_pairing_code_anon(text,text,text,text,text,text,text) to anon;
grant execute on function public.user_device_heartbeat(uuid,text) to anon;
grant execute on function public.user_device_next_action(uuid,text) to anon;
grant execute on function public.user_device_action_response(uuid,text,uuid,text) to anon;
grant execute on function public.user_device_unpair(uuid,text) to anon;
