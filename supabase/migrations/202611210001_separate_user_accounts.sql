-- Allows an Admin account and a separate User account to pair securely.
alter table public.devices add column if not exists user_id uuid references auth.users(id) on delete set null;
create index if not exists devices_user_id_idx on public.devices(user_id);
drop policy if exists "owners manage their devices" on public.devices;
create policy "admins manage owned devices" on public.devices for all to authenticated
using ((select auth.uid()) = owner_id) with check ((select auth.uid()) = owner_id);
create policy "paired users read own device" on public.devices for select to authenticated
using ((select auth.uid()) = user_id);
create policy "paired users update own device" on public.devices for update to authenticated
using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "paired users read action requests" on public.action_requests for select to authenticated
using (exists (select 1 from public.devices d where d.id = device_id and d.user_id = (select auth.uid())));
create policy "paired users update action requests" on public.action_requests for update to authenticated
using (exists (select 1 from public.devices d where d.id = device_id and d.user_id = (select auth.uid())))
with check (exists (select 1 from public.devices d where d.id = device_id and d.user_id = (select auth.uid()) and d.owner_id = action_requests.owner_id));
create or replace function public.claim_pairing_code(p_code_hash text,p_device_key text,p_device_name text,p_model text,p_android_version text,p_app_version text)
returns uuid language plpgsql security definer set search_path=public,pg_temp as $function$
declare v_invite public.pairing_invites%rowtype; v_device_id uuid; v_user_id uuid:=auth.uid();
begin
 if v_user_id is null then raise exception 'Authentication required'; end if;
 select * into v_invite from public.pairing_invites where code_hash=p_code_hash and claimed_at is null and expires_at>now() for update;
 if not found then raise exception 'Invalid or expired pairing code'; end if;
 insert into public.devices(owner_id,user_id,device_key,device_name,model,android_version,app_version,status,last_seen_at)
 values(v_invite.owner_id,v_user_id,p_device_key,p_device_name,p_model,p_android_version,p_app_version,'online',now()) returning id into v_device_id;
 update public.pairing_invites set claimed_at=now(),claimed_device_id=v_device_id where id=v_invite.id;
 return v_device_id;
end;$function$;
revoke all on function public.claim_pairing_code(text,text,text,text,text,text) from public;
grant execute on function public.claim_pairing_code(text,text,text,text,text,text) to authenticated;
