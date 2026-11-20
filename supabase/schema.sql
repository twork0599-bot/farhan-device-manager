-- Reproducible schema reference. The live Supabase project has already been configured.
create table public.devices (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  device_key text not null,
  device_name text not null,
  model text,
  android_version text,
  app_version text,
  status text not null default 'offline' check (status in ('online','offline','revoked')),
  last_seen_at timestamptz,
  paired_at timestamptz not null default now(),
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  installed_apps jsonb not null default '[]'::jsonb,
  unique(owner_id, device_key)
);
create table public.pairing_invites (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  code_hash text not null unique,
  expires_at timestamptz not null,
  claimed_at timestamptz,
  claimed_device_id uuid references public.devices(id) on delete set null,
  created_at timestamptz not null default now()
);
create table public.action_requests (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  device_id uuid not null references public.devices(id) on delete cascade,
  action_type text not null check (action_type in ('open_app','open_dialer','compose_sms','screen_share','file_transfer','disconnect')),
  payload jsonb not null default '{}'::jsonb,
  status text not null default 'pending' check (status in ('pending','approved','denied','running','completed','expired','cancelled')),
  requires_consent boolean not null default true,
  consented_at timestamptz,
  requested_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '2 minutes'),
  completed_at timestamptz
);
create table public.device_events (
  id bigint generated always as identity primary key,
  owner_id uuid not null references auth.users(id) on delete cascade,
  device_id uuid not null references public.devices(id) on delete cascade,
  event_type text not null,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
alter table public.devices enable row level security;
alter table public.pairing_invites enable row level security;
alter table public.action_requests enable row level security;
alter table public.device_events enable row level security;
create policy "owners manage their devices" on public.devices for all to authenticated using ((select auth.uid()) = owner_id) with check ((select auth.uid()) = owner_id);
create policy "owners manage their pairing invites" on public.pairing_invites for all to authenticated using ((select auth.uid()) = owner_id) with check ((select auth.uid()) = owner_id);
create policy "owners read their action requests" on public.action_requests for select to authenticated using ((select auth.uid()) = owner_id);
create policy "owners create action requests" on public.action_requests for insert to authenticated with check ((select auth.uid()) = owner_id);
create policy "owners update their action requests" on public.action_requests for update to authenticated using ((select auth.uid()) = owner_id) with check ((select auth.uid()) = owner_id);
create policy "owners read device events" on public.device_events for select to authenticated using ((select auth.uid()) = owner_id);
