# Gloworld-Labs-Supabase-Integration
Gloworld Labs Supabase Integration – Bootstrap SQL, docs, and examples for connecting Gloworld apps to Supabase.
-- ==========================================================
-- Gloworld Labs + Supabase Bootstrap
-- Schema, RLS, buckets, helper functions, indexes.
-- Idempotent: safe to re-run.
-- ==========================================================

-- 0) Extensions (idempotent)
create extension if not exists pgcrypto;
create extension if not exists pg_stat_statements;
create extension if not exists "uuid-ossp";

-- 1) Helpers ------------------------------------------------

-- Generic updated_at trigger fn (idempotent)
create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

-- Ensure a profile row exists for an auth user
create or replace function public.ensure_profile()
returns trigger
language plpgsql security definer set search_path = public
as $$
begin
  insert into gloworld_app.profiles (id)
  values (new.id)
  on conflict (id) do nothing;
  return new;
end;
$$;

-- 2) App schema ---------------------------------------------
create schema if not exists gloworld_app;

-- 2.1 Profiles (1:1 with auth.users)
create table if not exists gloworld_app.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique,
  display_name text,
  avatar_url text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
drop trigger if exists trg_profiles_updated on gloworld_app.profiles;
create trigger trg_profiles_updated
before update on gloworld_app.profiles
for each row execute procedure public.set_updated_at();

-- Backfill hook when a new auth user is created
drop trigger if exists trg_auth_user_on_insert on auth.users;
create trigger trg_auth_user_on_insert
after insert on auth.users
for each row execute procedure public.ensure_profile();

-- 2.2 Projects (a user can own many projects)
create table if not exists gloworld_app.projects (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  description text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists idx_projects_owner on gloworld_app.projects(owner_id);
drop trigger if exists trg_projects_updated on gloworld_app.projects;
create trigger trg_projects_updated
before update on gloworld_app.projects
for each row execute procedure public.set_updated_at();

-- 2.3 Supabase connections per project (what your app uses)
create table if not exists gloworld_app.user_supabase_connections (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  project_id uuid not null references gloworld_app.projects(id) on delete cascade,
  supabase_url text not null,
  anon_key text not null,
  -- optional: keep ciphertext if you implement a vault
  service_role_ciphertext text,
  status text not null default 'active' check (status in ('active','inactive','error')),
  last_verified_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (user_id, project_id)
);
create index if not exists idx_conn_user_project on gloworld_app.user_supabase_connections(user_id, project_id);
drop trigger if exists trg_conn_updated on gloworld_app.user_supabase_connections;
create trigger trg_conn_updated
before update on gloworld_app.user_supabase_connections
for each row execute procedure public.set_updated_at();

-- 2.4 Files/assets your builder generates (metadata)
create table if not exists gloworld_app.generated_files (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references gloworld_app.projects(id) on delete cascade,
  path text not null,
  kind text not null check (kind in ('component','page','asset','schema','migration')),
  size_bytes bigint,
  storage_key text,          -- pointer if you upload to Storage
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);
create index if not exists idx_files_project on gloworld_app.generated_files(project_id);

-- 2.5 AI job tracking (observability)
create table if not exists gloworld_app.ai_jobs (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references gloworld_app.projects(id) on delete cascade,
  user_id uuid references auth.users(id),
  provider text not null,             -- e.g. openai, perplexity, etc.
  model text not null,
  status text not null default 'queued' check (status in ('queued','running','succeeded','failed')),
  input_tokens integer,
  output_tokens integer,
  cost_usd numeric(10,4),
  correlation_id text,
  meta jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  finished_at timestamptz
);
create index if not exists idx_ai_jobs_project on gloworld_app.ai_jobs(project_id);
create index if not exists idx_ai_jobs_status on gloworld_app.ai_jobs(status);

-- 3) Row Level Security -------------------------------------
alter table gloworld_app.profiles enable row level security;
alter table gloworld_app.projects enable row level security;
alter table gloworld_app.user_supabase_connections enable row level security;
alter table gloworld_app.generated_files enable row level security;
alter table gloworld_app.ai_jobs enable row level security;

-- Profiles: users can view/update only themselves
drop policy if exists "profiles_self_rw" on gloworld_app.profiles;
create policy "profiles_self_rw"
on gloworld_app.profiles
for all
using (auth.uid() = id)
with check (auth.uid() = id);

-- Projects: owner full access, others none (expand if you add collaborators)
drop policy if exists "projects_owner_rw" on gloworld_app.projects;
create policy "projects_owner_rw"
on gloworld_app.projects
for all
using (owner_id = auth.uid())
with check (owner_id = auth.uid());

-- Connections: owner of the project only
drop policy if exists "connections_owner_rw" on gloworld_app.user_supabase_connections;
create policy "connections_owner_rw"
on gloworld_app.user_supabase_connections
for all
using (
  user_id = auth.uid()
  and exists (
    select 1 from gloworld_app.projects p
    where p.id = user_supabase_connections.project_id
      and p.owner_id = auth.uid()
  )
)
with check (user_id = auth.uid());

-- Files: visible within owned project
drop policy if exists "files_project_owner" on gloworld_app.generated_files;
create policy "files_project_owner"
on gloworld_app.generated_files
for all
using (
  exists (
    select 1 from gloworld_app.projects p
    where p.id = generated_files.project_id
      and p.owner_id = auth.uid()
  )
)
with check (
  exists (
    select 1 from gloworld_app.projects p
    where p.id = generated_files.project_id
      and p.owner_id = auth.uid()
  )
);

-- AI jobs: same as files (project owner)
drop policy if exists "jobs_project_owner" on gloworld_app.ai_jobs;
create policy "jobs_project_owner"
on gloworld_app.ai_jobs
for all
using (
  exists (
    select 1 from gloworld_app.projects p
    where p.id = ai_jobs.project_id
      and p.owner_id = auth.uid()
  )
)
with check (
  exists (
    select 1 from gloworld_app.projects p
    where p.id = ai_jobs.project_id
      and p.owner_id = auth.uid()
  )
);

-- 4) Storage bucket for generated assets --------------------
insert into storage.buckets (id, name, public)
values ('gloworld-assets','gloworld-assets', true)
on conflict (id) do nothing;

-- Public read for the bucket; write guarded by application logic.
create policy if not exists "Public read access to gloworld-assets"
on storage.objects
for select
to public
using (bucket_id = 'gloworld-assets');

-- Optional tighter write policy (only project owners through service role)
-- You can keep writes server-side via service role and skip a public policy.

-- 5) Verification helper -----------------------------------
-- Lightweight success signal your edge function can call after checking creds
create or replace function public.verify_connection_success(_connection_id uuid)
returns boolean
language plpgsql
as $$
declare
  uid uuid := auth.uid();
begin
  update gloworld_app.user_supabase_connections
     set last_verified_at = now(), status = 'active'
   where id = _connection_id
     and user_id = uid;
  return found;
end;
$$;
