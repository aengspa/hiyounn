-- ─────────────────────────────────────────────────────────────
-- Migration: AI-proposed detection rules (approved by a person before use)
--
-- NOT APPLIED AUTOMATICALLY. Review, then run in the Supabase SQL editor (or
-- `supabase db push`). Idempotent: safe to re-run.
-- ─────────────────────────────────────────────────────────────

-- Full CustomRule stored in `data`; a few columns surfaced for lookups.
create table if not exists public.custom_rules (
  id          text primary key,
  owner_id    text not null references public.app_users (id) on delete cascade,
  project_id  text not null references public.projects (id) on delete cascade,
  status      text not null check (status in ('proposed', 'approved', 'rejected')),
  data        jsonb not null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists custom_rules_owner_idx   on public.custom_rules (owner_id);
create index if not exists custom_rules_project_idx on public.custom_rules (project_id);

-- Only the service role (server) touches this table; RLS on with no policies
-- keeps anon/authenticated keys out, same as the other tables.
alter table public.custom_rules enable row level security;
