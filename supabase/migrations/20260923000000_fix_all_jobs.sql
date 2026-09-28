-- ─────────────────────────────────────────────────────────────
-- Migration: immutable source versions + fix-all jobs + private artifacts
--
-- NOT APPLIED AUTOMATICALLY. Review, then run in the Supabase SQL editor (or
-- `supabase db push`) for the target project. Idempotent: safe to re-run.
--
-- The app raises schema_migration_required (HTTP 503) instead of silently
-- dropping data when these objects are missing.
-- ─────────────────────────────────────────────────────────────

-- ── projects / scans: link to the source version that was scanned ──
alter table public.projects add column if not exists current_source_version_id text;
alter table public.scans    add column if not exists source_version_id   text;
alter table public.scans    add column if not exists source_content_hash text;

-- ── source_versions (immutable snapshots) ─────────────────────
-- files: { "relative/path": "content" }. Written once, never updated.
create table if not exists public.source_versions (
  id                text primary key,
  project_id        text not null references public.projects (id) on delete cascade,
  owner_id          text not null references public.app_users (id) on delete cascade,
  kind              text not null check (kind in ('original', 'fixed', 'reupload')),
  parent_version_id text references public.source_versions (id) on delete set null,
  fix_job_id        text,
  files             jsonb not null,
  file_count        integer not null,
  total_bytes       integer not null,
  content_hash      text not null,
  created_at        timestamptz not null default now()
);
create index if not exists source_versions_project_idx on public.source_versions (project_id);
create index if not exists source_versions_owner_idx   on public.source_versions (owner_id);

-- ── fix_jobs ──────────────────────────────────────────────────
-- Full FixJob stored in `data`; a few columns surfaced for lookups.
create table if not exists public.fix_jobs (
  id              text primary key,
  project_id      text not null references public.projects (id) on delete cascade,
  owner_id        text not null references public.app_users (id) on delete cascade,
  scan_id         text not null references public.scans (id) on delete cascade,
  idempotency_key text not null,
  status          text not null check (status in ('running', 'completed', 'partial', 'failed')),
  data            jsonb not null,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  constraint fix_jobs_owner_key_unique unique (owner_id, idempotency_key)
);
create index if not exists fix_jobs_scan_idx on public.fix_jobs (scan_id);

-- ── legacy per-finding artifacts (old single-item flow) ───────
-- Referenced by the existing code but never defined in schema.sql. Kept only
-- until the old per-finding UI is removed; new downloads use Storage below.
create table if not exists public.fix_artifacts (
  id          text primary key,
  finding_id  text not null references public.findings (id) on delete cascade,
  project_id  text not null references public.projects (id) on delete cascade,
  owner_id    text not null references public.app_users (id) on delete cascade,
  data        jsonb not null,
  zip_base64  text,
  created_at  timestamptz not null default now()
);
create index if not exists fix_artifacts_finding_idx on public.fix_artifacts (finding_id);

-- ── RLS: deny-by-default (server uses the service-role key) ───
alter table public.source_versions enable row level security;
alter table public.fix_jobs        enable row level security;
alter table public.fix_artifacts   enable row level security;

-- ── Private Storage bucket for fix-job ZIPs ───────────────────
-- public = false: objects are only reachable with the service-role key via
-- the app's owner-checked download route. No storage policies are added, so
-- anon/authenticated clients cannot list or read objects.
-- Bucket name must match ARTIFACT_BUCKET (default "fix-artifacts").
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('fix-artifacts', 'fix-artifacts', false, 52428800, array['application/zip'])
on conflict (id) do update set public = false;
