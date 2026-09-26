-- ─────────────────────────────────────────────────────────────
-- Vibe Coding Security Agent — Supabase schema
--
-- Persistent store for the app. Solves the Vercel problem where an in-memory
-- Map is not shared across serverless function invocations: every project /
-- scan / finding now lives in Postgres and is visible to every function.
--
-- AUTH & OWNERSHIP MODEL
-- ----------------------
-- The MVP ships its own dependency-free auth (scrypt password hashes + a
-- signed HttpOnly cookie), so it does NOT use Supabase Auth. There is no
-- auth.uid() at the database layer. Instead:
--   1. The server connects with the SERVICE ROLE key (bypasses RLS).
--   2. The application's store layer enforces per-user ownership on every
--      read/write (the app's own defense against the IDOR class of bug it
--      detects). See src/lib/store/*.
--
-- RLS is still ENABLED with a deny-by-default posture so that the public anon
-- key can never read or write these tables directly. When Supabase Auth is
-- adopted later, replace app_users with auth.users, switch owner_id back to
-- uuid, and add auth.uid()-based policies.
--
-- Ids are TEXT to match the app's own id() generator (e.g. "proj_...").
-- Rich nested domain objects (evidence, diffs, verification results, scope,
-- plan, report) are stored as JSONB to keep the mapping simple and lossless.
-- ─────────────────────────────────────────────────────────────

-- ── app_users ─────────────────────────────────────────────────
create table if not exists public.app_users (
  id            text primary key,
  email         text not null unique,
  name          text,
  password_hash text,
  created_at    timestamptz not null default now()
);

-- ── projects ──────────────────────────────────────────────────
create table if not exists public.projects (
  id                  text primary key,
  owner_id            text not null references public.app_users (id) on delete cascade,
  name                text not null,
  repository_url      text,
  deployment_url      text,
  source_code         text,
  source_zip_name     text,
  last_scanned_commit text,
  current_commit      text,
  last_scan_date      timestamptz,
  handler_fixed       boolean not null default false,
  created_at          timestamptz not null default now()
);
create index if not exists projects_owner_idx on public.projects (owner_id);

-- ── scans ─────────────────────────────────────────────────────
create table if not exists public.scans (
  id            text primary key,
  project_id    text not null references public.projects (id) on delete cascade,
  status        text not null default 'queued',
  commit_sha    text,
  started_at    timestamptz not null default now(),
  completed_at  timestamptz,
  finding_ids   jsonb not null default '[]'::jsonb,
  scope         jsonb not null default '{}'::jsonb,
  plan          jsonb,
  report        jsonb
);
create index if not exists scans_project_idx on public.scans (project_id);

-- ── findings ──────────────────────────────────────────────────
-- The full SecurityFinding domain object is stored in `data` (JSONB). A few
-- columns are surfaced for indexing / querying convenience.
create table if not exists public.findings (
  id          text primary key,
  scan_id     text not null references public.scans (id) on delete cascade,
  severity    text not null,
  status      text not null default 'detected',
  data        jsonb not null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists findings_scan_idx on public.findings (scan_id);

-- ── fix_attempts ──────────────────────────────────────────────
create table if not exists public.fix_attempts (
  id          text primary key,
  finding_id  text not null references public.findings (id) on delete cascade,
  applied     boolean not null default false,
  data        jsonb not null,
  created_at  timestamptz not null default now()
);
create index if not exists fixes_finding_idx on public.fix_attempts (finding_id);

-- ── verifications ─────────────────────────────────────────────
-- One VerificationResult per finding (latest wins). Stored whole as JSONB.
create table if not exists public.verifications (
  finding_id  text primary key references public.findings (id) on delete cascade,
  data        jsonb not null,
  created_at  timestamptz not null default now()
);

-- ─────────────────────────────────────────────────────────────
-- Row Level Security — deny-by-default.
--
-- RLS is enabled with NO permissive policies for the anon/authenticated roles,
-- so the public anon key cannot touch these tables. The server uses the
-- service-role key, which bypasses RLS; ownership is enforced in the app's
-- store layer. This is the "second line of defense" posture described above.
-- ─────────────────────────────────────────────────────────────

alter table public.app_users     enable row level security;
alter table public.projects      enable row level security;
alter table public.scans         enable row level security;
alter table public.findings      enable row level security;
alter table public.fix_attempts  enable row level security;
alter table public.verifications enable row level security;
