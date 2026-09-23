-- ─────────────────────────────────────────────────────────────
-- Vibe Coding Security Agent — Supabase schema (Phase 2 target)
--
-- Row Level Security (RLS) is ENABLED on every table. Each policy binds rows
-- to their owning user via auth.uid(). This is the app's own defense against
-- the IDOR class of bug it detects: even if an API authorization check were
-- missed, the database refuses cross-user reads.
--
-- The in-memory store in src/lib/store/store.ts mirrors this ownership model
-- so switching DATA_STORE=supabase later needs no schema change.
-- ─────────────────────────────────────────────────────────────

-- Users are managed by Supabase Auth (auth.users). We reference auth.uid().

-- ── projects ──────────────────────────────────────────────────
create table if not exists public.projects (
  id                 uuid primary key default gen_random_uuid(),
  owner_id           uuid not null references auth.users (id) on delete cascade,
  name               text not null,
  repository_url     text,
  deployment_url     text,
  last_scanned_commit text,
  current_commit     text,
  last_scan_date     timestamptz,
  created_at         timestamptz not null default now()
);

-- ── scans ─────────────────────────────────────────────────────
create table if not exists public.scans (
  id            uuid primary key default gen_random_uuid(),
  project_id    uuid not null references public.projects (id) on delete cascade,
  status        text not null default 'queued',
  commit_sha    text,
  started_at    timestamptz not null default now(),
  completed_at  timestamptz,
  scope         jsonb not null default '{}'::jsonb
);

-- ── findings ──────────────────────────────────────────────────
create table if not exists public.findings (
  id                    uuid primary key default gen_random_uuid(),
  scan_id               uuid not null references public.scans (id) on delete cascade,
  title                 text not null,
  severity              text not null,
  category              text not null,
  owasp                 text,
  cwe                   text,
  cvss                  numeric,
  description           text not null,
  human_readable_impact text not null,
  why_it_matters        text not null,
  location_file         text,
  location_line         int,
  remediation           text,
  status                text not null default 'detected',
  simulated             boolean not null default false,
  verification_key      text,
  created_at            timestamptz not null default now(),
  updated_at            timestamptz not null default now()
);

-- ── evidence ──────────────────────────────────────────────────
create table if not exists public.evidence (
  id          uuid primary key default gen_random_uuid(),
  finding_id  uuid not null references public.findings (id) on delete cascade,
  kind        text not null,
  label       text not null,
  content     text not null,
  masked      boolean not null default false,
  language    text
);

-- ── fix_attempts ──────────────────────────────────────────────
create table if not exists public.fix_attempts (
  id                uuid primary key default gen_random_uuid(),
  finding_id        uuid not null references public.findings (id) on delete cascade,
  source            text not null default 'deterministic',
  summary           text not null,
  plain_explanation text not null,
  diffs             jsonb not null default '[]'::jsonb,
  applied           boolean not null default false,
  created_at        timestamptz not null default now()
);

-- ── verification_tests ────────────────────────────────────────
create table if not exists public.verification_tests (
  id          uuid primary key default gen_random_uuid(),
  finding_id  uuid not null references public.findings (id) on delete cascade,
  label       text not null,
  before      jsonb,
  after       jsonb,
  outcome     text not null,
  created_at  timestamptz not null default now()
);

-- ── regression_tests ──────────────────────────────────────────
create table if not exists public.regression_tests (
  id          uuid primary key default gen_random_uuid(),
  finding_id  uuid not null references public.findings (id) on delete cascade,
  checks      jsonb not null default '[]'::jsonb,
  outcome     text not null,
  created_at  timestamptz not null default now()
);

-- ─────────────────────────────────────────────────────────────
-- Row Level Security
-- ─────────────────────────────────────────────────────────────

alter table public.projects           enable row level security;
alter table public.scans              enable row level security;
alter table public.findings           enable row level security;
alter table public.evidence           enable row level security;
alter table public.fix_attempts       enable row level security;
alter table public.verification_tests enable row level security;
alter table public.regression_tests   enable row level security;

-- Projects: owner-only, all operations.
create policy "projects_owner" on public.projects
  for all using (owner_id = auth.uid()) with check (owner_id = auth.uid());

-- Scans: accessible only if the parent project belongs to the caller.
create policy "scans_via_project" on public.scans
  for all using (
    exists (select 1 from public.projects p
            where p.id = scans.project_id and p.owner_id = auth.uid())
  ) with check (
    exists (select 1 from public.projects p
            where p.id = scans.project_id and p.owner_id = auth.uid())
  );

-- Findings: accessible only via an owned scan -> project.
create policy "findings_via_scan" on public.findings
  for all using (
    exists (
      select 1 from public.scans s
      join public.projects p on p.id = s.project_id
      where s.id = findings.scan_id and p.owner_id = auth.uid()
    )
  ) with check (
    exists (
      select 1 from public.scans s
      join public.projects p on p.id = s.project_id
      where s.id = findings.scan_id and p.owner_id = auth.uid()
    )
  );

-- Helper macro pattern for finding-child tables (evidence, fixes, tests).
create policy "evidence_via_finding" on public.evidence
  for all using (
    exists (
      select 1 from public.findings f
      join public.scans s on s.id = f.scan_id
      join public.projects p on p.id = s.project_id
      where f.id = evidence.finding_id and p.owner_id = auth.uid()
    )
  ) with check (
    exists (
      select 1 from public.findings f
      join public.scans s on s.id = f.scan_id
      join public.projects p on p.id = s.project_id
      where f.id = evidence.finding_id and p.owner_id = auth.uid()
    )
  );

create policy "fixes_via_finding" on public.fix_attempts
  for all using (
    exists (
      select 1 from public.findings f
      join public.scans s on s.id = f.scan_id
      join public.projects p on p.id = s.project_id
      where f.id = fix_attempts.finding_id and p.owner_id = auth.uid()
    )
  ) with check (
    exists (
      select 1 from public.findings f
      join public.scans s on s.id = f.scan_id
      join public.projects p on p.id = s.project_id
      where f.id = fix_attempts.finding_id and p.owner_id = auth.uid()
    )
  );

create policy "vtests_via_finding" on public.verification_tests
  for all using (
    exists (
      select 1 from public.findings f
      join public.scans s on s.id = f.scan_id
      join public.projects p on p.id = s.project_id
      where f.id = verification_tests.finding_id and p.owner_id = auth.uid()
    )
  ) with check (true);

create policy "rtests_via_finding" on public.regression_tests
  for all using (
    exists (
      select 1 from public.findings f
      join public.scans s on s.id = f.scan_id
      join public.projects p on p.id = s.project_id
      where f.id = regression_tests.finding_id and p.owner_id = auth.uid()
    )
  ) with check (true);
