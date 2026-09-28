# Vibe Coding Security Agent

Security definitions v2: [integration notes and tool coverage](docs/security/definitions-v2-integration.md).

> **Don't trust the fix. Verify it.**

An independent Security Agent for developers who build with AI but can't review
security like an AppSec engineer. It runs one verification loop:

**Scan → Evidence → Fix → Re-test → Regression Test → Verify**

A vulnerability isn't "resolved" because someone edited the code. It's resolved
only when the **same attack is re-run and blocked**, and your **normal features
still work**.

---

## What's real vs simulated in this MVP

The scanner architecture is built so real tools drop in behind one interface.
Every finding carries a `simulated` flag, surfaced in the UI as a badge.

| Scanner | Status | Notes |
|---|---|---|
| Secret scanner | **Real** | Regex + provider patterns (Stripe, OpenAI, AWS, GitHub, Slack, Google, private keys). Secrets masked in evidence. |
| Static rules (XSS, injection, traversal, IDOR, ASVS 5.0 signals) | **Real** | Regex/signal SAST, re-checked per finding after a fix. |
| Dependency CVEs | **Real** | OSV.dev lookup (offline fallback is marked `simulated`). |
| AI code analysis | **Real** (needs `LLM_*`) | Per-file chunks, riskiest first, with a project map. Finds logic/authz bugs rules miss and reviews rule findings. |
| Security headers & CORS | **Real** | Read-only HTTP GET against the deployment URL; static fallback. ZAP-ready. |
| Supabase RLS | Simulated | Simulated policy state. Supabase Management API-ready. |

## The loop: rules are the baseline, AI is a detector and a second opinion

**Scan.** Rule scanners run first. With an LLM configured, the AI reviews the
code in chunks (riskiest files first, parallel calls) and (a) adds issues the
rules miss, (b) gives an opinion on each rule finding (`confirmed` /
`likely_false_positive`). It never deletes a rule finding. Same issue from both
→ one finding. Files the AI could not review are listed with the reason, and
the results page says so under the headline.

**Fix all.** Secrets and dependency upgrades are fixed **by rule** (secret →
`process.env.NAME`; dependency → highest fixed version in the same major).
Secrets are never sent to the AI. Other findings get an AI patch; secret values
are masked in everything sent to the AI. Findings the AI flagged as likely false
positives are not auto-edited. The original upload is never modified; the fix is
a new source version and a changed-files ZIP.

### AI-based SAST features

| Feature | What it does | Where |
|---|---|---|
| Exploit tests | For each fixed code finding the AI writes an exploit test against a harness; it runs on the original (must reproduce) and on the fix (must be blocked) in `node --permission` with network/process/file modules stubbed. An exploit blocked on the fix settles rule-vs-AI disagreements; one that still works overrides "fixed". | `src/lib/exploit/` |
| Route permission table | The AI extracts login/admin/ownership facts per route (each row checked against the real declaration line); rules turn the gaps into findings. | `src/lib/scanners/authzMatrix.ts` |
| Semgrep baseline | Semgrep runs as a rule scanner (merged with the regex rules, AI-triaged, per-finding re-verify). Needs `SEMGREP_BIN` or `semgrep` on PATH. | `src/lib/scanners/semgrepScanner.ts` |
| AI-proposed rules | From AI-only findings the AI proposes a one-line regex; the server checks it matches the original line, is not noisy, and runs within a time limit (`vm` timeout). A person approves it on the results page; approved rules then run as baseline rules. | `src/lib/rules/customRules.ts` |
| Incremental re-upload | "코드 새로 올리기" on the project page adds a new source version; the next scan re-runs rules on everything but sends only changed files to the AI and carries over earlier AI results for unchanged files. | `src/lib/scan/scanPipeline.ts` |

Every finding shows its exact source line (secrets masked); fix-all shows a
per-file and per-finding diff; re-verify shows the rule comment, the AI comment,
the exploit-test result and the evidence code for each item. Rule findings the
AI flags as likely false positives get a second, evidence-backed AI ruling; a
"not vulnerable" ruling moves them to a separate group and out of fix-all.

### End-to-end benchmark

`scripts/e2e/` holds two benchmark apps (`fixtures/`), a browser driver
generator, and a mock OpenAI-compatible gateway for plumbing tests without a real
model:

```bash
node scripts/e2e/mock-llm-gateway.mjs &          # :4010, requires the api-key header
LLM_BASE_URL=http://localhost:4010/v1 LLM_AUTH_HEADER=api-key LLM_API_KEY=mock-gateway-key \
  LLM_MODEL=mock npm run build && npm run start
node scripts/e2e/make-browser-driver.mjs         # writes .local/e2e-driver.js
# then, in a logged-in browser tab, run .local/e2e-driver.js and read window.__e2e
```

### Sample app to try the loop

`samples/memo-board/` is a small Express + `node:sqlite` memo board with real,
exploitable weaknesses (SQL injection, IDOR, reflected and DOM XSS, SSRF, a
missing admin check, a predictable session token and cookie without flags,
plaintext default passwords, an MD5 signature over a hardcoded secret). It runs
on its own (`cd samples/memo-board && npm install && npm start`, Node 22.13+).

The product ships only its **source**: "메모 보드 (샘플) 추가하기" on the
new-project page (`POST /api/projects/sample`) creates an ordinary project, so
every scan, fix and re-verify runs for real. Nothing is precomputed. The same
files are downloadable as `/samples/memo-board-sample.zip`. After editing the
folder, run `npm run samples` to regenerate `src/lib/samples/memo-board.generated.ts`
and both ZIPs; a test fails if they drift.

**Supabase:** apply `supabase/migrations/20260929000000_custom_rules.sql` for AI-proposed rules.

**Settings fixes introduce:** fixes that make code read a new env var (e.g.
`JWT_SECRET`, `PREVIEW_ALLOWED_HOSTS`) fail closed until it is set; the fix
result and ZIP list them. Recommended setup: [docs/security/fix-configuration.md](docs/security/fix-configuration.md).

**Re-verify.** The rule re-check is the baseline and follows each finding's own
line (not "any match in the file"). Dependencies are re-queried on OSV. The AI
reviews the same fixed code independently. Agree → decided. Disagree →
`판단이 엇갈려요` (a person decides). AI-only findings are decided by the AI and
labelled as such. Nothing here runs the app, so "fixed" means fixed in source.

---

## The IDOR demo (most important scenario)

The bundled demo app has `GET /api/users/:id` with no ownership check.

1. **Detect** — the authorization scanner finds the missing check.
2. **Reproduce** — User A (`session-user-a`) requests User B's record
   (`GET /api/users/102`) → `HTTP 200`, victim's data returned. Attack confirmed.
3. **Generate Fix** — adds `ownerId: session.user.id` to the query.
4. **Apply Fix** — finding moves to `fixed` (not resolved).
5. **Re-test (security)** — the same attack now returns `HTTP 403 Forbidden`.
6. **Regression** — User A can still read their own record
   (`GET /api/users/101` → `HTTP 200`), login and API still work.
7. **Verify** — only now does the finding become `resolved` →
   *"Security Fix Verified"* (for this finding, not the whole app).

---

## Architecture

```
SecurityOrchestrator
   ├── SecretScanner            (real)
   ├── DependencyScanner        (simulated)
   ├── BaaSConfigScanner        (simulated)
   ├── AuthorizationScanner     (real, + verify/regression engine)
   └── HeaderScanner            (real)
```

```
src/
  app/
    page.tsx                       Landing
    dashboard/                     Projects, add, project detail
    dashboard/scans/[id]/          Scan results + Scan Scope
    dashboard/findings/[id]/       Finding detail + timeline + fix + verify
    api/                           projects, scans, findings, fix, verify
  components/                      UI + interactive client components
  lib/
    domain/types.ts                SecurityFinding, Evidence, Verification, ...
    scanners/                      SecurityScanner interface + orchestrator + scanners
    demo/                          Bundled vulnerable app + project fixture
    remediation/fixGenerator.ts    Fix generation (separate from verification)
    store/                         Store facade (store.ts) + memory & supabase
                                   backends, both ownership-checked (IDOR-proof)
    auth.ts                        Auth seam (Supabase Auth pluggable)
supabase/schema.sql                Postgres schema with RLS on every table
```

### Design principles enforced in code

- **Evidence over guesswork** — findings always carry evidence; verification is
  deterministic (HTTP status codes), never an LLM opinion.
- **Generation ≠ verification** — `fixGenerator` proposes; only the verification
  engine can resolve a finding, and only after re-running the attack.
- **No false safety** — the UI never says "Safe" / "Passed" / "100% Secure".
  It shows tested vs untested scope and a disclaimer.
- **Own IDOR-proofing** — every store access is ownership-checked; the Supabase
  schema enables RLS on every table as a second line of defense.
- **Secret hygiene** — secrets are masked in evidence; `.env` is gitignored;
  only `.env.example` is committed.

---

## Running locally

> **Requires Node.js 18.17+.** Node was not available in the build
> environment where this was scaffolded, so dependencies were not installed
> here — run the install step on your machine.

```bash
cp .env.example .env.local   # optional for the MVP demo (DATA_STORE=memory)
npm install
npm run dev                  # http://localhost:3000
```

Then: open the dashboard → the seeded **Acme Notes (demo)** project →
**Run Security Scan** → open the *"Other users' private data can be accessed"*
finding → **Generate Fix → Apply Fix → Verify Fix**.

To type-check / build:

```bash
npm run build
```

## Environment variables

See `.env.example`. Client-safe keys use the `NEXT_PUBLIC_` prefix; the Supabase
service role key, `AUTH_SECRET`, and LLM key are server-only and must never be
exposed.

| Variable | When required | Purpose |
|---|---|---|
| `AUTH_SECRET` | **Production** | Stable HMAC key for session cookies. Without it the app throws at startup in production (a random per-process fallback would break sessions across serverless invocations). Generate with `openssl rand -hex 32`. |
| `DATA_STORE` | Always (defaults to `memory`) | `memory` for local dev; `supabase` for any deployment. |
| `NEXT_PUBLIC_SUPABASE_URL` | `DATA_STORE=supabase` | Supabase project URL. |
| `SUPABASE_SERVICE_ROLE_KEY` | `DATA_STORE=supabase` | Server-only. Used by the store layer; bypasses RLS. |
| `LLM_PROVIDER` / `LLM_API_KEY` / `LLM_MODEL` | Optional | Enables AI code analysis, AI fixes and AI re-review. Without it the product runs on rules only. Models that accept only the default temperature (e.g. GPT-5 family) are detected automatically. |
| `LIMIT_AI_SCAN_*`, `LIMIT_FIX_ALL_CONCURRENCY` | Optional | AI scan chunk size, chunk count, concurrency, per-call timeout and total budget. See `src/lib/config/limits.ts`. |

## Deploying (Vercel)

The default `memory` store keeps data in a per-process `Map`. On Vercel each
serverless invocation may run in a different process, so a scan created by one
request is invisible to the request that renders its result page — the page
404s. **Use the Supabase store in production:**

1. Create a Supabase project and run `supabase/schema.sql` in the SQL editor.
2. In Vercel project settings, set environment variables:
   - `DATA_STORE=supabase`
   - `NEXT_PUBLIC_SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`
   - `AUTH_SECRET` (a fixed 32-byte hex string)
3. Redeploy. Projects, scans, and findings now persist across all requests.

## Roadmap (phased)

- **Phase 1 (done)** — full UX skeleton + real IDOR/secret/header scanners.
- **Phase 2** — swap simulated scanners for Gitleaks / OSV / ZAP; Supabase store.
- **Phase 3** — persist per-finding replayable verification tests.
- **Phase 4** — LLM remediation behind the existing fix interface.
- **Phase 5/6** — richer fix + regression verification across more finding types.

## Safe DAST note

Dynamic checks are read-only and non-destructive. Only test targets you own.
URL ownership verification is a planned addition before broadening DAST.
```
