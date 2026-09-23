# Vibe Coding Security Agent

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
| Secret scanner | **Real** | Regex detection, secrets masked in evidence. Gitleaks-ready. |
| Authorization / IDOR | **Real** | Static detection + live attack reproduction + full verify/regression loop. |
| Security headers & CORS | **Real** | Read-only HTTP GET against the deployment URL; static fallback. ZAP-ready. |
| Dependency CVEs | Simulated | Canned advisories from `package.json`. `npm audit` / OSV-ready. |
| Supabase RLS | Simulated | Simulated policy state. Supabase Management API-ready. |
| AI remediation | Deterministic | Rule-based patches today; LLM pluggable behind the same interface. |

The flagship end-to-end demo is **IDOR** — it runs the complete loop with real,
deterministic evidence.

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
    store/store.ts                 Repository w/ ownership authorization
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
service role key and LLM key are server-only and must never be exposed.

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
