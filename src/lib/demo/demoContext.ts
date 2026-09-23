import type { ProjectContext } from "@/lib/scanners/types";
import { VULNERABLE_HANDLER_SOURCE, HANDLER_FILE } from "@/lib/demo/vulnerableApp";

/**
 * Builds the ProjectContext for the bundled vulnerable demo project. In
 * production this would be hydrated from a cloned repository; here it's a fixed
 * fixture so the demo is fully deterministic.
 *
 * NOTE: the hardcoded secret below is intentional bait for the secret scanner.
 * It is a fake value, not a real credential.
 */
export function buildDemoContext(
  projectId: string,
  opts: {
    name: string;
    repositoryUrl?: string;
    deploymentUrl?: string;
    commitSha?: string;
    /** When true, the handler file reflects the applied fix. */
    fixedHandler?: boolean;
    /** 사용자가 붙여넣은 소스 코드(AI 스캔 대상). */
    userSource?: string;
  }
): ProjectContext {
  // The context always represents the on-disk (pre-fix) demo repo for scanning.
  // The verification engine toggles fixed behavior via handleUsersRequest(),
  // not by rewriting these files. `fixedHandler` is accepted for API symmetry.
  void opts.fixedHandler;
  const handlerSource = VULNERABLE_HANDLER_SOURCE;

  const files: Record<string, string> = {
    [HANDLER_FILE]: handlerSource,
      "src/lib/db.ts": `import { createClient } from "@supabase/supabase-js";

// BUG: service role secret hardcoded in client-reachable module.
const SUPABASE_SERVICE_KEY = "sbp_live_9f2c1a77e4b84d0e9a3c5f6d7b8e2a10";

export const admin = createClient(
  "https://demo.supabase.co",
  SUPABASE_SERVICE_KEY
);`,
      ".env": `NEXT_PUBLIC_SUPABASE_URL=https://demo.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo
DATABASE_PASSWORD=SuperSecretDbPass123!`,
      "next.config.js": `module.exports = {
  async headers() {
    return []; // BUG: no security headers configured
  },
};`,
      // WEB-003 XSS bait: 사용자 입력을 인코딩 없이 DOM에 삽입.
      "src/components/Comment.tsx": `export function Comment({ req }) {
  // BUG: 사용자 입력을 그대로 HTML로 삽입 (XSS)
  return <div dangerouslySetInnerHTML={{ __html: req.query.text }} />;
}`,
      // WEB-004 인젝션 bait: 문자열 연결 SQL + eval.
      "src/api/search/route.ts": `import { db } from "@/lib/db";

export async function GET(req) {
  const q = req.query.q;
  // BUG: 입력값을 그대로 붙인 SQL (SQL 인젝션)
  const rows = await db.query(\`SELECT * FROM notes WHERE title = '\${q}'\`);
  // BUG: 입력값으로 코드 실행 (코드 인젝션)
  const parsed = eval(req.query.expr);
  return Response.json({ rows, parsed });
}`,
      // WEB-005 민감정보 과다 노출 bait: user 전체(비밀번호 해시 포함) 반환.
      "src/api/profile/route.ts": `import { db } from "@/lib/db";

export async function GET(req, { params }) {
  // user 레코드에는 email, passwordHash, token 같은 민감 필드가 포함된다.
  const user = await db.users.findUnique({ where: { id: params.id } });
  // BUG: passwordHash 등 민감 필드를 걸러내지 않고 그대로 반환
  return Response.json(user);
}`,
      // WEB-006 경로 트래버설 bait: 사용자 입력을 검증 없이 파일 경로로 사용.
      "src/api/download/route.ts": `import { readFileSync } from "fs";
import path from "path";

export async function GET(req) {
  const name = req.query.file;
  // BUG: 정규화·기준 디렉터리 봉쇄 없이 입력을 파일 경로로 사용 (경로 트래버설)
  const data = readFileSync(path.join("./uploads", name));
  return new Response(data);
}`,
      // BAAS-001 RLS bait: profiles 테이블에 RLS가 없다(정적 SQL 분석 대상).
      "supabase/migrations/0001_init.sql": `-- 데모 스키마
create table public.profiles (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  full_name text,
  phone text
);

-- BUG: profiles에 RLS를 켜지 않았다 — 공개 키로 전체 행 조회 가능.

create table public.notes (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  body text
);

alter table public.notes enable row level security;
create policy "notes_owner" on public.notes
  for all using (owner_id = auth.uid());
`,
    "package.json": JSON.stringify(
      {
        dependencies: {
          next: "13.4.1",
          "@supabase/supabase-js": "2.21.0",
          lodash: "4.17.19",
        },
      },
      null,
      2
    ),
  };

  // 사용자가 붙여넣은 실제 코드가 있으면 AI 스캔 대상으로 추가.
  if (opts.userSource && opts.userSource.trim()) {
    files["user-source:main"] = opts.userSource.trim();
  }

  return {
    projectId,
    name: opts.name,
    repositoryUrl: opts.repositoryUrl,
    deploymentUrl: opts.deploymentUrl,
    commitSha: opts.commitSha,
    stack: {
      frameworks: ["next.js", "react"],
      languages: ["typescript"],
      baas: ["supabase"],
      hasEnvFile: true,
    },
    files,
  };
}
