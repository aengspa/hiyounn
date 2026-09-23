import type { SecurityFinding, FixAttempt, FixDiff } from "@/lib/domain/types";
import { id, now } from "@/lib/util";
import {
  VULNERABLE_HANDLER_SOURCE,
  FIXED_HANDLER_SOURCE,
  HANDLER_FILE,
} from "@/lib/demo/vulnerableApp";

/**
 * Fix generator.
 *
 * The "generation Agent" and the "verification Agent" are logically separate:
 * this module ONLY proposes a fix. It never marks anything resolved — that is
 * the verification engine's job, and only after re-running the attack.
 *
 * In the MVP this uses deterministic, rule-based patches keyed off the
 * finding's verificationKey. When LLM_PROVIDER is configured, callLlmFix()
 * would be swapped in behind the same interface (source: "llm").
 */

function unifiedDiff(before: string, after: string): string {
  const beforeLines = before.split("\n").map((l) => `- ${l}`);
  const afterLines = after.split("\n").map((l) => `+ ${l}`);
  return [...beforeLines, ...afterLines].join("\n");
}

export function generateFix(finding: SecurityFinding): FixAttempt {
  const key = finding.verificationKey ?? "";

  if (key.startsWith("idor:")) {
    const diffs: FixDiff[] = [
      {
        file: HANDLER_FILE,
        patch: unifiedDiff(VULNERABLE_HANDLER_SOURCE, FIXED_HANDLER_SOURCE),
      },
    ];
    return {
      id: id("fix"),
      findingId: finding.id,
      source: "deterministic",
      summary:
        "Add an ownership check so the query only returns the record when it belongs to the logged-in user.",
      plainExplanation:
        "This change adds an authorization check that confirms the requested data belongs to the currently logged-in user. If it doesn't, the app now returns 'Forbidden' instead of the other person's data.",
      diffs,
      applied: false,
      createdAt: now(),
    };
  }

  if (key.startsWith("secret:")) {
    return {
      id: id("fix"),
      findingId: finding.id,
      source: "deterministic",
      summary: "Move the secret to a server-only environment variable and rotate it.",
      plainExplanation:
        "This change removes the secret from your code and reads it from a server-only setting instead, so it is never exposed. You should also regenerate the old value so the leaked one stops working.",
      diffs: [
        {
          file: finding.location?.file ?? "src/lib/db.ts",
          patch: [
            `- const SUPABASE_SERVICE_KEY = "sbp_live_••••••••••••••••••••";`,
            `+ const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;`,
          ].join("\n"),
        },
      ],
      applied: false,
      createdAt: now(),
    };
  }

  if (key.startsWith("headers:")) {
    return {
      id: id("fix"),
      findingId: finding.id,
      source: "deterministic",
      summary: "Add standard security headers in next.config.js.",
      plainExplanation:
        "This change tells browsers how to protect your users by adding standard security headers to every response.",
      diffs: [
        {
          file: "next.config.js",
          patch: [
            `-     return []; // BUG: no security headers configured`,
            `+     return [{`,
            `+       source: "/(.*)",`,
            `+       headers: [`,
            `+         { key: "X-Frame-Options", value: "DENY" },`,
            `+         { key: "X-Content-Type-Options", value: "nosniff" },`,
            `+         { key: "Strict-Transport-Security", value: "max-age=63072000" },`,
            `+         { key: "Content-Security-Policy", value: "default-src 'self'" },`,
            `+       ],`,
            `+     }];`,
          ].join("\n"),
        },
      ],
      applied: false,
      createdAt: now(),
    };
  }

  if (key.startsWith("xss:")) {
    const file = finding.location?.file ?? "src/components/Comment.tsx";
    const bad = finding.evidence.find((e) => e.kind === "source_code")?.content;
    return {
      id: id("fix"),
      findingId: finding.id,
      source: "deterministic",
      summary: "Render user input as text instead of raw HTML (or sanitize it).",
      plainExplanation:
        "이 변경은 사용자 입력을 HTML로 직접 넣지 않고 일반 텍스트로 렌더링합니다. 꼭 HTML이 필요하면 신뢰할 수 있는 정제 라이브러리를 거치도록 합니다.",
      diffs: [
        {
          file,
          patch: [
            `- ${bad ?? `<div dangerouslySetInnerHTML={{ __html: userInput }} />`}`,
            `+ <div>{userInput}</div>  // 텍스트로 렌더링 (React가 자동 인코딩)`,
            `+ // HTML이 반드시 필요하면: dangerouslySetInnerHTML={{ __html: sanitize(userInput) }}`,
          ].join("\n"),
        },
      ],
      applied: false,
      createdAt: now(),
    };
  }

  if (key.startsWith("inj:")) {
    const file = finding.location?.file ?? "src/api/search/route.ts";
    const bad = finding.evidence.find((e) => e.kind === "source_code")?.content ?? "";
    const isEval = /eval|Function|exec/.test(bad);
    return {
      id: id("fix"),
      findingId: finding.id,
      source: "deterministic",
      summary: isEval
        ? "Remove dynamic code/command execution and use a safe alternative."
        : "Use parameterized queries instead of string concatenation.",
      plainExplanation: isEval
        ? "이 변경은 입력값으로 코드를 실행하는 위험한 부분을 제거하고, 안전한 처리 방식으로 바꿉니다."
        : "이 변경은 쿼리에 입력값을 직접 붙이지 않고, 파라미터로 전달해 인젝션을 막습니다.",
      diffs: [
        {
          file,
          patch: isEval
            ? [
                `- ${bad || `const parsed = eval(req.query.expr);`}`,
                `+ const parsed = JSON.parse(req.query.expr); // eval 대신 안전한 파싱`,
              ].join("\n")
            : [
                `- ${bad || "const rows = await db.query(`SELECT * FROM notes WHERE title = '${q}'`);"}`,
                "+ const rows = await db.query(\"SELECT * FROM notes WHERE title = $1\", [q]); // 파라미터 바인딩",
              ].join("\n"),
        },
      ],
      applied: false,
      createdAt: now(),
    };
  }

  if (key.startsWith("trav:")) {
    const file = finding.location?.file ?? "src/api/download/route.ts";
    const bad = finding.evidence.find((e) => e.kind === "source_code")?.content;
    return {
      id: id("fix"),
      findingId: finding.id,
      source: "deterministic",
      summary: "Normalize the path and confine it to a base directory (and whitelist the file name).",
      plainExplanation:
        "이 변경은 사용자가 준 파일 이름을 정규화한 뒤, 허용된 폴더 밖으로 벗어나지 않는지 확인합니다. 벗어나면 요청을 거부합니다.",
      diffs: [
        {
          file,
          patch: [
            `- ${bad ?? `const data = readFileSync(path.join("./uploads", name));`}`,
            `+ const base = path.resolve("./uploads");`,
            `+ const target = path.resolve(base, path.basename(name)); // 파일명만 사용`,
            `+ if (!target.startsWith(base + path.sep)) {`,
            `+   return new Response("forbidden", { status: 403 });`,
            `+ }`,
            `+ const data = readFileSync(target);`,
          ].join("\n"),
        },
      ],
      applied: false,
      createdAt: now(),
    };
  }

  if (key.startsWith("expose:")) {
    const file = finding.location?.file ?? "src/api/profile/route.ts";
    return {
      id: id("fix"),
      findingId: finding.id,
      source: "deterministic",
      summary: "Return only whitelisted fields; strip sensitive fields from the response.",
      plainExplanation:
        "이 변경은 응답에 필요한 필드만 골라 담아, 비밀번호 해시 같은 민감한 값이 밖으로 나가지 않게 합니다.",
      diffs: [
        {
          file,
          patch: [
            `- return Response.json(user);`,
            `+ const { id, email, fullName } = user; // 민감 필드(passwordHash, token 등) 제외`,
            `+ return Response.json({ id, email, fullName });`,
          ].join("\n"),
        },
      ],
      applied: false,
      createdAt: now(),
    };
  }

  if (key.startsWith("bfla:")) {
    return {
      id: id("fix"),
      findingId: finding.id,
      source: "deterministic",
      summary: "Add a server-side role check to admin-only routes.",
      plainExplanation:
        "이 변경은 관리자 전용 경로에 서버측 역할(role) 검사를 추가합니다. 관리자가 아니면 403으로 거부해, 일반 사용자가 관리자 기능을 쓰지 못하게 합니다.",
      diffs: [
        {
          file: finding.location?.file ?? "src/app/api/admin/users/route.ts",
          patch: [
            `  export async function GET(req) {`,
            `+   const session = await getSession(req);`,
            `+   // 관리자 역할이 아니면 접근 거부(함수 수준 권한 검사)`,
            `+   if (session?.user?.role !== "admin") {`,
            `+     return json({ error: "forbidden" }, 403);`,
            `+   }`,
            `    // ... 관리자 작업 ...`,
            `  }`,
          ].join("\n"),
        },
      ],
      applied: false,
      createdAt: now(),
    };
  }

  if (key.startsWith("cookie:")) {
    return {
      id: id("fix"),
      findingId: finding.id,
      source: "deterministic",
      summary: "Set HttpOnly, Secure, and SameSite on session cookies.",
      plainExplanation:
        "이 변경은 세션 쿠키에 보호 속성을 추가합니다. 스크립트가 못 읽게(HttpOnly), HTTPS에서만 전송되게(Secure), 다른 사이트 요청엔 안 실리게(SameSite) 합니다.",
      diffs: [
        {
          file: finding.location?.file ?? "src/lib/authActions.ts",
          patch: [
            `- cookies().set(SESSION_COOKIE, token, { path: "/" });`,
            `+ cookies().set(SESSION_COOKIE, token, {`,
            `+   httpOnly: true,`,
            `+   secure: true,`,
            `+   sameSite: "lax",`,
            `+   path: "/",`,
            `+ });`,
          ].join("\n"),
        },
      ],
      applied: false,
      createdAt: now(),
    };
  }

  if (key.startsWith("brute:")) {
    return {
      id: id("fix"),
      findingId: finding.id,
      source: "deterministic",
      summary: "Add rate limiting / lockout to the login endpoint.",
      plainExplanation:
        "이 변경은 로그인 시도 횟수를 IP·계정 단위로 제한해, 연속 실패가 일정 횟수를 넘으면 잠시 차단(429)합니다. 자동화된 비밀번호 대입을 막습니다.",
      diffs: [
        {
          file: "src/middleware.ts",
          patch: [
            `+ // 로그인 경로 레이트 리밋(예시). 실서비스는 Redis/Upstash 권장.`,
            `+ const hits = new Map<string, { n: number; ts: number }>();`,
            `+ export function middleware(req) {`,
            `+   if (req.nextUrl.pathname.startsWith("/api/auth/login")) {`,
            `+     const key = req.ip ?? "unknown";`,
            `+     const rec = hits.get(key) ?? { n: 0, ts: Date.now() };`,
            `+     if (Date.now() - rec.ts > 60_000) { rec.n = 0; rec.ts = Date.now(); }`,
            `+     rec.n++; hits.set(key, rec);`,
            `+     if (rec.n > 5) return new Response("Too Many Requests", { status: 429 });`,
            `+   }`,
            `+ }`,
          ].join("\n"),
        },
      ],
      applied: false,
      createdAt: now(),
    };
  }

  if (key.startsWith("enum:")) {
    return {
      id: id("fix"),
      findingId: finding.id,
      source: "deterministic",
      summary: "Return identical responses for valid and invalid accounts (and uniform timing).",
      plainExplanation:
        "이 변경은 로그인 실패 시 계정이 있든 없든 똑같은 일반 메시지와 상태코드를 반환하도록 통일합니다. 응답 시간 차이도 없애기 위해, 계정이 없을 때도 더미 비밀번호 검증을 수행합니다.",
      diffs: [
        {
          file: finding.location?.file ?? "src/lib/authActions.ts",
          patch: [
            `- if (!user) return { error: "가입되지 않은 이메일입니다." };`,
            `- if (!verifyPassword(password, user.passwordHash)) return { error: "비밀번호가 틀렸습니다." };`,
            `+ // 계정 유무를 드러내지 않도록 동일한 일반 메시지 + 균일 타이밍`,
            `+ const invalid = { error: "이메일 또는 비밀번호가 올바르지 않습니다." };`,
            `+ const hash = user?.passwordHash ?? DUMMY_HASH; // 없어도 더미 검증(타이밍 균일화)`,
            `+ const ok = verifyPassword(password, hash);`,
            `+ if (!user || !ok) return invalid;`,
          ].join("\n"),
        },
      ],
      applied: false,
      createdAt: now(),
    };
  }

  if (key.startsWith("tls:")) {
    return {
      id: id("fix"),
      findingId: finding.id,
      source: "deterministic",
      summary: "Redirect all HTTP to HTTPS and enable HSTS.",
      plainExplanation:
        "이 변경은 모든 평문(HTTP) 요청을 HTTPS로 돌리고, 브라우저가 항상 HTTPS로만 접속하도록 HSTS 헤더를 추가합니다.",
      diffs: [
        {
          file: "next.config.js",
          patch: [
            `+   async headers() {`,
            `+     return [{`,
            `+       source: "/(.*)",`,
            `+       headers: [`,
            `+         { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },`,
            `+       ],`,
            `+     }];`,
            `+   },`,
            `+   // 호스팅(예: Vercel/Nginx)에서 http→https 강제 리다이렉트도 함께 설정하세요.`,
          ].join("\n"),
        },
      ],
      applied: false,
      createdAt: now(),
    };
  }

  if (key.startsWith("exposed:")) {
    return {
      id: id("fix"),
      findingId: finding.id,
      source: "deterministic",
      summary: "Block sensitive paths and disable debug routes in production.",
      plainExplanation:
        "이 변경은 .env, .git 같은 민감 경로 접근을 차단하고, 디버그 라우트를 프로덕션에서 끄는 리다이렉트/거부 규칙을 추가합니다.",
      diffs: [
        {
          file: "next.config.js",
          patch: [
            `+   async redirects() {`,
            `+     // 민감 경로를 외부에서 접근하지 못하도록 차단(404 처리)`,
            `+     return [`,
            `+       { source: "/.env", destination: "/404", permanent: false },`,
            `+       { source: "/.git/:path*", destination: "/404", permanent: false },`,
            `+       { source: "/debug", destination: "/404", permanent: false },`,
            `+     ];`,
            `+   },`,
          ].join("\n"),
        },
      ],
      applied: false,
      createdAt: now(),
    };
  }

  if (key.startsWith("rls:")) {
    return {
      id: id("fix"),
      findingId: finding.id,
      source: "deterministic",
      summary: "Enable RLS and add an owner-only policy on the table.",
      plainExplanation:
        "This change turns on access rules for your database table so each person can only see their own rows.",
      diffs: [
        {
          file: "supabase/policies.sql",
          patch: [
            `+ alter table public.profiles enable row level security;`,
            `+ create policy "own rows" on public.profiles`,
            `+   for select using (auth.uid() = user_id);`,
          ].join("\n"),
        },
      ],
      applied: false,
      createdAt: now(),
    };
  }

  // Generic fallback.
  return {
    id: id("fix"),
    findingId: finding.id,
    source: "deterministic",
    summary: finding.remediation ?? "Apply the recommended remediation.",
    plainExplanation:
      finding.remediation ??
      "Follow the recommended remediation steps for this finding.",
    diffs: [],
    applied: false,
    createdAt: now(),
  };
}


// ─────────────────────────────────────────────────────────────
// AI 기반 수정안 생성 (LLM 설정 시)
// ─────────────────────────────────────────────────────────────

import { isConfigured, completeJson } from "@/lib/ai/llmClient";

const FIX_SYSTEM_PROMPT = `당신은 시니어 보안 엔지니어입니다.
주어진 취약점에 대한 코드 수정안을 제안합니다.
반드시 아래 JSON 하나만 출력하세요.

{
  "summary": "무엇을 어떻게 고치는지 한 문장(한국어)",
  "plainExplanation": "코드를 모르는 사용자를 위한 쉬운 설명(한국어)",
  "file": "수정할 파일 경로",
  "before": "수정 전 코드(문제되는 부분)",
  "after": "수정 후 코드"
}

규칙: 최소한의 변경만 제안하고, 실제 동작하는 코드를 제시하세요.`;

interface AiFixRaw {
  summary?: string;
  plainExplanation?: string;
  file?: string;
  before?: string;
  after?: string;
}

/**
 * 수정안 생성 진입점.
 * - LLM이 설정되어 있으면 AI로 수정안 생성 시도 (source: "llm").
 * - 실패하거나 미설정이면 규칙 기반 generateFix()로 fallback.
 *
 * 생성 Agent와 검증 Agent는 분리되어 있습니다. 이 함수는 수정안을 "제안"만
 * 하며, 해결 여부는 검증 엔진이 결정합니다.
 */
export async function generateFixSmart(
  finding: SecurityFinding
): Promise<FixAttempt> {
  const key = finding.verificationKey ?? "";
  const deterministicKnown =
    key.startsWith("idor:") ||
    key.startsWith("secret:") ||
    key.startsWith("headers:") ||
    key.startsWith("rls:") ||
    key.startsWith("xss:") ||
    key.startsWith("inj:") ||
    key.startsWith("expose:") ||
    key.startsWith("trav:") ||
    key.startsWith("exposed:") ||
    key.startsWith("tls:") ||
    key.startsWith("enum:") ||
    key.startsWith("brute:") ||
    key.startsWith("cookie:") ||
    key.startsWith("bfla:");

  // 결정적으로 잘 아는 취약점은 규칙 기반이 더 정확 → 그대로 사용.
  if (deterministicKnown || !isConfigured()) {
    return generateFix(finding);
  }

  // 그 외(주로 AI가 찾은 항목)는 AI에게 수정안을 요청.
  try {
    const evidenceText = finding.evidence
      .map((e) => `[${e.kind}] ${e.label}\n${e.content}`)
      .join("\n\n");
    const raw = await completeJson(
      FIX_SYSTEM_PROMPT,
      `취약점: ${finding.title}\n영향: ${finding.humanReadableImpact}\n\n근거:\n${evidenceText}\n\nJSON으로만 답하세요.`
    );
    const parsed = JSON.parse(stripFence(raw)) as AiFixRaw;
    const before = parsed.before ?? "";
    const after = parsed.after ?? "";
    return {
      id: id("fix"),
      findingId: finding.id,
      source: "llm",
      summary: parsed.summary || finding.remediation || "AI가 제안한 수정안입니다.",
      plainExplanation:
        parsed.plainExplanation ||
        "이 변경은 발견된 보안 문제를 해결하기 위한 것입니다.",
      diffs:
        before || after
          ? [{ file: parsed.file || "붙여넣은 코드", patch: unifiedDiff(before, after) }]
          : [],
      applied: false,
      createdAt: now(),
    };
  } catch {
    // AI 실패 시 규칙 기반으로 안전하게 fallback.
    return generateFix(finding);
  }
}

function stripFence(text: string): string {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenced) return fenced[1].trim();
  const b = text.indexOf("{");
  const e = text.lastIndexOf("}");
  if (b >= 0 && e > b) return text.slice(b, e + 1);
  return text.trim();
}
