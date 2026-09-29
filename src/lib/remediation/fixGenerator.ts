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
        "정보를 보여주기 전에 그 정보가 현재 로그인한 사람의 것인지 확인하도록 바꾸는 수정안이에요.",
      plainExplanation:
        "지금 코드는 요청한 번호만 보고 정보를 찾아 돌려줘요. 이 수정안은 로그인한 사람의 정보일 때만 돌려주고, 다른 사람의 정보면 거절(403)하게 해요. 로그인한 사람이 자기 정보를 보는 흐름은 그대로 유지돼요. 적용한 뒤 자기 정보는 보이고, 다른 사람의 번호로 요청하면 거절되는지 확인해 주세요.",
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
      summary: "코드에 직접 적힌 비밀키를 빼고, 서버 환경변수에서 읽도록 바꾸는 수정안이에요.",
      plainExplanation:
        "외부 서비스에 접속할 때 쓰는 비밀키가 코드에 직접 들어 있어요. 이 수정안은 키를 코드에서 빼고 서버 환경변수 SUPABASE_SERVICE_ROLE_KEY에서 읽게 해요. 기능이 전처럼 동작하려면 배포 서비스의 비밀 설정에 이 값을 넣어야 해요. 이미 공개된 키라면 코드만 바꿔서는 막을 수 없으니, 새 키를 발급하고 기존 키를 사용할 수 없게 해 주세요. 적용한 뒤 이 키를 쓰는 기능이 정상으로 동작하는지 확인해 주세요.",
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
      summary: "모든 페이지 응답에 브라우저 보호 설정(보안 헤더)을 추가하는 수정안이에요.",
      plainExplanation:
        "지금 설정 파일(next.config.js)에는 브라우저에 보내는 보호 설정이 없어요. 이 수정안은 다른 사이트가 내 페이지를 몰래 화면 안에 넣지 못하게 하는 설정 등 4가지를 모든 응답에 붙여요. 이 중 콘텐츠 보안 정책(Content-Security-Policy)은 내 사이트 밖의 스크립트·이미지·글꼴을 막아서, 외부 서비스를 쓰는 화면이 깨질 수 있어요. 적용한 뒤 주요 화면이 전처럼 보이고 동작하는지 확인해 주세요.",
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
      summary: "사용자가 입력한 글을 화면에 그대로 실행하지 않고 글자로만 표시하도록 바꾸는 수정안이에요.",
      plainExplanation:
        "지금 코드는 사용자가 입력한 내용을 HTML로 그대로 화면에 넣어요. 입력에 스크립트가 섞여 있으면 글을 보는 사람의 브라우저에서 실행될 수 있어요. 이 수정안은 입력을 글자로만 표시해서, 글 내용은 그대로 보이고 태그는 실행되지 않게 해요. 굵은 글씨 같은 HTML 서식이 꼭 필요하다면 믿을 수 있는 정리 도구(sanitize 라이브러리)를 거친 뒤 넣어야 해요. 적용한 뒤 글이 전처럼 보이는지, <b> 같은 태그를 입력하면 글자 그대로 보이는지 확인해 주세요.",
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
        ? "요청으로 들어온 값을 코드로 실행하지 않고, 데이터로만 읽도록 바꾸는 수정안이에요."
        : "데이터베이스 조회문에 입력값을 직접 이어 붙이지 않고, 값으로만 따로 전달하도록 바꾸는 수정안이에요.",
      plainExplanation: isEval
        ? "지금 코드는 요청에 들어온 값을 프로그램 코드처럼 실행해요(eval 등). 누군가 이 값에 코드를 넣어 보내면 서버에서 그대로 실행될 수 있어요. 이 수정안은 값을 실행하지 않고 JSON 데이터로만 읽게 해요. JSON 형식이 아닌 값을 보내던 기능은 오류가 날 수 있으니, 적용한 뒤 평소 보내는 값이 정상으로 처리되는지 확인해 주세요."
        : "지금 코드는 사용자가 보낸 값을 데이터베이스 조회문(SQL)에 글자 그대로 이어 붙여요. 값에 조회문 일부를 섞어 보내면 의도하지 않은 조회가 실행될 수 있어요(SQL 인젝션). 이 수정안은 값을 조회문과 분리해 따로 전달해요(파라미터 바인딩). 조회 결과는 전과 같아야 해요. 적용한 뒤 평소 검색이 그대로 되는지, 작은따옴표(')가 들어간 값도 오류 없이 처리되는지 확인해 주세요.",
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
      summary: "요청한 파일 이름에서 폴더 경로를 떼어 내고, 허용한 폴더(uploads) 안의 파일만 읽도록 바꾸는 수정안이에요.",
      plainExplanation:
        "지금 코드는 사용자가 보낸 파일 이름을 그대로 경로에 붙여 파일을 읽어요. 이름에 ../ 같은 경로를 넣으면 허용한 폴더 밖의 파일까지 읽힐 수 있어요. 이 수정안은 파일 이름만 남기고, 최종 위치가 uploads 폴더 밖이면 거절(403)해요. uploads 폴더에 바로 들어 있는 파일을 받는 흐름은 그대로예요. 하위 폴더의 파일을 받던 기능이 있다면 동작이 바뀌니, 적용한 뒤 평소 받던 파일이 그대로 내려받아지는지 확인해 주세요.",
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
      summary: "응답에 필요한 정보(id, email, fullName)만 골라 보내도록 바꾸는 수정안이에요.",
      plainExplanation:
        "지금 코드는 데이터베이스에서 읽은 사용자 정보를 통째로 응답에 담아요. 그 안에 비밀번호 해시나 토큰 같은 값이 있으면 요청한 사람에게 그대로 전달될 수 있어요. 이 수정안은 화면에 필요한 값만 골라 보내요. 적용한 뒤 이 정보를 쓰는 화면이 전처럼 보이는지 확인해 주세요. 빠진 값 때문에 비어 보이는 곳이 있으면, 그 값이 민감하지 않은지 확인한 뒤 목록에 직접 추가해 주세요.",
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
      summary: "관리자 기능을 실행하기 전에 요청한 사람이 관리자인지 서버에서 확인하도록 바꾸는 수정안이에요.",
      plainExplanation:
        "지금 코드는 관리자용 주소로 들어온 요청을 누가 보냈는지 확인하지 않고 처리해요. 이 수정안은 로그인 정보(세션)의 역할이 admin인 사람만 통과시키고, 그 외에는 거절(403)해요. 관리자가 기능을 쓰는 흐름은 그대로 유지돼요. getSession이 프로젝트에 실제로 있는 함수인지 확인하고, 없으면 지금 쓰는 로그인 확인 방식으로 바꿔 주세요. 적용한 뒤 관리자 계정은 기능을 쓸 수 있고 일반 계정은 거절되는지 확인해 주세요.",
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
      summary: "로그인 상태를 저장하는 쿠키에 보호 설정 세 가지(HttpOnly, Secure, SameSite)를 추가하는 수정안이에요.",
      plainExplanation:
        "지금 로그인 쿠키에는 보호 설정이 없어요. 이 수정안은 페이지의 스크립트가 쿠키를 읽지 못하게 하고(HttpOnly), 암호화된 연결(HTTPS)에서만 보내며(Secure), 다른 사이트에서 시작된 요청에는 쿠키가 실리지 않게 해요(SameSite). 로그인·로그아웃 흐름은 그대로예요. HTTPS가 아닌 주소에서는 Secure 설정 때문에 로그인이 유지되지 않을 수 있어요. 적용한 뒤 배포한 사이트에서 로그인이 유지되는지 확인해 주세요.",
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
      summary: "로그인을 짧은 시간에 너무 많이 시도하면 잠시 거절하도록 바꾸는 수정안이에요.",
      plainExplanation:
        "지금 로그인 주소는 시도 횟수에 제한이 없어, 프로그램으로 비밀번호를 계속 바꿔 넣어 볼 수 있어요. 이 수정안은 같은 접속 주소(IP)에서 1분에 5번을 넘게 시도하면 잠시 거절(429)해요. 평소처럼 몇 번 로그인하는 흐름에는 영향이 없어요. 이 예시는 서버 메모리에 횟수를 세서, 서버가 여러 대이거나 다시 시작되면 횟수가 따로 세어져요. src/middleware.ts가 이미 있다면 기존 내용과 합쳐야 해요. 적용한 뒤 정상 로그인이 되는지, 6번째 시도부터 거절되는지 확인해 주세요.",
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
      summary: "로그인에 실패했을 때 가입된 이메일인지 드러나지 않도록 같은 안내 문구를 보여 주는 수정안이에요.",
      plainExplanation:
        "지금 코드는 '가입되지 않은 이메일'과 '비밀번호가 틀림'을 다르게 알려 줘요. 이 차이로 어떤 이메일이 가입돼 있는지 알아낼 수 있어요. 이 수정안은 두 경우 모두 같은 문구로 답하고, 계정이 없을 때도 비밀번호 확인을 한 번 해서 응답 시간 차이도 줄여요. 올바른 이메일과 비밀번호로 로그인하는 흐름은 그대로예요. DUMMY_HASH 값이 프로젝트에 정의돼 있는지 확인하고, 적용한 뒤 정상 로그인과 실패 안내가 모두 제대로 나오는지 확인해 주세요.",
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
      summary: "브라우저가 이 사이트에 항상 암호화된 연결(HTTPS)로만 접속하도록 설정을 추가하는 수정안이에요.",
      plainExplanation:
        "이 수정안은 브라우저에 '이 사이트는 앞으로 HTTPS로만 접속하라'는 설정(HSTS 헤더)을 보내게 해요. 암호화되지 않은 주소(http://)로 들어온 요청을 HTTPS로 옮기는 설정은 이 코드만으로는 되지 않아요. 호스팅 서비스(예: Vercel, Nginx) 설정에서 HTTP를 HTTPS로 옮기는 기능을 직접 켜 주세요. 하위 도메인까지 적용되는 옵션이 들어 있어서, 모든 하위 도메인이 HTTPS를 지원해야 해요. 적용한 뒤 사이트와 하위 도메인이 모두 HTTPS로 열리는지 확인해 주세요.",
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
      summary: "밖에서 열리면 안 되는 주소(.env, .git, /debug)로 온 요청을 없는 페이지(404)로 보내는 수정안이에요.",
      plainExplanation:
        "설정 파일(.env), 코드 기록(.git), 디버그 화면이 밖에서 열리면 비밀값이나 내부 정보가 보일 수 있어요. 이 수정안은 next.config.js에 이 주소들을 404 페이지로 돌리는 규칙을 추가해요. 다른 페이지 흐름에는 영향이 없어요. 디버그 기능 자체를 끄는 것은 아니니, 배포 환경에서 꺼져 있는지 따로 확인해 주세요. 적용한 뒤 배포한 사이트에서 /.env, /.git/config, /debug 주소를 열어 내용이 보이지 않는지 확인해 주세요.",
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
      summary: "데이터베이스 profiles 표에 행 단위 접근 규칙(RLS)을 켜고, 자기 행만 읽을 수 있게 하는 수정안이에요.",
      plainExplanation:
        "지금 profiles 표에는 누가 어떤 행을 읽을 수 있는지 정하는 규칙이 켜져 있지 않아요. 이 수정안은 표에 행 단위 접근 규칙(Row Level Security)을 켜고, user_id가 로그인한 사람과 같은 행만 읽히게 해요. 이 SQL은 Supabase의 SQL 편집기에서 직접 실행해야 적용돼요. 규칙을 켜면 읽기 외의 저장·수정·삭제도 따로 규칙을 만들기 전까지 거절돼요. 적용한 뒤 자기 정보는 보이고 다른 사람의 행은 보이지 않는지, 저장 기능이 계속 되는지 확인해 주세요.",
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
    summary:
      finding.remediation ?? "이 항목은 정해진 자동 수정 규칙이 없어 코드 변경안을 만들지 않았어요.",
    plainExplanation: [
      "이 항목은 정해진 자동 수정 규칙이 없어 코드 변경안을 만들지 않았어요.",
      finding.remediation
        ? `수정 방향: ${finding.remediation}`
        : "점검 결과의 설명을 참고해 문제가 된 코드를 직접 고쳐 주세요.",
      "고친 뒤 다시 점검해서 같은 문제가 남아 있는지 확인해 주세요.",
    ].join(" "),
    diffs: [],
    applied: false,
    createdAt: now(),
  };
}


// ─────────────────────────────────────────────────────────────
// AI 기반 수정안 생성 (LLM 설정 시)
// ─────────────────────────────────────────────────────────────

import { isConfigured, completeJson } from "@/lib/ai/llmClient";

/** 테스트에서 JSON 필드 이름이 그대로인지 확인할 수 있게 내보낸다. */
export const FIX_SYSTEM_PROMPT = `당신은 시니어 보안 엔지니어입니다.
주어진 취약점에 대한 코드 수정안을 제안합니다.
반드시 아래 JSON 하나만 출력하세요.

{
  "summary": "무엇을 어떻게 고치는지 한 문장(한국어)",
  "plainExplanation": "코드를 모르는 사용자를 위한 쉬운 설명(한국어)",
  "file": "수정할 파일 경로",
  "before": "수정 전 코드(문제되는 부분)",
  "after": "수정 후 코드"
}

규칙: 최소한의 변경만 제안하고, 실제 동작하는 코드를 제시하세요.

[summary와 plainExplanation 작성법]
- 이 단계는 수정안을 "제안"하는 단계입니다. 파일에 적용하지도, 다시 검사하지도 않았습니다.
  "해결했어요", "막았어요", "고쳤어요", "안전해졌어요"처럼 결과를 단정하지 말고
  "~하도록 바꾸는 수정안이에요", "~하게 해요"처럼 쓰세요.
- summary: 무엇을 어떻게 바꾸는지 한 문장.
  예: "정보를 보여주기 전에 그 정보가 현재 로그인한 사람의 것인지 확인하도록 바꾸는 수정안이에요."
- plainExplanation: 짧은 문장 3~5개로, 아래 순서대로 씁니다.
  1) 무엇을 바꾸는지  2) 왜 바꾸는지(지금 코드의 어떤 처리 때문인지)
  3) 정상 사용 흐름을 어떻게 유지하는지(동작이 바뀌는 부분이 있으면 그것도)
  4) 적용한 뒤 사용자가 직접 확인할 것(실제 사용자 행동으로. 예: "로그인한 사람이 자기 정보를 볼 수 있는지 확인해 주세요.")
- 수정에 환경변수나 배포 설정이 필요하면 그 이름과, 사용자가 설정에 직접 넣어야 한다는 점을 plainExplanation에 씁니다.
- 주어진 근거만으로 안전한 코드 변경을 만들 수 없으면 before와 after를 빈 문자열로 두고,
  plainExplanation에 왜 지금 정보만으로는 고칠 수 없는지, 어떤 파일이나 정보가 더 필요한지,
  사용자가 설정(예: 배포 서비스의 비밀 설정)에서 직접 바꿔야 하는 부분이 있는지 씁니다.`;

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
      summary: parsed.summary || finding.remediation || "AI가 제안한 수정안이에요. 아직 파일에 적용하지 않았어요.",
      plainExplanation:
        parsed.plainExplanation ||
        "AI가 이 수정안에 대한 설명을 보내지 않았어요. 변경 전·후 코드를 직접 확인하고, 적용한 뒤 다시 점검해서 같은 문제가 남았는지 확인해 주세요.",
      diffs:
        before || after
          ? [
              {
                file: parsed.file || "붙여넣은 코드",
                patch: unifiedDiff(before, after),
                beforeText: before,
                afterText: after,
              },
            ]
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
