/**
 * 수정본이 새로 요구하는 환경변수 찾기.
 *
 * 수정이 process.env.X를 새로 읽게 만들면(비밀값을 코드에서 뺐거나, 허용 목록·서명 키가
 * 필요해진 경우), 받은 파일을 반영하기 전에 그 값을 설정해야 한다. 설정하지 않으면
 * 안전한 쪽으로 멈추도록(요청 거절) 고쳐져 있어서 기능이 동작하지 않는다.
 * 원본 프로젝트 어디에서든 이미 쓰던 이름은 이미 설정돼 있다고 보고 뺀다.
 */

export interface RequiredEnv {
  name: string;
  kind: "secret" | "allowlist" | "config";
  files: string[];
  guidance: string;
}

const ENV_RE = /process\.env\.([A-Z][A-Z0-9_]*)|process\.env\[\s*["'`]([A-Z][A-Z0-9_]*)["'`]\s*\]/g;

function envNames(content: string): Set<string> {
  const out = new Set<string>();
  for (const m of content.matchAll(ENV_RE)) out.add(m[1] ?? m[2]);
  return out;
}

const WHERE = "로컬은 .env.local, Vercel은 Project Settings → Environment Variables(Production·Preview 각각)에 넣고 다시 배포하세요.";

export function guidanceFor(name: string): { kind: RequiredEnv["kind"]; guidance: string } {
  if (/^JWT_(SECRET|KEY)$/.test(name) || /JWT.*SECRET/.test(name)) {
    return {
      kind: "secret",
      guidance: `로그인 토큰이 진짜인지 확인할 때 쓰는 비밀키(서명 키)예요. 토큰을 발급하는 쪽과 같은 값이어야 하고(HS256), 32바이트 이상 무작위 값을 쓰세요(예: openssl rand -base64 48). 비어 있으면 로그인이 필요한 요청이 모두 거절돼요. ${WHERE}`,
    };
  }
  if (/ALLOWED_HOSTS|ALLOWLIST|ALLOWED_ORIGINS|ALLOWED_DOMAINS/.test(name)) {
    return {
      kind: "allowlist",
      guidance: `서버가 요청해도 되는 호스트 이름만 쉼표로 구분해 넣으세요(예: example.com,www.example.com). https://, 포트, 경로는 빼고, localhost·내부 주소·IP는 넣지 마세요. 비워 두면 이 기능은 모든 요청을 거절해요. ${WHERE}`,
    };
  }
  if (/SECRET|KEY|TOKEN|PASSWORD|PRIVATE|CREDENTIAL/.test(name)) {
    return {
      kind: "secret",
      guidance: `코드에서 뺀 비밀값이에요. 새로 발급한 값을 넣고, 코드에 적혀 있던(노출된) 값은 폐기하세요. 저장소나 코드에는 넣지 마세요. ${WHERE}`,
    };
  }
  return { kind: "config", guidance: `수정본이 새로 읽는 설정값이에요. 알맞은 값을 넣으세요. ${WHERE}` };
}

export function requiredEnvForFix(
  baseFiles: Record<string, string>,
  fixedFiles: Record<string, string>,
  changedFiles: string[]
): RequiredEnv[] {
  const known = new Set<string>();
  for (const content of Object.values(baseFiles)) for (const n of envNames(content)) known.add(n);
  const found = new Map<string, Set<string>>();
  for (const file of changedFiles) {
    for (const n of envNames(fixedFiles[file] ?? "")) {
      if (known.has(n)) continue;
      found.set(n, (found.get(n) ?? new Set()).add(file));
    }
  }
  return [...found.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, files]) => ({ name, files: [...files].sort(), ...guidanceFor(name) }));
}
