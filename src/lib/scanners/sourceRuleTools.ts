import type { Check } from "@/lib/rules/types";
import { RuleToolRuntime, gap, safeLabel, type ToolResult } from "@/lib/scanners/ruleToolRuntime";

const POPULAR = ["react", "next", "express", "lodash", "axios", "typescript", "vite", "firebase", "openai", "@supabase/supabase-js"];
interface Dependency { name: string; version: string }
interface PackageMetadata { scripts?: Record<string, string>; time?: { created?: string } }

function dependencies(runtime: RuleToolRuntime): Dependency[] {
  const source = runtime.context.files["package.json"];
  if (!source) throw new Error("package.json이 없어 npm 패키지를 점검할 수 없습니다.");
  const manifest = JSON.parse(source) as Record<string, Record<string, unknown>>;
  const names = new Map<string, string>();
  for (const group of ["dependencies", "devDependencies", "optionalDependencies"]) {
    for (const [name, version] of Object.entries(manifest[group] ?? {})) {
      if (typeof version === "string") names.set(name, version);
    }
  }
  let lock: { packages?: Record<string, { version?: string }> } = {};
  if (runtime.context.files["package-lock.json"]) lock = JSON.parse(runtime.context.files["package-lock.json"]);
  return [...names].map(([name, version]) => ({ name, version: lock.packages?.[`node_modules/${name}`]?.version ?? version }));
}

function similarName(a: string, b: string): boolean {
  if (a === b || Math.abs(a.length - b.length) > 1) return false;
  if (a.length === b.length) {
    const diffs = [...a].map((c, i) => c === b[i] ? -1 : i).filter((i) => i >= 0);
    return diffs.length === 1 || (diffs.length === 2 && diffs[1] === diffs[0] + 1 &&
      a[diffs[0]] === b[diffs[1]] && a[diffs[1]] === b[diffs[0]]);
  }
  const longer = a.length > b.length ? a : b;
  const shorter = a.length > b.length ? b : a;
  return [...longer].some((_, i) => longer.slice(0, i) + longer.slice(i + 1) === shorter);
}

async function packageMetadata(runtime: RuleToolRuntime, dep: Dependency): Promise<{ missing: boolean; data?: PackageMetadata }> {
  if (!/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(dep.name)) throw new Error("지원하지 않는 패키지 이름입니다.");
  if (/^(?:file:|link:|workspace:|git|https?:|npm:)/.test(dep.version)) {
    throw new Error("npm 레지스트리 외의 의존성은 별도 출처 검토가 필요합니다.");
  }
  const key = `package:${dep.name}@${dep.version}`;
  if (runtime.cache.has(key)) return runtime.cache.get(key) as { missing: boolean; data?: PackageMetadata };
  const version = /^\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/.test(dep.version) ? dep.version : "latest";
  const response = await runtime.request(`https://registry.npmjs.org/${encodeURIComponent(dep.name)}/${encodeURIComponent(version)}`);
  const result = response.status === 404 ? { missing: true } : {
    missing: false,
    data: response.status === 200 ? JSON.parse(response.body) as PackageMetadata : undefined,
  };
  if (!result.missing && !result.data) throw new Error("npm 레지스트리 조회에 실패했습니다.");
  runtime.cache.set(key, result);
  return result;
}

async function provenance(runtime: RuleToolRuntime, check: Check): Promise<ToolResult> {
  const deps = dependencies(runtime);
  if (deps.length === 0) return gap("점검할 npm 의존성이 없습니다.");
  const findings: ToolResult["findings"] = [];
  const failures: string[] = [];
  const limit = check.id === "package-age-popularity" ? 15 : 50;
  if (deps.length > limit) failures.push(`요청 상한으로 ${deps.length - limit}개 패키지는 점검하지 못했습니다.`);
  for (const dep of deps.slice(0, limit)) {
    try {
      let reasons: string[] = [];
      let confirmed = false;
      if (check.id === "typosquat-similarity") {
        const lookalike = POPULAR.find((known) => similarName(known, dep.name));
        if (lookalike) reasons.push(`공식 패키지 ${lookalike}와 이름이 유사합니다.`);
      } else if (check.id === "registry-existence") {
        if ((await packageMetadata(runtime, dep)).missing) {
          reasons.push("선언한 npm 패키지/버전이 레지스트리에 없습니다. 비공개 패키지는 별도 확인하세요.");
          confirmed = true;
        }
      } else if (check.id === "install-script-audit") {
        const metadata = await packageMetadata(runtime, dep);
        if (metadata.missing) { failures.push(`${safeLabel(dep.name)}: 레지스트리 항목 없음`); continue; }
        const hooks = ["preinstall", "install", "postinstall"].filter((hook) => metadata.data?.scripts?.[hook]);
        if (hooks.length) reasons.push(`설치 스크립트 검토 필요: ${hooks.join(", ")}`);
      } else if (check.id === "package-age-popularity") {
        const metadata = await runtime.request(`https://registry.npmjs.org/${encodeURIComponent(dep.name)}`, { maxBytes: 1024 * 1024 });
        if (metadata.status !== 200) throw new Error("패키지 생성 시점 조회 실패");
        const created = (JSON.parse(metadata.body) as PackageMetadata).time?.created;
        if (!created || !Number.isFinite(Date.parse(created))) throw new Error("생성 시점이 없습니다.");
        const age = (Date.now() - Date.parse(created)) / 86_400_000;
        if (age < Number(check.params?.minAgeDays ?? 30)) reasons.push(`생성된 지 ${Math.max(0, Math.floor(age))}일 된 패키지입니다.`);
        const downloads = await runtime.request(`https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(dep.name)}`);
        if (downloads.status !== 200) throw new Error("주간 다운로드 조회 실패");
        const count = (JSON.parse(downloads.body) as { downloads?: number }).downloads;
        if (typeof count !== "number") throw new Error("다운로드 통계가 없습니다.");
        if (count < Number(check.params?.minWeeklyDownloads ?? 100)) reasons.push(`주간 다운로드 ${count}회로 출처 확인이 필요합니다.`);
      } else return gap(`지원하지 않는 출처 검사: ${check.id}`);

      if (reasons.length) findings.push(runtime.finding(check,
        `${safeLabel(dep.name)}: ${reasons.join(" ")} 버전 범위는 latest 메타데이터로 추정합니다.`,
        `${safeLabel(dep.name)} — ${reasons.join(" ")}`, { confirmed, key: `tool:${runtime.rule.id}:${check.id}:${dep.name}` }));
    } catch {
      failures.push(`${safeLabel(dep.name)}: 출처 정보를 조회하지 못했습니다.`);
    }
  }
  return { findings, gap: failures.length ? failures.join("\n") : undefined };
}

const LLM_USE = /openai|anthropic|langchain|generateText|chat\.completions|responses\.create|messages\.create/i;
const SECRET = /sk-[A-Za-z0-9_-]{12,}|(?:api[_-]?key|password|secret)\s*[:=]\s*["'][^"']{8,}["']/i;
const SOURCE_FILE = /\.(?:[cm]?[jt]sx?|py|rb|php|go|java|cs)$/i;

function analyzeLlm(runtime: RuleToolRuntime, check: Check): ToolResult {
  const files = Object.entries(runtime.context.files).filter(([path, source]) => SOURCE_FILE.test(path) &&
    !/(?:^|\/)(?:node_modules|vendor|\.git)\//.test(path) && LLM_USE.test(source));
  if (!files.length) return gap("LLM 통합 소스가 없어 데이터 흐름을 점검하지 못했습니다.");
  const findings: ToolResult["findings"] = [];
  for (const [file, source] of files) {
    const lines = source.split("\n");
    lines.forEach((line, index) => {
      const window = lines.slice(Math.max(0, index - 5), index + 6).join("\n");
      let signal = false;
      let reason = "";
      switch (check.id) {
        case "scan-secret-in-system-prompt":
          signal = SECRET.test(line) && /(?:role\s*:\s*["']system|system|prompt|instructions)/i.test(window);
          reason = "시스템 프롬프트 주변에 비밀정보 형태가 있습니다.";
          break;
        case "scan-llm-output-to-sink":
          signal = /eval\s*\(|(?:exec|execSync|query|execute)\s*\(|new\s+Function\s*\(/.test(line) &&
            /completion|output|response\.(?:choices|output)|message\.content/i.test(window);
          reason = "모델 출력이 코드·셸·DB 실행 싱크에 연결될 수 있습니다.";
          break;
        case "scan-llm-tool-permissions":
          signal = /(?:tools|functions)\s*[:=]|tool_choice/.test(line) &&
            /exec|shell|delete|write|update|filesystem/i.test(window) && !/confirm|approval|allowlist|authorize/i.test(window);
          reason = "LLM 쓰기/실행 도구 주변에 승인·허용 목록이 보이지 않습니다.";
          break;
        case "scan-llm-output-rendered-html":
          signal = /dangerouslySetInnerHTML|\.innerHTML\s*=|\.html\s*\(/.test(line) &&
            /completion|output|response|message\.content/i.test(window) && !/DOMPurify|sanitizeHtml/.test(window);
          reason = "모델 출력이 HTML로 렌더링되는 경로가 있습니다.";
          break;
      }
      if (signal) findings.push(runtime.finding(check, `${reason} 정적 신호이므로 코드 흐름 검토가 필요합니다.`,
        `${safeLabel(file)}:${index + 1} — ${reason}`, { file, line: index + 1 }));
    });
  }
  return { findings };
}

export async function executeSourceTool(runtime: RuleToolRuntime, check: Check): Promise<ToolResult> {
  return check.toolId === "package_provenance_checker" ? provenance(runtime, check) : analyzeLlm(runtime, check);
}
