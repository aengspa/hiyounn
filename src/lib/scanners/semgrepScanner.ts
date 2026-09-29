import { spawn } from "child_process";
import { existsSync } from "fs";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "fs/promises";
import os from "os";
import path from "path";
import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import type { RegressionTest, ScanScope, SecurityFinding, VerificationResult, VerificationTest } from "@/lib/domain/types";
import { VerificationUnavailableError } from "@/lib/store/errors";
import { safeProjectPath } from "@/lib/remediation/patchEngine";
import { issueClass } from "@/lib/scanners/findingMerge";
import { stillPresentAfterFix } from "@/lib/scanners/findingPresence";
import { id, now } from "@/lib/util";
import { installedBin } from "@/lib/tools/installableTools";
import { logToolEvent } from "@/lib/tools/toolInstaller";

/**
 * Semgrep 규칙 검사(기준 규칙 검사기 중 하나).
 *
 * SEMGREP_BIN(또는 PATH의 semgrep, 또는 서버가 도구 폴더에 설치한 고정 버전)이 있을 때만 돈다. 임시 폴더에 코드 사본을 쓰고
 * semgrep을 실행한다(서버의 키·비밀값 환경변수는 넘기지 않음). 레지스트리 규칙
 * (SEMGREP_CONFIG, 기본 p/javascript,p/nodejsscan,p/owasp-top-ten)은 semgrep이
 * 내려받는다. 결과 줄 내용은 semgrep 출력이 아니라 우리 파일에서 읽는다.
 */

const DEFAULT_CONFIG = "p/javascript,p/nodejsscan,p/owasp-top-ten";
const CODE = /\.(?:m?[jt]sx?|cjs|py|go|java|rb|php)$/;
const RUN_TIMEOUT_MS = 120_000;

export function semgrepBin(env: Record<string, string | undefined> = process.env): string | undefined {
  const explicit = env.SEMGREP_BIN?.trim();
  if (explicit) return existsSync(explicit) ? explicit : undefined;
  for (const dir of (env.PATH ?? "").split(path.delimiter)) {
    const candidate = path.join(dir, "semgrep");
    if (dir && existsSync(candidate)) return candidate;
  }
  // 점검 시작 때 서버가 허용 목록에서 설치한 고정 버전(없으면 undefined).
  return installedBin("semgrep", env);
}

export function semgrepConfigs(env: Record<string, string | undefined> = process.env): string[] {
  return (env.SEMGREP_CONFIG?.trim() || DEFAULT_CONFIG)
    .split(",")
    .map((c) => c.trim())
    .filter((c) => /^(p|r)\/[A-Za-z0-9._\-/]+$/.test(c) || c === "auto")
    .slice(0, 6);
}

interface SemgrepHit {
  checkId: string;
  file: string;
  line: number;
  message: string;
  severity: string;
  cwe?: string;
}

/**
 * 문제 종류별 쉬운 안내. 제목은 findingMerge.issueClass의 키워드 분류가 같은 종류로
 * 나오도록 골랐다(CWE가 없는 Semgrep 결과는 제목으로 분류된다).
 */
export const SEMGREP_CLASS_TEXT: Record<string, { title: string; impact: string; remediation: string }> = {
  sqli: {
    title: "사용자가 보낸 값으로 데이터베이스 쿼리를 직접 만들고 있어요 (SQL 인젝션)",
    impact: "누군가 입력값에 쿼리 조각을 섞어 보내면 저장된 데이터가 밖으로 새거나 지워질 수 있어요.",
    remediation: "값을 SQL 문장에 직접 이어 붙이지 말고, 자리 표시자(? 또는 $1)를 쓰고 값은 따로 넘기는 방식(파라미터 바인딩)으로 바꿔 주세요.",
  },
  cmd: {
    title: "입력값으로 서버에서 코드나 명령이 실행될 수 있어요 (코드·커맨드 인젝션)",
    impact: "누군가 값을 조작해 보내면 서버에서 원하지 않는 명령이나 코드가 실행될 수 있어요.",
    remediation: "eval이나 셸 명령에 입력값을 넣지 말아 주세요. 명령이 꼭 필요하면 execFile처럼 명령과 값을 따로 넘기고, 허용할 값의 목록을 정해 주세요.",
  },
  xss: {
    title: "사용자가 입력한 글이 화면에서 코드처럼 실행될 수 있어요 (XSS)",
    impact: "누군가 심어 둔 스크립트가 이 화면을 여는 사람의 브라우저에서 실행될 수 있어요.",
    remediation: "사용자가 입력한 글을 HTML로 넣지 말고 글자로만 표시하도록 바꿔 주세요. 꼭 HTML이 필요하면 DOMPurify 같은 검증된 도구로 위험한 태그를 지운 뒤 넣어 주세요.",
  },
  path: {
    title: "사용자가 보낸 값이 파일 경로로 그대로 쓰일 수 있어요 (경로 트래버설)",
    impact: "허용한 폴더 밖에 있는 서버 파일을 읽거나 바꿀 수 있어요.",
    remediation: "path.resolve로 경로를 정리한 뒤 허용한 폴더 안인지(startsWith) 확인하고, 아니면 거절해 주세요.",
  },
  ssrf: {
    title: "사용자가 준 주소로 서버가 대신 요청을 보내요 (SSRF)",
    impact: "누군가 서버를 거쳐 밖에서는 닿지 않는 내부 서비스에 요청을 보낼 수 있어요.",
    remediation: "서버가 요청을 보낼 수 있는 주소를 허용 목록으로 정하고, 그 밖의 주소나 내부 주소(localhost, 사설 IP)는 거절해 주세요.",
  },
  redirect: {
    title: "사용자가 준 주소로 방문자를 다른 사이트로 보낼 수 있어요 (오픈 리다이렉트)",
    impact: "이 사이트 주소처럼 보이는 링크로 사람들을 가짜 사이트에 보내는 데 쓰일 수 있어요.",
    remediation: "이동할 주소를 내 사이트 안의 경로나 허용 목록에 있는 주소로만 받도록 바꿔 주세요.",
  },
  jwt: {
    title: "로그인 토큰의 서명을 제대로 확인하지 않아요",
    impact: "누군가 직접 만든 토큰으로 다른 사용자인 척 로그인할 수 있어요.",
    remediation: "토큰을 쓸 때 decode가 아니라 verify로 서명을 확인하고, 허용할 알고리즘을 정해 주세요.",
  },
  crypto: {
    title: "쉽게 풀리는 약한 암호화 방식을 쓰고 있어요",
    impact: "암호화한 데이터가 풀리거나 다른 사람이 위조할 수 있어요.",
    remediation: "MD5, SHA-1, DES 같은 오래된 방식 대신 AES-GCM이나 SHA-256 이상을 쓰고, 비밀번호 저장에는 bcrypt나 Argon2를 써 주세요.",
  },
  random: {
    title: "보안에 쓰는 값을 예측 가능한 난수로 만들어요",
    impact: "누군가 토큰이나 비밀번호 재설정 값을 맞힐 수 있어요.",
    remediation: "Math.random 대신 crypto.randomBytes나 crypto.randomUUID로 값을 만들어 주세요.",
  },
  deser: {
    title: "믿을 수 없는 데이터를 객체로 되살리고 있어요 (역직렬화)",
    impact: "누군가 조작한 데이터를 보내 서버에서 코드가 실행되게 할 수 있어요.",
    remediation: "바깥에서 온 데이터는 JSON.parse처럼 데이터만 읽는 방식으로 처리하고, 코드까지 되살리는 라이브러리는 쓰지 말아 주세요.",
  },
  proto: {
    title: "바깥 값으로 모든 객체의 기본 동작을 바꿀 수 있어요 (프로토타입 오염)",
    impact: "앱 곳곳의 객체가 다른 사람이 정한 대로 동작하게 될 수 있어요.",
    remediation: "객체를 합치거나 값을 넣을 때 __proto__, constructor, prototype 같은 키는 거절해 주세요.",
  },
  secret: {
    title: "비밀키가 코드에 직접 들어 있어요",
    impact: "코드를 볼 수 있는 사람은 누구나 이 값으로 연결된 서비스에 접속할 수 있어요.",
    remediation: "비밀키를 코드에서 빼고 배포 서비스의 비밀 설정(환경변수)에 저장해 주세요. 이미 공개된 키라면 새 키를 발급하고 기존 키는 사용할 수 없게 해야 해요.",
  },
};

function mapSeverity(sev: string, cls: string | null): SecurityFinding["severity"] {
  if (cls === "sqli" || cls === "cmd" || cls === "deser") return "critical";
  if (sev === "ERROR") return "high";
  if (sev === "WARNING") return "medium";
  return "low";
}

async function runSemgrep(bin: string, files: Record<string, string>, configs: string[]): Promise<SemgrepHit[]> {
  const dir = await realpath(await mkdtemp(path.join(os.tmpdir(), "hoi-semgrep-")));
  try {
    for (const [raw, content] of Object.entries(files)) {
      const rel = safeProjectPath(raw);
      if (!rel || !CODE.test(rel)) continue;
      const target = path.join(dir, rel);
      await mkdir(path.dirname(target), { recursive: true });
      await writeFile(target, content);
    }
    const args = ["scan", "--json", "--metrics=off", "--disable-version-check", "--quiet", "--no-git-ignore", "--timeout", "20", ...configs.flatMap((c) => ["--config", c]), dir];
    // 서버 키가 든 환경변수는 넘기지 않는다.
    const env: NodeJS.ProcessEnv = {
      NODE_ENV: "production",
      PATH: process.env.PATH ?? "",
      HOME: process.env.HOME ?? dir,
      LANG: "en_US.UTF-8",
      SEMGREP_SEND_METRICS: "off",
      // Windows에서 Python(설치한 semgrep)이 동작하려면 필요한 시스템 폴더(비밀 아님).
      ...(process.platform === "win32" && process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}),
    };
    const started = Date.now();
    const stdout = await new Promise<string>((resolve, reject) => {
      const child = spawn(bin, args, { env, stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      let err = "";
      const timer = setTimeout(() => child.kill("SIGKILL"), RUN_TIMEOUT_MS);
      child.stdout.on("data", (d: Buffer) => (out += d.toString("utf8")));
      child.stderr.on("data", (d: Buffer) => {
        if (err.length < 4000) err += d.toString("utf8");
      });
      child.on("error", (e) => {
        clearTimeout(timer);
        reject(e);
      });
      child.on("close", (code) => {
        clearTimeout(timer);
        // semgrep은 발견이 있어도 0, 설정 오류면 2 이상.
        logToolEvent({ event: "run", id: "semgrep", exit: code, ms: Date.now() - started });
        if (code !== 0 && code !== 1) reject(new Error(`semgrep exit ${code}: ${err.trim().split("\n").slice(-2).join(" ")}`));
        else resolve(out);
      });
    });
    const parsed = JSON.parse(stdout) as { results?: Array<Record<string, unknown>> };
    const hits: SemgrepHit[] = [];
    for (const r of parsed.results ?? []) {
      const abs = String(r.path ?? "");
      const rel = path.relative(dir, path.isAbsolute(abs) ? abs : path.join(dir, abs)).split(path.sep).join("/");
      const extra = (r.extra ?? {}) as { message?: string; severity?: string; metadata?: { cwe?: string[] | string } };
      const cweRaw = Array.isArray(extra.metadata?.cwe) ? extra.metadata?.cwe[0] : extra.metadata?.cwe;
      hits.push({
        checkId: String(r.check_id ?? "semgrep"),
        file: rel,
        line: Number((r.start as { line?: number } | undefined)?.line ?? 0),
        message: String(extra.message ?? "").replace(/\s+/g, " ").slice(0, 400),
        severity: String(extra.severity ?? "INFO"),
        cwe: cweRaw ? String(cweRaw).match(/CWE-\d+/i)?.[0]?.toUpperCase() : undefined,
      });
    }
    return hits.filter((h) => files[h.file] !== undefined && h.line > 0);
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

/** 같은 파일 묶음으로 여러 번 부르면 한 번만 실행한다(재검증에서 항목마다 부르므로). */
const runCache = new WeakMap<Record<string, string>, Promise<SemgrepHit[]>>();

function cachedRun(bin: string, files: Record<string, string>, configs: string[]): Promise<SemgrepHit[]> {
  let p = runCache.get(files);
  if (!p) {
    p = runSemgrep(bin, files, configs);
    runCache.set(files, p);
  }
  return p;
}

function toFinding(h: SemgrepHit, files: Record<string, string>): SecurityFinding {
  const cls = issueClass({ cwe: h.cwe, title: `${h.checkId} ${h.message}`, category: "" });
  const text = cls ? SEMGREP_CLASS_TEXT[cls] : undefined;
  const lineText = (files[h.file].split("\n")[h.line - 1] ?? "").trim().slice(0, 300);
  const shortRule = h.checkId.split(".").pop();
  return {
    id: id("finding"),
    scanId: "",
    title: text?.title ?? `Semgrep 규칙에 걸린 코드가 있어요 (${shortRule})`,
    severity: mapSeverity(h.severity, cls),
    category: "Semgrep",
    cwe: h.cwe,
    description: `Semgrep ${h.checkId}: ${h.message}`,
    // Semgrep 메시지는 영어라 화면 설명에는 쓰지 않고 근거(Semgrep 출력)에만 남긴다.
    humanReadableImpact:
      text?.impact ?? "Semgrep 규칙이 이 줄을 보안 문제가 생길 수 있는 코드로 표시했어요. 어떤 문제인지는 근거의 Semgrep 규칙 설명(영어)에 적혀 있어요.",
    whyItMatters: `코드에서 확인했어요: 공개 점검 규칙 모음(Semgrep)의 ${shortRule} 규칙이 이 줄에 걸렸어요. 실제로 문제가 생기는지는 실행해 확인하지 않았어요.`,
    location: { file: h.file, line: h.line },
    evidence: [
      { id: id("ev"), kind: "source_code", label: `${h.file}:${h.line}`, content: lineText, language: "typescript" },
      { id: id("ev"), kind: "scanner_output", label: "Semgrep 출력(규칙 설명은 영어)", content: `규칙: ${h.checkId}\n메시지: ${h.message}` },
    ],
    remediation:
      text?.remediation ??
      "근거에 있는 Semgrep 규칙 설명(영어)을 보고 이 줄을 고친 뒤 다시 점검해 주세요. 어떻게 고칠지 정하기 어렵다면 이 규칙 이름으로 공식 문서를 찾아보세요.",
    status: "detected",
    simulated: false,
    verificationKey: `semgrep:${h.checkId}:${h.file}:${h.line}`,
    createdAt: now(),
    updatedAt: now(),
  };
}

export class SemgrepScanner implements SecurityScanner {
  readonly name = "semgrep-scanner";
  readonly displayName = "Semgrep";
  readonly step = "static_analysis" as const;
  readonly simulated = false;

  async isApplicable(context: ProjectContext): Promise<boolean> {
    return Boolean(semgrepBin()) && Object.keys(context.files).some((p) => CODE.test(p));
  }

  async scan(context: ProjectContext): Promise<SecurityFinding[]> {
    return (await this.scanWithReport(context)).findings;
  }

  async scanWithReport(context: ProjectContext): Promise<{ findings: SecurityFinding[]; status: NonNullable<ScanScope["semgrep"]> }> {
    const bin = semgrepBin();
    const configs = semgrepConfigs();
    if (!bin) return { findings: [], status: { status: "not_installed", findings: 0 } };
    try {
      const hits = await cachedRun(bin, context.files, configs);
      // 여러 규칙이 같은 줄의 같은 종류 문제를 잡으면 하나로 본다.
      const seen = new Set<string>();
      const findings = hits
        .map((h) => toFinding(h, context.files))
        .filter((f) => {
          const key = `${f.location!.file}:${f.location!.line}:${issueClass(f) ?? f.verificationKey}`;
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        });
      return { findings, status: { status: "ran", findings: findings.length, config: configs.join(",") } };
    } catch (e) {
      return {
        findings: [],
        status: { status: "failed", findings: 0, config: configs.join(","), detail: (e instanceof Error ? e.message : String(e)).slice(0, 300) },
      };
    }
  }

  /** 같은 Semgrep 규칙이 원래 문제가 된 줄(또는 수정이 만든 새 줄)에 아직 걸리는지. */
  async verify(finding: SecurityFinding, context: ProjectContext): Promise<VerificationResult> {
    const key = finding.verificationKey ?? "";
    const m = key.match(/^semgrep:(.+):([^:]+):(\d+)$/);
    const bin = semgrepBin();
    const file = finding.location?.file;
    if (!m || !bin || !file || context.files[file] === undefined) throw new VerificationUnavailableError();
    let hits: SemgrepHit[];
    try {
      hits = await cachedRun(bin, context.files, semgrepConfigs());
    } catch {
      throw new VerificationUnavailableError();
    }
    const same = hits.filter((h) => h.checkId === m[1] && h.file === file);
    const lines = context.files[file].split("\n");
    const still = stillPresentAfterFix({
      hits: same.map((h) => ({ line: h.line, text: lines[h.line - 1] ?? "" })),
      originalLineText: finding.evidence.find((e) => e.kind === "source_code")?.content,
      originalLine: finding.location?.line,
      baselineContent: context.baselineFiles?.[file],
      fixedLineCount: lines.length,
    });
    const security: VerificationTest = {
      id: id("vtest"),
      findingId: finding.id,
      label: "Semgrep 재검사",
      before: { label: "수정 전", request: `semgrep ${m[1]}: ${file}`, response: "규칙에 걸림", attackSucceeded: true },
      after: {
        label: "수정 후",
        request: `semgrep ${m[1]}: ${file}`,
        response: still ? "같은 Semgrep 규칙이 수정본에서도 걸려요" : "같은 Semgrep 규칙이 수정본에서는 걸리지 않아요",
        attackSucceeded: still,
      },
      outcome: still ? "fail" : "pass",
      createdAt: now(),
    };
    const regression: RegressionTest = { id: id("rtest"), findingId: finding.id, checks: [], outcome: "pass", createdAt: now() };
    return { findingId: finding.id, security, regression, resolved: false };
  }
}
