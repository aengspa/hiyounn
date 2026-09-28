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

/**
 * Semgrep 규칙 검사(기준 규칙 검사기 중 하나).
 *
 * SEMGREP_BIN(또는 PATH의 semgrep)이 있을 때만 돈다. 임시 폴더에 코드 사본을 쓰고
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
  return undefined;
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

const CLASS_TEXT: Record<string, { title: string; impact: string }> = {
  sqli: { title: "데이터베이스 쿼리에 입력값이 직접 조립됩니다 (SQL 인젝션)", impact: "공격자가 쿼리 구조를 바꿔 데이터를 훔치거나 지울 수 있습니다." },
  cmd: { title: "입력값으로 시스템 명령이나 코드가 실행됩니다 (인젝션)", impact: "공격자가 서버에서 원하는 명령을 실행할 수 있습니다." },
  xss: { title: "사용자 입력이 그대로 화면에 삽입될 수 있습니다 (XSS)", impact: "공격자의 스크립트가 방문자 브라우저에서 실행될 수 있습니다." },
  path: { title: "사용자 입력이 파일 경로로 그대로 사용됩니다 (경로 트래버설)", impact: "허용된 폴더 밖의 파일이 읽히거나 바뀔 수 있습니다." },
  ssrf: { title: "사용자 입력 URL로 서버가 요청을 보냅니다 (SSRF)", impact: "공격자가 서버를 통해 내부 서비스에 접근할 수 있습니다." },
  redirect: { title: "사용자 입력으로 다른 사이트로 이동시킵니다 (오픈 리다이렉트)", impact: "피싱 사이트로 사용자를 보내는 데 악용될 수 있습니다." },
  jwt: { title: "토큰 서명을 제대로 검증하지 않습니다", impact: "공격자가 만든 토큰으로 다른 사용자인 척할 수 있습니다." },
  crypto: { title: "약한 암호화 방식을 씁니다", impact: "암호화된 데이터가 풀리거나 위조될 수 있습니다." },
  random: { title: "보안 값을 예측 가능한 난수로 만듭니다", impact: "공격자가 토큰이나 비밀번호 재설정 값을 맞힐 수 있습니다." },
  deser: { title: "신뢰할 수 없는 데이터를 역직렬화합니다", impact: "공격자가 서버에서 코드를 실행할 수 있습니다." },
  proto: { title: "프로토타입 오염이 가능합니다", impact: "앱 전체 객체의 동작이 공격자 뜻대로 바뀔 수 있습니다." },
  secret: { title: "비밀 값이 코드에 직접 적혀 있습니다", impact: "코드를 볼 수 있는 누구나 이 값으로 시스템에 접근할 수 있습니다." },
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
    };
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
  const text = cls ? CLASS_TEXT[cls] : undefined;
  const lineText = (files[h.file].split("\n")[h.line - 1] ?? "").trim().slice(0, 300);
  return {
    id: id("finding"),
    scanId: "",
    title: text?.title ?? `Semgrep 규칙에 걸린 코드가 있어요 (${h.checkId.split(".").pop()})`,
    severity: mapSeverity(h.severity, cls),
    category: "Semgrep",
    cwe: h.cwe,
    description: `Semgrep ${h.checkId}: ${h.message}`,
    humanReadableImpact: text?.impact ?? h.message,
    whyItMatters: text?.impact ?? h.message,
    location: { file: h.file, line: h.line },
    evidence: [
      { id: id("ev"), kind: "source_code", label: `${h.file}:${h.line}`, content: lineText, language: "typescript" },
      { id: id("ev"), kind: "scanner_output", label: "Semgrep 출력", content: `규칙: ${h.checkId}\n메시지: ${h.message}` },
    ],
    remediation: h.message,
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
