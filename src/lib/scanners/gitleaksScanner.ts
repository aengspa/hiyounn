import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "fs/promises";
import os from "os";
import path from "path";
import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import type { RegressionTest, SecurityEvidence, SecurityFinding, VerificationResult, VerificationTest } from "@/lib/domain/types";
import { VerificationUnavailableError } from "@/lib/store/errors";
import { safeProjectPath } from "@/lib/remediation/patchEngine";
import { secretFingerprint } from "@/lib/scanners/secretScanner";
import { bundledBin, getInstallableTool, installedBin, systemBin } from "@/lib/tools/installableTools";
import { defaultRunner, logToolEvent, scrubbedToolEnv } from "@/lib/tools/toolInstaller";
import { id, maskSecret, now } from "@/lib/util";

/**
 * Gitleaks 비밀키 검사(기준 규칙 검사기 중 하나).
 *
 * GITLEAKS_BIN·PATH의 gitleaks, 빌드 때 배포본에 함께 넣은 고정 버전(vendor-bin/),
 * 또는 서버가 허용 목록에서 설치한 고정 버전이 있을 때만 돈다. 임시 폴더에 코드 사본을 쓰고 `gitleaks detect --no-git`으로 본다.
 * 올린 파일에 .git 폴더가 실제로 있으면 코드 기록(커밋)도 본다.
 * 비밀값은 저장하지 않는다. 근거 줄은 우리 파일에서 읽고 값은 가린다.
 */

const RUN_TIMEOUT_MS = 120_000;

export function gitleaksBin(env: Record<string, string | undefined> = process.env): string | undefined {
  const tool = getInstallableTool("gitleaks")!;
  return systemBin(tool, env) ?? bundledBin(tool, env) ?? installedBin("gitleaks", env);
}

export interface GitleaksHit {
  ruleId: string;
  file: string;
  line: number;
  /** 메모리에서만 쓴다(가리기·지문). 발견 항목에는 넣지 않는다. */
  secret: string;
  commit?: string;
}

/**
 * gitleaks JSON 보고서 → 우리 파일 기준 경로의 결과.
 * baseDir 밖을 가리키거나 경로가 이상한 결과는 버린다.
 */
export function parseGitleaksReport(json: string, baseDir: string): GitleaksHit[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json || "[]");
  } catch {
    throw new Error("gitleaks report is not JSON");
  }
  if (!Array.isArray(parsed)) return [];
  const hits: GitleaksHit[] = [];
  for (const r of parsed as Array<Record<string, unknown>>) {
    const rawFile = String(r.File ?? "");
    if (!rawFile) continue;
    const abs = path.resolve(baseDir, rawFile);
    const rel = path.relative(baseDir, abs).split(path.sep).join("/");
    const safe = safeProjectPath(rel);
    if (!safe || safe !== rel) continue;
    const line = Number(r.StartLine ?? 0);
    if (!Number.isInteger(line) || line <= 0) continue;
    const commit = typeof r.Commit === "string" && /^[0-9a-f]{7,40}$/i.test(r.Commit) ? r.Commit : undefined;
    hits.push({
      ruleId: String(r.RuleID ?? "gitleaks").replace(/[^A-Za-z0-9._-]/g, "").slice(0, 80) || "gitleaks",
      file: rel,
      line,
      secret: typeof r.Secret === "string" ? r.Secret : "",
      ...(commit ? { commit } : {}),
    });
  }
  return hits;
}

function shortMask(raw: string): string {
  return maskSecret(raw.split("\n")[0]).slice(0, 48);
}

/** 우리 파일의 줄을 읽어 비밀값을 가린다. 값이 줄에서 안 보이면 줄 전체를 보여 주지 않는다. */
export function maskedLine(files: Record<string, string>, file: string, line: number, secret: string): string {
  const text = files[file]?.split("\n")[line - 1];
  const first = secret.split("\n")[0];
  if (text === undefined || !first || !text.includes(first)) return "(비밀값이 있는 줄이라 내용은 보여 드리지 않아요)";
  return text.split(first).join(shortMask(secret)).trim().slice(0, 300);
}

function toFinding(h: GitleaksHit, files: Record<string, string>): SecurityFinding {
  const history = Boolean(h.commit);
  const isEnvFile = h.file.endsWith(".env");
  const evidence: SecurityEvidence[] = [
    {
      id: id("ev"),
      kind: "source_code",
      label: history ? `${h.file}:${h.line} (커밋 ${h.commit!.slice(0, 8)})` : `${h.file}:${h.line}`,
      content: history ? `일치: ${shortMask(h.secret)}` : maskedLine(files, h.file, h.line, h.secret),
      masked: true,
      language: "typescript",
    },
    {
      id: id("ev"),
      kind: "scanner_output",
      label: "Gitleaks 결과 (값은 가려서 보여 드려요)",
      content: `규칙: ${h.ruleId}\n파일: ${h.file}\n줄: ${h.line}${history ? `\n커밋: ${h.commit}` : ""}\n일치: ${shortMask(h.secret)}`,
      masked: true,
    },
  ];
  return {
    id: id("finding"),
    scanId: "",
    title: history
      ? "지운 줄 알았던 비밀키가 코드 기록(커밋)에 아직 남아 있어요"
      : isEnvFile
        ? "비밀값이 적힌 .env 파일이 코드와 함께 들어 있어요"
        : "외부 서비스에 접속할 때 쓰는 비밀키가 코드에 직접 들어 있어요",
    severity: "critical",
    category: "Secret Exposure",
    owasp: "A07 – Identification and Authentication Failures",
    cwe: "CWE-798",
    cvss: 9.1,
    description: history
      ? `Gitleaks 규칙 "${h.ruleId}"이(가) 커밋 ${h.commit}의 ${h.file} 파일 ${h.line}번째 줄에서 일치했어요.`
      : `Gitleaks 규칙 "${h.ruleId}"이(가) ${h.file} 파일 ${h.line}번째 줄에서 일치했어요.`,
    humanReadableImpact:
      "코드를 볼 수 있는 사람은 누구나 이 값을 복사해 쓸 수 있어요. 이 값으로 연결된 서비스에 이 프로젝트인 것처럼 접속해 데이터를 보거나 바꿀 수 있어요.",
    whyItMatters: history
      ? `코드 기록에서 확인했어요: 예전 커밋의 ${h.file} ${h.line}번째 줄에 비밀키 형식의 값이 있었어요. 지금 파일에서 지웠어도 기록을 받은 사람은 볼 수 있어요. 이 값이 지금도 쓰이는 키인지는 확인하지 않았어요.`
      : `코드에서 확인했어요: 비밀키 찾기 도구(Gitleaks)의 ${h.ruleId} 규칙이 ${h.file} ${h.line}번째 줄에 걸렸어요. 이 값이 지금 실제로 쓰이는 키인지, 이미 밖으로 공개됐는지는 확인하지 않았어요.`,
    location: { file: h.file, line: h.line },
    evidence,
    remediation: history
      ? "이 키는 이미 기록에 남아 있으니 새 키를 발급하고 기존 키는 사용할 수 없게 해 주세요. 그다음 비밀키는 배포 서비스의 비밀 설정(환경변수)에 저장하고 코드에는 넣지 말아 주세요."
      : isEnvFile
        ? "이 파일의 비밀값은 배포 서비스의 비밀 설정(환경변수)에 저장하고, .env 파일은 .gitignore에 넣어 코드와 함께 올리지 않도록 해 주세요. 이미 공개된 키라면 새 키를 발급하고 기존 키는 사용할 수 없게 해야 해요."
        : "비밀키를 코드에서 빼고 배포 서비스의 비밀 설정(환경변수)에 저장한 뒤, 코드에서는 그 설정을 읽어 쓰도록 바꿔 주세요. 이미 공개된 키라면 새 키를 발급하고 기존 키는 사용할 수 없게 해야 해요.",
    status: "detected",
    simulated: false,
    verificationKey: `gitleaks:${h.ruleId}:${h.file}:${h.line}`,
    ...(h.secret ? { fingerprint: secretFingerprint(h.secret) } : {}),
    createdAt: now(),
    updatedAt: now(),
  };
}

/** 결과 → 발견 항목. 같은 값은 한 번만(현재 파일 쪽을 남기고 기록 쪽은 버림). */
export function gitleaksFindings(hits: GitleaksHit[], files: Record<string, string>): SecurityFinding[] {
  const ordered = [...hits].sort((a, b) => Number(Boolean(a.commit)) - Number(Boolean(b.commit)));
  const seen = new Set<string>();
  const out: SecurityFinding[] = [];
  for (const h of ordered) {
    if (!h.commit && files[h.file] === undefined) continue;
    const key = h.secret ? secretFingerprint(h.secret) : `${h.ruleId}:${h.file}:${h.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(toFinding(h, files));
  }
  return out;
}

async function runOnce(bin: string, args: string[], cwd: string, reportPath: string): Promise<string> {
  const started = Date.now();
  const r = await defaultRunner(bin, args, { env: scrubbedToolEnv(), timeoutMs: RUN_TIMEOUT_MS, cwd });
  logToolEvent({ event: "run", id: "gitleaks", mode: args.includes("--no-git") ? "dir" : "git", exit: r.code, ms: Date.now() - started });
  if (r.code !== 0) throw new Error(`gitleaks exit ${r.code}: ${r.stderr.trim().split("\n").slice(-1).join(" ").slice(0, 200)}`);
  return readFile(reportPath, "utf8");
}

async function runGitleaks(bin: string, files: Record<string, string>): Promise<GitleaksHit[]> {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "hoi-gitleaks-")));
  const src = path.join(root, "src");
  try {
    const gitFiles: Array<[string, string]> = [];
    await mkdir(src, { recursive: true });
    for (const [raw, content] of Object.entries(files)) {
      const rel = safeProjectPath(raw);
      if (!rel) continue;
      if (rel === ".git" || rel.startsWith(".git/")) {
        gitFiles.push([rel, content]);
        continue;
      }
      const target = path.join(src, rel);
      await mkdir(path.dirname(target), { recursive: true });
      await writeFile(target, content);
    }
    const common = ["--report-format", "json", "--no-banner", "--exit-code", "0", "--log-level", "error"];
    const dirReport = path.join(root, "report-dir.json");
    const hits = parseGitleaksReport(
      await runOnce(bin, ["detect", "--no-git", "--source", src, "--report-path", dirReport, ...common], src, dirReport),
      src
    );
    // 올린 파일에 .git이 실제로 있을 때만 코드 기록도 본다. 실패하면 기록 검사만 빠진다.
    if (gitFiles.some(([p]) => p === ".git/HEAD")) {
      for (const [rel, content] of gitFiles) {
        const target = path.join(src, rel);
        await mkdir(path.dirname(target), { recursive: true });
        await writeFile(target, content);
      }
      const gitReport = path.join(root, "report-git.json");
      try {
        const history = parseGitleaksReport(await runOnce(bin, ["detect", "--source", src, "--report-path", gitReport, ...common], src, gitReport), src);
        hits.push(...history.filter((h) => h.commit));
      } catch {
        // 기록 검사 실패는 현재 파일 결과에 영향을 주지 않는다.
      }
    }
    return hits;
  } finally {
    await rm(root, { recursive: true, force: true }).catch(() => {});
  }
}

/** 같은 파일 묶음으로 여러 번 부르면 한 번만 실행한다(재검증에서 항목마다 부르므로). */
const runCache = new WeakMap<Record<string, string>, Promise<GitleaksHit[]>>();

function cachedRun(bin: string, files: Record<string, string>): Promise<GitleaksHit[]> {
  let p = runCache.get(files);
  if (!p) {
    p = runGitleaks(bin, files);
    runCache.set(files, p);
  }
  return p;
}

export class GitleaksScanner implements SecurityScanner {
  readonly name = "gitleaks-scanner";
  readonly displayName = "Gitleaks";
  readonly step = "secret_scan" as const;
  readonly simulated = false;

  async isApplicable(context: ProjectContext): Promise<boolean> {
    return Boolean(gitleaksBin()) && Object.keys(context.files).length > 0;
  }

  async scan(context: ProjectContext): Promise<SecurityFinding[]> {
    return (await this.scanWithReport(context)).findings;
  }

  async scanWithReport(context: ProjectContext): Promise<{ findings: SecurityFinding[]; status: "ran" | "not_installed" | "failed"; detail?: string }> {
    const bin = gitleaksBin();
    if (!bin) return { findings: [], status: "not_installed" };
    try {
      const hits = await cachedRun(bin, context.files);
      return { findings: gitleaksFindings(hits, context.files), status: "ran" };
    } catch (e) {
      return { findings: [], status: "failed", detail: (e instanceof Error ? e.message : String(e)).slice(0, 300) };
    }
  }

  /** 수정본을 다시 검사해 같은 비밀값(지문)이 어디에든 남았는지 본다. */
  async verify(finding: SecurityFinding, context: ProjectContext): Promise<VerificationResult> {
    const m = (finding.verificationKey ?? "").match(/^gitleaks:([^:]+):(.+):(\d+)$/);
    const bin = gitleaksBin();
    const file = finding.location?.file;
    const fromHistory = finding.evidence.some((e) => e.kind === "scanner_output" && e.content.includes("\n커밋: "));
    // 커밋 기록은 파일 수정으로 바뀌지 않으므로 자동 확인하지 않는다.
    if (!m || !bin || !file || fromHistory) throw new VerificationUnavailableError();
    let hits: GitleaksHit[];
    try {
      hits = await cachedRun(bin, context.files);
    } catch {
      throw new VerificationUnavailableError();
    }
    const current = hits.filter((h) => !h.commit);
    const still = finding.fingerprint
      ? current.some((h) => h.secret && secretFingerprint(h.secret) === finding.fingerprint)
      : current.some((h) => h.ruleId === m[1] && h.file === file);
    const security: VerificationTest = {
      id: id("vtest"),
      findingId: finding.id,
      label: "Gitleaks 재검사",
      before: { label: "수정 전", request: `gitleaks ${m[1]}: ${file}`, response: "비밀키 형식의 값이 있음", attackSucceeded: true },
      after: {
        label: "수정 후",
        request: `gitleaks ${m[1]}: ${file}`,
        response: still
          ? "같은 비밀값이 수정본에도 남아 있어요"
          : "수정본에서는 같은 비밀값이 보이지 않아요. 이미 공개된 키라면 새 키 발급은 따로 확인해야 해요.",
        attackSucceeded: still,
      },
      outcome: still ? "fail" : "pass",
      createdAt: now(),
    };
    const regression: RegressionTest = { id: id("rtest"), findingId: finding.id, checks: [], outcome: "pass", createdAt: now() };
    // 키 폐기·재발급은 여기서 확인할 수 없으므로 secretScanner와 같이 resolved는 false.
    return { findingId: finding.id, security, regression, resolved: false };
  }
}
