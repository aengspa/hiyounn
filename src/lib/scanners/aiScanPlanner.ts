import type { AiScanCoverage } from "@/lib/domain/types";
import { safeProjectPath } from "@/lib/remediation/patchEngine";

/**
 * AI 코드 분석 계획.
 *
 * 전체 코드를 한 번에 보내지 않는다. 위험도가 높은 파일(라우트·인증·미들웨어·
 * DB·요청 처리)부터 묶음(chunk)으로 나눠 보내고, 각 묶음에는 "프로젝트 지도"
 * (파일 목록 + 라우트·미들웨어 선언)를 함께 줘서 파일을 넘나드는 문제
 * (예: 라우터 마운트에 관리자 확인이 빠짐)도 볼 수 있게 한다.
 * 한도를 넘는 파일은 자르지 않고 이유와 함께 기록한다.
 */

const CODE_FILE = /\.(?:m?[jt]sx?|cjs|vue|svelte|py|rb|go|php|java|kt|cs)$/i;
const SKIP_DIR = /(^|\/)(node_modules|dist|build|\.next|out|coverage|vendor)\//;

export function isAiReviewable(path: string): boolean {
  return CODE_FILE.test(path) && !SKIP_DIR.test(path) && !/\.min\.js$/.test(path);
}

/** 높을수록 먼저 본다. 경로와 내용의 신호를 더한다. */
export function riskScore(path: string, content: string): number {
  let s = 0;
  if (/(^|\/)(routes?|api|controllers?|handlers?|middlewares?|auth|admin|webhooks?|actions?|server|pages\/api)(\/|\.|$)/i.test(path)) s += 5;
  if (/(^|\/)app\/.*\/route\.[jt]sx?$/.test(path)) s += 5;
  if (/(^|\/)(app|server|index|main|middleware)\.(m?[jt]s|cjs)$/i.test(path)) s += 3;
  if (/\breq\.|\brequest\.|\bparams\b|searchParams|formData|\.body\b/.test(content)) s += 3;
  if (/innerHTML|dangerouslySetInnerHTML|\bexec(?:Sync)?\(|\beval\(|\.query\(|\bfetch\(|jwt|cookie|password|token|sendFile|readFile|\$queryRaw|child_process|redirect\(/i.test(content)) s += 3;
  if (/(^|\/)(tests?|__tests__|spec|mocks?|fixtures|stories)(\/|$)|\.(test|spec|stories)\.|\.d\.ts$/i.test(path)) s -= 6;
  return s;
}

/** 파일 목록과 라우트·미들웨어 선언만 뽑은 짧은 지도. */
export function buildProjectMap(files: Record<string, string>, maxChars = 3500): string {
  const paths = Object.keys(files).sort();
  const out: string[] = ["파일 목록:"];
  for (const p of paths.slice(0, 150)) out.push(`- ${p} (${files[p].split("\n").length}줄)`);
  if (paths.length > 150) out.push(`- … 외 ${paths.length - 150}개`);
  out.push("", "라우트·미들웨어 선언:");
  const DECL =
    /\b(?:app|router|server|api)\.(?:get|post|put|patch|delete|use|all|route)\s*\(|export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b|export\s+(?:const|async\s+function|function)\s+\w*(?:auth|require|guard|middleware|admin|session)\w*/i;
  for (const p of paths) {
    if (!isAiReviewable(p)) continue;
    files[p].split("\n").forEach((line, i) => {
      if (DECL.test(line)) out.push(`${p}:${i + 1}: ${line.trim().slice(0, 160)}`);
    });
  }
  let text = out.join("\n");
  if (text.length > maxChars) text = `${text.slice(0, maxChars)}\n…(지도 일부 생략)`;
  return text;
}

export interface AiScanPlan {
  chunks: string[][];
  omitted: AiScanCoverage["omitted"];
  /** AI 분석 대상 코드 파일 수. */
  total: number;
}

export function planChunks(
  files: Record<string, string>,
  opts: { chunkChars: number; maxChunks: number; fileChars: number }
): AiScanPlan {
  const ranked = Object.keys(files)
    .filter((p) => isAiReviewable(p) && files[p].trim() && safeProjectPath(p) === p)
    .sort((a, b) => riskScore(b, files[b]) - riskScore(a, files[a]) || a.localeCompare(b));

  const chunks: string[][] = [];
  const omitted: AiScanCoverage["omitted"] = [];
  let current: string[] = [];
  let used = 0;
  for (const p of ranked) {
    const size = files[p].length + p.length + 16;
    if (files[p].length > opts.fileChars) {
      omitted.push({ path: p, reason: "too_large" });
      continue;
    }
    if (current.length > 0 && used + size > opts.chunkChars) {
      chunks.push(current);
      current = [];
      used = 0;
    }
    if (current.length === 0 && chunks.length >= opts.maxChunks) {
      omitted.push({ path: p, reason: "over_budget" });
      continue;
    }
    current.push(p);
    used += size;
  }
  if (current.length > 0) chunks.push(current);
  return { chunks, omitted, total: ranked.length };
}
