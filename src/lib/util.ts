import type { ScanStep } from "@/lib/domain/types";

let counter = 0;
/**
 * Id generator. The random suffix keeps ids unique across serverless
 * instances (each has its own counter), which matters for Postgres keys.
 */
export function id(prefix = "id"): string {
  counter += 1;
  const rnd = new Uint8Array(4);
  globalThis.crypto.getRandomValues(rnd);
  const suffix = Array.from(rnd, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${prefix}_${Date.now().toString(36)}_${counter}${suffix}`;
}

export function now(): string {
  return new Date().toISOString();
}

export const SCAN_STEP_LABELS: Record<ScanStep, string> = {
  detect_stack: "프로젝트 스택 감지",
  secret_scan: "비밀정보 스캔",
  dependency_scan: "라이브러리 취약점 스캔",
  static_analysis: "정적 코드 분석",
  authorization_analysis: "접근 권한 분석",
  deployment_check: "배포 보안 점검",
  dynamic_testing: "동적 보안 테스트",
  generating_findings: "결과 생성",
};

export const SCAN_STEP_ORDER: ScanStep[] = [
  "detect_stack",
  "secret_scan",
  "dependency_scan",
  "static_analysis",
  "authorization_analysis",
  "deployment_check",
  "dynamic_testing",
  "generating_findings",
];

/** Mask sensitive substrings so raw secrets are never displayed or logged. */
export function maskSecret(value: string): string {
  if (value.length <= 8) return "•".repeat(value.length);
  return value.slice(0, 4) + "•".repeat(value.length - 8) + value.slice(-4);
}

/**
 * Run `worker` over `items` with at most `limit` in flight. Results keep the
 * input order. A rejected worker rejects the whole run (callers catch per item).
 */
export async function runPool<T, R>(
  items: readonly T[],
  limit: number,
  worker: (item: T, index: number) => Promise<R>
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const lanes = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await worker(items[i], i);
    }
  });
  await Promise.all(lanes);
  return results;
}
