import type { ScanStep } from "@/lib/domain/types";

let counter = 0;
/** Deterministic-ish id generator for the in-memory store. */
export function id(prefix = "id"): string {
  counter += 1;
  return `${prefix}_${Date.now().toString(36)}_${counter}`;
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
