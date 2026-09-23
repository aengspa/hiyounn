import type { SecurityRule } from "@/lib/rules/types";
import { getRule } from "@/lib/rules/registry";

/**
 * 스캐너 구현 ↔ 규칙 바인딩.
 *
 * 기존 스캐너(src/lib/scanners/*)의 name을 규칙 ID에 연결한다. 이렇게 해야
 * 규칙 레지스트리가 "어떤 도구로 무엇을 검사할지"를 선언하고, 스캐너는 그
 * 도구의 실제 구현 역할만 한다. ai-code-scanner는 특정 규칙에 매이지 않고
 * ai_code_analyzer 도구로만 동작한다(규칙 없음).
 */
export const SCANNER_TO_RULE: Record<string, string | null> = {
  "secret-scanner": "SEC-001",
  "dependency-scanner": "SEC-004",
  "authorization-scanner": "WEB-002",
  "header-cors-scanner": "WEB-007",
  "exposed-endpoint-scanner": "WEB-008",
  "tls-scanner": "WEB-009",
  "user-enumeration-scanner": "WEB-010",
  "bruteforce-scanner": "WEB-011",
  "cookie-scanner": "WEB-012",
  "bfla-scanner": "WEB-013",
  "baas-config-scanner": "BAAS-001",
  // 정적 웹 스캐너는 여러 규칙(WEB-003/004/005)을 담당하므로 단일 바인딩이 없다.
  // 계획(ScanPlan)에는 아래 STATIC_WEB_RULES 전체가 게이트를 거쳐 포함되고,
  // 개별 finding의 규칙은 verificationKey로 결정된다(ruleIdForVerificationKey).
  "static-web-scanner": null,
  "ai-code-scanner": null, // 규칙 없이 도구만
};

/** 정적 웹 스캐너(static-web-scanner)가 담당하는 규칙 목록. */
export const STATIC_WEB_RULES = ["WEB-003", "WEB-004", "WEB-005", "WEB-006"];

/** verificationKey 접두어 → 규칙 ID. finding에 ruleId를 부착할 때 사용. */
export function ruleIdForVerificationKey(key: string | undefined): string | null {
  if (!key) return null;
  if (key.startsWith("idor:")) return "WEB-002";
  if (key.startsWith("secret:")) return "SEC-001";
  if (key.startsWith("dep:")) return "SEC-004";
  if (key.startsWith("headers:") || key.startsWith("cors:")) return "WEB-007";
  if (key.startsWith("exposed:")) return "WEB-008";
  if (key.startsWith("tls:")) return "WEB-009";
  if (key.startsWith("enum:")) return "WEB-010";
  if (key.startsWith("brute:")) return "WEB-011";
  if (key.startsWith("cookie:")) return "WEB-012";
  if (key.startsWith("bfla:")) return "WEB-013";
  if (key.startsWith("rls:")) return "BAAS-001";
  if (key.startsWith("xss:")) return "WEB-003";
  if (key.startsWith("inj:")) return "WEB-004";
  if (key.startsWith("expose:")) return "WEB-005";
  if (key.startsWith("trav:")) return "WEB-006";
  if (key.startsWith("ai:")) return null; // AI 발견은 규칙 미상
  return null;
}

export function ruleForScanner(scannerName: string): SecurityRule | undefined {
  const id = SCANNER_TO_RULE[scannerName];
  if (!id) return undefined;
  return getRule(id);
}
