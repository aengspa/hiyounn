import type { SecurityRule } from "@/lib/rules/types";
import { getRule } from "@/lib/rules/registry";
import {
  ASVS5_RULE_IDS,
  asvsRuleIdForSignal,
} from "@/lib/rules/asvs5Catalog";

/**
 * 스캐너 구현 ↔ 규칙 바인딩.
 *
 * 기존 스캐너(src/lib/scanners/*)의 name을 규칙 ID에 연결한다. 정적 웹
 * 스캐너는 여러 선언형 규칙을 담당하며 finding의 verificationKey로 정확한
 * 규칙을 역매핑한다.
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
  "static-web-scanner": null,
  "ai-code-scanner": null,
};

/** 정적 웹 스캐너가 담당하는 기존 규칙 + ASVS 5.0 세부 정적 규칙. */
export const STATIC_WEB_RULES = [
  "WEB-003",
  "WEB-004",
  "WEB-005",
  "WEB-006",
  "WEB-014",
  ...ASVS5_RULE_IDS,
];

/** verificationKey 접두어 → 규칙 ID. finding에 ruleId를 부착할 때 사용. */
export function ruleIdForVerificationKey(key: string | undefined): string | null {
  if (!key) return null;
  if (key.startsWith("asvs5:")) {
    const signalKey = key.split(":", 3)[1] ?? "";
    return asvsRuleIdForSignal(signalKey);
  }
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
  if (key.startsWith("sidor:")) return "WEB-014";
  if (key.startsWith("ai:")) return null;
  return null;
}

export function ruleForScanner(scannerName: string): SecurityRule | undefined {
  const id = SCANNER_TO_RULE[scannerName];
  if (!id) return undefined;
  return getRule(id);
}
