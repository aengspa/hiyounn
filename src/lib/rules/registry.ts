import type { SecurityRule } from "@/lib/rules/types";
import { RULES } from "@/lib/rules/definitions";
import { isRegisteredTool } from "@/lib/rules/toolCatalog";

/**
 * 규칙 레지스트리.
 *
 * 서버 시작 시 모든 규칙을 스키마 검증한다. 검증 실패한 규칙은 적재하지 않는다
 * (문서: "유효한 규칙만 레지스트리에 적재"). 검증 항목:
 *   - id/version 존재, id 전역 유일
 *   - 참조하는 tool_id가 도구 카탈로그에 등록됨
 *   - selector가 아는 연산자만 사용
 *   - verificationRequiredChecks가 실제 checks(또는 표준 검사)를 참조
 */

const KNOWN_OPS = new Set(["equals", "contains", "in", "exists"]);
// checks 외에 verification에서 참조 가능한 서버 표준 검사(문서 5-3).
const STANDARD_VERIFICATION_CHECKS = new Set([
  "existing-functional-tests",
  "changed-code-scan",
]);

export interface RuleValidationError {
  ruleId: string;
  message: string;
}

function validateRule(
  rule: SecurityRule,
  seenIds: Set<string>
): string[] {
  const errors: string[] = [];

  if (!rule.id) errors.push("id 누락");
  if (!rule.version) errors.push("version 누락");
  if (rule.id && seenIds.has(rule.id)) errors.push(`중복 id: ${rule.id}`);

  // selector 연산자 검사
  const clauses = [...(rule.selector.all ?? []), ...(rule.selector.any ?? [])];
  for (const c of clauses) {
    if (!KNOWN_OPS.has(c.op)) errors.push(`알 수 없는 selector 연산자: ${c.op}`);
  }

  // 도구 등록 검사
  const checkIds = new Set<string>();
  for (const chk of rule.checks) {
    checkIds.add(chk.id);
    if (!isRegisteredTool(chk.toolId)) {
      errors.push(`등록되지 않은 tool_id: ${chk.toolId} (check ${chk.id})`);
    }
    if (!rule.methods.includes(chk.method)) {
      errors.push(`check ${chk.id}의 method ${chk.method}가 methods에 없음`);
    }
  }

  // verification 참조 검사
  for (const vc of rule.verificationRequiredChecks) {
    if (!checkIds.has(vc) && !STANDARD_VERIFICATION_CHECKS.has(vc)) {
      errors.push(`verification이 존재하지 않는 검사 참조: ${vc}`);
    }
  }

  // MVP 안전장치: 파괴적 작업 금지
  if (rule.execution.destructiveOperations !== false) {
    errors.push("execution.destructiveOperations는 false여야 함");
  }

  return errors;
}

interface LoadedRegistry {
  rules: SecurityRule[];
  errors: RuleValidationError[];
  digest: string;
}

function loadRegistry(): LoadedRegistry {
  const valid: SecurityRule[] = [];
  const errors: RuleValidationError[] = [];
  const seen = new Set<string>();

  for (const rule of RULES) {
    const ruleErrors = validateRule(rule, seen);
    if (ruleErrors.length > 0) {
      for (const m of ruleErrors) errors.push({ ruleId: rule.id ?? "?", message: m });
      continue; // 유효하지 않은 규칙은 적재하지 않음
    }
    seen.add(rule.id);
    valid.push(rule);
  }

  // 규칙 집합의 간단한 다이제스트(계획 신선도 확인용).
  const digest = simpleDigest(
    valid.map((r) => `${r.id}@${r.version}`).sort().join(",")
  );

  return { rules: valid, errors, digest };
}

function simpleDigest(input: string): string {
  let h = 5381;
  for (let i = 0; i < input.length; i++) {
    h = (h * 33) ^ input.charCodeAt(i);
  }
  return "reg_" + (h >>> 0).toString(16);
}

const REGISTRY = loadRegistry();

if (REGISTRY.errors.length > 0 && process.env.NODE_ENV !== "production") {
  // 개발 중에는 검증 실패를 눈에 띄게 남긴다(비밀·레포 내용은 포함 안 함).
  console.warn(
    "[rule-registry] 유효하지 않은 규칙:",
    REGISTRY.errors.map((e) => `${e.ruleId}: ${e.message}`)
  );
}

export function getRules(): SecurityRule[] {
  return REGISTRY.rules;
}

export function getRule(id: string): SecurityRule | undefined {
  return REGISTRY.rules.find((r) => r.id === id);
}

export function isRegisteredRule(id: string, version?: string): boolean {
  const r = getRule(id);
  if (!r) return false;
  return version ? r.version === version : true;
}

export function registryDigest(): string {
  return REGISTRY.digest;
}

export const POLICY_VERSION = "automatic-security-qa-v1";
