import type { ProjectContext } from "@/lib/scanners/types";
import type { SecurityRule, RuleCheck } from "@/lib/rules/types";
import { isRegisteredRule } from "@/lib/rules/registry";
import { isRegisteredTool } from "@/lib/rules/toolCatalog";
import type { ExecutionTier } from "@/lib/domain/types";

/**
 * 실행 게이트 (문서 4-3).
 *
 * 도구를 실행하기 전에 서버가 반드시 통과시켜야 하는 검사들.
 * 모델/사용자 입력을 그대로 실행하지 않고, 서버가 규칙 레지스트리와 확인된
 * 프로젝트 정보로만 실행을 승인한다.
 *
 * 각 assert는 실패 시 GateError를 던진다. 게이트를 통과하지 못한 검사는
 * 실행되지 않고 coverage_gap 또는 오류로 기록된다.
 */

export class GateError extends Error {
  constructor(
    public code: GateErrorCode,
    message: string
  ) {
    super(message);
    this.name = "GateError";
  }
}

export type GateErrorCode =
  | "RULE_NOT_REGISTERED"
  | "TOOL_NOT_REGISTERED"
  | "SCOPE_DENIED"
  | "TIER_NOT_ALLOWED"
  | "PREREQUISITE_MISSING"
  | "DESTRUCTIVE_FORBIDDEN";

/** 현재 실행 컨텍스트에서 허용되는 최고 실행 등급을 계산한다. */
export function allowedMaxTier(context: ProjectContext): ExecutionTier {
  // 배포 URL(테스트 대상)이 있으면 능동 검사까지 허용. 없으면 정적(PASSIVE)만.
  // MVP에서는 ISOLATED_ACTIVE까지만 자동 허용하고, PATCH/PRIVILEGED_CHANGE는
  // 별도 승인 흐름에서만 올린다.
  if (context.deploymentUrl) return "ISOLATED_ACTIVE";
  return "PASSIVE";
}

const TIER_ORDER: Record<ExecutionTier, number> = {
  PASSIVE: 0,
  SAFE_ACTIVE: 1,
  ISOLATED_ACTIVE: 2,
  PATCH: 3,
  PRIVILEGED_CHANGE: 4,
};

export function assertRegisteredRule(rule: SecurityRule): void {
  if (!isRegisteredRule(rule.id, rule.version)) {
    throw new GateError(
      "RULE_NOT_REGISTERED",
      `등록되지 않은 규칙: ${rule.id}@${rule.version}`
    );
  }
}

export function assertRegisteredTool(check: RuleCheck): void {
  if (!isRegisteredTool(check.toolId)) {
    throw new GateError(
      "TOOL_NOT_REGISTERED",
      `등록되지 않은 도구: ${check.toolId}`
    );
  }
}

export function assertTierAllowed(
  rule: SecurityRule,
  context: ProjectContext
): void {
  const max = allowedMaxTier(context);
  if (TIER_ORDER[rule.execution.tier] > TIER_ORDER[max]) {
    throw new GateError(
      "TIER_NOT_ALLOWED",
      `실행 등급 ${rule.execution.tier}는 현재 허용 범위(${max})를 초과함`
    );
  }
}

export function assertNonDestructive(rule: SecurityRule): void {
  if (rule.execution.destructiveOperations !== false) {
    throw new GateError(
      "DESTRUCTIVE_FORBIDDEN",
      `파괴적 작업은 금지됨: ${rule.id}`
    );
  }
}

/**
 * 선행 조건 평가. 부족한 조건 목록을 반환한다(예외 아님).
 * 서버는 부족분을 coverage_gap으로 기록한다.
 */
export function evaluatePrerequisites(
  rule: SecurityRule,
  context: ProjectContext
): { ready: boolean; missing: string[] } {
  const missing: string[] = [];
  const have = availableConditions(context);
  for (const [, conds] of Object.entries(rule.prerequisites)) {
    for (const c of conds ?? []) {
      if (!have.has(c)) missing.push(c);
    }
  }
  return { ready: missing.length === 0, missing: [...new Set(missing)] };
}

/**
 * 현재 프로젝트/환경에서 충족된 선행 조건 집합.
 * MVP 데모 컨텍스트 기준으로 매핑한다.
 */
function availableConditions(context: ProjectContext): Set<string> {
  const s = new Set<string>();
  // 소스 스냅샷은 항상 있다(파일 맵 존재).
  if (Object.keys(context.files).length > 0) s.add("source_checkout");
  // 배포 URL이 있으면 테스트 배포가 승인된 것으로 간주(MVP).
  if (context.deploymentUrl) {
    s.add("authorized_test_deployment");
    // 데모: 테스트 사용자/객체는 데모 앱에 준비되어 있다.
    s.add("test_user_a");
    s.add("test_user_b");
    s.add("object_owned_by_a");
    s.add("object_owned_by_b");
  }
  return s;
}
