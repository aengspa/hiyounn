import type { ExecutionTier, Severity, ComponentKind } from "@/lib/domain/types";

/**
 * 검사 규칙 스키마 (선언형 TS 규칙 객체).
 *
 * 문서의 YAML 규칙 스키마를 TypeScript로 옮긴 것. 규칙은 스캐너 코드에서
 * 분리되어 선언형으로 관리되고, 서버가 이 규칙을 근거로 도구 입력을 조립한다.
 * LLM이 실행 코드나 도구/등급을 직접 지정하지 못하게 하는 것이 핵심.
 */

export type ScanMethod = "SAST" | "CONFIG" | "DAST" | "TEST";

/** selector는 서버가 아는 연산자만 사용한다. eval/임의 코드 금지. */
export type SelectorOp = "equals" | "contains" | "in" | "exists";

export interface SelectorClause {
  field: string; // 예: "components.kind", "capabilities.authentication"
  op: SelectorOp;
  value?: unknown;
}

export interface Selector {
  all?: SelectorClause[];
  any?: SelectorClause[];
}

export interface StandardRef {
  framework: string; // 예: OWASP_API_SECURITY_TOP_10
  version: string;
  id: string; // 예: API1:2023
}

export interface RuleCheck {
  id: string; // 검사 ID(규칙 내 유일)
  toolId: string; // tool-catalog에 등록된 도구 ID
  method: ScanMethod;
  /** TEST/DAST 검사의 기대값 등 추가 매개변수. */
  actor?: string;
  object?: string;
  operation?: "read" | "update" | "delete" | "create";
  expected?: "allowed" | "denied";
}

export interface RuleExecution {
  tier: ExecutionTier;
  maxRequests?: number;
  timeoutSeconds?: number;
  target?: "source_checkout" | "registered_test_deployment";
  destructiveOperations: false; // MVP: 파괴적 작업 금지
}

export interface RuleRemediation {
  autoPatch: "branch_only" | "none";
  allowedPaths: string[];
  productionChange: "approval_required" | "not_applicable";
}

export interface SecurityRule {
  id: string; // 전역 유일(예: WEB-002)
  version: string;
  title: string;
  titleKo: string;
  severity: Severity;
  standards: StandardRef[];
  /** 적용 대상 구성요소 종류. */
  appliesTo: ComponentKind[];
  selector: Selector;
  methods: ScanMethod[];
  /** 방법별 선행 조건(능력/환경 키). 부족하면 coverage_gap. */
  prerequisites: Partial<Record<ScanMethod, string[]>>;
  checks: RuleCheck[];
  execution: RuleExecution;
  remediation: RuleRemediation;
  /** 재검증에 반드시 통과해야 하는 검사 ID(공격 차단 + 정상 기능 보존). */
  verificationRequiredChecks: string[];
}

/** 도구 카탈로그 항목. 등록되지 않은 도구는 실행 불가. */
export interface ToolCatalogEntry {
  toolId: string;
  displayName: string;
  method: ScanMethod;
  /** 이 도구가 만들어내는 증거 종류(설명용). */
  producesEvidence: string[];
}
