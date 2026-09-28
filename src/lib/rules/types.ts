import type {
  ComponentKind,
  ExecutionTier,
  Severity as DomainSeverity,
} from "@/lib/domain/types";

/** 사용자가 선택하는 점검 모드. 상위 모드는 하위 모드 규칙을 포함한다. */
export type ScanMode = "A" | "B" | "C";
export type Severity = DomainSeverity;
export type AppKind = ComponentKind;
export type Method = "SAST" | "CONFIG" | "TEST";

/** 기존 호출부와 도구 카탈로그가 쓰는 이름을 유지한다. */
export type ScanMethod = Method | "DAST";
export type Tier = Extract<
  ExecutionTier,
  "PASSIVE" | "SAFE_ACTIVE" | "ISOLATED_ACTIVE"
>;

/** linked_baas_project는 검증된 소스/번들에서 발견한 공개 BaaS 대상만 뜻한다. */
export type Target =
  | "source_checkout"
  | "registered_test_deployment"
  | "linked_baas_project";

export type Prerequisite =
  | "source_checkout"
  | "authorized_test_deployment"
  | "linked_baas_project"
  | "test_user_a"
  | "test_user_b"
  | "object_owned_by_a"
  | "object_owned_by_b"
  | "admin_session";

export type Framework =
  | "CWE"
  | "CAPEC"
  | "OWASP_TOP_10"
  | "OWASP_API_SECURITY_TOP_10"
  | "OWASP_LLM_TOP_10"
  | "MITRE_ATTACK"
  | "MITRE_ATLAS";

export interface StandardRef {
  framework: Framework;
  version?: string;
  id: string;
}

/** selector는 서버가 아는 연산자만 사용한다. eval/임의 코드 금지. */
export interface Condition {
  field: string;
  op: "equals" | "not_equals" | "contains" | "exists" | "in";
  value?: unknown;
}

export interface Selector {
  all?: Array<Condition | Selector>;
  any?: Array<Condition | Selector>;
}

/** 이전 타입명을 쓰는 코드와 호환한다. */
export type SelectorClause = Condition;
export type SelectorOp = Condition["op"];

export interface Check {
  id: string;
  toolId: string;
  method: ScanMethod;
  actor?: "test_user_a" | "test_user_b" | "anonymous";
  object?: "object_owned_by_a" | "object_owned_by_b";
  operation?: "read" | "create" | "update" | "delete";
  expected?: "denied" | "allowed";
  confidence?: "confirmed" | "tentative";
  when?: Condition;
  params?: Record<string, unknown>;
}

export type RuleCheck = Check;

export interface Execution {
  tier: Tier;
  target: Target;
  maxRequests?: number;
  timeoutSeconds?: number;
  destructiveOperations: false;
  mutatesOwnTestData?: boolean;
}

export type RuleExecution = Execution;

export interface Remediation {
  autoPatch: "branch_only" | "none";
  allowedPaths: string[];
  productionChange: "approval_required" | "not_applicable";
  manualStepsKo?: string[];
}

export type RuleRemediation = Remediation;

export interface SecurityRule {
  id: string;
  family: string;
  version: string;
  mode: ScanMode;
  title: string;
  titleKo: string;
  summaryKo: string;
  severity: Severity;
  standards: StandardRef[];
  appliesTo: AppKind[];
  selector: Selector;
  methods: ScanMethod[];
  prerequisites: Partial<Record<ScanMethod, Prerequisite[]>>;
  checks: Check[];
  execution: Execution;
  remediation: Remediation;
  verificationRequiredChecks: string[];
  produces?: Prerequisite[];
  coverageGap?: { when: Condition; messageKo: string };
}

/** 도구 카탈로그 항목. 등록·구현되지 않은 도구는 실행할 수 없다. */
export interface ToolCatalogEntry {
  toolId: string;
  displayName: string;
  method: ScanMethod;
  producesEvidence: string[];
  /** 실제 구현을 제공하는 스캐너 또는 체크 디스패처 이름. */
  implementation?: string;
}
