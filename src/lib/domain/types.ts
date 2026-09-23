/**
 * Core domain types for the Vibe Coding Security Agent.
 *
 * Design principle: evidence over AI guesswork. Every finding carries
 * concrete evidence, and every "resolved" state is backed by deterministic
 * verification + regression test results — never by an LLM's opinion.
 */

// ─────────────────────────────────────────────────────────────
// Severity & status
// ─────────────────────────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low";

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

/**
 * A finding must walk this full lifecycle before it can be "resolved".
 * We never jump straight from "fixed" to "resolved": the same attack must be
 * re-run (security verification) AND normal features must be re-checked
 * (regression verification).
 */
export type FindingStatus =
  | "detected"
  | "verified" // attack reproduced — vulnerability is real, not theoretical
  | "fixing"
  | "fixed" // a fix has been applied to the working copy
  | "verification_failed" // re-run of the attack still succeeds
  | "regression_failed" // fix broke a legitimate feature
  | "resolved"; // attack blocked AND regression passed

// ─────────────────────────────────────────────────────────────
// 문서 아키텍처 어휘 (Phase A) — 웹 대상 MVP
//
// 목표 아키텍처 문서의 상태/등급/능력 어휘를 흡수한다. 기존 FindingStatus는
// 그대로 두되(UI/스토어 호환), 규칙 엔진·검증 계층은 아래 TestStatus를 쓴다.
// ─────────────────────────────────────────────────────────────

/** 검사 결과 상태. "미실행/실패/통과"를 절대 섞지 않는다. */
export type TestStatus =
  | "CONFIRMED" // 취약점이 실제로 재현·확인됨
  | "SUSPECTED" // 정적 신호는 있으나 재현 안 됨
  | "NOT_DETECTED" // 조사했으나 발견하지 못함
  | "NOT_APPLICABLE" // 이 프로젝트엔 해당 없음
  | "NOT_TESTED" // 테스트 환경/전제조건 부족으로 미실행
  | "TEST_FAILED" // 검사기 오류
  | "FIXED_VERIFIED" // 수정 후 재검증까지 통과
  | "REGRESSION_FAILED"; // 수정이 정상 기능을 깨뜨림

/** 검사 실행 등급. 서버만 승인·확정한다. */
export type ExecutionTier =
  | "PASSIVE" // 읽기 전용(코드/설정 정적 분석)
  | "SAFE_ACTIVE" // 비파괴 HTTP 요청(헤더/CORS 등)
  | "ISOLATED_ACTIVE" // 격리 환경에서의 공격 재현(IDOR 등)
  | "PATCH" // 브랜치 패치 생성
  | "PRIVILEGED_CHANGE"; // 운영 반영(승인 필요)

/** 구성요소·기능의 탐지 상태. not_detected와 absent를 구분해 유지한다. */
export type CapabilityState =
  | "detected"
  | "not_detected" // 조사했으나 못 찾음
  | "absent" // 없다는 근거가 확보됨
  | "unknown";

/** FindingStatus → TestStatus 매핑(문서 어휘로 표현할 때 사용). */
export function toTestStatus(s: FindingStatus): TestStatus {
  switch (s) {
    case "detected":
      return "SUSPECTED";
    case "verified":
      return "CONFIRMED";
    case "fixing":
    case "fixed":
      return "CONFIRMED"; // 아직 재검증 전 — 확인된 취약점에 패치만 적용된 상태
    case "verification_failed":
      return "CONFIRMED";
    case "regression_failed":
      return "REGRESSION_FAILED";
    case "resolved":
      return "FIXED_VERIFIED";
  }
}

// ─────────────────────────────────────────────────────────────
// Evidence
// ─────────────────────────────────────────────────────────────

export type EvidenceKind =
  | "source_code"
  | "http_request"
  | "http_response"
  | "scanner_output"
  | "configuration"
  | "attack_reproduction";

/**
 * A single piece of concrete evidence. `masked` indicates the content has had
 * sensitive values redacted before storage/display (we never store raw
 * user secrets or repo contents in logs).
 */
export interface SecurityEvidence {
  id: string;
  kind: EvidenceKind;
  label: string;
  /** Monospace-rendered content: code snippet, raw HTTP, scanner output, etc. */
  content: string;
  masked?: boolean;
  language?: string;
}

// ─────────────────────────────────────────────────────────────
// Finding
// ─────────────────────────────────────────────────────────────

export interface CodeLocation {
  file: string;
  line: number;
}

export interface SecurityFinding {
  id: string;
  scanId: string;
  title: string;
  severity: Severity;
  category: string;

  // Professional classification — shown as detail, never as the headline.
  owasp?: string;
  cwe?: string;
  cvss?: number;

  /** Technical description. */
  description: string;
  /** Plain-language "what can happen to you" — this is the headline for users. */
  humanReadableImpact: string;
  /** Plain-language "why this matters". */
  whyItMatters: string;

  location?: CodeLocation;
  evidence: SecurityEvidence[];

  /** Remediation guidance text (may be AI-generated, kept separate from verification). */
  remediation?: string;

  status: FindingStatus;

  /** True if this finding came from a mock scanner rather than a real tool. */
  simulated: boolean;

  /**
   * Identifier the verification engine uses to re-run the exact test that
   * proved this finding. Deterministic re-runs are keyed off this.
   */
  verificationKey?: string;

  // ── 규칙 엔진 참조 (Phase A) ──
  /** 이 발견을 만든 규칙 ID(예: WEB-002). 규칙 레지스트리 기반임을 나타냄. */
  ruleId?: string;
  /** 표준 참조(OWASP 등). 예: ["OWASP API1:2023"]. */
  standards?: string[];
  /** 이 발견을 확인한 검사의 실행 등급. */
  executionTier?: ExecutionTier;
  /** 문서 어휘 상태. 미지정 시 status에서 유도. */
  testStatus?: TestStatus;

  createdAt: string;
  updatedAt: string;
}

// ─────────────────────────────────────────────────────────────
// Fix attempts
// ─────────────────────────────────────────────────────────────

export interface FixDiff {
  file: string;
  /** Unified-diff-style hunk lines. */
  patch: string;
}

export interface FixAttempt {
  id: string;
  findingId: string;
  /** "deterministic" (rule-based) or "llm" — kept explicit for trust. */
  source: "deterministic" | "llm";
  summary: string;
  /** Plain-language explanation for users who can't read the diff. */
  plainExplanation: string;
  diffs: FixDiff[];
  applied: boolean;
  createdAt: string;
}

// ─────────────────────────────────────────────────────────────
// Verification & regression
// ─────────────────────────────────────────────────────────────

export type TestOutcome = "pass" | "fail";

export interface AttackReproduction {
  label: string;
  request: string;
  response: string;
  /** Did the attack SUCCEED? (true = vulnerable) */
  attackSucceeded: boolean;
}

/** Security verification: re-running the original attack after the fix. */
export interface VerificationTest {
  id: string;
  findingId: string;
  label: string;
  before?: AttackReproduction;
  after?: AttackReproduction;
  outcome: TestOutcome; // pass = attack now blocked
  createdAt: string;
}

/** Regression verification: legitimate behavior must still work. */
export interface RegressionCheck {
  label: string;
  expectation: string;
  outcome: TestOutcome;
  detail?: string;
}

export interface RegressionTest {
  id: string;
  findingId: string;
  checks: RegressionCheck[];
  outcome: TestOutcome; // pass = every legitimate check passed
  createdAt: string;
}

export interface VerificationResult {
  findingId: string;
  security: VerificationTest;
  regression: RegressionTest;
  /** Final: only true when security passed AND regression passed. */
  resolved: boolean;
}

// ─────────────────────────────────────────────────────────────
// Scan scope & scan
// ─────────────────────────────────────────────────────────────

export interface ScanScope {
  scanDate: string;
  repository?: string;
  deploymentUrl?: string;
  testedCommit?: string;
  scannerVersion: string;
  rulesetVersion: string;
  testedCategories: string[];
  untestedCategories: string[];
}

export type ScanStatus = "queued" | "running" | "completed" | "failed";

/** The visual pipeline steps shown during a scan. */
export type ScanStep =
  | "detect_stack"
  | "secret_scan"
  | "dependency_scan"
  | "static_analysis"
  | "authorization_analysis"
  | "deployment_check"
  | "dynamic_testing"
  | "generating_findings";

export interface Scan {
  id: string;
  projectId: string;
  status: ScanStatus;
  commitSha?: string;
  startedAt: string;
  completedAt?: string;
  findingIds: string[];
  scope: ScanScope;
  /** 규칙 기반 실행 계획(선택 검사 + 커버리지 갭). Phase A. */
  plan?: ScanPlan;
}

// ─────────────────────────────────────────────────────────────
// Project & user
// ─────────────────────────────────────────────────────────────

export interface Project {
  id: string;
  ownerId: string;
  name: string;
  repositoryUrl?: string;
  deploymentUrl?: string;
  lastScannedCommit?: string;
  currentCommit?: string;
  lastScanDate?: string;
  /** 사용자가 붙여넣은 소스 코드(AI 스캔 대상). 서버에만 보관. */
  sourceCode?: string;
  /** 업로드된 소스 zip 파일명(있는 경우). */
  sourceZipName?: string;
  createdAt: string;
}

export interface User {
  id: string;
  email: string;
  name?: string;
  /** scrypt 해시("salt:key"). 평문 비밀번호는 절대 저장하지 않음. */
  passwordHash?: string;
  createdAt?: string;
}

// Severity counts used across dashboards.
export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

// ─────────────────────────────────────────────────────────────
// 문서 아키텍처 리소스 (Phase A) — 웹 대상만(web/api/baas)
// ─────────────────────────────────────────────────────────────

/** 웹사이트 점검 대상 구성요소 종류. 앱/모바일/게임 등은 MVP 범위 밖. */
export type ComponentKind = "web" | "api" | "baas";

/** Discovery 결과: 프로젝트가 무엇으로 이루어져 있는지. */
export interface ProjectManifest {
  schemaVersion: "1.0";
  projectId: string;
  source: {
    repositoryId?: string;
    commitSha?: string;
    access: "read_only";
  };
  components: Array<{
    id: string;
    kind: ComponentKind;
    framework?: string;
    evidenceRefs: string[];
  }>;
  /** 기능(인증/사용자소유데이터 등)의 탐지 상태. */
  capabilities: Record<
    string,
    { state: CapabilityState; evidenceRefs: string[]; confidence: number }
  >;
  environment: {
    testOrigin?: string;
    testAccountsAvailable: boolean;
    cloudConfigAccess: boolean;
  };
  uncertainties: string[];
}

/** 서버가 확정한 실행 계획의 검사 항목. */
export interface PlannedCheck {
  ruleId: string;
  ruleVersion: string;
  componentId: string;
  checkId: string;
  toolId: string;
  tier: ExecutionTier;
  prerequisiteStatus: "READY" | "MISSING";
}

/** 검사하지 못한 항목과 이유. */
export interface CoverageGap {
  ruleId: string;
  checkId: string;
  reason: string;
}

/** 서버가 규칙 레지스트리로 확정한 스캔 계획. */
export interface ScanPlan {
  schemaVersion: "1.0";
  planId: string;
  projectId: string;
  sourceCommitSha?: string;
  policyVersion: string;
  ruleRegistryDigest: string;
  selectedChecks: PlannedCheck[];
  coverageGaps: CoverageGap[];
}

/** 개별 검사 실행 결과. */
export interface TestResult {
  checkId: string;
  ruleId: string;
  status: TestStatus;
  expected?: unknown;
  observed?: unknown;
  evidenceIds: string[];
  executedAt?: string;
  toolVersion?: string;
}
