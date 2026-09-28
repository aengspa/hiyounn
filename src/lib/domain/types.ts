import type { ScanMode, TestAccount } from "@/lib/domain/scanMode";
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
  /** Variants of the same security issue, used for report grouping. */
  family?: string;
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
  /** Unified-diff-style hunk lines (for display). */
  patch: string;
  /**
   * Exact source text to replace and its replacement. When present, the
   * artifact builder can apply this fix to a working copy by literal string
   * replacement (safer than re-parsing the display patch). If beforeText is
   * empty, afterText is treated as new file content (or appended).
   */
  beforeText?: string;
  afterText?: string;
  /**
   * "create"일 때만 새 파일을 만든다(afterText가 파일 전체 내용). 없으면
   * 기존 파일의 beforeText를 afterText로 바꾸는 수정으로 본다.
   */
  mode?: "replace" | "create";
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
// Fix artifacts (modified project copy)
// ─────────────────────────────────────────────────────────────

/** One file inside a generated fix artifact (the modified working copy). */
export interface ArtifactFile {
  /** Path within the project (e.g. "src/api/users/route.ts"). */
  path: string;
  /** Whether this file was changed relative to the preserved original. */
  changed: boolean;
}

/**
 * A downloadable, integrity-checked copy of the project with selected fixes
 * applied. The original upload is never mutated; this is a separate working
 * copy. The ZIP bytes are stored separately (base64) keyed by id.
 */
export interface FixArtifact {
  id: string;
  /** The fix job (finding) this artifact was produced for. */
  findingId: string;
  projectId: string;
  ownerId: string;
  /** Applied fix attempt ids that shaped this copy. */
  appliedFixIds: string[];
  files: ArtifactFile[];
  /** Download file name, e.g. "myproject-fixed-3.zip". */
  fileName: string;
  /** ZIP byte size. */
  size: number;
  /** SHA-256 hex of the ZIP bytes (integrity). */
  sha256: string;
  /** Monotonic version per (project, finding). */
  version: number;
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
  /** 검사한 불변 소스 버전. 실제 Git 커밋이 아니다. */
  sourceVersionId?: string;
  /** 검사한 소스 버전의 내용 해시(SHA-256). */
  sourceContentHash?: string;
  /** 실제 Git 커밋을 알 때만 채운다. 가짜 해시를 넣지 않는다. */
  commitSha?: string;
  startedAt: string;
  completedAt?: string;
  findingIds: string[];
  scope: ScanScope;
  /** 규칙 기반 실행 계획(선택 검사 + 커버리지 갭). Phase A. */
  plan?: ScanPlan;
  /** 스캔 완료 후 생성한 요약 보고서(AI 또는 결정적). */
  report?: ScanReport;
}

/** 스캔 결과 요약 보고서. AI 설정 시 LLM 생성, 아니면 결정적 요약. */
export interface ScanReport {
  /** 한 문단 요약(한국어). */
  summary: string;
  /** 핵심 포인트(불릿). */
  highlights: string[];
  /** 권장 다음 단계(한국어). */
  recommendation: string;
  generatedAt: string;
  source: "llm" | "deterministic";
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
  /**
   * True when the user confirmed they own / are authorized to actively test
   * `deploymentUrl`. Required before any active (network) DAST check runs.
   */
  deploymentAuthorized?: boolean;
  /**
   * 사용자가 고른 보안 스캔 방식 (A: static / B: safe_active / C: isolated_active).
   * 없으면 이전 동작(권한 확인 시 ISOLATED_ACTIVE까지 허용)을 따른다.
   */
  scanMode?: ScanMode;
  /** C 방식에서 쓰는 격리 서버 테스트 계정. 비밀번호는 서버에만 보관. */
  testAccounts?: TestAccount[];
  /**
   * True ONLY for the bundled "Acme Notes (demo)" project. Demo projects scan
   * the built-in vulnerable fixture (for the IDOR full-loop demo). Real user
   * projects scan ONLY their own uploaded/pasted source — the demo fixture is
   * never mixed into user results.
   */
  isDemo?: boolean;
  /**
   * 지금 점검 대상인 불변 소스 버전. 처음에는 업로드 원본이고, 사용자가
   * 수정본을 다시 등록하면 새 버전으로 바뀐다. 원본 버전은 지우지 않는다.
   */
  currentSourceVersionId?: string;
  createdAt: string;
}

// ─────────────────────────────────────────────────────────────
// Source versions (immutable)
// ─────────────────────────────────────────────────────────────

/**
 * 한 번 저장하면 바뀌지 않는 소스 스냅샷. 원본·수정본·재등록본을 서로
 * 섞지 않기 위해 내용 해시와 함께 따로 보관한다.
 */
export interface SourceVersion {
  id: string;
  projectId: string;
  ownerId: string;
  kind: "original" | "fixed" | "reupload";
  /** 수정본이면 어떤 버전에서 만들어졌는지. */
  parentVersionId?: string;
  /** 수정본이면 어떤 전체 수정 작업이 만들었는지. */
  fixJobId?: string;
  /** 상대 경로 → 파일 내용. */
  files: Record<string, string>;
  fileCount: number;
  totalBytes: number;
  /** 정렬한 (경로, 내용) 목록의 SHA-256. */
  contentHash: string;
  createdAt: string;
}

// ─────────────────────────────────────────────────────────────
// Fix-all jobs
// ─────────────────────────────────────────────────────────────

/**
 * 항목별 수정 결과.
 *  - applied: 수정이 작업 복사본에 실제로 적용됨 (아직 해결 확인은 아님)
 *  - apply_failed: 수정안은 있었지만 원본과 맞지 않거나 충돌해 적용하지 못함
 *  - unsupported: 자동 수정 방법이 없음 (배포 설정, 외부 작업 등)
 *  - skipped: 한도·시간 초과 등으로 이번 작업에서 다루지 못함
 */
export type FixItemOutcome = "applied" | "apply_failed" | "unsupported" | "skipped";

export interface FixJobItem {
  findingId: string;
  title: string;
  severity: Severity;
  ruleId?: string;
  outcome: FixItemOutcome;
  /** 내부 사유 코드 (예: before_not_found, conflict, unsafe_path). */
  reasonCode?: string;
  /** 사용자에게 보여 줄 짧은 이유. */
  reason?: string;
  fixSource?: "deterministic" | "llm";
  /** 이 항목 때문에 바뀐 파일. */
  files: string[];
  summary?: string;
  plainExplanation?: string;
  /** LLM 수정안을 요청했다면 그 요청의 추적 ID. */
  llmCorrelationId?: string;
}

export type FixJobStatus = "running" | "completed" | "partial" | "failed";

/** 다운로드할 수정 파일 묶음. 바뀐 파일만 원래 상대 경로로 담는다. */
export interface FixJobArtifact {
  id: string;
  fileName: string;
  size: number;
  /** ZIP 바이트의 SHA-256. 다운로드 파일과 비교할 수 있다. */
  sha256: string;
  changedFiles: string[];
  /** 저장소 안 위치. 사용자 입력으로 만들지 않는다. */
  storageKey: string;
  createdAt: string;
}

export interface FixJob {
  id: string;
  projectId: string;
  ownerId: string;
  scanId: string;
  /** 수정의 기준이 된 소스 버전(= 스캔한 버전). */
  baseVersionId: string;
  baseContentHash: string;
  /** 수정이 적용된 새 소스 버전. 적용된 항목이 없으면 없다. */
  resultVersionId?: string;
  resultContentHash?: string;
  /** 같은 요청의 중복 실행을 막는 키. */
  idempotencyKey: string;
  status: FixJobStatus;
  items: FixJobItem[];
  changedFiles: string[];
  artifact?: FixJobArtifact;
  /** 한도 때문에 이번 작업에서 뺀 항목 수. */
  skippedForLimit: number;
  errorCode?: string;
  errorMessage?: string;
  createdAt: string;
  updatedAt: string;
  completedAt?: string;
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
