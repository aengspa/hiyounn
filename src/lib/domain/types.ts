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
  /** 업로드한 소스 코드 zip 파일 이름(메타데이터). */
  sourceZipName?: string;
  createdAt: string;
}

export interface User {
  id: string;
  email: string;
  /** Display name (optional). */
  name?: string;
  /** scrypt password hash, formatted "salt:derivedKey" (both hex). Absent for the seeded demo user. */
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
