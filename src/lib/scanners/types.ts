import type { SecurityFinding, VerificationResult, ScanStep } from "@/lib/domain/types";

/**
 * The context a scanner needs to reason about a project. In the MVP this is
 * populated from the demo fixtures; in production it would be hydrated from a
 * cloned repo + deployment metadata.
 */
export interface ProjectContext {
  projectId: string;
  name: string;
  repositoryUrl?: string;
  deploymentUrl?: string;
  commitSha?: string;

  /** Detected stack — drives which scanners are applicable. */
  stack: {
    frameworks: string[]; // e.g. ["next.js", "react"]
    languages: string[]; // e.g. ["typescript"]
    baas?: string[]; // e.g. ["supabase"]
    hasEnvFile: boolean;
  };

  /**
   * A lightweight virtual file map for static/secret scanning in the MVP.
   * Keys are relative paths, values are file contents. This is the bundled
   * vulnerable demo app, NOT arbitrary user code execution.
   */
  files: Record<string, string>;
}

/**
 * Common interface every scanner implements. This is the seam that lets us
 * swap mock scanners for real tools (Semgrep, Gitleaks, OWASP ZAP) later
 * without touching the orchestrator or UI.
 */
export interface SecurityScanner {
  /** Machine name, e.g. "secret-scanner". */
  readonly name: string;
  /** Human label shown in the scan pipeline UI. */
  readonly displayName: string;
  /** Which pipeline step this scanner reports under. */
  readonly step: ScanStep;
  /** True if this scanner produces simulated (mock) results in the MVP. */
  readonly simulated: boolean;

  isApplicable(context: ProjectContext): Promise<boolean>;
  scan(context: ProjectContext): Promise<SecurityFinding[]>;

  /**
   * Optional deterministic re-verification of a single finding, used by the
   * verification engine after a fix is applied.
   */
  verify?(
    finding: SecurityFinding,
    context: ProjectContext
  ): Promise<VerificationResult>;
}

export const SCANNER_VERSION = "0.1.0";
export const RULESET_VERSION = "2026.09.03";
