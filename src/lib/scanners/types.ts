import type { SecurityFinding, VerificationResult, ScanStep } from "@/lib/domain/types";
import type { ScanMode, TestAccount } from "@/lib/domain/scanMode";

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
   * A lightweight virtual file map for static/secret scanning.
   * Keys are relative paths, values are file contents. For a real project these
   * are the user's own files; for the bundled demo it's the fixed vulnerable
   * fixture. Never executed as code.
   */
  files: Record<string, string>;

  /**
   * True when `files` are the user's own project source (uploaded/pasted),
   * false/undefined for the bundled demo fixture. Lets scanners treat every
   * file as user source without a `user-source:` naming convention.
   */
  isUserProject?: boolean;

  /**
   * True only when the user has explicitly confirmed they own/are authorized to
   * test `deploymentUrl`. Active (network) checks require this — a URL alone is
   * NOT authorization. The bundled demo target is always authorized.
   */
  deploymentAuthorized?: boolean;

  /** 사용자가 고른 스캔 방식. 실행 게이트의 최고 허용 등급을 결정한다. */
  scanMode?: ScanMode;

  /** C(격리 동적 분석) 방식에서 제공된 테스트 계정. */
  testAccounts?: TestAccount[];
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
