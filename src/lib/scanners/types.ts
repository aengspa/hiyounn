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

  /** 사용자가 선택한 규칙 모드. 없으면 제공된 입력으로 A/B/C를 보수적으로 추론한다. */
  scanMode?: import("@/lib/rules/types").ScanMode;

  /** 검증된 소스/배포 번들에서 발견한 공개 BaaS 연결 정보. 관리자 키는 금지한다. */
  linkedBaasProjects?: Array<{
    provider: "supabase" | "firebase";
    url: string;
    publicKey?: string;
    source: "verified_source" | "verified_bundle";
    tables?: string[];
    collections?: string[];
    buckets?: string[];
    projectId?: string;
  }>;

  /** 모드 C의 보호된 읽기·격리 테스트 행 프로브에 쓰는 단기 사용자 세션. */
  testSessions?: {
    test_user_a?: { bearerToken: string; probeUrl: string; subject?: string };
    test_user_b?: { bearerToken: string; probeUrl: string; subject?: string };
    admin_session?: { bearerToken: string; probeUrl: string; subject?: string };
  };

  /** 모드 C에서 사용자가 준비한 테스트 전용 객체 식별자. */
  testObjects?: {
    object_owned_by_a?: string;
    object_owned_by_b?: string;
  };

  /** 비용 통제를 위해 사용자가 명시적으로 지정한 LLM 전용 점검 엔드포인트. */
  llmProbeEndpoint?: string;
  /** Known private canaries used to distinguish leakage from refusals/echoes. */
  llmPrivateMarkers?: string[];

  /** Known endpoints, supplied by trusted discovery or the user's test configuration. */
  probeEndpoints?: {
    redirect?: string[];
    /** Endpoints explicitly confirmed to reject invalid JSON before side effects. */
    invalidJson?: string[];
  };

  /** Only a disposable fixture may be changed, with an owner session for rollback. */
  baasTestFixture?: {
    table: string;
    rowId: string;
    testOnly: true;
    originalValues: Record<string, string | number | boolean | null>;
    probeValues: Record<string, string | number | boolean | null>;
  };

  /** Server-held proof. Active tools recheck the token immediately before a scan. */
  ownershipProof?: {
    host: string;
    token: string;
    expiresAt: string;
    method: "dns_txt" | "well_known_file";
  };

  /** Internal state populated only after proof verification; never accepted from a request body. */
  ownershipVerified?: boolean;

  /** Set only when the source intake can actually provide decoded commit history. */
  gitHistoryAvailable?: boolean;
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

export const SCANNER_VERSION = "0.2.0";
export const RULESET_VERSION = "2026.09.28";
