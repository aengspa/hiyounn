import type {
  Project,
  Scan,
  SecurityFinding,
  FixAttempt,
  FixArtifact,
  FixJob,
  SourceVersion,
  VerificationResult,
  User,
} from "@/lib/domain/types";
import type { ScanMode, TestAccount } from "@/lib/domain/scanMode";
import type { Buffer } from "buffer";

export interface CreateProjectInput {
  name: string;
  repositoryUrl?: string;
  deploymentUrl?: string;
  /** 검사할 소스 파일(상대 경로 → 내용). 비어 있으면 안 된다. */
  files: Record<string, string>;
  /** 어떤 방식으로 받은 코드인지. */
  sourceKind: "zip" | "paste";
  sourceZipName?: string;
  deploymentAuthorized?: boolean;
  scanMode?: ScanMode;
  testAccounts?: TestAccount[];
}

/**
 * The storage backend contract.
 *
 * Both the in-memory backend (dev / tests) and the Supabase backend implement
 * this identical, fully-async interface. The facade in `store.ts` picks one
 * based on DATA_STORE and re-exports these as the app's store API.
 *
 * Every method that touches a project, scan, finding, source version or fix job
 * takes an `ownerId` and MUST enforce ownership — throwing NotAuthorizedError
 * for cross-user access and NotFoundError for missing resources.
 */
export interface StoreBackend {
  // ── Users (auth) ──
  findUserByEmail(email: string): Promise<User | undefined>;
  getUserById(userId: string): Promise<User | undefined>;
  createUser(input: {
    email: string;
    passwordHash: string;
    name?: string;
  }): Promise<User>;

  // ── Projects ──
  listProjects(ownerId: string): Promise<Project[]>;
  getProject(projectId: string, ownerId: string): Promise<Project>;
  /** Creates the project AND its immutable original source version. */
  createProject(ownerId: string, input: CreateProjectInput): Promise<Project>;

  // ── Source versions (immutable) ──
  getSourceVersion(versionId: string, ownerId: string): Promise<SourceVersion>;
  /** Stores a new version. The project must belong to `version.ownerId`. */
  saveSourceVersion(version: SourceVersion): Promise<void>;
  /** The version a new scan should read (creates one for legacy projects). */
  getCurrentSourceVersion(projectId: string, ownerId: string): Promise<SourceVersion | undefined>;

  // ── Scans ──
  listScans(projectId: string, ownerId: string): Promise<Scan[]>;
  getScan(scanId: string, ownerId: string): Promise<Scan>;
  runScan(projectId: string, ownerId: string): Promise<Scan>;
  scanPlan(projectId: string, ownerId: string): Promise<unknown>;

  // ── Findings ──
  getFinding(findingId: string, ownerId: string): Promise<SecurityFinding>;
  getFindingsForScan(
    scanId: string,
    ownerId: string
  ): Promise<SecurityFinding[]>;

  // ── Fix-all jobs ──
  /**
   * Inserts the job unless one with the same (ownerId, idempotencyKey) already
   * exists; then returns that one with `created: false`.
   */
  insertFixJob(job: FixJob): Promise<{ job: FixJob; created: boolean }>;
  updateFixJob(job: FixJob): Promise<void>;
  getFixJob(jobId: string, ownerId: string): Promise<FixJob>;
  findFixJobByKey(ownerId: string, idempotencyKey: string): Promise<FixJob | undefined>;
  listFixJobsForScan(scanId: string, ownerId: string): Promise<FixJob[]>;

  // ── Per-finding fixes & verification (legacy single-item flow) ──
  generateFixForFinding(
    findingId: string,
    ownerId: string
  ): Promise<FixAttempt>;
  getFixForFinding(
    findingId: string,
    ownerId: string
  ): Promise<FixAttempt | undefined>;
  applyFix(findingId: string, ownerId: string): Promise<SecurityFinding>;
  verifyFinding(
    findingId: string,
    ownerId: string
  ): Promise<{ finding: SecurityFinding; result: VerificationResult }>;
  getVerification(
    findingId: string,
    ownerId: string
  ): Promise<VerificationResult | undefined>;

  // ── Legacy per-finding artifacts (replaced by fix-all jobs) ──
  buildFixArtifact(findingId: string, ownerId: string): Promise<FixArtifact>;
  getFixArtifact(
    artifactId: string,
    ownerId: string
  ): Promise<FixArtifact | undefined>;
  getFixArtifactBytes(
    artifactId: string,
    ownerId: string
  ): Promise<Buffer | undefined>;
  listFixArtifacts(
    findingId: string,
    ownerId: string
  ): Promise<FixArtifact[]>;
}
