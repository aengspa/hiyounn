import type {
  Project,
  Scan,
  SecurityFinding,
  FixAttempt,
  VerificationResult,
  User,
} from "@/lib/domain/types";

/**
 * The storage backend contract.
 *
 * Both the in-memory backend (dev / demo) and the Supabase backend implement
 * this identical, fully-async interface. The facade in `store.ts` picks one
 * based on DATA_STORE and re-exports these as the app's store API.
 *
 * Every method that touches a project, scan, or finding takes an `ownerId` and
 * MUST enforce ownership — throwing NotAuthorizedError for cross-user access
 * and NotFoundError for missing resources. This is the app's own defense
 * against the IDOR class of bug it detects, independent of any DB-level RLS.
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
  createProject(
    ownerId: string,
    input: {
      name: string;
      repositoryUrl?: string;
      deploymentUrl?: string;
      sourceCode?: string;
    }
  ): Promise<Project>;

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

  // ── Fixes & verification ──
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
  ): Promise<{ finding: SecurityFinding; result?: VerificationResult }>;
  getVerification(
    findingId: string,
    ownerId: string
  ): Promise<VerificationResult | undefined>;
}
