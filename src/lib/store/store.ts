import type {
  Project,
  Scan,
  SecurityFinding,
  FixAttempt,
  VerificationResult,
  User,
} from "@/lib/domain/types";
import { toTestStatus } from "@/lib/domain/types";
import { id, now } from "@/lib/util";
import { buildDemoContext } from "@/lib/demo/demoContext";
import { SecurityOrchestrator } from "@/lib/scanners/orchestrator";
import { generateFixSmart } from "@/lib/remediation/fixGenerator";

/**
 * In-memory data store with a repository-style API.
 *
 * IMPORTANT: every read/write that touches a project, scan, or finding takes an
 * `ownerId` and enforces ownership. This is the app's own defense against IDOR
 * — the very class of bug it detects. Callers must pass the authenticated
 * user's id; the store throws NotAuthorized if the resource isn't theirs.
 *
 * Swapping to Supabase later means implementing this same interface against
 * the DB (with RLS as a second line of defense). DATA_STORE=supabase would
 * select that implementation.
 */

export class NotAuthorizedError extends Error {
  constructor() {
    super("Not authorized to access this resource");
    this.name = "NotAuthorizedError";
  }
}
export class NotFoundError extends Error {
  constructor() {
    super("Resource not found");
    this.name = "NotFoundError";
  }
}

interface Db {
  users: Map<string, User>;
  projects: Map<string, Project>;
  scans: Map<string, Scan>;
  findings: Map<string, SecurityFinding>;
  fixes: Map<string, FixAttempt>;
  verifications: Map<string, VerificationResult>;
  /** Whether the IDOR handler for a project has an applied fix. */
  handlerFixed: Map<string, boolean>;
}

// Persist across hot reloads in dev via globalThis.
const g = globalThis as unknown as { __vsa_db?: Db };

function freshDb(): Db {
  return {
    users: new Map(),
    projects: new Map(),
    scans: new Map(),
    findings: new Map(),
    fixes: new Map(),
    verifications: new Map(),
    handlerFixed: new Map(),
  };
}

const db: Db = g.__vsa_db ?? freshDb();
g.__vsa_db = db;

const orchestrator = new SecurityOrchestrator();

// ─────────────────────────────────────────────────────────────
// Demo user + seeded project so the app is usable immediately.
// ─────────────────────────────────────────────────────────────

export const DEMO_USER: User = { id: "demo-user", email: "you@example.com" };

function ensureSeed() {
  if (!db.users.has(DEMO_USER.id)) {
    db.users.set(DEMO_USER.id, DEMO_USER);
  }
  const alreadySeeded = [...db.projects.values()].some(
    (p) => p.ownerId === DEMO_USER.id
  );
  if (!alreadySeeded) {
    const p: Project = {
      id: id("proj"),
      ownerId: DEMO_USER.id,
      name: "Acme Notes (demo)",
      repositoryUrl: "https://github.com/acme/acme-notes",
      deploymentUrl: "https://acme-notes.example.com",
      lastScannedCommit: undefined,
      currentCommit: "b72c42d",
      lastScanDate: undefined,
      createdAt: now(),
    };
    db.projects.set(p.id, p);
  }
}
ensureSeed();

// ─────────────────────────────────────────────────────────────
// Users (auth)
// ─────────────────────────────────────────────────────────────

export class EmailInUseError extends Error {
  constructor() {
    super("An account with this email already exists");
    this.name = "EmailInUseError";
  }
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function findUserByEmail(email: string): User | undefined {
  const key = normalizeEmail(email);
  return [...db.users.values()].find((u) => u.email.toLowerCase() === key);
}

export function getUserById(userId: string): User | undefined {
  return db.users.get(userId);
}

/**
 * Create a new account. `passwordHash` must already be a scrypt hash
 * ("salt:key"); the store never sees or stores a plaintext password.
 */
export function createUser(input: {
  email: string;
  passwordHash: string;
  name?: string;
}): User {
  if (findUserByEmail(input.email)) throw new EmailInUseError();
  const user: User = {
    id: id("user"),
    email: normalizeEmail(input.email),
    name: input.name?.trim() || undefined,
    passwordHash: input.passwordHash,
    createdAt: now(),
  };
  db.users.set(user.id, user);
  return user;
}

// ─────────────────────────────────────────────────────────────
// Ownership helpers
// ─────────────────────────────────────────────────────────────

function assertProjectOwner(projectId: string, ownerId: string): Project {
  const p = db.projects.get(projectId);
  if (!p) throw new NotFoundError();
  if (p.ownerId !== ownerId) throw new NotAuthorizedError();
  return p;
}

function assertScanOwner(scanId: string, ownerId: string): Scan {
  const s = db.scans.get(scanId);
  if (!s) throw new NotFoundError();
  assertProjectOwner(s.projectId, ownerId); // walks up to project ownership
  return s;
}

function assertFindingOwner(findingId: string, ownerId: string): SecurityFinding {
  const f = db.findings.get(findingId);
  if (!f) throw new NotFoundError();
  assertScanOwner(f.scanId, ownerId);
  return f;
}

// ─────────────────────────────────────────────────────────────
// Projects
// ─────────────────────────────────────────────────────────────

export function listProjects(ownerId: string): Project[] {
  return [...db.projects.values()]
    .filter((p) => p.ownerId === ownerId)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export function getProject(projectId: string, ownerId: string): Project {
  return assertProjectOwner(projectId, ownerId);
}

export function createProject(
  ownerId: string,
  input: {
    name: string;
    repositoryUrl?: string;
    deploymentUrl?: string;
    sourceCode?: string;
  }
): Project {
  const p: Project = {
    id: id("proj"),
    ownerId,
    name: input.name.trim(),
    repositoryUrl: input.repositoryUrl?.trim() || undefined,
    deploymentUrl: input.deploymentUrl?.trim() || undefined,
    sourceCode: input.sourceCode?.trim() || undefined,
    currentCommit: "b72c42d",
    createdAt: now(),
  };
  db.projects.set(p.id, p);
  return p;
}

// ─────────────────────────────────────────────────────────────
// Scans
// ─────────────────────────────────────────────────────────────

export function listScans(projectId: string, ownerId: string): Scan[] {
  assertProjectOwner(projectId, ownerId);
  return [...db.scans.values()]
    .filter((s) => s.projectId === projectId)
    .sort((a, b) => b.startedAt.localeCompare(a.startedAt));
}

export function getScan(scanId: string, ownerId: string): Scan {
  return assertScanOwner(scanId, ownerId);
}

export function getFinding(findingId: string, ownerId: string): SecurityFinding {
  return assertFindingOwner(findingId, ownerId);
}

export function getFindingsForScan(
  scanId: string,
  ownerId: string
): SecurityFinding[] {
  const scan = assertScanOwner(scanId, ownerId);
  return scan.findingIds
    .map((fid) => db.findings.get(fid))
    .filter((f): f is SecurityFinding => Boolean(f));
}

/** Run a full scan for a project (ownership enforced). */
export async function runScan(projectId: string, ownerId: string): Promise<Scan> {
  const project = assertProjectOwner(projectId, ownerId);
  const commit = project.currentCommit ?? "b72c42d";

  const context = buildDemoContext(project.id, {
    name: project.name,
    repositoryUrl: project.repositoryUrl,
    deploymentUrl: project.deploymentUrl,
    commitSha: commit,
    userSource: project.sourceCode,
  });

  const { findings, scope, plan } = await orchestrator.run(context);

  const scan: Scan = {
    id: id("scan"),
    projectId: project.id,
    status: "completed",
    commitSha: commit,
    startedAt: now(),
    completedAt: now(),
    findingIds: [],
    scope,
    plan,
  };

  for (const f of findings) {
    f.scanId = scan.id;
    db.findings.set(f.id, f);
    scan.findingIds.push(f.id);
  }
  db.scans.set(scan.id, scan);

  // reset any prior applied-fix state for a fresh scan
  db.handlerFixed.set(project.id, false);

  // update project scan metadata
  project.lastScannedCommit = commit;
  project.lastScanDate = scan.completedAt;
  db.projects.set(project.id, project);

  return scan;
}

/** The scan pipeline plan for the progress UI. */
export async function scanPlan(projectId: string, ownerId: string) {
  const project = assertProjectOwner(projectId, ownerId);
  const context = buildDemoContext(project.id, {
    name: project.name,
    repositoryUrl: project.repositoryUrl,
    deploymentUrl: project.deploymentUrl,
    commitSha: project.currentCommit,
    userSource: project.sourceCode,
  });
  return orchestrator.plan(context);
}

// ─────────────────────────────────────────────────────────────
// Fixes & verification
// ─────────────────────────────────────────────────────────────

export async function generateFixForFinding(
  findingId: string,
  ownerId: string
): Promise<FixAttempt> {
  const finding = assertFindingOwner(findingId, ownerId);
  const fix = await generateFixSmart(finding);
  db.fixes.set(fix.id, fix);
  return fix;
}

export function getFixForFinding(
  findingId: string,
  ownerId: string
): FixAttempt | undefined {
  assertFindingOwner(findingId, ownerId);
  return [...db.fixes.values()]
    .filter((f) => f.findingId === findingId)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0];
}

/** Apply a fix: marks the finding "fixing" -> "fixed". Does NOT resolve it. */
export function applyFix(findingId: string, ownerId: string): SecurityFinding {
  const finding = assertFindingOwner(findingId, ownerId);
  const fix = getFixForFinding(findingId, ownerId);
  if (fix) {
    fix.applied = true;
    db.fixes.set(fix.id, fix);
  }
  const scan = db.scans.get(finding.scanId)!;
  // For the IDOR finding, mark the demo handler as fixed so verify() sees it.
  if ((finding.verificationKey ?? "").startsWith("idor:")) {
    db.handlerFixed.set(scan.projectId, true);
  }
  finding.status = "fixed";
  finding.testStatus = toTestStatus(finding.status);
  finding.updatedAt = now();
  db.findings.set(finding.id, finding);
  return finding;
}

/**
 * Run verification (security re-test + regression). Updates finding status to
 * resolved / verification_failed / regression_failed based on deterministic
 * test results only.
 */
export async function verifyFinding(
  findingId: string,
  ownerId: string
): Promise<{ finding: SecurityFinding; result?: VerificationResult }> {
  const finding = assertFindingOwner(findingId, ownerId);
  const scanner = orchestrator.scannerForFinding(finding);

  if (!scanner?.verify) {
    // Non-verifiable finding types: keep them at "fixed" and be honest.
    return { finding };
  }

  const scan = db.scans.get(finding.scanId)!;
  const project = db.projects.get(scan.projectId)!;
  const context = buildDemoContext(project.id, {
    name: project.name,
    repositoryUrl: project.repositoryUrl,
    deploymentUrl: project.deploymentUrl,
    commitSha: project.currentCommit,
    fixedHandler: db.handlerFixed.get(project.id) ?? false,
  });

  const result = await scanner.verify(finding, context);
  db.verifications.set(finding.id, result);

  if (result.security.outcome === "fail") {
    finding.status = "verification_failed";
  } else if (result.regression.outcome === "fail") {
    finding.status = "regression_failed";
  } else {
    finding.status = "resolved";
  }
  finding.testStatus = toTestStatus(finding.status);
  finding.updatedAt = now();
  db.findings.set(finding.id, finding);

  return { finding, result };
}

export function getVerification(
  findingId: string,
  ownerId: string
): VerificationResult | undefined {
  assertFindingOwner(findingId, ownerId);
  return db.verifications.get(findingId);
}
