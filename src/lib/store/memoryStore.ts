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
import { generateScanReport } from "@/lib/reporting/reportGenerator";
import { generateFixSmart } from "@/lib/remediation/fixGenerator";
import { NotAuthorizedError, NotFoundError, EmailInUseError } from "./errors";
import type { StoreBackend } from "./backend";

/**
 * In-memory backend. Fast, dependency-free, and used for local dev / the demo.
 *
 * WARNING: state lives in this process only. On Vercel each serverless
 * invocation may run in a different process, so data written by one request is
 * NOT visible to another. Use DATA_STORE=supabase in any deployed environment.
 * This backend persists across dev hot reloads via globalThis.
 */

export const DEMO_USER: User = { id: "demo-user", email: "you@example.com" };

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

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export class MemoryStore implements StoreBackend {
  private db: Db;
  private orchestrator = new SecurityOrchestrator();

  constructor() {
    // Persist across hot reloads in dev via globalThis.
    const g = globalThis as unknown as { __vsa_db?: Db };
    this.db = g.__vsa_db ?? freshDb();
    g.__vsa_db = this.db;
    this.ensureSeed();
  }

  private ensureSeed() {
    const db = this.db;
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

  // ── Ownership helpers ──
  private assertProjectOwner(projectId: string, ownerId: string): Project {
    const p = this.db.projects.get(projectId);
    if (!p) throw new NotFoundError();
    if (p.ownerId !== ownerId) throw new NotAuthorizedError();
    return p;
  }

  private assertScanOwner(scanId: string, ownerId: string): Scan {
    const s = this.db.scans.get(scanId);
    if (!s) throw new NotFoundError();
    this.assertProjectOwner(s.projectId, ownerId);
    return s;
  }

  private assertFindingOwner(
    findingId: string,
    ownerId: string
  ): SecurityFinding {
    const f = this.db.findings.get(findingId);
    if (!f) throw new NotFoundError();
    this.assertScanOwner(f.scanId, ownerId);
    return f;
  }

  // ── Users ──
  async findUserByEmail(email: string): Promise<User | undefined> {
    const key = normalizeEmail(email);
    return [...this.db.users.values()].find(
      (u) => u.email.toLowerCase() === key
    );
  }

  async getUserById(userId: string): Promise<User | undefined> {
    return this.db.users.get(userId);
  }

  async createUser(input: {
    email: string;
    passwordHash: string;
    name?: string;
  }): Promise<User> {
    if (await this.findUserByEmail(input.email)) throw new EmailInUseError();
    const user: User = {
      id: id("user"),
      email: normalizeEmail(input.email),
      name: input.name?.trim() || undefined,
      passwordHash: input.passwordHash,
      createdAt: now(),
    };
    this.db.users.set(user.id, user);
    return user;
  }

  // ── Projects ──
  async listProjects(ownerId: string): Promise<Project[]> {
    return [...this.db.projects.values()]
      .filter((p) => p.ownerId === ownerId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async getProject(projectId: string, ownerId: string): Promise<Project> {
    return this.assertProjectOwner(projectId, ownerId);
  }

  async createProject(
    ownerId: string,
    input: {
      name: string;
      repositoryUrl?: string;
      deploymentUrl?: string;
      sourceCode?: string;
    }
  ): Promise<Project> {
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
    this.db.projects.set(p.id, p);
    return p;
  }

  // ── Scans ──
  async listScans(projectId: string, ownerId: string): Promise<Scan[]> {
    this.assertProjectOwner(projectId, ownerId);
    return [...this.db.scans.values()]
      .filter((s) => s.projectId === projectId)
      .sort((a, b) => b.startedAt.localeCompare(a.startedAt));
  }

  async getScan(scanId: string, ownerId: string): Promise<Scan> {
    return this.assertScanOwner(scanId, ownerId);
  }

  async getFinding(
    findingId: string,
    ownerId: string
  ): Promise<SecurityFinding> {
    return this.assertFindingOwner(findingId, ownerId);
  }

  async getFindingsForScan(
    scanId: string,
    ownerId: string
  ): Promise<SecurityFinding[]> {
    const scan = this.assertScanOwner(scanId, ownerId);
    return scan.findingIds
      .map((fid) => this.db.findings.get(fid))
      .filter((f): f is SecurityFinding => Boolean(f));
  }

  async runScan(projectId: string, ownerId: string): Promise<Scan> {
    const project = this.assertProjectOwner(projectId, ownerId);
    const commit = project.currentCommit ?? "b72c42d";

    const context = buildDemoContext(project.id, {
      name: project.name,
      repositoryUrl: project.repositoryUrl,
      deploymentUrl: project.deploymentUrl,
      commitSha: commit,
      userSource: project.sourceCode,
    });

    const { findings, scope, plan } = await this.orchestrator.run(context);

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
      this.db.findings.set(f.id, f);
      scan.findingIds.push(f.id);
    }

    try {
      scan.report = await generateScanReport(findings, scope);
    } catch {
      // 보고서 생성 실패가 스캔 자체를 실패시키지는 않는다.
    }

    this.db.scans.set(scan.id, scan);
    this.db.handlerFixed.set(project.id, false);

    project.lastScannedCommit = commit;
    project.lastScanDate = scan.completedAt;
    this.db.projects.set(project.id, project);

    return scan;
  }

  async scanPlan(projectId: string, ownerId: string): Promise<unknown> {
    const project = this.assertProjectOwner(projectId, ownerId);
    const context = buildDemoContext(project.id, {
      name: project.name,
      repositoryUrl: project.repositoryUrl,
      deploymentUrl: project.deploymentUrl,
      commitSha: project.currentCommit,
      userSource: project.sourceCode,
    });
    return this.orchestrator.plan(context);
  }

  // ── Fixes & verification ──
  async generateFixForFinding(
    findingId: string,
    ownerId: string
  ): Promise<FixAttempt> {
    const finding = this.assertFindingOwner(findingId, ownerId);
    const fix = await generateFixSmart(finding);
    this.db.fixes.set(fix.id, fix);
    return fix;
  }

  async getFixForFinding(
    findingId: string,
    ownerId: string
  ): Promise<FixAttempt | undefined> {
    this.assertFindingOwner(findingId, ownerId);
    return [...this.db.fixes.values()]
      .filter((f) => f.findingId === findingId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0];
  }

  async applyFix(
    findingId: string,
    ownerId: string
  ): Promise<SecurityFinding> {
    const finding = this.assertFindingOwner(findingId, ownerId);
    const fix = await this.getFixForFinding(findingId, ownerId);
    if (fix) {
      fix.applied = true;
      this.db.fixes.set(fix.id, fix);
    }
    const scan = this.db.scans.get(finding.scanId)!;
    if ((finding.verificationKey ?? "").startsWith("idor:")) {
      this.db.handlerFixed.set(scan.projectId, true);
    }
    finding.status = "fixed";
    finding.testStatus = toTestStatus(finding.status);
    finding.updatedAt = now();
    this.db.findings.set(finding.id, finding);
    return finding;
  }

  async verifyFinding(
    findingId: string,
    ownerId: string
  ): Promise<{ finding: SecurityFinding; result?: VerificationResult }> {
    const finding = this.assertFindingOwner(findingId, ownerId);
    const scanner = this.orchestrator.scannerForFinding(finding);

    if (!scanner?.verify) {
      return { finding };
    }

    const scan = this.db.scans.get(finding.scanId)!;
    const project = this.db.projects.get(scan.projectId)!;
    const context = buildDemoContext(project.id, {
      name: project.name,
      repositoryUrl: project.repositoryUrl,
      deploymentUrl: project.deploymentUrl,
      commitSha: project.currentCommit,
      fixedHandler: this.db.handlerFixed.get(project.id) ?? false,
    });

    const result = await scanner.verify(finding, context);
    this.db.verifications.set(finding.id, result);

    if (result.security.outcome === "fail") {
      finding.status = "verification_failed";
    } else if (result.regression.outcome === "fail") {
      finding.status = "regression_failed";
    } else {
      finding.status = "resolved";
    }
    finding.testStatus = toTestStatus(finding.status);
    finding.updatedAt = now();
    this.db.findings.set(finding.id, finding);

    return { finding, result };
  }

  async getVerification(
    findingId: string,
    ownerId: string
  ): Promise<VerificationResult | undefined> {
    this.assertFindingOwner(findingId, ownerId);
    return this.db.verifications.get(findingId);
  }
}
