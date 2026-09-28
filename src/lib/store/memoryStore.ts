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
import { Buffer } from "buffer";
import { toTestStatus } from "@/lib/domain/types";
import { id, now } from "@/lib/util";
import { contextForProject } from "@/lib/scanners/contextFor";
import { SecurityOrchestrator } from "@/lib/scanners/orchestrator";
import { generateScanReport } from "@/lib/reporting/reportGenerator";
import { generateFixSmart } from "@/lib/remediation/fixGenerator";
import {
  buildFixArtifact,
  buildFixedFileMap,
} from "@/lib/remediation/artifactBuilder";
import { serializeFileMap } from "@/lib/demo/sourceFiles";
import { makeSourceVersion } from "@/lib/source/sourceVersion";
import {
  NotAuthorizedError,
  NotFoundError,
  EmailInUseError,
  VerificationUnavailableError,
} from "./errors";
import {
  assertHasSourceFiles,
  legacyFilesFromProject,
  SourceMissingError,
} from "./sourceHelpers";
import type { CreateProjectInput, StoreBackend } from "./backend";

/**
 * In-memory backend. Fast, dependency-free, and used for local dev / tests.
 *
 * WARNING: state lives in this process only. On Vercel each serverless
 * invocation may run in a different process, so data written by one request is
 * NOT visible to another. Use DATA_STORE=supabase in any deployed environment.
 * This backend persists across dev hot reloads via globalThis.
 *
 * There is no seeded demo user or demo project: every project belongs to a
 * real logged-in user. The public demo uses a built-in fixture that is never
 * stored here.
 */

interface Db {
  users: Map<string, User>;
  projects: Map<string, Project>;
  scans: Map<string, Scan>;
  findings: Map<string, SecurityFinding>;
  fixes: Map<string, FixAttempt>;
  verifications: Map<string, VerificationResult>;
  /** Whether the IDOR handler for a project has an applied fix (demo only). */
  handlerFixed: Map<string, boolean>;
  /** Legacy per-finding artifact metadata by artifact id. */
  artifacts: Map<string, FixArtifact>;
  /** Legacy per-finding artifact ZIP bytes (base64) by artifact id. */
  artifactBytes: Map<string, string>;
  /** Immutable source versions by id. */
  sourceVersions: Map<string, SourceVersion>;
  /** Fix-all jobs by id. */
  fixJobs: Map<string, FixJob>;
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
    artifacts: new Map(),
    artifactBytes: new Map(),
    sourceVersions: new Map(),
    fixJobs: new Map(),
  };
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/** Callers get copies so they can never mutate stored state by accident. */
function clone<T>(v: T): T {
  return structuredClone(v);
}

export class MemoryStore implements StoreBackend {
  private db: Db;
  private orchestrator = new SecurityOrchestrator();

  constructor() {
    // Persist across hot reloads in dev via globalThis.
    const g = globalThis as unknown as { __vsa_db?: Db };
    const existing = g.__vsa_db;
    // Older dev sessions may hold a Db without the newer maps.
    this.db = existing ? { ...freshDb(), ...existing } : freshDb();
    g.__vsa_db = this.db;
  }

  /** Test helper: wipe all in-memory state. */
  reset(): void {
    const fresh = freshDb();
    Object.assign(this.db, fresh);
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
    input: CreateProjectInput
  ): Promise<Project> {
    assertHasSourceFiles(input.files);
    const projectId = id("proj");
    const version = makeSourceVersion({
      projectId,
      ownerId,
      kind: "original",
      files: input.files,
    });
    const p: Project = {
      id: projectId,
      ownerId,
      name: input.name.trim(),
      repositoryUrl: input.repositoryUrl?.trim() || undefined,
      deploymentUrl: input.deploymentUrl?.trim() || undefined,
      // Legacy single-finding flow still reads this blob.
      sourceCode: serializeFileMap(version.files),
      sourceZipName: input.sourceKind === "zip" ? input.sourceZipName : undefined,
      deploymentAuthorized: input.deploymentAuthorized ?? false,
      scanMode: input.scanMode,
      testAccounts: input.testAccounts?.length ? input.testAccounts : undefined,
      isDemo: false,
      currentSourceVersionId: version.id,
      createdAt: now(),
    };
    this.db.sourceVersions.set(version.id, version);
    this.db.projects.set(p.id, p);
    return p;
  }

  // ── Source versions ──
  async getSourceVersion(versionId: string, ownerId: string): Promise<SourceVersion> {
    const v = this.db.sourceVersions.get(versionId);
    if (!v) throw new NotFoundError();
    if (v.ownerId !== ownerId) throw new NotAuthorizedError();
    this.assertProjectOwner(v.projectId, ownerId);
    return clone(v);
  }

  async saveSourceVersion(version: SourceVersion): Promise<void> {
    this.assertProjectOwner(version.projectId, version.ownerId);
    if (this.db.sourceVersions.has(version.id)) {
      throw new Error("source versions are immutable");
    }
    this.db.sourceVersions.set(version.id, clone(version));
  }

  async getCurrentSourceVersion(
    projectId: string,
    ownerId: string
  ): Promise<SourceVersion | undefined> {
    const project = this.assertProjectOwner(projectId, ownerId);
    if (project.isDemo) return undefined;
    if (project.currentSourceVersionId) {
      return this.getSourceVersion(project.currentSourceVersionId, ownerId);
    }
    // Legacy project: create the original version from the stored blob once.
    const files = legacyFilesFromProject(project);
    if (!files) return undefined;
    const version = makeSourceVersion({ projectId, ownerId, kind: "original", files });
    this.db.sourceVersions.set(version.id, version);
    project.currentSourceVersionId = version.id;
    this.db.projects.set(project.id, project);
    return clone(version);
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
    const version = await this.getCurrentSourceVersion(projectId, ownerId);
    if (!project.isDemo && !version) throw new SourceMissingError();

    const startedAt = now();
    const context = contextForProject(project, { files: version?.files });
    const { findings, scope, plan } = await this.orchestrator.run(context);

    const scan: Scan = {
      id: id("scan"),
      projectId: project.id,
      status: "completed",
      sourceVersionId: version?.id,
      sourceContentHash: version?.contentHash,
      commitSha: project.currentCommit || undefined,
      startedAt,
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

    project.lastScannedCommit = project.currentCommit || undefined;
    project.lastScanDate = scan.completedAt;
    this.db.projects.set(project.id, project);

    return scan;
  }

  async scanPlan(projectId: string, ownerId: string): Promise<unknown> {
    const project = this.assertProjectOwner(projectId, ownerId);
    const version = await this.getCurrentSourceVersion(projectId, ownerId);
    const context = contextForProject(project, { files: version?.files });
    return this.orchestrator.plan(context);
  }

  // ── Fix-all jobs ──
  async insertFixJob(job: FixJob): Promise<{ job: FixJob; created: boolean }> {
    const existing = await this.findFixJobByKey(job.ownerId, job.idempotencyKey);
    if (existing) return { job: existing, created: false };
    const scan = this.assertScanOwner(job.scanId, job.ownerId);
    if (scan.projectId !== job.projectId) throw new NotAuthorizedError();
    this.db.fixJobs.set(job.id, clone(job));
    return { job: clone(job), created: true };
  }

  async updateFixJob(job: FixJob): Promise<void> {
    const stored = this.db.fixJobs.get(job.id);
    if (!stored) throw new NotFoundError();
    if (stored.ownerId !== job.ownerId) throw new NotAuthorizedError();
    this.db.fixJobs.set(job.id, clone(job));
  }

  async getFixJob(jobId: string, ownerId: string): Promise<FixJob> {
    const job = this.db.fixJobs.get(jobId);
    if (!job) throw new NotFoundError();
    if (job.ownerId !== ownerId) throw new NotAuthorizedError();
    return clone(job);
  }

  async findFixJobByKey(
    ownerId: string,
    idempotencyKey: string
  ): Promise<FixJob | undefined> {
    const job = [...this.db.fixJobs.values()].find(
      (j) => j.ownerId === ownerId && j.idempotencyKey === idempotencyKey
    );
    return job ? clone(job) : undefined;
  }

  async listFixJobsForScan(scanId: string, ownerId: string): Promise<FixJob[]> {
    this.assertScanOwner(scanId, ownerId);
    return [...this.db.fixJobs.values()]
      .filter((j) => j.scanId === scanId && j.ownerId === ownerId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map(clone);
  }

  // ── Fixes & verification (legacy single-item flow) ──
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
  ): Promise<{ finding: SecurityFinding; result: VerificationResult }> {
    const finding = this.assertFindingOwner(findingId, ownerId);
    const scanner = this.orchestrator.scannerForFinding(finding);

    if (!scanner?.verify) {
      throw new VerificationUnavailableError();
    }

    const scan = this.db.scans.get(finding.scanId)!;
    const project = this.db.projects.get(scan.projectId)!;

    // Re-verify against the FIXED copy, not the original. Apply this finding's
    // generated fixes to a copy of the original source and hand that file map
    // to the scanner. For the demo project (no user source), fall back to the
    // handlerFixed flag the demo scanner understands.
    const fixes = [...this.db.fixes.values()].filter(
      (f) => f.findingId === findingId
    );
    let fixedFiles: Record<string, string> | undefined;
    if (!project.isDemo && project.sourceCode && fixes.length > 0) {
      fixedFiles = buildFixedFileMap(project.sourceCode, fixes).copy;
    }
    const context = contextForProject(project, {
      fixedHandler: this.db.handlerFixed.get(project.id) ?? false,
      files: fixedFiles,
    });

    const result = await scanner.verify(finding, context);
    this.db.verifications.set(finding.id, result);

    if (result.security.outcome === "fail") {
      finding.status = "verification_failed";
    } else if (result.regression.outcome === "fail") {
      finding.status = "regression_failed";
    } else if (result.resolved) {
      finding.status = "resolved";
    } else {
      // A scanner may produce useful source/config evidence that is not strong
      // enough for final resolution (for example AI review or secret rotation).
      finding.status = "fixed";
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

  // ── Legacy per-finding artifacts ──
  async buildFixArtifact(
    findingId: string,
    ownerId: string
  ): Promise<FixArtifact> {
    const finding = this.assertFindingOwner(findingId, ownerId);
    const scan = this.db.scans.get(finding.scanId)!;
    const project = this.db.projects.get(scan.projectId)!;

    // Gather applied (or at least generated) fixes for this finding.
    const fixes = [...this.db.fixes.values()]
      .filter((f) => f.findingId === findingId)
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    if (fixes.length === 0) {
      throw new NotFoundError();
    }

    // Version = existing artifacts for this finding + 1.
    const existing = [...this.db.artifacts.values()].filter(
      (a) => a.findingId === findingId
    );
    const version = existing.length + 1;

    const built = buildFixArtifact(
      project.sourceCode,
      fixes,
      project.name,
      version
    );

    const safeName =
      project.name.replace(/[^a-zA-Z0-9_-]+/g, "-").replace(/^-+|-+$/g, "") ||
      "project";
    const artifact: FixArtifact = {
      id: id("artifact"),
      findingId,
      projectId: project.id,
      ownerId,
      appliedFixIds: fixes.map((f) => f.id),
      files: built.files,
      fileName: `${safeName}-fixed-v${version}.zip`,
      size: built.size,
      sha256: built.sha256,
      version,
      createdAt: now(),
    };

    this.db.artifacts.set(artifact.id, artifact);
    this.db.artifactBytes.set(artifact.id, built.zip.toString("base64"));
    return artifact;
  }

  async getFixArtifact(
    artifactId: string,
    ownerId: string
  ): Promise<FixArtifact | undefined> {
    const a = this.db.artifacts.get(artifactId);
    if (!a) return undefined;
    if (a.ownerId !== ownerId) throw new NotAuthorizedError();
    return a;
  }

  async getFixArtifactBytes(
    artifactId: string,
    ownerId: string
  ): Promise<Buffer | undefined> {
    const a = this.db.artifacts.get(artifactId);
    if (!a) return undefined;
    if (a.ownerId !== ownerId) throw new NotAuthorizedError();
    const b64 = this.db.artifactBytes.get(artifactId);
    if (b64 === undefined) return undefined;
    return Buffer.from(b64, "base64");
  }

  async listFixArtifacts(
    findingId: string,
    ownerId: string
  ): Promise<FixArtifact[]> {
    this.assertFindingOwner(findingId, ownerId);
    return [...this.db.artifacts.values()]
      .filter((a) => a.findingId === findingId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }
}
