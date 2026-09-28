import type {
  CustomRule,
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
import { parseScanMode, type TestAccount } from "@/lib/domain/scanMode";
import { toTestStatus } from "@/lib/domain/types";
import { id, now } from "@/lib/util";
import { Buffer } from "buffer";
import { contextForProject } from "@/lib/scanners/contextFor";
import { runScanPipeline } from "@/lib/scan/scanPipeline";
import { SecurityOrchestrator } from "@/lib/scanners/orchestrator";
import { generateScanReport } from "@/lib/reporting/reportGenerator";
import { generateFixSmart } from "@/lib/remediation/fixGenerator";
import { buildFixArtifact } from "@/lib/remediation/artifactBuilder";
import { serializeFileMap } from "@/lib/demo/sourceFiles";
import { makeSourceVersion } from "@/lib/source/sourceVersion";
import {
  NotAuthorizedError,
  NotFoundError,
  EmailInUseError,
  VerificationUnavailableError,
  SchemaMigrationRequiredError,
} from "./errors";
import {
  assertHasSourceFiles,
  legacyFilesFromProject,
  SourceMissingError,
} from "./sourceHelpers";
import type { CreateProjectInput, StoreBackend } from "./backend";
import {
  selectRows,
  selectOne,
  insertRows,
  upsertRows,
  updateRows,
  deleteRows,
  isSchemaError,
  isUniqueViolation,
} from "./supabaseClient";

/**
 * Supabase-backed store. Same interface + same ownership semantics as the
 * in-memory backend, but every project / scan / finding / source version /
 * fix job is persisted to Postgres so state is shared across all Vercel
 * serverless invocations.
 *
 * Ownership is enforced here (the app's IDOR defense); the DB has RLS enabled
 * deny-by-default as a second line of defense (the server uses the service
 * role key which bypasses RLS).
 *
 * Missing tables/columns raise SchemaMigrationRequiredError (HTTP 503). We no
 * longer retry without the new columns, because that made unsaved data look
 * saved.
 */

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

const q = encodeURIComponent;

/** Run a DB call; a missing table/column becomes SchemaMigrationRequiredError. */
async function guarded<T>(what: string, fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    if (isSchemaError(e)) throw new SchemaMigrationRequiredError(what);
    throw e;
  }
}

// ── Row shapes (snake_case as stored) ──
interface UserRow {
  id: string;
  email: string;
  name: string | null;
  password_hash: string | null;
  created_at: string;
}
interface ProjectRow {
  id: string;
  owner_id: string;
  name: string;
  repository_url: string | null;
  deployment_url: string | null;
  source_code: string | null;
  source_zip_name: string | null;
  last_scanned_commit: string | null;
  current_commit: string | null;
  last_scan_date: string | null;
  handler_fixed: boolean;
  is_demo?: boolean | null;
  deployment_authorized?: boolean | null;
  scan_mode?: string | null;
  test_accounts?: TestAccount[] | null;
  current_source_version_id?: string | null;
  created_at: string;
}
interface ScanRow {
  id: string;
  project_id: string;
  status: Scan["status"];
  commit_sha: string | null;
  source_version_id?: string | null;
  source_content_hash?: string | null;
  started_at: string;
  completed_at: string | null;
  finding_ids: string[];
  scope: Scan["scope"];
  plan: Scan["plan"] | null;
  report: Scan["report"] | null;
}
interface FindingRow {
  id: string;
  scan_id: string;
  severity: string;
  status: string;
  data: SecurityFinding;
  created_at: string;
  updated_at: string;
}
interface FixRow {
  id: string;
  finding_id: string;
  applied: boolean;
  data: FixAttempt;
  created_at: string;
}
interface VerificationRow {
  finding_id: string;
  data: VerificationResult;
  created_at: string;
}
interface FixArtifactRow {
  id: string;
  finding_id: string;
  project_id: string;
  owner_id: string;
  data: FixArtifact;
  zip_base64: string | null;
  created_at: string;
}
interface SourceVersionRow {
  id: string;
  project_id: string;
  owner_id: string;
  kind: SourceVersion["kind"];
  parent_version_id: string | null;
  fix_job_id: string | null;
  files: Record<string, string>;
  file_count: number;
  total_bytes: number;
  content_hash: string;
  created_at: string;
}
interface FixJobRow {
  id: string;
  project_id: string;
  owner_id: string;
  scan_id: string;
  idempotency_key: string;
  status: FixJob["status"];
  data: FixJob;
  created_at: string;
  updated_at: string;
}

// ── Row ↔ domain mappers ──
function toUser(r: UserRow): User {
  return {
    id: r.id,
    email: r.email,
    name: r.name ?? undefined,
    passwordHash: r.password_hash ?? undefined,
    createdAt: r.created_at,
  };
}
function toProject(r: ProjectRow): Project {
  return {
    id: r.id,
    ownerId: r.owner_id,
    name: r.name,
    repositoryUrl: r.repository_url ?? undefined,
    deploymentUrl: r.deployment_url ?? undefined,
    sourceCode: r.source_code ?? undefined,
    sourceZipName: r.source_zip_name ?? undefined,
    lastScannedCommit: r.last_scanned_commit ?? undefined,
    currentCommit: r.current_commit ?? undefined,
    lastScanDate: r.last_scan_date ?? undefined,
    isDemo: r.is_demo ?? undefined,
    deploymentAuthorized: r.deployment_authorized ?? undefined,
    scanMode: parseScanMode(r.scan_mode) ?? undefined,
    testAccounts: r.test_accounts ?? undefined,
    currentSourceVersionId: r.current_source_version_id ?? undefined,
    createdAt: r.created_at,
  };
}
function toScan(r: ScanRow): Scan {
  return {
    id: r.id,
    projectId: r.project_id,
    status: r.status,
    commitSha: r.commit_sha ?? undefined,
    sourceVersionId: r.source_version_id ?? undefined,
    sourceContentHash: r.source_content_hash ?? undefined,
    startedAt: r.started_at,
    completedAt: r.completed_at ?? undefined,
    findingIds: r.finding_ids ?? [],
    scope: r.scope,
    plan: r.plan ?? undefined,
    report: r.report ?? undefined,
  };
}
function toSourceVersion(r: SourceVersionRow): SourceVersion {
  return {
    id: r.id,
    projectId: r.project_id,
    ownerId: r.owner_id,
    kind: r.kind,
    parentVersionId: r.parent_version_id ?? undefined,
    fixJobId: r.fix_job_id ?? undefined,
    files: r.files ?? {},
    fileCount: r.file_count,
    totalBytes: r.total_bytes,
    contentHash: r.content_hash,
    createdAt: r.created_at,
  };
}
function fromSourceVersion(v: SourceVersion): SourceVersionRow {
  return {
    id: v.id,
    project_id: v.projectId,
    owner_id: v.ownerId,
    kind: v.kind,
    parent_version_id: v.parentVersionId ?? null,
    fix_job_id: v.fixJobId ?? null,
    files: v.files,
    file_count: v.fileCount,
    total_bytes: v.totalBytes,
    content_hash: v.contentHash,
    created_at: v.createdAt,
  };
}
function fromFixJob(j: FixJob): FixJobRow {
  return {
    id: j.id,
    project_id: j.projectId,
    owner_id: j.ownerId,
    scan_id: j.scanId,
    idempotency_key: j.idempotencyKey,
    status: j.status,
    data: j,
    created_at: j.createdAt,
    updated_at: j.updatedAt,
  };
}

export class SupabaseStore implements StoreBackend {
  private orchestrator = new SecurityOrchestrator();

  // ── Ownership helpers ──
  private async requireProject(
    projectId: string,
    ownerId: string
  ): Promise<Project> {
    const row = await selectOne<ProjectRow>(
      "projects",
      `id=eq.${q(projectId)}&select=*`
    );
    if (!row) throw new NotFoundError();
    if (row.owner_id !== ownerId) throw new NotAuthorizedError();
    return toProject(row);
  }

  private async requireScan(scanId: string, ownerId: string): Promise<Scan> {
    const row = await selectOne<ScanRow>(
      "scans",
      `id=eq.${q(scanId)}&select=*`
    );
    if (!row) throw new NotFoundError();
    await this.requireProject(row.project_id, ownerId); // walks up
    return toScan(row);
  }

  private async requireFinding(
    findingId: string,
    ownerId: string
  ): Promise<SecurityFinding> {
    const row = await selectOne<FindingRow>(
      "findings",
      `id=eq.${q(findingId)}&select=*`
    );
    if (!row) throw new NotFoundError();
    await this.requireScan(row.scan_id, ownerId);
    return row.data;
  }

  private async handlerFixed(projectId: string): Promise<boolean> {
    const row = await selectOne<{ handler_fixed: boolean }>(
      "projects",
      `id=eq.${q(projectId)}&select=handler_fixed`
    );
    return row?.handler_fixed ?? false;
  }

  // ── Users ──
  async findUserByEmail(email: string): Promise<User | undefined> {
    const row = await selectOne<UserRow>(
      "app_users",
      `email=eq.${q(normalizeEmail(email))}&select=*`
    );
    return row ? toUser(row) : undefined;
  }

  async getUserById(userId: string): Promise<User | undefined> {
    const row = await selectOne<UserRow>(
      "app_users",
      `id=eq.${q(userId)}&select=*`
    );
    return row ? toUser(row) : undefined;
  }

  async createUser(input: {
    email: string;
    passwordHash: string;
    name?: string;
  }): Promise<User> {
    if (await this.findUserByEmail(input.email)) throw new EmailInUseError();
    const row: UserRow = {
      id: id("user"),
      email: normalizeEmail(input.email),
      name: input.name?.trim() || null,
      password_hash: input.passwordHash,
      created_at: now(),
    };
    try {
      const [inserted] = await insertRows<UserRow>("app_users", row);
      return toUser(inserted);
    } catch (e) {
      // The email column is UNIQUE; a race between the check above and the
      // insert surfaces as a unique-violation. Map it to the same typed error
      // the memory backend throws so signupAction shows the right message.
      if (isUniqueViolation(e)) throw new EmailInUseError();
      throw e;
    }
  }

  // ── Projects ──
  async listProjects(ownerId: string): Promise<Project[]> {
    const rows = await selectRows<ProjectRow>(
      "projects",
      `owner_id=eq.${q(ownerId)}&select=*&order=created_at.desc`
    );
    return rows.map(toProject);
  }

  async getProject(projectId: string, ownerId: string): Promise<Project> {
    return this.requireProject(projectId, ownerId);
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
    const row: Partial<ProjectRow> = {
      id: projectId,
      owner_id: ownerId,
      name: input.name.trim(),
      repository_url: input.repositoryUrl?.trim() || null,
      deployment_url: input.deploymentUrl?.trim() || null,
      // Legacy single-finding flow still reads this blob.
      source_code: serializeFileMap(version.files),
      source_zip_name: input.sourceKind === "zip" ? input.sourceZipName ?? null : null,
      current_commit: null,
      handler_fixed: false,
      is_demo: false,
      deployment_authorized: input.deploymentAuthorized ?? false,
      scan_mode: input.scanMode ?? null,
      test_accounts: input.testAccounts?.length ? input.testAccounts : null,
      current_source_version_id: null,
      created_at: now(),
    };

    // No cross-table transaction over PostgREST. Insert the project, then its
    // original version, then point the project at it. If the version insert
    // fails, remove the half-created project so it never shows up code-less.
    const [inserted] = await guarded("projects", () =>
      insertRows<ProjectRow>("projects", row)
    );
    try {
      await guarded("source_versions", () =>
        insertRows("source_versions", fromSourceVersion(version))
      );
      await guarded("projects.current_source_version_id", () =>
        updateRows("projects", `id=eq.${q(projectId)}`, {
          current_source_version_id: version.id,
        })
      );
    } catch (e) {
      await deleteRows("projects", `id=eq.${q(projectId)}`).catch(() => {});
      throw e;
    }
    return toProject({ ...inserted, current_source_version_id: version.id });
  }

  // ── Source versions ──
  async getSourceVersion(versionId: string, ownerId: string): Promise<SourceVersion> {
    const row = await guarded("source_versions", () =>
      selectOne<SourceVersionRow>("source_versions", `id=eq.${q(versionId)}&select=*`)
    );
    if (!row) throw new NotFoundError();
    if (row.owner_id !== ownerId) throw new NotAuthorizedError();
    await this.requireProject(row.project_id, ownerId);
    return toSourceVersion(row);
  }

  async saveSourceVersion(version: SourceVersion): Promise<void> {
    await this.requireProject(version.projectId, version.ownerId);
    // Plain insert: a duplicate id fails (versions are immutable).
    await guarded("source_versions", () =>
      insertRows("source_versions", fromSourceVersion(version))
    );
  }

  async getCurrentSourceVersion(
    projectId: string,
    ownerId: string
  ): Promise<SourceVersion | undefined> {
    const project = await this.requireProject(projectId, ownerId);
    if (project.isDemo) return undefined;
    if (project.currentSourceVersionId) {
      return this.getSourceVersion(project.currentSourceVersionId, ownerId);
    }
    // Legacy project: create the original version from the stored blob once.
    const files = legacyFilesFromProject(project);
    if (!files) return undefined;
    const version = makeSourceVersion({ projectId, ownerId, kind: "original", files });
    await this.saveSourceVersion(version);
    await guarded("projects.current_source_version_id", () =>
      updateRows("projects", `id=eq.${q(projectId)}`, {
        current_source_version_id: version.id,
      })
    );
    return version;
  }

  // ── Scans ──
  async listScans(projectId: string, ownerId: string): Promise<Scan[]> {
    await this.requireProject(projectId, ownerId);
    const rows = await selectRows<ScanRow>(
      "scans",
      `project_id=eq.${q(projectId)}&select=*&order=started_at.desc`
    );
    return rows.map(toScan);
  }

  async getScan(scanId: string, ownerId: string): Promise<Scan> {
    return this.requireScan(scanId, ownerId);
  }

  async getFinding(
    findingId: string,
    ownerId: string
  ): Promise<SecurityFinding> {
    return this.requireFinding(findingId, ownerId);
  }

  async getFindingsForScan(
    scanId: string,
    ownerId: string
  ): Promise<SecurityFinding[]> {
    await this.requireScan(scanId, ownerId);
    const rows = await selectRows<FindingRow>(
      "findings",
      `scan_id=eq.${q(scanId)}&select=*&order=created_at.asc`
    );
    return rows.map((r) => r.data);
  }

  async runScan(projectId: string, ownerId: string): Promise<Scan> {
    const project = await this.requireProject(projectId, ownerId);
    const version = await this.getCurrentSourceVersion(projectId, ownerId);
    if (!project.isDemo && !version) throw new SourceMissingError();

    const startedAt = now();
    const { findings, scope, plan, proposals } = await runScanPipeline({
      backend: this,
      project,
      version,
      ownerId,
      orchestrator: this.orchestrator,
    });

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
      scan.findingIds.push(f.id);
    }

    try {
      scan.report = await generateScanReport(findings, scope);
    } catch {
      // 보고서 생성 실패가 스캔 자체를 실패시키지는 않는다.
    }

    // PostgREST gives us no cross-table transaction, and findings.scan_id has a
    // FK to scans.id — so findings can't be written before their scan row
    // exists. We instead make the scan row's own visibility the commit point:
    //
    //   1. insert the scan as "running" with empty finding_ids (FK target now
    //      exists for the findings insert),
    //   2. insert the findings,
    //   3. patch the scan to "completed" with the populated finding_ids.
    //
    // A concurrent reader therefore sees either no scan, a "running" scan
    // (findings still landing), or a "completed" scan whose findings are
    // guaranteed present — never a "completed" scan with missing findings.
    await guarded("scans.source_version_id", () =>
      insertRows("scans", {
        id: scan.id,
        project_id: scan.projectId,
        status: "running",
        commit_sha: scan.commitSha ?? null,
        source_version_id: scan.sourceVersionId ?? null,
        source_content_hash: scan.sourceContentHash ?? null,
        started_at: scan.startedAt,
        completed_at: null,
        finding_ids: [],
        scope: scan.scope,
        plan: scan.plan ?? null,
        report: scan.report ?? null,
      })
    );

    if (findings.length > 0) {
      await insertRows(
        "findings",
        findings.map((f) => ({
          id: f.id,
          scan_id: scan.id,
          severity: f.severity,
          status: f.status,
          data: f,
          created_at: f.createdAt,
          updated_at: f.updatedAt,
        }))
      );
    }

    await updateRows("scans", `id=eq.${q(scan.id)}`, {
      status: scan.status,
      completed_at: scan.completedAt ?? null,
      finding_ids: scan.findingIds,
    });

    // AI가 제안한 규칙은 "제안" 상태로 저장한다(사람이 승인해야 돈다).
    for (const rule of proposals) {
      rule.sourceScanId = scan.id;
      await this.saveCustomRule(rule).catch(() => {});
    }

    // reset applied-fix state + update project scan metadata
    await updateRows("projects", `id=eq.${q(project.id)}`, {
      handler_fixed: false,
      last_scanned_commit: project.currentCommit || null,
      last_scan_date: scan.completedAt,
    });

    return scan;
  }

  async scanPlan(projectId: string, ownerId: string): Promise<unknown> {
    const project = await this.requireProject(projectId, ownerId);
    const version = await this.getCurrentSourceVersion(projectId, ownerId);
    const context = contextForProject(project, { files: version?.files });
    return this.orchestrator.plan(context);
  }

  // ── AI-proposed rules ──
  async listCustomRules(ownerId: string, projectId?: string): Promise<CustomRule[]> {
    const filter = `owner_id=eq.${q(ownerId)}${projectId ? `&project_id=eq.${q(projectId)}` : ""}&select=data&order=created_at.desc`;
    const rows = await guarded("custom_rules", () => selectRows<{ data: CustomRule }>("custom_rules", filter));
    return rows.map((r) => r.data);
  }

  async getCustomRule(ruleId: string, ownerId: string): Promise<CustomRule> {
    const row = await guarded("custom_rules", () =>
      selectOne<{ owner_id: string; data: CustomRule }>("custom_rules", `id=eq.${q(ruleId)}&select=owner_id,data`)
    );
    if (!row) throw new NotFoundError();
    if (row.owner_id !== ownerId) throw new NotAuthorizedError();
    return row.data;
  }

  async saveCustomRule(rule: CustomRule): Promise<void> {
    await this.requireProject(rule.projectId, rule.ownerId);
    const existing = await guarded("custom_rules", () =>
      selectOne<{ owner_id: string }>("custom_rules", `id=eq.${q(rule.id)}&select=owner_id`)
    );
    if (existing && existing.owner_id !== rule.ownerId) throw new NotAuthorizedError();
    await guarded("custom_rules", () =>
      upsertRows("custom_rules", {
        id: rule.id,
        owner_id: rule.ownerId,
        project_id: rule.projectId,
        status: rule.status,
        data: rule,
        created_at: rule.createdAt,
        updated_at: now(),
      })
    );
  }

  // ── Re-upload ──
  async addSourceVersion(
    projectId: string,
    ownerId: string,
    files: Record<string, string>,
    meta?: { sourceKind: "zip" | "paste"; zipName?: string }
  ): Promise<SourceVersion> {
    const project = await this.requireProject(projectId, ownerId);
    assertHasSourceFiles(files);
    const version = makeSourceVersion({ projectId, ownerId, kind: "reupload", files, parentVersionId: project.currentSourceVersionId });
    await this.saveSourceVersion(version);
    await guarded("projects.current_source_version_id", () =>
      updateRows("projects", `id=eq.${q(projectId)}`, {
        current_source_version_id: version.id,
        source_code: serializeFileMap(version.files),
        source_zip_name: meta?.sourceKind === "zip" ? meta.zipName ?? null : null,
      })
    );
    return version;
  }

  // ── Fix-all jobs ──
  async insertFixJob(job: FixJob): Promise<{ job: FixJob; created: boolean }> {
    const scan = await this.requireScan(job.scanId, job.ownerId);
    if (scan.projectId !== job.projectId) throw new NotAuthorizedError();
    try {
      await guarded("fix_jobs", () => insertRows("fix_jobs", fromFixJob(job)));
      return { job, created: true };
    } catch (e) {
      // unique(owner_id, idempotency_key): someone already started this job.
      if (isUniqueViolation(e)) {
        const existing = await this.findFixJobByKey(job.ownerId, job.idempotencyKey);
        if (existing) return { job: existing, created: false };
      }
      throw e;
    }
  }

  async updateFixJob(job: FixJob): Promise<void> {
    const rows = await guarded("fix_jobs", () =>
      updateRows<FixJobRow>(
        "fix_jobs",
        `id=eq.${q(job.id)}&owner_id=eq.${q(job.ownerId)}`,
        { status: job.status, data: job, updated_at: job.updatedAt }
      )
    );
    if (!rows || rows.length === 0) throw new NotFoundError();
  }

  async getFixJob(jobId: string, ownerId: string): Promise<FixJob> {
    const row = await guarded("fix_jobs", () =>
      selectOne<FixJobRow>("fix_jobs", `id=eq.${q(jobId)}&select=*`)
    );
    if (!row) throw new NotFoundError();
    if (row.owner_id !== ownerId) throw new NotAuthorizedError();
    return row.data;
  }

  async findFixJobByKey(
    ownerId: string,
    idempotencyKey: string
  ): Promise<FixJob | undefined> {
    const row = await guarded("fix_jobs", () =>
      selectOne<FixJobRow>(
        "fix_jobs",
        `owner_id=eq.${q(ownerId)}&idempotency_key=eq.${q(idempotencyKey)}&select=*`
      )
    );
    return row?.data;
  }

  async listFixJobsForScan(scanId: string, ownerId: string): Promise<FixJob[]> {
    await this.requireScan(scanId, ownerId);
    const rows = await guarded("fix_jobs", () =>
      selectRows<FixJobRow>(
        "fix_jobs",
        `scan_id=eq.${q(scanId)}&owner_id=eq.${q(ownerId)}&select=*&order=created_at.desc`
      )
    );
    return rows.map((r) => r.data);
  }

  // ── Fixes & verification (legacy single-item flow) ──
  async generateFixForFinding(
    findingId: string,
    ownerId: string
  ): Promise<FixAttempt> {
    const finding = await this.requireFinding(findingId, ownerId);
    const fix = await generateFixSmart(finding);
    await insertRows("fix_attempts", {
      id: fix.id,
      finding_id: fix.findingId,
      applied: fix.applied,
      data: fix,
      created_at: fix.createdAt,
    });
    return fix;
  }

  async getFixForFinding(
    findingId: string,
    ownerId: string
  ): Promise<FixAttempt | undefined> {
    await this.requireFinding(findingId, ownerId);
    const rows = await selectRows<FixRow>(
      "fix_attempts",
      `finding_id=eq.${q(findingId)}&select=*&order=created_at.desc&limit=1`
    );
    return rows[0]?.data;
  }

  async applyFix(
    findingId: string,
    ownerId: string
  ): Promise<SecurityFinding> {
    const finding = await this.requireFinding(findingId, ownerId);
    const fix = await this.getFixForFinding(findingId, ownerId);
    if (fix) {
      fix.applied = true;
      await upsertRows("fix_attempts", {
        id: fix.id,
        finding_id: fix.findingId,
        applied: true,
        data: fix,
        created_at: fix.createdAt,
      });
    }

    // For the IDOR finding, mark the owning project's demo handler as fixed so
    // verify() later observes the patched behavior.
    if ((finding.verificationKey ?? "").startsWith("idor:")) {
      const scanRow = await selectOne<ScanRow>(
        "scans",
        `id=eq.${q(finding.scanId)}&select=project_id`
      );
      if (scanRow) {
        await updateRows("projects", `id=eq.${q(scanRow.project_id)}`, {
          handler_fixed: true,
        });
      }
    }

    finding.status = "fixed";
    finding.testStatus = toTestStatus(finding.status);
    finding.updatedAt = now();
    await this.persistFinding(finding);
    return finding;
  }

  async verifyFinding(
    findingId: string,
    ownerId: string
  ): Promise<{ finding: SecurityFinding; result: VerificationResult }> {
    const finding = await this.requireFinding(findingId, ownerId);
    const scanner = this.orchestrator.scannerForFinding(finding);

    if (!scanner?.verify) {
      throw new VerificationUnavailableError();
    }

    const scanRow = await selectOne<ScanRow>(
      "scans",
      `id=eq.${q(finding.scanId)}&select=project_id`
    );
    const project = await this.requireProject(scanRow!.project_id, ownerId);
    const context = contextForProject(project, {
      fixedHandler: await this.handlerFixed(project.id),
    });

    const result = await scanner.verify(finding, context);
    await upsertRows("verifications", {
      finding_id: finding.id,
      data: result,
      created_at: now(),
    });

    if (result.security.outcome === "fail") {
      finding.status = "verification_failed";
    } else if (result.regression.outcome === "fail") {
      finding.status = "regression_failed";
    } else if (result.resolved) {
      finding.status = "resolved";
    } else {
      // Preserve fixed-but-unverified when evidence is informative but not
      // sufficient for final resolution.
      finding.status = "fixed";
    }
    finding.testStatus = toTestStatus(finding.status);
    finding.updatedAt = now();
    await this.persistFinding(finding);

    return { finding, result };
  }

  async getVerification(
    findingId: string,
    ownerId: string
  ): Promise<VerificationResult | undefined> {
    await this.requireFinding(findingId, ownerId);
    const row = await selectOne<VerificationRow>(
      "verifications",
      `finding_id=eq.${q(findingId)}&select=*`
    );
    return row?.data;
  }

  // ── Legacy per-finding artifacts ──
  // Persisted in the legacy `fix_artifacts` table (metadata + base64 ZIP).
  // Replaced by fix-all jobs + private Storage; kept until the old UI is gone.
  async buildFixArtifact(
    findingId: string,
    ownerId: string
  ): Promise<FixArtifact> {
    const finding = await this.requireFinding(findingId, ownerId);
    const scan = await this.getScan(finding.scanId, ownerId);
    const project = await this.getProject(scan.projectId, ownerId);

    const fixes = (
      await selectRows<FixRow>(
        "fix_attempts",
        `finding_id=eq.${q(findingId)}&select=*&order=created_at.asc`
      )
    ).map((r) => r.data);
    if (fixes.length === 0) throw new NotFoundError();

    const existing = await guarded("fix_artifacts", () =>
      selectRows<{ id: string }>(
        "fix_artifacts",
        `finding_id=eq.${q(findingId)}&select=id`
      )
    );
    const version = existing.length + 1;

    const built = buildFixArtifact(project.sourceCode, fixes, project.name, version);
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

    await guarded("fix_artifacts", () =>
      insertRows("fix_artifacts", [
        {
          id: artifact.id,
          finding_id: findingId,
          project_id: project.id,
          owner_id: ownerId,
          data: artifact,
          zip_base64: built.zip.toString("base64"),
          created_at: artifact.createdAt,
        },
      ])
    );
    return artifact;
  }

  async getFixArtifact(
    artifactId: string,
    ownerId: string
  ): Promise<FixArtifact | undefined> {
    const row = await guarded("fix_artifacts", () =>
      selectOne<FixArtifactRow>("fix_artifacts", `id=eq.${q(artifactId)}&select=*`)
    );
    if (!row) return undefined;
    if (row.owner_id !== ownerId) throw new NotAuthorizedError();
    return row.data;
  }

  async getFixArtifactBytes(
    artifactId: string,
    ownerId: string
  ): Promise<Buffer | undefined> {
    const row = await guarded("fix_artifacts", () =>
      selectOne<FixArtifactRow>("fix_artifacts", `id=eq.${q(artifactId)}&select=*`)
    );
    if (!row) return undefined;
    if (row.owner_id !== ownerId) throw new NotAuthorizedError();
    if (!row.zip_base64) return undefined;
    return Buffer.from(row.zip_base64, "base64");
  }

  async listFixArtifacts(
    findingId: string,
    ownerId: string
  ): Promise<FixArtifact[]> {
    await this.requireFinding(findingId, ownerId);
    const rows = await guarded("fix_artifacts", () =>
      selectRows<FixArtifactRow>(
        "fix_artifacts",
        `finding_id=eq.${q(findingId)}&select=*&order=created_at.desc`
      )
    );
    return rows.map((r) => r.data);
  }

  private async persistFinding(finding: SecurityFinding): Promise<void> {
    await updateRows("findings", `id=eq.${q(finding.id)}`, {
      severity: finding.severity,
      status: finding.status,
      data: finding,
      updated_at: finding.updatedAt,
    });
  }
}
