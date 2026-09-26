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
import {
  selectRows,
  selectOne,
  insertRows,
  upsertRows,
  updateRows,
} from "./supabaseClient";

/**
 * Supabase-backed store. Same interface + same ownership semantics as the
 * in-memory backend, but every project / scan / finding is persisted to
 * Postgres so state is shared across all Vercel serverless invocations.
 *
 * Ownership is enforced here (the app's IDOR defense); the DB has RLS enabled
 * deny-by-default as a second line of defense (the server uses the service
 * role key which bypasses RLS).
 */

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
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
  created_at: string;
}
interface ScanRow {
  id: string;
  project_id: string;
  status: Scan["status"];
  commit_sha: string | null;
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

// ── Row → domain mappers ──
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
    createdAt: r.created_at,
  };
}
function toScan(r: ScanRow): Scan {
  return {
    id: r.id,
    projectId: r.project_id,
    status: r.status,
    commitSha: r.commit_sha ?? undefined,
    startedAt: r.started_at,
    completedAt: r.completed_at ?? undefined,
    findingIds: r.finding_ids ?? [],
    scope: r.scope,
    plan: r.plan ?? undefined,
    report: r.report ?? undefined,
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
      `id=eq.${encodeURIComponent(projectId)}&select=*`
    );
    if (!row) throw new NotFoundError();
    if (row.owner_id !== ownerId) throw new NotAuthorizedError();
    return toProject(row);
  }

  private async requireScan(scanId: string, ownerId: string): Promise<Scan> {
    const row = await selectOne<ScanRow>(
      "scans",
      `id=eq.${encodeURIComponent(scanId)}&select=*`
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
      `id=eq.${encodeURIComponent(findingId)}&select=*`
    );
    if (!row) throw new NotFoundError();
    await this.requireScan(row.scan_id, ownerId);
    return row.data;
  }

  private async handlerFixed(projectId: string): Promise<boolean> {
    const row = await selectOne<{ handler_fixed: boolean }>(
      "projects",
      `id=eq.${encodeURIComponent(projectId)}&select=handler_fixed`
    );
    return row?.handler_fixed ?? false;
  }

  // ── Users ──
  async findUserByEmail(email: string): Promise<User | undefined> {
    const row = await selectOne<UserRow>(
      "app_users",
      `email=eq.${encodeURIComponent(normalizeEmail(email))}&select=*`
    );
    return row ? toUser(row) : undefined;
  }

  async getUserById(userId: string): Promise<User | undefined> {
    const row = await selectOne<UserRow>(
      "app_users",
      `id=eq.${encodeURIComponent(userId)}&select=*`
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
      // insert surfaces as a 409 unique-violation. Map it to the same typed
      // error the memory backend throws so signupAction shows the right message.
      const msg = e instanceof Error ? e.message : "";
      if (msg.includes("409") || msg.includes("duplicate key")) {
        throw new EmailInUseError();
      }
      throw e;
    }
  }

  // ── Projects ──
  async listProjects(ownerId: string): Promise<Project[]> {
    const rows = await selectRows<ProjectRow>(
      "projects",
      `owner_id=eq.${encodeURIComponent(ownerId)}&select=*&order=created_at.desc`
    );
    return rows.map(toProject);
  }

  async getProject(projectId: string, ownerId: string): Promise<Project> {
    return this.requireProject(projectId, ownerId);
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
    const row: Partial<ProjectRow> = {
      id: id("proj"),
      owner_id: ownerId,
      name: input.name.trim(),
      repository_url: input.repositoryUrl?.trim() || null,
      deployment_url: input.deploymentUrl?.trim() || null,
      source_code: input.sourceCode?.trim() || null,
      current_commit: "b72c42d",
      handler_fixed: false,
      created_at: now(),
    };
    const [inserted] = await insertRows<ProjectRow>("projects", row);
    return toProject(inserted);
  }

  // ── Scans ──
  async listScans(projectId: string, ownerId: string): Promise<Scan[]> {
    await this.requireProject(projectId, ownerId);
    const rows = await selectRows<ScanRow>(
      "scans",
      `project_id=eq.${encodeURIComponent(
        projectId
      )}&select=*&order=started_at.desc`
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
      `scan_id=eq.${encodeURIComponent(
        scanId
      )}&select=*&order=created_at.asc`
    );
    return rows.map((r) => r.data);
  }

  async runScan(projectId: string, ownerId: string): Promise<Scan> {
    const project = await this.requireProject(projectId, ownerId);
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
    await insertRows("scans", {
      id: scan.id,
      project_id: scan.projectId,
      status: "running",
      commit_sha: scan.commitSha ?? null,
      started_at: scan.startedAt,
      completed_at: null,
      finding_ids: [],
      scope: scan.scope,
      plan: scan.plan ?? null,
      report: scan.report ?? null,
    });

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

    await updateRows("scans", `id=eq.${encodeURIComponent(scan.id)}`, {
      status: scan.status,
      completed_at: scan.completedAt ?? null,
      finding_ids: scan.findingIds,
    });

    // reset applied-fix state + update project scan metadata
    await updateRows(
      "projects",
      `id=eq.${encodeURIComponent(project.id)}`,
      {
        handler_fixed: false,
        last_scanned_commit: commit,
        last_scan_date: scan.completedAt,
      }
    );

    return scan;
  }

  async scanPlan(projectId: string, ownerId: string): Promise<unknown> {
    const project = await this.requireProject(projectId, ownerId);
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
      `finding_id=eq.${encodeURIComponent(
        findingId
      )}&select=*&order=created_at.desc&limit=1`
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
        `id=eq.${encodeURIComponent(finding.scanId)}&select=project_id`
      );
      if (scanRow) {
        await updateRows(
          "projects",
          `id=eq.${encodeURIComponent(scanRow.project_id)}`,
          { handler_fixed: true }
        );
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
  ): Promise<{ finding: SecurityFinding; result?: VerificationResult }> {
    const finding = await this.requireFinding(findingId, ownerId);
    const scanner = this.orchestrator.scannerForFinding(finding);

    if (!scanner?.verify) {
      return { finding };
    }

    const scanRow = await selectOne<ScanRow>(
      "scans",
      `id=eq.${encodeURIComponent(finding.scanId)}&select=project_id`
    );
    const project = await this.requireProject(scanRow!.project_id, ownerId);
    const context = buildDemoContext(project.id, {
      name: project.name,
      repositoryUrl: project.repositoryUrl,
      deploymentUrl: project.deploymentUrl,
      commitSha: project.currentCommit,
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
    } else {
      finding.status = "resolved";
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
      `finding_id=eq.${encodeURIComponent(findingId)}&select=*`
    );
    return row?.data;
  }

  private async persistFinding(finding: SecurityFinding): Promise<void> {
    await updateRows(
      "findings",
      `id=eq.${encodeURIComponent(finding.id)}`,
      {
        severity: finding.severity,
        status: finding.status,
        data: finding,
        updated_at: finding.updatedAt,
      }
    );
  }
}
