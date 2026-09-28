import { createHash } from "crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { unzipToFileMap } from "@/lib/net/unzip";
import {
  createProject,
  createUser,
  getFindingsForScan,
  getSourceVersion,
  runScan,
  NotAuthorizedError,
} from "@/lib/store/store";
import { isStale, loadFixJob, readFixJobArtifact, startFixAll } from "@/lib/fixjobs/fixAllService";
import type { generateLlmFileFix } from "@/lib/remediation/llmFileFix";
import type { FixAttempt } from "@/lib/domain/types";

// All values are fake test fixtures (no real secrets).
const FILES = {
  "src/a.ts": 'export const apiKey = "abcdefghijklmnop1234";\nexport const x = 1;\n',
  "src/b.ts": 'export const token = "qrstuvwxyzabcdef5678";\nexport const y = 2;\n',
  "README.md": "not scanned",
};

type LlmFix = typeof generateLlmFileFix;

/** Stub LLM: replaces the hard-coded literal line with a process.env read. */
const stubFix: LlmFix = async ({ finding, filePath, fileContent }) => {
  const line = fileContent.split("\n").find((l) => /"[A-Za-z0-9]{16,}"/.test(l));
  if (!line) return { kind: "declined", reason: "nothing", correlationId: "c-1" };
  const after = line.replace(/"[A-Za-z0-9]{16,}"/, "process.env.APP_SECRET ?? \"\"");
  const fix: FixAttempt = {
    id: `fix_${finding.id}`,
    findingId: finding.id,
    source: "llm",
    summary: "환경변수로 옮겼어요.",
    plainExplanation: "비밀값을 코드에서 뺐어요.",
    diffs: [{ file: filePath, patch: "", beforeText: line, afterText: after, mode: "replace" }],
    applied: false,
    createdAt: new Date().toISOString(),
  };
  return { kind: "fix", fix, correlationId: "c-2" };
};

async function setup(tag: string) {
  const user = await createUser({ email: `${tag}-${Date.now()}@example.test`, passwordHash: "x:y" });
  const project = await createProject(user.id, { name: `p-${tag}`, files: FILES, sourceKind: "paste" });
  const scan = await runScan(project.id, user.id);
  const findings = await getFindingsForScan(scan.id, user.id);
  return { user, project, scan, findings };
}

describe("startFixAll", () => {
  let ctx: Awaited<ReturnType<typeof setup>>;
  beforeAll(async () => {
    ctx = await setup("main");
  });

  it("scan records the immutable source version it read", async () => {
    expect(ctx.scan.sourceVersionId).toBeTruthy();
    expect(ctx.scan.commitSha).toBeUndefined();
    const v = await getSourceVersion(ctx.scan.sourceVersionId!, ctx.user.id);
    expect(v.kind).toBe("original");
    expect(v.contentHash).toBe(ctx.scan.sourceContentHash);
    expect(ctx.findings.filter((f) => f.verificationKey?.startsWith("secret:")).length).toBeGreaterThanOrEqual(2);
  });

  it("applies fixes, stores a new version and a changed-files-only ZIP", async () => {
    const secretIds = ctx.findings.filter((f) => f.verificationKey?.startsWith("secret:")).map((f) => f.id);
    const { job, reused } = await startFixAll(
      { ownerId: ctx.user.id, scanId: ctx.scan.id, findingIds: secretIds },
      { llmConfigured: true, llmFix: stubFix }
    );
    expect(reused).toBe(false);
    expect(job.status).toBe("completed");
    expect(job.items.every((i) => i.outcome === "applied")).toBe(true);
    expect(job.changedFiles).toEqual(["src/a.ts", "src/b.ts"]);

    // Original version unchanged; result version holds the fix.
    const base = await getSourceVersion(job.baseVersionId, ctx.user.id);
    expect(base.files["src/a.ts"]).toBe(FILES["src/a.ts"]);
    const result = await getSourceVersion(job.resultVersionId!, ctx.user.id);
    expect(result.kind).toBe("fixed");
    expect(result.parentVersionId).toBe(base.id);
    expect(result.files["src/a.ts"]).toContain("process.env.APP_SECRET");
    expect(result.files["README.md"]).toBe(FILES["README.md"]);

    // ZIP: only changed files (+ summary), integrity matches.
    const bytes = await readFixJobArtifact(job);
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(job.artifact!.sha256);
    const unzipped = unzipToFileMap(Buffer.from(bytes));
    expect(Object.keys(unzipped).sort()).toEqual(["HOI-SECURITY-FIX-SUMMARY.md", "src/a.ts", "src/b.ts"]);
    expect(unzipped["src/a.ts"]).toBe(result.files["src/a.ts"]);
    expect(unzipped["HOI-SECURITY-FIX-SUMMARY.md"]).toContain("다시 배포해야 해요");
    expect(unzipped["HOI-SECURITY-FIX-SUMMARY.md"]).not.toContain("abcdefghijklmnop1234");

    // Findings are never marked resolved by fixing.
    const after = await getFindingsForScan(ctx.scan.id, ctx.user.id);
    expect(after.some((f) => f.status === "resolved")).toBe(false);

    // Same request again → same job, not a second run.
    const again = await startFixAll(
      { ownerId: ctx.user.id, scanId: ctx.scan.id, findingIds: secretIds },
      { llmConfigured: true, llmFix: stubFix }
    );
    expect(again.reused).toBe(true);
    expect(again.job.id).toBe(job.id);
  });

  it("rejects a project without code", async () => {
    await expect(
      createProject(ctx.user.id, { name: "empty", files: {}, sourceKind: "paste" })
    ).rejects.toMatchObject({ code: "source_required", status: 400 });
  });

  it("blocks other users", async () => {
    const other = await createUser({ email: `other-${Date.now()}@example.test`, passwordHash: "x:y" });
    await expect(startFixAll({ ownerId: other.id, scanId: ctx.scan.id })).rejects.toBeInstanceOf(NotAuthorizedError);
  });
});

describe("startFixAll failure handling", () => {
  it("without LLM, unsupported items make the job failed with no artifact", async () => {
    const c = await setup("nollm");
    const { job } = await startFixAll(
      { ownerId: c.user.id, scanId: c.scan.id },
      { llmConfigured: false }
    );
    expect(job.status).toBe("failed");
    expect(job.errorCode).toBe("nothing_applied");
    expect(job.artifact).toBeUndefined();
    expect(job.resultVersionId).toBeUndefined();
    expect(job.items.some((i) => i.outcome === "applied")).toBe(false);
  });

  it("LLM errors are failures, never success", async () => {
    const c = await setup("llmerr");
    const failing: LlmFix = async () => ({ kind: "error", code: "timeout", correlationId: "c-9" });
    const { job } = await startFixAll(
      { ownerId: c.user.id, scanId: c.scan.id },
      { llmConfigured: true, llmFix: failing }
    );
    expect(job.status).toBe("failed");
    const secretItems = job.items.filter((i) => i.reasonCode?.startsWith("ai_"));
    expect(secretItems.length).toBeGreaterThan(0);
    expect(secretItems.every((i) => i.outcome === "apply_failed")).toBe(true);
  });

  it("a failed job can be retried with a fresh key", async () => {
    const c = await setup("retry");
    const failing: LlmFix = async () => ({ kind: "error", code: "http_error", correlationId: null });
    const first = await startFixAll({ ownerId: c.user.id, scanId: c.scan.id }, { llmConfigured: true, llmFix: failing });
    expect(first.job.status).toBe("failed");
    const second = await startFixAll({ ownerId: c.user.id, scanId: c.scan.id }, { llmConfigured: true, llmFix: stubFix });
    expect(second.reused).toBe(false);
    expect(second.job.id).not.toBe(first.job.id);
    expect(["completed", "partial"]).toContain(second.job.status);
  });

  it("over-limit items are reported as skipped, not dropped", async () => {
    const c = await setup("limit");
    const limits = { ...(await import("@/lib/config/limits")).LIMITS, fixAllMaxItems: 1 };
    const { job } = await startFixAll(
      { ownerId: c.user.id, scanId: c.scan.id },
      { llmConfigured: true, llmFix: stubFix, limits }
    );
    expect(job.skippedForLimit).toBe(c.findings.filter((f) => f.status !== "resolved").length - 1);
    expect(job.items.filter((i) => i.reasonCode === "item_limit").length).toBe(job.skippedForLimit);
    expect(job.status === "partial" || job.status === "failed").toBe(true);
  });

  it("stale check only touches running jobs", async () => {
    const c = await setup("stale");
    const { job } = await startFixAll({ ownerId: c.user.id, scanId: c.scan.id }, { llmConfigured: false });
    const later = Date.parse(job.updatedAt) + 10 * 60_000;
    const read = await loadFixJob(job.id, c.user.id, { nowMs: () => later });
    expect(read.status).toBe(job.status);
    expect(isStale({ ...job, status: "running" }, later, 180_000)).toBe(true);
    expect(isStale({ ...job, status: "running" }, Date.parse(job.updatedAt) + 1_000, 180_000)).toBe(false);
  });
});
