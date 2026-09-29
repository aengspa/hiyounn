import { createHash } from "crypto";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { unzipToFileMap } from "@/lib/net/unzip";
import {
  createProject,
  createUser,
  getFindingsForScan,
  getSourceVersion,
  runScan,
  NotAuthorizedError,
} from "@/lib/store/store";
import {
  APPLIED_UNVERIFIED_REASON,
  isStale,
  loadFixJob,
  readFixJobArtifact,
  startFixAll,
} from "@/lib/fixjobs/fixAllService";
import type { generateLlmFileFix } from "@/lib/remediation/llmFileFix";
import type { FixAttempt } from "@/lib/domain/types";
import { LIMITS } from "@/lib/config/limits";
import { excerptChars } from "@/lib/remediation/fixExcerpt";

// All values are fake test fixtures (no real secrets).
const SECRET_FILES = {
  "src/a.ts": 'export const apiKey = "abcdefghijklmnop1234";\nexport const x = 1;\n',
  "src/b.ts": 'export const token = "qrstuvwxyzabcdef5678";\nexport const y = 2;\n',
  "README.md": "not scanned",
};

// Code-level issue the rules can't fix by themselves (goes to the AI path).
const XSS_FILES = {
  "src/view.ts": 'export function render(el: HTMLElement, name: string) {\n  el.innerHTML = "<b>" + name + "</b>";\n}\n',
  "src/list.ts": 'export function row(li: HTMLElement, text: string) {\n  li.innerHTML = "<i>" + text + "</i>";\n}\n',
};

type LlmFix = typeof generateLlmFileFix;

function llmFixOf(filePath: string, findingId: string, before: string, after: string): Awaited<ReturnType<LlmFix>> {
  const fix: FixAttempt = {
    id: `fix_${findingId}`,
    findingId,
    source: "llm",
    summary: "텍스트로 넣도록 바꿨어요.",
    plainExplanation: "HTML 대신 글자로 넣어요.",
    diffs: [{ file: filePath, patch: "", beforeText: before, afterText: after, mode: "replace" }],
    applied: false,
    createdAt: new Date().toISOString(),
  };
  return { kind: "fix", fix, correlationId: "c-2" };
}

/** Stub LLM: turns an innerHTML concatenation into textContent. */
const stubFix: LlmFix = async ({ finding, filePath, fileContent }) => {
  const line = fileContent.split("\n").find((l) => l.includes("innerHTML"));
  if (!line) return { kind: "declined", reason: "nothing", correlationId: "c-1" };
  const after = line.replace(/innerHTML = "<\w>" \+ (\w+) \+ "<\/\w>"/, "textContent = $1");
  return llmFixOf(filePath, finding.id, line, after);
};

/** A ~60,000-char file with one innerHTML line in the middle. */
function bigFile(): { content: string; vulnLine: string; lineNo: number } {
  const filler = (i: number) => `export function f${i}(a: number): number {\n  return a + ${i};\n}\n`;
  const vulnLine = '  el.innerHTML = "<b>" + name + "</b>";';
  let content = 'import { helper } from "./helper";\n\nexport const h = helper;\n';
  let i = 0;
  while (content.length < 30_000) content += filler(i++);
  const lineNo = content.split("\n").length + 1;
  content += `export function render(el: HTMLElement, name: string) {\n${vulnLine}\n}\n`;
  while (content.length < 60_000) content += filler(i++);
  return { content, vulnLine, lineNo };
}

/** Stub LLM that only looks at what the model would see (the excerpt when given). */
function stubFromExcerpt(input: Parameters<LlmFix>[0]): Awaited<ReturnType<LlmFix>> {
  const seen = input.excerpt ? input.excerpt.parts.map((p) => p.text).join("\n") : input.fileContent;
  const line = seen.split("\n").find((l) => l.includes("innerHTML"));
  if (!line) return { kind: "declined", reason: "nothing here", correlationId: "c-x" };
  return llmFixOf(input.filePath, input.finding.id, line, line.replace(/innerHTML = "<\w>" \+ (\w+) \+ "<\/\w>"/, "textContent = $1"));
}

async function setup(tag: string, files: Record<string, string>) {
  const user = await createUser({ email: `${tag}-${Date.now()}-${Math.random()}@example.test`, passwordHash: "x:y" });
  const project = await createProject(user.id, { name: `p-${tag}`, files, sourceKind: "paste" });
  const scan = await runScan(project.id, user.id);
  const findings = await getFindingsForScan(scan.id, user.id);
  return { user, project, scan, findings };
}

describe("startFixAll", () => {
  let ctx: Awaited<ReturnType<typeof setup>>;
  beforeAll(async () => {
    ctx = await setup("main", SECRET_FILES);
  });

  it("scan records the immutable source version it read", async () => {
    expect(ctx.scan.sourceVersionId).toBeTruthy();
    expect(ctx.scan.commitSha).toBeUndefined();
    const v = await getSourceVersion(ctx.scan.sourceVersionId!, ctx.user.id);
    expect(v.kind).toBe("original");
    expect(v.contentHash).toBe(ctx.scan.sourceContentHash);
    expect(ctx.findings.filter((f) => f.verificationKey?.startsWith("secret:")).length).toBeGreaterThanOrEqual(2);
  });

  it("fixes secrets by rule without the AI, stores a new version and a changed-files-only ZIP", async () => {
    const secretIds = ctx.findings.filter((f) => f.verificationKey?.startsWith("secret:")).map((f) => f.id);
    const llm = vi.fn(stubFix);
    const { job, reused } = await startFixAll(
      { ownerId: ctx.user.id, scanId: ctx.scan.id, findingIds: secretIds },
      { llmConfigured: true, llmFix: llm }
    );
    expect(reused).toBe(false);
    expect(job.status).toBe("completed");
    expect(job.items.every((i) => i.outcome === "applied" && i.fixSource === "deterministic")).toBe(true);
    // Secrets never go to the AI.
    expect(llm).not.toHaveBeenCalled();
    expect(job.changedFiles).toEqual(["src/a.ts", "src/b.ts"]);

    // Original version unchanged; result version holds the fix.
    const base = await getSourceVersion(job.baseVersionId, ctx.user.id);
    expect(base.files["src/a.ts"]).toBe(SECRET_FILES["src/a.ts"]);
    const result = await getSourceVersion(job.resultVersionId!, ctx.user.id);
    expect(result.kind).toBe("fixed");
    expect(result.parentVersionId).toBe(base.id);
    expect(result.files["src/a.ts"]).toContain("export const apiKey = process.env.API_KEY;");
    expect(result.files["src/b.ts"]).toContain("export const token = process.env.APP_TOKEN;");
    expect(result.files["README.md"]).toBe(SECRET_FILES["README.md"]);

    // ZIP: only changed files (+ summary), integrity matches, no secret inside.
    const bytes = await readFixJobArtifact(job);
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(job.artifact!.sha256);
    const unzipped = unzipToFileMap(Buffer.from(bytes));
    expect(Object.keys(unzipped).sort()).toEqual(["HOI-SECURITY-FIX-SUMMARY.md", "src/a.ts", "src/b.ts"]);
    expect(unzipped["src/a.ts"]).toBe(result.files["src/a.ts"]);
    expect(unzipped["HOI-SECURITY-FIX-SUMMARY.md"]).toContain("다시 배포해야 해요");
    expect(unzipped["HOI-SECURITY-FIX-SUMMARY.md"]).not.toContain("abcdefghijklmnop1234");
    // The fix moved secrets to new env vars: the job and the ZIP say so before anyone applies it.
    expect(job.requiredEnv?.map((e) => e.name)).toEqual(["API_KEY", "APP_TOKEN"]);
    expect(unzipped["HOI-SECURITY-FIX-SUMMARY.md"]).toContain("반영 전에 설정할 환경변수 (2개)");
    expect(unzipped["HOI-SECURITY-FIX-SUMMARY.md"]).toContain("- API_KEY (src/a.ts)");

    // Applied but not re-verified: the wording says so and never claims the problem is solved.
    const claimsSolved = /해결했어요|해결됐어요|막았어요|안전해졌어요/;
    for (const item of job.items) {
      expect(item.reason).toBe(APPLIED_UNVERIFIED_REASON);
      expect(`${item.reason} ${item.summary} ${item.plainExplanation}`).not.toMatch(claimsSolved);
    }
    expect(unzipped["HOI-SECURITY-FIX-SUMMARY.md"]).toContain("재검증 전");
    expect(unzipped["HOI-SECURITY-FIX-SUMMARY.md"]).not.toMatch(claimsSolved);

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

describe("startFixAll AI path", () => {
  it("applies AI fixes for code issues", async () => {
    const c = await setup("ai-ok", XSS_FILES);
    const { job } = await startFixAll({ ownerId: c.user.id, scanId: c.scan.id }, { llmConfigured: true, llmFix: stubFix });
    expect(job.status).toBe("completed");
    expect(job.items.every((i) => i.outcome === "applied" && i.fixSource === "llm")).toBe(true);
    const result = await getSourceVersion(job.resultVersionId!, c.user.id);
    expect(result.files["src/view.ts"]).toContain("el.textContent = name;");
    // The per-item edit records where in the file it starts (line 2 of view.ts).
    const item = job.items.find((i) => i.files.includes("src/view.ts"))!;
    expect(item.edits?.[0]).toMatchObject({ file: "src/view.ts", line: 2 });
  });

  it("without LLM, code issues are unsupported and the job fails with no artifact", async () => {
    const c = await setup("nollm", XSS_FILES);
    const { job } = await startFixAll({ ownerId: c.user.id, scanId: c.scan.id }, { llmConfigured: false });
    expect(job.status).toBe("failed");
    expect(job.errorCode).toBe("nothing_applied");
    expect(job.artifact).toBeUndefined();
    expect(job.resultVersionId).toBeUndefined();
    expect(job.items.every((i) => i.outcome === "unsupported" && i.reasonCode === "no_auto_fix")).toBe(true);
  });

  it("without LLM, secrets are still fixed by rule", async () => {
    const c = await setup("nollm-secret", SECRET_FILES);
    const { job } = await startFixAll({ ownerId: c.user.id, scanId: c.scan.id }, { llmConfigured: false });
    expect(job.status).toBe("completed");
    expect(job.artifact).toBeDefined();
  });

  it("LLM errors are failures, never success", async () => {
    const c = await setup("llmerr", XSS_FILES);
    const failing: LlmFix = async () => ({ kind: "error", code: "timeout", correlationId: "c-9" });
    const { job } = await startFixAll({ ownerId: c.user.id, scanId: c.scan.id }, { llmConfigured: true, llmFix: failing });
    expect(job.status).toBe("failed");
    expect(job.items.every((i) => i.outcome === "apply_failed" && i.reasonCode === "ai_timeout")).toBe(true);
  });

  it("an auth failure stops further AI calls and says why", async () => {
    const c = await setup("authfail", XSS_FILES);
    const failing = vi.fn<LlmFix>(async () => ({ kind: "error", code: "auth_failed", correlationId: null }));
    const { job } = await startFixAll(
      { ownerId: c.user.id, scanId: c.scan.id },
      { llmConfigured: true, llmFix: failing, limits: { ...LIMITS, fixAllConcurrency: 1 } }
    );
    expect(failing).toHaveBeenCalledTimes(1);
    const outcomes = job.items.map((i) => `${i.outcome}:${i.reasonCode}`).sort();
    expect(outcomes).toEqual(["apply_failed:ai_auth_failed", "skipped:ai_unavailable"]);
    expect(job.items.every((i) => i.reason?.includes("AI 키"))).toBe(true);
  });

  it("a failed job can be retried with a fresh key", async () => {
    const c = await setup("retry", XSS_FILES);
    const failing: LlmFix = async () => ({ kind: "error", code: "http_error", correlationId: null });
    const first = await startFixAll({ ownerId: c.user.id, scanId: c.scan.id }, { llmConfigured: true, llmFix: failing });
    expect(first.job.status).toBe("failed");
    const second = await startFixAll({ ownerId: c.user.id, scanId: c.scan.id }, { llmConfigured: true, llmFix: stubFix });
    expect(second.reused).toBe(false);
    expect(second.job.id).not.toBe(first.job.id);
    expect(["completed", "partial"]).toContain(second.job.status);
  });

  it("does not auto-edit code for a rule finding the AI flagged as a likely false positive", async () => {
    const c = await setup("fp", XSS_FILES);
    // The memory store returns its stored objects, so this sets the AI review
    // the scan would have attached.
    const target = (await getFindingsForScan(c.scan.id, c.user.id))[0];
    target.aiReview = { verdict: "likely_false_positive", reason: "상수만 씀" };
    const llm = vi.fn(stubFix);
    const { job } = await startFixAll({ ownerId: c.user.id, scanId: c.scan.id }, { llmConfigured: true, llmFix: llm });
    const item = job.items.find((i) => i.findingId === target.id)!;
    expect(item.outcome).toBe("unsupported");
    expect(item.reasonCode).toBe("disputed_at_scan");
    expect(llm).toHaveBeenCalledTimes(c.findings.length - 1);
  });

  it("masks secrets in code sent to the AI and restores them when applying", async () => {
    const secret = "sk_live_" + "Q".repeat(24);
    const files = {
      "src/widget.tsx": `"use client";\nconst key = "${secret}";\nexport function W(el: HTMLElement, v: string) {\n  el.innerHTML = "<i>" + v + "</i>";\n}\n`,
    };
    const c = await setup("redact", files);
    const seen: string[] = [];
    const llm: LlmFix = async ({ finding, filePath, fileContent }) => {
      seen.push(fileContent);
      const secretLine = fileContent.split("\n")[1];
      const htmlLine = fileContent.split("\n")[3];
      // The edit touches the (masked) secret line too, to prove restore works.
      return llmFixOf(filePath, finding.id, `${secretLine}\nexport function W(el: HTMLElement, v: string) {\n${htmlLine}`,
        `${secretLine} // TODO: move to server\nexport function W(el: HTMLElement, v: string) {\n  el.textContent = v;`);
    };
    const { job } = await startFixAll({ ownerId: c.user.id, scanId: c.scan.id }, { llmConfigured: true, llmFix: llm });

    // The client-side secret is refused by rule (moving it to env would still expose it).
    const secretItem = job.items.find((i) => c.findings.find((f) => f.id === i.findingId)?.verificationKey?.startsWith("secret:"))!;
    expect(secretItem.outcome).toBe("unsupported");
    expect(secretItem.reasonCode).toBe("secret_in_client_code");

    expect(seen.length).toBe(1);
    expect(seen[0]).not.toContain(secret);
    expect(seen[0]).toContain("__HOI_REDACTED_SECRET_1__");
    const result = await getSourceVersion(job.resultVersionId!, c.user.id);
    expect(result.files["src/widget.tsx"]).toContain(`const key = "${secret}"; // TODO: move to server`);
    expect(result.files["src/widget.tsx"]).toContain("el.textContent = v;");
    expect(result.files["src/widget.tsx"]).not.toContain("__HOI_REDACTED_SECRET_");
  });

  it("over-limit items are reported as skipped, not dropped", async () => {
    const c = await setup("limit", XSS_FILES);
    const { job } = await startFixAll(
      { ownerId: c.user.id, scanId: c.scan.id },
      { llmConfigured: true, llmFix: stubFix, limits: { ...LIMITS, fixAllMaxItems: 1 } }
    );
    expect(job.skippedForLimit).toBe(c.findings.filter((f) => f.status !== "resolved").length - 1);
    expect(job.items.filter((i) => i.reasonCode === "item_limit").length).toBe(job.skippedForLimit);
    expect(job.status === "partial" || job.status === "failed").toBe(true);
  });

  it("fixes a file longer than the per-call budget by sending an excerpt and patching the full file", async () => {
    const { content, vulnLine, lineNo } = bigFile();
    expect(content.length).toBeGreaterThanOrEqual(60_000);
    const c = await setup("big", { "src/big.ts": content });
    const target = c.findings.find((f) => f.location?.file === "src/big.ts" && f.location.line === lineNo)!;
    expect(target).toBeDefined();
    const seen: Parameters<LlmFix>[0][] = [];
    const llm: LlmFix = async (input) => {
      seen.push(input);
      return stubFromExcerpt(input);
    };
    const { job } = await startFixAll(
      { ownerId: c.user.id, scanId: c.scan.id, findingIds: [target.id] },
      { llmConfigured: true, llmFix: llm }
    );
    const item = job.items[0];
    expect(item.outcome).toBe("applied");
    expect(item.fixSource).toBe("llm");
    expect(item.edits?.[0]).toMatchObject({ file: "src/big.ts", line: lineNo });

    // The model saw only an excerpt under the budget that contains the flagged line and the imports.
    expect(seen.length).toBe(1);
    const ex = seen[0].excerpt!;
    expect(ex).toBeDefined();
    expect(excerptChars(ex)).toBeLessThanOrEqual(LIMITS.llmFixWindowChars);
    expect(ex.parts.some((p) => p.text.includes(vulnLine))).toBe(true);
    expect(ex.parts[0]).toMatchObject({ startLine: 1 });
    expect(ex.parts[0].text).toContain('import { helper } from "./helper";');

    // The edit landed at the flagged line; every other byte is unchanged.
    const result = await getSourceVersion(job.resultVersionId!, c.user.id);
    expect(result.files["src/big.ts"]).toBe(content.replace(vulnLine, "  el.textContent = name;"));
  });

  it("an excerpt edit whose before text is not in the file fails safely", async () => {
    const { content, lineNo } = bigFile();
    const c = await setup("big-bad", { "src/big.ts": content });
    const target = c.findings.find((f) => f.location?.file === "src/big.ts" && f.location.line === lineNo)!;
    const llm: LlmFix = async ({ finding, filePath }) =>
      llmFixOf(filePath, finding.id, '  el.innerHTML = "<b>" + nameX + "</b>";', "  el.textContent = nameX;");
    const { job } = await startFixAll(
      { ownerId: c.user.id, scanId: c.scan.id, findingIds: [target.id] },
      { llmConfigured: true, llmFix: llm }
    );
    expect(job.items[0]).toMatchObject({ outcome: "apply_failed", reasonCode: "before_not_found" });
    expect(job.items[0].reason).toContain("적용하지 않았어요");
    expect(job.status).toBe("failed");
    expect(job.resultVersionId).toBeUndefined();
  });

  it("without a line location, tries consecutive chunks of a long file and stops at the first valid fix", async () => {
    const { content, vulnLine, lineNo } = bigFile();
    const c = await setup("big-noline", { "src/big.ts": content });
    const target = (await getFindingsForScan(c.scan.id, c.user.id)).find(
      (f) => f.location?.file === "src/big.ts" && f.location.line === lineNo
    )!;
    // The memory store returns stored objects: drop the line and make the evidence unfindable.
    target.location = { file: "src/big.ts", line: 0 };
    target.evidence = target.evidence.map((e) => ({ ...e, content: "(표시할 코드가 없어요)" }));
    const llm = vi.fn<LlmFix>(async (input) => stubFromExcerpt(input));
    const { job } = await startFixAll(
      { ownerId: c.user.id, scanId: c.scan.id, findingIds: [target.id] },
      { llmConfigured: true, llmFix: llm }
    );
    expect(job.items[0].outcome).toBe("applied");
    const calls = llm.mock.calls.map((a) => a[0].excerpt!);
    expect(calls.length).toBeGreaterThanOrEqual(2);
    expect(calls.every((ex) => excerptChars(ex) <= LIMITS.llmFixWindowChars)).toBe(true);
    expect(calls.slice(0, -1).some((ex) => ex.parts.some((p) => p.text.includes(vulnLine)))).toBe(false);
    const result = await getSourceVersion(job.resultVersionId!, c.user.id);
    expect(result.files["src/big.ts"]).toBe(content.replace(vulnLine, "  el.textContent = name;"));
  });

  it("stale check only touches running jobs", async () => {
    const c = await setup("stale", XSS_FILES);
    const { job } = await startFixAll({ ownerId: c.user.id, scanId: c.scan.id }, { llmConfigured: false });
    const later = Date.parse(job.updatedAt) + 10 * 60_000;
    const read = await loadFixJob(job.id, c.user.id, { nowMs: () => later });
    expect(read.status).toBe(job.status);
    expect(isStale({ ...job, status: "running" }, later, 180_000)).toBe(true);
    expect(isStale({ ...job, status: "running" }, Date.parse(job.updatedAt) + 1_000, 180_000)).toBe(false);
  });
});
