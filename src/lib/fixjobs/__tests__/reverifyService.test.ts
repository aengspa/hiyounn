import { describe, expect, it } from "vitest";
import {
  createProject,
  createUser,
  getFindingsForScan,
  runScan,
  NotAuthorizedError,
} from "@/lib/store/store";
import { startFixAll } from "@/lib/fixjobs/fixAllService";
import { reverifyFixJob, selectFilesForReview, validateLlmResult } from "@/lib/fixjobs/reverifyService";
import { SecurityOrchestrator } from "@/lib/scanners/orchestrator";
import type { generateLlmFileFix } from "@/lib/remediation/llmFileFix";
import type { FixAttempt, SecurityFinding, SourceVersion } from "@/lib/domain/types";
import { fixStatusFor } from "@/lib/ui/fixStatus";

// Fake fixtures only.
const FILES = {
  "src/a.ts": 'export const apiKey = "abcdefghijklmnop1234";\nexport const x = 1;\n',
};

const stubFix: typeof generateLlmFileFix = async ({ finding, filePath, fileContent }) => {
  const line = fileContent.split("\n").find((l) => /"[A-Za-z0-9]{16,}"/.test(l))!;
  const after = line.replace(/"[A-Za-z0-9]{16,}"/, 'process.env.APP_SECRET ?? ""');
  const fix: FixAttempt = {
    id: `fix_${finding.id}`,
    findingId: finding.id,
    source: "llm",
    summary: "s",
    plainExplanation: "p",
    diffs: [{ file: filePath, patch: "", beforeText: line, afterText: after, mode: "replace" }],
    applied: false,
    createdAt: new Date().toISOString(),
  };
  return { kind: "fix", fix, correlationId: "c" };
};

async function fixedJob(tag: string) {
  const user = await createUser({ email: `${tag}-${Date.now()}-${Math.random()}@example.test`, passwordHash: "x:y" });
  const project = await createProject(user.id, { name: tag, files: FILES, sourceKind: "paste" });
  const scan = await runScan(project.id, user.id);
  const findings = await getFindingsForScan(scan.id, user.id);
  const secretIds = findings.filter((f) => f.verificationKey?.startsWith("secret:")).map((f) => f.id);
  const { job } = await startFixAll(
    { ownerId: user.id, scanId: scan.id, findingIds: secretIds },
    { llmConfigured: true, llmFix: stubFix }
  );
  return { user, job, secretIds };
}

describe("reverifyFixJob", () => {
  it("re-checks the FIXED version with rules and never touches finding status", async () => {
    const { user, job, secretIds } = await fixedJob("rv-rule");
    expect(job.status).toBe("completed");
    const out = await reverifyFixJob(job.id, user.id, { llmConfigured: false });
    const v = out.verification!;
    expect(v.status).toBe("completed");
    expect(v.resultVersionId).toBe(job.resultVersionId);
    for (const fid of secretIds) {
      const it = v.items.find((i) => i.findingId === fid)!;
      expect(it.verdict).toBe("fixed_in_source");
      expect(it.method).toBe("rule");
    }
    const findings = await getFindingsForScan(job.scanId, user.id);
    expect(findings.some((f) => f.status === "resolved")).toBe(false);
  });

  it("LLM failure is reported as failed, not success", async () => {
    const { user, job } = await fixedJob("rv-fail");
    const out = await reverifyFixJob(job.id, user.id, {
      llmConfigured: true,
      orchestrator: new SecurityOrchestrator([]), // force the AI path
      llmCall: async () => {
        throw new Error("boom");
      },
    });
    expect(out.verification!.status).toBe("failed");
    expect(out.verification!.aiStatus).toBe("failed");
    expect(out.verification!.items.every((i) => i.verdict === "inconclusive" && i.reasonCode === "ai_failed")).toBe(true);
    expect(out.verification!.sentFiles).toEqual(["src/a.ts"]);
  });

  it("accepts AI verdicts only with snippets that exist in the fixed file", async () => {
    const { user, job, secretIds } = await fixedJob("rv-llm");
    const out = await reverifyFixJob(job.id, user.id, {
      llmConfigured: true,
      orchestrator: new SecurityOrchestrator([]),
      llmCall: async (_s, userText) => {
        const input = JSON.parse(userText) as { findings: { id: string }[] };
        return {
          correlationId: "c",
          text: JSON.stringify({
            results: [
              {
                findingId: input.findings[0].id,
                verdict: "fixed_in_source",
                summary: "ok",
                evidence: [
                  { role: "mitigation", file: "src/a.ts", snippet: 'export const apiKey = process.env.APP_SECRET ?? "";', explanation: "env" },
                ],
              },
              { findingId: "made-up-id", verdict: "fixed_in_source", evidence: [] },
            ],
          }),
        };
      },
    });
    const items = out.verification!.items;
    expect(items.find((i) => i.findingId === secretIds[0])!.verdict).toBe("fixed_in_source");
    expect(items.some((i) => i.findingId === "made-up-id")).toBe(false);
  });

  it("blocks other users", async () => {
    const { job } = await fixedJob("rv-own");
    const other = await createUser({ email: `o-${Date.now()}@example.test`, passwordHash: "x:y" });
    await expect(reverifyFixJob(job.id, other.id)).rejects.toBeInstanceOf(NotAuthorizedError);
  });
});

describe("validateLlmResult", () => {
  const finding = { id: "f1", title: "t", severity: "high" } as SecurityFinding;
  const version = { files: { "a.ts": "const safe = escape(input);\nrender(safe);\n" } } as unknown as SourceVersion;
  const sent = new Set(["a.ts"]);

  it("rejects invented snippets", () => {
    const r = validateLlmResult(
      finding,
      { verdict: "fixed_in_source", evidence: [{ role: "mitigation", file: "a.ts", snippet: "sanitize(everything)", explanation: "" }] },
      version,
      sent
    );
    expect(r.verdict).toBe("inconclusive");
    expect(r.reasonCode).toBe("evidence_not_verified");
  });

  it("rejects snippets from files that were not sent", () => {
    const r = validateLlmResult(
      finding,
      { verdict: "still_present", evidence: [{ role: "vulnerable_code", file: "b.ts", snippet: "const safe = escape(input);", explanation: "" }] },
      version,
      sent
    );
    expect(r.verdict).toBe("inconclusive");
  });

  it("missing answer is inconclusive", () => {
    expect(validateLlmResult(finding, undefined, version, sent).reasonCode).toBe("no_answer");
  });
});

describe("selectFilesForReview", () => {
  it("records omitted files instead of truncating", () => {
    const version = { files: { "a.ts": "x".repeat(100), "b.ts": "y".repeat(100), "big.ts": "z".repeat(500) } } as unknown as SourceVersion;
    const fs = [
      { location: { file: "a.ts", line: 1 } },
      { location: { file: "big.ts", line: 1 } },
      { location: { file: "b.ts", line: 1 } },
    ] as SecurityFinding[];
    const r = selectFilesForReview(version, fs, [], { reverifyPromptChars: 150, llmFileChars: 400 });
    expect(r.sent).toEqual(["a.ts"]);
    expect(r.omitted).toEqual([
      { path: "big.ts", reason: "too_large" },
      { path: "b.ts", reason: "over_budget" },
    ]);
  });
});

describe("fixStatusFor", () => {
  it("maps to the four labels", () => {
    expect(fixStatusFor("f", {}).label).toBe("점검이 필요해요");
    expect(
      fixStatusFor("f", { jobStatus: "running", item: { findingId: "f", outcome: "skipped", reasonCode: "pending" } }).label
    ).toBe("지금 수정해요");
    expect(fixStatusFor("f", { item: { findingId: "f", outcome: "apply_failed" } }).label).toBe("해결 실패했어요");
    const applied = { findingId: "f", outcome: "applied" as const };
    expect(fixStatusFor("f", { item: applied }).label).toBe("점검이 필요해요");
    expect(
      fixStatusFor("f", { item: applied, verification: { status: "completed", items: [{ findingId: "f", verdict: "fixed_in_source" }] } }).label
    ).toBe("해결 완료했어요");
    expect(
      fixStatusFor("f", { item: applied, verification: { status: "completed", items: [{ findingId: "f", verdict: "still_present" }] } }).label
    ).toBe("해결 실패했어요");
    expect(
      fixStatusFor("f", { item: applied, verification: { status: "failed", items: [{ findingId: "f", verdict: "inconclusive", reasonCode: "ai_failed" }] } }).label
    ).toBe("점검이 필요해요");
  });
});
