import { describe, expect, it, vi } from "vitest";
import {
  createProject,
  createUser,
  getFindingsForScan,
  runScan,
  NotAuthorizedError,
} from "@/lib/store/store";
import { startFixAll } from "@/lib/fixjobs/fixAllService";
import { mergeVerdicts, reverifyFixJob, selectFilesForReview, validateLlmResult } from "@/lib/fixjobs/reverifyService";
import { SecurityOrchestrator } from "@/lib/scanners/orchestrator";
import type { generateLlmFileFix } from "@/lib/remediation/llmFileFix";
import type { FixAttempt, ReverifyItem, SecurityFinding, SourceVersion } from "@/lib/domain/types";
import { fixStatusFor } from "@/lib/ui/fixStatus";

// Fake fixtures only.
const SECRET_FILES = {
  "src/a.ts": 'export const apiKey = "abcdefghijklmnop1234";\nexport const x = 1;\n',
};
const XSS_FILES = {
  "src/view.ts": 'export function render(el: HTMLElement, name: string) {\n  el.innerHTML = "<b>" + name + "</b>";\n}\n',
};

const stubFix: typeof generateLlmFileFix = async ({ finding, filePath, fileContent }) => {
  const line = fileContent.split("\n").find((l) => l.includes("innerHTML"))!;
  const fix: FixAttempt = {
    id: `fix_${finding.id}`,
    findingId: finding.id,
    source: "llm",
    summary: "s",
    plainExplanation: "p",
    diffs: [{ file: filePath, patch: "", beforeText: line, afterText: "  el.textContent = name;", mode: "replace" }],
    applied: false,
    createdAt: new Date().toISOString(),
  };
  return { kind: "fix", fix, correlationId: "c" };
};

async function fixedJob(tag: string, files: Record<string, string>) {
  const user = await createUser({ email: `${tag}-${Date.now()}-${Math.random()}@example.test`, passwordHash: "x:y" });
  const project = await createProject(user.id, { name: tag, files, sourceKind: "paste" });
  const scan = await runScan(project.id, user.id);
  const findings = await getFindingsForScan(scan.id, user.id);
  const { job } = await startFixAll({ ownerId: user.id, scanId: scan.id }, { llmConfigured: true, llmFix: stubFix });
  return { user, job, ids: findings.map((f) => f.id) };
}

/** 공격 재현 테스트를 만들지 않는 대체(이 파일의 다른 테스트용). */
const noExploit = async () => ({ kind: "untestable" as const, reason: "test" });

function aiAnswer(results: unknown[]) {
  return async () => ({ correlationId: "c", text: JSON.stringify({ results }) });
}

describe("reverifyFixJob", () => {
  it("re-checks the FIXED version with rules and never touches finding status", async () => {
    const { user, job, ids } = await fixedJob("rv-rule", SECRET_FILES);
    expect(job.status).toBe("completed");
    const out = await reverifyFixJob(job.id, user.id, { llmConfigured: false });
    const v = out.verification!;
    expect(v.status).toBe("completed");
    expect(v.resultVersionId).toBe(job.resultVersionId);
    for (const fid of ids) {
      const it = v.items.find((i) => i.findingId === fid)!;
      expect(it.verdict).toBe("fixed_in_source");
      expect(it.method).toBe("rule");
    }
    const findings = await getFindingsForScan(job.scanId, user.id);
    expect(findings.some((f) => f.status === "resolved")).toBe(false);
  });

  it("sends secret items to the AI only with values masked", async () => {
    const { user, job } = await fixedJob("rv-secret-ai", SECRET_FILES);
    const payloads: string[] = [];
    const llmCall = vi.fn(async (_s: string, u: string) => {
      payloads.push(u);
      return { correlationId: "c", text: JSON.stringify({ results: [] }) };
    });
    await reverifyFixJob(job.id, user.id, { llmConfigured: true, llmCall, exploitGen: noExploit });
    // 답이 없으면 한 번 더 묻는다. 두 번 모두 값이 가려져 있어야 한다.
    expect(llmCall).toHaveBeenCalledTimes(2);
    for (const p of payloads) expect(p).not.toContain("abcdefghijklmnop1234");
  });

  it("sends short aliases, maps answers back, and re-asks only the unanswered findings", async () => {
    const { user, job, ids } = await fixedJob("rv-alias", {
      "src/view.ts": 'export function render(el: HTMLElement, name: string) {\n  el.innerHTML = "<b>" + name + "</b>";\n}\n',
      "src/card.ts": 'export function card(el: HTMLElement, title: string) {\n  el.innerHTML = "<h2>" + title + "</h2>";\n}\n',
    });
    expect(ids.length).toBe(2);
    const asked: string[][] = [];
    const llmCall = vi.fn(async (_s: string, u: string) => {
      const sentIds = (JSON.parse(u).findings as { id: string }[]).map((f) => f.id);
      asked.push(sentIds);
      const answer = (alias: string) => ({ findingId: alias, verdict: "inconclusive", summary: `answer ${asked.length}`, evidence: [] });
      // 첫 호출: 한 개만 답하고 한 개는 틀린 별칭으로 돌려준다. 두 번째 호출: 남은 하나에 답한다.
      const results = asked.length === 1 ? [answer("F1"), answer("F9")] : [answer("F1")];
      return { correlationId: "c", text: JSON.stringify({ results }) };
    });
    const out = await reverifyFixJob(job.id, user.id, { llmConfigured: true, llmCall, exploitGen: noExploit });
    expect(asked).toEqual([["F1", "F2"], ["F1"]]);
    for (const it of out.verification!.items) {
      expect(it.reasonCode).not.toBe("no_answer");
      expect(it.aiSummary).toMatch(/^answer [12]$/);
    }
    expect(out.verification!.items.map((i) => i.aiSummary).sort()).toEqual(["answer 1", "answer 2"]);
  });

  it("rule and AI agreeing gives a rule+llm verdict", async () => {
    const { user, job, ids } = await fixedJob("rv-agree", XSS_FILES);
    const out = await reverifyFixJob(job.id, user.id, {
      llmConfigured: true,
      exploitGen: noExploit,
      llmCall: aiAnswer([
        {
          findingId: ids[0],
          verdict: "fixed_in_source",
          summary: "ok",
          evidence: [{ role: "mitigation", file: "src/view.ts", snippet: "el.textContent = name;", explanation: "text" }],
        },
      ]),
    });
    const it = out.verification!.items[0];
    expect(it.verdict).toBe("fixed_in_source");
    expect(it.method).toBe("rule+llm");
    expect(it.ruleVerdict).toBe("fixed_in_source");
    expect(it.aiVerdict).toBe("fixed_in_source");
  });

  it("rule and AI disagreeing is disputed, not decided by either", async () => {
    const { user, job, ids } = await fixedJob("rv-dispute", XSS_FILES);
    const out = await reverifyFixJob(job.id, user.id, {
      llmConfigured: true,
      exploitGen: noExploit,
      llmCall: aiAnswer([
        {
          findingId: ids[0],
          verdict: "still_present",
          summary: "name still flows into HTML elsewhere",
          evidence: [
            { role: "vulnerable_code", file: "src/view.ts", snippet: "export function render(el: HTMLElement, name: string) {", explanation: "x" },
          ],
        },
      ]),
    });
    const it = out.verification!.items[0];
    expect(it.verdict).toBe("inconclusive");
    expect(it.reasonCode).toBe("disputed");
    expect(it.ruleVerdict).toBe("fixed_in_source");
    expect(it.aiVerdict).toBe("still_present");
    expect(fixStatusFor(it.findingId, { item: { findingId: it.findingId, outcome: "applied" }, verification: out.verification! }).label).toBe(
      "판단이 엇갈려요"
    );
  });

  it("LLM failure is reported as failed, not success", async () => {
    const { user, job } = await fixedJob("rv-fail", XSS_FILES);
    const out = await reverifyFixJob(job.id, user.id, {
      llmConfigured: true,
      exploitGen: noExploit,
      orchestrator: new SecurityOrchestrator([]), // no rule re-check: force the AI path
      llmCall: async () => {
        throw new Error("boom");
      },
    });
    expect(out.verification!.status).toBe("failed");
    expect(out.verification!.aiStatus).toBe("failed");
    expect(out.verification!.items.every((i) => i.verdict === "inconclusive" && i.reasonCode === "ai_failed")).toBe(true);
    expect(out.verification!.sentFiles).toEqual(["src/view.ts"]);
  });

  it("accepts AI-only verdicts only with snippets that exist in the fixed file", async () => {
    const { user, job, ids } = await fixedJob("rv-llm", XSS_FILES);
    const out = await reverifyFixJob(job.id, user.id, {
      llmConfigured: true,
      exploitGen: noExploit,
      orchestrator: new SecurityOrchestrator([]),
      llmCall: aiAnswer([
        {
          findingId: ids[0],
          verdict: "fixed_in_source",
          summary: "ok",
          evidence: [{ role: "mitigation", file: "src/view.ts", snippet: "el.textContent = name;", explanation: "text" }],
        },
        { findingId: "made-up-id", verdict: "fixed_in_source", evidence: [] },
      ]),
    });
    const items = out.verification!.items;
    expect(items.find((i) => i.findingId === ids[0])!.verdict).toBe("fixed_in_source");
    expect(items.find((i) => i.findingId === ids[0])!.method).toBe("llm");
    expect(items.some((i) => i.findingId === "made-up-id")).toBe(false);
  });

  it("blocks other users", async () => {
    const { job } = await fixedJob("rv-own", SECRET_FILES);
    const other = await createUser({ email: `o-${Date.now()}@example.test`, passwordHash: "x:y" });
    await expect(reverifyFixJob(job.id, other.id)).rejects.toBeInstanceOf(NotAuthorizedError);
  });
});

describe("false-positive adjudication at re-verify", () => {
  it("an AI 'not vulnerable' verdict with code evidence marks a flagged rule finding as a false positive", async () => {
    const { user, job, ids } = await fixedJob("rv-fp", XSS_FILES);
    // The memory store returns stored objects: simulate the scan-time AI flag.
    const f = (await getFindingsForScan(job.scanId, user.id)).find((x) => x.id === ids[0])!;
    f.aiReview = { verdict: "likely_false_positive", reason: "상수" };
    let asked: { question?: string } | undefined;
    const out = await reverifyFixJob(job.id, user.id, {
      llmConfigured: true,
      exploitGen: noExploit,
      llmCall: async (_s, u) => {
        asked = (JSON.parse(u) as { findings: { question?: string }[] }).findings[0];
        return {
          correlationId: "c",
          text: JSON.stringify({
            results: [
              {
                findingId: ids[0],
                verdict: "not_vulnerable",
                summary: "name은 서버 상수라 공격자가 바꿀 수 없어요.",
                evidence: [{ role: "safe_code", file: "src/view.ts", snippet: "el.textContent = name;", explanation: "text" }],
              },
            ],
          }),
        };
      },
    });
    expect(asked?.question).toBe("is_vulnerability");
    const it = out.verification!.items[0];
    expect(it.verdict).toBe("false_positive");
    expect(it.aiSummary).toContain("서버 상수");
    expect(fixStatusFor(it.findingId, { verification: out.verification! }).label).toBe("오탐으로 판정됐어요");
  });

  it("'not vulnerable' is ignored for findings that were not flagged", () => {
    const finding = { id: "f1", title: "t", severity: "high" } as SecurityFinding;
    const version = { files: { "a.ts": "const safe = escape(input);\n" } } as unknown as SourceVersion;
    const raw = { verdict: "not_vulnerable", evidence: [{ role: "safe_code", file: "a.ts", snippet: "const safe = escape(input);" }] };
    expect(validateLlmResult(finding, raw, version, new Set(["a.ts"]), false).verdict).toBe("inconclusive");
    expect(validateLlmResult(finding, raw, version, new Set(["a.ts"]), true).verdict).toBe("false_positive");
  });
});

describe("exploit tests in the verdict", () => {
  const f = { id: "f", title: "t", severity: "high", verificationKey: "ai:a.js:1" } as SecurityFinding;
  const item = (verdict: ReverifyItem["verdict"], method: ReverifyItem["method"]): ReverifyItem => ({
    findingId: "f", title: "t", severity: "high", verdict, method, evidence: [],
  });

  it("an exploit blocked on the fix confirms an otherwise undecided item", () => {
    const r = mergeVerdicts(f, undefined, undefined, "failed", { status: "blocked", detail: "d" });
    expect(r.verdict).toBe("fixed_in_source");
    expect(r.method).toBe("exploit");
    expect(r.executed).toBe(true);
  });

  it("an exploit that still works overrides a 'fixed' verdict", () => {
    const r = mergeVerdicts(f, undefined, item("fixed_in_source", "llm"), "completed", { status: "still_exploitable", detail: "d" });
    expect(r.verdict).toBe("still_present");
    expect(fixStatusFor("f", { item: { findingId: "f", outcome: "applied" }, verification: { status: "completed", items: [r] } }).label).toBe("아직 남아 있어요");
  });

  it("an exploit that did not reproduce on the original is not used", () => {
    const r = mergeVerdicts(f, undefined, item("fixed_in_source", "llm"), "completed", { status: "not_reproduced", detail: "d" });
    expect(r.verdict).toBe("fixed_in_source");
    expect(r.executed).toBeUndefined();
  });

  it("re-verify runs the exploit check for applied code findings", async () => {
    const { user, job, ids } = await fixedJob("rv-exploit", XSS_FILES);
    const run = vi.fn(async () => ({ status: "blocked" as const, detail: "막힘" }));
    const out = await reverifyFixJob(job.id, user.id, {
      llmConfigured: true,
      llmCall: aiAnswer([]),
      exploitGen: async () => ({ kind: "test" as const, code: "module.exports = async () => ({ attackSucceeded: false })", attack: "a", correlationId: "c" }),
      exploitRun: run,
    });
    expect(run).toHaveBeenCalledTimes(1);
    const it = out.verification!.items.find((i) => i.findingId === ids[0])!;
    expect(it.exploit?.status).toBe("blocked");
    expect(it.executed).toBe(true);
  });
});

describe("mergeVerdicts", () => {
  const f = { id: "f", title: "t", severity: "high", verificationKey: "xss:a.ts:1" } as SecurityFinding;
  const item = (verdict: ReverifyItem["verdict"], method: ReverifyItem["method"]): ReverifyItem => ({
    findingId: "f", title: "t", severity: "high", verdict, method, evidence: [],
  });

  it("an inconclusive AI answer never overrides the rule", () => {
    const r = mergeVerdicts(f, item("still_present", "rule"), item("inconclusive", "llm"), "completed");
    expect(r.verdict).toBe("still_present");
    expect(r.method).toBe("rule");
  });

  it("dependency items without a rule answer stay inconclusive (no AI)", () => {
    const dep = { ...f, verificationKey: "dep:lodash" } as SecurityFinding;
    const r = mergeVerdicts(dep, undefined, undefined, "not_needed");
    expect(r.verdict).toBe("inconclusive");
    expect(r.reasonCode).toBe("dep_recheck_unavailable");
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
  it("maps outcomes and verdicts to distinct labels", () => {
    expect(fixStatusFor("f", {}).label).toBe("점검이 필요해요");
    expect(
      fixStatusFor("f", { jobStatus: "running", item: { findingId: "f", outcome: "skipped", reasonCode: "pending" } }).label
    ).toBe("지금 수정해요");
    // Not applying a fix is not a failed resolution.
    expect(fixStatusFor("f", { item: { findingId: "f", outcome: "apply_failed" } }).label).toBe("자동으로 못 고쳤어요");
    expect(fixStatusFor("f", { item: { findingId: "f", outcome: "unsupported" } }).label).toBe("자동으로 못 고쳤어요");
    // An adjudicated false positive shows the ruling even though fix-all skipped it.
    expect(
      fixStatusFor("f", { adjudicatedFalsePositive: true, item: { findingId: "f", outcome: "unsupported", reasonCode: "disputed_at_scan" } }).label
    ).toBe("오탐으로 판정됐어요");
    const applied = { findingId: "f", outcome: "applied" as const };
    const verified = (it: Record<string, unknown>) =>
      fixStatusFor("f", { item: applied, verification: { status: "completed", items: [{ findingId: "f", ...it } as never] } }).label;
    expect(fixStatusFor("f", { item: applied }).label).toBe("점검이 필요해요");
    expect(verified({ verdict: "fixed_in_source", method: "rule" })).toBe("해결 확인했어요");
    expect(verified({ verdict: "fixed_in_source", method: "rule+llm" })).toBe("해결 확인했어요");
    expect(verified({ verdict: "fixed_in_source", method: "llm" })).toBe("AI가 해결로 판단했어요");
    expect(verified({ verdict: "still_present", method: "rule" })).toBe("아직 남아 있어요");
    expect(verified({ verdict: "inconclusive", reasonCode: "disputed" })).toBe("판단이 엇갈려요");
    expect(
      fixStatusFor("f", { item: applied, verification: { status: "failed", items: [{ findingId: "f", verdict: "inconclusive", reasonCode: "ai_failed" }] } }).label
    ).toBe("점검이 필요해요");
  });
});
