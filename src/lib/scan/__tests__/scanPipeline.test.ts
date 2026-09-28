import { describe, expect, it } from "vitest";
import { createProject, createUser, getCurrentSourceVersion, getProject, addSourceVersion, saveCustomRule, listCustomRules } from "@/lib/store/store";
import { MemoryStore } from "@/lib/store/memoryStore";
import { SecurityOrchestrator } from "@/lib/scanners/orchestrator";
import { runScanPipeline } from "@/lib/scan/scanPipeline";
import { CustomRuleScanner, matchLines, validateProposal } from "@/lib/rules/customRules";
import type { CustomRule, SecurityFinding } from "@/lib/domain/types";
import type { ProjectContext, SecurityScanner } from "@/lib/scanners/types";

// Fake fixtures only. The "AI" is a stand-in scanner so no model is called.
function fakeAi(seen: { scopes: (string[] | undefined)[] }): SecurityScanner {
  return {
    name: "ai-code-scanner",
    displayName: "fake ai",
    step: "static_analysis",
    simulated: false,
    isApplicable: async () => true,
    scan: async (ctx: ProjectContext) => {
      seen.scopes.push(ctx.aiScope);
      return Object.keys(ctx.files)
        .filter((p) => p.endsWith(".js") && (!ctx.aiScope || ctx.aiScope.includes(p)))
        .map((p) => ({
          id: `f-${p}-${Math.random()}`,
          scanId: "",
          title: "쿼리에 입력값이 직접 들어감",
          severity: "high",
          category: "AI Detected",
          cwe: "CWE-89",
          description: "",
          humanReadableImpact: "",
          whyItMatters: "",
          location: { file: p, line: 1 },
          evidence: [{ id: "e", kind: "source_code", label: p, content: ctx.files[p].split("\n")[0] }],
          status: "detected",
          simulated: false,
          verificationKey: `ai:${p}:1`,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        })) as SecurityFinding[];
    },
  };
}

const FILES = {
  "a.js": 'db.run("DELETE FROM t WHERE id=" + req.query.id);\nconst ok = 1;',
  "b.js": 'db.run("UPDATE t SET x=1 WHERE id=" + req.body.id);\nconst ok = 2;',
};

async function setup(tag: string) {
  const user = await createUser({ email: `${tag}-${Date.now()}-${Math.random()}@example.test`, passwordHash: "x:y" });
  const project = await createProject(user.id, { name: tag, files: FILES, sourceKind: "paste" });
  return { user, project };
}

describe("AI-proposed rules", () => {
  const finding = { id: "f1", severity: "high", title: "t", location: { file: "a.js", line: 1 } } as SecurityFinding;
  const owner = { ownerId: "u", projectId: "p" };

  it("accepts a specific rule that matches its own line", () => {
    const rule = validateProposal({ pattern: 'db\\.run\\(\\s*"[^"]*"\\s*\\+', title: "SQL 문자열 연결", severity: "high" }, finding, FILES, owner);
    expect(rule).not.toBeNull();
    expect(rule!.status).toBe("proposed");
    expect(rule!.preview.map((p) => p.file)).toEqual(["a.js", "b.js"]);
  });

  it("rejects rules that miss their line, are too broad, use bad flags, or backtrack forever", () => {
    expect(validateProposal({ pattern: "SELECT" }, finding, FILES, owner)).toBeNull();
    expect(validateProposal({ pattern: "const" }, finding, { ...FILES, "c.js": "const a=1\nconst b=2\nconst c=3\nconst d=4" }, owner)).toBeNull();
    expect(validateProposal({ pattern: "db", flags: "g" }, finding, FILES, owner)?.flags ?? "").toBe("");
    expect(validateProposal({ pattern: "db", flags: "x" }, finding, FILES, owner)).toBeNull();
    const slow = matchLines({ pattern: "^(a+)+$", flags: "" }, { "x.js": "a".repeat(40) + "b" }, 100);
    expect(slow.timedOut).toBe(true);
  });

  it("approved rules run as baseline findings and re-verify per finding", async () => {
    const rule = validateProposal({ pattern: 'db\\.run\\(\\s*"[^"]*"\\s*\\+' }, finding, FILES, owner)!;
    const scanner = new CustomRuleScanner();
    const ctx = (files: Record<string, string>, baselineFiles?: Record<string, string>): ProjectContext => ({
      projectId: "p", name: "p", stack: { frameworks: [], languages: [], hasEnvFile: false }, files, isUserProject: true,
      customRules: [{ ...rule, status: "approved" } as CustomRule], baselineFiles,
    });
    const found = await scanner.scan(ctx(FILES));
    expect(found.map((f) => f.location)).toEqual([{ file: "a.js", line: 1 }, { file: "b.js", line: 1 }]);
    const fixed = { ...FILES, "a.js": 'db.run("DELETE FROM t WHERE id=?", [req.query.id]);\nconst ok = 1;' };
    expect((await scanner.verify(found[0], ctx(fixed, FILES))).security.outcome).toBe("pass");
    expect((await scanner.verify(found[1], ctx(fixed, FILES))).security.outcome).toBe("fail");
    // A proposed (not approved) rule does not run.
    expect(await new CustomRuleScanner().isApplicable({ ...ctx(FILES), customRules: [rule] })).toBe(false);
  });

  it("the pipeline proposes validated rules from AI-only findings", async () => {
    const { user, project } = await setup("propose");
    const version = await getCurrentSourceVersion(project.id, user.id);
    const out = await runScanPipeline({
      backend: new MemoryStore(),
      project,
      version,
      ownerId: user.id,
      orchestrator: new SecurityOrchestrator([fakeAi({ scopes: [] })]),
      opts: {
        llmConfigured: true,
        proposeComplete: async (_s, u) => {
          const ids = (JSON.parse(u) as { findings: { id: string }[] }).findings.map((f) => f.id);
          return JSON.stringify({
            proposals: [
              { findingId: ids[0], title: "SQL 문자열 연결", pattern: 'db\\.run\\(\\s*"[^"]*"\\s*\\+', severity: "high" },
              { findingId: ids[1], title: "너무 넓음", pattern: "." },
            ],
          });
        },
      },
    });
    expect(out.proposals).toHaveLength(1);
    expect(out.proposals[0]).toMatchObject({ status: "proposed", ownerId: user.id, projectId: project.id });
    // Approving it makes the next scan run it as a rule.
    await saveCustomRule({ ...out.proposals[0], status: "approved" });
    expect((await listCustomRules(user.id)).some((r) => r.status === "approved")).toBe(true);
  });
});

describe("incremental scan after re-upload", () => {
  it("AI re-reads only changed files and carries over the rest", async () => {
    const { user, project } = await setup("incremental");
    const seen = { scopes: [] as (string[] | undefined)[] };
    const memory = new MemoryStore();
    (memory as unknown as { orchestrator: SecurityOrchestrator }).orchestrator = new SecurityOrchestrator([fakeAi(seen)]);

    const first = await memory.runScan(project.id, user.id);
    expect(seen.scopes[0]).toBeUndefined();

    await addSourceVersion(project.id, user.id, { ...FILES, "b.js": 'db.run("UPDATE t SET x=2 WHERE id=" + req.body.id);\nconst ok = 3;' }, { sourceKind: "paste" });
    expect((await getProject(project.id, user.id)).currentSourceVersionId).toBeTruthy();
    const second = await memory.runScan(project.id, user.id);

    expect(seen.scopes[1]).toEqual(["b.js"]);
    expect(second.scope.incremental).toMatchObject({ previousScanId: first.id, changedFiles: ["b.js"], unchangedFiles: 1, carriedOver: 1 });
    const findings = await memory.getFindingsForScan(second.id, user.id);
    const a = findings.find((f) => f.location?.file === "a.js")!;
    const b = findings.find((f) => f.location?.file === "b.js")!;
    expect(a.carriedOverFromScanId).toBe(first.id);
    expect(b.carriedOverFromScanId).toBeUndefined();
  });
});
