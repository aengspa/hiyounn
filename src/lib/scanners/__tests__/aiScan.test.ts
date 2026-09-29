import { describe, expect, it, vi } from "vitest";
import { AiCodeScanner } from "@/lib/scanners/aiCodeScanner";
import { planChunks, riskScore, buildProjectMap } from "@/lib/scanners/aiScanPlanner";
import { mergeAiIntoRules, issueClass } from "@/lib/scanners/findingMerge";
import { redactSecrets } from "@/lib/ai/redact";
import { LlmError } from "@/lib/ai/llmClient";
import { LIMITS } from "@/lib/config/limits";
import type { SecurityFinding } from "@/lib/domain/types";
import type { ProjectContext } from "@/lib/scanners/types";

// Fake fixtures only; the model is replaced by `complete`.
function ctx(files: Record<string, string>): ProjectContext {
  return { projectId: "p", name: "p", stack: { frameworks: [], languages: [], hasEnvFile: false }, files, isUserProject: true };
}

const ROUTES = [
  'const router = require("express").Router();',
  'router.get("/:orderId", async (req, res) => {',
  "  const order = await orders.findById(req.params.orderId);",
  "  res.json(order);",
  "});",
].join("\n");

function answer(findings: unknown[], ruleReviews: unknown[] = []) {
  return JSON.stringify({ findings, ruleReviews });
}

/** The route-table call runs in parallel with the chunk calls; answer it separately. */
const isTableCall = (system: string) => system.includes("map every HTTP route");

function ruleFinding(over: Partial<SecurityFinding>): SecurityFinding {
  return {
    id: "r1",
    scanId: "",
    title: "rule",
    severity: "high",
    category: "Injection",
    description: "",
    humanReadableImpact: "",
    whyItMatters: "",
    evidence: [],
    status: "detected",
    simulated: false,
    createdAt: "",
    updatedAt: "",
    ...over,
  };
}

describe("AI scan planning", () => {
  it("reviews risky files first and records what it could not send", () => {
    const files = {
      "src/utils/format.js": "export const f = (x) => x;",
      "src/routes/orders.js": ROUTES,
      "src/__tests__/a.test.js": "test('x', () => {})",
      "big.js": "x".repeat(1_000),
      "README.md": "docs",
    };
    expect(riskScore("src/routes/orders.js", ROUTES)).toBeGreaterThan(riskScore("src/utils/format.js", files["src/utils/format.js"]));
    const plan = planChunks(files, { chunkChars: 250, maxChunks: 1, fileChars: 500 });
    expect(plan.total).toBe(4); // README is not code
    expect(plan.chunks[0][0]).toBe("src/routes/orders.js");
    expect(plan.omitted).toContainEqual({ path: "big.js", reason: "too_large" });
    expect(plan.omitted.some((o) => o.reason === "over_budget")).toBe(true);
  });

  it("the project map lists route declarations across files", () => {
    const map = buildProjectMap({ "src/app.js": 'app.use("/api/admin", requireLogin, require("./routes/admin"));' });
    expect(map).toContain('src/app.js:1: app.use("/api/admin", requireLogin');
  });
});

describe("AiCodeScanner.scanWithReport", () => {
  const scanner = new AiCodeScanner();

  it("keeps only findings whose code exists, and takes the line from the file", async () => {
    const complete = vi.fn(async (system: string) =>
      isTableCall(system) ? JSON.stringify({ routes: [] }) : answer([
        { title: "다른 사용자의 주문 조회", severity: "high", cwe: "CWE-639", file: "src/routes/orders.js", line: 9, codeSnippet: "const order = await orders.findById(req.params.orderId);" },
        { title: "invented", severity: "high", file: "src/routes/orders.js", line: 1, codeSnippet: "db.dropEverything(req.body)" },
      ])
    );
    const r = await scanner.scanWithReport(ctx({ "src/routes/orders.js": ROUTES }), { complete });
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].location).toEqual({ file: "src/routes/orders.js", line: 3 });
    // One chunk call + one route-table call.
    expect(r.coverage).toMatchObject({ status: "complete", filesTotal: 1, filesReviewed: 1, calls: 2 });
  });

  it("never sends secret values to the model", async () => {
    const secret = "sk_live_" + "Z".repeat(24);
    let sent = "";
    const complete = async (_s: string, user: string) => {
      sent = user;
      return answer([]);
    };
    await scanner.scanWithReport(ctx({ "src/pay.js": `const k = "${secret}";\n${ROUTES}` }), { complete });
    expect(sent).not.toContain(secret);
    expect(sent).toContain("__HOI_REDACTED_SECRET_1__");
  });

  it("attaches validated reviews to rule findings", async () => {
    const rules = [ruleFinding({ id: "r1", location: { file: "src/routes/orders.js", line: 3 } })];
    const complete = async () =>
      answer([], [
        { id: "r1", verdict: "likely_false_positive", reason: "상수만 씀" },
        { id: "not-a-rule", verdict: "confirmed" },
      ]);
    const r = await scanner.scanWithReport(ctx({ "src/routes/orders.js": ROUTES }), { complete, ruleFindings: rules });
    expect([...r.ruleReviews.entries()]).toEqual([["r1", { verdict: "likely_false_positive", reason: "상수만 씀" }]]);
  });

  it("does not ask the AI to judge secret findings it can only see masked", async () => {
    const rules = [
      ruleFinding({ id: "s1", verificationKey: "secret:src/routes/orders.js:3", location: { file: "src/routes/orders.js", line: 3 } }),
      ruleFinding({ id: "r1", location: { file: "src/routes/orders.js", line: 3 } }),
    ];
    let sent = "";
    const complete = async (_s: string, user: string) => {
      sent = user;
      return answer([]);
    };
    await scanner.scanWithReport(ctx({ "src/routes/orders.js": ROUTES }), { complete, ruleFindings: rules });
    expect(sent).toContain('"id":"r1"');
    expect(sent).not.toContain('"id":"s1"');
  });

  it("a failed chunk is a coverage gap, not zero findings", async () => {
    const files = { "src/routes/a.js": ROUTES, "src/routes/b.js": ROUTES.replace("orderId", "itemId") };
    let n = 0;
    const complete = async (system: string) => {
      if (isTableCall(system)) return JSON.stringify({ routes: [] });
      n += 1;
      if (n === 1) throw new LlmError("timeout", "c");
      return answer([]);
    };
    const r = await scanner.scanWithReport(ctx(files), {
      complete,
      limits: { ...LIMITS, aiScanChunkChars: 300, aiScanConcurrency: 1 },
    });
    expect(r.coverage.status).toBe("partial");
    expect(r.coverage.filesReviewed).toBe(1);
    expect(r.coverage.omitted).toEqual([{ path: expect.any(String), reason: "call_failed" }]);
  });

  it("an auth failure stops the remaining calls", async () => {
    const files = { "src/routes/a.js": ROUTES, "src/routes/b.js": ROUTES, "src/routes/c.js": ROUTES };
    const complete = vi.fn(async () => {
      throw new LlmError("auth_failed", "c", 401);
    });
    const r = await scanner.scanWithReport(ctx(files), {
      complete,
      limits: { ...LIMITS, aiScanChunkChars: 300, aiScanConcurrency: 1 },
    });
    // The route-table call and the first chunk start together; nothing after the failure.
    expect(complete.mock.calls.length).toBeLessThanOrEqual(2);
    expect(r.coverage.status).toBe("failed");
    expect(r.coverage.omitted.every((o) => o.reason === "ai_unavailable")).toBe(true);
  });
});

describe("merging AI findings into rule findings", () => {
  it("merges the same issue nearby and keeps AI-only issues", () => {
    const rules = [ruleFinding({ id: "r", cwe: "CWE-89", location: { file: "a.js", line: 7 } })];
    const ai = [
      ruleFinding({ id: "a1", title: "SQL", cwe: "CWE-89", location: { file: "a.js", line: 8 } }),
      ruleFinding({ id: "a2", title: "SSRF", cwe: "CWE-918", location: { file: "a.js", line: 8 } }),
    ];
    const { aiKept, merged } = mergeAiIntoRules(rules, ai);
    expect(merged).toBe(1);
    expect(aiKept.map((f) => f.id)).toEqual(["a2"]);
    expect(rules[0].aiReview).toEqual({ verdict: "confirmed", reason: "SQL" });
  });

  it("classifies by CWE first, then by words", () => {
    expect(issueClass({ cwe: "CWE-78", title: "", category: "" })).toBe("cmd");
    expect(issueClass({ title: "관리자 삭제 기능에 관리자 확인이 없음", category: "" })).toBe("authz");
  });
});

describe("redactSecrets", () => {
  it("masks the same value consistently and restores it", () => {
    const secret = "sk_live_" + "A".repeat(24);
    const r = redactSecrets({ "a.js": `const x = "${secret}";`, "b.js": `use("${secret}")` });
    expect(r.count).toBe(1);
    expect(r.files["a.js"]).toBe('const x = "__HOI_REDACTED_SECRET_1__";');
    expect(r.restore(r.files["b.js"])).toBe(`use("${secret}")`);
    expect(r.redactText(`key ${secret}`)).toBe("key __HOI_REDACTED_SECRET_1__");
  });
});

describe("route permission table", () => {
  it("keeps only rows whose route line exists and turns gaps into findings", async () => {
    const { validateAuthzRoutes, findingsFromAuthzMatrix } = await import("@/lib/scanners/authzMatrix");
    const files = {
      "src/routes/admin.js": 'const router = require("express").Router();\nrouter.delete("/users/:userId", async (req, res) => {\n  await users.deleteUser(req.params.userId);\n});\n',
    };
    const rows = validateAuthzRoutes(
      {
        routes: [
          { method: "DELETE", path: "/api/admin/users/:userId", file: "src/routes/admin.js", snippet: 'router.delete("/users/:userId", async (req, res) => {', auth: "required", admin: "none", ownership: "n/a", mutates: true },
          { method: "GET", path: "/api/invented", file: "src/routes/admin.js", snippet: 'router.get("/invented", handler);', auth: "none", admin: "n/a", ownership: "n/a" },
          { method: "PATCH", path: "/x", file: "src/routes/admin.js", snippet: 'router.delete("/users/:userId", async (req, res) => {', auth: "maybe", admin: "n/a", ownership: "n/a" },
        ],
      },
      files
    );
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({ line: 2, auth: "required", admin: "none" });
    expect(rows[1].auth).toBe("unknown");
    const findings = findingsFromAuthzMatrix(rows);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ cwe: "CWE-285", severity: "critical", location: { file: "src/routes/admin.js", line: 2 } });
    expect(rows[0].findingIds).toEqual([findings[0].id]);
  });

  it("does not flag routes that are public by design", async () => {
    const { validateAuthzRoutes, findingsFromAuthzMatrix } = await import("@/lib/scanners/authzMatrix");
    const files = { "src/routes/reset.js": 'router.post("/request", async (req, res) => {\n});\n' };
    const rows = validateAuthzRoutes(
      { routes: [{ method: "POST", path: "/api/reset/request", file: "src/routes/reset.js", snippet: 'router.post("/request", async (req, res) => {', auth: "public", admin: "n/a", ownership: "n/a", mutates: true }] },
      files
    );
    expect(rows[0].auth).toBe("public");
    expect(findingsFromAuthzMatrix(rows)).toHaveLength(0);
    // Even if the model says "none", a reset-request path is public by design.
    const saidNone = validateAuthzRoutes({ routes: [{ ...rows[0], auth: "none" }] }, files);
    expect(saidNone[0].auth).toBe("public");
    expect(findingsFromAuthzMatrix(saidNone)).toHaveLength(0);
    // A normal mutating route without login is still a gap.
    const orders = { "src/routes/orders.js": 'router.post("/orders", async (req, res) => {\n});\n' };
    const gap = validateAuthzRoutes({ routes: [{ method: "POST", path: "/api/orders", file: "src/routes/orders.js", snippet: 'router.post("/orders", async (req, res) => {', auth: "none", admin: "n/a", ownership: "n/a", mutates: true }] }, orders);
    expect(findingsFromAuthzMatrix(gap).map((f) => f.cwe)).toEqual(["CWE-306"]);
  });

  it("admin functions are judged by the admin check, not ownership", async () => {
    const { findingsFromAuthzMatrix } = await import("@/lib/scanners/authzMatrix");
    const row = { method: "DELETE", path: "/api/admin/users/:userId", file: "a.js", line: 1, snippet: "x", auth: "required" as const, admin: "none" as const, ownership: "missing" as const, mutates: true };
    expect(findingsFromAuthzMatrix([row]).map((f) => f.cwe)).toEqual(["CWE-285"]);
  });

  it("the scan returns the table from a parallel AI call", async () => {
    const scanner = new AiCodeScanner();
    const complete = vi.fn(async (system: string) =>
      system.includes("map every HTTP route")
        ? JSON.stringify({ routes: [{ method: "GET", path: "/orders/:orderId", file: "src/routes/orders.js", snippet: 'router.get("/:orderId", async (req, res) => {', auth: "required", admin: "n/a", ownership: "missing" }] })
        : answer([])
    );
    const r = await scanner.scanWithReport(ctx({ "src/routes/orders.js": ROUTES }), { complete });
    expect(r.authzMatrix).toHaveLength(1);
    expect(r.authzFindings.map((f) => f.cwe)).toEqual(["CWE-639"]);
  });
});

describe("scan-time adjudication", () => {
  it("accepts 'not vulnerable' only with code that exists", async () => {
    const { validateAdjudication } = await import("@/lib/scanners/aiCodeScanner");
    const files = { "a.js": 'await fetch(process.env.MAIL_API_URL, { method: "POST" });\n' };
    const ids = new Set(["r1"]);
    const ok = validateAdjudication(
      { id: "r1", verdict: "not_vulnerable", reason: "환경변수 주소", evidence: [{ file: "a.js", snippet: "await fetch(process.env.MAIL_API_URL, { method: \"POST\" });" }] },
      ids,
      files
    );
    expect(ok?.adjudication.verdict).toBe("not_vulnerable");
    const invented = validateAdjudication({ id: "r1", verdict: "not_vulnerable", reason: "x", evidence: [{ file: "a.js", snippet: "validateUrl(target)" }] }, ids, files);
    expect(invented?.adjudication.verdict).toBe("unsure");
    expect(validateAdjudication({ id: "other", verdict: "vulnerable" }, ids, files)).toBeNull();
  });
});

describe("AI prompt response schemas", () => {
  // Wording may change; the JSON contract the parsers rely on must not.
  it("scan prompt keeps its field names and enum values", async () => {
    const { AI_SCAN_SYSTEM_PROMPT: p } = await import("@/lib/scanners/aiCodeScanner");
    for (const key of ["findings", "title", "severity", "category", "owasp", "cwe", "humanReadableImpact", "whyItMatters", "file", "line", "codeSnippet", "remediation", "ruleReviews", "id", "verdict", "reason"]) {
      expect(p).toContain(`"${key}":`);
    }
    expect(p).toContain('"severity": "critical|high|medium|low"');
    expect(p).toContain('"verdict": "confirmed|likely_false_positive|unsure"');
    expect(p).toContain('"category": "취약점 분류(영문 표준 명칭)"');
    expect(p).toContain('"owasp": "OWASP 분류(예: A01 - Broken Access Control) 또는 빈 문자열"');
    expect(p).toContain('"cwe": "CWE 번호(예: CWE-89) 또는 빈 문자열"');
    expect(p).toContain('"codeSnippet": "문제되는 코드를 파일에서 글자 그대로 복사(최소 한 줄 전체)"');
    expect(p).toContain("__HOI_REDACTED_SECRET_숫자__");
    expect(p).toContain('{"findings": [], "ruleReviews": [...]}');
    // The e2e mock gateway routes calls by this sentence.
    expect(p).toContain("시니어 애플리케이션 보안 엔지니어");
  });

  it("adjudication prompt keeps its verdicts and evidence fields", async () => {
    const { AI_ADJUDICATE_SYSTEM_PROMPT: p } = await import("@/lib/scanners/aiCodeScanner");
    expect(p).toContain('"verdict": "not_vulnerable" | "vulnerable" | "unsure"');
    for (const key of ["results", "id", "reason", "evidence", "file", "snippet", "explanation"]) expect(p).toContain(`"${key}":`);
    expect(p).toContain("final reviewer for rule-based");
  });

  it("verify prompt keeps its verdicts, roles and fields", async () => {
    const { AI_VERIFY_SYSTEM_PROMPT: p } = await import("@/lib/scanners/aiCodeScanner");
    expect(p).toContain('"verdict": "still_present|fixed|inconclusive"');
    expect(p).toContain('"role": "vulnerable_code|mitigation"');
    expect(p.match(/"verdict": "preserved\|broken\|inconclusive"/g)).toHaveLength(2);
    for (const key of ["summary", "evidence", "file", "snippet", "explanation", "regression", "checks", "label", "expectation"]) {
      expect(p).toContain(`"${key}":`);
    }
    expect(p).toContain("originalFinding");
  });

  it("route-table prompt keeps its enum values", async () => {
    const { AUTHZ_SYSTEM_PROMPT: p } = await import("@/lib/scanners/authzMatrix");
    expect(p).toContain("map every HTTP route");
    expect(p).toContain('"auth": "required" | "public" | "none" | "unknown"');
    expect(p).toContain('"admin": "required" | "none" | "n/a" | "unknown"');
    expect(p).toContain('"ownership": "checked" | "missing" | "n/a" | "unknown"');
    expect(p).toContain('"notes":');
  });
});

describe("merging related classes", () => {
  it("merges weak-random and weak-crypto only on the exact same line", async () => {
    const { mergeCorroborating } = await import("@/lib/scanners/findingMerge");
    const rule = [ruleFinding({ id: "r", cwe: "CWE-338", location: { file: "reset.js", line: 8 } })];
    const same = mergeCorroborating(rule, [ruleFinding({ id: "s1", cwe: "CWE-327", location: { file: "reset.js", line: 8 } })], "semgrep");
    expect(same.merged).toBe(1);
    expect(rule[0].corroboratedBy).toEqual(["semgrep"]);
    const near = mergeCorroborating(rule, [ruleFinding({ id: "s2", cwe: "CWE-327", location: { file: "reset.js", line: 9 } })], "semgrep");
    expect(near.merged).toBe(0);
  });
});
