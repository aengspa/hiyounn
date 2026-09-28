import { describe, expect, it } from "vitest";
import { StaticWebScanner } from "@/lib/scanners/staticWebScanner";
import { SecretScanner, findSecretMatches } from "@/lib/scanners/secretScanner";
import { stillPresentAfterFix } from "@/lib/scanners/findingPresence";
import type { ProjectContext } from "@/lib/scanners/types";

// 가짜 Stripe 키. 한 덩어리 리터럴로 두면 GitHub push protection이 실제 키로 보고 push를 막는다.
const FAKE_STRIPE_KEY = ["sk", "live", "51HxQpLKj3n4Vb8ZtQwErTyUiOpAsDfGh"].join("_");

// Fake fixtures only.
function ctx(files: Record<string, string>, baselineFiles?: Record<string, string>): ProjectContext {
  return {
    projectId: "p",
    name: "p",
    stack: { frameworks: [], languages: [], hasEnvFile: false },
    files,
    isUserProject: true,
    baselineFiles,
  };
}

// The pasted app from the smoke test, before and after the AI fixes.
const ORIGINAL = [
  'const express = require("express");',
  'const db = require("./db");',
  "const app = express();",
  'app.get("/api/users/:id", async (req, res) => {',
  '  const user = await db.query("SELECT * FROM users WHERE id = " + req.params.id);',
  "  res.json(user);",
  "});",
  'app.get("/search", (req, res) => {',
  '  res.send("<h1>Results for " + req.query.q + "</h1>");',
  "});",
].join("\n");

const FIXED = [
  'const express = require("express");',
  'const db = require("./db");',
  "const app = express();",
  'app.get("/api/users/:id", async (req, res) => {',
  "  if (!/^\\d+$/.test(req.params.id)) {",
  '    return res.status(400).send("Invalid user id");',
  "  }",
  '  const user = await db.query("SELECT * FROM users WHERE id = ?", [req.params.id]);',
  "  res.json(user);",
  "});",
  'app.get("/search", (req, res) => {',
  '  res.send("<h1>Results for " + escapeHtml(String(req.query.q ?? "")) + "</h1>");',
  "});",
].join("\n");

describe("static rule re-verify (per finding)", () => {
  const scanner = new StaticWebScanner();

  it("detects SQL injection and server-side reflected XSS in the original", async () => {
    const findings = await scanner.scan(ctx({ "src/server.js": ORIGINAL }));
    const cwes = findings.map((f) => f.cwe).sort();
    expect(cwes).toContain("CWE-89");
    expect(cwes).toContain("CWE-79");
  });

  it("SQL: concatenation in bind arguments is not injection; building the SQL string is", async () => {
    const sqlCwes = async (line: string) =>
      (await scanner.scan(ctx({ "src/q.js": `app.get("/x", (req, res) => {\n${line}\n});\n` }))).filter((f) => f.cwe === "CWE-89").length;
    // memo-board sample, after the AI fix: the "%" + q + "%" is a bound value, not SQL.
    expect(await sqlCwes('  const rows = db.prepare("SELECT id, text FROM memos WHERE owner_id = ? AND text LIKE ?").all(req.user.id, "%" + q + "%");')).toBe(0);
    expect(await sqlCwes('  db.query("SELECT * FROM t WHERE name LIKE ?", ["%" + req.query.q + "%"]);')).toBe(0);
    // Still flagged: the SQL text itself is built from input.
    expect(await sqlCwes(`  const rows = db.prepare("SELECT id, text FROM memos WHERE owner_id = " + req.user.id + " AND text LIKE '%" + q + "%'").all();`)).toBe(1);
    expect(await sqlCwes("  db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);")).toBe(1);
    expect(await sqlCwes('  const sql = base + " WHERE id = " + req.params.id;')).toBe(1);
    // Middle line of a multi-line template: no whole SQL literal on the line, judged by the line.
    expect(await sqlCwes("    WHERE id = ${req.params.id}")).toBe(1);
  });

  it("re-verify passes when the memo-board search query is parameterized", async () => {
    const before = 'app.get("/api/memos", (req, res) => {\n  const q = req.query.q || "";\n  const rows = db.prepare("SELECT id, text FROM memos WHERE owner_id = " + req.user.id + " AND text LIKE \'%" + q + "%\'").all();\n  res.json(rows);\n});\n';
    const after = before.replace(/const rows = .*\n/, 'const rows = db.prepare("SELECT id, text FROM memos WHERE owner_id = ? AND text LIKE ?").all(req.user.id, "%" + q + "%");\n');
    expect(after).not.toBe(before);
    const [sqli] = (await scanner.scan(ctx({ "server.js": before }))).filter((f) => f.cwe === "CWE-89");
    expect(sqli).toBeDefined();
    const result = await scanner.verify(sqli, ctx({ "server.js": after }, { "server.js": before }));
    expect(result.security.outcome).toBe("pass");
  });

  it("a parameterized query is not flagged because of a later concatenation line", async () => {
    const [sqli] = (await scanner.scan(ctx({ "src/server.js": ORIGINAL }))).filter((f) => f.cwe === "CWE-89");
    const result = await scanner.verify(sqli, ctx({ "src/server.js": FIXED }, { "src/server.js": ORIGINAL }));
    expect(result.security.outcome).toBe("pass");
  });

  it("an escaped value in res.send passes; the unescaped original fails", async () => {
    const [xss] = (await scanner.scan(ctx({ "src/server.js": ORIGINAL }))).filter((f) => f.cwe === "CWE-79");
    expect((await scanner.verify(xss, ctx({ "src/server.js": FIXED }, { "src/server.js": ORIGINAL }))).security.outcome).toBe("pass");
    expect((await scanner.verify(xss, ctx({ "src/server.js": ORIGINAL }, { "src/server.js": ORIGINAL }))).security.outcome).toBe("fail");
  });

  it("one unfixed finding does not fail a fixed one in the same file", async () => {
    const two = [
      'const a = await db.query("SELECT * FROM a WHERE id = " + req.params.id);',
      "// unrelated",
      "// unrelated",
      "// unrelated",
      "// unrelated",
      "// unrelated",
      "// unrelated",
      "// unrelated",
      "// unrelated",
      "// unrelated",
      'const b = await db.query("SELECT * FROM b WHERE id = " + req.params.id);',
    ].join("\n");
    const [first, second] = (await scanner.scan(ctx({ "x.js": two }))).filter((f) => f.cwe === "CWE-89");
    const onlyFirstFixed = two.replace(
      'db.query("SELECT * FROM a WHERE id = " + req.params.id)',
      'db.query("SELECT * FROM a WHERE id = ?", [req.params.id])'
    );
    const c = ctx({ "x.js": onlyFirstFixed }, { "x.js": two });
    expect((await scanner.verify(first, c)).security.outcome).toBe("pass");
    expect((await scanner.verify(second, c)).security.outcome).toBe("fail");
  });

  it("a fix that moves the same pattern to a new line nearby still counts as present", () => {
    expect(
      stillPresentAfterFix({
        hits: [{ line: 6, text: 'const q = "SELECT * FROM t WHERE id = " + id;' }],
        originalLineText: 'db.query("SELECT * FROM t WHERE id = " + id);',
        originalLine: 5,
        baselineContent: 'a\nb\nc\nd\ndb.query("SELECT * FROM t WHERE id = " + id);\n',
        fixedLineCount: 7,
      })
    ).toBe(true);
  });
});

describe("secret rule re-verify (per secret)", () => {
  const scanner = new SecretScanner();
  const A = 'export const apiKey = "abcdefghijklmnop1234";';
  const B = 'export const token = "qrstuvwxyzabcdef5678";';

  it("follows the exact secret, not every secret in the file", async () => {
    const findings = await scanner.scan(ctx({ "src/a.ts": `${A}\n${B}\n` }));
    expect(findings).toHaveLength(2);
    const fixedOne = `export const apiKey = process.env.API_KEY;\n${B}\n`;
    const results = await Promise.all(findings.map((f) => scanner.verify(f, ctx({ "src/a.ts": fixedOne }))));
    const byLine = Object.fromEntries(findings.map((f, i) => [f.location!.line, results[i].security.outcome]));
    expect(byLine).toEqual({ 1: "pass", 2: "fail" });
  });

  it("a secret moved to another file is still present", async () => {
    const [f] = await scanner.scan(ctx({ "src/a.ts": `${A}\n` }));
    const moved = ctx({ "src/a.ts": "export const apiKey = cfg.key;\n", "src/cfg.ts": `export const key = "abcdefghijklmnop1234";\n` });
    expect((await scanner.verify(f, moved)).security.outcome).toBe("fail");
  });

  it("provider keys are detected once, not once per matching rule", () => {
    const m = findSecretMatches({ "s.js": 'const STRIPE_SECRET = "' + FAKE_STRIPE_KEY + '";' });
    expect(m).toHaveLength(1);
    expect(m[0].rule.name).toBe("Stripe live secret key");
  });
});

describe("ASVS SSRF signal", () => {
  it("ignores server-configured URLs but flags request-derived ones", async () => {
    const { Asvs5Scanner } = await import("@/lib/scanners/asvs5Scanner");
    const scanner = new Asvs5Scanner();
    const ssrf = async (code: string) =>
      (await scanner.scan(ctx({ "src/x.js": code }))).filter((f) => f.cwe === "CWE-918").length;
    expect(await ssrf('await fetch(process.env.MAIL_API_URL, { method: "POST" });')).toBe(0);
    expect(await ssrf("const r = await fetch(req.query.url);")).toBe(1);
  });
});
