import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { SemgrepScanner } from "@/lib/scanners/semgrepScanner";
import { parseSourceBlob } from "@/lib/demo/sourceFiles";
import type { ProjectContext } from "@/lib/scanners/types";

// Runs only where Semgrep is installed (SEMGREP_BIN), e.g.
//   SEMGREP_BIN=.local/semgrep-venv/bin/semgrep npx vitest --run src/lib/scanners/__tests__/semgrep.test.ts
const files = parseSourceBlob(readFileSync(path.join(process.cwd(), "scripts/e2e/fixtures/vuln-express.txt"), "utf8"));
const ctx = (f: Record<string, string>, baselineFiles?: Record<string, string>): ProjectContext => ({
  projectId: "p",
  name: "p",
  stack: { frameworks: [], languages: [], hasEnvFile: false },
  files: f,
  isUserProject: true,
  baselineFiles,
});

describe.skipIf(!process.env.SEMGREP_BIN)("Semgrep scanner (real binary)", () => {
  it("finds injection issues, one finding per line and class, and re-verifies a fix", async () => {
    const scanner = new SemgrepScanner();
    const { findings, status } = await scanner.scanWithReport(ctx(files));
    expect(status.status).toBe("ran");
    const cwes = findings.map((f) => f.cwe);
    expect(cwes).toContain("CWE-79");
    const perLine = findings.map((f) => `${f.location!.line}:${f.cwe}`);
    expect(new Set(perLine).size).toBe(perLine.length);

    const xss = findings.find((f) => f.cwe === "CWE-79")!;
    const fixed = {
      ...files,
      "src/server.js": files["src/server.js"].replace(
        'res.send("<h1>Results for " + req.query.q + "</h1>");',
        'res.type("text/plain").send("Results for " + String(req.query.q ?? ""));'
      ),
    };
    const result = await scanner.verify(xss, ctx(fixed, files));
    expect(result.security.outcome).toBe("pass");
  }, 180_000);
});
