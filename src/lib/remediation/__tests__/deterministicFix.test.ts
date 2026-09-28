import { describe, expect, it } from "vitest";
import { deterministicFixFor, envNameFor, toEnvName } from "@/lib/remediation/deterministicFix";
import { applyDiffsAtomically } from "@/lib/remediation/patchEngine";
import { SecretScanner } from "@/lib/scanners/secretScanner";
import type { SecurityFinding } from "@/lib/domain/types";
import type { ProjectContext } from "@/lib/scanners/types";

// 가짜 Stripe 키. 한 덩어리 리터럴로 두면 GitHub push protection이 실제 키로 보고 push를 막는다.
const FAKE_STRIPE_KEY = ["sk", "live", "51HxQpLKj3n4Vb8ZtQwErTyUiOpAsDfGh"].join("_");

// Fake fixtures only.
function ctx(files: Record<string, string>): ProjectContext {
  return { projectId: "p", name: "p", stack: { frameworks: [], languages: [], hasEnvFile: false }, files, isUserProject: true };
}

async function secretFinding(files: Record<string, string>): Promise<SecurityFinding> {
  const [f] = await new SecretScanner().scan(ctx(files));
  return f;
}

function applied(files: Record<string, string>, finding: SecurityFinding): Record<string, string> {
  const r = deterministicFixFor(finding, files);
  if (!r || r.kind !== "fix") throw new Error(`expected a fix, got ${JSON.stringify(r)}`);
  const working = { ...files };
  const res = applyDiffsAtomically(working, files, r.fix.diffs);
  if (!res.ok) throw new Error(res.failure);
  return working;
}

function depFinding(name: string, fixed: string[]): SecurityFinding {
  return {
    id: "d",
    scanId: "",
    title: "dep",
    severity: "high",
    category: "Vulnerable Dependencies",
    description: "",
    humanReadableImpact: "",
    whyItMatters: "",
    evidence: [{ id: "e", kind: "scanner_output", label: "OSV", content: fixed.map((v, i) => `GHSA-${i} → 수정: ${v}`).join("\n") }],
    status: "detected",
    simulated: false,
    verificationKey: `dep:${name}`,
    createdAt: "",
    updatedAt: "",
  };
}

describe("secret fix", () => {
  it("moves a server-side literal to process.env using the variable name", async () => {
    const files = { "src/server.js": 'const STRIPE_SECRET = "' + FAKE_STRIPE_KEY + '";\nmodule.exports = STRIPE_SECRET;\n' };
    const out = applied(files, await secretFinding(files));
    expect(out["src/server.js"]).toBe("const STRIPE_SECRET = process.env.STRIPE_SECRET;\nmodule.exports = STRIPE_SECRET;\n");
  });

  it("keeps TypeScript string annotations compiling", async () => {
    const files = { "src/cfg.ts": 'export const apiKey: string = "abcdefghijklmnop1234";\n' };
    const out = applied(files, await secretFinding(files));
    expect(out["src/cfg.ts"]).toBe('export const apiKey: string = process.env.API_KEY ?? "";\n');
  });

  it("uses the provider name when there is no assignment", async () => {
    const files = { "src/pay.js": 'const stripe = new Stripe("' + FAKE_STRIPE_KEY + '");\n' };
    const out = applied(files, await secretFinding(files));
    expect(out["src/pay.js"]).toBe("const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);\n");
  });

  it("refuses client code, .env files and mixed strings with a reason", async () => {
    const client = { "src/w.tsx": '"use client";\nconst k = "' + FAKE_STRIPE_KEY + '";\n' };
    expect(deterministicFixFor(await secretFinding(client), client)).toMatchObject({ kind: "unsupported", reasonCode: "secret_in_client_code" });

    const env = { ".env": "DATABASE_PASSWORD=hunter2hunter2\n" };
    expect(deterministicFixFor(await secretFinding(env), env)).toMatchObject({ kind: "unsupported", reasonCode: "secret_in_env_file" });

    const mixed = { "src/h.js": 'const h = "Bearer ' + FAKE_STRIPE_KEY + '";\n' };
    expect(deterministicFixFor(await secretFinding(mixed), mixed)).toMatchObject({ kind: "unsupported", reasonCode: "secret_not_plain_literal" });
  });

  it("names env vars predictably", () => {
    expect(toEnvName("stripeSecretKey")).toBe("STRIPE_SECRET_KEY");
    expect(toEnvName("DATABASE_URL")).toBe("DATABASE_URL");
    expect(envNameFor("const token = ")).toBe("APP_TOKEN");
    expect(envNameFor("  apiKey: ")).toBe("API_KEY");
    expect(envNameFor("  'client-secret': ", "X")).toBe("CLIENT_SECRET");
  });
});

describe("dependency fix", () => {
  const pkg = (deps: string) => `{\n  "name": "demo",\n  "dependencies": {\n${deps}\n  }\n}\n`;

  it("bumps to the highest fixed version in the same major and keeps ^", () => {
    const files = { "package.json": pkg('    "lodash": "^4.17.15",\n    "express": "4.17.1"') };
    const out = applied(files, depFinding("lodash", ["4.17.19", "4.17.21", "3.10.2"]));
    expect(out["package.json"]).toContain('"lodash": "^4.17.21"');
    expect(out["package.json"]).toContain('"express": "4.17.1"');
  });

  it("refuses major bumps and complex ranges", () => {
    expect(deterministicFixFor(depFinding("next", ["15.0.0"]), { "package.json": pkg('    "next": "14.2.3"') })).toMatchObject({
      kind: "unsupported",
      reasonCode: "dep_major_bump",
    });
    expect(deterministicFixFor(depFinding("a", ["2.0.1"]), { "package.json": pkg('    "a": "2.x"') })).toMatchObject({
      kind: "unsupported",
      reasonCode: "dep_range_unknown",
    });
  });

  it("mentions the lockfile when one exists", () => {
    const files = { "package.json": pkg('    "lodash": "4.17.15"'), "package-lock.json": "{}" };
    const r = deterministicFixFor(depFinding("lodash", ["4.17.21"]), files);
    expect(r?.kind).toBe("fix");
    if (r?.kind === "fix") expect(r.fix.plainExplanation).toContain("npm install");
  });
});
