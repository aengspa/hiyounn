import path from "node:path";
import { describe, expect, it } from "vitest";
import { gitleaksFindings, parseGitleaksReport } from "@/lib/scanners/gitleaksScanner";
import { SecretScanner } from "@/lib/scanners/secretScanner";
import { mergeCorroborating } from "@/lib/scanners/findingMerge";
import type { ProjectContext } from "@/lib/scanners/types";

// 실제 gitleaks를 실행하지 않고, gitleaks v8 JSON 보고서 형식의 고정 입력을 쓴다.
const base = path.resolve("/tmp/hoi-gitleaks-x/src");
const SECRET = "AKIAIOSFODNN7EXAMPLQ";
const TOKEN = "zq8Wm2Rt7Yp4Lk9Vb3Nx6Hc1Jd5Fg0Se";
const files = {
  "src/config.js": `const region = "us-east-1";\nconst awsKey = "${SECRET}";\n`,
  "src/util.js": `export const t = { auth: "${TOKEN}" };\n`,
};
const report = JSON.stringify([
  { RuleID: "aws-access-token", Description: "AWS", StartLine: 2, EndLine: 2, Match: `awsKey = "${SECRET}"`, Secret: SECRET, File: path.join(base, "src/config.js"), Commit: "", Fingerprint: "x" },
  { RuleID: "generic-api-key", StartLine: 1, Match: `auth: "${TOKEN}"`, Secret: TOKEN, File: "src/util.js", Commit: "" },
  { RuleID: "aws-access-token", StartLine: 2, Secret: SECRET, File: "src/config.js", Commit: "0123456789abcdef0123456789abcdef01234567" },
  { RuleID: "x", StartLine: 1, Secret: "zzzzzzzzzzzz", File: path.join(base, "../../outside.js") },
  { RuleID: "x", StartLine: 0, Secret: "yyyyyyyyyyyy", File: "src/util.js" },
]);

describe("gitleaks report mapping", () => {
  const hits = parseGitleaksReport(report, base);

  it("keeps only in-project paths with valid lines", () => {
    expect(hits.map((h) => `${h.file}:${h.line}${h.commit ? "@c" : ""}`)).toEqual(["src/config.js:2", "src/util.js:1", "src/config.js:2@c"]);
  });

  it("maps to Secret Exposure findings with masked evidence and no raw secret anywhere", () => {
    const findings = gitleaksFindings(hits, files);
    // 같은 값이 기록에도 있으면 현재 파일 쪽 하나만 남긴다.
    expect(findings).toHaveLength(2);
    const aws = findings.find((f) => f.location?.file === "src/config.js")!;
    expect(aws).toMatchObject({ category: "Secret Exposure", cwe: "CWE-798", severity: "critical", verificationKey: "gitleaks:aws-access-token:src/config.js:2" });
    expect(aws.title).toContain("비밀키");
    expect(aws.evidence[0].content).toContain("const awsKey =");
    expect(aws.evidence.every((e) => e.masked)).toBe(true);
    const all = JSON.stringify(findings);
    expect(all).not.toContain(SECRET);
    expect(all).not.toContain(TOKEN);
  });

  it("merges with the built-in secret scanner finding on the same line", async () => {
    const ctx: ProjectContext = { projectId: "p", name: "p", stack: { frameworks: [], languages: [], hasEnvFile: false }, files, isUserProject: true };
    const builtIn = await new SecretScanner().scan(ctx);
    expect(builtIn.some((f) => f.location?.file === "src/config.js" && f.location.line === 2)).toBe(true);
    const merged = mergeCorroborating(builtIn, gitleaksFindings(hits, files), "gitleaks");
    expect(merged.kept.find((f) => f.location?.file === "src/config.js")).toBeUndefined();
    expect(builtIn.find((f) => f.location?.file === "src/config.js")?.corroboratedBy).toContain("gitleaks");
  });

  it("reports history-only secrets with a masked value", () => {
    const only = gitleaksFindings([{ ruleId: "aws-access-token", file: "old.js", line: 3, secret: SECRET, commit: "0123456789abcdef" }], files);
    expect(only).toHaveLength(1);
    expect(only[0].title).toContain("코드 기록");
    expect(JSON.stringify(only)).not.toContain(SECRET);
  });
});
