import { describe, expect, it } from "vitest";
import { StaticWebScanner } from "@/lib/scanners/staticWebScanner";
import { SecretScanner } from "@/lib/scanners/secretScanner";
import { SEMGREP_CLASS_TEXT } from "@/lib/scanners/semgrepScanner";
import { issueClass } from "@/lib/scanners/findingMerge";
import type { ProjectContext } from "@/lib/scanners/types";

// 사용자용 안내 문구를 바꿔도 판정·식별 값은 그대로인지, 필드마다 역할이 나뉘는지 본다.

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

const VULN = [
  'app.get("/api/users/:id", async (req, res) => {',
  '  const user = await db.query("SELECT * FROM users WHERE id = " + req.params.id);',
  "  res.json(user);",
  "});",
  'app.get("/search", (req, res) => {',
  '  res.send("<h1>Results for " + req.query.q + "</h1>");',
  "});",
].join("\n");

describe("static scanner copy", () => {
  it("keeps ids/categories/severity and splits impact, reason and fix into different sentences", async () => {
    const findings = await new StaticWebScanner().scan(ctx({ "src/server.js": VULN }));
    const sqli = findings.find((f) => f.cwe === "CWE-89")!;
    const xss = findings.find((f) => f.cwe === "CWE-79")!;
    expect(sqli.category).toBe("Injection");
    expect(sqli.severity).toBe("critical");
    expect(sqli.verificationKey).toBe("inj:src/server.js:2");
    expect(xss.category).toBe("Cross-Site Scripting");
    expect(xss.verificationKey).toBe("xss:src/server.js:6");
    for (const f of findings) {
      expect(f.whyItMatters).not.toBe(f.humanReadableImpact);
      expect(f.remediation).not.toBe(f.whyItMatters);
      // 코드만 읽은 결과라는 점을 밝힌다.
      expect(f.whyItMatters.startsWith("코드에서 확인했어요")).toBe(true);
    }
    // 근거로 인용한 코드 줄은 그대로 둔다.
    expect(sqli.evidence.find((e) => e.kind === "source_code")?.content).toBe(
      'const user = await db.query("SELECT * FROM users WHERE id = " + req.params.id);'
    );
  });

  it("re-verify follows the signal kind, not the display title (older stored findings)", async () => {
    const scanner = new StaticWebScanner();
    const [sqli] = (await scanner.scan(ctx({ "src/server.js": VULN }))).filter((f) => f.cwe === "CWE-89");
    // 예전 문구로 저장된 항목이라도 코드가 그대로면 "남아 있음"이어야 한다.
    const legacy = { ...sqli, title: "데이터베이스 쿼리에 입력값이 직접 조립됩니다 (SQL 인젝션)" };
    const same = ctx({ "src/server.js": VULN }, { "src/server.js": VULN });
    expect((await scanner.verify(legacy, same)).security.outcome).toBe("fail");
  });
});

describe("secret scanner copy", () => {
  it("tells the user to move and rotate the key, and keeps the value masked", async () => {
    const [f] = await new SecretScanner().scan(ctx({ "src/a.ts": 'export const apiKey = "abcdefghijklmnop1234";\n' }));
    expect(f.verificationKey).toBe("secret:src/a.ts:1");
    expect(f.category).toBe("Secret Exposure");
    expect(f.cwe).toBe("CWE-798");
    expect(f.title).toContain("비밀키");
    expect(f.remediation).toContain("새 키를 발급");
    expect(f.evidence.every((e) => !e.content.includes("abcdefghijklmnop1234"))).toBe(true);
  });
});

describe("semgrep class copy", () => {
  it("each title still classifies as the same issue kind for merging", () => {
    // 제목 키워드로 분류되는 종류(findingMerge.KEYWORD_CLASS)는 같은 종류로, 나머지는 분류 없음으로.
    const keywordClasses = new Set(["sqli", "cmd", "xss", "path", "secret", "ssrf", "jwt", "random"]);
    for (const [cls, text] of Object.entries(SEMGREP_CLASS_TEXT)) {
      expect(issueClass({ title: text.title, category: "Semgrep" }), cls).toBe(keywordClasses.has(cls) ? cls : null);
      expect(text.remediation.length).toBeGreaterThan(0);
    }
  });
});
