import { describe, expect, it } from "vitest";
import { guidanceFor, requiredEnvForFix } from "@/lib/remediation/requiredEnv";

describe("requiredEnvForFix", () => {
  it("lists variables a fix newly reads, not ones the project already used", () => {
    const base = {
      "src/auth.js": "const claims = jwt.decode(token);",
      "src/mail.js": "fetch(process.env.MAIL_API_URL)",
      "src/preview.js": "fetch(target)",
    };
    const fixed = {
      ...base,
      "src/auth.js": 'jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] })',
      "src/preview.js": 'const allowed = process.env["PREVIEW_ALLOWED_HOSTS"]; const u = process.env.MAIL_API_URL;',
    };
    const env = requiredEnvForFix(base, fixed, ["src/auth.js", "src/preview.js"]);
    expect(env.map((e) => [e.name, e.kind, e.files])).toEqual([
      ["JWT_SECRET", "secret", ["src/auth.js"]],
      ["PREVIEW_ALLOWED_HOSTS", "allowlist", ["src/preview.js"]],
    ]);
  });

  it("gives kind-specific guidance", () => {
    expect(guidanceFor("JWT_SECRET").guidance).toContain("HS256");
    expect(guidanceFor("PREVIEW_ALLOWED_HOSTS").guidance).toContain("모든 요청을 거절");
    expect(guidanceFor("STRIPE_SECRET").kind).toBe("secret");
    expect(guidanceFor("PAGE_SIZE").kind).toBe("config");
  });
});
