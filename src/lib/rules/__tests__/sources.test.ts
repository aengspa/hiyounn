import { describe, expect, it } from "vitest";
import { RULES } from "@/lib/rules/definitions";
import {
  CITED_SOURCES,
  REFERENCE_SOURCES,
  frameworkStats,
  introStats,
  standardLabel,
  standardUrl,
} from "@/lib/rules/sources";

describe("서비스 소개의 근거 출처와 숫자", () => {
  it("상단 숫자는 규칙에서 계산한다", () => {
    const s = introStats();
    expect(s.items).toBe(RULES.length);
    const cwe = new Set(RULES.flatMap((r) => r.standards.filter((x) => x.framework === "CWE").map((x) => x.id)));
    expect(s.cweIds).toBe(cwe.size);
    expect(s.frameworks).toBeGreaterThan(0);
    expect(s.frameworks).toBeLessThanOrEqual(CITED_SOURCES.length);
  });

  it("보여 주는 인용 기준은 모두 실제 규칙이 쓰는 기준이다", () => {
    const stats = frameworkStats();
    for (const src of CITED_SOURCES) {
      expect(src.framework && stats.get(src.framework)?.items).toBeGreaterThan(0);
    }
  });

  it("결과 예시가 쓰는 WEB-014 규칙이 있다", () => {
    const rule = RULES.find((r) => r.id === "WEB-014");
    expect(rule).toBeDefined();
    expect(rule!.standards.some((r) => r.id === "CWE-639")).toBe(true);
  });

  it("근거 번호의 이름과 원문 주소를 만든다", () => {
    expect(standardLabel({ framework: "CWE", id: "CWE-639" })).toBe("CWE-639");
    expect(standardUrl({ framework: "CWE", id: "CWE-639" })).toBe("https://cwe.mitre.org/data/definitions/639.html");
    expect(standardUrl({ framework: "CAPEC", id: "CAPEC-122" })).toBe("https://capec.mitre.org/data/definitions/122.html");
    expect(standardUrl({ framework: "MITRE_ATTACK", id: "T1190" })).toBe("https://attack.mitre.org/techniques/T1190/");
    expect(standardLabel({ framework: "OWASP_API_SECURITY_TOP_10", id: "API1:2023" })).toBe("OWASP API1:2023");
  });

  it("모든 외부 주소는 https다", () => {
    for (const s of [...CITED_SOURCES, ...REFERENCE_SOURCES]) {
      if (s.url) expect(s.url.startsWith("https://")).toBe(true);
    }
  });
});
