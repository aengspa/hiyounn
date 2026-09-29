import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fc from "fast-check";
import { generateScanReport } from "@/lib/reporting/reportGenerator";
import { containsGuaranteePhrase } from "@/lib/ui/presentation";
import type { ScanScope, SecurityFinding, Severity } from "@/lib/domain/types";

const SCOPE: ScanScope = {
  scanDate: "2025-01-01T00:00:00.000Z",
  scannerVersion: "test",
  rulesetVersion: "test",
  testedCategories: ["코드에 직접 적힌 비밀키", "다른 사람 데이터 접근"],
  untestedCategories: ["Social Engineering"],
};

function finding(over: Partial<SecurityFinding> & { id: string; severity: Severity }): SecurityFinding {
  return {
    scanId: "",
    title: "요청한 정보가 로그인한 사람의 것인지 확인하지 않아요",
    category: "Broken Access Control",
    description: "",
    humanReadableImpact: "로그인한 사람이 주소의 번호만 바꿔 다른 사람의 주문 정보를 볼 수 있어요. 추가 설명이에요.",
    whyItMatters: "",
    evidence: [],
    remediation: "",
    status: "detected",
    simulated: false,
    createdAt: "",
    updatedAt: "",
    ...over,
  } as SecurityFinding;
}

describe("generateScanReport — deterministic fallback", () => {
  beforeEach(() => vi.stubEnv("LLM_PROVIDER", "none"));
  afterEach(() => vi.unstubAllEnvs());

  it("no findings: states scope limits without promising safety", async () => {
    const r = await generateScanReport([], SCOPE);
    expect(r.source).toBe("deterministic");
    expect(r.highlights).toEqual([]);
    expect(r.summary).toContain("확인한 범위에서는 문제를 찾지 못했어요");
    expect(r.summary).toContain("2개 항목");
    expect(r.summary).toContain("확인하지 못한 항목이 1개");
    expect(r.summary).not.toMatch(/배포해도/);
    expect(containsGuaranteePhrase(`${r.summary} ${r.recommendation}`)).toBe(false);
  });

  it("findings: separates confirmed from suspected and orders the action", async () => {
    const r = await generateScanReport(
      [
        finding({ id: "a", severity: "high", ruleId: "R1", status: "verified" }),
        finding({ id: "b", severity: "critical", ruleId: "R2", title: "외부 서비스 비밀키가 코드에 들어 있어요." }),
      ],
      SCOPE
    );
    expect(r.summary).toContain("2건");
    expect(r.summary).toContain("1건은 점검 도구가 실제 요청으로 확인");
    expect(r.summary).toContain("1건은 코드나 설정에서 찾은 의심 신호");
    // 심각도 높은 항목이 먼저, 제목 뒤에 가능한 영향의 첫 문장이 붙는다.
    expect(r.highlights[0]).toBe(
      "[심각] 외부 서비스 비밀키가 코드에 들어 있어요. 로그인한 사람이 주소의 번호만 바꿔 다른 사람의 주문 정보를 볼 수 있어요."
    );
    expect(r.recommendation).toContain("먼저 심각도 '심각' 항목 1건");
    expect(r.recommendation).toContain("재검증");
    expect(r.recommendation).toContain("나머지 항목");
  });

  /**
   * 속성: 어떤 발견 조합이든 결정적 보고서는 안전을 보장하는 표현을 쓰지 않고,
   * 발견 수(가족 단위로 묶은 뒤)와 확인하지 못한 범위를 요약에 남긴다.
   */
  it("property: never guarantees safety and always reports scope", async () => {
    const sev = fc.constantFrom<Severity>("critical", "high", "medium", "low");
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.record({ severity: sev, verified: fc.boolean() }), { maxLength: 8 }),
        fc.nat({ max: 3 }),
        async (items, untested) => {
          const findings = items.map((it, i) =>
            finding({ id: `f${i}`, ruleId: `R${i}`, severity: it.severity, status: it.verified ? "verified" : "detected" })
          );
          const scope = { ...SCOPE, untestedCategories: Array.from({ length: untested }, (_, i) => `U${i}`) };
          const r = await generateScanReport(findings, scope);
          const text = [r.summary, r.recommendation, ...r.highlights].join(" ");
          expect(containsGuaranteePhrase(text)).toBe(false);
          expect(r.highlights.length).toBe(Math.min(findings.length, 5));
          if (findings.length > 0) expect(r.summary).toContain(`${findings.length}건`);
          if (untested > 0) expect(r.summary).toContain(`확인하지 못한 항목이 ${untested}개`);
        }
      ),
      { numRuns: 60 }
    );
  });
});
