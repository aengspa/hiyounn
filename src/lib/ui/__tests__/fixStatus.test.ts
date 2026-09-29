import { describe, expect, it } from "vitest";
import { APPLIED_UNVERIFIED_MESSAGE, fixStatusFor, fixStepsFor } from "@/lib/ui/fixStatus";

const applied = { findingId: "f", outcome: "applied" as const };
const verified = (it: Record<string, unknown>) =>
  fixStatusFor("f", { item: applied, verification: { status: "completed", items: [{ findingId: "f", ...it } as never] } });

describe("fixStatusFor 문구", () => {
  it("적용만 하고 재검증 전이면 해결이라고 하지 않는다", () => {
    const s = fixStatusFor("f", { item: applied });
    expect(s.pending).toBe(APPLIED_UNVERIFIED_MESSAGE);
    expect(s.confirmed).toBeUndefined();
  });

  it("코드 기준 해결은 라벨을 유지하고 실행 확인이 필요하다는 보충 설명을 붙인다", () => {
    for (const method of ["rule", "rule+llm"]) {
      const s = verified({ verdict: "fixed_in_source", method });
      expect(s.label).toBe("해결 확인했어요");
      expect(s.note).toBe("코드 기준으로 확인했어요. 실제 서비스에서는 실행해 확인해 주세요.");
    }
    const executed = verified({ verdict: "fixed_in_source", method: "exploit", executed: true });
    expect(executed.label).toBe("해결 확인했어요");
    expect(executed.note).toContain("테스트를 실행해 확인했어요");
  });

  it("결론 없음은 서버가 채운 원인별 설명을 그대로 보여 준다", () => {
    const summary = "AI가 이 항목에 대한 답을 주지 않아 고쳐졌는지 확인하지 못했어요.";
    const s = verified({ verdict: "inconclusive", reasonCode: "no_answer", summary });
    expect(s.label).toBe("점검이 필요해요");
    expect(s.pending).toBe(summary);
    expect(verified({ verdict: "inconclusive", reasonCode: "ai_failed" }).pending).toContain("확인하지 못했어요");
  });

  it("detail은 확인된 것과 아직 확인이 필요한 것을 이어 붙인 문장이다", () => {
    const s = verified({ verdict: "still_present", method: "rule" });
    expect(s.detail).toBe(`${s.confirmed} ${s.pending}`);
  });
});

describe("fixStepsFor", () => {
  it("수정안 만들기 · 파일에 적용 · 재검증 세 단계를 따로 보여 준다", () => {
    const steps = fixStepsFor("f", { item: applied })!;
    expect(steps.map((s) => s.label)).toEqual(["수정안 만들기", "파일에 적용", "재검증"]);
    expect(steps.map((s) => s.state)).toEqual(["done", "done", "todo"]);
    expect(fixStepsFor("f", {})).toBeUndefined();
  });
});
