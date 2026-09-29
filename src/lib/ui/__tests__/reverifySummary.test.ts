import { describe, expect, it } from "vitest";
import { reverifySummaryFor, type FixStatusVerifyItem } from "@/lib/ui/fixStatus";

const item = (findingId: string, v: Partial<FixStatusVerifyItem>): FixStatusVerifyItem =>
  ({ findingId, verdict: "inconclusive", ...v }) as FixStatusVerifyItem;

describe("reverifySummaryFor", () => {
  it("재검증 기록이 없으면 요약을 만들지 않는다", () => {
    expect(reverifySummaryFor(undefined)).toBeUndefined();
  });

  it("완료: 실행·규칙 확인과 AI 판단을 나눠 세고, 남음·확인 불가·오탐을 따로 센다", () => {
    const s = reverifySummaryFor({
      status: "completed",
      items: [
        item("a", { verdict: "fixed_in_source", method: "rule" }),
        item("b", { verdict: "fixed_in_source", method: "exploit", executed: true }),
        item("c", { verdict: "fixed_in_source", method: "llm" }),
        item("d", { verdict: "still_present", method: "rule" }),
        item("e", { verdict: "inconclusive" }),
        item("f", { verdict: "fixed_in_source", method: "rule+llm", reasonCode: "disputed" }),
        item("g", { verdict: "false_positive", method: "llm" }),
      ],
    });
    expect(s).toEqual({
      state: "completed",
      resolvedConfirmed: 2,
      resolvedExecuted: 1,
      resolvedAi: 1,
      stillPresent: 1,
      unknown: 2,
      falsePositive: 1,
    });
  });

  it("일부만 결론이 난 경우에도 결론 없는 항목은 확인 불가로 센다", () => {
    const s = reverifySummaryFor({
      status: "completed",
      items: [item("a", { verdict: "fixed_in_source", method: "rule" }), item("b", { verdict: "inconclusive", reasonCode: "ai_failed" })],
    });
    expect(s?.resolvedConfirmed).toBe(1);
    expect(s?.unknown).toBe(1);
  });

  it("실패: 저장된 이유를 담고 개수는 세지 않는다", () => {
    const s = reverifySummaryFor({
      status: "failed",
      errorMessage: "AI 응답을 받지 못했어요.",
      items: [item("a", { verdict: "fixed_in_source", method: "rule" })],
    });
    expect(s?.state).toBe("failed");
    expect(s?.reason).toBe("AI 응답을 받지 못했어요.");
    expect(s?.resolvedConfirmed).toBe(0);
  });

  it("진행 중: 예전 항목을 결과로 세지 않는다", () => {
    const s = reverifySummaryFor({ status: "running", items: [item("a", { verdict: "still_present" })] });
    expect(s?.state).toBe("running");
    expect(s?.stillPresent).toBe(0);
  });
});
