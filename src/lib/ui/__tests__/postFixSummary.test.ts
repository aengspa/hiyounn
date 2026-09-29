import { describe, expect, it } from "vitest";
import {
  NOT_CHECKED_MESSAGE,
  fixStatusFor,
  postFixSummaryFor,
  type FixStatusJobItem,
  type FixStatusVerifyItem,
  type PostFixSummary,
} from "@/lib/ui/fixStatus";

const ids = (n: number) => Array.from({ length: n }, (_, i) => `f${i + 1}`);
const vItem = (findingId: string, v: Partial<FixStatusVerifyItem>): FixStatusVerifyItem =>
  ({ findingId, verdict: "inconclusive", ...v }) as FixStatusVerifyItem;
const bucketsPlusNotChecked = (s: PostFixSummary) =>
  s.resolvedConfirmed + s.resolvedAi + s.stillPresent + s.needsCheck + s.falsePositive + s.notChecked;

describe("postFixSummaryFor", () => {
  // 17건 중 3건은 처음 점검 때 오탐 판정, 13건 적용, 재검증: 규칙·실행 9 + AI 4 + 오탐 4.
  const findingIds = ids(17);
  const fpIds = ["f15", "f16", "f17"];
  const jobItems: FixStatusJobItem[] = findingIds.map((id, i) => ({
    findingId: id,
    outcome: i < 13 ? "applied" : "unsupported",
  }));
  const items: FixStatusVerifyItem[] = [
    ...findingIds.slice(0, 7).map((id) => vItem(id, { verdict: "fixed_in_source", method: "rule" })),
    ...findingIds.slice(7, 9).map((id) => vItem(id, { verdict: "fixed_in_source", method: "exploit", executed: true })),
    ...findingIds.slice(9, 13).map((id) => vItem(id, { verdict: "fixed_in_source", method: "llm" })),
    ...findingIds.slice(13).map((id) => vItem(id, { verdict: "false_positive", method: "llm" })),
  ];
  const verification = { status: "completed" as const, items };

  it("재검증 결과를 실행·규칙 / AI / 오탐으로 나눠 세고 합이 처음 발견 수와 같다", () => {
    const s = postFixSummaryFor({ findingIds, jobItems, verification, adjudicatedFalsePositiveIds: fpIds });
    expect(s).toMatchObject({
      state: "completed",
      originalTotal: 17,
      initialFalsePositive: 3,
      appliedCount: 13,
      resolvedConfirmed: 9,
      resolvedExecuted: 2,
      resolvedAi: 4,
      stillPresent: 0,
      needsCheck: 0,
      falsePositive: 4,
      notChecked: 0,
    });
    expect(bucketsPlusNotChecked(s)).toBe(s.originalTotal);
  });

  it("처음 오탐 판정 항목도 지금 재검증이 해결이라고 하면 카드는 해결로 보인다", () => {
    const v = { status: "completed" as const, items: [vItem("f15", { verdict: "fixed_in_source", method: "rule" })] };
    expect(fixStatusFor("f15", { adjudicatedFalsePositive: true, verification: v }).key).toBe("resolved");
    const ai = { status: "completed" as const, items: [vItem("f15", { verdict: "fixed_in_source", method: "llm" })] };
    expect(fixStatusFor("f15", { adjudicatedFalsePositive: true, verification: ai }).key).toBe("resolved_ai");
    const still = { status: "completed" as const, items: [vItem("f15", { verdict: "still_present" })] };
    expect(fixStatusFor("f15", { adjudicatedFalsePositive: true, verification: still }).key).toBe("still_present");
  });

  it("카드 상태와 요약 칸이 같은 분류를 쓴다", () => {
    const s = postFixSummaryFor({ findingIds, jobItems, verification, adjudicatedFalsePositiveIds: fpIds });
    const keyCount = (k: string) =>
      findingIds.filter(
        (id) =>
          fixStatusFor(id, {
            item: jobItems.find((it) => it.findingId === id),
            verification,
            adjudicatedFalsePositive: fpIds.includes(id),
          }).key === k
      ).length;
    expect(keyCount("resolved")).toBe(s.resolvedConfirmed);
    expect(keyCount("resolved_ai")).toBe(s.resolvedAi);
    expect(keyCount("false_positive")).toBe(s.falsePositive);
  });

  it("재검증 결과가 없는 항목은 '이번 재검증에서 확인하지 못함'으로 센다", () => {
    const partial = { status: "completed" as const, items: items.slice(0, 10) };
    const s = postFixSummaryFor({ findingIds, jobItems, verification: partial, adjudicatedFalsePositiveIds: fpIds });
    expect(s.notChecked).toBe(7);
    expect(bucketsPlusNotChecked(s)).toBe(s.originalTotal);
    for (const id of ["f11", "f16"]) {
      const st = fixStatusFor(id, {
        item: jobItems.find((it) => it.findingId === id),
        verification: partial,
        adjudicatedFalsePositive: fpIds.includes(id),
      });
      expect(st.key).toBe("needs_check");
      expect(st.pending).toContain(NOT_CHECKED_MESSAGE);
    }
  });

  it("진행 중·실패면 상태별 개수를 세지 않는다", () => {
    for (const status of ["running", "failed"] as const) {
      const s = postFixSummaryFor({ findingIds, jobItems, verification: { status, items, errorMessage: "멈췄어요" } });
      expect(s.state).toBe(status);
      expect(bucketsPlusNotChecked(s)).toBe(0);
      expect(s.appliedCount).toBe(13);
    }
    expect(postFixSummaryFor({ findingIds, verification: { status: "failed", items: [], errorMessage: "멈췄어요" } }).reason).toBe("멈췄어요");
  });

  it("적용만 하고 재검증 전이면 해결로 세거나 보여 주지 않는다", () => {
    const s = postFixSummaryFor({ findingIds, jobItems });
    expect(s.state).toBe("none");
    expect(s.appliedCount).toBe(13);
    expect(bucketsPlusNotChecked(s)).toBe(0);
    for (const id of findingIds.slice(0, 13)) {
      const st = fixStatusFor(id, { jobStatus: "completed", item: jobItems.find((it) => it.findingId === id) });
      expect(st.key).not.toMatch(/^resolved/);
      expect(st.label).not.toContain("해결");
    }
  });
});
