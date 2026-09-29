import { describe, expect, it } from "vitest";
import { formatKstDateTime, kstParts } from "@/lib/time";

describe("KST 시간 표시", () => {
  it("UTC 오후 3시 30분은 KST로 다음 날 0시 30분이다(서버 시간대와 무관)", () => {
    expect(kstParts("2026-01-01T15:30:45Z")).toEqual({ year: 2026, month: 1, day: 2, hour: 0, minute: 30, second: 45 });
  });

  it("연말 경계도 KST 기준으로 넘어간다", () => {
    expect(kstParts("2026-12-31T20:00:00Z")).toMatchObject({ year: 2027, month: 1, day: 1, hour: 5 });
  });

  it("사람이 읽는 형식도 KST 날짜와 시각을 쓴다", () => {
    const text = formatKstDateTime("2026-01-01T15:30:45Z");
    expect(text).toContain("2026. 1. 2.");
    expect(text).toContain("12:30:45");
    expect(text).toContain("오전");
  });

  it("잘못된 값은 예외 대신 안내 문구를 돌려준다", () => {
    expect(formatKstDateTime("not-a-date")).toBe("기록 없음");
  });
});
