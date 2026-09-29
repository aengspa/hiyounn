import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { aggregateStatus, groupFindings, groupKey, type GroupableFinding } from "@/lib/ui/groupFindings";
import type { Severity } from "@/lib/domain/types";

const f = (id: string, over: Partial<GroupableFinding> = {}): GroupableFinding => ({
  id,
  title: "SQL 쿼리에 입력값이 그대로 들어가요",
  severity: "medium",
  ...over,
});

describe("groupFindings", () => {
  it("같은 규칙이 파일 3곳에서 나오면 한 묶음, 위치 3곳, 가장 높은 심각도", () => {
    const groups = groupFindings([
      f("a", { ruleId: "WEB-002", severity: "medium", location: { file: "src/a.ts", line: 3 } }),
      f("b", { ruleId: "WEB-002", severity: "critical", location: { file: "src/b.ts", line: 10 } }),
      f("c", { ruleId: "WEB-002", severity: "low", location: { file: "src/c.ts", line: 7 } }),
    ]);
    expect(groups).toHaveLength(1);
    const g = groups[0];
    expect(g.ids).toEqual(["a", "b", "c"]);
    expect(g.severity).toBe("critical");
    expect(g.representative.id).toBe("b");
    expect(g.locations.map((l) => `${l.file}:${l.line}`)).toEqual(["src/a.ts:3", "src/b.ts:10", "src/c.ts:7"]);
  });

  it("CWE가 다르면(종류가 다르면) 따로 묶는다", () => {
    const groups = groupFindings([
      f("a", { cwe: "CWE-89", title: "같은 제목" }),
      f("b", { cwe: "CWE-79", title: "같은 제목" }),
      f("c", { cwe: "CWE-564", title: "다른 제목" }), // 89와 같은 종류(sqli)
    ]);
    expect(groups.map((g) => g.ids)).toEqual([["a", "c"], ["b"]]);
  });

  it("규칙 ID가 다르면 CWE가 같아도 합치지 않고, 규칙·CWE가 없으면 제목으로 묶는다", () => {
    expect(groupKey({ ruleId: "WEB-001", cwe: "CWE-89", title: "x" })).not.toBe(groupKey({ ruleId: "WEB-002", cwe: "CWE-89", title: "x" }));
    const groups = groupFindings([f("a", { title: "Open  Redirect!" }), f("b", { title: "open redirect" }), f("c", { title: "XSS" })]);
    expect(groups.map((g) => g.ids)).toEqual([["a", "b"], ["c"]]);
  });

  /** **Validates: 같은 취약점만 묶고, 항목은 하나도 잃지 않는다** */
  it("속성: 모든 id가 정확히 한 번 들어가고, 한 묶음 안은 모두 같은 키", () => {
    const sev = fc.constantFrom<Severity>("critical", "high", "medium", "low");
    const item = fc.record({
      ruleId: fc.option(fc.constantFrom("R1", "R2"), { nil: undefined }),
      cwe: fc.option(fc.constantFrom("CWE-89", "CWE-79", "CWE-22", "CWE-999"), { nil: undefined }),
      title: fc.constantFrom("A", "B", "C"),
      severity: sev,
    });
    fc.assert(
      fc.property(fc.array(item, { maxLength: 30 }), (raw) => {
        const items = raw.map((r, i) => ({ ...r, id: `f${i}` }));
        const groups = groupFindings(items);
        const ids = groups.flatMap((g) => g.ids).sort();
        expect(ids).toEqual(items.map((x) => x.id).sort());
        for (const g of groups) {
          expect(new Set(g.members.map(groupKey)).size).toBe(1);
          const best = Math.min(...g.members.map((m) => ["critical", "high", "medium", "low"].indexOf(m.severity)));
          expect(["critical", "high", "medium", "low"].indexOf(g.severity)).toBe(best);
        }
      })
    );
  });
});

describe("aggregateStatus", () => {
  it("가장 나쁜 상태를 라벨로 쓰고, 다르면 내역을 만든다", () => {
    const s = aggregateStatus(["resolved", "still_present", "resolved"]);
    expect(s.key).toBe("still_present");
    expect(s.label).toBe("아직 남아 있어요");
    expect(s.breakdown).toBe("아직 남아 있음 1곳 · 해결 확인 2곳");
  });

  it("모두 같으면 내역이 없고, 오탐은 모두 오탐일 때만 묶음 상태가 된다", () => {
    expect(aggregateStatus(["resolved", "resolved"])).toEqual({ key: "resolved", label: "해결 확인했어요" });
    expect(aggregateStatus(["false_positive", "false_positive"]).key).toBe("false_positive");
    expect(aggregateStatus(["false_positive", "resolved"]).key).toBe("resolved");
    expect(aggregateStatus(["needs_check", "not_fixed", "resolved_ai"]).key).toBe("not_fixed");
  });
});
