import { describe, expect, it } from "vitest";
import { diffLines, fileDiff } from "@/lib/diff/lineDiff";

describe("line diff", () => {
  it("shows a replaced line as deletion then addition, with line numbers", () => {
    const { lines } = diffLines(["a", "old", "c"], ["a", "new", "c"]);
    expect(lines.map((l) => `${l.type}:${l.oldNo ?? "-"}:${l.newNo ?? "-"}:${l.text}`)).toEqual([
      "ctx:1:1:a",
      "del:2:-:old",
      "add:-:2:new",
      "ctx:3:3:c",
    ]);
  });

  it("groups changes into hunks with context and counts", () => {
    const before = Array.from({ length: 30 }, (_, i) => `line ${i + 1}`).join("\n");
    const after = before.replace("line 3", "LINE 3").replace("line 25", "LINE 25");
    const d = fileDiff(before, after, 2);
    expect(d.added).toBe(2);
    expect(d.removed).toBe(2);
    expect(d.hunks).toHaveLength(2);
    expect(d.hunks[1].oldStart).toBe(23);
  });

  it("handles inserted lines", () => {
    const d = fileDiff("a\nb", "a\nx\ny\nb");
    expect(d.added).toBe(2);
    expect(d.removed).toBe(0);
  });
});
