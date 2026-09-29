import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { chunkFile, excerptAroundLine, excerptChars, findEvidenceLine } from "@/lib/remediation/fixExcerpt";
import type { FileExcerpt } from "@/lib/remediation/fixExcerpt";

/** Every part must be copied verbatim from the file at the line range it claims. */
function partsAreVerbatim(content: string, ex: FileExcerpt): boolean {
  const lines = content.split("\n");
  return ex.parts.every((p) =>
    p.partial
      ? p.startLine === p.endLine && lines[p.startLine - 1].includes(p.text)
      : p.text === lines.slice(p.startLine - 1, p.endLine).join("\n")
  );
}

const lineArb = fc.oneof(
  fc.constantFrom('import { a } from "a";', "", "  return x;", "}", "export function f() {"),
  fc.string({ maxLength: 120 }).map((s) => s.replace(/\n/g, " "))
);
const fileArb = fc.array(lineArb, { minLength: 1, maxLength: 300 }).map((ls) => ls.join("\n"));

describe("excerptAroundLine", () => {
  it("keeps the imports, the whole enclosing function and stays under budget", () => {
    const body = Array.from({ length: 400 }, (_, i) => `export const v${i} = ${i};`).join("\n");
    const fn = 'export function render(el: HTMLElement, name: string) {\n  const x = 1;\n  el.innerHTML = name;\n  return x;\n}';
    const content = `import { a } from "a";\nconst b = require("b");\n\n${body}\n${fn}\n${body}`;
    const line = content.split("\n").findIndex((l) => l.includes("innerHTML")) + 1;
    const ex = excerptAroundLine(content, line, 2_000);
    expect(excerptChars(ex)).toBeLessThanOrEqual(2_000);
    expect(ex.parts[0]).toMatchObject({ startLine: 1, endLine: 2 });
    expect(ex.parts[1].text).toContain(fn);
    expect(partsAreVerbatim(content, ex)).toBe(true);
  });

  it("takes part of a single line that is longer than the budget", () => {
    const content = `a\n${"x".repeat(5_000)}TARGET${"y".repeat(5_000)}\nb`;
    const ex = excerptAroundLine(content, 2, 1_000, 5_000);
    expect(ex.parts).toHaveLength(1);
    expect(ex.parts[0].partial).toBe(true);
    expect(ex.parts[0].text).toContain("TARGET");
    expect(ex.parts[0].text.length).toBeLessThanOrEqual(1_000);
  });

  /** Property: excerpt is under budget, verbatim, and contains the target line. **Validates: fix-all large-file excerpt** */
  it("property: under budget, verbatim, includes the target line", () => {
    fc.assert(
      fc.property(fileArb, fc.nat(), fc.integer({ min: 200, max: 3_000 }), (content, pick, budget) => {
        const lines = content.split("\n");
        const line = (pick % lines.length) + 1;
        const ex = excerptAroundLine(content, line, budget);
        if (excerptChars(ex) > budget || !partsAreVerbatim(content, ex)) return false;
        return ex.parts.some((p) => p.startLine <= line && line <= p.endLine);
      })
    );
  });
});

describe("chunkFile", () => {
  it("property: chunks are under budget, verbatim, and cover every line in order", () => {
    fc.assert(
      fc.property(fileArb, fc.integer({ min: 200, max: 3_000 }), (content, budget) => {
        const chunks = chunkFile(content, budget);
        let next = 1;
        for (const ch of chunks) {
          if (excerptChars(ch) > budget || !partsAreVerbatim(content, ch)) return false;
          const bodyPart = ch.parts[ch.parts.length - 1];
          if (bodyPart.startLine !== next && !(bodyPart.partial && bodyPart.startLine === next - 1)) return false;
          next = bodyPart.endLine + 1;
        }
        return next === content.split("\n").length + 1;
      })
    );
  });
});

describe("findEvidenceLine", () => {
  it("finds the evidence snippet (or one of its lines) in the file", () => {
    const content = "a\nb\n  el.innerHTML = name;\nc";
    const ev = (c: string) => [{ id: "e", kind: "source_code" as const, label: "x", content: c }];
    expect(findEvidenceLine(content, ev("el.innerHTML = name;"))).toEqual({ line: 3, column: 2 });
    expect(findEvidenceLine(content, ev("3: nope\nel.innerHTML = name;"))?.line).toBe(3);
    expect(findEvidenceLine(content, ev("(표시할 코드가 없어요)"))).toBeNull();
  });
});
