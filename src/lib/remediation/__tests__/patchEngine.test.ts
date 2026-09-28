import { describe, expect, it } from "vitest";
import { applyDiffsAtomically, safeProjectPath } from "@/lib/remediation/patchEngine";

const original = {
  "src/a.ts": "const a = 1;\nconst b = 2;\n",
  "src/b.ts": "export function f() {\n  return eval(x);\n}\n",
};

describe("safeProjectPath", () => {
  it("rejects traversal and absolute paths", () => {
    expect(safeProjectPath("../etc/passwd")).toBeNull();
    expect(safeProjectPath("/etc/passwd")).toBeNull();
    expect(safeProjectPath("C:/x.ts")).toBeNull();
    expect(safeProjectPath("src/./a.ts")).toBe("src/a.ts");
  });
});

describe("applyDiffsAtomically", () => {
  it("applies an exact replacement", () => {
    const w = { ...original };
    const r = applyDiffsAtomically(w, original, [
      { file: "src/a.ts", patch: "", beforeText: "const a = 1;", afterText: "const a = 10;" },
    ]);
    expect(r.ok).toBe(true);
    expect(w["src/a.ts"]).toContain("const a = 10;");
  });

  it("is atomic: one bad diff leaves every file untouched", () => {
    const w = { ...original };
    const r = applyDiffsAtomically(w, original, [
      { file: "src/a.ts", patch: "", beforeText: "const a = 1;", afterText: "const a = 10;" },
      { file: "src/b.ts", patch: "", beforeText: "not in file", afterText: "x" },
    ]);
    expect(r).toEqual({ ok: false, failure: "before_not_found", file: "src/b.ts" });
    expect(w).toEqual(original);
  });

  it("does not invent files or escape the project", () => {
    const w = { ...original };
    expect(
      applyDiffsAtomically(w, original, [{ file: "src/missing.ts", patch: "", beforeText: "a", afterText: "b" }])
    ).toMatchObject({ ok: false, failure: "file_not_found" });
    expect(
      applyDiffsAtomically(w, original, [{ file: "../x.ts", patch: "", beforeText: "a", afterText: "b" }])
    ).toMatchObject({ ok: false, failure: "unsafe_path" });
  });

  it("rejects insertion-only diffs without a known position", () => {
    const w = { ...original };
    const r = applyDiffsAtomically(w, original, [{ file: "src/a.ts", patch: "+ added line" }]);
    expect(r).toMatchObject({ ok: false, failure: "insertion_point_unknown" });
  });

  it("rejects ambiguous matches", () => {
    const o = { "x.ts": "foo();\nfoo();\n" };
    const w = { ...o };
    const r = applyDiffsAtomically(w, o, [{ file: "x.ts", patch: "", beforeText: "foo();", afterText: "bar();" }]);
    expect(r).toMatchObject({ ok: false, failure: "ambiguous_match" });
  });

  it("detects conflicts with an earlier fix", () => {
    const w = { ...original };
    applyDiffsAtomically(w, original, [
      { file: "src/a.ts", patch: "", beforeText: "const a = 1;", afterText: "const a = 10;" },
    ]);
    const r = applyDiffsAtomically(w, original, [
      { file: "src/a.ts", patch: "", beforeText: "const a = 1;", afterText: "const a = 99;" },
    ]);
    expect(r).toMatchObject({ ok: false, failure: "conflict" });
  });

  it("creates a new file only in explicit create mode", () => {
    const w: Record<string, string> = { ...original };
    const r = applyDiffsAtomically(w, original, [
      { file: "src/new.ts", patch: "", afterText: "export {};", mode: "create" },
    ]);
    expect(r.ok).toBe(true);
    expect(w["src/new.ts"]).toBe("export {};");
    const again = applyDiffsAtomically(w, original, [
      { file: "src/a.ts", patch: "", afterText: "x", mode: "create" },
    ]);
    expect(again).toMatchObject({ ok: false, failure: "file_exists" });
  });
});
