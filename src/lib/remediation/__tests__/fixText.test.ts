import { describe, expect, it } from "vitest";
import { FIX_SYSTEM_PROMPT, generateFix } from "@/lib/remediation/fixGenerator";
import { SYSTEM_PROMPT as FILE_FIX_PROMPT } from "@/lib/remediation/llmFileFix";
import type { SecurityFinding } from "@/lib/domain/types";

// 수정안(제안) 단계의 문구는 결과를 단정하지 않는다.
const CLAIMS_SOLVED = /해결했어요|해결됐어요|막았어요|고쳤어요|안전해졌어요/;
const HANGUL = /[가-힣]/;

function finding(verificationKey: string, remediation?: string): SecurityFinding {
  return {
    id: "f1",
    scanId: "s1",
    title: "t",
    severity: "high",
    category: "Injection",
    description: "",
    humanReadableImpact: "",
    whyItMatters: "",
    evidence: [],
    status: "detected",
    simulated: false,
    verificationKey,
    remediation,
    createdAt: "",
    updatedAt: "",
  };
}

describe("fix prompts keep their JSON contract", () => {
  it("legacy AI fix prompt keeps the same field names", () => {
    for (const key of ['"summary"', '"plainExplanation"', '"file"', '"before"', '"after"']) {
      expect(FIX_SYSTEM_PROMPT).toContain(key);
    }
  });

  it("file fix prompt keeps canFix/edits/reason fields", () => {
    for (const key of ['"canFix": true', '"summary"', '"plainExplanation"', '"edits"', '"before"', '"after"', '{ "canFix": false, "reason"']) {
      expect(FILE_FIX_PROMPT).toContain(key);
    }
  });

  it("both prompts forbid claiming the problem is solved at proposal time", () => {
    expect(FIX_SYSTEM_PROMPT).toContain("해결했어요");
    expect(FILE_FIX_PROMPT).toContain("해결했어요");
    expect(FILE_FIX_PROMPT).toMatch(/PROPOSAL/);
  });
});

describe("rule-based fix text", () => {
  const keys = [
    "idor:x", "secret:x", "headers:x", "xss:x", "inj:x", "trav:x", "expose:x",
    "bfla:x", "cookie:x", "brute:x", "enum:x", "tls:x", "exposed:x", "rls:x",
  ];

  it.each(keys)("%s: plain Korean proposal with a patch, no resolution claim", (key) => {
    const fix = generateFix(finding(key));
    expect(fix.summary).toMatch(HANGUL);
    expect(fix.plainExplanation).toMatch(HANGUL);
    expect(`${fix.summary} ${fix.plainExplanation}`).not.toMatch(CLAIMS_SOLVED);
    expect(fix.plainExplanation).toContain("확인해 주세요");
    expect(fix.diffs.length).toBeGreaterThan(0);
    expect(fix.applied).toBe(false);
  });

  it("fallback explains why there is no patch and what to do next", () => {
    const fix = generateFix(finding("unknown:x", "입력값 길이를 제한하세요."));
    expect(fix.diffs).toEqual([]);
    expect(fix.plainExplanation).toContain("입력값 길이를 제한하세요.");
    expect(fix.plainExplanation).toContain("다시 점검");
    expect(generateFix(finding("unknown:x")).summary).toMatch(HANGUL);
  });
});
