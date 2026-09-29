import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SECURITY_PREAMBLE, buildSystemPrompt, callLlm, completeJson } from "@/lib/ai/llmClient";
import { USER_FRIENDLY_STYLE } from "@/lib/ai/userFriendlyStyle";

// 공통 설명 지침이 모든 LLM 호출 경로(system 프롬프트)에 실제로 실리는지 확인한다.
// 문구 자체의 쉬움은 이 테스트로 증명할 수 없다(실제 모델 응답 확인 필요).

function okResponse(content: string) {
  return new Response(JSON.stringify({ choices: [{ message: { content } }] }), { status: 200 });
}

function sentSystem(fetchMock: ReturnType<typeof vi.fn>, call = 0): string {
  const body = JSON.parse(String((fetchMock.mock.calls[call][1] as RequestInit).body));
  return body.messages.find((m: { role: string }) => m.role === "system").content;
}

describe("buildSystemPrompt", () => {
  it("보안 서문 → 설명 지침 → 작업별 지시 순서로 조립한다", () => {
    const task = "TASK-SCHEMA: return {\"verdict\":\"fixed|still_present\"}";
    const out = buildSystemPrompt({ system: task });
    const a = out.indexOf(SECURITY_PREAMBLE);
    const b = out.indexOf(USER_FRIENDLY_STYLE);
    const c = out.indexOf(task);
    expect(a).toBe(0);
    expect(b).toBeGreaterThan(a);
    expect(c).toBeGreaterThan(b);
    // 작업별 지시(응답 스키마)는 한 글자도 바뀌지 않는다.
    expect(out.endsWith(task)).toBe(true);
  });

  it("userFacing:false면 설명 지침만 빠지고 보안 서문은 남는다", () => {
    const out = buildSystemPrompt({ system: "t", userFacing: false });
    expect(out).toContain(SECURITY_PREAMBLE);
    expect(out).not.toContain(USER_FRIENDLY_STYLE);
  });

  it("guard:false(범용 생성기)면 아무것도 붙이지 않는다", () => {
    expect(buildSystemPrompt({ system: "t", guard: false })).toBe("t");
  });
});

describe("LLM 호출 경로에 설명 지침이 전달된다", () => {
  beforeEach(() => {
    vi.spyOn(console, "info").mockImplementation(() => {});
    vi.stubEnv("LLM_PROVIDER", "openai");
    vi.stubEnv("LLM_API_KEY", "test-key-style");
    vi.stubEnv("LLM_MODEL", "style-test-model");
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("callLlm 직접 호출", async () => {
    const fetchMock = vi.fn(async () => okResponse('{"ok":true}'));
    vi.stubGlobal("fetch", fetchMock);
    await callLlm({ system: "REVERIFY-TASK", user: "u", purpose: "reverify" });
    const system = sentSystem(fetchMock);
    expect(system.startsWith(SECURITY_PREAMBLE)).toBe(true);
    expect(system).toContain(USER_FRIENDLY_STYLE);
    expect(system.endsWith("REVERIFY-TASK")).toBe(true);
  });

  it("completeJson 호출", async () => {
    const fetchMock = vi.fn(async () => okResponse('{"ok":true}'));
    vi.stubGlobal("fetch", fetchMock);
    await completeJson("SCAN-TASK", "u", 1000, "scan");
    const system = sentSystem(fetchMock);
    expect(system.startsWith(SECURITY_PREAMBLE)).toBe(true);
    expect(system).toContain(USER_FRIENDLY_STYLE);
    expect(system.endsWith("SCAN-TASK")).toBe(true);
  });

  it("user 메시지(코드·근거)는 지침 때문에 바뀌지 않는다", async () => {
    const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) => okResponse('{"ok":true}'));
    vi.stubGlobal("fetch", fetchMock);
    const code = "// file: src/a.js\nconst q = \"SELECT * FROM t WHERE id=\" + id;";
    await callLlm({ system: "t", user: code });
    const body = JSON.parse(String((fetchMock.mock.calls[0][1] as RequestInit).body));
    expect(body.messages.find((m: { role: string }) => m.role === "user").content).toBe(code);
  });
});