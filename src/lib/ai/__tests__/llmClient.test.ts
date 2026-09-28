import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { callLlm } from "@/lib/ai/llmClient";

// Fake placeholder values only — never real keys.
const ENV = { LLM_PROVIDER: "openai", LLM_API_KEY: "test-key-llm" };

function okResponse(content: string) {
  return new Response(JSON.stringify({ choices: [{ message: { content } }] }), { status: 200 });
}

function unsupportedTemperature() {
  return new Response(
    JSON.stringify({
      error: {
        message: "Unsupported value: 'temperature' does not support 0 with this model.",
        type: "invalid_request_error",
        param: "temperature",
        code: "unsupported_value",
      },
    }),
    { status: 400 }
  );
}

function sentBodies(fetchMock: ReturnType<typeof vi.fn>): Record<string, unknown>[] {
  return fetchMock.mock.calls.map((c) => JSON.parse(String((c[1] as RequestInit).body)));
}

describe("callLlm (openai) temperature handling", () => {
  beforeEach(() => {
    vi.spyOn(console, "info").mockImplementation(() => {});
    for (const [k, v] of Object.entries(ENV)) vi.stubEnv(k, v);
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("sends the requested temperature to models that accept it", async () => {
    vi.stubEnv("LLM_MODEL", "temp-ok-model");
    const fetchMock = vi.fn().mockResolvedValue(okResponse('{"ok":true}'));
    vi.stubGlobal("fetch", fetchMock);

    const res = await callLlm({ system: "s", user: "u", temperature: 0 });

    expect(res.text).toBe('{"ok":true}');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(sentBodies(fetchMock)[0].temperature).toBe(0);
  });

  it("retries once without temperature when the model only supports the default", async () => {
    vi.stubEnv("LLM_MODEL", "fixed-temp-model-a");
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(unsupportedTemperature())
      .mockResolvedValueOnce(okResponse('{"ok":true}'));
    vi.stubGlobal("fetch", fetchMock);

    const res = await callLlm({ system: "s", user: "u", temperature: 0 });

    expect(res.text).toBe('{"ok":true}');
    expect(res.meta.httpStatus).toBe(200);
    const bodies = sentBodies(fetchMock);
    expect(bodies).toHaveLength(2);
    expect(bodies[0].temperature).toBe(0);
    expect(bodies[1]).not.toHaveProperty("temperature");
    // JSON mode is kept on the retry.
    expect(bodies[1].response_format).toEqual({ type: "json_object" });
  });

  it("remembers the model and skips temperature on later calls", async () => {
    vi.stubEnv("LLM_MODEL", "fixed-temp-model-b");
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(unsupportedTemperature())
      // A Response body can be read once, so every call needs a fresh one.
      .mockImplementation(async () => okResponse('{"ok":true}'));
    vi.stubGlobal("fetch", fetchMock);

    await callLlm({ system: "s", user: "u", temperature: 0 });
    await callLlm({ system: "s", user: "u", temperature: 0.1 });

    const bodies = sentBodies(fetchMock);
    expect(bodies).toHaveLength(3);
    expect(bodies[2]).not.toHaveProperty("temperature");
  });

  it("does not retry other 400 errors", async () => {
    vi.stubEnv("LLM_MODEL", "temp-ok-model-2");
    const other = new Response(
      JSON.stringify({ error: { message: "bad", param: "messages", code: "invalid_value" } }),
      { status: 400 }
    );
    const fetchMock = vi.fn().mockResolvedValueOnce(other);
    vi.stubGlobal("fetch", fetchMock);

    await expect(callLlm({ system: "s", user: "u", temperature: 0 })).rejects.toMatchObject({
      code: "http_error",
      httpStatus: 400,
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("callLlm gateway routing", () => {
  beforeEach(() => {
    vi.spyOn(console, "info").mockImplementation(() => {});
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("sends to the gateway base URL with a custom auth header and extra headers", async () => {
    vi.stubEnv("LLM_PROVIDER", "openai");
    vi.stubEnv("LLM_API_KEY", "test-gateway-key");
    vi.stubEnv("LLM_MODEL", "gateway-model");
    vi.stubEnv("LLM_BASE_URL", "https://gateway.example.test/v1/");
    vi.stubEnv("LLM_AUTH_HEADER", "api-key");
    vi.stubEnv("LLM_EXTRA_HEADERS", '{"x-tenant":"hoi"}');
    const fetchMock = vi.fn(async () => okResponse('{"ok":true}'));
    vi.stubGlobal("fetch", fetchMock);

    await callLlm({ system: "s", user: "u" });

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://gateway.example.test/v1/chat/completions");
    const headers = init.headers as Record<string, string>;
    expect(headers["api-key"]).toBe("test-gateway-key");
    expect(headers.authorization).toBeUndefined();
    expect(headers["x-tenant"]).toBe("hoi");
    expect(init.redirect).toBe("error");
  });

  it("refuses the official endpoint when a gateway is required but not set", async () => {
    vi.stubEnv("LLM_PROVIDER", "openai");
    vi.stubEnv("LLM_API_KEY", "test-key-llm");
    vi.stubEnv("LLM_REQUIRE_GATEWAY", "true");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(callLlm({ system: "s", user: "u" })).rejects.toMatchObject({ code: "not_configured" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("ignores non-https gateway URLs", async () => {
    const { resolveLlmConfig } = await import("@/lib/ai/llmConfig");
    expect(resolveLlmConfig({ LLM_PROVIDER: "openai", LLM_API_KEY: "k", LLM_BASE_URL: "http://gateway.example.test" }).baseUrl).toBeUndefined();
    expect(resolveLlmConfig({ LLM_PROVIDER: "openai", LLM_API_KEY: "k", LLM_BASE_URL: "http://localhost:4000/v1" }).baseUrl).toBe("http://localhost:4000/v1");
  });
});
