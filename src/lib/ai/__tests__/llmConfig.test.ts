import { describe, expect, it } from "vitest";
import { describeLlmConfig, isLlmConfigured, resolveLlmConfig } from "@/lib/ai/llmConfig";

// Fake placeholder values only — never real keys.
const K1 = "test-key-llm";
const K2 = "test-key-openai";

describe("resolveLlmConfig", () => {
  it("is disabled with no env", () => {
    const c = resolveLlmConfig({});
    expect(c.provider).toBe("none");
    expect(isLlmConfigured({})).toBe(false);
  });

  it("prefers LLM_API_KEY over OPENAI_API_KEY", () => {
    const c = resolveLlmConfig({ LLM_PROVIDER: "openai", LLM_API_KEY: K1, OPENAI_API_KEY: K2 });
    expect(c.keySource).toBe("LLM_API_KEY");
    expect(c.apiKey).toBe(K1);
  });

  it("falls back to OPENAI_API_KEY for openai (compat)", () => {
    const c = resolveLlmConfig({ LLM_PROVIDER: "openai", OPENAI_API_KEY: K2 });
    expect(c.keySource).toBe("OPENAI_API_KEY");
    expect(isLlmConfigured({ LLM_PROVIDER: "openai", OPENAI_API_KEY: K2 })).toBe(true);
  });

  it("treats a bare OPENAI_API_KEY as openai", () => {
    const c = resolveLlmConfig({ OPENAI_API_KEY: K2 });
    expect(c.provider).toBe("openai");
    expect(c.providerSource).toBe("OPENAI_API_KEY_COMPAT");
  });

  it("does not use OPENAI_API_KEY for other providers", () => {
    expect(isLlmConfigured({ LLM_PROVIDER: "anthropic", OPENAI_API_KEY: K2 })).toBe(false);
  });

  it("LLM_PROVIDER=none disables even with keys", () => {
    expect(isLlmConfigured({ LLM_PROVIDER: "none", LLM_API_KEY: K1 })).toBe(false);
  });

  it("model order: LLM_MODEL > OPENAI_MODEL > default", () => {
    expect(resolveLlmConfig({ LLM_API_KEY: K1, LLM_MODEL: "m1", OPENAI_MODEL: "m2" }).model).toBe("m1");
    expect(resolveLlmConfig({ LLM_API_KEY: K1, OPENAI_MODEL: "m2" }).model).toBe("m2");
    expect(resolveLlmConfig({ LLM_API_KEY: K1 }).modelSource).toBe("default");
  });

  it("describeLlmConfig never exposes the key value", () => {
    const d = describeLlmConfig({ LLM_PROVIDER: "openai", LLM_API_KEY: K1 });
    expect(d.apiKeyPresent).toBe(true);
    expect(JSON.stringify(d)).not.toContain(K1);
  });
});
