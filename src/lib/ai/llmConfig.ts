/**
 * 공통 LLM 설정 (서버 전용).
 *
 * 스캔·수정안·보고서·AI 재검증·/api/generate가 모두 이 모듈 하나로 제공자,
 * 키, 모델을 결정한다. 호출부마다 다른 환경변수를 읽던 문제를 없앤다.
 *
 * 선택한 방식: LLM_API_KEY를 우선 사용하고, 없으면 OPENAI_API_KEY를 호환
 * 설정으로 사용한다. 운영 환경이 어느 이름으로 키를 넣었든 동작하도록 하기
 * 위함이다. 새 설정은 LLM_PROVIDER=openai + LLM_API_KEY를 권장한다.
 *
 *   제공자: LLM_PROVIDER가 있으면 그 값(none이면 비활성).
 *           LLM_PROVIDER가 없고 OPENAI_API_KEY만 있으면 openai로 본다.
 *   키:     LLM_API_KEY > (openai일 때) OPENAI_API_KEY
 *   모델:   LLM_MODEL > (openai일 때) OPENAI_MODEL > 제공자 기본값
 *
 * 키 값은 이 모듈 밖으로 나가지 않는다. 진단에는 describeLlmConfig()의
 * boolean만 사용한다. 로그·응답·테스트에 키를 출력하지 않는다.
 */

export type LlmProvider = "openai" | "anthropic" | "gemini" | "none";
export type ActiveLlmProvider = Exclude<LlmProvider, "none">;

export const DEFAULT_LLM_MODEL: Record<ActiveLlmProvider, string> = {
  openai: "gpt-4o-mini",
  anthropic: "claude-3-5-sonnet-latest",
  gemini: "gemini-1.5-flash",
};

type Env = Record<string, string | undefined>;

export interface ResolvedLlmConfig {
  provider: LlmProvider;
  /** 서버 내부 호출용. 절대 로그·응답에 넣지 말 것. */
  apiKey: string | undefined;
  model: string | undefined;
  keySource: "LLM_API_KEY" | "OPENAI_API_KEY" | null;
  providerSource: "LLM_PROVIDER" | "OPENAI_API_KEY_COMPAT" | "unset";
  modelSource: "LLM_MODEL" | "OPENAI_MODEL" | "default" | null;
}

function clean(v: string | undefined): string | undefined {
  const t = v?.trim();
  return t ? t : undefined;
}

export function resolveLlmConfig(env: Env = process.env): ResolvedLlmConfig {
  const rawProvider = clean(env.LLM_PROVIDER)?.toLowerCase();
  const llmKey = clean(env.LLM_API_KEY);
  const openaiKey = clean(env.OPENAI_API_KEY);

  let provider: LlmProvider = "none";
  let providerSource: ResolvedLlmConfig["providerSource"] = "unset";
  if (rawProvider) {
    providerSource = "LLM_PROVIDER";
    if (rawProvider === "openai" || rawProvider === "anthropic" || rawProvider === "gemini") {
      provider = rawProvider;
    }
  } else if (openaiKey || llmKey) {
    // LLM_PROVIDER 없이 키만 있는 기존 운영 설정은 OpenAI로 본다.
    provider = "openai";
    providerSource = "OPENAI_API_KEY_COMPAT";
  }

  if (provider === "none") {
    return { provider, apiKey: undefined, model: undefined, keySource: null, providerSource, modelSource: null };
  }

  let apiKey: string | undefined;
  let keySource: ResolvedLlmConfig["keySource"] = null;
  if (llmKey) {
    apiKey = llmKey;
    keySource = "LLM_API_KEY";
  } else if (provider === "openai" && openaiKey) {
    apiKey = openaiKey;
    keySource = "OPENAI_API_KEY";
  }

  let model: string;
  let modelSource: ResolvedLlmConfig["modelSource"];
  const llmModel = clean(env.LLM_MODEL);
  const openaiModel = clean(env.OPENAI_MODEL);
  if (llmModel) {
    model = llmModel;
    modelSource = "LLM_MODEL";
  } else if (provider === "openai" && openaiModel) {
    model = openaiModel;
    modelSource = "OPENAI_MODEL";
  } else {
    model = DEFAULT_LLM_MODEL[provider];
    modelSource = "default";
  }

  return { provider, apiKey, model, keySource, providerSource, modelSource };
}

/** 키가 준비된 제공자가 있으면 true. */
export function isLlmConfigured(env: Env = process.env): boolean {
  const c = resolveLlmConfig(env);
  return c.provider !== "none" && Boolean(c.apiKey);
}

/** 진단용. 키 값 대신 존재 여부만 담는다. */
export function describeLlmConfig(env: Env = process.env) {
  const c = resolveLlmConfig(env);
  return {
    provider: c.provider,
    configured: c.provider !== "none" && Boolean(c.apiKey),
    apiKeyPresent: Boolean(c.apiKey),
    keySource: c.keySource,
    providerSource: c.providerSource,
    model: c.model ?? null,
    modelSource: c.modelSource,
  };
}
