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
  /**
   * OpenAI 호환 게이트웨이 주소(LLM_BASE_URL). 있으면 모든 openai 호출이
   * 공식 api.openai.com 대신 이 주소로 간다.
   */
  baseUrl?: string;
  /** 키를 실을 헤더(LLM_AUTH_HEADER). 기본 authorization(Bearer). */
  authHeader: string;
  /** 게이트웨이가 요구하는 추가 헤더(LLM_EXTRA_HEADERS, JSON 객체). */
  extraHeaders: Record<string, string>;
  /** LLM_REQUIRE_GATEWAY=true면 게이트웨이 없이 공식 엔드포인트로 가지 않는다. */
  requireGateway: boolean;
  keySource: "LLM_API_KEY" | "OPENAI_API_KEY" | null;
  providerSource: "LLM_PROVIDER" | "OPENAI_API_KEY_COMPAT" | "unset";
  modelSource: "LLM_MODEL" | "OPENAI_MODEL" | "default" | null;
}

function clean(v: string | undefined): string | undefined {
  const t = v?.trim();
  return t ? t : undefined;
}

/** https만(개발용 localhost는 http 허용). 쿼리·자격 증명이 든 주소는 받지 않는다. */
function parseBaseUrl(raw: string | undefined): string | undefined {
  const v = clean(raw);
  if (!v) return undefined;
  try {
    const u = new URL(v);
    const local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
    if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) return undefined;
    if (u.username || u.password || u.search || u.hash) return undefined;
    return u.toString().replace(/\/+$/, "");
  } catch {
    return undefined;
  }
}

const HEADER_NAME = /^[A-Za-z0-9-]{1,64}$/;

function parseExtraHeaders(raw: string | undefined): Record<string, string> {
  const v = clean(raw);
  if (!v) return {};
  try {
    const obj = JSON.parse(v) as unknown;
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) return {};
    const out: Record<string, string> = {};
    for (const [k, val] of Object.entries(obj as Record<string, unknown>)) {
      if (HEADER_NAME.test(k) && typeof val === "string" && !/[\r\n]/.test(val)) out[k.toLowerCase()] = val;
    }
    return out;
  } catch {
    return {};
  }
}

export function resolveLlmConfig(env: Env = process.env): ResolvedLlmConfig {
  const rawProvider = clean(env.LLM_PROVIDER)?.toLowerCase();
  const gateway = {
    baseUrl: parseBaseUrl(env.LLM_BASE_URL),
    authHeader: HEADER_NAME.test(clean(env.LLM_AUTH_HEADER) ?? "") ? clean(env.LLM_AUTH_HEADER)!.toLowerCase() : "authorization",
    extraHeaders: parseExtraHeaders(env.LLM_EXTRA_HEADERS),
    requireGateway: (clean(env.LLM_REQUIRE_GATEWAY) ?? "").toLowerCase() === "true",
  };
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
    return { provider, apiKey: undefined, model: undefined, keySource: null, providerSource, modelSource: null, ...gateway };
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

  return { provider, apiKey, model, keySource, providerSource, modelSource, ...gateway };
}

/** 게이트웨이를 요구하는데 없으면 호출하지 않는다(공식 엔드포인트 사용 거부). */
function gatewayBlocked(c: ResolvedLlmConfig): boolean {
  return c.requireGateway && (c.provider !== "openai" || !c.baseUrl);
}

/** 키가 준비된 제공자가 있으면 true. */
export function isLlmConfigured(env: Env = process.env): boolean {
  const c = resolveLlmConfig(env);
  return c.provider !== "none" && Boolean(c.apiKey) && !gatewayBlocked(c);
}

/** 진단용. 키 값 대신 존재 여부만 담는다. */
export function describeLlmConfig(env: Env = process.env) {
  const c = resolveLlmConfig(env);
  return {
    provider: c.provider,
    configured: c.provider !== "none" && Boolean(c.apiKey) && !gatewayBlocked(c),
    gateway: c.baseUrl ? new URL(c.baseUrl).host : null,
    requireGateway: c.requireGateway,
    apiKeyPresent: Boolean(c.apiKey),
    keySource: c.keySource,
    providerSource: c.providerSource,
    model: c.model ?? null,
    modelSource: c.modelSource,
  };
}
