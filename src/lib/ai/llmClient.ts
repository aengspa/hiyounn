/**
 * 제공자 무관 LLM 클라이언트.
 *
 * 환경변수로 제공자를 고릅니다 (서버 전용, 절대 클라이언트에 노출 금지):
 *   LLM_PROVIDER = "openai" | "anthropic" | "gemini" | "none"
 *   LLM_API_KEY  = 발급받은 API 키
 *   LLM_MODEL    = (선택) 모델명. 미지정 시 제공자별 기본값 사용.
 *
 * 키가 없거나 provider=none 이면 isConfigured()가 false를 반환하고,
 * AI 스캐너는 조용히 비활성화됩니다(앱은 정상 동작).
 *
 * 제품 원칙: AI는 "해석·설명·수정안 생성"에만 사용합니다. 취약점의 실제 존재
 * 여부/수정 성공 여부는 결정적 테스트로 검증합니다.
 */

export type LlmProvider = "openai" | "anthropic" | "gemini" | "none";

const DEFAULT_MODEL: Record<Exclude<LlmProvider, "none">, string> = {
  openai: "gpt-4o-mini",
  anthropic: "claude-3-5-sonnet-latest",
  gemini: "gemini-1.5-flash",
};

export function getProvider(): LlmProvider {
  const p = (process.env.LLM_PROVIDER ?? "none").toLowerCase();
  if (p === "openai" || p === "anthropic" || p === "gemini") return p;
  return "none";
}

export function isConfigured(): boolean {
  return getProvider() !== "none" && Boolean(process.env.LLM_API_KEY);
}

function model(provider: Exclude<LlmProvider, "none">): string {
  return process.env.LLM_MODEL || DEFAULT_MODEL[provider];
}

/**
 * system + user 프롬프트를 보내고 텍스트 응답을 받습니다.
 * JSON만 받도록 프롬프트에서 지시하고, 여기서는 원문 텍스트를 반환합니다.
 */
export async function completeJson(
  system: string,
  user: string,
  timeoutMs = 30000
): Promise<string> {
  const provider = getProvider();
  if (provider === "none" || !process.env.LLM_API_KEY) {
    throw new Error("LLM is not configured");
  }
  const key = process.env.LLM_API_KEY;

  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    if (provider === "openai") {
      return await callOpenAi(key, model("openai"), system, user, controller.signal);
    }
    if (provider === "anthropic") {
      return await callAnthropic(key, model("anthropic"), system, user, controller.signal);
    }
    return await callGemini(key, model("gemini"), system, user, controller.signal);
  } finally {
    clearTimeout(t);
  }
}

async function callOpenAi(
  key: string,
  model: string,
  system: string,
  user: string,
  signal: AbortSignal
): Promise<string> {
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    signal,
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key}`,
    },
    body: JSON.stringify({
      model,
      messages: [
        { role: "system", content: system },
        { role: "user", content: user },
      ],
      temperature: 0.1,
      response_format: { type: "json_object" },
    }),
  });
  if (!res.ok) throw new Error(`OpenAI ${res.status}`);
  const data = await res.json();
  return data.choices?.[0]?.message?.content ?? "";
}

async function callAnthropic(
  key: string,
  model: string,
  system: string,
  user: string,
  signal: AbortSignal
): Promise<string> {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    signal,
    headers: {
      "content-type": "application/json",
      "x-api-key": key,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model,
      max_tokens: 2048,
      temperature: 0.1,
      system,
      messages: [{ role: "user", content: user }],
    }),
  });
  if (!res.ok) throw new Error(`Anthropic ${res.status}`);
  const data = await res.json();
  return data.content?.[0]?.text ?? "";
}

async function callGemini(
  key: string,
  model: string,
  system: string,
  user: string,
  signal: AbortSignal
): Promise<string> {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`;
  const res = await fetch(url, {
    method: "POST",
    signal,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: system }] },
      contents: [{ role: "user", parts: [{ text: user }] }],
      generationConfig: {
        temperature: 0.1,
        responseMimeType: "application/json",
      },
    }),
  });
  if (!res.ok) throw new Error(`Gemini ${res.status}`);
  const data = await res.json();
  return data.candidates?.[0]?.content?.parts?.[0]?.text ?? "";
}
