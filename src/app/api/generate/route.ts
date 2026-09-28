import { NextRequest, NextResponse } from "next/server";
import { requireUserId } from "@/lib/auth";
import { handleApiError } from "@/lib/api";
import { callLlm, LlmError } from "@/lib/ai/llmClient";
import { LIMITS } from "@/lib/config/limits";

export const runtime = "nodejs";

/**
 * 범용 텍스트 생성 엔드포인트.
 *
 * 공통 LLM 설정(llmConfig)을 사용한다: LLM_PROVIDER / LLM_API_KEY / LLM_MODEL,
 * OpenAI에 한해 OPENAI_API_KEY / OPENAI_MODEL 호환. 서버 키로 비용이 드는
 * 호출이므로 로그인한 사용자만 쓸 수 있다.
 */
const MAX_PROMPT_CHARS = 8000;

export async function POST(req: NextRequest) {
  try {
    await requireUserId();

    let body: { prompt?: unknown };
    try {
      body = await req.json();
    } catch {
      return NextResponse.json({ error: "잘못된 요청 형식입니다." }, { status: 400 });
    }

    const prompt = typeof body.prompt === "string" ? body.prompt.trim() : "";
    if (!prompt) {
      return NextResponse.json({ error: "prompt를 입력해 주세요." }, { status: 400 });
    }
    if (prompt.length > MAX_PROMPT_CHARS) {
      return NextResponse.json({ error: "요청이 너무 길어요." }, { status: 413 });
    }

    // ── 사이트 용도에 맞게 이 지시문을 바꾸세요 ──────────────────
    const systemInstruction = "사용자의 요청에 한국어로, 간결하고 정확하게 답하라.";
    // ────────────────────────────────────────────────────────────

    const { text } = await callLlm({
      system: systemInstruction,
      user: prompt,
      json: false,
      guard: false,
      temperature: 0.7,
      timeoutMs: LIMITS.llmCallTimeoutMs,
      purpose: "generate",
    });
    return NextResponse.json({ text });
  } catch (err) {
    if (err instanceof LlmError) {
      if (err.code === "not_configured") {
        return NextResponse.json({ error: "AI 설정이 아직 준비되지 않았어요." }, { status: 503 });
      }
      const msg = err.code === "timeout" ? "AI 응답 시간이 초과되었습니다." : "AI 요청에 실패했습니다.";
      return NextResponse.json({ error: msg, correlationId: err.correlationId }, { status: 502 });
    }
    return handleApiError(err);
  }
}
