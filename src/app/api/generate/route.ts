import { NextRequest, NextResponse } from "next/server";

export const runtime = "nodejs";

// 이 라우트가 사용하는 환경변수:
//   OPENAI_API_KEY  (필수) — 코드에 절대 쓰지 말 것. 서버 환경변수로만 읽음.
//   OPENAI_MODEL    (선택) — 미지정 시 아래 기본값 사용.
//
// 기본 모델은 존재가 확인된 gpt-4o-mini로 둡니다. 다른 모델(예: 신규 모델)을
// 쓰려면 코드를 고치지 말고 Vercel 환경변수 OPENAI_MODEL에 이름만 넣으세요.
const DEFAULT_MODEL = "gpt-4o-mini";

export async function POST(req: NextRequest) {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    return NextResponse.json(
      { error: "서버에 OPENAI_API_KEY가 설정되지 않았습니다." },
      { status: 500 }
    );
  }

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

  const model = process.env.OPENAI_MODEL || DEFAULT_MODEL;

  // ── 사이트 용도에 맞게 이 지시문을 바꾸세요 ──────────────────
  // 예: "입력한 키워드로 블로그 제목 5개를 만들어라" 등
  const systemInstruction =
    "사용자의 요청에 한국어로, 간결하고 정확하게 답하라.";
  // ────────────────────────────────────────────────────────────

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);

  try {
    const res = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      signal: controller.signal,
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: "system", content: systemInstruction },
          { role: "user", content: prompt },
        ],
        temperature: 0.7,
      }),
    });

    if (!res.ok) {
      return NextResponse.json(
        { error: "AI 요청에 실패했습니다." },
        { status: 502 }
      );
    }

    const data = await res.json();
    const text = data.choices?.[0]?.message?.content ?? "";
    return NextResponse.json({ text });
  } catch (err) {
    const msg =
      err instanceof Error && err.name === "AbortError"
        ? "AI 응답 시간이 초과되었습니다."
        : "AI 요청 중 오류가 발생했습니다.";
    return NextResponse.json({ error: msg }, { status: 502 });
  } finally {
    clearTimeout(timeout);
  }
}
