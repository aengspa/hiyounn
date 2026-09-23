// Serverless function: POST /api/chat
//
// A provider-agnostic chat proxy. The API key is read ONLY from
// process.env.LLM_API_KEY and is never written in code or returned to the
// client. Configure via environment variables (e.g. Vercel Project Settings):
//
//   LLM_PROVIDER = "openai" | "anthropic" | "gemini"   (default: "openai")
//   LLM_API_KEY  = <your secret key>                    (required)
//   LLM_MODEL    = <optional model name>
//
// Request body: { "messages": [{ "role": "user", "content": "..." }], "system"?: "..." }
// Response:     { "reply": "..." }

const DEFAULT_MODEL = {
  openai: "gpt-4o-mini",
  anthropic: "claude-3-5-sonnet-latest",
  gemini: "gemini-1.5-flash",
};

function getProvider() {
  const p = (process.env.LLM_PROVIDER || "openai").toLowerCase();
  return p === "anthropic" || p === "gemini" ? p : "openai";
}

module.exports = async function handler(req, res) {
  // CORS: allow the browser to call this function. Tighten the origin in
  // production by setting ALLOWED_ORIGIN to your site's URL.
  const allowedOrigin = process.env.ALLOWED_ORIGIN || "*";
  res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "content-type");

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method Not Allowed" });
  }

  const apiKey = process.env.LLM_API_KEY;
  if (!apiKey) {
    // Never leak whether/what the key is — just report it's not configured.
    return res.status(500).json({ error: "LLM is not configured on the server." });
  }

  // Parse body (Vercel usually pre-parses JSON, but be defensive).
  let body = req.body;
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch {
      return res.status(400).json({ error: "Invalid JSON body." });
    }
  }
  body = body || {};

  const system = typeof body.system === "string" ? body.system : "";
  const messages = Array.isArray(body.messages) ? body.messages : null;
  if (!messages || messages.length === 0) {
    return res.status(400).json({ error: "`messages` array is required." });
  }

  const provider = getProvider();
  const model = process.env.LLM_MODEL || DEFAULT_MODEL[provider];

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);

  try {
    let reply = "";
    if (provider === "openai") {
      reply = await callOpenAi(apiKey, model, system, messages, controller.signal);
    } else if (provider === "anthropic") {
      reply = await callAnthropic(apiKey, model, system, messages, controller.signal);
    } else {
      reply = await callGemini(apiKey, model, system, messages, controller.signal);
    }
    return res.status(200).json({ reply });
  } catch (err) {
    const msg = err && err.name === "AbortError" ? "Upstream timeout." : "Upstream request failed.";
    return res.status(502).json({ error: msg });
  } finally {
    clearTimeout(timeout);
  }
};

// Force the Node.js serverless runtime (global fetch requires Node 18+).
module.exports.config = { runtime: "nodejs20.x" };

async function callOpenAi(key, model, system, messages, signal) {
  const msgs = system ? [{ role: "system", content: system }, ...messages] : messages;
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    signal,
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key}`,
    },
    body: JSON.stringify({ model, messages: msgs, temperature: 0.2 }),
  });
  if (!res.ok) throw new Error(`OpenAI ${res.status}`);
  const data = await res.json();
  return data.choices?.[0]?.message?.content ?? "";
}

async function callAnthropic(key, model, system, messages, signal) {
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
      temperature: 0.2,
      system: system || undefined,
      messages: messages.map((m) => ({
        role: m.role === "assistant" ? "assistant" : "user",
        content: String(m.content ?? ""),
      })),
    }),
  });
  if (!res.ok) throw new Error(`Anthropic ${res.status}`);
  const data = await res.json();
  return data.content?.[0]?.text ?? "";
}

async function callGemini(key, model, system, messages, signal) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`;
  const res = await fetch(url, {
    method: "POST",
    signal,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      systemInstruction: system ? { parts: [{ text: system }] } : undefined,
      contents: messages.map((m) => ({
        role: m.role === "assistant" ? "model" : "user",
        parts: [{ text: String(m.content ?? "") }],
      })),
      generationConfig: { temperature: 0.2 },
    }),
  });
  if (!res.ok) throw new Error(`Gemini ${res.status}`);
  const data = await res.json();
  return data.candidates?.[0]?.content?.parts?.[0]?.text ?? "";
}
