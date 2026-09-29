"use client";

import { useState } from "react";
import { Button, Card, FriendlyError } from "@/components/ui";

export default function Generator() {
  const [prompt, setPrompt] = useState("");
  const [result, setResult] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function generate(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setResult("");
    setLoading(true);
    try {
      const response = await fetch("/api/generate", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ prompt }),
      });
      const data = await response.json().catch(() => null);
      if (!response.ok || !data || data.error) {
        setError(friendlyGenerateError(data?.error, response.status));
      } else {
        setResult(typeof data.text === "string" ? data.text : "");
      }
    } catch {
      setError("연결이 잠깐 끊겼어요. 인터넷 연결을 확인하고 다시 시도해 주세요.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card variant="raised" className="mx-auto w-full max-w-2xl p-5 sm:p-6">
      <form onSubmit={generate} className="space-y-4" aria-busy={loading}>
        <div>
          <label htmlFor="generator-prompt" className="block text-base font-semibold text-ink">
            호이에게 요청할 내용
          </label>
          <textarea
            id="generator-prompt"
            value={prompt}
            onChange={(event) => setPrompt(event.target.value)}
            rows={4}
            aria-invalid={Boolean(error)}
            aria-describedby={error ? "generator-error" : "generator-hint"}
            placeholder="무엇을 도와드릴까요?"
            className="mt-2 min-h-32 w-full resize-y rounded-2xl border-2 border-line-input bg-surface px-4 py-3 text-ink hover:border-brand-700 focus:border-brand-700"
          />
          <p id="generator-hint" className="mt-2 text-sm text-ink-muted">필요한 결과와 확인할 조건을 함께 적어 주세요.</p>
        </div>
        <Button type="submit" disabled={loading || !prompt.trim()} aria-busy={loading} className="w-full">
          {loading ? "요청을 살펴보고 있어요…" : "호이에게 요청하기"}
        </Button>
      </form>

      {error && (
        <FriendlyError
          className="mt-4"
          title="요청을 마치지 못했어요"
          description={<span id="generator-error">{error}</span>}
        />
      )}

      {result && (
        <div role="status" aria-live="polite" className="mt-4 whitespace-pre-wrap break-words rounded-2xl border border-line bg-surface-warm p-4 text-ink">
          {result}
        </div>
      )}
    </Card>
  );
}

function friendlyGenerateError(error: unknown, status: number): string {
  if (error === "forbidden" || status === 401 || status === 403) {
    return "요청할 권한을 확인하지 못했어요. 로그인 상태를 확인해 주세요.";
  }
  if (status === 429) return "요청이 잠시 몰렸어요. 잠깐 기다린 뒤 다시 시도해 주세요.";
  return "지금은 결과를 만들기 어려워요. 잠시 뒤 다시 시도해 주세요.";
}
