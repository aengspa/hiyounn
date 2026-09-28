"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui";

/**
 * 같은 프로젝트에 코드를 새로 올린다(ZIP 또는 붙여넣기). 다음 점검은 이전 점검과
 * 비교해 바뀐 파일만 AI가 새로 보고, 나머지는 이전 AI 결과를 이어서 보여 준다.
 */
export function ReuploadForm({ projectId }: { projectId: string }) {
  const router = useRouter();
  const [mode, setMode] = useState<"zip" | "paste">("zip");
  const [code, setCode] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: "ok" | "error"; text: string } | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      let res: Response;
      if (mode === "zip") {
        if (!file) throw new Error("ZIP 파일을 골라 주세요.");
        const form = new FormData();
        form.set("file", file);
        res = await fetch(`/api/projects/${encodeURIComponent(projectId)}/versions`, { method: "POST", body: form });
      } else {
        res = await fetch(`/api/projects/${encodeURIComponent(projectId)}/versions`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ sourceCode: code }),
        });
      }
      const data = await res.json().catch(() => null);
      if (!res.ok) throw new Error(data?.message ?? "코드를 올리지 못했어요.");
      const n = Array.isArray(data?.changedFiles) ? data.changedFiles.length : 0;
      setMessage({ tone: "ok", text: `새 코드를 올렸어요. 바뀐 파일 ${n}개만 AI가 새로 보고, 나머지는 이전 결과를 이어서 보여 줘요. 위의 ‘다시 점검하기’를 눌러 주세요.` });
      setCode("");
      setFile(null);
      router.refresh();
    } catch (err) {
      setMessage({ tone: "error", text: err instanceof Error ? err.message : "코드를 올리지 못했어요." });
    } finally {
      setBusy(false);
    }
  }

  return (
    <details className="rounded-3xl border border-line bg-surface p-4 sm:p-5">
      <summary className="cursor-pointer text-base font-bold text-ink">코드 새로 올리기</summary>
      <form onSubmit={submit} className="mt-3 space-y-3">
        <div className="flex gap-2 text-sm">
          {(["zip", "paste"] as const).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => setMode(m)}
              aria-pressed={mode === m}
              className={`rounded-xl border px-3 py-1.5 font-bold ${mode === m ? "border-brand-800 text-brand-800" : "border-line text-ink-subtle"}`}
            >
              {m === "zip" ? "ZIP 파일" : "코드 붙여넣기"}
            </button>
          ))}
        </div>
        {mode === "zip" ? (
          <input
            type="file"
            accept=".zip,application/zip"
            aria-label="프로젝트 ZIP"
            onChange={(e) => setFile(e.currentTarget.files?.[0] ?? null)}
            className="block w-full text-sm"
          />
        ) : (
          <textarea
            value={code}
            onChange={(e) => setCode(e.currentTarget.value)}
            aria-label="새 코드"
            rows={8}
            placeholder={"// file: src/server.js\n..."}
            className="w-full rounded-2xl border border-line-input bg-surface p-3 font-mono text-xs"
          />
        )}
        <Button type="submit" disabled={busy} aria-busy={busy}>
          새 코드 올리기
        </Button>
        {message && (
          <p role="status" className={`text-sm ${message.tone === "ok" ? "text-success" : "text-danger"}`}>
            {message.text}
          </p>
        )}
      </form>
    </details>
  );
}
