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
    <details className="group rounded-3xl border-2 border-line bg-surface p-4 shadow-warm open:bg-surface-warm sm:p-5">
      <summary className="flex min-h-11 cursor-pointer list-none items-center justify-between gap-3 text-base font-extrabold text-ink marker:content-none hover:text-brand-800 [&::-webkit-details-marker]:hidden">
        <span>코드 새로 올리기</span>
        <span
          aria-hidden="true"
          className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border-2 border-brand-300 bg-primary-soft text-lg leading-none text-brand-900 transition-transform group-open:rotate-45 motion-reduce:transition-none"
        >
          +
        </span>
      </summary>
      <form onSubmit={submit} className="mt-3 space-y-4 border-t-2 border-dashed border-line pt-4">
        <div className="inline-flex gap-1 rounded-2xl border-2 border-line bg-surface-warm p-1 text-sm">
          {(["zip", "paste"] as const).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => setMode(m)}
              aria-pressed={mode === m}
              className={`min-h-11 rounded-xl border-2 px-4 font-bold ${
                mode === m
                  ? "border-line-input bg-surface text-brand-800 shadow-[0_2px_0_var(--border-strong)]"
                  : "border-transparent text-ink-subtle hover:bg-surface hover:text-ink"
              }`}
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
            className="block min-h-12 w-full rounded-2xl border-2 border-line-input bg-surface p-2 text-sm file:mr-3 file:min-h-10 file:rounded-xl file:border-0 file:bg-primary-soft file:px-4 file:font-bold file:text-brand-800"
          />
        ) : (
          <textarea
            value={code}
            onChange={(e) => setCode(e.currentTarget.value)}
            aria-label="새 코드"
            rows={8}
            placeholder={"// file: src/server.js\n..."}
            className="w-full rounded-2xl border-2 border-line-input bg-surface p-3 font-mono text-sm hover:border-brand-700 focus:border-brand-700"
          />
        )}
        <Button type="submit" variant="secondary" disabled={busy} aria-busy={busy}>
          새 코드 올리기
        </Button>
        {message && (
          <p
            role="status"
            className={`rounded-2xl border-2 px-4 py-3 text-sm font-semibold ${
              message.tone === "ok"
                ? "border-[#bfe0c8] bg-success-soft text-success"
                : "border-[#f3c4bd] bg-danger-soft text-danger"
            }`}
          >
            {message.text}
          </p>
        )}
      </form>
    </details>
  );
}
