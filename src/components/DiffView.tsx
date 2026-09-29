"use client";

import { useState } from "react";
import { fileDiff, type DiffHunk } from "@/lib/diff/lineDiff";

/** 파일 하나(또는 수정 조각 하나)의 줄 단위 비교. 지운 줄은 빨강, 넣은 줄은 초록. */
export function DiffHunks({ hunks, offset = 0 }: { hunks: DiffHunk[]; /** 조각이 파일의 몇 번째 줄부터인지(줄 번호 보정). */ offset?: number }) {
  return (
    <pre className="overflow-x-auto text-xs leading-5">
      <code>
        {hunks.map((h, hi) => (
          <div key={hi}>
            <div className="select-none bg-info-soft px-3 text-info">
              @@ 수정 전 {h.oldStart + offset}줄 · 수정 후 {h.newStart + offset}줄 @@
            </div>
            {h.lines.map((l, li) => {
              const tone =
                l.type === "del" ? "bg-danger-soft text-danger" : l.type === "add" ? "bg-success-soft text-success" : "text-ink";
              return (
                <div key={li} className={`flex min-w-max ${tone}`}>
                  <span className="w-10 shrink-0 select-none pr-2 text-right text-ink-muted">{l.oldNo !== undefined ? l.oldNo + offset : ""}</span>
                  <span className="w-10 shrink-0 select-none pr-2 text-right text-ink-muted">{l.newNo !== undefined ? l.newNo + offset : ""}</span>
                  <span className="w-5 shrink-0 select-none text-center" aria-hidden>
                    {l.type === "del" ? "−" : l.type === "add" ? "+" : " "}
                  </span>
                  <span className="sr-only">{l.type === "del" ? "지운 줄: " : l.type === "add" ? "넣은 줄: " : ""}</span>
                  <span className="whitespace-pre pr-4">{l.text || " "}</span>
                </div>
              );
            })}
          </div>
        ))}
      </code>
    </pre>
  );
}

/** 항목 하나 때문에 바뀐 코드(전·후 조각). */
export function EditDiff({ edits }: { edits: { file: string; before: string; after: string; line?: number }[] }) {
  if (edits.length === 0) return null;
  return (
    <div className="mt-3 space-y-2">
      {edits.map((e, i) => {
        const d = fileDiff(e.before, e.after, 2);
        return (
          <figure key={i} className="overflow-hidden rounded-2xl border-2 border-line bg-surface">
            <figcaption className="flex items-center justify-between border-b border-line px-3 py-1.5 text-xs text-ink-muted">
              <span className="break-all font-mono">{e.file}</span>
              <span>
                <span className="text-danger">−{d.removed}</span> <span className="text-success">+{d.added}</span>
              </span>
            </figcaption>
            <DiffHunks hunks={d.hunks} offset={(e.line ?? 1) - 1} />
          </figure>
        );
      })}
    </div>
  );
}

interface DiffFile {
  path: string;
  isNew: boolean;
  added: number;
  removed: number;
  coarse: boolean;
  hunks: DiffHunk[];
}

/** 전체 수정이 바꾼 파일 전부의 비교. 열 때 서버에서 받아 온다. */
export function JobDiff({ jobId }: { jobId: string }) {
  const [files, setFiles] = useState<DiffFile[] | null>(null);
  const [state, setState] = useState<"idle" | "loading" | "error">("idle");

  async function load() {
    if (files || state === "loading") return;
    setState("loading");
    try {
      const res = await fetch(`/api/fix-jobs/${encodeURIComponent(jobId)}/diff`, { cache: "no-store" });
      const data = await res.json();
      if (!res.ok || !Array.isArray(data?.files)) throw new Error("diff");
      setFiles(data.files as DiffFile[]);
      setState("idle");
    } catch {
      setState("error");
    }
  }

  return (
    <details
      className="mt-4 rounded-2xl border-2 border-line bg-surface"
      onToggle={(e) => {
        if ((e.currentTarget as HTMLDetailsElement).open) void load();
      }}
    >
      <summary className="flex min-h-11 cursor-pointer items-center px-4 py-3 text-sm font-bold text-ink hover:text-brand-800">바뀐 코드 전체 보기 (수정 전 → 수정 후)</summary>
      <div className="space-y-3 border-t-2 border-line p-3">
        {state === "loading" && <p className="text-sm text-ink-muted">비교를 불러오고 있어요…</p>}
        {state === "error" && <p className="text-sm text-danger">비교를 불러오지 못했어요. 다시 열어 주세요.</p>}
        {files?.map((f) => (
          <figure key={f.path} className="overflow-hidden rounded-2xl border-2 border-line">
            <figcaption className="flex flex-wrap items-center justify-between gap-2 border-b border-line bg-surface-warm px-3 py-1.5 text-xs text-ink-muted">
              <span className="break-all font-mono">
                {f.path}
                {f.isNew ? " (새 파일)" : ""}
              </span>
              <span>
                <span className="text-danger">−{f.removed}</span> <span className="text-success">+{f.added}</span>
                {f.coarse ? " · 파일이 커서 통째로 비교했어요" : ""}
              </span>
            </figcaption>
            <DiffHunks hunks={f.hunks} />
          </figure>
        ))}
      </div>
    </details>
  );
}
