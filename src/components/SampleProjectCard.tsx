"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui";

/** 체험용 샘플 앱을 프로젝트로 추가한다. 점검·수정은 매번 실제로 실행된다. */
export function SampleProjectCard({
  sample,
  className = "",
}: {
  sample: { id: string; name: string; description: string; zipPath: string };
  className?: string;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function add() {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/projects/sample", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sampleId: sample.id }),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data?.project?.id) throw new Error(data?.message ?? "샘플을 추가하지 못했어요.");
      router.push(`/dashboard/projects/${data.project.id}`);
      router.refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "샘플을 추가하지 못했어요.");
      setBusy(false);
    }
  }

  return (
    <div className={`flex flex-col rounded-3xl border-2 border-dashed border-brand-300 bg-sun-soft p-5 sm:p-6 ${className}`}>
      <p className="text-lg font-extrabold text-ink">샘플 앱으로 먼저 체험하기</p>
      <p className="mt-1 text-sm leading-relaxed text-ink-subtle">
        {sample.description} 샘플을 추가하면 보통 프로젝트처럼 점검·수정·재검증이 매번 실제로 실행돼요.
      </p>
      <div className="mt-auto flex flex-wrap items-center gap-3 pt-4">
        <Button variant="secondary" onClick={add} disabled={busy} aria-busy={busy}>
          {sample.name} 추가하기
        </Button>
        <a href={sample.zipPath} download className="inline-flex min-h-11 items-center text-sm font-bold text-brand-800 hover:underline">
          ZIP으로 내려받기
        </a>
      </div>
      {error && (
        <p role="alert" className="mt-2 text-sm text-danger">
          {error}
        </p>
      )}
    </div>
  );
}
