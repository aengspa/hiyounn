"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

interface Step {
  step: string;
  label: string;
  active: boolean;
}

export function RunScanButton({ projectId }: { projectId: string }) {
  const router = useRouter();
  const [running, setRunning] = useState(false);
  const [steps, setSteps] = useState<Step[]>([]);
  const [currentIdx, setCurrentIdx] = useState(-1);
  const [error, setError] = useState<string | null>(null);

  /** Parse a JSON response defensively; return null if it isn't JSON. */
  async function readJson(res: Response): Promise<any> {
    try {
      return await res.json();
    } catch {
      return null;
    }
  }

  async function run() {
    setRunning(true);
    setError(null);
    setSteps([]);
    setCurrentIdx(-1);

    try {
      // 1) fetch the pipeline plan for the animation
      const planRes = await fetch(`/api/projects/${projectId}/scan-plan`);
      if (!planRes.ok) {
        const data = await readJson(planRes);
        throw new Error(
          data?.error ?? `스캔 계획을 불러오지 못했습니다 (${planRes.status}).`
        );
      }
      const planData = await readJson(planRes);
      const plan: Step[] = (planData?.steps ?? []).filter(
        (s: Step) => s.active
      );
      setSteps(plan);

      // 2) kick off the real scan in parallel with the step animation
      const scanPromise = fetch(`/api/projects/${projectId}/scan`, {
        method: "POST",
      });

      for (let i = 0; i < plan.length; i++) {
        setCurrentIdx(i);
        await new Promise((r) => setTimeout(r, 450));
      }

      const scanRes = await scanPromise;
      const scanData = await readJson(scanRes);
      if (!scanRes.ok) {
        throw new Error(
          scanData?.error ?? `스캔에 실패했습니다 (${scanRes.status}).`
        );
      }
      if (!scanData?.scan?.id) {
        throw new Error("스캔 결과를 받지 못했습니다. 다시 시도해 주세요.");
      }

      router.push(`/dashboard/scans/${scanData.scan.id}`);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "스캔 중 문제가 발생했습니다. 다시 시도해 주세요."
      );
      setRunning(false);
      setSteps([]);
      setCurrentIdx(-1);
    }
  }

  return (
    <>
      <div className="flex flex-col items-end gap-1">
        <button
          onClick={run}
          disabled={running}
          className="rounded-lg bg-brand-600 px-4 py-2 font-medium text-white hover:bg-brand-700 disabled:opacity-60"
        >
          {running ? "스캔 중…" : "보안 스캔 실행"}
        </button>
        {error && (
          <p role="alert" className="max-w-xs text-right text-sm text-red-600">
            {error}
          </p>
        )}
      </div>

      {running && steps.length > 0 && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-6 shadow-xl">
            <h3 className="text-lg font-semibold text-slate-900">
              보안 스캔을 실행하는 중
            </h3>
            <p className="mt-1 text-sm text-slate-500">
              에이전트가 프로젝트의 기술 스택에 맞는 검사를 자동으로 선택합니다.
            </p>
            <ol className="mt-5 space-y-2">
              {steps.map((s, i) => {
                const done = i < currentIdx;
                const active = i === currentIdx;
                return (
                  <li
                    key={s.step}
                    className="flex items-center gap-3 rounded-lg px-2 py-1.5"
                  >
                    <span
                      className={`flex h-6 w-6 items-center justify-center rounded-full text-xs font-bold ${
                        done
                          ? "bg-emerald-100 text-emerald-700"
                          : active
                            ? "bg-brand-100 text-brand-700"
                            : "bg-slate-100 text-slate-400"
                      }`}
                    >
                      {done ? "✓" : i + 1}
                    </span>
                    <span
                      className={
                        done
                          ? "text-slate-500"
                          : active
                            ? "font-medium text-slate-900"
                            : "text-slate-400"
                      }
                    >
                      {s.label}
                    </span>
                    {active && (
                      <span className="ml-auto h-2 w-2 animate-ping rounded-full bg-brand-500" />
                    )}
                  </li>
                );
              })}
            </ol>
          </div>
        </div>
      )}
    </>
  );
}
