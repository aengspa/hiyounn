"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui";
import { ProgressDialog } from "@/components/ProgressDialog";

interface Step {
  step: string;
  label: string;
  active: boolean;
}

type RunPhase = "idle" | "planning" | "scanning" | "complete";

class ScanRequestError extends Error {
  constructor(
    readonly status: number,
    readonly code: unknown,
    readonly serverMessage?: string,
  ) {
    super("scan_request_failed");
  }
}

export function RunScanButton({ projectId, label = "보안 점검 시작" }: { projectId: string; label?: string }) {
  const router = useRouter();
  const [phase, setPhase] = useState<RunPhase>("idle");
  const [steps, setSteps] = useState<Step[]>([]);
  const [error, setError] = useState<string | null>(null);
  const running = phase !== "idle";

  async function readJson(res: Response): Promise<any> {
    try {
      return await res.json();
    } catch {
      return null;
    }
  }

  async function run() {
    setPhase("planning");
    setError(null);
    setSteps([]);

    try {
      const planRes = await fetch(`/api/projects/${projectId}/scan-plan`);
      if (!planRes.ok) {
        const data = await readJson(planRes);
        throw new ScanRequestError(planRes.status, data?.error, data?.message);
      }
      const planData = await readJson(planRes);
      setSteps((planData?.steps ?? []).filter((step: Step) => step.active));
      setPhase("scanning");

      const scanRes = await fetch(`/api/projects/${projectId}/scan`, { method: "POST" });
      const scanData = await readJson(scanRes);
      if (!scanRes.ok) {
        throw new ScanRequestError(scanRes.status, scanData?.error, scanData?.message);
      }
      if (!scanData?.scan?.id) throw new Error("invalid_scan_response");

      setPhase("complete");
      router.push(`/dashboard/scans/${scanData.scan.id}`);
      router.refresh();
    } catch (cause) {
      setError(friendlyError(cause));
      setPhase("idle");
      setSteps([]);
    }
  }

  const title =
    phase === "planning"
      ? "어떤 항목을 볼지 정하고 있어요"
      : phase === "complete"
        ? "점검을 마쳤어요"
        : "코드를 살펴보고 있어요";

  return (
    <>
      <div className="flex flex-col items-stretch gap-2 sm:items-end">
        <Button onClick={run} disabled={running} aria-busy={running} size="md">
          {running ? "호이가 점검 중…" : error ? "다시 점검하기" : label}
        </Button>
        {error && (
          <p role="alert" className="max-w-sm rounded-2xl border-2 border-[#f3c4bd] bg-danger-soft px-3 py-2 text-sm font-semibold text-danger">
            {error}
          </p>
        )}
      </div>

      <ProgressDialog
        open={running}
        title={title}
        description="서버가 허용된 점검만 실행해요. 끝나면 결과 화면으로 이동해요."
        liveMessage={phase === "scanning" ? `점검 실행 중. 실행하는 단계 ${steps.length}개` : title}
      >
        {steps.length > 0 && (
          <div>
            <p className="text-sm font-semibold text-ink">이번에 실행하는 단계</p>
            <ol className="mt-3 space-y-2">
              {steps.map((step) => (
                <li
                  key={step.step}
                  className="flex min-h-11 items-center gap-3 rounded-2xl border-2 border-line bg-surface-warm px-3 py-2"
                >
                  <span aria-hidden="true" className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border-2 border-brand-300 bg-sun-soft font-bold text-brand-900">
                    {phase === "complete" ? "✓" : "•"}
                  </span>
                  <span className="min-w-0 flex-1 break-words text-sm font-bold text-ink">{step.label}</span>
                </li>
              ))}
            </ol>
          </div>
        )}
      </ProgressDialog>
    </>
  );
}

function friendlyError(cause: unknown): string {
  if (cause instanceof ScanRequestError) {
    if (cause.status === 401) return "로그인이 필요해요. 다시 로그인한 뒤 시도해 주세요.";
    if (cause.code === "forbidden" || cause.status === 403) {
      return "이 프로젝트를 점검할 권한을 확인하지 못했어요. 로그인 상태를 확인해 주세요.";
    }
    if (cause.code === "not_found" || cause.status === 404) {
      return "프로젝트를 찾지 못했어요. 목록에서 다시 열어 주세요.";
    }
    if (cause.serverMessage) return cause.serverMessage;
    if (cause.status === 429) return "요청이 잠시 몰렸어요. 잠깐 기다린 뒤 다시 시도해 주세요.";
    return "서버에서 점검을 마치지 못했어요. 잠시 뒤 다시 시도해 주세요.";
  }
  if (cause instanceof TypeError) {
    return "연결이 잠깐 끊겼어요. 인터넷 연결을 확인하고 다시 시도해 주세요.";
  }
  return "점검 결과를 확인하지 못했어요. 잠시 뒤 다시 시도해 주세요.";
}
