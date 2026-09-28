"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Hoi } from "@/components/mascot/Hoi";
import { Button } from "@/components/ui";

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
  ) {
    super("scan_request_failed");
  }
}

export function RunScanButton({ projectId }: { projectId: string }) {
  const router = useRouter();
  const dialogRef = useRef<HTMLDivElement>(null);
  const [phase, setPhase] = useState<RunPhase>("idle");
  const [steps, setSteps] = useState<Step[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [dialogNotice, setDialogNotice] = useState<string | null>(null);
  const running = phase !== "idle";

  useEffect(() => {
    if (!running) return;
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    dialogRef.current?.focus();

    function keepDialogOpen(event: KeyboardEvent) {
      const dialog = dialogRef.current;
      if (!dialog) return;

      if (event.key === "Escape") {
        event.preventDefault();
        setDialogNotice("점검 요청이 실행 중이라 이 창을 닫을 수 없어요. 완료되면 결과로 바로 이동해요.");
        return;
      }

      if (event.key !== "Tab") return;
      const focusable = Array.from(dialog.querySelectorAll<HTMLElement>(
        'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ));
      if (focusable.length === 0) {
        event.preventDefault();
        dialog.focus();
        return;
      }

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement;
      if (event.shiftKey && (active === first || !dialog.contains(active))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    }

    function containFocus(event: FocusEvent) {
      const dialog = dialogRef.current;
      if (dialog && event.target instanceof Node && !dialog.contains(event.target)) {
        dialog.focus();
      }
    }

    document.addEventListener("keydown", keepDialogOpen);
    document.addEventListener("focusin", containFocus);
    return () => {
      document.removeEventListener("keydown", keepDialogOpen);
      document.removeEventListener("focusin", containFocus);
      document.body.style.overflow = previousOverflow;
      previousFocus?.focus();
    };
  }, [running]);

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
    setDialogNotice(null);
    setSteps([]);

    try {
      const planRes = await fetch(`/api/projects/${projectId}/scan-plan`);
      if (!planRes.ok) {
        const data = await readJson(planRes);
        throw new ScanRequestError(planRes.status, data?.error);
      }
      const planData = await readJson(planRes);
      const activeSteps: Step[] = (planData?.steps ?? []).filter(
        (step: Step) => step.active,
      );
      setSteps(activeSteps);
      setPhase("scanning");

      const scanRes = await fetch(`/api/projects/${projectId}/scan`, { method: "POST" });
      const scanData = await readJson(scanRes);
      if (!scanRes.ok) {
        throw new ScanRequestError(scanRes.status, scanData?.error);
      }
      if (!scanData?.scan?.id) {
        throw new Error("invalid_scan_response");
      }

      setPhase("complete");
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
      router.push(`/dashboard/scans/${scanData.scan.id}`);
    } catch (cause) {
      setError(friendlyError(cause));
      setPhase("idle");
      setSteps([]);
    }
  }

  return (
    <>
      <div className="flex flex-col items-stretch gap-2 sm:items-end">
        <Button onClick={run} disabled={running} aria-busy={running} size="sm">
          {running ? "호이가 점검 중…" : error ? "보안 점검 다시 시도" : "보안 점검 시작"}
        </Button>
        {error && (
          <p role="alert" className="max-w-sm text-sm font-medium text-red-700">
            {error}
          </p>
        )}
      </div>

      {running && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#3a2b20]/45 p-4 backdrop-blur-sm">
          <div
            ref={dialogRef}
            role="dialog"
            aria-modal="true"
            aria-busy="true"
            aria-labelledby="scan-dialog-title"
            aria-describedby="scan-dialog-description"
            tabIndex={-1}
            className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-3xl border border-line bg-surface p-5 shadow-2xl outline-none sm:p-7"
          >
            <div className="flex flex-col items-center gap-3 text-center sm:flex-row sm:text-left">
              <Hoi mood="searching" size="md" decorative />
              <div>
                <h2 id="scan-dialog-title" className="text-xl font-black text-ink">
                  {phase === "planning"
                    ? "어떤 항목을 볼지 정하고 있어요"
                    : phase === "complete"
                      ? "점검을 마쳤어요"
                      : "선택한 항목을 살펴보고 있어요"}
                </h2>
                <p id="scan-dialog-description" className="mt-1 text-sm leading-relaxed text-ink-subtle">
                  서버가 허용된 점검만 실행해요. 개별 진행률이나 예상 시간은 제공하지 않으며,
                  요청이 끝나면 결과 화면으로 이동해요.
                </p>
              </div>
            </div>

            <div className="sr-only" aria-live="polite" aria-atomic="true">
              {phase === "planning"
                ? "점검 계획 확인 중"
                : phase === "complete"
                  ? "점검 완료"
                  : `점검 실행 중. 선택된 항목 ${steps.length}개`}
              {dialogNotice ? ` ${dialogNotice}` : ""}
            </div>

            {steps.length > 0 && (
              <div className="mt-5">
                <p className="text-sm font-extrabold text-ink">이번에 실제로 실행하는 단계</p>
                <ol className="mt-3 space-y-2">
                  {steps.map((step) => {
                    const complete = phase === "complete";
                    return (
                      <li
                        key={step.step}
                        className="flex min-h-12 items-center gap-3 rounded-2xl border border-line bg-surface-warm px-3 py-2"
                      >
                        <span
                          aria-hidden="true"
                          className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full font-black ${
                            complete ? "bg-success-soft text-success" : "bg-primary-soft text-brand-900"
                          }`}
                        >
                          {complete ? "✓" : "•"}
                        </span>
                        <span className="min-w-0 flex-1 break-words font-bold text-ink">{step.label}</span>
                        <span className={`text-xs font-bold ${complete ? "text-success" : "text-brand-800"}`}>
                          {complete ? "완료" : "실행 중"}
                        </span>
                      </li>
                    );
                  })}
                </ol>
              </div>
            )}

            {phase === "planning" && (
              <div className="mt-5 rounded-2xl bg-surface-warm p-4 text-sm text-ink-subtle" role="status">
                소스 연결 상태와 배포 점검 승인 범위를 확인하고 있어요.
              </div>
            )}
            <p className="mt-5 text-center text-xs leading-relaxed text-ink-muted">
              실행 중 창을 닫으면 요청이 취소된 것처럼 보일 수 있어 닫기 기능을 제공하지 않아요.
            </p>
            {dialogNotice && (
              <p role="status" className="mt-3 rounded-2xl bg-warning-soft p-3 text-sm text-warning">
                {dialogNotice}
              </p>
            )}
          </div>
        </div>
      )}
    </>
  );
}

function friendlyError(cause: unknown): string {
  if (cause instanceof ScanRequestError) {
    if (cause.code === "forbidden" || cause.status === 401 || cause.status === 403) {
      return "이 프로젝트를 점검할 권한을 확인하지 못했어요. 로그인 상태와 프로젝트 권한을 확인해 주세요.";
    }
    if (cause.code === "not_found" || cause.status === 404) {
      return "프로젝트를 찾지 못했어요. 목록에서 다시 열어 주세요.";
    }
    if (cause.status === 429) {
      return "요청이 잠시 몰렸어요. 잠깐 기다린 뒤 다시 시도해 주세요.";
    }
    return "서버에서 점검을 마치지 못했어요. 잠시 뒤 다시 시도해 주세요.";
  }
  if (cause instanceof TypeError) {
    return "연결이 잠깐 끊겼어요. 인터넷 연결을 확인하고 다시 시도해 주세요.";
  }
  return "점검 결과를 확인하지 못했어요. 잠시 뒤 다시 시도해 주세요.";
}
