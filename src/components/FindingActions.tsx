"use client";

import { useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import type { FindingStatus, FixAttempt, VerificationResult } from "@/lib/domain/types";
import { Hoi } from "@/components/mascot/Hoi";
import { HoiSpeech } from "@/components/mascot/HoiSpeech";
import { Badge, Button, Card, Evidence, FriendlyError } from "@/components/ui";

interface Props {
  findingId: string;
  initialStatus: FindingStatus;
  initialFix: FixAttempt | null;
  initialVerification: VerificationResult | null;
}

type BusyAction = "generate" | "apply" | "verify";

class ApiRequestError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

export function FindingActions({ findingId, initialStatus, initialFix, initialVerification }: Props) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [status, setStatus] = useState<FindingStatus>(initialStatus);
  const [fix, setFix] = useState<FixAttempt | null>(initialFix);
  const [verification, setVerification] = useState<VerificationResult | null>(initialVerification);
  const [busy, setBusy] = useState<BusyAction | null>(null);
  const [confirmingFix, setConfirmingFix] = useState(false);
  const [confirmingApply, setConfirmingApply] = useState(false);
  const [reviewConfirmed, setReviewConfirmed] = useState(false);
  const [error, setError] = useState<{ title: string; message: string } | null>(null);
  const [celebrating, setCelebrating] = useState(false);
  const [artifact, setArtifact] = useState<{
    id: string;
    fileName: string;
    sha256: string;
    size: number;
    version: number;
    files: { path: string; changed: boolean }[];
  } | null>(null);
  const [buildingArtifact, setBuildingArtifact] = useState(false);

  useEffect(() => {
    if (searchParams.get("fix") === "1" && !fix) setConfirmingFix(true);
  }, [searchParams, fix]);

  useEffect(() => {
    if (!celebrating) return;
    const timer = window.setTimeout(() => setCelebrating(false), 1400);
    return () => window.clearTimeout(timer);
  }, [celebrating]);

  async function postJson(path: string): Promise<any> {
    const response = await fetch(path, { method: "POST" });
    let data: any = null;
    try {
      data = await response.json();
    } catch {
      data = null;
    }
    if (!response.ok) {
      throw new ApiRequestError(data?.error ?? `요청을 마치지 못했어요 (${response.status}).`, response.status);
    }
    return data;
  }

  async function generateFix() {
    setBusy("generate");
    setError(null);
    try {
      const data = await postJson(`/api/findings/${findingId}/generate-fix`);
      if (!data?.fix) throw new Error("수정안을 받지 못했어요.");
      setFix(data.fix);
      setConfirmingFix(false);
      router.refresh();
    } catch (cause) {
      setError(mapError(cause, "generate"));
    } finally {
      setBusy(null);
    }
  }

  async function applyFix() {
    setBusy("apply");
    setError(null);
    try {
      const data = await postJson(`/api/findings/${findingId}/apply-fix`);
      if (!data?.finding) throw new Error("반영 상태를 갱신하지 못했어요.");
      setStatus(data.finding.status);
      setFix((current) => current ? { ...current, applied: true } : current);
      setConfirmingApply(false);
      setReviewConfirmed(false);
      router.refresh();
    } catch (cause) {
      setError(mapError(cause, "apply"));
    } finally {
      setBusy(null);
    }
  }

  async function verify() {
    setBusy("verify");
    setError(null);
    try {
      const data = await postJson(`/api/findings/${findingId}/verify`);
      if (!data?.finding || !data?.result) {
        throw new Error("검증 결과를 받지 못했어요. 잠시 후 다시 시도해 주세요.");
      }
      const nextStatus = data.finding.status as FindingStatus;
      setStatus(nextStatus);
      setVerification(data.result);
      if (nextStatus === "resolved" && status !== "resolved") setCelebrating(true);
      router.refresh();
    } catch (cause) {
      setError(mapError(cause, "verify"));
    } finally {
      setBusy(null);
    }
  }

  async function buildArtifact() {
    setBuildingArtifact(true);
    setError(null);
    try {
      const data = await postJson(`/api/findings/${findingId}/build-artifact`);
      if (!data?.artifact) throw new Error("수정본을 생성하지 못했어요.");
      setArtifact(data.artifact);
    } catch (cause) {
      setError(mapError(cause, "generate"));
    } finally {
      setBuildingArtifact(false);
    }
  }

  const canVerify = status === "fixed" || status === "verification_failed" || status === "regression_failed";
  const currentStage = !fix ? 2 : !fix.applied ? 3 : canVerify ? 5 : status === "resolved" ? 6 : 4;
  const guide = getGuide({ status, fix, canVerify });

  return (
    <div className="mt-7 space-y-6" aria-busy={busy !== null}>
      <div className="sr-only" aria-live="polite" aria-atomic="true">
        {busy === "generate"
          ? "수정안을 만들고 있어요"
          : busy === "apply"
            ? "반영 상태를 갱신하고 있어요"
            : busy === "verify"
              ? "고친 내용과 기존 기능을 다시 확인하고 있어요"
              : ""}
      </div>
      <JourneyTimeline
        currentStage={currentStage}
        status={status}
        hasFix={Boolean(fix)}
        applied={Boolean(fix?.applied)}
        verification={verification}
      />

      {status === "resolved" ? (
        <div className="relative overflow-hidden rounded-3xl border border-green-300 bg-success-soft p-5 sm:p-6" aria-live="polite">
          {celebrating && <Confetti />}
          <div className="relative flex flex-col items-center gap-4 text-center sm:flex-row sm:text-left">
            <Hoi mood="celebrate" size="md" decorative />
            <div>
              <h3 className="text-xl font-black text-success">고친 내용이 잘 막히는지 확인했어요!</h3>
              <p className="mt-1 text-sm leading-relaxed text-green-800">
                같은 보안 문제가 다시 생기지 않았고, 이 점검에서 확인 가능한 기본 기능 조건도 통과했어요. 이 한 항목에 대한 결과이며 서비스 전체 안전을 보장하지는 않아요.
              </p>
            </div>
          </div>
        </div>
      ) : (
        <HoiSpeech mood={status === "verification_failed" || status === "regression_failed" ? "concerned" : "guide"} size="sm">
          {guide}
        </HoiSpeech>
      )}

      {status === "verification_failed" && (
        <OutcomeGuide
          title="아직 같은 문제가 완전히 막히지 않았어요"
          description="수정 후에도 원래 문제를 확인한 규칙이나 재현 방법에서 취약 동작이 다시 나타났어요. 수정 범위를 보완하고 실제 대상에 반영한 뒤 다시 확인해 주세요."
          next="다음 행동 · 수정 내용 보완 → 실제 소스·배포 반영 확인 → ‘다시 재검증’"
        />
      )}
      {status === "regression_failed" && (
        <OutcomeGuide
          title="보안 문제는 막았지만 기존 기능을 다시 확인해야 해요"
          description="정상 사용 흐름이나 무결성 확인 중 하나 이상이 기대대로 동작하지 않았어요. 변경을 되돌리거나 호환되게 보완한 뒤 보안과 기능을 함께 다시 확인해 주세요."
          next="다음 행동 · 실패한 기능 확인 → 되돌리기 또는 보완 → ‘다시 재검증’"
        />
      )}

      {!fix && confirmingFix && (
        <Card variant="warm" className="p-5" role="group" aria-labelledby="generate-confirm-title">
          <h3 id="generate-confirm-title" className="font-extrabold text-ink">2단계 · 수정안을 만들어 볼까요?</h3>
          <p className="mt-2 text-sm leading-relaxed text-ink-subtle">
            승인하면 AI 또는 결정적 규칙이 제안만 만들어요. 이 단계에서는 코드, 저장소, 배포 환경이 바뀌지 않아요.
          </p>
          <div className="mt-4 flex flex-col gap-2 sm:flex-row">
            <Button onClick={generateFix} disabled={busy !== null} className="w-full sm:w-auto">
              {busy === "generate" ? "수정안 만드는 중…" : "승인하고 수정안 만들기"}
            </Button>
            <Button variant="secondary" onClick={() => setConfirmingFix(false)} disabled={busy !== null} className="w-full sm:w-auto">
              아직 만들지 않기
            </Button>
          </div>
        </Card>
      )}

      {!fix && !confirmingFix && (
        <Button onClick={() => setConfirmingFix(true)} disabled={busy !== null} size="lg" className="w-full sm:w-auto">
          2단계 · 수정안 만들기
        </Button>
      )}

      {fix && (
        <section aria-labelledby="proposed-fix-title">
          <div className="flex flex-wrap items-center gap-2">
            <h3 id="proposed-fix-title" className="text-xl font-black text-ink">제안된 수정</h3>
            <Badge tone={fix.source === "llm" ? "info" : "neutral"}>
              {fix.source === "llm" ? "AI 모델 제안" : "규칙 기반 제안"}
            </Badge>
            {fix.applied && <Badge tone="success">점검 기록상 반영됨</Badge>}
          </div>
          <p className="mt-3 text-lg font-bold leading-relaxed text-ink">{fix.summary}</p>
          <p className="mt-2 leading-relaxed text-ink-subtle">{fix.plainExplanation}</p>

          <div className="mt-5 grid gap-3 md:grid-cols-3">
            <InfoCard title="변경 영향" text="아래 diff의 파일과 줄이 바뀔 수 있어요. 관련 호출부와 권한 흐름을 함께 확인해 주세요." />
            <InfoCard title="실제 반영" text="이 서비스는 현재 저장소 파일을 직접 바꾸지 않아요. 변경을 실제 소스나 배포 환경에 별도로 반영해야 해요." />
            <InfoCard title="되돌림" text="반영 전 브랜치·백업을 준비하고, 문제가 생기면 diff의 추가 줄을 되돌린 뒤 정상 기능을 다시 확인해 주세요." />
          </div>

          <div className="mt-5 space-y-4">
            {fix.diffs.length > 0 ? fix.diffs.map((diff, index) => (
              <DiffBlock key={`${diff.file}-${index}`} file={diff.file} patch={diff.patch} />
            )) : <p className="rounded-2xl bg-warning-soft p-4 text-sm text-warning">제안에 저장된 diff가 없어요. 상태를 갱신하기 전에 원본 수정 내용을 별도로 확인해 주세요.</p>}
          </div>

          {!fix.applied && !confirmingApply && (
            <Button onClick={() => setConfirmingApply(true)} disabled={busy !== null} size="lg" className="mt-5 w-full sm:w-auto">
              3단계 · 변경 검토하고 승인
            </Button>
          )}

          {!fix.applied && confirmingApply && (
            <Card variant="danger" className="mt-5 p-5" role="group" aria-labelledby="apply-confirm-title">
              <h3 id="apply-confirm-title" className="font-extrabold text-red-900">4단계 · 반영 상태를 갱신할까요?</h3>
              <p className="mt-2 text-sm leading-relaxed text-red-800">
                이 버튼은 점검 기록에서 수정안의 적용 상태를 갱신해요. 실제 저장소·파일·배포 환경에 diff를 쓰지 않으므로, 직접 반영했는지 별도로 확인해야 해요.
              </p>
              <label className="mt-4 flex min-h-11 cursor-pointer items-start gap-3 rounded-2xl border border-red-200 bg-white p-3 text-sm font-bold text-ink">
                <input
                  type="checkbox"
                  checked={reviewConfirmed}
                  onChange={(event) => setReviewConfirmed(event.target.checked)}
                  className="mt-0.5 h-5 w-5 shrink-0 accent-[#9e1b32]"
                />
                <span>diff, 영향, 되돌림 안내를 읽었고 실제 반영 여부를 별도로 확인하겠습니다.</span>
              </label>
              <div className="mt-4 flex flex-col gap-2 sm:flex-row">
                <Button variant="danger" onClick={applyFix} disabled={!reviewConfirmed || busy !== null} className="w-full sm:w-auto">
                  {busy === "apply" ? "기록 갱신 중…" : "승인하고 반영 상태 갱신"}
                </Button>
                <Button variant="secondary" onClick={() => { setConfirmingApply(false); setReviewConfirmed(false); }} disabled={busy !== null} className="w-full sm:w-auto">
                  더 검토하기
                </Button>
              </div>
            </Card>
          )}
        </section>
      )}

      {canVerify && (
        <Card variant="raised" className="p-5 sm:p-6">
          <h3 className="text-lg font-black text-ink">5단계 · 보안과 기존 기능 다시 확인</h3>
          <p className="mt-2 text-sm leading-relaxed text-ink-subtle">
            마지막으로 저장된 소스 또는 허가된 배포 대상을 같은 규칙으로 점검해요. 실제 변경이 그 대상에 반영되지 않았다면 제안만으로 통과할 수 없어요.
          </p>
          <Button onClick={verify} disabled={busy !== null} size="lg" className="mt-4 w-full sm:w-auto">
            {busy === "verify" ? "재검증 중…" : status === "fixed" ? "5단계 · 수정 재검증" : "다시 재검증"}
          </Button>
          <p className="mt-3 text-xs leading-relaxed text-ink-muted">
            검사기·소스·배포 전제조건이 없어 자동 재검증할 수 없는 경우 422 안내가 표시되며, 실패 상태로 바꾸지 않아요.
          </p>
        </Card>
      )}

      {fix && (
        <Card variant="raised" className="p-5 sm:p-6">
          <h3 className="text-lg font-black text-ink">수정본 프로젝트 다운로드</h3>
          <p className="mt-2 text-sm leading-relaxed text-ink-subtle">
            업로드한 원본은 그대로 두고, 수정안을 적용한 <strong>복사본</strong>을 ZIP으로 만들어요. 원본 파일은 절대 덮어쓰지 않아요.
          </p>
          <Button onClick={buildArtifact} disabled={buildingArtifact} size="lg" className="mt-4 w-full sm:w-auto">
            {buildingArtifact ? "수정본 만드는 중…" : artifact ? "수정본 다시 생성" : "수정본 ZIP 생성"}
          </Button>

          {artifact && (
            <div className="mt-5 rounded-2xl border border-line bg-surface-warm p-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="min-w-0">
                  <p className="font-mono text-sm font-bold text-ink">{artifact.fileName}</p>
                  <p className="mt-1 text-xs text-ink-muted">
                    버전 v{artifact.version} · {(artifact.size / 1024).toFixed(1)} KB · 변경 {artifact.files.filter((f) => f.changed).length}/{artifact.files.length}개 파일
                  </p>
                </div>
                <a
                  href={`/api/artifacts/${artifact.id}/download`}
                  className="inline-flex shrink-0 items-center justify-center rounded-2xl bg-brand-700 px-4 py-2 font-bold text-white hover:bg-brand-900"
                  download
                >
                  ZIP 다운로드
                </a>
              </div>
              <dl className="mt-3 grid gap-1 text-xs text-ink-muted">
                <div className="flex flex-wrap gap-1">
                  <dt className="font-bold">SHA-256</dt>
                  <dd className="break-all font-mono">{artifact.sha256}</dd>
                </div>
                <div className="flex flex-wrap gap-1">
                  <dt className="font-bold">artifact ID</dt>
                  <dd className="break-all font-mono">{artifact.id}</dd>
                </div>
              </dl>
              <ul className="mt-3 space-y-1 text-xs">
                {artifact.files.map((f) => (
                  <li key={f.path} className="flex items-center gap-2 font-mono">
                    <span className={f.changed ? "text-success" : "text-ink-muted"}>{f.changed ? "✎" : "·"}</span>
                    <span className={f.changed ? "font-bold text-ink" : "text-ink-muted"}>{f.path}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Card>
      )}

      {error && (
        <FriendlyError
          title={error.title}
          description={<><p>{error.message}</p><p className="mt-2 font-bold">현재 상태는 유지됐어요. 조건을 확인한 뒤 같은 버튼으로 다시 시도할 수 있어요.</p></>}
        />
      )}

      {verification && <VerificationResultPanel verification={verification} status={status} />}
    </div>
  );
}

function JourneyTimeline({ currentStage, status, hasFix, applied, verification }: {
  currentStage: number;
  status: FindingStatus;
  hasFix: boolean;
  applied: boolean;
  verification: VerificationResult | null;
}) {
  const steps = [
    { label: "발견 확인", done: true },
    { label: "수정안 만들기", done: hasFix },
    { label: "변경 영향 검토", done: applied },
    { label: "반영 상태 갱신", done: applied },
    { label: "보안·기능 재검증", done: Boolean(verification) },
    { label: "해결 확인", done: status === "resolved" },
  ];
  return (
    <section aria-labelledby="journey-title">
      <div className="flex items-center justify-between gap-3">
        <h3 id="journey-title" className="text-xl font-black text-ink">6단계 해결 여정</h3>
        <Badge tone="primary">현재 {currentStage}/6단계</Badge>
      </div>
      <ol className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {steps.map((step, index) => {
          const number = index + 1;
          const current = number === currentStage && !step.done;
          return (
            <li
              key={step.label}
              aria-current={current ? "step" : undefined}
              className={`flex min-h-12 items-center gap-3 rounded-2xl border px-3 py-2 ${
                step.done ? "border-green-200 bg-success-soft" : current ? "border-orange-300 bg-primary-soft" : "border-line bg-white"
              }`}
            >
              <span className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-sm font-black ${step.done ? "bg-success text-white" : current ? "bg-brand-700 text-white" : "bg-surface-warm text-ink-muted"}`}>
                {step.done ? "✓" : number}
              </span>
              <span className={`text-sm font-bold ${step.done ? "text-success" : current ? "text-brand-900" : "text-ink-muted"}`}>{step.label}</span>
            </li>
          );
        })}
      </ol>
    </section>
  );
}

function DiffBlock({ file, patch }: { file: string; patch: string }) {
  return (
    <div className="max-w-full overflow-hidden rounded-2xl border border-line">
      <div className="break-all border-b border-line bg-surface-warm px-4 py-2 font-mono text-xs font-bold text-ink-subtle">{file}</div>
      <pre className="evidence max-w-full overflow-x-auto bg-code p-4 text-sm" tabIndex={0} aria-label={`${file} 수정 diff`}>
        {patch.split("\n").map((line, index) => (
          <span key={index} className={`block min-w-max ${line.startsWith("+") ? "text-green-300" : line.startsWith("-") ? "text-red-300" : "text-[#fffaf2]"}`}>{line || " "}</span>
        ))}
      </pre>
    </div>
  );
}

function InfoCard({ title, text }: { title: string; text: string }) {
  return <Card variant="warm" className="p-4"><h4 className="font-extrabold text-ink">{title}</h4><p className="mt-1 text-sm leading-relaxed text-ink-subtle">{text}</p></Card>;
}

function OutcomeGuide({ title, description, next }: { title: string; description: string; next: string }) {
  return (
    <Card variant="danger" className="p-5">
      <h3 className="text-lg font-black text-red-900">{title}</h3>
      <p className="mt-2 text-sm leading-relaxed text-red-800">{description}</p>
      <p className="mt-3 rounded-2xl bg-white p-3 text-sm font-extrabold text-ink">{next}</p>
    </Card>
  );
}

function VerificationResultPanel({ verification, status }: { verification: VerificationResult; status: FindingStatus }) {
  const security = verification.security;
  const regression = verification.regression;
  return (
    <section className="space-y-5" aria-labelledby="verification-result-title">
      <h3 id="verification-result-title" className="text-xl font-black text-ink">재검증 결과</h3>
      <div className="grid gap-3 md:grid-cols-2">
        {security.before && (
          <div><p className="mb-2 font-extrabold text-ink">수정 전 · 문제가 생겼던 기록</p><Evidence content={security.before.response} tone="danger" /></div>
        )}
        {security.after && (
          <div><p className="mb-2 font-extrabold text-ink">수정 후 · {security.after.attackSucceeded ? "아직 문제가 생겨요" : "문제가 막혔어요"}</p><Evidence content={security.after.response} tone={security.after.attackSucceeded ? "danger" : "success"} /></div>
        )}
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        <Verdict title={`보안 확인 · ${security.label}`} passed={security.outcome === "pass"} success="같은 취약 동작이 다시 나타나지 않았어요." failure="같은 취약 동작이 여전히 나타났어요." />
        <Card variant={regression.outcome === "pass" ? "warm" : "danger"} className="p-5">
          <h4 className="font-extrabold text-ink">기존 기능·무결성 확인</h4>
          <ul className="mt-3 space-y-2 text-sm">
            {regression.checks.map((check, index) => (
              <li key={`${check.label}-${index}`} className="flex items-start gap-2">
                <span aria-hidden="true" className={check.outcome === "pass" ? "text-success" : "text-danger"}>{check.outcome === "pass" ? "✓" : "✕"}</span>
                <span className="min-w-0 text-ink-subtle"><strong className="text-ink">{check.label}</strong><span className="block">기대: {check.expectation}</span>{check.detail && <span className="block break-all font-mono text-xs text-ink-muted">{check.detail}</span>}</span>
              </li>
            ))}
          </ul>
        </Card>
      </div>
      <Card variant="flat" className="p-4 text-sm text-ink-subtle">
        <dl className="grid gap-2 sm:grid-cols-2">
          <div><dt className="font-bold text-ink-muted">보안 검사 ID</dt><dd className="break-all font-mono text-xs">{security.id}</dd></div>
          <div><dt className="font-bold text-ink-muted">기능 검사 ID</dt><dd className="break-all font-mono text-xs">{regression.id}</dd></div>
          <div><dt className="font-bold text-ink-muted">보안 검사 시각</dt><dd>{new Date(security.createdAt).toLocaleString("ko-KR")}</dd></div>
          <div><dt className="font-bold text-ink-muted">기능 검사 시각</dt><dd>{new Date(regression.createdAt).toLocaleString("ko-KR")}</dd></div>
        </dl>
      </Card>
      {status === "fixed" && !verification.resolved && (
        <Card variant="warm" className="p-5 text-sm leading-relaxed text-warning">자동 확인 결과만으로 해결 완료를 확정하지 못했어요. 비밀 키 재발급이나 별도 런타임 확인처럼 수동 단계가 남아 있을 수 있어요.</Card>
      )}
    </section>
  );
}

function Verdict({ title, passed, success, failure }: { title: string; passed: boolean; success: string; failure: string }) {
  return (
    <Card variant={passed ? "warm" : "danger"} className="p-5">
      <h4 className="font-extrabold text-ink">{title}</h4>
      <p className={`mt-2 text-sm font-bold ${passed ? "text-success" : "text-danger"}`}>{passed ? `✓ ${success}` : `✕ ${failure}`}</p>
    </Card>
  );
}

function Confetti() {
  const dots = [
    ["left-[8%]", "top-4", "bg-brand-600"], ["left-[20%]", "top-10", "bg-[#ffc857]"],
    ["left-[35%]", "top-3", "bg-[#9e1b32]"], ["right-[8%]", "top-5", "bg-success"],
    ["right-[22%]", "top-12", "bg-brand-600"], ["right-[38%]", "top-2", "bg-[#ffc857]"],
  ];
  return <div aria-hidden="true" className="pointer-events-none absolute inset-0">{dots.map(([x, y, color], index) => <span key={index} className={`absolute ${x} ${y} ${color} h-2.5 w-2.5 animate-ping rounded-sm`} style={{ animationDelay: `${index * 90}ms`, animationIterationCount: "1" }} />)}</div>;
}

function getGuide({ status, fix, canVerify }: { status: FindingStatus; fix: FixAttempt | null; canVerify: boolean }): string {
  if (!fix) return "다음은 수정안 만들기예요. 승인 전에는 아무 코드도 바뀌지 않아요.";
  if (!fix.applied) return "제안 diff와 영향, 되돌림 방법을 읽고 실제 소스에 반영했는지 확인한 뒤 기록 상태 갱신을 승인해 주세요.";
  if (canVerify) return "기록상 반영 상태예요. 실제 저장소나 배포 대상에 변경이 반영됐는지 확인한 뒤 보안과 기존 기능을 다시 점검해요.";
  return "현재 기록을 확인하고 다음 단계를 진행해 주세요.";
}

function mapError(cause: unknown, action: BusyAction): { title: string; message: string } {
  if (cause instanceof ApiRequestError) {
    if (cause.status === 422) {
      return {
        title: "자동 확인을 진행할 수 없어요",
        message: "검사 대상·소스·허가 상태를 확인하거나 안내된 수동 확인을 진행해 주세요.",
      };
    }
    if (cause.status === 401 || cause.status === 403) {
      return { title: "이 작업 권한을 확인하지 못했어요", message: "프로젝트 소유자와 로그인 상태를 확인해 주세요." };
    }
    if (cause.status === 404) {
      return { title: "대상을 찾지 못했어요", message: "점검 결과 목록에서 항목을 다시 열어 주세요." };
    }
    if (cause.status === 429) {
      return { title: "요청이 잠시 몰렸어요", message: "잠깐 기다린 뒤 같은 버튼으로 다시 시도해 주세요." };
    }
    return { title: "서버에서 요청을 마치지 못했어요", message: "잠시 뒤 다시 시도해 주세요. 현재 상태는 바뀌지 않았어요." };
  }
  const title = action === "generate" ? "수정안을 만들지 못했어요" : action === "apply" ? "반영 상태를 갱신하지 못했어요" : "고친 내용을 다시 확인하지 못했어요";
  const message = cause instanceof TypeError
    ? "연결이 잠깐 끊겼어요. 인터넷 연결을 확인하고 다시 시도해 주세요."
    : "결과를 확인하지 못했어요. 잠시 뒤 다시 시도해 주세요.";
  return { title, message };
}
