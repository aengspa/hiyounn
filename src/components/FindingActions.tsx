"use client";

import { useState } from "react";
import type {
  FixAttempt,
  VerificationResult,
  FindingStatus,
} from "@/lib/domain/types";
import { Evidence } from "@/components/ui";

interface Props {
  findingId: string;
  initialStatus: FindingStatus;
  initialFix: FixAttempt | null;
  initialVerification: VerificationResult | null;
}

export function FindingActions({
  findingId,
  initialStatus,
  initialFix,
  initialVerification,
}: Props) {
  const [status, setStatus] = useState<FindingStatus>(initialStatus);
  const [fix, setFix] = useState<FixAttempt | null>(initialFix);
  const [verification, setVerification] = useState<VerificationResult | null>(
    initialVerification
  );
  const [busy, setBusy] = useState<string | null>(null);

  async function generateFix() {
    setBusy("generate");
    const res = await fetch(`/api/findings/${findingId}/generate-fix`, {
      method: "POST",
    });
    const data = await res.json();
    if (data.fix) setFix(data.fix);
    setBusy(null);
  }

  async function applyFix() {
    setBusy("apply");
    const res = await fetch(`/api/findings/${findingId}/apply-fix`, {
      method: "POST",
    });
    const data = await res.json();
    if (data.finding) {
      setStatus(data.finding.status);
      setFix((f) => (f ? { ...f, applied: true } : f));
    }
    setBusy(null);
  }

  async function verify() {
    setBusy("verify");
    const res = await fetch(`/api/findings/${findingId}/verify`, {
      method: "POST",
    });
    const data = await res.json();
    if (data.finding) setStatus(data.finding.status);
    if (data.result) setVerification(data.result);
    setBusy(null);
  }

  const canVerify =
    status === "fixed" ||
    status === "verification_failed" ||
    status === "regression_failed";

  // 다음에 해야 할 행동을 한 줄로 안내.
  const guide = !fix
    ? "먼저 위 보고서를 확인하세요. 준비되면 AI 수정안을 생성합니다."
    : !fix.applied
      ? "수정안(아래 코드 변경)을 확인하고, 적용하면 검증 준비가 됩니다."
      : canVerify
        ? "수정을 적용했습니다. 이제 같은 공격을 다시 실행해 실제로 막혔는지, 정상 기능은 그대로인지 검증하세요."
        : status === "resolved"
          ? "이 취약점의 수정이 검증되었습니다."
          : "";

  return (
    <div className="mt-10 space-y-8">
      {/* 타임라인 */}
      <VerificationTimeline
        status={status}
        hasFix={!!fix}
        applied={!!fix?.applied}
        verification={verification}
      />

      {/* 다음 단계 안내 */}
      {guide && (
        <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-600">
          <span className="font-medium text-slate-700">다음 단계 · </span>
          {guide}
        </div>
      )}

      {/* 액션 버튼 */}
      <div className="flex flex-wrap gap-3">
        {!fix && (
          <button
            onClick={generateFix}
            disabled={busy !== null}
            className="rounded-lg bg-brand-600 px-4 py-2 font-medium text-white hover:bg-brand-700 disabled:opacity-60"
          >
            {busy === "generate" ? "생성 중…" : "AI 수정안 생성"}
          </button>
        )}
        {fix && !fix.applied && (
          <button
            onClick={applyFix}
            disabled={busy !== null}
            className="rounded-lg bg-brand-600 px-4 py-2 font-medium text-white hover:bg-brand-700 disabled:opacity-60"
          >
            {busy === "apply" ? "적용 중…" : "수정 적용"}
          </button>
        )}
        {canVerify && (
          <button
            onClick={verify}
            disabled={busy !== null}
            className="rounded-lg bg-emerald-600 px-4 py-2 font-medium text-white hover:bg-emerald-700 disabled:opacity-60"
          >
            {busy === "verify" ? "검증 중…" : "수정 검증하기"}
          </button>
        )}
      </div>

      {/* 수정안 diff */}
      {fix && (
        <section>
          <h2 className="mb-2 text-sm font-semibold tracking-wide text-slate-500">
            제안된 수정
            <span className="ml-2 rounded bg-slate-100 px-1.5 py-0.5 text-[11px] font-normal text-slate-500">
              생성 방식: {fix.source === "llm" ? "AI 모델" : "규칙 기반"}
            </span>
          </h2>
          <p className="mb-3 text-slate-700">{fix.summary}</p>
          <div className="space-y-3">
            {fix.diffs.map((d, i) => (
              <DiffBlock key={i} file={d.file} patch={d.patch} />
            ))}
          </div>
          <div className="mt-3 rounded-lg border border-brand-100 bg-brand-50 p-3 text-sm text-brand-900">
            <span className="font-medium">쉽게 설명하면 · </span>
            {fix.plainExplanation}
          </div>
        </section>
      )}

      {/* 검증 결과 */}
      {verification && (
        <VerificationResultPanel verification={verification} status={status} />
      )}
    </div>
  );
}

function DiffBlock({ file, patch }: { file: string; patch: string }) {
  return (
    <div className="overflow-hidden rounded-lg border border-slate-200">
      <div className="border-b border-slate-200 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-600">
        {file}
      </div>
      <pre className="evidence overflow-x-auto bg-slate-900 p-3">
        {patch.split("\n").map((line, i) => {
          const color = line.startsWith("+")
            ? "text-emerald-400"
            : line.startsWith("-")
              ? "text-red-400"
              : "text-slate-300";
          return (
            <div key={i} className={color}>
              {line || " "}
            </div>
          );
        })}
      </pre>
    </div>
  );
}

function VerificationResultPanel({
  verification,
  status,
}: {
  verification: VerificationResult;
  status: FindingStatus;
}) {
  const sec = verification.security;
  const reg = verification.regression;

  return (
    <section className="space-y-6">
      {/* 공격 재현 전/후 */}
      <div>
        <h2 className="mb-2 text-sm font-semibold tracking-wide text-slate-500">
          공격 재현 (수정 전 / 수정 후)
        </h2>
        <div className="grid gap-3 md:grid-cols-2">
          {sec.before && (
            <div>
              <p className="mb-1 text-sm font-medium text-slate-700">수정 전</p>
              <p className="mb-2 text-sm text-red-600">
                ❌ 권한 없는 접근이 성공함
              </p>
              <Evidence content={sec.before.response} tone="danger" />
            </div>
          )}
          {sec.after && (
            <div>
              <p className="mb-1 text-sm font-medium text-slate-700">수정 후</p>
              <p
                className={`mb-2 text-sm ${
                  sec.after.attackSucceeded ? "text-red-600" : "text-emerald-600"
                }`}
              >
                {sec.after.attackSucceeded
                  ? "❌ 권한 없는 접근이 여전히 성공함"
                  : "✓ 권한 없는 접근이 차단됨"}
              </p>
              <Evidence
                content={sec.after.response}
                tone={sec.after.attackSucceeded ? "danger" : "success"}
              />
            </div>
          )}
        </div>
      </div>

      {/* 판정 */}
      <div className="grid gap-4 md:grid-cols-2">
        <Verdict
          title="보안 검증"
          ok={sec.outcome === "pass"}
          okText="✓ 다른 사용자 데이터 접근이 차단됨"
          failText="✗ 공격이 여전히 성공함"
        />
        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <p className="mb-2 text-sm font-medium text-slate-700">회귀 검증 (정상 기능)</p>
          <ul className="space-y-1 text-sm">
            {reg.checks.map((c) => (
              <li key={c.label} className="flex items-start gap-2">
                <span
                  className={
                    c.outcome === "pass" ? "text-emerald-600" : "text-red-600"
                  }
                >
                  {c.outcome === "pass" ? "✓" : "✗"}
                </span>
                <span className="text-slate-700">
                  {c.label}
                  {c.detail && (
                    <span className="block font-mono text-xs text-slate-400">
                      {c.detail}
                    </span>
                  )}
                </span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* 최종 판정 */}
      <FinalVerdict status={status} resolved={verification.resolved} />
    </section>
  );
}

function Verdict({
  title,
  ok,
  okText,
  failText,
}: {
  title: string;
  ok: boolean;
  okText: string;
  failText: string;
}) {
  return (
    <div
      className={`rounded-xl border p-4 ${
        ok ? "border-emerald-200 bg-emerald-50" : "border-red-200 bg-red-50"
      }`}
    >
      <p className="mb-1 text-sm font-medium text-slate-700">{title}</p>
      <p className={ok ? "text-emerald-700" : "text-red-700"}>
        {ok ? okText : failText}
      </p>
    </div>
  );
}

function FinalVerdict({
  status,
  resolved,
}: {
  status: FindingStatus;
  resolved: boolean;
}) {
  if (resolved && status === "resolved") {
    return (
      <div className="rounded-xl border border-emerald-300 bg-emerald-50 p-5">
        <p className="text-lg font-semibold text-emerald-800">
          ✓ 보안 수정이 검증되었습니다
        </p>
        <p className="mt-1 text-sm text-emerald-700">
          같은 공격을 다시 실행했더니 이제 차단되었고, 정상 기능도 그대로
          동작합니다. 이는 이 취약점 한 건에 대한 수정이 검증되었다는 의미이며, 앱
          전체가 안전하다는 뜻은 아닙니다.
        </p>
      </div>
    );
  }
  if (status === "verification_failed") {
    return (
      <div className="rounded-xl border border-red-300 bg-red-50 p-5">
        <p className="text-lg font-semibold text-red-800">재검증 실패</p>
        <p className="mt-1 text-sm text-red-700">
          수정 후에도 같은 공격이 여전히 성공합니다. 이 취약점은 해결되지
          않았습니다.
        </p>
      </div>
    );
  }
  if (status === "regression_failed") {
    return (
      <div className="rounded-xl border border-red-300 bg-red-50 p-5">
        <p className="text-lg font-semibold text-red-800">기능 회귀 실패</p>
        <p className="mt-1 text-sm text-red-700">
          수정이 공격은 막았지만 정상 기능 하나를 망가뜨렸습니다. 이 취약점은
          해결되지 않았습니다.
        </p>
      </div>
    );
  }
  return null;
}

// ─────────────────────────────────────────────────────────────
// 타임라인
// ─────────────────────────────────────────────────────────────

function VerificationTimeline({
  status,
  hasFix,
  applied,
  verification,
}: {
  status: FindingStatus;
  hasFix: boolean;
  applied: boolean;
  verification: VerificationResult | null;
}) {
  const attackReproduced = status !== "detected";
  const secDone = verification?.security.outcome === "pass";
  const regDone = verification?.regression.outcome === "pass";

  const steps = [
    { label: "발견", done: true },
    { label: "공격 재현", done: attackReproduced },
    { label: "수정안 생성", done: hasFix },
    { label: "수정 적용", done: applied },
    { label: "공격 재검증", done: !!verification },
    { label: "회귀 검증", done: !!verification },
    { label: "검증 완료", done: status === "resolved" && !!secDone && !!regDone },
  ];

  return (
    <section>
      <h2 className="mb-3 text-sm font-semibold tracking-wide text-slate-500">
        검증 타임라인
      </h2>
      <ol className="flex flex-wrap items-center gap-2">
        {steps.map((s, i) => (
          <li key={s.label} className="flex items-center gap-2">
            <span
              className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-sm ${
                s.done
                  ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                  : "border-slate-200 bg-white text-slate-400"
              }`}
            >
              <span>{s.done ? "✓" : "○"}</span>
              {s.label}
            </span>
            {i < steps.length - 1 && <span className="text-slate-300">→</span>}
          </li>
        ))}
      </ol>
    </section>
  );
}
