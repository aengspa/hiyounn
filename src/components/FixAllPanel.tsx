"use client";

import { useId, useState } from "react";
import type { Severity } from "@/lib/domain/types";
import type { PublicFixJob } from "@/lib/fixjobs/publicJob";
import { Badge, Button, Card, Confetti, SeverityBadge, buttonClassName, type BadgeTone } from "@/components/ui";
import { Hoi } from "@/components/mascot/Hoi";
import { ProgressDialog } from "@/components/ProgressDialog";
import { fixStatusFor, type FixStatusKey } from "@/lib/ui/fixStatus";
import type { CodeContext } from "@/lib/ui/codeContext";
import type { SecurityFinding } from "@/lib/domain/types";
import { CodeView } from "@/components/CodeView";
import { EditDiff, JobDiff } from "@/components/DiffView";
import { AdjudicationNote, VerifyNote } from "@/components/ReviewNotes";

export interface FindingView {
  id: string;
  title: string;
  severity: Severity;
  humanReadableImpact: string;
  whyItMatters: string;
  remediation?: string;
  location?: { file: string; line: number };
  /** AI 분석만 찾은 항목. */
  isAi: boolean;
  /** 규칙 기반 항목에 대한 AI 의견과 재판정(있을 때). */
  aiReview?: SecurityFinding["aiReview"];
  /** 문제가 된 실제 코드(비밀값은 가림). */
  code?: CodeContext;
  /** 같은 문제를 함께 찾은 다른 검사기. */
  corroboratedBy?: string[];
  /** 재업로드 증분 점검에서 이전 결과를 이어 온 항목. */
  carriedOver?: boolean;
}

/** 점검 때 AI가 근거와 함께 오탐으로 판정한 규칙 항목. */
function isAdjudicatedFalsePositive(f: FindingView): boolean {
  return f.aiReview?.adjudication?.verdict === "not_vulnerable";
}

const STATUS_TONE: Record<FixStatusKey, BadgeTone> = {
  fixing: "info",
  needs_check: "warning",
  not_fixed: "warning",
  resolved: "success",
  resolved_ai: "info",
  still_present: "danger",
  disputed: "warning",
  false_positive: "neutral",
};

const GUIDANCE = "받은 파일을 프로젝트에 반영해주세요. 공개한 웹사이트도 적용하려면 다시 배포해야 해요.";
const POLL_MS = 3000;
const POLL_MAX = 80; // 약 4분

async function readJson(res: Response): Promise<any> {
  try {
    return await res.json();
  } catch {
    return null;
  }
}

function errorText(status: number, data: any, fallback: string): string {
  if (status === 401) return "로그인이 필요해요. 다시 로그인한 뒤 시도해 주세요.";
  if (status === 403 || status === 404) return "이 점검 기록을 찾을 수 없어요. 목록에서 다시 열어 주세요.";
  if (typeof data?.message === "string" && data.message) return data.message;
  if (status === 504 || status === 408) return "처리 시간이 너무 오래 걸려 멈췄어요. 잠시 후 다시 시도해 주세요.";
  return fallback;
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}KB`;
  return `${(n / 1024 / 1024).toFixed(1)}MB`;
}

export function FixAllPanel({
  scanId,
  findings,
  initialJob,
  canFix,
}: {
  scanId: string;
  findings: FindingView[];
  initialJob?: PublicFixJob;
  /** 이 점검이 소스 버전을 기록했을 때만 전체 수정이 가능하다. */
  canFix: boolean;
}) {
  const [job, setJob] = useState<PublicFixJob | undefined>(initialJob);
  const [busy, setBusy] = useState<"fix" | "verify" | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function poll(jobId: string, until: (j: PublicFixJob) => boolean): Promise<PublicFixJob | undefined> {
    for (let i = 0; i < POLL_MAX; i++) {
      await new Promise((r) => setTimeout(r, POLL_MS));
      const res = await fetch(`/api/fix-jobs/${encodeURIComponent(jobId)}`, { cache: "no-store" });
      const data = await readJson(res);
      if (!res.ok) throw Object.assign(new Error("poll_failed"), { status: res.status, data });
      if (data?.job && until(data.job)) return data.job as PublicFixJob;
    }
    return undefined;
  }

  async function runFixAll() {
    setBusy("fix");
    setError(null);
    try {
      const res = await fetch(`/api/scans/${encodeURIComponent(scanId)}/fix-all`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      const data = await readJson(res);
      if (!res.ok || !data?.job) {
        setError(errorText(res.status, data, "전체 수정을 마치지 못했어요. 잠시 후 다시 시도해 주세요."));
        return;
      }
      let next = data.job as PublicFixJob;
      if (next.status === "running") {
        const done = await poll(next.id, (j) => j.status !== "running");
        if (!done) {
          setError("수정이 아직 끝나지 않았어요. 잠시 후 이 화면을 새로고침해 주세요.");
          return;
        }
        next = done;
      }
      setJob(next);
    } catch (e) {
      const st = (e as { status?: number }).status;
      setError(
        st ? errorText(st, (e as { data?: unknown }).data, "수정 상태를 확인하지 못했어요.") : "연결이 잠깐 끊겼어요. 인터넷 연결을 확인하고 다시 시도해 주세요."
      );
    } finally {
      setBusy(null);
    }
  }

  async function runVerify() {
    if (!job) return;
    setBusy("verify");
    setError(null);
    try {
      const res = await fetch(`/api/fix-jobs/${encodeURIComponent(job.id)}/verify`, { method: "POST" });
      const data = await readJson(res);
      if (res.status === 409 && data?.error === "verify_in_progress") {
        const done = await poll(job.id, (j) => j.verification?.status !== "running");
        if (done) setJob(done);
        else setError("재검증이 아직 끝나지 않았어요. 잠시 후 새로고침해 주세요.");
        return;
      }
      if (!res.ok || !data?.job) {
        setError(errorText(res.status, data, "재검증을 마치지 못했어요. 잠시 후 다시 시도해 주세요."));
        return;
      }
      setJob(data.job as PublicFixJob);
    } catch {
      setError("연결이 잠깐 끊겼어요. 인터넷 연결을 확인하고 다시 시도해 주세요.");
    } finally {
      setBusy(null);
    }
  }

  const finished = job && job.status !== "running";
  const falsePositives = findings.filter(isAdjudicatedFalsePositive);
  const active = findings.filter((f) => !isAdjudicatedFalsePositive(f));

  function renderRow(f: FindingView) {
    const item = job?.items.find((it) => it.findingId === f.id);
    const status =
      busy === "fix"
        ? fixStatusFor(f.id, { jobStatus: "running", item: { findingId: f.id, outcome: "skipped", reasonCode: "pending" } })
        : fixStatusFor(f.id, { jobStatus: job?.status, item, verification, adjudicatedFalsePositive: isAdjudicatedFalsePositive(f) });
    const verifyItem = verification && verification.status !== "running" ? verification.items.find((it) => it.findingId === f.id) : undefined;
    return (
      <FindingRow
        finding={f}
        statusKey={status.key}
        statusLabel={status.label}
        statusDetail={status.detail}
        fixNote={item?.outcome === "applied" ? item.plainExplanation ?? item.summary : undefined}
        edits={item?.outcome === "applied" ? item.edits : undefined}
        verifyItem={verifyItem}
      />
    );
  }
  const showFixButton = findings.length > 0 && canFix && (!job || job.status === "failed");
  const verification = job?.verification;

  return (
    <>
      {/* 맨 위: 전체 수정하기 (화면의 유일한 주요 버튼) */}
      {findings.length > 0 && (
        <section aria-labelledby="fix-all-title" className="mt-6">
          {showFixButton && (
            <Card variant="raised" className="p-5 sm:p-6">
              <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <p className="inline-flex rounded-full bg-sun-soft px-3 py-0.5 text-[13px] font-bold text-brand-900">가장 먼저 할 일</p>
                  <h2 id="fix-all-title" className="mt-2 text-xl font-extrabold text-ink">
                    {job?.status === "failed" ? "다시 한 번 고쳐 볼까요?" : "찾은 부분을 한 번에 고쳐 볼까요?"}
                  </h2>
                  <p className="mt-1 text-sm leading-relaxed text-ink-subtle">
                    올린 원본은 그대로 두고, 고친 사본을 따로 만들어요. 고친 파일은 내려받아 직접 반영해요.
                  </p>
                </div>
                <Button onClick={runFixAll} disabled={busy !== null} aria-busy={busy === "fix"} size="lg" className="w-full shrink-0 sm:w-auto">
                  {job?.status === "failed" ? "다시 고쳐 보기" : "한 번에 고쳐 보기"}
                </Button>
              </div>
            </Card>
          )}
          {!canFix && (
            <Card variant="warm" className="p-5 text-sm leading-relaxed text-ink-subtle">
              <h2 id="fix-all-title" className="font-extrabold text-ink">이 점검 기록은 한 번에 고치기를 할 수 없어요</h2>
              <p className="mt-1">어떤 코드를 점검했는지 기록이 남지 않은 예전 점검이에요. 프로젝트에서 다시 점검해 주세요.</p>
            </Card>
          )}
          {error && (
            <p role="alert" className="mt-3 rounded-2xl border-2 border-[#f3c4bd] bg-danger-soft p-3 text-sm font-semibold text-danger">
              {error}
            </p>
          )}
        </section>
      )}

      {/* 수정 결과 */}
      {finished && job && (
        <FixResult job={job} busy={busy} onVerify={runVerify} />
      )}

      {/* 항목 목록 */}
      <section aria-labelledby="findings-title" className="mt-10">
        <h2 id="findings-title" className="text-xl font-extrabold text-ink sm:text-2xl">
          호이가 찾은 부분 <span className="text-brand-800">({active.length}개)</span>
        </h2>
        <ol className="mt-4 space-y-3">
          {active.map((f) => (
            <li key={f.id}>{renderRow(f)}</li>
          ))}
        </ol>
      </section>

      {falsePositives.length > 0 && (
        <details className="mt-8 rounded-3xl border-2 border-dashed border-line-strong bg-surface-warm p-4 sm:p-5">
          <summary className="flex min-h-11 cursor-pointer items-center text-base font-extrabold text-ink hover:text-brand-800">
            AI가 오탐으로 판정한 규칙 결과 ({falsePositives.length}개)
          </summary>
          <p className="mt-2 text-sm text-ink-subtle">
            규칙 검사가 잡았지만, AI가 코드 근거를 확인해 실제 취약점이 아니라고 판정한 항목이에요. 기록으로 남겨 두었고 자동 수정 대상에서는 뺐어요.
          </p>
          <ol className="mt-4 space-y-3">
            {falsePositives.map((f) => (
              <li key={f.id}>{renderRow(f)}</li>
            ))}
          </ol>
        </details>
      )}

      <ProgressDialog
        open={busy !== null}
        title={busy === "verify" ? "고친 코드를 다시 확인하고 있어요" : "찾은 부분을 고치고 있어요"}
        description={
          busy === "verify"
            ? "수정본 코드를 기준으로 원래 문제가 남아 있는지 확인해요. 최대 1~2분 걸릴 수 있어요."
            : `항목 ${findings.length}개를 차례로 고쳐요. 최대 1~2분 걸릴 수 있고, 끝나면 결과를 보여 드려요.`
        }
      />
    </>
  );
}

const SEV_ACCENT: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
};

const CORROBORATOR_LABEL: Record<string, string> = {
  semgrep: "Semgrep도 확인",
  "authz-table": "권한 표도 확인",
  ai: "AI도 확인",
};

function FindingRow({
  finding,
  statusKey,
  statusLabel,
  statusDetail,
  fixNote,
  edits,
  verifyItem,
}: {
  finding: FindingView;
  statusKey: FixStatusKey;
  statusLabel: string;
  statusDetail: string;
  fixNote?: string;
  edits?: { file: string; before: string; after: string }[];
  verifyItem?: NonNullable<PublicFixJob["verification"]>["items"][number];
}) {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const adjudication = finding.aiReview?.adjudication;
  return (
    <div className="relative overflow-hidden rounded-3xl border-2 border-line bg-surface p-5 pl-6 shadow-warm sm:p-6 sm:pl-7">
      {/* 심각도 색 띠(장식). 심각도는 배지의 글자·아이콘으로도 전달한다 */}
      <span aria-hidden="true" className={`absolute inset-y-0 left-0 w-1.5 ${SEV_ACCENT[finding.severity] ?? "bg-line-strong"}`} />
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={STATUS_TONE[statusKey]}>{statusLabel}</Badge>
        <SeverityBadge severity={finding.severity} />
        {finding.isAi && <Badge tone="neutral">AI 분석</Badge>}
        {finding.aiReview?.verdict === "confirmed" && <Badge tone="neutral">AI도 확인</Badge>}
        {finding.aiReview?.verdict === "likely_false_positive" && !adjudication && <Badge tone="neutral">AI: 오탐 가능성</Badge>}
        {(finding.corroboratedBy ?? [])
          .filter((c) => c !== "ai")
          .map((c) => (
            <Badge key={c} tone="neutral">
              {CORROBORATOR_LABEL[c] ?? `${c}도 확인`}
            </Badge>
          ))}
        {finding.carriedOver && <Badge tone="neutral">이전 점검에서 이어옴</Badge>}
      </div>
      <h3 className="mt-3 break-words text-lg font-extrabold text-ink sm:text-xl">{finding.title}</h3>
      <p className="mt-1 break-keep leading-relaxed text-ink-subtle">{finding.humanReadableImpact}</p>

      {finding.code ? (
        <CodeView code={finding.code} caption="문제가 된 코드" />
      ) : (
        finding.location && (
          <p className="mt-3 break-all font-mono text-xs text-ink-muted">
            {finding.location.file}:{finding.location.line}
          </p>
        )
      )}

      {adjudication && <AdjudicationNote adjudication={adjudication} />}

      {edits && edits.length > 0 && (
        <div className="mt-4">
          <h4 className="text-sm font-bold text-ink">이번에 바꾼 코드</h4>
          {fixNote && <p className="mt-1 text-sm text-ink-subtle">{fixNote}</p>}
          <EditDiff edits={edits} />
        </div>
      )}

      {verifyItem && <VerifyNote item={verifyItem} fallback={statusDetail} />}

      <button
        type="button"
        className="mt-4 inline-flex min-h-11 items-center gap-2 rounded-full border-2 border-line bg-surface-warm px-4 text-sm font-bold text-brand-800 hover:border-brand-300"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((v) => !v)}
      >
        {open ? "접기" : "자세히 보기"}
        <span aria-hidden="true" className={`transition-transform motion-reduce:transition-none ${open ? "rotate-180" : ""}`}>
          ▾
        </span>
      </button>
      <div id={panelId} hidden={!open} className="mt-3 space-y-3 rounded-2xl border-2 border-dashed border-line bg-surface-warm p-4 text-sm leading-relaxed text-ink-subtle">
        <p>
          <span className="block font-bold text-ink">지금 상태</span>
          {statusDetail}
        </p>
        <p>
          <span className="block font-bold text-ink">이대로 두면 어떤 일이 생겨요?</span>
          {finding.whyItMatters}
        </p>
        {finding.aiReview?.verdict === "likely_false_positive" && !adjudication && (
          <p>
            <span className="block font-bold text-ink">AI 의견</span>
            규칙이 찾은 항목이지만 AI는 실제 문제가 아닐 수 있다고 봤어요
            {finding.aiReview.reason ? ` (${finding.aiReview.reason})` : ""}. 규칙 결과는 그대로 두었으니 코드를 보고 판단해 주세요.
          </p>
        )}
        {finding.remediation && (
          <p>
            <span className="block font-bold text-ink">이렇게 고쳐보세요</span>
            {finding.remediation}
          </p>
        )}
      </div>
    </div>
  );
}

function FixResult({
  job,
  busy,
  onVerify,
}: {
  job: PublicFixJob;
  busy: "fix" | "verify" | null;
  onVerify: () => void;
}) {
  const failedItems = job.items.filter((it) => it.outcome !== "applied");
  const appliedItems = job.items.filter((it) => it.outcome === "applied");
  const v = job.verification;
  const vCounts = { resolved: 0, resolvedAi: 0, still: 0, disputed: 0, check: 0 };
  if (v && v.status !== "running") {
    for (const it of v.items) {
      if (it.reasonCode === "disputed") vCounts.disputed += 1;
      else if (it.verdict === "fixed_in_source" && it.method === "llm") vCounts.resolvedAi += 1;
      else if (it.verdict === "fixed_in_source") vCounts.resolved += 1;
      else if (it.verdict === "still_present") vCounts.still += 1;
      else vCounts.check += 1;
    }
  }
  // 규칙 재검사로 확인한 해결만 있고, 남아 있음·엇갈림·확인 필요·AI 판단이 하나도 없을 때만 축하한다.
  const allBlocked =
    job.status === "completed" && !!v && v.status === "completed" && vCounts.resolved > 0 && vCounts.resolvedAi + vCounts.still + vCounts.disputed + vCounts.check === 0;
  const vSummary = [
    vCounts.resolved && `해결 확인 ${vCounts.resolved}개`,
    vCounts.resolvedAi && `AI 판단 해결 ${vCounts.resolvedAi}개`,
    vCounts.still && `남아 있음 ${vCounts.still}개`,
    vCounts.disputed && `판단 엇갈림 ${vCounts.disputed}개`,
    vCounts.check && `확인 필요 ${vCounts.check}개`,
  ]
    .filter(Boolean)
    .join(" · ");
  const headline =
    job.status === "completed"
      ? `${appliedItems.length}개 항목을 모두 고쳤어요`
      : job.status === "partial"
        ? `${job.items.length}개 중 ${appliedItems.length}개를 고쳤어요`
        : job.errorMessage ?? "수정을 적용하지 못했어요";

  return (
    <section aria-labelledby="fix-result-title" className="mt-6">
      <Card variant={job.status === "failed" ? "danger" : "raised"} className="p-5 sm:p-6">
        <h2 id="fix-result-title" className="text-xl font-extrabold text-ink">
          {headline}
        </h2>
        {job.status !== "failed" && (
          <p className="mt-1 text-sm text-ink-subtle">
            고친 내용이 정말 잘 막히는지는 아직 확인 전이에요. 아래 버튼으로 호이가 한 번 더 확인해요.
          </p>
        )}

        {job.changedFiles.length > 0 && (
          <div className="mt-4">
            <h3 className="text-sm font-bold text-ink">바뀐 파일 ({job.changedFiles.length}개)</h3>
            <ul className="mt-2 space-y-1">
              {job.changedFiles.map((p) => (
                <li key={p} className="break-all font-mono text-xs text-ink-subtle">
                  {p}
                </li>
              ))}
            </ul>
          </div>
        )}

        {job.changedFiles.length > 0 && <JobDiff jobId={job.id} />}

        {job.requiredEnv.length > 0 && (
          <div className="mt-4 rounded-2xl border-2 border-[#f0d9a6] bg-warning-soft p-4 text-sm leading-relaxed">
            <h3 className="font-bold text-warning">받은 파일을 반영하기 전에 설정할 환경변수 ({job.requiredEnv.length}개)</h3>
            <p className="mt-1 text-ink-subtle">설정하지 않으면 해당 기능이 안전하게 멈추도록(요청 거절) 고쳐져 있어요.</p>
            <ul className="mt-2 space-y-2">
              {job.requiredEnv.map((e) => (
                <li key={e.name}>
                  <span className="font-mono font-bold text-ink">{e.name}</span>
                  <span className="ml-1 text-xs text-ink-muted">({e.files.join(", ")})</span>
                  <span className="block text-ink-subtle">{e.guidance}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {failedItems.length > 0 && (
          <div className="mt-4">
            <h3 className="text-sm font-bold text-ink">고치지 못한 항목 ({failedItems.length}개)</h3>
            <ul className="mt-2 space-y-2 text-sm">
              {failedItems.map((it) => (
                <li key={it.findingId} className="rounded-2xl border-2 border-line bg-surface p-3">
                  <span className="font-bold text-ink">{it.title}</span>
                  <span className="block text-ink-subtle">{it.reason}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {job.artifact && (
          <div className="mt-5 flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
            <a
              href={job.artifact.downloadPath}
              download={job.artifact.fileName}
              className={buttonClassName({ variant: "secondary" })}
            >
              고친 파일 내려받기
              <span className="text-[13px] font-medium text-ink-subtle">({formatBytes(job.artifact.size)})</span>
            </a>
            <Button onClick={onVerify} disabled={busy !== null} aria-busy={busy === "verify"}>
              {v ? "한 번 더 확인하기" : "정말 막혔는지 다시 확인하기"}
            </Button>
          </div>
        )}
        {job.artifact && (
          <>
            <p className="mt-4 rounded-2xl border-2 border-[#c9def3] bg-info-soft p-3 text-sm font-semibold leading-relaxed text-info">{GUIDANCE}</p>
            <p className="mt-2 break-all text-xs text-ink-muted">
              파일 확인값(SHA-256): <span className="font-mono">{job.artifact.sha256}</span>
            </p>
          </>
        )}
      </Card>

      {v && v.status !== "running" && (
        <Card
          variant={v.status === "failed" ? "danger" : allBlocked ? "warm" : "default"}
          className={`relative mt-4 overflow-hidden p-5 sm:p-6 ${allBlocked ? "!border-[#bfe0c8]" : ""}`}
          aria-live="polite"
        >
          {allBlocked && <Confetti />}
          <div className="flex items-center gap-4">
            {allBlocked && <Hoi mood="celebrate" size="md" decorative className="shrink-0" />}
            <h2 className="text-xl font-extrabold text-ink">
              {v.status === "failed"
                ? "다시 확인하는 과정을 끝내지 못했어요"
                : allBlocked
                  ? "잘 막았어요! 한 단계 더 튼튼해졌어요"
                  : vCounts.still > 0
                    ? "아직 완전히 막히지 않은 곳이 있어요"
                    : "다시 확인한 결과"}
            </h2>
          </div>
          {v.status === "failed" && (
            <p className="mt-1 text-sm text-ink-subtle">{v.errorMessage ?? "잠시 후 다시 시도해 주세요."}</p>
          )}
          {vSummary && <p className="mt-1 text-sm text-ink-subtle">{vSummary}</p>}
          <p className="mt-2 text-xs leading-relaxed text-ink-muted">
            규칙 재검사가 기준이에요. AI 판단은 규칙으로 볼 수 없는 항목을 판단하거나 규칙 결과를 교차 확인할 때 써요. 둘이 다르면 &ldquo;판단이 엇갈려요&rdquo;로 표시해요.
          </p>
          <p className="mt-2 text-xs leading-relaxed text-ink-muted">
            수정본 코드를 기준으로 확인한 결과예요. 배포한 사이트에서 실행해 본 결과는 아니에요.
          </p>
          {v.aiStatus === "not_available" && (
            <p className="mt-2 text-sm text-warning">AI 재검증을 쓸 수 없어 일부 항목은 확인하지 못했어요.</p>
          )}
          {v.omittedFiles.length > 0 && (
            <p className="mt-2 text-sm text-warning">
              파일 {v.omittedFiles.length}개는 길이 한도 때문에 AI 재검증에 보내지 못했어요.
            </p>
          )}
        </Card>
      )}
    </section>
  );
}
