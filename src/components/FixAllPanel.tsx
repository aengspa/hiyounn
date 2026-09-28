"use client";

import { useId, useState } from "react";
import type { Severity } from "@/lib/domain/types";
import type { PublicFixJob } from "@/lib/fixjobs/publicJob";
import { Badge, Button, Card, SeverityBadge, type BadgeTone } from "@/components/ui";
import { ProgressDialog } from "@/components/ProgressDialog";
import { fixStatusFor, type FixStatusKey } from "@/lib/ui/fixStatus";

export interface FindingView {
  id: string;
  title: string;
  severity: Severity;
  humanReadableImpact: string;
  whyItMatters: string;
  remediation?: string;
  location?: { file: string; line: number };
  isAi: boolean;
}

const STATUS_TONE: Record<FixStatusKey, BadgeTone> = {
  fixing: "info",
  needs_check: "warning",
  resolved: "success",
  failed: "danger",
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
                  <h2 id="fix-all-title" className="text-lg font-bold text-ink">
                    {job?.status === "failed" ? "다시 전체 수정해 볼까요?" : "찾은 부분을 한 번에 고쳐 볼까요?"}
                  </h2>
                  <p className="mt-1 text-sm leading-relaxed text-ink-subtle">
                    올린 원본은 그대로 두고, 고친 사본을 따로 만들어요. 고친 파일은 내려받아 직접 반영해요.
                  </p>
                </div>
                <Button onClick={runFixAll} disabled={busy !== null} aria-busy={busy === "fix"} className="w-full sm:w-auto">
                  {job?.status === "failed" ? "다시 전체 수정하기" : "전체 수정하기"}
                </Button>
              </div>
            </Card>
          )}
          {!canFix && (
            <Card variant="warm" className="p-5 text-sm leading-relaxed text-ink-subtle">
              <h2 id="fix-all-title" className="font-bold text-ink">이 점검 기록은 전체 수정을 할 수 없어요</h2>
              <p className="mt-1">어떤 코드를 점검했는지 기록이 남지 않은 예전 점검이에요. 프로젝트에서 다시 점검해 주세요.</p>
            </Card>
          )}
          {error && (
            <p role="alert" className="mt-3 rounded-2xl bg-danger-soft p-3 text-sm font-medium text-danger">
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
        <h2 id="findings-title" className="text-lg font-bold text-ink">
          확인할 부분 ({findings.length}개)
        </h2>
        <ol className="mt-4 space-y-3">
          {findings.map((f) => {
            const item = job?.items.find((it) => it.findingId === f.id);
            const status =
              busy === "fix"
                ? fixStatusFor(f.id, { jobStatus: "running", item: { findingId: f.id, outcome: "skipped", reasonCode: "pending" } })
                : fixStatusFor(f.id, { jobStatus: job?.status, item, verification });
            return (
              <li key={f.id}>
                <FindingRow finding={f} statusKey={status.key} statusLabel={status.label} statusDetail={status.detail} fixNote={item?.outcome === "applied" ? item.plainExplanation ?? item.summary : undefined} />
              </li>
            );
          })}
        </ol>
      </section>

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

function FindingRow({
  finding,
  statusKey,
  statusLabel,
  statusDetail,
  fixNote,
}: {
  finding: FindingView;
  statusKey: FixStatusKey;
  statusLabel: string;
  statusDetail: string;
  fixNote?: string;
}) {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  return (
    <div className="rounded-3xl border border-line bg-surface p-5 shadow-warm sm:p-6">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={STATUS_TONE[statusKey]}>{statusLabel}</Badge>
        <SeverityBadge severity={finding.severity} />
        {finding.isAi && <Badge tone="neutral">AI 분석</Badge>}
      </div>
      <h3 className="mt-3 break-words text-base font-bold text-ink sm:text-lg">{finding.title}</h3>
      <p className="mt-1 break-keep leading-relaxed text-ink-subtle">{finding.humanReadableImpact}</p>
      <button
        type="button"
        className="mt-3 inline-flex min-h-11 items-center rounded-xl pr-2 text-sm font-bold text-brand-800 hover:underline"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((v) => !v)}
      >
        {open ? "접기" : "더보기"}
      </button>
      <div id={panelId} hidden={!open} className="mt-2 space-y-3 border-t border-line pt-3 text-sm leading-relaxed text-ink-subtle">
        <p>
          <span className="font-bold text-ink">지금 상태: </span>
          {statusDetail}
        </p>
        <p>
          <span className="font-bold text-ink">왜 위험한가요? </span>
          {finding.whyItMatters}
        </p>
        {finding.remediation && (
          <p>
            <span className="font-bold text-ink">어떻게 고치나요? </span>
            {finding.remediation}
          </p>
        )}
        {fixNote && (
          <p>
            <span className="font-bold text-ink">이번에 바꾼 내용: </span>
            {fixNote}
          </p>
        )}
        {finding.location && (
          <p className="break-all font-mono text-xs text-ink-muted">
            {finding.location.file}:{finding.location.line}
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
  const vCounts = { resolved: 0, failed: 0, check: 0 };
  if (v && v.status !== "running") {
    for (const it of v.items) {
      if (it.verdict === "fixed_in_source") vCounts.resolved += 1;
      else if (it.verdict === "still_present") vCounts.failed += 1;
      else vCounts.check += 1;
    }
  }
  const headline =
    job.status === "completed"
      ? `${appliedItems.length}개 항목을 모두 고쳤어요`
      : job.status === "partial"
        ? `${job.items.length}개 중 ${appliedItems.length}개를 고쳤어요`
        : job.errorMessage ?? "수정을 적용하지 못했어요";

  return (
    <section aria-labelledby="fix-result-title" className="mt-6">
      <Card variant={job.status === "failed" ? "danger" : "warm"} className="p-5 sm:p-6">
        <h2 id="fix-result-title" className="text-lg font-bold text-ink">
          {headline}
        </h2>
        {job.status !== "failed" && (
          <p className="mt-1 text-sm text-ink-subtle">
            고친 내용은 아직 재검증 전이에요. 재검증으로 문제가 사라졌는지 확인해 주세요.
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

        {failedItems.length > 0 && (
          <div className="mt-4">
            <h3 className="text-sm font-bold text-ink">고치지 못한 항목 ({failedItems.length}개)</h3>
            <ul className="mt-2 space-y-2 text-sm">
              {failedItems.map((it) => (
                <li key={it.findingId} className="rounded-2xl bg-surface p-3">
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
              className="hoi-button-3d inline-flex min-h-12 items-center justify-center gap-2 rounded-2xl border-2 border-line-input bg-surface px-5 font-bold text-ink shadow-[0_3px_0_var(--border-strong)] hover:bg-surface-warm"
            >
              수정된 파일 다운로드
              <span className="text-xs font-medium text-ink-muted">({formatBytes(job.artifact.size)})</span>
            </a>
            <Button onClick={onVerify} disabled={busy !== null} aria-busy={busy === "verify"}>
              {v ? "다시 재검증하기" : "재검증하기"}
            </Button>
          </div>
        )}
        {job.artifact && (
          <>
            <p className="mt-4 rounded-2xl bg-info-soft p-3 text-sm leading-relaxed text-info">{GUIDANCE}</p>
            <p className="mt-2 break-all text-xs text-ink-muted">
              파일 확인값(SHA-256): <span className="font-mono">{job.artifact.sha256}</span>
            </p>
          </>
        )}
      </Card>

      {v && v.status !== "running" && (
        <Card variant={v.status === "failed" ? "danger" : "default"} className="mt-4 p-5 sm:p-6" aria-live="polite">
          <h2 className="text-lg font-bold text-ink">
            {v.status === "failed" ? "AI 재검증을 완료하지 못했어요" : "재검증 결과"}
          </h2>
          {v.status === "failed" ? (
            <p className="mt-1 text-sm text-ink-subtle">
              {v.errorMessage ?? "잠시 후 다시 시도해 주세요."} 규칙으로 확인한 항목 결과는 아래 목록에 반영돼 있어요.
            </p>
          ) : (
            <p className="mt-1 text-sm text-ink-subtle">
              해결 완료 {vCounts.resolved}개 · 해결 실패 {vCounts.failed}개 · 점검 필요 {vCounts.check}개
            </p>
          )}
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
