"use client";

import { useId, useState, type ReactNode } from "react";
import type { Severity } from "@/lib/domain/types";
import type { PublicFixJob } from "@/lib/fixjobs/publicJob";
import { Badge, Button, Card, Confetti, SeverityBadge, buttonClassName, type BadgeTone } from "@/components/ui";
import { Hoi } from "@/components/mascot/Hoi";
import { ProgressDialog } from "@/components/ProgressDialog";
import {
  FIX_STATUS_MARK,
  FIX_STEP_MARK,
  REVERIFY_BUTTON_LABEL,
  VERIFY_BUTTON_LABEL,
  fixStatusFor,
  fixStepsFor,
  type FixStatus,
  type FixStatusKey,
  type FixStep,
} from "@/lib/ui/fixStatus";
import type { CodeContext } from "@/lib/ui/codeContext";
import type { SecurityFinding } from "@/lib/domain/types";
import { CodeView } from "@/components/CodeView";
import { EditDiff, JobDiff } from "@/components/DiffView";
import { AdjudicationNote, VerifyNote } from "@/components/ReviewNotes";
import { FindingLocations } from "@/components/FindingLocations";
import { aggregateStatus, formatLocation, groupFindings, type FindingGroup } from "@/lib/ui/groupFindings";

export interface FindingView {
  id: string;
  title: string;
  severity: Severity;
  humanReadableImpact: string;
  whyItMatters: string;
  remediation?: string;
  location?: { file: string; line: number };
  /** 기술 정보(자세히 보기 안에서만 보여 줌). */
  ruleId?: string;
  cwe?: string;
  owasp?: string;
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

const GUIDANCE = "받은 파일을 프로젝트에 반영해 주세요. 공개한 웹사이트에도 적용하려면 다시 배포해야 해요.";
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

/** 묶은 개수와 원래 개수가 다르면 둘 다 보여 준다. 예: "문제 5가지 · 발견 위치 12곳" */
function countText(groups: number, raw: number): string {
  return groups === raw ? `${raw}개` : `문제 ${groups}가지 · 발견 위치 ${raw}곳`;
}

type VerifyItem = NonNullable<PublicFixJob["verification"]>["items"][number];

/** 한 항목(발견 위치 하나)의 수정·재검증 상태. */
interface MemberState {
  finding: FindingView;
  status: FixStatus;
  steps?: FixStep[];
  hasJobItem: boolean;
  applied: boolean;
  fixNote?: string;
  edits?: { file: string; before: string; after: string }[];
  verifyItem?: VerifyItem;
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
        setError(errorText(res.status, data, "전체 수정을 마치지 못했어요. 파일은 바뀌지 않았어요. 잠시 후 다시 시도해 주세요."));
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
        st
          ? errorText(st, (e as { data?: unknown }).data, "수정이 어디까지 진행됐는지 확인하지 못했어요. 이 화면을 새로고침해 주세요.")
          : "연결이 잠깐 끊겼어요. 인터넷 연결을 확인하고 다시 시도해 주세요."
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
        setError(
          errorText(res.status, data, `재검증을 끝내지 못해 고친 항목이 해결됐는지 아직 확인하지 못했어요. 잠시 후 ‘${REVERIFY_BUTTON_LABEL}’를 눌러 주세요.`)
        );
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
  const verification = job?.verification;

  function memberState(f: FindingView): MemberState {
    const jobItem = job?.items.find((it) => it.findingId === f.id);
    const input =
      busy === "fix"
        ? { jobStatus: "running" as const, item: { findingId: f.id, outcome: "skipped" as const, reasonCode: "pending" } }
        : { jobStatus: job?.status, item: jobItem, verification, adjudicatedFalsePositive: isAdjudicatedFalsePositive(f) };
    const verifyItem =
      busy !== "fix" && verification && verification.status !== "running" ? verification.items.find((it) => it.findingId === f.id) : undefined;
    const applied = busy !== "fix" && jobItem?.outcome === "applied";
    return {
      finding: f,
      status: fixStatusFor(f.id, input),
      steps: fixStepsFor(f.id, input),
      hasJobItem: Boolean(input.item),
      applied,
      fixNote: applied ? jobItem?.plainExplanation ?? jobItem?.summary : undefined,
      edits: applied ? jobItem?.edits : undefined,
      verifyItem,
    };
  }

  function renderGroup(g: FindingGroup<FindingView>) {
    return <FindingRow group={g} members={g.members.map(memberState)} />;
  }
  const activeGroups = groupFindings(active);
  const falsePositiveGroups = groupFindings(falsePositives);
  const showFixButton = findings.length > 0 && canFix && (!job || job.status === "failed");

  return (
    <>
      {/* 맨 위: 전체 수정하기 (화면의 유일한 주요 버튼) */}
      {findings.length > 0 && (
        <section aria-labelledby="fix-all-title" className="mt-6">
          {showFixButton && (
            <Card variant="raised" className="p-5 sm:p-6">
              <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                <div className="min-w-0">
                  <p className="inline-flex rounded-full bg-sun-soft px-3 py-0.5 text-[13px] font-bold text-brand-900">가장 먼저 할 일</p>
                  <h2 id="fix-all-title" className="mt-2 text-xl font-extrabold text-ink">
                    {job?.status === "failed" ? "다시 한 번 고쳐 볼까요?" : "찾은 부분을 한 번에 고쳐 볼까요?"}
                  </h2>
                  <p className="mt-1 text-base leading-relaxed text-ink">
                    호이가 수정안을 만들어 고친 사본 파일에 적용해요. 올린 원본은 그대로예요. 고친 파일은 내려받아 직접 반영해요.
                  </p>
                </div>
                <Button onClick={runFixAll} disabled={busy !== null} aria-busy={busy === "fix"} size="lg" className="w-full shrink-0 sm:w-auto">
                  {job?.status === "failed" ? "다시 고쳐 보기" : "한 번에 고쳐 보기"}
                </Button>
              </div>
            </Card>
          )}
          {!canFix && (
            <Card variant="warm" className="p-5 text-base leading-relaxed text-ink">
              <h2 id="fix-all-title" className="font-extrabold text-ink">이 점검 기록은 한 번에 고치기를 할 수 없어요</h2>
              <p className="mt-1">어떤 코드를 점검했는지 기록이 남지 않은 예전 점검이에요. 프로젝트에서 다시 점검해 주세요.</p>
            </Card>
          )}
          {error && (
            <p role="alert" className="mt-3 break-words rounded-2xl border-2 border-[#f3c4bd] bg-danger-soft p-3 text-base font-semibold leading-relaxed text-danger">
              <span aria-hidden="true" className="mr-1">✕</span>
              {error}
            </p>
          )}
        </section>
      )}

      {/* 수정 결과 */}
      {finished && job && <FixResult job={job} findings={findings} busy={busy} onVerify={runVerify} />}

      {/* 항목 목록 */}
      <section aria-labelledby="findings-title" className="mt-10">
        <h2 id="findings-title" className="text-xl font-extrabold text-ink sm:text-2xl">
          호이가 찾은 부분 <span className="text-brand-800">({countText(activeGroups.length, active.length)})</span>
        </h2>
        <ol className="mt-4 space-y-3">
          {activeGroups.map((g) => (
            <li key={g.key}>{renderGroup(g)}</li>
          ))}
        </ol>
      </section>

      {falsePositives.length > 0 && (
        <details className="mt-8 rounded-3xl border-2 border-dashed border-line-strong bg-surface-warm p-4 sm:p-5">
          <summary className="flex min-h-11 cursor-pointer items-center text-base font-extrabold text-ink hover:text-brand-800">
            AI가 오탐으로 판정한 규칙 결과 ({countText(falsePositiveGroups.length, falsePositives.length)})
          </summary>
          <p className="mt-2 text-base leading-relaxed text-ink">
            규칙 검사가 잡았지만, AI가 코드 근거를 확인해 실제 취약점이 아니라고 판정한 항목이에요. 기록으로 남겨 두었고 자동 수정 대상에서는 뺐어요. 판정이 맞는지 근거 코드를 한 번 확인해 주세요.
          </p>
          <ol className="mt-4 space-y-3">
            {falsePositiveGroups.map((g) => (
              <li key={g.key}>{renderGroup(g)}</li>
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
            : `항목 ${findings.length}개의 수정안을 만들어 사본 파일에 차례로 적용해요. 최대 1~2분 걸릴 수 있고, 끝나면 결과를 보여 드려요.`
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

function sameText(a: string, b: string): boolean {
  const norm = (s: string) => s.replace(/\s+/g, " ").trim();
  return norm(a) === norm(b);
}

/**
 * 항목 설명 세 칸. 규칙 항목 중에는 영향과 이유에 같은 문장을 넣어 둔 것이 있어,
 * 앞 칸과 같은 문장은 건너뛴다.
 */
function explanationBlocks(f: FindingView): { key: string; label: string; text: string }[] {
  const candidates = [
    { key: "impact", label: "어떤 일이 생길 수 있나요", text: f.humanReadableImpact ?? "" },
    { key: "why", label: "왜 이렇게 판단했나요", text: f.whyItMatters ?? "" },
    { key: "fix", label: "이렇게 바꿔 주세요", text: f.remediation ?? "" },
  ];
  const out: typeof candidates = [];
  for (const c of candidates) {
    if (!c.text.trim()) continue;
    if (out.some((prev) => sameText(prev.text, c.text))) continue;
    out.push(c);
  }
  return out;
}

/**
 * 카드 하나 = 같은 취약점 묶음 하나. 한 곳에서만 발견됐으면 예전과 같은 모양이고,
 * 여러 곳이면 제목·설명은 한 번만, 위치 목록과 상태 내역을 보여 주고
 * 위치별 수정·재검증 결과는 "자세히 보기" 안에 위치 이름을 붙여 둔다.
 */
function FindingRow({ group, members }: { group: FindingGroup<FindingView>; members: MemberState[] }) {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const single = members.length === 1;
  const rep = members.find((m) => m.finding.id === group.representative.id) ?? members[0];
  const finding = rep.finding;
  const agg = single ? undefined : aggregateStatus(members.map((m) => m.status.key));
  const statusKey = agg ? agg.key : rep.status.key;
  const statusLabel = agg ? agg.label : rep.status.label;
  const statusNote = agg ? members.find((m) => m.status.key === statusKey)?.status.note : rep.status.note;
  const any = (p: (f: FindingView) => boolean) => members.some((m) => p(m.finding));
  const adjudication = finding.aiReview?.adjudication;
  const blocks = explanationBlocks(finding);
  const corroborators = [...new Set(members.flatMap((m) => m.finding.corroboratedBy ?? []))].filter((c) => c !== "ai");
  return (
    <div className="relative min-w-0 overflow-hidden rounded-3xl border-2 border-line bg-surface p-5 pl-6 shadow-warm sm:p-6 sm:pl-7">
      {/* 심각도 색 띠(장식). 심각도는 배지의 글자·아이콘으로도 전달한다 */}
      <span aria-hidden="true" className={`absolute inset-y-0 left-0 w-1.5 ${SEV_ACCENT[group.severity] ?? "bg-line-strong"}`} />
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={STATUS_TONE[statusKey]}>
          <span aria-hidden="true">{FIX_STATUS_MARK[statusKey]}</span>
          {statusLabel}
        </Badge>
        <SeverityBadge severity={group.severity} />
        {any((f) => f.isAi) && <Badge tone="neutral">AI 분석</Badge>}
        {any((f) => f.aiReview?.verdict === "confirmed") && <Badge tone="neutral">AI도 확인</Badge>}
        {any((f) => f.aiReview?.verdict === "likely_false_positive" && !f.aiReview?.adjudication) && (
          <Badge tone="neutral">AI: 오탐 가능성</Badge>
        )}
        {corroborators.map((c) => (
          <Badge key={c} tone="neutral">
            {CORROBORATOR_LABEL[c] ?? `${c}도 확인`}
          </Badge>
        ))}
        {any((f) => Boolean(f.carriedOver)) && <Badge tone="neutral">이전 점검에서 이어옴</Badge>}
      </div>
      {agg?.breakdown && (
        <p className="mt-2 break-words text-sm font-bold leading-relaxed text-ink">
          <span className="sr-only">위치별 상태: </span>
          {agg.breakdown}
        </p>
      )}
      {statusNote && <p className="mt-2 break-words text-sm font-semibold leading-relaxed text-ink">{statusNote}</p>}
      <h3 className="mt-3 break-words text-lg font-extrabold text-ink sm:text-xl">{finding.title}</h3>
      {!single && (
        <>
          <p className="mt-1 text-base font-semibold leading-relaxed text-ink-subtle">같은 문제가 {members.length}곳에서 발견됐어요</p>
          <FindingLocations locations={group.locations} className="mt-3" />
        </>
      )}

      <div className="mt-4 space-y-4">
        {blocks.map((b) => (
          <div key={b.key} className={b.key === "fix" ? "rounded-2xl border-2 border-line bg-surface-warm p-4" : undefined}>
            <h4 className="text-sm font-bold text-brand-800">{b.label}</h4>
            <p className="mt-1 whitespace-pre-line break-words text-base leading-relaxed text-ink">{b.text}</p>
          </div>
        ))}
      </div>

      {single && adjudication && <AdjudicationNote adjudication={adjudication} />}

      {single && (rep.hasJobItem || rep.verifyItem) && <FixOutcome {...outcomeProps(rep)} />}

      <button
        type="button"
        className="mt-4 inline-flex min-h-11 items-center gap-2 rounded-full border-2 border-line bg-surface-warm px-4 text-sm font-bold text-brand-800 hover:border-brand-300"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((v) => !v)}
      >
        {open ? "접기" : single ? "자세히 보기 (코드·기술 정보)" : "자세히 보기 (위치별 코드·수정 결과)"}
        <span aria-hidden="true" className={`transition-transform motion-reduce:transition-none ${open ? "rotate-180" : ""}`}>
          ▾
        </span>
      </button>
      <div
        id={panelId}
        hidden={!open}
        className="mt-3 min-w-0 space-y-3 rounded-2xl border-2 border-dashed border-line bg-surface-warm p-4 text-sm leading-relaxed text-ink-subtle"
      >
        {single ? (
          <MemberTech finding={finding} />
        ) : (
          <ol className="space-y-4">
            {members.map((m) => {
              const where = m.finding.location ? formatLocation(m.finding.location) : "위치 기록 없음";
              const adj = m.finding.aiReview?.adjudication;
              return (
                <li key={m.finding.id} className="min-w-0 rounded-2xl border-2 border-line bg-surface p-4">
                  <h4 className="flex flex-wrap items-center gap-2 text-sm font-bold text-ink">
                    <span className="min-w-0 break-all font-mono text-xs">{where}</span>
                    <span className="inline-flex items-center gap-1 font-semibold">
                      <span aria-hidden="true">{FIX_STATUS_MARK[m.status.key]}</span>
                      {m.status.label}
                    </span>
                  </h4>
                  <div className="mt-2 space-y-3">
                    <MemberTech finding={m.finding} hideLocation />
                    {adj && <AdjudicationNote adjudication={adj} />}
                    {(m.hasJobItem || m.verifyItem) && <FixOutcome {...outcomeProps(m)} label={`${where} 수정과 재검증 결과`} />}
                  </div>
                </li>
              );
            })}
          </ol>
        )}
      </div>
    </div>
  );
}

function outcomeProps(m: MemberState) {
  return { status: m.status, steps: m.steps, applied: m.applied, fixNote: m.fixNote, edits: m.edits, verifyItem: m.verifyItem };
}

/** 한 위치의 코드·AI 의견·기술 정보. */
function MemberTech({ finding, hideLocation = false }: { finding: FindingView; hideLocation?: boolean }) {
  const adjudication = finding.aiReview?.adjudication;
  return (
    <>
      {finding.code ? (
        <CodeView code={finding.code} caption="문제가 된 코드" />
      ) : finding.location && !hideLocation ? (
        <p className="break-all font-mono text-xs text-ink">
          {finding.location.file}:{finding.location.line}
        </p>
      ) : null}
      {finding.aiReview?.verdict === "likely_false_positive" && !adjudication && (
        <p className="break-words text-base text-ink">
          <span className="block text-sm font-bold text-ink">AI 의견</span>
          규칙이 찾은 항목이지만 AI는 실제 문제가 아닐 수 있다고 봤어요
          {finding.aiReview.reason ? ` (${finding.aiReview.reason})` : ""}. 규칙 결과는 그대로 두었으니 코드를 보고 판단해 주세요.
        </p>
      )}
      <dl className="grid gap-2 sm:grid-cols-2">
        <TechRow label="규칙 ID" value={finding.ruleId} />
        <TechRow label="CWE" value={finding.cwe} />
        <TechRow label="OWASP" value={finding.owasp} />
        <TechRow label="위치" value={finding.location ? `${finding.location.file}:${finding.location.line}` : undefined} />
      </dl>
    </>
  );
}

function TechRow({ label, value }: { label: string; value?: string }) {
  return (
    <div className="min-w-0">
      <dt className="font-bold text-ink-subtle">{label}</dt>
      <dd className="mt-0.5 break-all font-mono text-xs text-ink">{value || "기록 없음"}</dd>
    </div>
  );
}

function OutcomePart({ title, mark, children }: { title: string; mark: string; children: ReactNode }) {
  return (
    <div className="mt-4 min-w-0">
      <h5 className="flex items-center gap-1.5 text-sm font-bold text-ink">
        <span aria-hidden="true" className="inline-block w-4 text-center">
          {mark}
        </span>
        {title}
      </h5>
      <div className="mt-1 break-words text-base leading-relaxed text-ink">{children}</div>
    </div>
  );
}

function pendingTitle(status: FixStatus): string {
  if (status.key === "not_fixed") return "고치지 못한 이유와 할 일";
  if (status.key === "fixing") return "진행 상황";
  return "아직 확인이 필요한 것";
}

/**
 * 항목별 수정·재검증 결과. 세 단계(수정안 만들기 → 파일에 적용 → 재검증)와
 * "무엇을 바꿨나요 / 확인된 것 / 아직 확인이 필요한 것"을 나눠 보여 준다.
 */
function FixOutcome({
  status,
  steps,
  applied,
  fixNote,
  edits,
  verifyItem,
  label = "수정과 재검증 결과",
}: {
  status: FixStatus;
  steps?: FixStep[];
  applied: boolean;
  fixNote?: string;
  edits?: { file: string; before: string; after: string }[];
  verifyItem?: NonNullable<PublicFixJob["verification"]>["items"][number];
  /** 묶음 카드 안에서는 위치를 붙여 구분한다. */
  label?: string;
}) {
  const showChanges = Boolean(steps) && status.key !== "fixing" && status.key !== "false_positive";
  return (
    <section aria-label={label} className="mt-5 min-w-0 rounded-2xl border-2 border-line bg-surface-warm p-4">
      <h4 className="text-base font-extrabold text-ink">수정과 재검증 결과</h4>
      {steps && (
        <ol className="mt-2 flex flex-col gap-1 text-sm text-ink sm:flex-row sm:flex-wrap sm:gap-x-5">
          {steps.map((s) => (
            <li key={s.id} className="flex items-center gap-1.5">
              <span aria-hidden="true" className="inline-block w-4 text-center font-extrabold">
                {FIX_STEP_MARK[s.state]}
              </span>
              <span className="font-bold">{s.label}</span>
              <span>: {s.text}</span>
            </li>
          ))}
        </ol>
      )}

      {showChanges && (
        <OutcomePart title="무엇을 바꿨나요" mark="✎">
          {applied ? (
            <>
              <p>{fixNote || "수정 내용을 고친 사본 파일에 적용했어요."}</p>
              {edits && edits.length > 0 && <EditDiff edits={edits} />}
            </>
          ) : (
            <p>이 항목 때문에 바뀐 파일은 없어요.</p>
          )}
        </OutcomePart>
      )}

      {status.confirmed && (
        <OutcomePart title="확인된 것" mark={FIX_STATUS_MARK[status.key]}>
          <p>{status.confirmed}</p>
        </OutcomePart>
      )}

      {status.pending && (
        <OutcomePart title={pendingTitle(status)} mark="?">
          <p>{status.pending}</p>
        </OutcomePart>
      )}

      {verifyItem && <VerifyNote item={verifyItem} shownText={status.detail} />}
    </section>
  );
}

function FixResult({
  job,
  findings,
  busy,
  onVerify,
}: {
  job: PublicFixJob;
  findings: FindingView[];
  busy: "fix" | "verify" | null;
  onVerify: () => void;
}) {
  const failedItems = job.items.filter((it) => it.outcome !== "applied");
  // 고치지 못한 항목도 같은 취약점끼리 묶어 제목은 한 번, 위치는 목록으로 보여 준다.
  const findingById = new Map(findings.map((f) => [f.id, f]));
  const failedGroups = groupFindings(
    failedItems.map((it) => {
      const f = findingById.get(it.findingId);
      return {
        id: it.findingId,
        title: f?.title ?? it.title,
        severity: f?.severity ?? it.severity,
        ruleId: f ? f.ruleId : it.ruleId,
        cwe: f?.cwe,
        location: f?.location,
        reason: it.reason,
      };
    })
  );
  const appliedItems = job.items.filter((it) => it.outcome === "applied");
  const v = job.verification;
  const vCounts = { resolved: 0, executed: 0, resolvedAi: 0, still: 0, falsePositive: 0, disputed: 0, check: 0 };
  if (v && v.status !== "running") {
    for (const it of v.items) {
      if (it.reasonCode === "disputed") vCounts.disputed += 1;
      else if (it.verdict === "fixed_in_source" && it.method === "llm" && !it.executed) vCounts.resolvedAi += 1;
      else if (it.verdict === "fixed_in_source") {
        vCounts.resolved += 1;
        if (it.executed) vCounts.executed += 1;
      } else if (it.verdict === "still_present") vCounts.still += 1;
      else if (it.verdict === "false_positive") vCounts.falsePositive += 1;
      else vCounts.check += 1;
    }
  }
  // 규칙 재검사(또는 실행 테스트)로 확인한 해결만 있고, 남아 있음·엇갈림·확인 필요·AI 판단·오탐이 하나도 없을 때만 축하한다.
  const allBlocked =
    job.status === "completed" &&
    !!v &&
    v.status === "completed" &&
    vCounts.resolved > 0 &&
    vCounts.resolvedAi + vCounts.still + vCounts.falsePositive + vCounts.disputed + vCounts.check === 0;
  const codeOnly = vCounts.resolved - vCounts.executed;

  const confirmedLines: { mark: string; text: string }[] = [];
  if (vCounts.resolved > 0) {
    const how =
      vCounts.executed === 0
        ? "코드 기준"
        : codeOnly === 0
          ? "공격 재현 테스트 실행"
          : `코드 기준 ${codeOnly}개, 공격 재현 테스트 실행 ${vCounts.executed}개`;
    confirmedLines.push({ mark: "✓", text: `해결 확인 ${vCounts.resolved}개 (${how})` });
  }
  if (vCounts.resolvedAi > 0) confirmedLines.push({ mark: "✓", text: `AI가 코드를 읽고 해결로 판단 ${vCounts.resolvedAi}개` });
  if (vCounts.still > 0) confirmedLines.push({ mark: "✕", text: `같은 문제가 아직 남아 있음 ${vCounts.still}개` });
  if (vCounts.falsePositive > 0) confirmedLines.push({ mark: "−", text: `AI가 오탐으로 판정 ${vCounts.falsePositive}개` });

  const pendingLines: { mark: string; text: string }[] = [];
  if (vCounts.disputed > 0) pendingLines.push({ mark: "?", text: `규칙 재검사와 AI 판단이 엇갈림 ${vCounts.disputed}개. 해당 항목의 바뀐 코드를 직접 확인해 주세요.` });
  if (vCounts.check > 0) pendingLines.push({ mark: "?", text: `고쳐졌는지 결론을 내리지 못함 ${vCounts.check}개. 항목마다 무엇을 확인하지 못했는지 아래에 적어 두었어요.` });
  if (v?.errorMessage) pendingLines.push({ mark: "?", text: v.errorMessage });
  else if (v?.status === "failed")
    pendingLines.push({ mark: "?", text: `재검증을 끝내지 못해 고친 항목이 해결됐는지 아직 확인하지 못했어요. 잠시 후 ‘${REVERIFY_BUTTON_LABEL}’를 눌러 주세요.` });
  if (v?.aiStatus === "not_available")
    pendingLines.push({ mark: "?", text: "AI 재검토가 설정되어 있지 않아, 규칙으로 다시 검사할 수 없는 항목은 확인하지 못했어요." });
  if (v && v.omittedFiles.length > 0)
    pendingLines.push({
      mark: "?",
      text: `파일 ${v.omittedFiles.length}개는 한 번에 검토할 수 있는 양을 넘어 AI 재검토에 보내지 못했어요. 그 파일의 바뀐 부분은 직접 확인해 주세요.`,
    });
  if (vCounts.resolved + vCounts.resolvedAi > 0)
    pendingLines.push({
      mark: "?",
      text:
        vCounts.executed > 0
          ? "공격 재현 테스트는 격리된 환경에서 실행했고, 나머지는 수정본 코드를 읽고 확인했어요. 배포한 사이트에서는 받은 파일로 다시 배포한 뒤 한 번 더 점검해 주세요."
          : "수정본 코드를 읽고 확인한 결과예요. 배포한 사이트에서 실행해 본 결과는 아니에요. 받은 파일로 다시 배포한 뒤 한 번 더 점검해 주세요.",
    });

  const headline =
    job.status === "completed"
      ? `${appliedItems.length}개 항목에 수정 내용을 적용했어요`
      : job.status === "partial"
        ? `${job.items.length}개 중 ${appliedItems.length}개 항목에 수정 내용을 적용했어요`
        : "수정 내용을 파일에 적용하지 못했어요";

  return (
    <section aria-labelledby="fix-result-title" className="mt-6">
      <Card variant={job.status === "failed" ? "danger" : "raised"} className="min-w-0 p-5 sm:p-6">
        <h2 id="fix-result-title" className="break-words text-xl font-extrabold text-ink">
          <span aria-hidden="true" className="mr-1.5">
            {job.status === "failed" ? "✕" : "✓"}
          </span>
          {headline}
        </h2>
        {job.status === "failed" && (
          <p className="mt-2 break-words text-base leading-relaxed text-ink">
            {job.errorMessage ?? "파일은 바뀌지 않았어요. 아래 항목마다 적힌 이유를 확인한 뒤 다시 시도해 주세요."}
          </p>
        )}
        {job.status !== "failed" && !v && (
          <p className="mt-2 text-base leading-relaxed text-ink">
            고친 사본 파일에 적용까지 했어요. 문제가 해결됐는지는 아직 확인하지 않았어요. 아래 ‘{VERIFY_BUTTON_LABEL}’로 재검증해 주세요.
          </p>
        )}
        {job.status !== "failed" && v && (
          <p className="mt-2 text-base leading-relaxed text-ink">재검증 결과는 아래에 따로 정리했어요.</p>
        )}

        {job.changedFiles.length > 0 && (
          <div className="mt-5">
            <h3 className="text-base font-bold text-ink">무엇을 바꿨나요</h3>
            <p className="mt-1 text-base leading-relaxed text-ink">
              파일 {job.changedFiles.length}개를 고쳤어요. 올린 원본은 그대로 두고 고친 사본에만 적용했어요.
            </p>
            <ul className="mt-2 space-y-1">
              {job.changedFiles.map((p) => (
                <li key={p} className="break-all font-mono text-sm text-ink">
                  {p}
                </li>
              ))}
            </ul>
          </div>
        )}

        {job.changedFiles.length > 0 && <JobDiff jobId={job.id} />}

        {job.requiredEnv.length > 0 && (
          <div className="mt-4 rounded-2xl border-2 border-[#f0d9a6] bg-warning-soft p-4 text-base leading-relaxed">
            <h3 className="font-bold text-warning">받은 파일을 반영하기 전에 설정할 환경변수 ({job.requiredEnv.length}개)</h3>
            <p className="mt-1 text-ink">설정하지 않으면 해당 기능이 안전하게 멈추도록(요청 거절) 고쳐져 있어요.</p>
            <ul className="mt-2 space-y-2">
              {job.requiredEnv.map((e) => (
                <li key={e.name} className="min-w-0 break-words">
                  <span className="break-all font-mono font-bold text-ink">{e.name}</span>
                  <span className="ml-1 break-all text-xs text-ink-muted">({e.files.join(", ")})</span>
                  <span className="block text-ink">{e.guidance}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {failedItems.length > 0 && (
          <div className="mt-5">
            <h3 className="text-base font-bold text-ink">
              자동으로 고치지 못한 항목 ({countText(failedGroups.length, failedItems.length)})
            </h3>
            <p className="mt-1 text-sm leading-relaxed text-ink-subtle">이 항목들은 파일이 바뀌지 않았어요. 이유와 해야 할 일을 확인해 주세요.</p>
            <ul className="mt-2 space-y-2">
              {failedGroups.map((g) => {
                const reasons = [...new Set(g.members.map((m) => m.reason).filter((r): r is string => Boolean(r)))];
                return (
                  <li key={g.key} className="min-w-0 rounded-2xl border-2 border-line bg-surface p-3">
                    <span className="flex items-start gap-1.5 break-words font-bold text-ink">
                      <span aria-hidden="true">✕</span>
                      <span className="min-w-0">{g.representative.title}</span>
                    </span>
                    {g.members.length > 1 && (
                      <>
                        <span className="mt-1 block text-sm font-semibold text-ink-subtle">같은 문제가 {g.members.length}곳에 있어요</span>
                        <FindingLocations locations={g.locations} className="mt-2" />
                      </>
                    )}
                    {reasons.length === 1 && <span className="mt-1 block break-words text-base leading-relaxed text-ink">{reasons[0]}</span>}
                    {reasons.length > 1 && (
                      <ul className="mt-1 space-y-1">
                        {g.members
                          .filter((m) => m.reason)
                          .map((m) => (
                            <li key={m.id} className="min-w-0 break-words text-base leading-relaxed text-ink">
                              <span className="break-all font-mono text-xs font-bold">{m.location ? formatLocation(m.location) : "위치 기록 없음"}</span>{" "}
                              {m.reason}
                            </li>
                          ))}
                      </ul>
                    )}
                  </li>
                );
              })}
            </ul>
          </div>
        )}

        {job.artifact && (
          <div className="mt-5 flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
            <a href={job.artifact.downloadPath} download={job.artifact.fileName} className={buttonClassName({ variant: "secondary" })}>
              고친 파일 내려받기
              <span className="text-[13px] font-medium text-ink-subtle">({formatBytes(job.artifact.size)})</span>
            </a>
            <Button onClick={onVerify} disabled={busy !== null} aria-busy={busy === "verify"}>
              {v ? REVERIFY_BUTTON_LABEL : VERIFY_BUTTON_LABEL}
            </Button>
          </div>
        )}
        {job.artifact && (
          <>
            <p className="mt-4 rounded-2xl border-2 border-[#c9def3] bg-info-soft p-3 text-base font-semibold leading-relaxed text-info">{GUIDANCE}</p>
            <p className="mt-2 break-all text-xs text-ink-muted">
              파일 확인값(SHA-256): <span className="font-mono">{job.artifact.sha256}</span>
            </p>
          </>
        )}
      </Card>

      {v && v.status !== "running" && (
        <Card
          variant={v.status === "failed" ? "danger" : allBlocked ? "warm" : "default"}
          className={`relative mt-4 min-w-0 overflow-hidden p-5 sm:p-6 ${allBlocked ? "!border-[#bfe0c8]" : ""}`}
          aria-live="polite"
        >
          {allBlocked && <Confetti />}
          <div className="flex items-center gap-4">
            {allBlocked && <Hoi mood="celebrate" size="md" decorative className="shrink-0" />}
            <h2 className="break-words text-xl font-extrabold text-ink">
              {v.status === "failed"
                ? "재검증을 끝내지 못했어요"
                : allBlocked
                  ? "다시 확인한 항목에서 같은 문제가 보이지 않았어요"
                  : vCounts.still > 0
                    ? "아직 남아 있는 문제가 있어요"
                    : "재검증 결과"}
            </h2>
          </div>

          <div className="mt-4 grid gap-4 sm:grid-cols-2">
            <div className="min-w-0">
              <h3 className="text-base font-bold text-ink">확인된 것</h3>
              {confirmedLines.length > 0 ? (
                <ul className="mt-1 space-y-1 text-base leading-relaxed text-ink">
                  {confirmedLines.map((l) => (
                    <li key={l.text} className="flex items-start gap-1.5 break-words">
                      <span aria-hidden="true" className="inline-block w-4 shrink-0 text-center font-extrabold">
                        {l.mark}
                      </span>
                      <span className="min-w-0">{l.text}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-1 text-base leading-relaxed text-ink">아직 결론이 난 항목이 없어요.</p>
              )}
            </div>
            <div className="min-w-0">
              <h3 className="text-base font-bold text-ink">아직 확인이 필요한 것</h3>
              {pendingLines.length > 0 ? (
                <ul className="mt-1 space-y-1 text-base leading-relaxed text-ink">
                  {pendingLines.map((l) => (
                    <li key={l.text} className="flex items-start gap-1.5 break-words">
                      <span aria-hidden="true" className="inline-block w-4 shrink-0 text-center font-extrabold">
                        {l.mark}
                      </span>
                      <span className="min-w-0">{l.text}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-1 text-base leading-relaxed text-ink">따로 적어 둘 내용이 없어요. 항목별 결과는 아래 목록에서 볼 수 있어요.</p>
              )}
            </div>
          </div>
          <p className="mt-4 text-sm leading-relaxed text-ink-subtle">
            항목별로 무엇을 확인했는지는 아래 목록의 ‘수정과 재검증 결과’에서 볼 수 있어요. 규칙 재검사가 기준이고, AI 판단은 규칙으로 볼 수 없는 항목을 판단하거나 규칙 결과를 교차 확인할 때 써요. 둘이 다르면 &ldquo;판단이 엇갈려요&rdquo;로 표시해요.
          </p>
        </Card>
      )}
    </section>
  );
}
