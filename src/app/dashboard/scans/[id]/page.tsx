import { notFound } from "next/navigation";
import { PageHeader } from "@/components/PageHeader";
import { HoiScene } from "@/components/mascot/HoiScene";
import { requirePageUserId } from "@/lib/auth";
import {
  getScan,
  getProject,
  getFindingsForScan,
  listFixJobsForScan,
  NotFoundError,
  NotAuthorizedError,
} from "@/lib/store/store";
import { Card, TechnicalDetails, categoryLabel, tierLabel } from "@/components/ui";
import type { ScanPlan, ScanScope } from "@/lib/domain/types";
import { sortBySeverity } from "@/lib/ui/presentation";
import { FixAllPanel, type FindingView } from "@/components/FixAllPanel";
import { toPublicJob } from "@/lib/fixjobs/publicJob";
import { isStale } from "@/lib/fixjobs/fixAllService";
import { LIMITS } from "@/lib/config/limits";

export const dynamic = "force-dynamic";

/**
 * 점검 보고서.
 *   제목 → "확인할 부분 N개를 찾았어요" → 맨 위 "전체 수정하기" → 항목 목록.
 *   항목의 "더보기"는 설명만 펼친다(항목별 단계 UI 없음).
 *   수정 후에는 요약·바뀐 파일·실패 항목·다운로드·재검증을 보여 준다.
 */
export default async function ScanResultsPage({ params }: { params: { id: string } }) {
  const uid = await requirePageUserId(`/dashboard/scans/${params.id}`);
  let scan;
  try {
    scan = await getScan(params.id, uid);
  } catch (e) {
    if (e instanceof NotFoundError || e instanceof NotAuthorizedError) notFound();
    throw e;
  }
  const project = await getProject(scan.projectId, uid);
  const findings = sortBySeverity(await getFindingsForScan(scan.id, uid));
  const jobs = await listFixJobsForScan(scan.id, uid);
  // 가장 최근 작업. 오래 멈춘 실행 중 작업은 화면에서도 실패로 보여 준다.
  const latest = jobs[0];
  const initialJob = latest
    ? toPublicJob(
        isStale(latest, Date.now(), LIMITS.staleJobMs)
          ? { ...latest, status: "failed", errorCode: "timeout", errorMessage: "수정 작업이 제한 시간 안에 끝나지 않았어요. 다시 시도해 주세요." }
          : latest
      )
    : undefined;

  const views: FindingView[] = findings.map((f) => ({
    id: f.id,
    title: f.title,
    severity: f.severity,
    humanReadableImpact: f.humanReadableImpact,
    whyItMatters: f.whyItMatters,
    remediation: f.remediation,
    location: f.location,
    isAi: Boolean(f.verificationKey?.startsWith("ai:") || f.category === "AI Detected"),
  }));

  const projectHref = `/dashboard/projects/${scan.projectId}`;
  const scannedAt = new Date(scan.completedAt ?? scan.startedAt).toLocaleString("ko-KR");

  return (
    <>
      <PageHeader title={`${project.name} 점검 결과`} backHref={projectHref} backLabel="이전" />
      <div className="mx-auto max-w-4xl px-4 py-7 sm:px-6 sm:py-10">
        <section aria-labelledby="report-title">
          <p className="text-sm text-ink-muted">{scannedAt} 점검</p>
          <h2 id="report-title" className="mt-1 text-2xl font-bold text-ink">
            {findings.length > 0
              ? `확인할 부분 ${findings.length}개를 찾았어요`
              : "이번 범위에서 확인할 부분을 찾지 못했어요"}
          </h2>
        </section>

        {findings.length === 0 ? (
          <HoiScene
            mood="rest"
            size="md"
            className="mt-6"
            title="찾은 항목이 없어요"
            description="자동 점검이 모든 문제를 찾지는 못해요. 아래 점검 범위와 한계를 확인하고, 코드가 바뀌면 다시 점검해 주세요."
          />
        ) : (
          <FixAllPanel
            scanId={scan.id}
            findings={views}
            initialJob={initialJob}
            canFix={Boolean(scan.sourceVersionId)}
          />
        )}

        <section className="mt-12" aria-labelledby="coverage-title">
          <h2 id="coverage-title" className="sr-only">점검 범위와 한계</h2>
          <TechnicalDetails summary="점검 범위와 한계 보기">
            <ScanScopePanel scope={scan.scope} />
            {scan.plan ? <PlanPanel plan={scan.plan} /> : null}
            <dl className="mt-5 grid gap-3 border-t border-line pt-5 text-sm sm:grid-cols-2">
              <ScopeRow label="점검 ID" value={scan.id} mono />
              <ScopeRow label="점검한 코드 확인값(SHA-256)" value={scan.sourceContentHash ?? "기록 없음"} mono />
            </dl>
          </TechnicalDetails>
        </section>
      </div>
    </>
  );
}

function ScanScopePanel({ scope }: { scope: ScanScope }) {
  return (
    <Card variant="warm" className="p-5">
      <div className="grid gap-6 md:grid-cols-2">
        <div>
          <h3 className="font-bold text-ink">확인한 항목</h3>
          {scope.testedCategories.length > 0 ? (
            <ul className="mt-3 space-y-2 text-sm text-ink-subtle">
              {scope.testedCategories.map((category) => <li key={category}>✓ {categoryLabel(category)}</li>)}
            </ul>
          ) : <p className="mt-3 text-sm text-ink-muted">기록된 점검 항목이 없어요.</p>}
        </div>
        <div>
          <h3 className="font-bold text-ink">확인하지 못한 항목</h3>
          {scope.untestedCategories.length > 0 ? (
            <ul className="mt-3 space-y-2 text-sm text-ink-subtle">
              {scope.untestedCategories.map((category) => <li key={category}>— {categoryLabel(category)}</li>)}
            </ul>
          ) : <p className="mt-3 text-sm text-ink-muted">별도로 기록된 미점검 분류가 없어요.</p>}
        </div>
      </div>
      <p className="mt-6 rounded-2xl border border-[#f0d9a6] bg-warning-soft p-4 text-sm leading-relaxed text-warning">
        자동 점검은 모든 문제를 찾지 못해요. 이 결과는 점검한 시점의 코드와 실행한 항목에만 해당하며, 발견이 없어도 모든 위험을 찾았다는 뜻은 아니에요.
      </p>
      <dl className="mt-5 grid gap-3 text-sm sm:grid-cols-2">
        <ScopeRow label="점검 시각" value={new Date(scope.scanDate).toLocaleString("ko-KR")} />
        <ScopeRow label="배포 주소" value={scope.deploymentUrl ?? "연결 안 됨"} />
        <ScopeRow label="스캐너 버전" value={scope.scannerVersion} mono />
        <ScopeRow label="룰셋 버전" value={scope.rulesetVersion} mono />
      </dl>
    </Card>
  );
}

function ScopeRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0 border-b border-line pb-2">
      <dt className="font-bold text-ink-muted">{label}</dt>
      <dd className={`mt-1 break-all text-ink ${mono ? "font-mono text-xs" : ""}`}>{value}</dd>
    </div>
  );
}

function PlanPanel({ plan }: { plan: ScanPlan }) {
  return (
    <div className="mt-6">
      <h3 className="font-bold text-ink">실행한 검사 ({plan.selectedChecks.length}개)</h3>
      {plan.selectedChecks.length === 0 ? (
        <p className="mt-2 text-sm text-ink-subtle">실행 가능한 검사가 없었어요.</p>
      ) : (
        <div className="mt-3 overflow-x-auto rounded-2xl border border-line">
          <table className="w-full min-w-[560px] text-left text-sm">
            <thead className="bg-surface-warm text-xs text-ink-muted">
              <tr><th className="p-3">규칙</th><th className="p-3">검사</th><th className="p-3">도구</th><th className="p-3">등급</th></tr>
            </thead>
            <tbody className="divide-y divide-line">
              {plan.selectedChecks.map((check) => (
                <tr key={`${check.ruleId}-${check.checkId}`}>
                  <td className="p-3 font-bold text-ink">{check.ruleId}</td>
                  <td className="p-3 font-mono text-xs">{check.checkId}</td>
                  <td className="p-3 font-mono text-xs">{check.toolId}</td>
                  <td className="p-3">{tierLabel(check.tier)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <h3 className="mt-6 font-bold text-ink">확인하지 못한 검사 ({plan.coverageGaps.length}개)</h3>
      {plan.coverageGaps.length === 0 ? (
        <p className="mt-2 text-sm text-ink-subtle">별도로 기록된 항목이 없어요. 그래도 모든 위험을 찾았다는 뜻은 아니에요.</p>
      ) : (
        <ul className="mt-3 space-y-2 text-sm text-ink-subtle">
          {plan.coverageGaps.map((gap, index) => (
            <li key={`${gap.ruleId}-${gap.checkId}-${index}`} className="rounded-2xl bg-warning-soft p-3">
              <span className="font-bold text-ink">{gap.ruleId}</span> · {gap.reason}
            </li>
          ))}
        </ul>
      )}
      <p className="mt-3 text-sm font-bold text-warning">확인하지 못한 항목은 “안전”이 아니라 “결론을 내리지 못함”이에요.</p>
    </div>
  );
}
