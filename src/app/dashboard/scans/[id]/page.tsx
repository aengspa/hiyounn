import { notFound } from "next/navigation";
import { PageHeader } from "@/components/PageHeader";
import { HoiScene } from "@/components/mascot/HoiScene";
import { Hoi } from "@/components/mascot/Hoi";
import { requirePageUserId } from "@/lib/auth";
import {
  getScan,
  getProject,
  getFindingsForScan,
  getSourceVersion,
  listCustomRules,
  listFixJobsForScan,
  NotFoundError,
  NotAuthorizedError,
} from "@/lib/store/store";
import { Card, TechnicalDetails, categoryLabel, tierLabel } from "@/components/ui";
import type { AiScanCoverage, RouteAuthzEntry, ScanPlan, ScanScope } from "@/lib/domain/types";
import { sortBySeverity } from "@/lib/ui/presentation";
import { FixAllPanel, type FindingView } from "@/components/FixAllPanel";
import { RuleProposals } from "@/components/RuleProposals";
import { toPublicJob } from "@/lib/fixjobs/publicJob";
import { isStale } from "@/lib/fixjobs/fixAllService";
import { LIMITS } from "@/lib/config/limits";
import { codeContextFor, secretValues } from "@/lib/ui/codeContext";
import { formatKstDateTime } from "@/lib/time";

export const dynamic = "force-dynamic";

/**
 * 점검 보고서.
 *   제목 → "확인할 부분 N개를 찾았어요" → 맨 위 "전체 수정하기" → 항목 목록.
 *   항목마다 "어떤 일이 생길 수 있나요 / 왜 이렇게 판단했나요 / 이렇게 바꿔 주세요"를 나눠 보여 주고,
 *   코드·경로·규칙 ID·CWE/OWASP는 "자세히 보기" 안에 둔다.
 *   수정 후에는 요약·바뀐 파일·실패 항목·다운로드·재검증을 보여 주고, 항목마다
 *   "무엇을 바꿨나요 / 확인된 것 / 아직 확인이 필요한 것"을 나눈다.
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
          ? { ...latest, status: "failed", errorCode: "timeout", errorMessage: "수정 작업이 제한 시간 안에 끝나지 않았어요. 올린 원본 코드는 그대로예요. 다시 시도해 주세요." }
          : latest
      )
    : undefined;

  // 점검한 그 버전의 코드로 문제가 된 줄을 보여 준다(비밀값은 가림).
  const scanned = scan.sourceVersionId ? await getSourceVersion(scan.sourceVersionId, uid).catch(() => undefined) : undefined;
  const secrets = scanned ? secretValues(scanned.files) : [];

  const views: FindingView[] = findings.map((f) => ({
    id: f.id,
    title: f.title,
    severity: f.severity,
    humanReadableImpact: f.humanReadableImpact,
    whyItMatters: f.whyItMatters,
    remediation: f.remediation,
    location: f.location,
    ruleId: f.ruleId,
    cwe: f.cwe,
    owasp: f.owasp,
    isAi: Boolean(f.verificationKey?.startsWith("ai:") || f.category === "AI Detected"),
    aiReview: f.aiReview,
    code: scanned ? codeContextFor(f, scanned.files, secrets) : undefined,
    corroboratedBy: f.corroboratedBy,
    carriedOver: Boolean(f.carriedOverFromScanId),
  }));
  const proposals = (await listCustomRules(uid, scan.projectId).catch(() => [])).filter((r) => r.sourceScanId === scan.id);
  const falsePositiveCount = views.filter((v) => v.aiReview?.adjudication?.verdict === "not_vulnerable").length;
  const activeCount = views.length - falsePositiveCount;

  const projectHref = `/dashboard/projects/${scan.projectId}`;
  const scannedAt = formatKstDateTime(scan.completedAt ?? scan.startedAt);

  return (
    <>
      <PageHeader title={`${project.name} 점검 결과`} backHref={projectHref} backLabel="이전" />
      <div className="mx-auto max-w-4xl px-4 py-7 sm:px-6 sm:py-10">
        <section aria-labelledby="report-title">
          <div className="flex items-center gap-4">
            <Hoi mood={activeCount > 0 ? "concerned" : "cheer"} size="md" decorative className="hidden sm:block" />
            <div className="min-w-0">
              <p className="inline-flex rounded-full border-2 border-line bg-surface px-3 py-0.5 text-[13px] font-bold text-ink-subtle">
                {scannedAt} 점검
              </p>
              <h2 id="report-title" className="mt-2 text-2xl font-extrabold tracking-tight text-ink sm:text-3xl">
                {activeCount > 0
                  ? `확인할 부분 ${activeCount}개를 찾았어요`
                  : "이번 범위에서 확인할 부분을 찾지 못했어요"}
              </h2>
            </div>
          </div>
          {falsePositiveCount > 0 && (
            <p className="mt-2 text-base leading-relaxed text-ink-subtle">
              규칙 결과 중 {falsePositiveCount}개는 AI가 코드 근거를 확인해 오탐으로 판정해서 아래에 따로 모았어요.
            </p>
          )}
          {scan.scope.aiCoverage && <AiCoverageNotice coverage={scan.scope.aiCoverage} />}
          {scan.scope.semgrep && <SemgrepNotice semgrep={scan.scope.semgrep} />}
          {scan.scope.incremental && (
            <p className="mt-2 text-base leading-relaxed text-ink-subtle">
              새로 올린 코드에서 바뀐 파일 {scan.scope.incremental.changedFiles.length}개만 AI가 새로 봤어요. 바뀌지 않은 파일{" "}
              {scan.scope.incremental.unchangedFiles}개는 규칙으로 다시 점검했고, 이전 AI 결과 {scan.scope.incremental.carriedOver}건은
              “이전 점검에서 이어옴”으로 표시했어요.
            </p>
          )}
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

        {scan.scope.authzMatrix && scan.scope.authzMatrix.length > 0 && <AuthzTable rows={scan.scope.authzMatrix} />}
        {proposals.length > 0 && <RuleProposals rules={proposals} />}

        <section className="mt-12" aria-labelledby="coverage-title">
          <h2 id="coverage-title" className="sr-only">점검 범위와 한계</h2>
          <TechnicalDetails summary="점검 범위와 한계 보기 (전문가용 정보)">
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

const CELL: Record<string, { text: string; tone: string }> = {
  required: { text: "확인함", tone: "text-success" },
  checked: { text: "확인함", tone: "text-success" },
  none: { text: "없음", tone: "font-bold text-danger" },
  missing: { text: "없음", tone: "font-bold text-danger" },
  "n/a": { text: "—", tone: "text-ink-muted" },
  public: { text: "공개(의도)", tone: "text-ink-subtle" },
  unknown: { text: "모름", tone: "text-warning" },
};

/**
 * 라우트별 권한 확인 표. 사실은 AI가 코드에서 뽑았고(선언 줄로 검증),
 * 빨간 칸의 문제 판단은 규칙이 했다.
 */
function AuthzTable({ rows }: { rows: RouteAuthzEntry[] }) {
  const gaps = rows.filter((r) => (r.findingIds ?? []).length > 0).length;
  return (
    <section className="mt-10" aria-labelledby="authz-title">
      <details open={gaps > 0} className="rounded-3xl border-2 border-line bg-surface p-4 shadow-warm sm:p-5">
        <summary id="authz-title" className="flex min-h-11 cursor-pointer items-center text-base font-extrabold text-ink hover:text-brand-800">
          라우트 권한 확인 표 ({rows.length}개 라우트{gaps > 0 ? `, 빈틈 ${gaps}곳` : ""})
        </summary>
        <p className="mt-2 text-sm text-ink-subtle">
          AI가 코드에서 라우트마다 로그인·관리자·소유자 확인이 있는지 뽑고(각 행은 실제 선언 줄로 확인했어요), 빨간 칸은 규칙이 빈틈으로 판단한 곳이에요.
        </p>
        <div className="mt-3 overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-sm">
            <thead className="text-xs text-ink-muted">
              <tr className="border-b border-line">
                <th className="py-2 pr-3 font-bold">라우트</th>
                <th className="py-2 pr-3 font-bold">로그인</th>
                <th className="py-2 pr-3 font-bold">관리자</th>
                <th className="py-2 pr-3 font-bold">소유자 확인</th>
                <th className="py-2 font-bold">위치</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i} className="border-b border-line align-top last:border-0">
                  <td className="py-2 pr-3 font-mono text-xs text-ink">
                    <span className="font-bold">{r.method}</span> {r.path}
                    {r.notes && <span className="mt-0.5 block font-sans text-ink-muted">{r.notes}</span>}
                  </td>
                  {[r.auth, r.admin, r.ownership].map((v, j) => (
                    <td key={j} className={`py-2 pr-3 ${CELL[v]?.tone ?? ""}`}>
                      {CELL[v]?.text ?? v}
                    </td>
                  ))}
                  <td className="py-2 font-mono text-xs text-ink-muted">
                    {r.file}:{r.line}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </section>
  );
}

function SemgrepNotice({ semgrep }: { semgrep: NonNullable<ScanScope["semgrep"]> }) {
  const text =
    semgrep.status === "ran"
      ? `추가 규칙 검사 도구(Semgrep)도 함께 돌렸어요(${semgrep.findings}건${semgrep.config ? `, ${semgrep.config}` : ""}). 같은 문제는 규칙 결과와 합쳤어요.`
      : semgrep.status === "not_installed"
        ? "추가 규칙 검사 도구(Semgrep)가 설치돼 있지 않아 그 검사는 건너뛰었어요. 나머지 규칙 검사 결과는 그대로 보여 드려요."
        : semgrep.status === "failed"
          ? "추가 규칙 검사 도구(Semgrep)가 검사를 끝내지 못해 그 결과는 빠져 있어요. 나머지 규칙 검사 결과는 그대로 보여 드려요."
          : "추가 규칙 검사 도구(Semgrep)는 이번에 건너뛰었어요.";
  return (
    <div className={`mt-2 break-words text-base leading-relaxed ${semgrep.status === "failed" ? "text-warning" : "text-ink-subtle"}`}>
      <p>{text}</p>
      {semgrep.status === "failed" && semgrep.detail && (
        <details className="mt-1 text-sm text-ink-subtle">
          <summary className="flex min-h-11 cursor-pointer items-center font-bold text-brand-800">오류 내용 보기 (기술 정보)</summary>
          <p className="break-all font-mono text-xs">{semgrep.detail}</p>
        </details>
      )}
    </div>
  );
}

const OMIT_REASON: Record<AiScanCoverage["omitted"][number]["reason"], string> = {
  too_large: "너무 긴 파일",
  over_budget: "한 번에 볼 수 있는 양을 넘은 파일",
  time_budget: "시간이 모자라 보지 못한 파일",
  call_failed: "AI 응답을 받지 못한 파일",
  ai_unavailable: "AI 설정 문제로 보지 못한 파일",
};

/**
 * AI 분석이 실제로 어디까지 봤는지 제목 바로 아래에 알린다. AI가 일부만 봤는데
 * 발견 수만 보이면, 적게 찾은 결과가 "문제가 적다"로 읽히기 때문이다.
 */
function AiCoverageNotice({ coverage }: { coverage: AiScanCoverage }) {
  if (coverage.status === "off") {
    return (
      <p className="mt-2 text-base font-semibold leading-relaxed text-ink">
        AI 분석이 꺼져 있어 규칙 기반 점검만 했어요. 다른 사람의 정보를 볼 수 있는지 같은 흐름 문제(권한 확인 누락)는 규칙만으로는 잘 잡히지 않아요.
      </p>
    );
  }
  if (coverage.status === "complete") {
    return (
      <p className="mt-2 text-base leading-relaxed text-ink-subtle">
        규칙 기반 점검과 함께 AI가 코드 파일 {coverage.filesTotal}개를 모두 살펴봤어요.
        {coverage.mergedWithRules > 0 && ` 같은 문제를 가리킨 규칙·AI 결과 ${coverage.mergedWithRules}건은 하나로 합쳤어요.`}
      </p>
    );
  }
  const counts = new Map<string, number>();
  for (const o of coverage.omitted) counts.set(o.reason, (counts.get(o.reason) ?? 0) + 1);
  const reasons = [...counts.entries()]
    .map(([reason, n]) => `${OMIT_REASON[reason as keyof typeof OMIT_REASON] ?? reason} ${n}개`)
    .join(", ");
  const retryable = coverage.omitted.some((o) => o.reason === "time_budget" || o.reason === "call_failed");
  return (
    <Card variant={coverage.status === "failed" ? "danger" : "warm"} className="mt-4 p-4 text-base leading-relaxed">
      <p className="font-bold text-ink">
        {coverage.status === "failed"
          ? "AI 분석을 하지 못해 규칙 기반 결과만 보여 드려요"
          : `AI는 코드 파일 ${coverage.filesTotal}개 중 ${coverage.filesReviewed}개만 살펴봤어요`}
      </p>
      {reasons && <p className="mt-1 text-ink-subtle">보지 못한 이유: {reasons}.</p>}
      <p className="mt-1 text-ink">
        AI가 보지 못한 파일의 문제는 이 목록에 없을 수 있어요.
        {retryable && " 다시 점검하면 이어서 확인할 수 있어요."}
      </p>
    </Card>
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
      <p className="mt-6 rounded-2xl border-2 border-[#f0d9a6] bg-warning-soft p-4 text-sm leading-relaxed text-warning">
        자동 점검은 모든 문제를 찾지 못해요. 이 결과는 점검한 시점의 코드와 실행한 항목에만 해당하며, 발견이 없어도 모든 위험을 찾았다는 뜻은 아니에요.
      </p>
      <dl className="mt-5 grid gap-3 text-sm sm:grid-cols-2">
        <ScopeRow label="점검 시각" value={`${formatKstDateTime(scope.scanDate)} (KST)`} />
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
        <div className="mt-3 overflow-x-auto rounded-2xl border-2 border-line bg-surface">
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
