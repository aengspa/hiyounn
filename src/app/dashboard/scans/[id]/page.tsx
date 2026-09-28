import Link from "next/link";
import { notFound } from "next/navigation";
import { PageHeader } from "@/components/PageHeader";
import { HoiScene } from "@/components/mascot/HoiScene";
import { HoiSpeech } from "@/components/mascot/HoiSpeech";
import { getCurrentUserId } from "@/lib/auth";
import {
  getScan,
  getFindingsForScan,
  NotFoundError,
  NotAuthorizedError,
} from "@/lib/store/store";
import {
  AiTag,
  Badge,
  Card,
  MetricCard,
  SectionHeader,
  SeverityBadge,
  SimulatedTag,
  StatusBadge,
  TechnicalDetails,
  buttonClassName,
  categoryLabel,
  tierLabel,
} from "@/components/ui";
import type { ScanPlan, ScanScope, Severity } from "@/lib/domain/types";
import { ScanReportPanel } from "@/components/ScanReportPanel";
import {
  LIMIT_NOTICE,
  SEV_LABEL,
  primaryActionForScan,
  sortBySeverity,
  summarizeResult,
} from "@/lib/ui/presentation";

export const dynamic = "force-dynamic";

const SEVERITY_KEYS: readonly Severity[] = ["critical", "high", "medium", "low"];

export default async function ScanResultsPage({ params }: { params: { id: string } }) {
  const uid = await getCurrentUserId();
  let scan;
  try {
    scan = await getScan(params.id, uid);
  } catch (e) {
    if (e instanceof NotFoundError || e instanceof NotAuthorizedError) notFound();
    throw e;
  }

  const findings = sortBySeverity(await getFindingsForScan(params.id, uid));
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let verified = 0;
  let fixedVerified = 0;
  for (const finding of findings) {
    counts[finding.severity] += 1;
    if (finding.status === "verified" || finding.status === "resolved") verified += 1;
    if (finding.status === "resolved") fixedVerified += 1;
  }

  const summary = summarizeResult(findings);
  const primaryAction = primaryActionForScan(findings);
  const firstFixable = findings.find((finding) => finding.status !== "resolved");
  const projectHref = `/dashboard/projects/${scan.projectId}`;

  return (
    <>
      <PageHeader
        title="호이의 점검 결과"
        subtitle="쉬운 요약부터 확인하고, 필요할 때 점검 근거와 기술 정보를 펼쳐보세요."
        backHref={projectHref}
        backLabel="프로젝트"
      />
      <div className="mx-auto max-w-5xl px-4 py-7 sm:px-6 sm:py-10">
        {/* 2. 호이의 한 줄 요약: 제목 바로 아래, 모든 기술 정보보다 앞 (요구사항 8.1~8.3, 12.5) */}
        <section aria-labelledby="hoi-summary-title">
          <h2 id="hoi-summary-title" className="sr-only">호이의 한 줄 요약</h2>
          <HoiSpeech
            mood={summary.mood}
            size="md"
            footer={summary.showLimitNotice ? LIMIT_NOTICE : undefined}
          >
            {summary.message}
          </HoiSpeech>
        </section>

        {/* 3. 가장 먼저 할 일: 화면의 유일한 Primary 버튼 (요구사항 8.7) */}
        <section className="mt-7" aria-labelledby="first-action-title">
          <Card variant={counts.critical > 0 ? "danger" : "raised"} className="p-5 sm:p-6">
            <p className="text-sm font-bold text-brand-800">가장 먼저 할 일</p>
            <div className="mt-1 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 id="first-action-title" className="text-xl font-bold text-ink">
                  {primaryAction.kind === "open-finding"
                    ? "가장 급한 미해결 항목부터 살펴봐요"
                    : "코드가 바뀌면 다시 점검해 주세요"}
                </h2>
                <p className="mt-1 text-sm leading-relaxed text-ink">
                  {primaryAction.kind === "open-finding"
                    ? "내용을 읽는 것만으로 코드는 바뀌지 않아요. 해결 단계마다 직접 승인할 수 있어요."
                    : "지금 남은 미해결 항목은 없어요. 아래 점검 범위와 한계도 함께 확인해 주세요."}
                </p>
              </div>
              {primaryAction.kind === "open-finding" ? (
                <Link
                  href={`/dashboard/findings/${primaryAction.findingId}`}
                  className={buttonClassName({ variant: "primary", className: "w-full sm:w-auto" })}
                >
                  가장 급한 항목 보기
                </Link>
              ) : (
                <Link
                  href={projectHref}
                  className={buttonClassName({ variant: "primary", className: "w-full sm:w-auto" })}
                >
                  다시 점검하러 가기
                </Link>
              )}
            </div>
          </Card>
        </section>

        {/* 4. 심각도 요약: 백엔드가 기록한 실제 개수만 표시 (요구사항 8.11, 12.3) */}
        <section className="pt-10" aria-labelledby="severity-title">
          <SectionHeader
            eyebrow="우선순위"
            title={<span id="severity-title">심각도 요약</span>}
            description="숫자는 이번 점검에서 실제로 기록된 발견과 검증 상태를 기준으로 해요."
          />
          <div className="mt-5 grid grid-cols-2 gap-3 lg:grid-cols-6">
            {SEVERITY_KEYS.map((severity) => (
              <SeverityMetric key={severity} label={SEV_LABEL[severity]} value={counts[severity]} severity={severity} />
            ))}
            <MetricCard label="문제 재현·확인" value={verified} tone="warning" className="col-span-1" />
            <MetricCard label="고친 뒤 확인 완료" value={fixedVerified} tone="success" className="col-span-1" />
          </div>
        </section>

        {/* 5. 해결 가이드 (내부 버튼은 모두 secondary) */}
        {scan.report ? (
          <ScanReportPanel report={scan.report} firstFixableFindingId={firstFixable?.id} />
        ) : (
          <section id="solution" className="scroll-mt-32 pt-10" aria-labelledby="solution-title">
            <SectionHeader
              eyebrow="해결"
              title={<span id="solution-title">{firstFixable ? "급한 항목부터 해결해요" : "지금은 범위를 확인해요"}</span>}
              description="자동 요약 보고서는 없지만, 기록된 발견과 근거는 그대로 확인할 수 있어요."
            />
            {firstFixable && (
              <Link
                href={`/dashboard/findings/${firstFixable.id}?fix=1`}
                className={buttonClassName({ variant: "secondary", className: "mt-5 w-full sm:w-auto" })}
              >
                첫 문제 해결 시작
              </Link>
            )}
          </section>
        )}

        {/* 6. 발견 목록: critical → high → medium → low (요구사항 8.2, 8.9) */}
        <section id="findings" className="scroll-mt-32 pt-12" aria-labelledby="findings-title">
          <SectionHeader
            eyebrow="확인한 내용"
            title={<span id="findings-title">발견 목록 ({findings.length}건)</span>}
            description="쉬운 영향 설명을 먼저 읽고, 상세 화면에서 코드 위치와 근거를 확인해요."
          />
          {findings.length === 0 ? (
            <HoiScene
              mood="rest"
              size="md"
              className="mt-5"
              title="이번 범위에서 찾은 항목은 없어요"
              description="확인하지 못한 항목이나 자동 점검이 놓친 문제가 있을 수 있어요. 아래 범위와 한계를 확인하고 코드가 바뀌면 다시 점검해 주세요."
            />
          ) : (
            <ol className="mt-5 space-y-4">
              {findings.map((finding, index) => {
                const isAi = finding.verificationKey?.startsWith("ai:") || finding.category === "AI Detected";
                return (
                  <li key={finding.id}>
                    <Link
                      href={`/dashboard/findings/${finding.id}`}
                      className="group block rounded-3xl border border-line bg-surface p-5 shadow-warm transition hover:border-brand-300 motion-reduce:transition-none sm:p-6"
                    >
                      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <Badge tone="primary">우선순위 {index + 1}</Badge>
                            <SeverityBadge severity={finding.severity} />
                            <StatusBadge status={finding.status} />
                            {finding.simulated && <SimulatedTag />}
                            {isAi && <AiTag />}
                          </div>
                          <h3 className="mt-3 break-words text-lg font-bold text-ink">{finding.title}</h3>
                          <p className="mt-2 break-keep leading-relaxed text-ink-subtle">{finding.humanReadableImpact}</p>
                          {finding.location && (
                            <p className="mt-3 break-all font-mono text-xs text-ink-muted">
                              {finding.location.file}:{finding.location.line}
                            </p>
                          )}
                        </div>
                        <span className="inline-flex min-h-11 shrink-0 items-center font-bold text-brand-800 group-hover:underline">
                          해결 가이드 보기 <span aria-hidden="true">&nbsp;→</span>
                        </span>
                      </div>
                    </Link>
                  </li>
                );
              })}
            </ol>
          )}
        </section>

        {/* 7. 점검 범위와 한계 */}
        <section id="coverage" className="scroll-mt-32 pt-12" aria-labelledby="coverage-title">
          <SectionHeader
            eyebrow="결과를 읽기 전에"
            title={<span id="coverage-title">점검 범위와 한계</span>}
            description="점검한 것과 확인하지 못한 것을 구분해야 결과를 정확히 이해할 수 있어요."
          />
          <ScanScopePanel scope={scan.scope} />
        </section>

        {/* 8. 기술 정보 (처음에는 접힘, 요구사항 8.5, 8.6) */}
        <section className="pt-10" aria-labelledby="expert-title">
          <SectionHeader
            eyebrow="필요할 때만"
            title={<span id="expert-title">전문가 정보</span>}
            description="실행 정책, 규칙, 도구, 커버리지 갭의 원문을 보존해요."
          />
          <TechnicalDetails summary="기술 정보 보기" className="mt-5">
            {scan.plan ? <PlanPanel plan={scan.plan} /> : (
              <p className="text-sm text-ink-subtle">이 점검에는 저장된 규칙 실행 계획이 없어요.</p>
            )}
            <dl className="mt-5 grid gap-3 border-t border-line pt-5 text-sm sm:grid-cols-2">
              <ScopeRow label="스캔 상태" value={scan.status} />
              <ScopeRow label="스캔 ID" value={scan.id} mono />
              <ScopeRow label="시작 시각" value={new Date(scan.startedAt).toLocaleString("ko-KR")} />
              <ScopeRow label="완료 시각" value={scan.completedAt ? new Date(scan.completedAt).toLocaleString("ko-KR") : "기록 없음"} />
            </dl>
            <div className="mt-5 border-t border-line pt-5 text-sm">
              <h3 className="font-bold text-ink">자동 보고서 요약</h3>
              <p className="mt-1 whitespace-pre-line leading-relaxed text-ink">
                {scan.report?.summary ?? "이 점검에는 저장된 자동 보고서 요약이 없어요."}
              </p>
            </div>
          </TechnicalDetails>
        </section>
      </div>
    </>
  );
}

function SeverityMetric({ label, value, severity }: { label: string; value: number; severity: Severity }) {
  const tone = severity === "critical" ? "danger" : severity === "high" || severity === "medium" ? "warning" : "info";
  return <MetricCard label={label} value={value} tone={tone} />;
}

function ScanScopePanel({ scope }: { scope: ScanScope }) {
  return (
    <Card variant="warm" className="mt-5 p-5 sm:p-6">
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
        자동 점검은 모든 문제를 찾지 못해요. 이 결과는 아래 커밋·시점·연결된 대상과 실행한 항목에만 해당하며, 발견이 없어도 모든 위험을 찾았다는 뜻은 아니에요.
      </p>
      <dl className="mt-5 grid gap-3 text-sm sm:grid-cols-2">
        <ScopeRow label="점검 시각" value={new Date(scope.scanDate).toLocaleString("ko-KR")} />
        <ScopeRow label="저장소" value={scope.repository ?? "연결 안 됨"} />
        <ScopeRow label="배포 주소" value={scope.deploymentUrl ?? "연결 안 됨"} />
        <ScopeRow label="점검 커밋" value={scope.testedCommit ?? "기록 없음"} mono />
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
    <div>
      <dl className="grid gap-3 text-sm sm:grid-cols-2">
        <ScopeRow label="정책 버전" value={plan.policyVersion} mono />
        <ScopeRow label="규칙 레지스트리 다이제스트" value={plan.ruleRegistryDigest} mono />
        <ScopeRow label="계획 ID" value={plan.planId} mono />
        <ScopeRow label="스키마 버전" value={plan.schemaVersion} mono />
        <ScopeRow label="프로젝트 ID" value={plan.projectId} mono />
        <ScopeRow label="소스 커밋" value={plan.sourceCommitSha ?? "기록 없음"} mono />
      </dl>

      <h3 className="mt-6 font-bold text-ink">실행한 검사 ({plan.selectedChecks.length}개)</h3>
      {plan.selectedChecks.length === 0 ? (
        <p className="mt-2 text-sm text-ink-subtle">실행 가능한 검사가 없었어요.</p>
      ) : (
        <div className="mt-3 overflow-x-auto rounded-2xl border border-line">
          <table className="min-w-[760px] w-full text-left text-sm">
            <thead className="bg-surface-warm text-xs text-ink-muted"><tr><th className="p-3">규칙</th><th className="p-3">버전</th><th className="p-3">구성요소</th><th className="p-3">검사</th><th className="p-3">도구</th><th className="p-3">등급</th><th className="p-3">전제조건</th></tr></thead>
            <tbody className="divide-y divide-line">
              {plan.selectedChecks.map((check) => (
                <tr key={`${check.ruleId}-${check.checkId}`}>
                  <td className="p-3 font-bold text-ink">{check.ruleId}</td>
                  <td className="p-3 font-mono text-xs">{check.ruleVersion}</td>
                  <td className="p-3 font-mono text-xs">{check.componentId}</td>
                  <td className="p-3 font-mono text-xs">{check.checkId}</td>
                  <td className="p-3 font-mono text-xs">{check.toolId}</td>
                  <td className="p-3">{tierLabel(check.tier)}</td>
                  <td className="p-3">{check.prerequisiteStatus}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h3 className="mt-6 font-bold text-ink">확인하지 못한 검사 ({plan.coverageGaps.length}개)</h3>
      {plan.coverageGaps.length === 0 ? (
        <p className="mt-2 text-sm text-ink-subtle">별도로 기록된 커버리지 갭이 없어요. 그래도 모든 위험을 찾았다는 뜻은 아니에요.</p>
      ) : (
        <ul className="mt-3 space-y-2 text-sm text-ink-subtle">
          {plan.coverageGaps.map((gap, index) => (
            <li key={`${gap.ruleId}-${gap.checkId}-${index}`} className="rounded-2xl bg-warning-soft p-3">
              <span className="font-bold text-ink">{gap.ruleId}</span>{" "}
              <span className="break-all font-mono text-xs">({gap.checkId})</span> · {gap.reason}
            </li>
          ))}
        </ul>
      )}
      <p className="mt-3 text-sm font-bold text-warning">확인하지 못한 항목은 “안전”이 아니라 “결론을 내리지 못함”이에요.</p>
    </div>
  );
}
