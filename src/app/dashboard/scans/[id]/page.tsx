import Link from "next/link";
import { notFound } from "next/navigation";
import { PageHeader } from "@/components/PageHeader";
import { getCurrentUserId } from "@/lib/auth";
import {
  getScan,
  getFindingsForScan,
  NotFoundError,
  NotAuthorizedError,
} from "@/lib/store/store";
import {
  SeverityBadge,
  StatusBadge,
  SimulatedTag,
  AiTag,
  categoryLabel,
  tierLabel,
} from "@/components/ui";
import { SEVERITY_ORDER } from "@/lib/domain/types";
import type { Severity, ScanScope, ScanPlan } from "@/lib/domain/types";
import { ScanReportPanel } from "@/components/ScanReportPanel";

export const dynamic = "force-dynamic";

export default async function ScanResultsPage({
  params,
}: {
  params: { id: string };
}) {
  const uid = await getCurrentUserId();
  let scan;
  try {
    scan = getScan(params.id, uid);
  } catch (e) {
    if (e instanceof NotFoundError || e instanceof NotAuthorizedError)
      notFound();
    throw e;
  }
  const findings = getFindingsForScan(params.id, uid).sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  );

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  let verified = 0;
  let fixedVerified = 0;
  for (const f of findings) {
    counts[f.severity] += 1;
    if (f.status === "verified" || f.status === "resolved") verified += 1;
    if (f.status === "resolved") fixedVerified += 1;
  }

  const headline =
    counts.critical > 0
      ? `배포 전에 확인이 필요한 심각한 문제가 ${counts.critical}건 있습니다.`
      : "점검한 범위 안에서는 심각한 취약점이 발견되지 않았습니다.";

  // 심각도순으로 정렬된 findings 중 아직 해결되지 않은 첫 항목(수정 진입점).
  const firstFixable = findings.find((f) => f.status !== "resolved");

  return (
    <>
      <PageHeader
        title="보안 스캔 요약"
        subtitle="발견된 취약점과 점검 범위를 확인하세요."
        backHref={`/dashboard/projects/${scan.projectId}`}
        backLabel="프로젝트"
      />
      <main className="mx-auto max-w-5xl px-6 py-8">
        {/* 요약 */}
        <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
          <p
            className={`text-lg font-medium ${
              counts.critical > 0 ? "text-red-700" : "text-emerald-700"
            }`}
          >
            {headline}
          </p>

          <div className="mt-6 grid grid-cols-2 gap-4 sm:grid-cols-6">
            <Metric label="심각" value={counts.critical} tone="critical" />
            <Metric label="높음" value={counts.high} tone="high" />
            <Metric label="보통" value={counts.medium} tone="medium" />
            <Metric label="낮음" value={counts.low} tone="low" />
            <Metric label="공격 재현됨" value={verified} />
            <Metric label="수정·검증 완료" value={fixedVerified} tone="ok" />
          </div>
        </section>

        {/* AI 보고서 + 수정 확인 */}
        {scan.report && (
          <ScanReportPanel
            report={scan.report}
            firstFixableFindingId={firstFixable?.id}
          />
        )}

        {/* 스캔 범위 */}
        <ScanScopePanel scope={scan.scope} />

        {/* 규칙 기반 실행 계획 & 커버리지 갭 */}
        {scan.plan && <PlanPanel plan={scan.plan} />}

        {/* 발견 목록 */}
        <h2 className="mt-10 text-lg font-semibold text-slate-900">
          발견된 취약점 ({findings.length}건)
        </h2>
        <div className="mt-3 space-y-3">
          {findings.map((f) => (
            <Link
              key={f.id}
              href={`/dashboard/findings/${f.id}`}
              className="block rounded-xl border border-slate-200 bg-white p-5 shadow-sm transition hover:border-brand-300 hover:shadow"
            >
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={f.severity} />
                    <StatusBadge status={f.status} />
                    {f.ruleId && (
                      <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[11px] font-medium text-slate-600">
                        {f.ruleId}
                      </span>
                    )}
                    {f.simulated && <SimulatedTag />}
                    {f.verificationKey?.startsWith("ai:") && <AiTag />}
                  </div>
                  <h3 className="mt-2 text-base font-semibold text-slate-900">
                    {f.title}
                  </h3>
                  <p className="mt-1 text-sm text-slate-600">
                    {f.humanReadableImpact}
                  </p>
                  {f.location && (
                    <p className="mt-2 font-mono text-xs text-slate-400">
                      {f.location.file}:{f.location.line}
                    </p>
                  )}
                </div>
                <span className="whitespace-nowrap text-sm text-brand-600">
                  자세히 보기 &rarr;
                </span>
              </div>
            </Link>
          ))}
        </div>
      </main>
    </>
  );
}

function Metric({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone?: Severity | "ok";
}) {
  const color =
    tone === "critical"
      ? "text-red-600"
      : tone === "high"
        ? "text-orange-600"
        : tone === "medium"
          ? "text-yellow-600"
          : tone === "low"
            ? "text-cyan-600"
            : tone === "ok"
              ? "text-emerald-600"
              : "text-slate-900";
  return (
    <div className="rounded-lg border border-slate-100 bg-slate-50 p-3 text-center">
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
      <div className="mt-0.5 text-xs text-slate-500">{label}</div>
    </div>
  );
}

function ScanScopePanel({ scope }: { scope: ScanScope }) {
  return (
    <section className="mt-6 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <h2 className="text-lg font-semibold text-slate-900">점검 범위</h2>
      <div className="mt-4 grid gap-x-8 gap-y-2 text-sm sm:grid-cols-2">
        <ScopeRow
          label="스캔 일시"
          value={new Date(scope.scanDate).toLocaleString("ko-KR")}
        />
        <ScopeRow label="저장소" value={scope.repository ?? "—"} />
        <ScopeRow label="배포 주소" value={scope.deploymentUrl ?? "—"} />
        <ScopeRow label="점검 커밋" value={scope.testedCommit ?? "—"} mono />
        <ScopeRow label="스캐너 버전" value={scope.scannerVersion} mono />
        <ScopeRow label="룰셋 버전" value={scope.rulesetVersion} mono />
      </div>

      <div className="mt-5 grid gap-6 sm:grid-cols-2">
        <div>
          <p className="mb-2 text-sm font-medium text-slate-700">점검한 항목</p>
          <ul className="space-y-1 text-sm text-slate-600">
            {scope.testedCategories.map((c) => (
              <li key={c} className="flex items-center gap-2">
                <span className="text-emerald-600">✓</span> {categoryLabel(c)}
              </li>
            ))}
          </ul>
        </div>
        <div>
          <p className="mb-2 text-sm font-medium text-slate-700">
            점검하지 않은 항목
          </p>
          <ul className="space-y-1 text-sm text-slate-500">
            {scope.untestedCategories.map((c) => (
              <li key={c} className="flex items-center gap-2">
                <span className="text-slate-400">—</span> {categoryLabel(c)}
              </li>
            ))}
          </ul>
        </div>
      </div>

      <p className="mt-5 rounded-lg bg-slate-50 p-3 text-xs text-slate-500">
        자동 보안 점검은 모든 취약점을 찾아내지 못합니다. 이 결과는 지정된 커밋과
        시점에 점검한 애플리케이션과 항목에 한정됩니다.
      </p>
    </section>
  );
}

function ScopeRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex justify-between gap-4 border-b border-slate-50 py-1">
      <span className="text-slate-500">{label}</span>
      <span className={`truncate text-slate-800 ${mono ? "font-mono text-xs" : ""}`}>
        {value}
      </span>
    </div>
  );
}


function PlanPanel({ plan }: { plan: ScanPlan }) {
  return (
    <section className="mt-6 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-slate-900">규칙 기반 실행 계획</h2>
        <span className="font-mono text-xs text-slate-400">
          {plan.policyVersion} · {plan.ruleRegistryDigest}
        </span>
      </div>
      <p className="mt-1 text-sm text-slate-500">
        서버가 규칙 레지스트리로 실행할 검사를 확정했습니다. 실행 등급과 도구는
        규칙 파일에서 채워지며, 모델이 임의로 바꿀 수 없습니다.
      </p>

      {/* 실행된 검사 */}
      <div className="mt-4">
        <p className="mb-2 text-sm font-medium text-slate-700">
          실행한 검사 ({plan.selectedChecks.length}개)
        </p>
        {plan.selectedChecks.length === 0 ? (
          <p className="text-sm text-slate-500">실행 가능한 검사가 없습니다.</p>
        ) : (
          <div className="overflow-hidden rounded-lg border border-slate-100">
            <table className="w-full text-sm">
              <thead className="bg-slate-50 text-left text-xs text-slate-500">
                <tr>
                  <th className="px-3 py-2">규칙</th>
                  <th className="px-3 py-2">검사</th>
                  <th className="px-3 py-2">도구</th>
                  <th className="px-3 py-2">등급</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-50">
                {plan.selectedChecks.map((c) => (
                  <tr key={`${c.ruleId}-${c.checkId}`}>
                    <td className="px-3 py-2 font-medium text-slate-700">{c.ruleId}</td>
                    <td className="px-3 py-2 font-mono text-xs text-slate-500">
                      {c.checkId}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-slate-500">
                      {c.toolId}
                    </td>
                    <td className="px-3 py-2 text-slate-600">{tierLabel(c.tier)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* 커버리지 갭 */}
      {plan.coverageGaps.length > 0 && (
        <div className="mt-5">
          <p className="mb-2 text-sm font-medium text-slate-700">
            검사하지 못한 항목 ({plan.coverageGaps.length}개)
          </p>
          <ul className="space-y-1 text-sm text-slate-500">
            {plan.coverageGaps.map((g, i) => (
              <li key={i} className="flex items-start gap-2">
                <span className="text-amber-500">—</span>
                <span>
                  <span className="font-medium text-slate-600">{g.ruleId}</span>
                  <span className="font-mono text-xs text-slate-400"> ({g.checkId})</span>
                  {" · "}
                  {g.reason}
                </span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs text-slate-400">
            검사하지 못한 항목은 “안전”이 아니라 “확인하지 못함”입니다. 테스트 배포
            대상과 계정을 연결하면 더 많은 검사를 실행할 수 있습니다.
          </p>
        </div>
      )}
    </section>
  );
}
