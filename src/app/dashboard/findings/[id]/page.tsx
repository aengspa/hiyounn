import { notFound } from "next/navigation";
import { PageHeader } from "@/components/PageHeader";
import { getCurrentUserId } from "@/lib/auth";
import {
  getFinding,
  getFixForFinding,
  getVerification,
  NotFoundError,
  NotAuthorizedError,
} from "@/lib/store/store";
import {
  SeverityBadge,
  StatusBadge,
  SimulatedTag,
  AiTag,
  Evidence,
  categoryLabel,
  TestStatusBadge,
  tierLabel,
} from "@/components/ui";
import { FindingActions } from "@/components/FindingActions";
import { toTestStatus } from "@/lib/domain/types";
import type { EvidenceKind } from "@/lib/domain/types";

export const dynamic = "force-dynamic";

const EVIDENCE_KIND_LABEL: Record<EvidenceKind, string> = {
  source_code: "소스 코드",
  http_request: "HTTP 요청",
  http_response: "HTTP 응답",
  scanner_output: "스캐너 출력",
  configuration: "설정 값",
  attack_reproduction: "공격 재현 결과",
};

export default async function FindingPage({
  params,
}: {
  params: { id: string };
}) {
  const uid = await getCurrentUserId();
  let finding;
  try {
    finding = await getFinding(params.id, uid);
  } catch (e) {
    if (e instanceof NotFoundError || e instanceof NotAuthorizedError)
      notFound();
    throw e;
  }
  const fix = (await getFixForFinding(params.id, uid)) ?? null;
  const verification = (await getVerification(params.id, uid)) ?? null;
  const isAi = finding.verificationKey?.startsWith("ai:") ?? false;

  return (
    <>
      <PageHeader
        title="취약점 보고서"
        subtitle="무엇이 위험한지 확인한 뒤, 아래에서 수정과 재검증을 진행하세요."
        backHref={`/dashboard/scans/${finding.scanId}`}
        backLabel="스캔 결과"
      />
      <main className="mx-auto max-w-4xl px-6 py-8">
        {/* 헤더 */}
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <StatusBadge status={finding.status} />
          <TestStatusBadge status={finding.testStatus ?? toTestStatus(finding.status)} />
          {finding.simulated && <SimulatedTag />}
          {isAi && <AiTag />}
        </div>
        <h1 className="mt-3 text-2xl font-bold text-slate-900">{finding.title}</h1>

        {/* 전문 분류 (부가 정보) */}
        <div className="mt-3 flex flex-wrap gap-x-6 gap-y-1 text-sm text-slate-500">
          {finding.ruleId && (
            <span className="font-medium text-slate-600">규칙: {finding.ruleId}</span>
          )}
          {finding.owasp && <span>OWASP: {finding.owasp}</span>}
          {finding.cwe && <span>CWE: {finding.cwe}</span>}
          {typeof finding.cvss === "number" && <span>CVSS: {finding.cvss}</span>}
          {finding.executionTier && <span>검사 등급: {tierLabel(finding.executionTier)}</span>}
          <span>분류: {categoryLabel(finding.category)}</span>
        </div>
        {finding.standards && finding.standards.length > 0 && (
          <div className="mt-1 flex flex-wrap gap-2 text-xs text-slate-400">
            {finding.standards.map((s) => (
              <span key={s} className="rounded bg-slate-100 px-1.5 py-0.5">
                {s}
              </span>
            ))}
          </div>
        )}

        {/* 무슨 일이 생길 수 있나요 */}
        <Section title="무슨 일이 생길 수 있나요?">
          <p className="text-slate-700">{finding.humanReadableImpact}</p>
        </Section>

        {/* 왜 중요한가요 */}
        <Section title="왜 중요한가요?">
          <p className="text-slate-700">{finding.whyItMatters}</p>
        </Section>

        {/* 위치 */}
        {finding.location && (
          <Section title="위치">
            <code className="rounded bg-slate-100 px-2 py-1 font-mono text-sm text-slate-800">
              {finding.location.file}:{finding.location.line}
            </code>
          </Section>
        )}

        {/* 근거 */}
        <Section title="근거 (Evidence)">
          {isAi && (
            <p className="mb-3 rounded-lg border border-sky-100 bg-sky-50 p-3 text-xs text-sky-800">
              이 항목은 AI가 코드를 읽고 찾아낸 결과입니다. AI의 판단은 참고용이며,
              재현 가능한 취약점은 아래에서 실제 테스트로 다시 검증합니다.
            </p>
          )}
          <div className="space-y-3">
            {finding.evidence.map((ev) => (
              <div key={ev.id}>
                {ev.masked && (
                  <p className="mb-1 text-xs text-slate-400">
                    민감한 값은 가려서 표시합니다.
                  </p>
                )}
                <Evidence
                  label={`${ev.label}  ·  ${EVIDENCE_KIND_LABEL[ev.kind]}`}
                  content={ev.content}
                  tone={ev.kind === "attack_reproduction" ? "danger" : "default"}
                />
              </div>
            ))}
          </div>
        </Section>

        {/* 인터랙티브: 수정, 검증, 타임라인 */}
        <FindingActions
          findingId={finding.id}
          initialStatus={finding.status}
          initialFix={fix}
          initialVerification={verification}
        />
      </main>
    </>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="mt-8">
      <h2 className="mb-2 text-sm font-semibold tracking-wide text-slate-500">
        {title}
      </h2>
      {children}
    </section>
  );
}
