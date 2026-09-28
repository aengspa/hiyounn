import { notFound } from "next/navigation";
import { PageHeader } from "@/components/PageHeader";
import { HoiSpeech } from "@/components/mascot/HoiSpeech";
import { getCurrentUserId } from "@/lib/auth";
import {
  getFinding,
  getFixForFinding,
  getVerification,
  NotFoundError,
  NotAuthorizedError,
} from "@/lib/store/store";
import {
  AiTag,
  Badge,
  Card,
  Evidence,
  SeverityBadge,
  SimulatedTag,
  StatusBadge,
  TechnicalDetails,
  TestStatusBadge,
  categoryLabel,
  tierLabel,
} from "@/components/ui";
import { FindingActions } from "@/components/FindingActions";
import { toTestStatus } from "@/lib/domain/types";
import type { EvidenceKind, SecurityEvidence } from "@/lib/domain/types";

export const dynamic = "force-dynamic";

const EVIDENCE_KIND_LABEL: Record<EvidenceKind, string> = {
  source_code: "소스 코드",
  http_request: "HTTP 요청",
  http_response: "HTTP 응답",
  scanner_output: "스캐너 출력",
  configuration: "설정 값",
  attack_reproduction: "문제 재현 결과",
};

export default async function FindingPage({ params }: { params: { id: string } }) {
  const uid = await getCurrentUserId();
  let finding;
  try {
    finding = await getFinding(params.id, uid);
  } catch (e) {
    if (e instanceof NotFoundError || e instanceof NotAuthorizedError) notFound();
    throw e;
  }

  const fix = (await getFixForFinding(params.id, uid)) ?? null;
  const verification = (await getVerification(params.id, uid)) ?? null;
  const isAi = finding.verificationKey?.startsWith("ai:") ?? false;
  const sourceEvidence = finding.evidence.find((evidence) => evidence.kind === "source_code");
  const currentStep = getCurrentStep(finding.status, Boolean(fix), Boolean(fix?.applied));

  return (
    <>
      <PageHeader
        title="호이가 찾은 부분"
        subtitle="쉬운 영향부터 읽고, 아래 해결 여정에서 한 단계씩 직접 확인해요."
        backHref={`/dashboard/scans/${finding.scanId}`}
        backLabel="점검 보고서"
      />
      <div className="mx-auto max-w-4xl px-4 py-7 sm:px-6 sm:py-10">
        <section aria-labelledby="finding-title">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <StatusBadge status={finding.status} />
            <TestStatusBadge status={finding.testStatus ?? toTestStatus(finding.status)} />
            {finding.simulated && <SimulatedTag />}
            {isAi && <AiTag />}
          </div>
          <h2 id="finding-title" className="mt-4 break-words text-3xl font-bold tracking-tight text-ink">
            {finding.title}
          </h2>
          <HoiSpeech mood={finding.status === "resolved" ? "celebrate" : "concerned"} size="md" className="mt-6">
            <span>
              <span className="block text-sm font-semibold text-brand-700">현재 단계 · {currentStep}</span>
              <span className="mt-1 block">
                {finding.status === "resolved"
                  ? "이 항목은 수정 후 보안과 기본 기능 확인을 모두 통과했어요."
                  : "괜찮아요. 먼저 영향과 위치를 확인한 뒤, 아래 해결 여정의 버튼 하나만 따라오면 돼요."}
              </span>
            </span>
          </HoiSpeech>
        </section>

        {(isAi || finding.simulated) && (
          <div className="mt-6 grid gap-3 sm:grid-cols-2">
            {isAi && (
              <Card variant="flat" className="border-blue-200 bg-info-soft p-4 text-sm leading-relaxed text-info">
                <strong>AI 분석 안내</strong><br />AI의 설명은 참고용이에요. 실제 상태는 저장된 근거와 재검증 결과를 우선해 판단해요.
              </Card>
            )}
            {finding.simulated && (
              <Card variant="warm" className="p-4 text-sm leading-relaxed text-ink-subtle">
                <strong className="text-ink">격리 시뮬레이션 안내</strong><br />허용된 격리 범위에서 문제 상황을 재현한 기록이에요. 운영 공격을 실행했다는 뜻이 아니에요.
              </Card>
            )}
          </div>
        )}

        <GuideSection eyebrow="먼저 읽어요" title="한눈에 보기">
          <Card variant="raised" className="p-5 sm:p-6">
            <p className="text-lg font-semibold leading-relaxed text-ink">{finding.whyItMatters}</p>
            <div className="mt-4 flex flex-wrap gap-2">
              <Badge tone={finding.severity === "critical" ? "danger" : finding.severity === "high" ? "warning" : "neutral"}>
                우선순위 · <SeverityBadge severity={finding.severity} className="ml-1 border-0 bg-transparent px-0" />
              </Badge>
              <Badge tone="neutral">분류 · {categoryLabel(finding.category)}</Badge>
            </div>
          </Card>
        </GuideSection>

        <GuideSection eyebrow="내 서비스에는" title="사용자 영향">
          <p className="text-lg leading-relaxed text-ink-subtle">{finding.humanReadableImpact}</p>
        </GuideSection>

        <GuideSection eyebrow="코드에서 확인해요" title="어디서 찾았나요?">
          {finding.location ? (
            <Card variant="warm" className="p-5">
              <dl className="grid gap-4 text-sm sm:grid-cols-[1fr_auto]">
                <div className="min-w-0">
                  <dt className="font-bold text-ink-muted">파일</dt>
                  <dd className="mt-1 break-all font-mono text-ink">{finding.location.file}</dd>
                </div>
                <div>
                  <dt className="font-bold text-ink-muted">줄</dt>
                  <dd className="mt-1 font-mono text-ink">{finding.location.line}</dd>
                </div>
              </dl>
            </Card>
          ) : (
            <p className="text-ink-subtle">특정 파일과 줄로 좁히지 못한 항목이에요. 아래 근거 요약과 전문가용 원문을 확인해 주세요.</p>
          )}
          {sourceEvidence && (
            <Evidence
              className="mt-4"
              label={`${sourceEvidence.label} · ${sourceEvidence.masked ? "민감값 마스킹됨" : "저장된 코드 문맥"}`}
              content={sourceEvidence.content}
            />
          )}
        </GuideSection>

        <GuideSection eyebrow="다음 행동" title="이렇게 고쳐보세요">
          <Card variant="warm" className="p-5 sm:p-6">
            <p className="leading-relaxed text-ink">
              {finding.remediation ?? "자동으로 제공된 구체적인 수정 지침이 없어요. 아래 수정안 생성 단계에서 제안을 만든 뒤 변경 범위와 영향을 검토해 주세요."}
            </p>
          </Card>
          <FindingActions
            findingId={finding.id}
            initialStatus={finding.status}
            initialFix={fix}
            initialVerification={verification}
          />
        </GuideSection>

        <GuideSection eyebrow="수정 뒤" title="고친 뒤 확인할 것">
          <ul className="grid gap-3 sm:grid-cols-2">
            <CheckItem title="같은 문제가 막혔나요?" description="처음 문제를 확인한 규칙이나 재현 방법으로 다시 점검해요." />
            <CheckItem title="기존 기능은 그대로인가요?" description="정상 사용 흐름과 저장·응답 무결성이 깨지지 않았는지 확인해요." />
            <CheckItem title="실제 대상에 반영했나요?" description="이 화면의 적용 표시는 점검 기록 상태예요. 저장소나 배포 환경 반영은 별도로 확인해요." />
            <CheckItem title="점검 범위가 같나요?" description="재검증이 저장된 소스나 허가된 배포 대상을 읽을 수 있는지 확인해요." />
          </ul>
        </GuideSection>

        <GuideSection eyebrow="판단 근거" title="호이가 확인한 근거">
          {finding.evidence.length === 0 ? (
            <p className="text-ink-subtle">저장된 근거가 없어요. 이 항목만으로 확정적인 결론을 내리지 마세요.</p>
          ) : (
            <div className="space-y-3">
              {finding.evidence.map((evidence, index) => (
                <EvidenceSummary key={evidence.id} evidence={evidence} index={index} />
              ))}
            </div>
          )}
        </GuideSection>

        <section className="mt-12" aria-labelledby="expert-details-title">
          <TechnicalDetails summary={<span id="expert-details-title">전문가용 정보 펼쳐보기</span>}>
            <dl className="grid gap-4 text-sm sm:grid-cols-2">
              <ExpertMeta label="CWE" value={finding.cwe ?? "기록 없음"} />
              <ExpertMeta label="OWASP" value={finding.owasp ?? "기록 없음"} />
              <ExpertMeta label="CVSS" value={typeof finding.cvss === "number" ? String(finding.cvss) : "기록 없음"} />
              <ExpertMeta label="ruleId" value={finding.ruleId ?? "기록 없음"} mono />
              <ExpertMeta label="tier" value={finding.executionTier ? `${finding.executionTier} · ${tierLabel(finding.executionTier)}` : "기록 없음"} />
              <ExpertMeta label="category" value={finding.category} />
              <ExpertMeta label="findingId" value={finding.id} mono />
              <ExpertMeta label="scanId" value={finding.scanId} mono />
              <ExpertMeta label="verificationKey" value={finding.verificationKey ?? "기록 없음"} mono />
              <ExpertMeta label="생성 시각" value={new Date(finding.createdAt).toLocaleString("ko-KR")} />
              <ExpertMeta label="갱신 시각" value={new Date(finding.updatedAt).toLocaleString("ko-KR")} />
              <ExpertMeta label="시뮬레이션" value={finding.simulated ? "true" : "false"} mono />
            </dl>
            <div className="mt-5">
              <p className="font-bold text-ink">standards</p>
              <div className="mt-2 flex flex-wrap gap-2">
                {finding.standards?.length ? finding.standards.map((standard) => <Badge key={standard}>{standard}</Badge>) : <span className="text-sm">기록 없음</span>}
              </div>
            </div>
            <div className="mt-5">
              <p className="font-bold text-ink">스캐너 기술 설명</p>
              <p className="mt-2 whitespace-pre-wrap text-sm leading-relaxed">{finding.description}</p>
            </div>
            <div className="mt-6 space-y-4 border-t border-line pt-5">
              <h3 className="font-semibold text-ink">스캐너 원문</h3>
              {finding.evidence.map((evidence) => (
                <div key={evidence.id}>
                  {evidence.masked && <p className="mb-2 text-xs font-bold text-warning">민감한 값은 저장된 마스킹 상태로만 표시해요.</p>}
                  <Evidence
                    label={`${evidence.label} · ${EVIDENCE_KIND_LABEL[evidence.kind]} · ID ${evidence.id}`}
                    content={evidence.content}
                    tone={evidence.kind === "attack_reproduction" ? "danger" : "default"}
                  />
                </div>
              ))}
            </div>
          </TechnicalDetails>
        </section>
      </div>
    </>
  );
}

function GuideSection({ eyebrow, title, children }: { eyebrow: string; title: string; children: React.ReactNode }) {
  const id = `section-${title.replace(/[^가-힣a-zA-Z0-9]/g, "-")}`;
  return (
    <section className="mt-12" aria-labelledby={id}>
      <p className="text-sm font-semibold text-brand-700">{eyebrow}</p>
      <h2 id={id} className="mt-1 mb-4 text-2xl font-bold tracking-tight text-ink">{title}</h2>
      {children}
    </section>
  );
}

function CheckItem({ title, description }: { title: string; description: string }) {
  return (
    <li className="rounded-2xl border border-line bg-white p-4 shadow-warm">
      <p className="font-semibold text-ink">□ {title}</p>
      <p className="mt-1 text-sm leading-relaxed text-ink-subtle">{description}</p>
    </li>
  );
}

function EvidenceSummary({ evidence, index }: { evidence: SecurityEvidence; index: number }) {
  return (
    <Card variant="flat" className="p-4">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={evidence.kind === "attack_reproduction" ? "danger" : "neutral"}>근거 {index + 1}</Badge>
        <span className="font-semibold text-ink">{evidence.label}</span>
      </div>
      <p className="mt-2 text-sm leading-relaxed text-ink-subtle">
        {EVIDENCE_KIND_LABEL[evidence.kind]} 기록이 저장되어 있어요.
        {evidence.masked ? " 민감한 값은 이미 가린 상태예요." : " 원문은 아래 전문가용 정보에서 확인할 수 있어요."}
      </p>
    </Card>
  );
}

function ExpertMeta({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0 border-b border-line pb-2">
      <dt className="font-bold text-ink-muted">{label}</dt>
      <dd className={`mt-1 break-all text-ink ${mono ? "font-mono text-xs" : ""}`}>{value}</dd>
    </div>
  );
}

function getCurrentStep(status: string, hasFix: boolean, applied: boolean): string {
  if (status === "resolved") return "6단계 · 해결 확인";
  if (status === "verification_failed" || status === "regression_failed" || status === "fixed") return "5단계 · 보안·기능 재검증";
  if (applied) return "5단계 · 보안·기능 재검증";
  if (hasFix) return "3단계 · 변경 영향 검토와 승인";
  return "2단계 · 수정안 만들기";
}
