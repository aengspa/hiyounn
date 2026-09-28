"use client";

import { useState } from "react";
import { PageHeader } from "@/components/PageHeader";
import { HoiSpeech } from "@/components/mascot/HoiSpeech";
import { HoiScene } from "@/components/mascot/HoiScene";
import {
  AiTag,
  Badge,
  Button,
  Card,
  CodeEvidence,
  Disclosure,
  SeverityBadge,
  SimulatedTag,
  StatusBadge,
  TestStatusBadge,
  categoryLabel,
} from "@/components/ui";
import type { SecurityFinding } from "@/lib/domain/types";

interface QuickResult {
  findings: SecurityFinding[];
  scannedFiles: string[];
  notCovered: string[];
}

export default function QuickCheckPage() {
  const [source, setSource] = useState("");
  const [result, setResult] = useState<QuickResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  async function run() {
    if (!source.trim()) {
      setError("확인할 코드를 먼저 붙여 넣어 주세요.");
      return;
    }

    setRunning(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch("/api/quick-check", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ source }),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data || data.error) {
        setError(friendlyQuickCheckError(data?.error));
        return;
      }
      setResult(data);
    } catch {
      setError("연결이 잠깐 끊겼어요. 인터넷 연결을 확인하고 다시 시도해 주세요.");
    } finally {
      setRunning(false);
    }
  }

  return (
    <>
      <PageHeader
        title="이 코드, 호이가 빠르게 살펴볼게요"
        subtitle="궁금한 코드를 붙여 넣으면 놓치기 쉬운 부분을 쉬운 말로 알려드려요."
        backHref="/dashboard"
        backLabel="내 프로젝트"
      />
      <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6">
        <HoiSpeech mood="searching" size="md">
          이 점검은 빠른 첫 확인이에요. 결과와 함께 이번에 보지 못한 범위도 알려드릴게요.
        </HoiSpeech>

        <Card variant="raised" className="mt-6 p-5 sm:p-7" aria-busy={running}>
          <label htmlFor="source" className="block text-lg font-black text-ink">
            살펴볼 코드
          </label>
          <p id="source-guidance" className="mt-1 text-sm leading-relaxed text-ink-subtle">
            여러 파일은 <code className="rounded-lg bg-surface-warm px-1.5 py-0.5 font-mono text-xs">// file: 경로</code>로 구분해 주세요. 입력의 앞 100,000자까지 검사해요.
          </p>
          <textarea
            id="source"
            name="source"
            value={source}
            onChange={(e) => {
              setSource(e.target.value);
              if (error) setError(null);
            }}
            rows={16}
            spellCheck={false}
            aria-invalid={Boolean(error)}
            aria-describedby={`source-guidance source-policy${error ? " quick-check-error" : ""}`}
            placeholder={`// file: src/lib/profile.ts\nexport function publicProfile(user) {\n  return { name: user.name };\n}`}
            className="mt-4 min-h-80 w-full resize-y rounded-2xl border border-line-strong bg-code p-4 font-mono text-sm leading-relaxed text-[#fffaf2] shadow-inner outline-none placeholder:text-code-muted focus:border-brand-500 focus:ring-2 focus:ring-primary-soft"
          />

          <div id="source-policy" className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
            <div className="rounded-2xl border border-line bg-surface-warm p-4">
              <p className="font-extrabold text-ink">전송과 저장</p>
              <p className="mt-1 leading-relaxed text-ink-subtle">
                코드는 서버로 전송해 현재 요청에서 검사해요. 프로젝트나 점검 결과로 저장하지 않아요.
              </p>
            </div>
            <div className="rounded-2xl border border-amber-200 bg-warning-soft p-4">
              <p className="font-extrabold text-ink">빠른 점검의 한계</p>
              <p className="mt-1 leading-relaxed text-ink-subtle">
                발견이 없더라도 안전을 보장하지 않아요. 전체 흐름은 프로젝트 점검에서 확인해 주세요.
              </p>
            </div>
          </div>

          {error && (
            <div id="quick-check-error" role="alert" aria-live="assertive" className="mt-4 rounded-2xl border border-red-200 bg-danger-soft p-4 text-sm text-danger">
              <p className="font-extrabold">점검을 시작하지 못했어요</p>
              <p className="mt-1">{error}</p>
            </div>
          )}

          <Button onClick={run} size="lg" disabled={running} aria-busy={running} className="mt-5 w-full sm:w-auto">
            <span aria-live="polite">{running ? "줄마다 꼼꼼히 읽고 있어요…" : "코드 살펴보기"}</span>
          </Button>
        </Card>

        {running && (
          <div role="status" aria-live="polite" className="mt-6">
            <HoiSpeech mood="searching" size="sm">줄마다 꼼꼼히 읽고 있어요. 잠시만 기다려 주세요.</HoiSpeech>
          </div>
        )}

        {result && <QuickResults result={result} />}
      </div>
    </>
  );
}

function QuickResults({ result }: { result: QuickResult }) {
  const { findings, scannedFiles, notCovered } = result;

  return (
    <section className="mt-10 space-y-6" aria-labelledby="quick-results-title" aria-live="polite">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-sm font-extrabold text-brand-700">빠른 점검 결과</p>
          <h2 id="quick-results-title" className="text-2xl font-black tracking-tight text-ink sm:text-3xl">
            고치면 좋은 부분 {findings.length}개를 찾았어요
          </h2>
        </div>
        <Badge tone="info">검사한 파일 {scannedFiles.length}개</Badge>
      </div>

      {findings.length === 0 ? (
        <HoiScene
          mood="rest"
          size="md"
          title="이번 빠른 점검에서는 신호를 찾지 못했어요"
          description="확인한 코드와 규칙 범위의 결과예요. 발견이 없다는 것이 안전하다는 뜻은 아니니 아래의 확인하지 못한 범위도 함께 봐 주세요."
        />
      ) : (
        <div className="space-y-5">
          {findings.map((finding, index) => (
            <FindingCard key={finding.id} finding={finding} index={index} />
          ))}
        </div>
      )}

      <Card variant="warm" className="p-5 sm:p-6">
        <h3 className="text-lg font-black text-ink">이번 빠른 점검에서 확인하지 못한 범위</h3>
        {notCovered.length > 0 ? (
          <ul className="mt-3 grid gap-2 text-sm leading-relaxed text-ink-subtle sm:grid-cols-2">
            {notCovered.map((item) => (
              <li key={item} className="rounded-xl border border-line bg-white px-3 py-2">• {item}</li>
            ))}
          </ul>
        ) : (
          <p className="mt-2 text-sm text-ink-subtle">서버가 별도로 알려준 제외 범위가 없어요. 자동 점검의 일반적인 한계는 여전히 적용돼요.</p>
        )}
        <p className="mt-4 text-sm font-bold text-warning">
          자동 점검만으로 모든 위험을 찾을 수는 없어요. 중요한 서비스는 전문가 검토도 함께 받아보세요.
        </p>
      </Card>
    </section>
  );
}

function FindingCard({ finding, index }: { finding: SecurityFinding; index: number }) {
  return (
    <Card variant="raised" className="overflow-hidden">
      <div className="border-b border-line bg-surface-warm px-5 py-4 sm:px-6">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-black text-ink-muted">{index + 1}번째로 살펴볼 곳</span>
          <SeverityBadge severity={finding.severity} />
          <StatusBadge status={finding.status} />
          {finding.testStatus && <TestStatusBadge status={finding.testStatus} />}
          {finding.simulated && <SimulatedTag />}
          {finding.category === "AI Detected" && <AiTag />}
        </div>
        <h3 className="mt-3 break-words text-xl font-black text-ink">{finding.title}</h3>
      </div>

      <div className="space-y-5 p-5 sm:p-6">
        <div>
          <h4 className="text-sm font-extrabold text-brand-700">어떤 영향이 있을까요?</h4>
          <p className="mt-1 break-keep leading-relaxed text-ink">{finding.humanReadableImpact}</p>
          {finding.whyItMatters && <p className="mt-2 text-sm leading-relaxed text-ink-subtle">{finding.whyItMatters}</p>}
        </div>

        {finding.remediation && (
          <div className="rounded-2xl border border-orange-200 bg-primary-soft/50 p-4">
            <h4 className="font-extrabold text-ink">이렇게 고쳐보세요</h4>
            <p className="mt-1 break-keep text-sm leading-relaxed text-ink-subtle">{finding.remediation}</p>
          </div>
        )}

        {finding.evidence.length > 0 && (
          <Disclosure summary="호이가 확인한 원본 근거 보기">
            <div className="space-y-3">
              {finding.evidence.map((evidence) => (
                <div key={evidence.id}>
                  {evidence.masked && <p className="mb-2 text-xs font-bold text-warning">민감할 수 있는 값은 가려서 보여드려요.</p>}
                  <CodeEvidence label={evidence.label} content={evidence.content} />
                </div>
              ))}
            </div>
          </Disclosure>
        )}

        <Disclosure summary="전문가용 정보 보기">
          <dl className="grid gap-3 text-sm sm:grid-cols-2">
            <TechnicalRow label="분류" value={categoryLabel(finding.category)} />
            <TechnicalRow label="규칙 ID" value={finding.ruleId ?? "기록 없음"} />
            <TechnicalRow label="위치" value={finding.location ? `${finding.location.file}:${finding.location.line}` : "기록 없음"} />
            <TechnicalRow label="CWE" value={finding.cwe ?? "기록 없음"} />
            <TechnicalRow label="OWASP" value={finding.owasp ?? "기록 없음"} />
            <TechnicalRow label="CVSS" value={finding.cvss?.toString() ?? "기록 없음"} />
            {finding.standards?.length ? <TechnicalRow label="표준" value={finding.standards.join(", ")} /> : null}
          </dl>
        </Disclosure>
      </div>
    </Card>
  );
}

function TechnicalRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="font-bold text-ink-muted">{label}</dt>
      <dd className="mt-0.5 break-all text-ink">{value}</dd>
    </div>
  );
}

function friendlyQuickCheckError(error: unknown) {
  if (error === "forbidden") return "코드를 확인할 권한을 찾지 못했어요. 로그인 상태를 확인해 주세요.";
  if (error === "source_too_large") return "코드가 너무 길어요. 확인할 부분을 나누어 다시 시도해 주세요.";
  if (error === "internal_error") return "지금은 코드를 살펴보기 어려워요. 잠시 후 다시 시도해 주세요.";
  return "검사를 마치지 못했어요. 코드를 확인한 뒤 다시 시도해 주세요.";
}
