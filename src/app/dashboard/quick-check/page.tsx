"use client";

import { useRef, useState } from "react";
import Link from "next/link";
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

const MAX_SOURCE_CHARS = 100_000;

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
  const resultRef = useRef<HTMLDivElement>(null);

  const overLimit = source.length > MAX_SOURCE_CHARS;

  async function run() {
    if (!source.trim()) {
      setError("확인할 코드를 먼저 붙여넣어 주세요.");
      return;
    }
    if (overLimit) {
      setError(`코드가 너무 길어요. ${MAX_SOURCE_CHARS.toLocaleString()}자 이하로 나누어 넣어주세요.`);
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
      requestAnimationFrame(() => {
        resultRef.current?.focus();
        resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    } catch {
      setError("연결이 잠깐 끊겼어요. 인터넷 연결을 확인하고 다시 시도해 주세요.");
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="mx-auto max-w-2xl px-4 py-10 sm:px-6">
      <Link href="/" className="text-sm font-medium text-brand-600 hover:underline">
        ← 홈으로
      </Link>

      <h1 className="mt-4 text-2xl font-bold tracking-tight text-ink sm:text-3xl">
        확인할 코드를 넣어주세요
      </h1>
      <p className="mt-2 text-base leading-relaxed text-ink-subtle">
        AI가 만든 코드를 그대로 붙여넣어도 괜찮아요.
      </p>

      <Card variant="default" className="mt-6 p-5 sm:p-6" aria-busy={running}>
        <label htmlFor="source" className="block text-base font-bold text-ink">
          확인할 코드
        </label>
        <textarea
          id="source"
          name="source"
          value={source}
          onChange={(e) => {
            setSource(e.target.value);
            if (error) setError(null);
          }}
          rows={14}
          spellCheck={false}
          aria-invalid={Boolean(error)}
          aria-describedby={`source-count${error ? " quick-check-error" : ""}`}
          placeholder="여기에 코드를 붙여넣으세요."
          className="mt-3 min-h-72 w-full resize-y rounded-xl border border-line-strong bg-code p-4 font-mono text-sm leading-relaxed text-[#eef1fb] shadow-inner outline-none placeholder:text-code-muted focus:border-brand-600 focus:ring-2 focus:ring-primary-soft"
        />
        <p
          id="source-count"
          className={`mt-2 text-right text-xs ${overLimit ? "font-semibold text-danger" : "text-ink-muted"}`}
        >
          {source.length.toLocaleString()} / {MAX_SOURCE_CHARS.toLocaleString()}자
        </p>

        <Disclosure summary="여러 파일을 넣는 방법" className="mt-3">
          <p className="text-sm leading-relaxed text-ink-subtle">
            여러 파일은 <code className="rounded bg-surface-warm px-1.5 py-0.5 font-mono text-xs">// file: 경로</code>{" "}
            주석으로 구분해 주세요. 예:
          </p>
          <CodeEvidence
            className="mt-3"
            content={`// file: src/lib/profile.ts\nexport function publicProfile(user) {\n  return { name: user.name };\n}`}
          />
        </Disclosure>

        <Disclosure summary="전송과 저장 확인하기" className="mt-3">
          <div className="space-y-3 text-sm leading-relaxed text-ink-subtle">
            <p>코드는 서버로 전송해 이번 요청에서만 검사해요. 프로젝트나 점검 결과로 저장하지 않아요.</p>
            <p className="font-semibold text-warning">
              발견이 없더라도 안전을 보장하지 않아요. 전체 흐름을 확인하려면 프로젝트 전체 점검을 이용해 주세요.
            </p>
          </div>
        </Disclosure>

        {error && (
          <div id="quick-check-error" role="alert" aria-live="assertive" className="mt-4 rounded-xl border border-red-200 bg-danger-soft p-4 text-sm text-danger">
            {error}
          </div>
        )}

        <Button onClick={run} size="lg" disabled={running} aria-busy={running} className="mt-5 w-full sm:w-auto">
          <span aria-live="polite">{running ? "코드를 확인하고 있어요…" : "코드 점검하기"}</span>
        </Button>

        <div className="mt-4">
          <Link href="/dashboard/new" className="text-sm font-medium text-brand-600 hover:underline">
            프로젝트 전체 점검하기 →
          </Link>
        </div>
      </Card>

      {result && (
        <div ref={resultRef} tabIndex={-1}>
          <QuickResults result={result} />
        </div>
      )}
    </div>
  );
}

function QuickResults({ result }: { result: QuickResult }) {
  const { findings, scannedFiles, notCovered } = result;

  return (
    <section className="mt-10 space-y-6" aria-labelledby="quick-results-title" aria-live="polite">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <h2 id="quick-results-title" className="text-xl font-bold tracking-tight text-ink sm:text-2xl">
          확인할 부분 {findings.length}개를 찾았어요
        </h2>
        <Badge tone="info">검사한 파일 {scannedFiles.length}개</Badge>
      </div>

      {findings.length === 0 ? (
        <Card variant="default" className="p-8 text-center">
          <p className="text-base font-semibold text-ink">이번 점검 범위에서 의심 항목을 찾지 못했어요</p>
          <p className="mt-2 text-sm leading-relaxed text-ink-subtle">
            확인한 코드와 규칙 범위의 결과예요. 발견이 없다는 것이 안전하다는 뜻은 아니니 아래의 확인하지 못한 범위도 함께 봐 주세요.
          </p>
        </Card>
      ) : (
        <div className="space-y-4">
          {findings.map((finding, index) => (
            <FindingCard key={finding.id} finding={finding} index={index} />
          ))}
        </div>
      )}

      <Card variant="default" className="p-5 sm:p-6">
        <h3 className="text-base font-bold text-ink">이번 빠른 점검에서 확인하지 못한 범위</h3>
        {notCovered.length > 0 ? (
          <ul className="mt-3 grid gap-2 text-sm leading-relaxed text-ink-subtle sm:grid-cols-2">
            {notCovered.map((item) => (
              <li key={item} className="rounded-lg border border-line bg-surface-warm px-3 py-2">• {item}</li>
            ))}
          </ul>
        ) : (
          <p className="mt-2 text-sm text-ink-subtle">서버가 별도로 알려준 제외 범위가 없어요. 자동 점검의 일반적인 한계는 여전히 적용돼요.</p>
        )}
        <p className="mt-4 text-sm font-semibold text-warning">
          자동 점검만으로 모든 위험을 찾을 수는 없어요. 중요한 서비스는 전문가 검토도 함께 받아보세요.
        </p>
      </Card>
    </section>
  );
}

function FindingCard({ finding, index }: { finding: SecurityFinding; index: number }) {
  return (
    <Card variant="default" className="overflow-hidden p-0">
      <div className="border-b border-line bg-surface-warm px-5 py-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-semibold text-ink-muted">{index + 1}번째로 살펴볼 곳</span>
          <SeverityBadge severity={finding.severity} />
          <StatusBadge status={finding.status} />
          {finding.testStatus && <TestStatusBadge status={finding.testStatus} />}
          {finding.simulated && <SimulatedTag />}
          {finding.category === "AI Detected" && <AiTag />}
        </div>
        <h3 className="mt-3 break-words text-lg font-bold text-ink">{finding.title}</h3>
      </div>

      <div className="space-y-5 p-5">
        <div>
          <h4 className="text-sm font-semibold text-brand-600">어떤 영향이 있을까요?</h4>
          <p className="mt-1 break-keep leading-relaxed text-ink">{finding.humanReadableImpact}</p>
          {finding.whyItMatters && <p className="mt-2 text-sm leading-relaxed text-ink-subtle">{finding.whyItMatters}</p>}
        </div>

        {finding.remediation && (
          <div className="rounded-xl border border-line bg-primary-soft/40 p-4">
            <h4 className="font-semibold text-ink">이렇게 고쳐보세요</h4>
            <p className="mt-1 break-keep text-sm leading-relaxed text-ink-subtle">{finding.remediation}</p>
          </div>
        )}

        {finding.evidence.length > 0 && (
          <Disclosure summary="원본 근거 보기">
            <div className="space-y-3">
              {finding.evidence.map((evidence) => (
                <div key={evidence.id}>
                  {evidence.masked && <p className="mb-2 text-xs font-semibold text-warning">민감할 수 있는 값은 가려서 보여드려요.</p>}
                  <CodeEvidence label={evidence.label} content={evidence.content} />
                </div>
              ))}
            </div>
          </Disclosure>
        )}

        <Disclosure summary="기술 정보 보기">
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
      <dt className="font-semibold text-ink-muted">{label}</dt>
      <dd className="mt-0.5 break-all text-ink">{value}</dd>
    </div>
  );
}

function friendlyQuickCheckError(error: unknown) {
  if (error === "forbidden") return "코드를 확인할 권한을 찾지 못했어요. 로그인 상태를 확인해 주세요.";
  if (error === "source_too_large") return `코드가 너무 길어요. ${MAX_SOURCE_CHARS.toLocaleString()}자 이하로 나누어 넣어주세요.`;
  if (error === "internal_error") return "지금은 코드를 살펴보기 어려워요. 잠시 후 다시 시도해 주세요.";
  return "검사를 마치지 못했어요. 코드를 확인한 뒤 다시 시도해 주세요.";
}
