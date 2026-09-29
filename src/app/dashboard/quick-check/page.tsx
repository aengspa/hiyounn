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
  FriendlyError,
  SeverityBadge,
  SimulatedTag,
  StatusBadge,
  TechnicalDetails,
  TestStatusBadge,
  buttonClassName,
  categoryLabel,
} from "@/components/ui";
import { HoiSpeech } from "@/components/mascot/HoiSpeech";
import type { SecurityFinding } from "@/lib/domain/types";
import {
  LIMIT_NOTICE,
  MAX_SOURCE_CHARS,
  QUICK_CHECK_EMPTY_MESSAGE,
  QUICK_CHECK_ERROR_COPY,
  SEV_EXPERT_LABEL,
  classifyQuickCheckError,
  formatCharCount,
  isOverSourceLimit,
  isQuickCheckSubmitDisabled,
  sortBySeverity,
  summarizeResult,
  validateQuickCheckSource,
  type QuickCheckErrorKind,
} from "@/lib/ui/presentation";

const AI_NOTICE = "호이가 AI로 코드를 읽고 찾은 내용이에요. 놓치거나 잘못 짚을 수 있어요.";

interface QuickResult {
  findings: SecurityFinding[];
  scannedFiles: string[];
  notCovered: string[];
}

/** 화면에 보여 줄 오류. 빈 입력은 fetch 전에 막고, 나머지는 요청 실패 종류별 문구를 쓴다. */
type QuickCheckError = { kind: "empty" } | { kind: QuickCheckErrorKind };

export default function QuickCheckPage() {
  const [source, setSource] = useState("");
  const [result, setResult] = useState<QuickResult | null>(null);
  const [error, setError] = useState<QuickCheckError | null>(null);
  const [running, setRunning] = useState(false);
  const resultRef = useRef<HTMLDivElement>(null);

  const overLimit = isOverSourceLimit(source);
  const submitDisabled = isQuickCheckSubmitDisabled({ source, running });

  const describedBy = [
    "source-count",
    overLimit ? "source-limit" : null,
    error ? "quick-check-error" : null,
  ]
    .filter(Boolean)
    .join(" ");

  async function run() {
    const validation = validateQuickCheckSource(source);
    if (validation === "empty") {
      setError({ kind: "empty" });
      return;
    }
    if (validation === "too_large") {
      setError({ kind: "source_too_large" });
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
        // 입력한 코드(source)는 건드리지 않는다.
        setError({ kind: classifyQuickCheckError({ networkFailed: false, errorCode: data?.error }) });
        return;
      }
      setResult(data);
      requestAnimationFrame(() => {
        resultRef.current?.focus();
        resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    } catch {
      setError({ kind: classifyQuickCheckError({ networkFailed: true }) });
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="mx-auto max-w-2xl px-4 py-10 sm:px-6">
      <Link
        href="/"
        className="inline-flex min-h-11 items-center gap-1 rounded-full border-2 border-line bg-surface px-3 text-sm font-bold text-brand-800 hover:border-brand-300"
      >
        <span aria-hidden="true">←</span> 홈으로
      </Link>

      <h1 className="mt-5 text-3xl font-extrabold tracking-tight text-ink sm:text-4xl">
        이 코드, 호이가 빠르게 살펴볼게요
      </h1>
      <p className="mt-2 text-base leading-relaxed text-ink-subtle">
        궁금한 코드를 붙여 넣으면 놓치기 쉬운 부분을 쉬운 말로 알려드려요. AI가 만든 코드를 그대로 붙여 넣어도 괜찮아요.
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
          aria-invalid={Boolean(error) || overLimit}
          aria-describedby={describedBy}
          placeholder="여기에 코드를 붙여 넣으세요."
          className="mt-3 min-h-72 w-full resize-y rounded-2xl border-2 border-line-input bg-surface p-4 font-mono text-sm leading-relaxed text-ink placeholder:text-ink-muted hover:border-brand-700 focus:border-brand-700 focus:bg-surface-warm"
        />
        <p
          id="source-count"
          className={`mt-2 text-right text-sm ${overLimit ? "font-bold text-danger" : "text-ink-subtle"}`}
        >
          {formatCharCount(source.length)}
        </p>
        <div id="source-limit" aria-live="polite" className="text-sm">
          {overLimit && (
            <p className="mt-1 rounded-2xl border-2 border-[#f3c4bd] bg-danger-soft px-4 py-3 font-bold text-danger">
              코드가 조금 길어요. {MAX_SOURCE_CHARS.toLocaleString("en-US")}자 이하로 줄이거나 여러 번에 나눠 넣어 주세요.
            </p>
          )}
        </div>

        <Disclosure summary="여러 파일을 넣는 방법" className="mt-3">
          <p className="text-sm leading-relaxed text-ink-subtle">
            여러 파일은{" "}
            <code className="rounded bg-surface-warm px-1.5 py-0.5 font-mono text-xs text-ink">{"// file: 경로"}</code>{" "}
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
            <p className="font-bold text-ink">
              발견이 없다고 해서 위험이 없다는 뜻은 아니에요. 전체 흐름을 확인하려면 프로젝트 전체 점검을 이용해 주세요.
            </p>
          </div>
        </Disclosure>

        {error && (
          <div id="quick-check-error" className="mt-4">
            {error.kind === "empty" ? (
              <FriendlyError title={QUICK_CHECK_EMPTY_MESSAGE} />
            ) : (
              <FriendlyError
                title={QUICK_CHECK_ERROR_COPY[error.kind].title}
                description={QUICK_CHECK_ERROR_COPY[error.kind].description}
              />
            )}
          </div>
        )}

        <Button
          onClick={run}
          variant="primary"
          size="lg"
          disabled={submitDisabled}
          aria-busy={running}
          className="mt-5 w-full sm:w-auto"
        >
          {running ? "코드를 확인하고 있어요…" : "코드 살펴보기"}
        </Button>

        <div className="mt-4">
          <Link href="/dashboard/new" className={buttonClassName({ variant: "ghost", size: "sm" })}>
            프로젝트 전체 점검하기 →
          </Link>
        </div>
      </Card>

      <div role="status" className="mt-6">
        {running && (
          <HoiSpeech mood="searching" size="sm">
            줄마다 꼼꼼히 읽고 있어요…
          </HoiSpeech>
        )}
      </div>

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
  const summary = summarizeResult(findings);
  const sorted = sortBySeverity(findings);

  return (
    <section className="mt-10 space-y-6" aria-labelledby="quick-results-title">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <h2 id="quick-results-title" className="text-2xl font-extrabold tracking-tight text-ink sm:text-3xl">
          {findings.length > 0 ? `확인할 부분 ${findings.length}개를 찾았어요` : "빠른 점검 결과"}
        </h2>
        <Badge tone="info">검사한 파일 {scannedFiles.length}개</Badge>
      </div>

      <HoiSpeech mood={summary.mood} footer={summary.showLimitNotice ? LIMIT_NOTICE : undefined}>
        {summary.message}
      </HoiSpeech>

      {sorted.length > 0 && (
        <div className="space-y-4">
          {sorted.map((finding, index) => (
            <FindingCard key={finding.id} finding={finding} index={index} />
          ))}
        </div>
      )}

      <Card variant="default" className="p-5 sm:p-6">
        <h3 className="text-base font-bold text-ink">이번 빠른 점검에서 확인하지 못한 범위</h3>
        {notCovered.length > 0 ? (
          <ul className="mt-3 grid gap-2 text-sm leading-relaxed text-ink-subtle sm:grid-cols-2">
            {notCovered.map((item) => (
              <li key={item} className="break-words rounded-2xl border border-line bg-surface-warm px-3 py-2">• {item}</li>
            ))}
          </ul>
        ) : (
          <p className="mt-2 text-sm text-ink-subtle">서버가 별도로 알려준 제외 범위가 없어요. 자동 점검의 일반적인 한계는 여전히 적용돼요.</p>
        )}
        <p className="mt-4 text-sm font-bold text-ink">
          자동 점검만으로 모든 위험을 찾을 수는 없어요. 중요한 서비스는 전문가 검토도 함께 받아보세요.
        </p>
      </Card>
    </section>
  );
}

function FindingCard({ finding, index }: { finding: SecurityFinding; index: number }) {
  const isAi = finding.category === "AI Detected";

  return (
    <Card variant="default" className="overflow-hidden p-0">
      <div className="border-b-2 border-line bg-surface-warm px-5 py-4 sm:px-6">
        <div className="flex flex-wrap items-center gap-2">
          <span className="inline-flex min-h-7 items-center rounded-full bg-ink px-3 text-[13px] font-bold text-surface">{index + 1}번째로 살펴볼 곳</span>
          <SeverityBadge severity={finding.severity} />
          <StatusBadge status={finding.status} />
          {finding.testStatus && <TestStatusBadge status={finding.testStatus} />}
          {finding.simulated && <SimulatedTag />}
          {isAi && <AiTag />}
        </div>
        <h3 className="mt-3 break-words text-lg font-bold text-ink">{finding.title}</h3>
      </div>

      <div className="space-y-5 p-5">
        {isAi && (
          <p className="rounded-2xl border-2 border-[#c9def3] bg-info-soft px-4 py-3 text-sm font-bold text-ink">
            {AI_NOTICE}
          </p>
        )}

        {explanationBlocks(finding).map((b) => (
          <div key={b.key} className={b.key === "fix" ? "rounded-2xl border-2 border-line bg-surface-warm p-4" : undefined}>
            <h4 className="text-sm font-bold text-brand-800">{b.label}</h4>
            <p className="mt-1 whitespace-pre-line break-words text-base leading-relaxed text-ink">{b.text}</p>
          </div>
        ))}

        <TechnicalDetails>
          <dl className="grid gap-3 text-sm sm:grid-cols-2">
            <TechnicalRow label="심각도(전문 용어)" value={SEV_EXPERT_LABEL[finding.severity] ?? finding.severity} />
            <TechnicalRow label="분류" value={categoryLabel(finding.category)} />
            <TechnicalRow label="규칙 ID" value={finding.ruleId ?? "기록 없음"} />
            <TechnicalRow label="위치" value={finding.location ? `${finding.location.file}:${finding.location.line}` : "기록 없음"} />
            <TechnicalRow label="CWE" value={finding.cwe ?? "기록 없음"} />
            <TechnicalRow label="OWASP" value={finding.owasp ?? "기록 없음"} />
            <TechnicalRow label="CVSS" value={finding.cvss?.toString() ?? "기록 없음"} />
            {finding.standards?.length ? <TechnicalRow label="표준" value={finding.standards.join(", ")} /> : null}
          </dl>

          {finding.evidence.length > 0 && (
            <div className="mt-5 space-y-3">
              <h4 className="text-sm font-bold text-ink">호이가 확인한 근거(원문)</h4>
              {finding.evidence.map((evidence) => (
                <div key={evidence.id}>
                  {evidence.masked && <p className="mb-2 text-xs font-bold text-ink">민감할 수 있는 값은 가려서 보여드려요.</p>}
                  <CodeEvidence label={evidence.label} content={evidence.content} />
                </div>
              ))}
            </div>
          )}
        </TechnicalDetails>
      </div>
    </Card>
  );
}

/**
 * 항목 설명 세 칸(영향 → 판단 이유 → 바꿀 점). 규칙 항목 중에는 영향과 이유에
 * 같은 문장을 넣어 둔 것이 있어, 앞 칸과 같은 문장은 건너뛴다.
 */
function explanationBlocks(f: SecurityFinding): { key: string; label: string; text: string }[] {
  const norm = (s: string) => s.replace(/\s+/g, " ").trim();
  const candidates = [
    { key: "impact", label: "어떤 일이 생길 수 있나요", text: f.humanReadableImpact ?? "" },
    { key: "why", label: "왜 이렇게 판단했나요", text: f.whyItMatters ?? "" },
    { key: "fix", label: "이렇게 바꿔 주세요", text: f.remediation ?? "" },
  ];
  const out: typeof candidates = [];
  for (const c of candidates) {
    if (!norm(c.text)) continue;
    if (out.some((prev) => norm(prev.text) === norm(c.text))) continue;
    out.push(c);
  }
  return out;
}

function TechnicalRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="font-bold text-ink-subtle">{label}</dt>
      <dd className="mt-0.5 break-all text-ink">{value}</dd>
    </div>
  );
}
