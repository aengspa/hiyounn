"use client";

import { useState } from "react";
import { PageHeader } from "@/components/PageHeader";
import { SeverityBadge, Evidence, categoryLabel } from "@/components/ui";
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
        setError(data?.error ?? "검사에 실패했습니다.");
        return;
      }
      setResult(data);
    } catch {
      setError("네트워크 오류입니다. 다시 시도해 주세요.");
    } finally {
      setRunning(false);
    }
  }

  return (
    <>
      <PageHeader
        title="빠른 코드 확인"
        subtitle="붙여넣은 코드만 정적으로 훑어봅니다. 프로젝트로 저장되지 않고, 결과도 기록되지 않습니다."
        backHref="/dashboard"
        backLabel="프로젝트"
      />
      <main className="mx-auto max-w-4xl px-6 py-8">
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <label className="mb-1 block text-sm font-medium text-slate-700">
            코드 붙여넣기
          </label>
          <p className="mb-2 text-xs text-slate-500">
            여러 파일은 <code className="rounded bg-slate-100 px-1">// file: 경로</code>{" "}
            주석으로 구분하면 파일별로 나눠 검사합니다.
          </p>
          <textarea
            value={source}
            onChange={(e) => setSource(e.target.value)}
            rows={12}
            placeholder={`// file: src/api/todos/[id].ts\nexport async function GET(req, { params }) {\n  const todo = await db.todos.findUnique({ where: { id: params.id } });\n  return Response.json(todo); // 소유자 확인 없음 → IDOR\n}`}
            className="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-100"
          />
          <div className="mt-3 flex items-center gap-3">
            <button
              onClick={run}
              disabled={running || !source.trim()}
              className="rounded-lg bg-brand-600 px-4 py-2 font-medium text-white hover:bg-brand-700 disabled:opacity-60"
            >
              {running ? "검사 중…" : "빠른 검사 실행"}
            </button>
            {error && (
              <span role="alert" className="text-sm text-red-600">
                {error}
              </span>
            )}
          </div>
        </div>

        {/* 한계 명시 — "안전"이라고 오인하지 않도록 */}
        <div className="mt-4 rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-800">
          <strong>이 빠른 검사가 하지 않는 것:</strong> 의존성(CVE) 검사, 여러
          파일에 걸친 데이터 흐름, Git 이력, 배포/런타임(DAST), 공격 재현·검증.
          발견이 없다고 “안전”한 것은 아닙니다. 전체 검사는 프로젝트로 만들어 스캔하세요.
        </div>

        {result && <QuickResults result={result} />}
      </main>
    </>
  );
}

function QuickResults({ result }: { result: QuickResult }) {
  const { findings, scannedFiles } = result;
  return (
    <section className="mt-8">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-slate-900">
          발견 {findings.length}건
        </h2>
        <span className="text-xs text-slate-500">
          검사한 파일 {scannedFiles.length}개
        </span>
      </div>

      {findings.length === 0 ? (
        <p className="mt-3 rounded-lg border border-slate-200 bg-white p-4 text-sm text-slate-600">
          이 정적 검사 범위에서는 신호가 발견되지 않았습니다. (위의 한계를
          참고하세요 — 이것이 “안전” 판정은 아닙니다.)
        </p>
      ) : (
        <div className="mt-3 space-y-3">
          {findings.map((f) => (
            <div
              key={f.id}
              className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm"
            >
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={f.severity} />
                {f.ruleId && (
                  <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[11px] font-medium text-slate-600">
                    {f.ruleId}
                  </span>
                )}
                <span className="text-xs text-slate-400">
                  {categoryLabel(f.category)}
                </span>
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
              {f.evidence[0] && (
                <div className="mt-3">
                  <Evidence
                    label={f.evidence[0].label}
                    content={f.evidence[0].content}
                  />
                </div>
              )}
              {f.remediation && (
                <div className="mt-3 rounded-lg border border-brand-100 bg-brand-50 p-3 text-sm text-brand-900">
                  <span className="font-medium">권장 조치 · </span>
                  {f.remediation}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
