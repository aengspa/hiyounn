"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import type { ScanReport } from "@/lib/domain/types";

/**
 * 스캔 결과 보고서 패널 + "수정하시겠습니까?" 확인 UI.
 *
 * 확인을 누르면 첫 번째 수정 대상 취약점 상세 페이지로 이동해 기존 수정
 * 파이프라인(수정안 생성 → 적용 → 검증)으로 진입합니다.
 */
export function ScanReportPanel({
  report,
  firstFixableFindingId,
}: {
  report: ScanReport;
  firstFixableFindingId?: string;
}) {
  const router = useRouter();
  const [asked, setAsked] = useState(false);

  const canFix = Boolean(firstFixableFindingId);

  return (
    <section className="mt-6 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="flex items-center gap-2">
        <h2 className="text-lg font-semibold text-slate-900">보안 보고서</h2>
        <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[11px] font-normal text-slate-500">
          {report.source === "llm" ? "AI 생성" : "자동 요약"}
        </span>
      </div>

      <p className="mt-3 leading-relaxed text-slate-700">{report.summary}</p>

      {report.highlights.length > 0 && (
        <ul className="mt-4 space-y-1.5">
          {report.highlights.map((h, i) => (
            <li key={i} className="flex gap-2 text-sm text-slate-600">
              <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-slate-400" />
              <span>{h}</span>
            </li>
          ))}
        </ul>
      )}

      <div className="mt-4 rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-600">
        <span className="font-medium text-slate-700">권장 다음 단계 · </span>
        {report.recommendation}
      </div>

      {/* 수정 확인 */}
      <div className="mt-6 border-t border-slate-100 pt-5">
        {!asked ? (
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-slate-700">
              발견된 문제를 지금 수정하시겠습니까?
            </p>
            <button
              onClick={() => setAsked(true)}
              disabled={!canFix}
              className="rounded-lg bg-slate-800 px-4 py-2 font-medium text-white hover:bg-slate-900 disabled:opacity-60"
            >
              {canFix ? "수정 진행" : "수정할 항목 없음"}
            </button>
          </div>
        ) : (
          <div className="rounded-lg border border-slate-300 bg-slate-50 p-4">
            <p className="font-medium text-slate-800">
              수정을 진행할까요?
            </p>
            <p className="mt-1 text-sm text-slate-600">
              확인을 누르면 AI가 수정안을 생성하고, 적용 후 같은 공격이 막히는지
              검증하는 단계로 이동합니다.
            </p>
            <div className="mt-4 flex gap-3">
              <button
                onClick={() =>
                  router.push(`/dashboard/findings/${firstFixableFindingId}?fix=1`)
                }
                className="rounded-lg bg-slate-800 px-4 py-2 font-medium text-white hover:bg-slate-900"
              >
                확인, 수정 시작
              </button>
              <button
                onClick={() => setAsked(false)}
                className="rounded-lg border border-slate-300 bg-white px-4 py-2 font-medium text-slate-700 hover:bg-slate-50"
              >
                취소
              </button>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
