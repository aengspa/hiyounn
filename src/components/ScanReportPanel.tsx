"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import type { ScanReport } from "@/lib/domain/types";
import { HoiSpeech } from "@/components/mascot/HoiSpeech";
import { Badge, Button, Card, TechnicalDetails } from "@/components/ui";

/** 해결 순서를 정리하고 첫 unresolved finding의 기존 ?fix=1 진입점을 유지합니다. */
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
    <section id="solution" className="scroll-mt-32 pt-10" aria-labelledby="solution-title">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-sm font-extrabold text-brand-700">호이의 해결 가이드</p>
        <Badge tone={report.source === "llm" ? "info" : "neutral"}>
          {report.source === "llm" ? "AI가 정리했어요" : "규칙으로 정리했어요"}
        </Badge>
      </div>
      <h2 id="solution-title" className="mt-1 text-2xl font-black tracking-tight text-ink">해결은 이렇게 시작해요</h2>

      <HoiSpeech mood="guide" size="sm" className="mt-5">
        {report.recommendation}
      </HoiSpeech>

      {report.highlights.length > 0 && (
        <Card variant="warm" className="mt-5 p-5">
          <h3 className="font-extrabold text-ink">해결할 때 기억할 점</h3>
          <ul className="mt-3 space-y-2">
            {report.highlights.map((highlight, index) => (
              <li key={index} className="flex gap-3 text-sm leading-relaxed text-ink-subtle">
                <span aria-hidden="true" className="mt-2 h-2 w-2 shrink-0 rounded-full bg-brand-600" />
                <span>{highlight}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <Card variant="raised" className="mt-5 p-5 sm:p-6">
        {!asked ? (
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h3 className="font-extrabold text-ink">
                {canFix ? "가장 급한 미해결 항목부터 볼까요?" : "지금 바로 시작할 미해결 항목은 없어요"}
              </h3>
              <p className="mt-1 text-sm leading-relaxed text-ink-subtle">
                {canFix
                  ? "상세 근거를 읽은 뒤 수정안을 만들지 직접 승인할 수 있어요."
                  : "이 결과만으로 서비스 전체의 안전을 보장하지는 않아요. 점검 범위와 한계를 함께 확인해 주세요."}
              </p>
            </div>
            <Button onClick={() => setAsked(true)} disabled={!canFix} className="w-full sm:w-auto">
              {canFix ? "첫 문제 해결 시작" : "해결할 항목 없음"}
            </Button>
          </div>
        ) : (
          <div role="group" aria-labelledby="start-fix-title">
            <h3 id="start-fix-title" className="font-extrabold text-ink">이 항목의 해결 가이드로 이동할까요?</h3>
            <p className="mt-2 text-sm leading-relaxed text-ink-subtle">
              이동만으로 수정안이 생성되거나 코드가 바뀌지 않아요. 상세 내용을 확인한 뒤 각 단계를 직접 승인합니다.
            </p>
            <div className="mt-4 flex flex-col gap-2 sm:flex-row">
              <Button
                onClick={() => router.push(`/dashboard/findings/${firstFixableFindingId}?fix=1`)}
                className="w-full sm:w-auto"
              >
                확인하고 이동
              </Button>
              <Button variant="secondary" onClick={() => setAsked(false)} className="w-full sm:w-auto">
                더 둘러보기
              </Button>
            </div>
          </div>
        )}
      </Card>

      <TechnicalDetails summary="보고서 생성 정보 보기" className="mt-4">
        <dl className="grid gap-3 text-sm sm:grid-cols-2">
          <div><dt className="font-bold text-ink-muted">생성 방식</dt><dd className="mt-1 text-ink">{report.source === "llm" ? "AI 모델" : "결정적 규칙"}</dd></div>
          <div><dt className="font-bold text-ink-muted">생성 시각</dt><dd className="mt-1 text-ink">{new Date(report.generatedAt).toLocaleString("ko-KR")}</dd></div>
        </dl>
        {report.source === "llm" && (
          <p className="mt-4 rounded-2xl bg-info-soft p-3 text-sm text-info">
            AI 요약은 이해를 돕기 위한 안내예요. 심각도, 상태, 점검 근거와 재검증 결과가 우선합니다.
          </p>
        )}
      </TechnicalDetails>
    </section>
  );
}
