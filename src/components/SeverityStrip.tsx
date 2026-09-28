import type { SeverityCounts, Severity } from "@/lib/domain/types";
import { SEV_LABEL, SeverityIcon } from "@/components/ui";
import { severityDisplay } from "@/lib/ui/presentation";

export type { SeverityCounts } from "@/lib/domain/types";

const ORDER: Severity[] = ["critical", "high", "medium", "low"];

// ui.tsx SEV_STYLE와 같은 배경·글자색 조합. critical에도 animation 클래스를 붙이지 않는다(요구사항 2.12).
const CHIP_STYLE: Record<Severity, string> = {
  critical: "border-[#f3c4bd] bg-danger-soft text-danger",
  high: "border-brand-300 bg-primary-soft text-brand-800",
  medium: "border-[#f0d9a6] bg-warning-soft text-warning",
  low: "border-[#c9def3] bg-info-soft text-info",
};

const CHIP_BASE = "inline-flex min-h-9 items-center gap-1.5 rounded-2xl border px-3 py-1 font-bold";

/** 0 이상 정수만 "받은 수"로 인정한다. 그 밖의 값은 추정하지 않고 불러오기 실패로 본다. */
function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function hasAllCounts(counts: SeverityCounts | null | undefined): counts is SeverityCounts {
  return !!counts && ORDER.every((severity) => isCount(counts[severity]));
}

/**
 * 심각도별 발견 수 요약 막대.
 * 백엔드가 준 정수만 그대로 보여주고, 점수·등급·백분율은 계산하지 않는다(요구사항 8.11).
 * 수를 받지 못하면 0 대신 안내 문구를 보여준다(요구사항 8.12).
 */
export function SeverityStrip({
  counts,
  resolved,
}: {
  counts?: SeverityCounts | null;
  resolved?: number | null;
}) {
  if (!hasAllCounts(counts)) {
    return (
      <p className="text-sm font-medium text-ink-subtle" role="status">
        발견 수를 불러오지 못했어요
      </p>
    );
  }

  return (
    <ul className="flex flex-wrap items-center gap-2 text-sm" aria-label="최신 점검 항목 요약">
      {ORDER.map((severity) => (
        <li key={severity} data-severity={severity} className={`${CHIP_BASE} ${CHIP_STYLE[severity]}`}>
          <SeverityIcon shape={severityDisplay(severity).icon} />
          <span>{SEV_LABEL[severity]}</span>
          <strong className="tabular-nums">{counts[severity]}</strong>
        </li>
      ))}
      {isCount(resolved) && (
        <li className={`${CHIP_BASE} border-[#bfe0c8] bg-success-soft text-success`}>
          <svg viewBox="0 0 16 16" width="12" height="12" className="shrink-0" aria-hidden="true" focusable="false">
            <path
              d="M3 8.5l3.2 3.2L13 5"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          <span>잘 해결했어요</span>
          <strong className="tabular-nums">{resolved}</strong>
        </li>
      )}
    </ul>
  );
}
