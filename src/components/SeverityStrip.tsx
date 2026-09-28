import type { SeverityCounts, Severity } from "@/lib/domain/types";

const SEVERITY: Record<Severity, { label: string; dot: string }> = {
  critical: { label: "지금 확인", dot: "bg-red-600" },
  high: { label: "먼저 고쳐요", dot: "bg-orange-600" },
  medium: { label: "다듬어 봐요", dot: "bg-amber-500" },
  low: { label: "여유 있을 때", dot: "bg-blue-500" },
};

export function SeverityStrip({ counts, resolved }: { counts: SeverityCounts; resolved: number }) {
  return (
    <div className="flex min-w-max flex-wrap items-center gap-x-4 gap-y-2 text-sm" aria-label="최신 점검 항목 요약">
      {(["critical", "high", "medium", "low"] as Severity[]).map((severity) => (
        <span key={severity} className="flex items-center gap-1.5">
          <span className={`h-2.5 w-2.5 rounded-full ${SEVERITY[severity].dot}`} aria-hidden="true" />
          <span className="text-ink-subtle">{SEVERITY[severity].label}</span>
          <strong className="text-ink">{counts[severity]}</strong>
        </span>
      ))}
      <span className="flex items-center gap-1.5">
        <span className="h-2.5 w-2.5 rounded-full bg-green-600" aria-hidden="true" />
        <span className="text-ink-subtle">잘 해결했어요</span>
        <strong className="text-ink">{resolved}</strong>
      </span>
    </div>
  );
}
