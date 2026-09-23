import type { SeverityCounts, Severity } from "@/lib/domain/types";

const SEV_DOT: Record<Severity, string> = {
  critical: "bg-red-600",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-cyan-500",
};

export function SeverityStrip({
  counts,
  resolved,
}: {
  counts: SeverityCounts;
  resolved: number;
}) {
  return (
    <div className="flex flex-wrap items-center gap-3 text-sm">
      {(["critical", "high", "medium", "low"] as Severity[]).map((s) => (
        <span key={s} className="flex items-center gap-1.5">
          <span className={`h-2.5 w-2.5 rounded-full ${SEV_DOT[s]}`} />
          <span className="capitalize text-slate-600">{s}</span>
          <span className="font-semibold text-slate-900">{counts[s]}</span>
        </span>
      ))}
      <span className="flex items-center gap-1.5">
        <span className="h-2.5 w-2.5 rounded-full bg-emerald-500" />
        <span className="text-slate-600">Verified</span>
        <span className="font-semibold text-slate-900">{resolved}</span>
      </span>
    </div>
  );
}
