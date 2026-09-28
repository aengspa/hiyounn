/** 스캔 범위를 3칸 막대로 보여준다. A=1칸, B=2칸, C=3칸. */
export function ScanScopeMeter({
  scope,
  className = "",
}: {
  scope: 1 | 2 | 3;
  className?: string;
}) {
  const label = scope === 1 ? "좁음" : scope === 2 ? "보통" : "넓음";
  const fill = ["bg-green-500", "bg-amber-500", "bg-red-500"];
  return (
    <div className={className}>
      <div className="flex items-center justify-between text-xs font-bold text-ink-muted">
        <span>스캔 범위</span>
        <span>{label}</span>
      </div>
      <div
        className="mt-1.5 flex gap-1.5"
        role="meter"
        aria-label="스캔 범위"
        aria-valuemin={1}
        aria-valuemax={3}
        aria-valuenow={scope}
        aria-valuetext={`3단계 중 ${scope}단계 (${label})`}
      >
        {[1, 2, 3].map((i) => (
          <span
            key={i}
            className={`h-2.5 flex-1 rounded-full ${i <= scope ? fill[scope - 1] : "bg-line"}`}
          />
        ))}
      </div>
    </div>
  );
}
