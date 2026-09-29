import { formatLocation } from "@/lib/ui/groupFindings";

const VISIBLE = 5;

/**
 * 같은 문제가 발견된 위치 목록(파일:줄). 긴 경로는 줄바꿈하고,
 * 5곳을 넘으면 나머지는 접어 둔다.
 */
export function FindingLocations({ locations, className = "" }: { locations: { file: string; line: number }[]; className?: string }) {
  if (locations.length === 0) return null;
  const head = locations.slice(0, VISIBLE);
  const rest = locations.slice(VISIBLE);
  const item = (l: { file: string; line: number }) => (
    <li key={formatLocation(l)} className="break-all font-mono text-xs leading-relaxed text-ink">
      {formatLocation(l)}
    </li>
  );
  return (
    <div className={`min-w-0 rounded-2xl border-2 border-line bg-surface-warm p-3 ${className}`}>
      <h4 className="text-sm font-bold text-brand-800">발견된 위치</h4>
      <ul className="mt-1 space-y-0.5">{head.map(item)}</ul>
      {rest.length > 0 && (
        <details className="mt-1">
          <summary className="flex min-h-11 cursor-pointer items-center text-sm font-bold text-brand-800 hover:text-brand-900">
            나머지 {rest.length}곳 더 보기
          </summary>
          <ul className="space-y-0.5">{rest.map(item)}</ul>
        </details>
      )}
    </div>
  );
}
