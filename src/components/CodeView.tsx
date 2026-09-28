import type { CodeContext } from "@/lib/ui/codeContext";

/**
 * 발견 위치의 실제 코드. 문제가 된 줄을 강조하고 위아래 몇 줄을 함께 보여 준다.
 * 비밀값은 서버에서 이미 가린 상태로 들어온다.
 */
export function CodeView({ code, caption }: { code: CodeContext; caption?: string }) {
  return (
    <figure className="mt-3 overflow-hidden rounded-2xl border border-line bg-surface-warm">
      <figcaption className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-3 py-1.5 text-xs text-ink-muted">
        <span className="break-all font-mono">
          {code.file}:{code.highlight[0]}
          {code.highlight.length > 1 ? `–${code.highlight[code.highlight.length - 1]}` : ""}
        </span>
        {caption && <span>{caption}</span>}
      </figcaption>
      <pre className="overflow-x-auto py-1 text-xs leading-5">
        <code>
          {code.lines.map((text, i) => {
            const n = code.startLine + i;
            const hot = code.highlight.includes(n);
            return (
              <div key={n} className={`flex min-w-max ${hot ? "bg-danger-soft" : ""}`}>
                <span className="w-12 shrink-0 select-none pr-3 text-right text-ink-muted">{n}</span>
                <span className={`whitespace-pre pr-4 ${hot ? "font-bold text-danger" : "text-ink"}`}>
                  {hot && <span className="sr-only">문제가 된 줄: </span>}
                  {text || " "}
                </span>
              </div>
            );
          })}
        </code>
      </pre>
    </figure>
  );
}
