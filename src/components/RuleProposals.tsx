"use client";

import { useState } from "react";
import type { CustomRule } from "@/lib/domain/types";
import { Badge, Button, SeverityBadge } from "@/components/ui";

const STATUS_TEXT: Record<CustomRule["status"], string> = {
  proposed: "승인 대기",
  approved: "승인함 · 다음 점검부터 규칙으로 돌아요",
  rejected: "거절함",
};

/**
 * AI만 찾은 문제에서 AI가 제안한 규칙. 사람이 승인하면 이 사용자의 이후 점검에서
 * 규칙(기준)으로 돈다. 제안 때 서버가 패턴이 원래 줄을 잡는지, 너무 넓지 않은지,
 * 시간 안에 도는지 확인했다.
 */
export function RuleProposals({ rules }: { rules: CustomRule[] }) {
  const [items, setItems] = useState(rules);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function decide(rule: CustomRule, decision: "approve" | "reject") {
    setBusy(rule.id);
    setError(null);
    try {
      const res = await fetch(`/api/custom-rules/${encodeURIComponent(rule.id)}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ decision }),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data?.rule) throw new Error(data?.message ?? "처리하지 못했어요.");
      setItems((list) => list.map((r) => (r.id === rule.id ? (data.rule as CustomRule) : r)));
    } catch (e) {
      setError(e instanceof Error ? e.message : "처리하지 못했어요.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="mt-10" aria-labelledby="rule-proposals-title">
      <details open className="rounded-3xl border border-line bg-surface p-4 sm:p-5">
        <summary id="rule-proposals-title" className="cursor-pointer text-base font-bold text-ink">
          AI가 제안한 규칙 ({items.length}개)
        </summary>
        <p className="mt-2 text-sm text-ink-subtle">
          AI만 찾은 문제를 다음부터 규칙으로도 잡을 수 있게 만든 제안이에요. 승인해야 규칙으로 쓰여요. 아래 “잡는 줄”은 이 프로젝트에서 이 규칙이 잡는 곳이에요.
        </p>
        {error && <p role="alert" className="mt-2 text-sm text-danger">{error}</p>}
        <ul className="mt-3 space-y-3">
          {items.map((r) => (
            <li key={r.id} className="rounded-2xl border border-line p-3">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={r.severity} />
                <Badge tone={r.status === "approved" ? "success" : r.status === "rejected" ? "neutral" : "warning"}>{STATUS_TEXT[r.status]}</Badge>
                {r.cwe && <span className="text-xs text-ink-muted">{r.cwe}</span>}
              </div>
              <p className="mt-2 font-bold text-ink">{r.title}</p>
              {r.rationale && <p className="mt-1 text-sm text-ink-subtle">{r.rationale}</p>}
              <pre className="mt-2 overflow-x-auto rounded-xl bg-surface-warm p-2 text-xs">
                <code>
                  /{r.pattern}/{r.flags}
                  {r.safePattern ? `   안전 예외: /${r.safePattern}/` : ""}
                </code>
              </pre>
              <p className="mt-2 text-xs font-bold text-ink-muted">잡는 줄</p>
              <ul className="mt-1 space-y-1">
                {r.preview.map((h, i) => (
                  <li key={i} className="overflow-x-auto font-mono text-xs text-ink">
                    <span className="text-ink-muted">
                      {h.file}:{h.line}
                    </span>{" "}
                    {h.text}
                  </li>
                ))}
              </ul>
              {r.status === "proposed" && (
                <div className="mt-3 flex gap-2">
                  <Button onClick={() => decide(r, "approve")} disabled={busy !== null} aria-busy={busy === r.id}>
                    승인하기
                  </Button>
                  <Button variant="secondary" onClick={() => decide(r, "reject")} disabled={busy !== null}>
                    거절하기
                  </Button>
                </div>
              )}
            </li>
          ))}
        </ul>
      </details>
    </section>
  );
}
