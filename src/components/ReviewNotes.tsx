import type { ExploitCheck, ReverifyEvidence, ReverifyVerdict, SecurityFinding } from "@/lib/domain/types";

const VERDICT_TEXT: Record<ReverifyVerdict, string> = {
  fixed_in_source: "해결됨",
  still_present: "아직 남아 있음",
  inconclusive: "판단 못 함",
  false_positive: "오탐(실제 취약점 아님)",
};

const VERDICT_TONE: Record<ReverifyVerdict, string> = {
  fixed_in_source: "text-success",
  still_present: "text-danger",
  inconclusive: "text-warning",
  false_positive: "text-ink-subtle",
};

const EXPLOIT_TEXT: Record<ExploitCheck["status"], string> = {
  blocked: "원본에서는 공격이 성공했고, 수정본에서는 막혔어요",
  still_exploitable: "수정본에서도 공격이 성공했어요",
  not_reproduced: "원본에서도 공격이 재현되지 않아 이 테스트로는 판단하지 않았어요",
  error: "테스트를 실행하지 못했어요",
  not_run: "실행하지 않았어요",
};

function EvidenceList({ evidence }: { evidence: ReverifyEvidence[] }) {
  if (evidence.length === 0) return null;
  return (
    <ul className="mt-2 space-y-2">
      {evidence.map((e, i) => (
        <li key={i} className="overflow-hidden rounded-xl border border-line">
          <div className="border-b border-line bg-surface-warm px-3 py-1 font-mono text-xs text-ink-muted">{e.file}</div>
          <pre className="overflow-x-auto px-3 py-1.5 text-xs leading-5 text-ink">
            <code>{e.snippet}</code>
          </pre>
          {e.explanation && <p className="border-t border-line px-3 py-1.5 text-xs text-ink-subtle">{e.explanation}</p>}
        </li>
      ))}
    </ul>
  );
}

export interface VerifyNoteItem {
  verdict: ReverifyVerdict;
  method?: string;
  reasonCode?: string;
  ruleVerdict?: ReverifyVerdict;
  ruleSummary?: string;
  aiVerdict?: ReverifyVerdict;
  aiSummary?: string;
  summary?: string;
  evidence: ReverifyEvidence[];
  exploit?: ExploitCheck;
}

/** 재검증에서 규칙·AI·공격 재현 테스트가 각각 뭐라고 했는지. */
export function VerifyNote({ item, fallback }: { item: VerifyNoteItem; fallback?: string }) {
  const ruleText = item.ruleSummary;
  const aiText = item.aiSummary;
  return (
    <section aria-label="재검증 코멘트" className="mt-3 rounded-2xl border border-line bg-surface-warm p-3 text-sm leading-relaxed">
      <h4 className="text-xs font-bold text-ink-muted">재검증 코멘트</h4>
      {ruleText && (
        <p className="mt-1.5">
          <span className="font-bold text-ink">규칙 재검사</span>
          {item.ruleVerdict && <span className={`ml-1 font-bold ${VERDICT_TONE[item.ruleVerdict]}`}>· {VERDICT_TEXT[item.ruleVerdict]}</span>}
          <span className="block text-ink-subtle">{ruleText}</span>
        </p>
      )}
      {aiText && (
        <p className="mt-1.5">
          <span className="font-bold text-ink">AI 코멘트</span>
          {item.aiVerdict && <span className={`ml-1 font-bold ${VERDICT_TONE[item.aiVerdict]}`}>· {VERDICT_TEXT[item.aiVerdict]}</span>}
          <span className="block text-ink-subtle">{aiText}</span>
        </p>
      )}
      {!ruleText && !aiText && (item.summary || fallback) && <p className="mt-1.5 text-ink-subtle">{item.summary || fallback}</p>}
      {item.exploit && item.exploit.status !== "not_run" && (
        <div className="mt-1.5">
          <span className="font-bold text-ink">공격 재현 테스트</span>
          <span
            className={`ml-1 font-bold ${
              item.exploit.status === "blocked" ? "text-success" : item.exploit.status === "still_exploitable" ? "text-danger" : "text-warning"
            }`}
          >
            · {EXPLOIT_TEXT[item.exploit.status]}
          </span>
          <span className="block text-ink-subtle">{item.exploit.detail}</span>
          {item.exploit.testCode && (
            <details className="mt-1">
              <summary className="cursor-pointer text-xs font-bold text-brand-800">AI가 작성한 테스트 코드 보기</summary>
              <pre className="mt-1 overflow-x-auto rounded-xl border border-line bg-surface p-2 text-xs leading-5">
                <code>{item.exploit.testCode}</code>
              </pre>
            </details>
          )}
        </div>
      )}
      <EvidenceList evidence={item.evidence} />
    </section>
  );
}

type Adjudication = NonNullable<NonNullable<SecurityFinding["aiReview"]>["adjudication"]>;

const ADJ_TEXT: Record<Adjudication["verdict"], string> = {
  not_vulnerable: "실제 취약점이 아니에요(오탐)",
  vulnerable: "실제 취약점이에요",
  unsure: "판단을 보류했어요",
};

/** 오탐 의견이 붙은 규칙 항목을 AI가 근거와 함께 다시 판정한 결과. */
export function AdjudicationNote({ adjudication }: { adjudication: Adjudication }) {
  return (
    <section aria-label="AI 재판정" className="mt-3 rounded-2xl border border-line bg-surface-warm p-3 text-sm leading-relaxed">
      <h4 className="text-xs font-bold text-ink-muted">AI 재판정 (규칙 결과가 실제 취약점인지)</h4>
      <p className="mt-1.5">
        <span
          className={`font-bold ${
            adjudication.verdict === "not_vulnerable" ? "text-ink-subtle" : adjudication.verdict === "vulnerable" ? "text-danger" : "text-warning"
          }`}
        >
          {ADJ_TEXT[adjudication.verdict]}
        </span>
        {adjudication.reason && <span className="block text-ink-subtle">{adjudication.reason}</span>}
      </p>
      <EvidenceList evidence={adjudication.evidence} />
    </section>
  );
}
