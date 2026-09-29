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

/** 색 없이도 결론을 구분하는 표시. 옆의 글자가 뜻을 전하므로 aria-hidden으로 둔다. */
const VERDICT_MARK: Record<ReverifyVerdict, string> = {
  fixed_in_source: "✓",
  still_present: "✕",
  inconclusive: "?",
  false_positive: "−",
};

const EXPLOIT_TEXT: Record<ExploitCheck["status"], string> = {
  blocked: "고치기 전에는 같은 방식으로 문제가 생겼고, 고친 뒤에는 막혔어요",
  still_exploitable: "고친 뒤에도 같은 방식으로 문제가 생겨요",
  not_reproduced: "고치기 전 코드에서도 문제가 재현되지 않아 이 테스트로는 판단하지 않았어요",
  error: "테스트를 실행하지 못해 이 방법으로는 확인하지 못했어요",
  not_run: "실행하지 않았어요",
};

const EXPLOIT_MARK: Record<ExploitCheck["status"], string> = {
  blocked: "✓",
  still_exploitable: "✕",
  not_reproduced: "?",
  error: "?",
  not_run: "○",
};

function Mark({ children }: { children: string }) {
  return (
    <span aria-hidden="true" className="mr-1 inline-block w-4 text-center font-extrabold">
      {children}
    </span>
  );
}

/** 근거 코드(파일 경로·인용 코드)는 기술 정보라 펼쳐 볼 때만 보여 준다. */
function EvidenceList({ evidence, summary = "근거 코드 보기" }: { evidence: ReverifyEvidence[]; summary?: string }) {
  if (evidence.length === 0) return null;
  return (
    <details className="mt-3">
      <summary className="flex min-h-11 cursor-pointer items-center text-sm font-bold text-brand-800 hover:underline">
        {summary} ({evidence.length}개)
      </summary>
      <ul className="mt-2 space-y-2">
        {evidence.map((e, i) => (
          <li key={i} className="overflow-hidden rounded-xl border-2 border-line bg-surface">
            <div className="break-all border-b border-line bg-surface-warm px-3 py-1 font-mono text-xs text-ink-muted">{e.file}</div>
            <pre className="overflow-x-auto px-3 py-1.5 text-xs leading-5 text-ink">
              <code>{e.snippet}</code>
            </pre>
            {e.explanation && <p className="break-words border-t border-line px-3 py-2 text-sm leading-relaxed text-ink">{e.explanation}</p>}
          </li>
        ))}
      </ul>
    </details>
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

/**
 * 재검증에서 규칙·AI·공격 재현 테스트가 각각 뭐라고 했는지(판단 근거).
 * `shownText`는 같은 카드에 이미 보여 준 상태 문장이다. 같은 문장을 두 번 쓰지 않는다.
 */
export function VerifyNote({ item, shownText }: { item: VerifyNoteItem; shownText?: string }) {
  const ruleText = item.ruleSummary;
  const aiText = item.aiSummary;
  const summary = item.summary?.trim();
  const showSummary = Boolean(!ruleText && !aiText && summary && !(shownText ?? "").includes(summary));
  const showExploit = Boolean(item.exploit && item.exploit.status !== "not_run");
  if (!ruleText && !aiText && !showSummary && !showExploit && item.evidence.length === 0) return null;
  return (
    <section aria-label="재검증 근거" className="mt-4 border-t-2 border-dashed border-line pt-4 text-base leading-relaxed">
      <h5 className="text-sm font-bold text-ink">재검증 근거</h5>
      {ruleText && (
        <p className="mt-2 break-words">
          <span className="font-bold text-ink">규칙 재검사</span>
          {item.ruleVerdict && (
            <span className={`ml-1 font-bold ${VERDICT_TONE[item.ruleVerdict]}`}>
              · <Mark>{VERDICT_MARK[item.ruleVerdict]}</Mark>
              {VERDICT_TEXT[item.ruleVerdict]}
            </span>
          )}
          <span className="block text-ink">{ruleText}</span>
        </p>
      )}
      {aiText && (
        <p className="mt-2 break-words">
          <span className="font-bold text-ink">AI 재검토</span>
          {item.aiVerdict && (
            <span className={`ml-1 font-bold ${VERDICT_TONE[item.aiVerdict]}`}>
              · <Mark>{VERDICT_MARK[item.aiVerdict]}</Mark>
              {VERDICT_TEXT[item.aiVerdict]}
            </span>
          )}
          <span className="block text-ink">{aiText}</span>
        </p>
      )}
      {showSummary && <p className="mt-2 break-words text-ink">{summary}</p>}
      {showExploit && item.exploit && (
        <div className="mt-2 break-words">
          <span className="font-bold text-ink">같은 방식으로 다시 시도해 본 결과</span>
          <span
            className={`ml-1 font-bold ${
              item.exploit.status === "blocked" ? "text-success" : item.exploit.status === "still_exploitable" ? "text-danger" : "text-warning"
            }`}
          >
            · <Mark>{EXPLOIT_MARK[item.exploit.status]}</Mark>
            {EXPLOIT_TEXT[item.exploit.status]}
          </span>
          {item.exploit.detail && <span className="block text-ink">{item.exploit.detail}</span>}
          {item.exploit.testCode && (
            <details className="mt-1">
              <summary className="flex min-h-11 cursor-pointer items-center text-sm font-bold text-brand-800 hover:underline">
                AI가 작성한 테스트 코드 보기
              </summary>
              <pre className="mt-1 overflow-x-auto rounded-xl border-2 border-line bg-surface p-2 text-xs leading-5">
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

const ADJ_MARK: Record<Adjudication["verdict"], string> = {
  not_vulnerable: "−",
  vulnerable: "✕",
  unsure: "?",
};

/** 오탐 의견이 붙은 규칙 항목을 AI가 근거와 함께 다시 판정한 결과. */
export function AdjudicationNote({ adjudication }: { adjudication: Adjudication }) {
  return (
    <section aria-label="AI 재판정" className="mt-4 rounded-2xl border-2 border-line bg-surface-warm p-4 text-base leading-relaxed">
      <h4 className="text-sm font-bold text-ink">AI가 다시 판단했어요 (규칙이 찾은 내용이 실제 문제인지)</h4>
      <p className="mt-2 break-words">
        <span
          className={`font-bold ${
            adjudication.verdict === "not_vulnerable" ? "text-ink-subtle" : adjudication.verdict === "vulnerable" ? "text-danger" : "text-warning"
          }`}
        >
          <Mark>{ADJ_MARK[adjudication.verdict]}</Mark>
          {ADJ_TEXT[adjudication.verdict]}
        </span>
        {adjudication.reason && <span className="block text-ink">{adjudication.reason}</span>}
      </p>
      <EvidenceList evidence={adjudication.evidence} />
    </section>
  );
}
