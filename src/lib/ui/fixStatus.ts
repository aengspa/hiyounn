/**
 * 항목 상태 라벨 (심각도와 별개).
 *
 *   fixing        "지금 수정해요"          전체 수정이 이 항목을 처리하는 중
 *   needs_check   "점검이 필요해요"        아직 고치지 않았거나, 재검증 전이거나, 결론을 못 냄
 *   not_fixed     "자동으로 못 고쳤어요"    자동 수정 방법이 없거나 적용하지 못함(직접 고쳐야 함)
 *   resolved      "해결 확인했어요"        규칙 재검사로 수정본에서 문제가 사라진 것을 확인
 *   resolved_ai   "AI가 해결로 판단했어요"  규칙으로 볼 수 없는 항목을 AI가 수정본 근거로 판단
 *   still_present "아직 남아 있어요"        수정본에 문제가 남아 있다는 근거가 있음
 *   disputed      "판단이 엇갈려요"        규칙 재검사와 AI 판단이 서로 다름(사람 확인)
 *   false_positive "오탐으로 판정됐어요"    규칙이 잡았지만 AI가 근거 코드로 실제 취약점이 아니라고 판정
 *
 * "해결"은 수정본 코드 기준이다. 배포된 사이트에서 실행해 확인한 결과가
 * 아니므로 detail에 그 사실을 적는다. 서버·클라이언트 모두에서 쓸 수 있도록
 * 서버 전용 모듈을 가져오지 않는다.
 */

export type FixStatusKey =
  | "fixing"
  | "needs_check"
  | "not_fixed"
  | "resolved"
  | "resolved_ai"
  | "still_present"
  | "disputed"
  | "false_positive";

export const FIX_STATUS_LABEL: Record<FixStatusKey, string> = {
  fixing: "지금 수정해요",
  needs_check: "점검이 필요해요",
  not_fixed: "자동으로 못 고쳤어요",
  resolved: "해결 확인했어요",
  resolved_ai: "AI가 해결로 판단했어요",
  still_present: "아직 남아 있어요",
  disputed: "판단이 엇갈려요",
  false_positive: "오탐으로 판정됐어요",
};

type Verdict = "fixed_in_source" | "still_present" | "inconclusive" | "false_positive";

export interface FixStatusJobItem {
  findingId: string;
  outcome: "applied" | "apply_failed" | "unsupported" | "skipped";
  reasonCode?: string;
  reason?: string;
}

export interface FixStatusVerifyItem {
  findingId: string;
  verdict: Verdict;
  reasonCode?: string;
  method?: "rule" | "llm" | "rule+llm" | "exploit";
  /** 공격 재현 테스트로 실행 확인했는지. */
  executed?: boolean;
  ruleVerdict?: Verdict;
  aiVerdict?: Verdict;
}

export interface FixStatusInput {
  /** 점검 때 AI가 근거와 함께 오탐으로 판정한 규칙 항목. */
  adjudicatedFalsePositive?: boolean;
  jobStatus?: "running" | "completed" | "partial" | "failed";
  item?: FixStatusJobItem;
  verification?: { status: "running" | "completed" | "failed"; items: FixStatusVerifyItem[] };
}

export interface FixStatus {
  key: FixStatusKey;
  label: string;
  detail: string;
}

function make(key: FixStatusKey, detail: string): FixStatus {
  return { key, label: FIX_STATUS_LABEL[key], detail };
}

const VERDICT_WORD: Record<Verdict, string> = {
  fixed_in_source: "해결됨",
  still_present: "남아 있음",
  inconclusive: "판단 못 함",
  false_positive: "오탐",
};

const SOURCE_ONLY = "수정본 코드 기준이에요. 배포한 사이트는 다시 배포한 뒤 점검해 주세요.";

const FALSE_POSITIVE_DETAIL =
  "규칙은 문제로 봤지만, AI가 근거 코드를 확인해 실제 취약점이 아니라고 판정했어요. 규칙 결과는 기록으로 남겨 두었으니 필요하면 직접 확인해 주세요.";

export function fixStatusFor(findingId: string, input: FixStatusInput): FixStatus {
  const { item, jobStatus, verification } = input;
  // 재검증에서 AI가 오탐으로 판정했으면 수정 여부와 상관없이 그 판정을 보여 준다.
  const verdictItem = verification?.status !== "running" ? verification?.items.find((it) => it.findingId === findingId) : undefined;
  if (verdictItem?.verdict === "false_positive") return make("false_positive", FALSE_POSITIVE_DETAIL);
  // 점검 때 오탐으로 판정된 항목은 전체 수정이 건너뛴다. "못 고침"이 아니라 판정을 보여 준다.
  if (input.adjudicatedFalsePositive) return make("false_positive", FALSE_POSITIVE_DETAIL);
  if (!item) return make("needs_check", "아직 고치지 않았어요.");

  if (jobStatus === "running" && item.reasonCode === "pending") {
    return make("fixing", "이 항목을 고치고 있어요.");
  }
  if (item.outcome === "apply_failed" || item.outcome === "unsupported") {
    return make("not_fixed", item.reason ?? "자동으로 고치지 못했어요. 설명을 보고 직접 고쳐 주세요.");
  }
  if (item.outcome === "skipped") {
    return make("needs_check", item.reason ?? "이번 수정에서 다루지 못했어요.");
  }

  // applied: 재검증 결과로만 해결 여부를 정한다.
  const v = verification?.items.find((it) => it.findingId === findingId);
  if (verification?.status === "running") return make("needs_check", "재검증하고 있어요.");
  if (!v) return make("needs_check", "수정했어요. 재검증으로 확인해 주세요.");

  if (v.reasonCode === "disputed") {
    const rule = v.ruleVerdict ? VERDICT_WORD[v.ruleVerdict] : "-";
    const ai = v.aiVerdict ? VERDICT_WORD[v.aiVerdict] : "-";
    return make("disputed", `규칙 재검사(${rule})와 AI 판단(${ai})이 달라요. 바뀐 코드를 직접 확인해 주세요.`);
  }
  if (v.verdict === "fixed_in_source") {
    if (v.executed) {
      return make(
        "resolved",
        `공격 재현 테스트가 원본에서는 성공하고 수정본에서는 막힌 것을 격리 환경에서 실행으로 확인했어요. ${SOURCE_ONLY}`
      );
    }
    if (v.method === "llm") {
      return make(
        "resolved_ai",
        `규칙으로 확인할 수 없는 항목이라 AI가 수정본 코드를 보고 판단했어요. 바뀐 코드를 한 번 더 확인해 주세요. ${SOURCE_ONLY}`
      );
    }
    const both = v.method === "rule+llm" ? " AI 판단도 같았어요." : "";
    return make("resolved", `규칙 재검사로 문제가 사라진 것을 확인했어요.${both} ${SOURCE_ONLY}`);
  }
  if (v.verdict === "still_present") {
    if (v.reasonCode === "exploit_succeeded_after_fix") {
      return make("still_present", "공격 재현 테스트가 수정본에서도 성공했어요. 수정이 공격을 막지 못해요.");
    }
    return make("still_present", "수정본 코드에 문제가 아직 남아 있어요. 설명을 보고 직접 고쳐 주세요.");
  }
  switch (v.reasonCode) {
    case "ai_failed":
      return make("needs_check", "AI 재검증을 완료하지 못했어요. 다시 시도해 주세요.");
    case "ai_not_available":
      return make("needs_check", "규칙으로 확인할 수 없고 AI 재검증도 쓸 수 없어 확인하지 못했어요. 직접 확인해 주세요.");
    case "dep_recheck_unavailable":
      return make(
        "needs_check",
        "올린 버전을 다시 조회하지 못했어요. 잠금 파일(package-lock.json)이 있으면 npm install로 갱신한 뒤 다시 점검해 주세요."
      );
    case "rule_unavailable":
      return make("needs_check", "규칙 재검사를 할 수 없었어요. 직접 확인해 주세요.");
    default:
      return make("needs_check", "재검증에서 결론을 내리지 못했어요. 직접 확인해 주세요.");
  }
}
