/**
 * 항목 상태 라벨 (심각도와 별개).
 *
 *   fixing        "지금 수정해요"          전체 수정이 이 항목을 처리하는 중
 *   needs_check   "점검이 필요해요"        아직 고치지 않았거나, 재검증 전이거나, 결론을 못 냄
 *   not_fixed     "자동으로 못 고쳤어요"    자동 수정 방법이 없거나 적용하지 못함(직접 고쳐야 함)
 *   resolved      "해결 확인했어요"        규칙 재검사(또는 공격 재현 테스트)로 수정본에서 문제가 사라진 것을 확인
 *   resolved_ai   "AI가 해결로 판단했어요"  규칙으로 볼 수 없는 항목을 AI가 수정본 근거로 판단
 *   still_present "아직 남아 있어요"        수정본에 문제가 남아 있다는 근거가 있음
 *   disputed      "판단이 엇갈려요"        규칙 재검사와 AI 판단이 서로 다름(사람 확인)
 *   false_positive "오탐으로 판정됐어요"    규칙이 잡았지만 AI가 근거 코드로 실제 취약점이 아니라고 판정
 *
 * 세 단계를 섞지 않는다: 수정안 만들기 → 파일에 적용 → 재검증.
 * 수정안을 만들거나 적용만 했을 때는 "해결"이라고 말하지 않는다.
 *
 * "해결"은 수정본 코드 기준이다. 배포된 사이트에서 실행해 확인한 결과가
 * 아니므로 note에 그 사실을 적는다. 서버·클라이언트 모두에서 쓸 수 있도록
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

/**
 * 색 없이도 상태를 구분하는 표시(배지 안 아이콘 자리). 화면에서는 aria-hidden으로 두고
 * 옆의 라벨 글자가 뜻을 전한다.
 *   ✓ 확인됨 · ✕ 남아 있음/못 고침 · ? 결론 없음/엇갈림 · … 진행 중 · − 판정으로 제외
 */
export const FIX_STATUS_MARK: Record<FixStatusKey, string> = {
  fixing: "…",
  needs_check: "?",
  not_fixed: "✕",
  resolved: "✓",
  resolved_ai: "✓",
  still_present: "✕",
  disputed: "?",
  false_positive: "−",
};

/**
 * 수정 적용 후 재검증 전 안내. src/lib/fixjobs/fixAllService.ts 의
 * APPLIED_UNVERIFIED_REASON 과 같은 문장이다. 그 모듈은 저장소(store)를 가져오는
 * 서버 전용 모듈이라 클라이언트 코드에서 import하지 않고 문장만 복사해 둔다.
 * 한쪽을 바꾸면 다른 쪽도 함께 바꿔 주세요.
 */
export const APPLIED_UNVERIFIED_MESSAGE = "수정 내용을 적용했어요. 문제가 해결됐는지 다시 확인해 주세요.";

/** 재검증을 다시 돌리는 버튼 글자. 안내 문장에서 같은 이름으로 가리킨다. */
export const VERIFY_BUTTON_LABEL = "재검증하기";
export const REVERIFY_BUTTON_LABEL = "재검증 다시 하기";

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
  /**
   * 재검증 설명. 결론을 못 낸 항목에는 서버(reverifyService)가 원인별 안내
   * (무엇을 확인하지 못했고 무엇이 필요한지)를 채워 둔다. 있으면 그 문장을 우선 쓴다.
   */
  summary?: string;
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
  /** 지금 상태와 다음에 할 일(confirmed + pending 을 이어 붙인 전체 문장). */
  detail: string;
  /** 화면의 "확인된 것": 재검증 등으로 실제로 확인한 사실. 없으면 비움. */
  confirmed?: string;
  /** 화면의 "아직 확인이 필요한 것": 확인하지 못한 부분과 사용자가 할 일. 없으면 비움. */
  pending?: string;
  /**
   * 라벨이 말하는 것보다 확인 범위가 좁을 때 라벨 바로 아래에 보여 줄 짧은 보충 설명
   * (예: 코드만 다시 읽었고 실제 서비스에서 실행하지는 않음).
   */
  note?: string;
}

function make(key: FixStatusKey, parts: { confirmed?: string; pending?: string; note?: string }): FixStatus {
  const detail = [parts.confirmed, parts.pending].filter(Boolean).join(" ");
  const out: FixStatus = { key, label: FIX_STATUS_LABEL[key], detail };
  if (parts.confirmed) out.confirmed = parts.confirmed;
  if (parts.pending) out.pending = parts.pending;
  if (parts.note) out.note = parts.note;
  return out;
}

const VERDICT_WORD: Record<Verdict, string> = {
  fixed_in_source: "해결됨",
  still_present: "남아 있음",
  inconclusive: "판단 못 함",
  false_positive: "오탐",
};

const REDEPLOY = "배포한 사이트에도 반영하려면 받은 파일로 다시 배포한 뒤 한 번 더 점검해 주세요.";

const NOTE_RULE = "코드 기준으로 확인했어요. 실제 서비스에서는 실행해 확인해 주세요.";
const NOTE_AI = "AI가 코드를 읽고 판단한 결과예요. 실제 서비스에서는 실행해 확인해 주세요.";
const NOTE_EXECUTED = "공격 재현 테스트를 실행해 확인했어요. 배포한 사이트는 다시 배포한 뒤 확인해 주세요.";

const FALSE_POSITIVE = {
  confirmed:
    "규칙 검사는 문제로 봤지만, AI가 근거 코드를 확인해 실제 문제는 아니라고 판정했어요. 이 판정은 제공된 코드의 이 부분에만 해당해요.",
  pending: "규칙 결과는 기록으로 남겨 두었어요. 아래 근거 코드를 보고 이 판정이 맞는지 한 번 더 확인해 주세요.",
};

const RETRY = `잠시 후 ‘${REVERIFY_BUTTON_LABEL}’를 눌러 주세요.`;

/**
 * 재검증에서 결론을 못 냈을 때, 서버 설명이 비어 있으면 쓰는 원인별 안내.
 * 서버의 INCONCLUSIVE_NOTES(reverifyService.ts)와 같은 원인 구분을 따른다.
 */
const INCONCLUSIVE_FALLBACK: Record<string, string> = {
  ai_failed: `AI 재검토를 끝내지 못해서 이 항목이 고쳐졌는지 확인하지 못했어요. 이 항목은 규칙으로 다시 검사할 수 없어요. ${RETRY}`,
  ai_not_available:
    "이 항목은 규칙으로 다시 검사할 수 없고, AI 재검토도 설정되어 있지 않아 고쳐졌는지 확인하지 못했어요. 바뀐 코드를 직접 확인하거나 AI를 설정한 뒤 다시 확인해 주세요.",
  dep_recheck_unavailable:
    "수정본의 외부 도구 버전을 공개된 보안 문제 목록에서 다시 조회하지 못해, 문제가 없는 버전으로 바뀌었는지 확인하지 못했어요. 잠금 파일(package-lock.json)이 있다면 npm install로 갱신한 뒤 다시 점검해 주세요.",
  rule_unavailable:
    "이 항목을 다시 검사할 규칙을 수정본에 적용하지 못해 고쳐졌는지 확인하지 못했어요. 아래 바뀐 코드에서 문제가 된 줄이 어떻게 바뀌었는지 직접 확인해 주세요.",
  no_answer: `AI가 이 항목에 대한 답을 주지 않아 고쳐졌는지 확인하지 못했어요. ${RETRY}`,
  ai_inconclusive: "AI가 수정본 코드만으로는 고쳐졌는지 판단하지 못했어요. 아래 바뀐 코드를 직접 확인해 주세요.",
  evidence_not_verified:
    "AI가 근거로 든 코드를 수정본 파일에서 그대로 찾지 못해 AI 판단을 반영하지 않았어요. 이 항목이 고쳐졌는지는 아직 확인하지 못했어요.",
  file_not_sent:
    "문제가 있던 파일이 한 번에 검토할 수 있는 양을 넘어 AI에게 보내지 못했어요. 해당 파일의 바뀐 부분을 직접 확인해 주세요.",
  no_reviewable_file: "문제가 있던 파일을 수정본에서 찾지 못해 확인하지 못했어요. 파일이 옮겨지거나 지워졌는지 확인해 주세요.",
  internal_error: `재검증 도중 서버에서 문제가 생겨 이 항목이 고쳐졌는지 확인하지 못했어요. ${RETRY}`,
};

const INCONCLUSIVE_DEFAULT =
  `다시 확인했지만 이 항목이 고쳐졌는지 결론을 내리지 못했어요. 아래 바뀐 코드에서 문제가 된 줄이 어떻게 바뀌었는지 직접 확인한 뒤 ‘${REVERIFY_BUTTON_LABEL}’를 눌러 주세요.`;

/** 재검증을 마쳤는데 이 항목의 결과가 없을 때(요약의 "이번 재검증에서 확인하지 못함"). */
export const NOT_CHECKED_MESSAGE = `이번 재검증에서 확인하지 못했어요. ‘${REVERIFY_BUTTON_LABEL}’를 눌러 주세요.`;

export function fixStatusFor(findingId: string, input: FixStatusInput): FixStatus {
  const { item, jobStatus, verification } = input;
  // 지금 재검증 결과가 있으면 처음 판정·수정 여부보다 그 결과를 먼저 따른다(요약과 같은 분류).
  const verdictItem = verification && verification.status !== "running" ? verification.items.find((it) => it.findingId === findingId) : undefined;
  if (verdictItem) return statusFromVerifyItem(verdictItem);
  // 재검증을 마쳤는데 이 항목 결과가 없으면 "이번에 확인하지 못함"으로 보여 준다.
  if (verification?.status === "completed") {
    const why = item && item.outcome !== "applied" && item.reason ? `${item.reason} ` : "";
    return make("needs_check", { pending: `${why}${NOT_CHECKED_MESSAGE}` });
  }
  // 점검 때 오탐으로 판정된 항목은 전체 수정이 건너뛴다. "못 고침"이 아니라 판정을 보여 준다.
  if (input.adjudicatedFalsePositive) return make("false_positive", FALSE_POSITIVE);
  if (!item) {
    return make("needs_check", {
      pending: "아직 수정안을 만들지 않았어요. 위의 ‘이렇게 바꿔 주세요’를 보고 직접 고치거나, 맨 위의 한 번에 고치기로 수정안을 만들 수 있어요.",
    });
  }

  if (jobStatus === "running" && item.reasonCode === "pending") {
    return make("fixing", { pending: "이 항목의 수정안을 만들어 사본 파일에 적용하고 있어요. 끝나면 무엇을 바꿨는지 보여 드려요." });
  }
  if (item.outcome === "apply_failed" || item.outcome === "unsupported") {
    return make("not_fixed", {
      pending:
        item.reason ?? "자동으로 고치지 못해 파일은 바뀌지 않았어요. 위의 ‘이렇게 바꿔 주세요’를 보고 직접 고친 뒤 다시 점검해 주세요.",
    });
  }
  if (item.outcome === "skipped") {
    return make("needs_check", {
      pending: item.reason ?? "이번 수정에서는 이 항목을 다루지 않아 파일이 바뀌지 않았어요. 다시 수정하거나 직접 고쳐 주세요.",
    });
  }

  // applied: 파일에 적용까지 한 상태. 해결 여부는 재검증 결과로만 정한다.
  const v = verification?.items.find((it) => it.findingId === findingId);
  if (verification?.status === "running") {
    return make("needs_check", { pending: "수정 내용을 적용했고, 문제가 해결됐는지 다시 확인하고 있어요." });
  }
  if (!v) return make("needs_check", { pending: item.reason ?? APPLIED_UNVERIFIED_MESSAGE });
  return statusFromVerifyItem(v);
}

/** 재검증 항목 하나 → 화면 상태. 요약(verifyBucketFor)과 같은 순서로 나눈다. */
function statusFromVerifyItem(v: FixStatusVerifyItem): FixStatus {
  // 재검증에서 AI가 오탐으로 판정했으면 수정 여부와 상관없이 그 판정을 보여 준다.
  if (v.verdict === "false_positive") return make("false_positive", FALSE_POSITIVE);
  if (v.reasonCode === "disputed") {
    if (v.executed) {
      return make("disputed", {
        pending:
          "공격 재현 테스트에서는 수정본이 막았지만, 코드 검사는 문제가 남아 있다고 봤어요. 어느 쪽이 맞는지 아직 확인하지 못했어요. 아래 바뀐 코드에서 문제가 된 줄을 직접 확인해 주세요.",
      });
    }
    const rule = v.ruleVerdict ? VERDICT_WORD[v.ruleVerdict] : "결론 없음";
    const ai = v.aiVerdict ? VERDICT_WORD[v.aiVerdict] : "결론 없음";
    return make("disputed", {
      pending: `규칙 재검사는 ‘${rule}’, AI는 ‘${ai}’으로 서로 다르게 판단했어요. 어느 쪽이 맞는지 아직 확인하지 못했어요. 아래 바뀐 코드에서 문제가 된 줄을 직접 확인해 주세요.`,
    });
  }
  if (v.verdict === "fixed_in_source") {
    if (v.executed) {
      return make("resolved", {
        confirmed: "원본에서 성공한 공격 재현 테스트가 수정본에서는 막힌 것을 격리된 환경에서 실행해 확인했어요.",
        pending: REDEPLOY,
        note: NOTE_EXECUTED,
      });
    }
    if (v.method === "llm") {
      return make("resolved_ai", {
        confirmed: "이 항목은 규칙으로 다시 검사할 수 없어서, AI가 수정본 코드를 읽고 해결됐다고 판단했어요.",
        pending: `AI 판단이 맞는지 아래 바뀐 코드를 한 번 더 확인해 주세요. ${REDEPLOY}`,
        note: NOTE_AI,
      });
    }
    const both = v.method === "rule+llm" ? " AI 판단도 같았어요." : "";
    return make("resolved", {
      confirmed: `규칙 재검사로 수정본 코드에서 같은 문제가 더는 보이지 않는 것을 확인했어요.${both}`,
      pending: REDEPLOY,
      note: NOTE_RULE,
    });
  }
  if (v.verdict === "still_present") {
    if (v.reasonCode === "exploit_succeeded_after_fix") {
      return make("still_present", {
        confirmed: "원본에서 성공한 공격 재현 테스트가 수정본에서도 성공했어요. 이번 수정으로는 문제가 막히지 않았어요.",
        pending: "위의 ‘이렇게 바꿔 주세요’를 보고 다시 고친 뒤 재검증해 주세요.",
      });
    }
    return make("still_present", {
      confirmed: "수정본 코드에 같은 문제가 아직 남아 있어요.",
      pending: "아래 재검증 근거와 위의 ‘이렇게 바꿔 주세요’를 보고 남은 부분을 고친 뒤 다시 확인해 주세요.",
    });
  }
  // 결론 없음: 서버가 채운 원인별 안내를 먼저 쓴다.
  if (v.summary && v.summary.trim()) return make("needs_check", { pending: v.summary });
  return make("needs_check", { pending: (v.reasonCode && INCONCLUSIVE_FALLBACK[v.reasonCode]) || INCONCLUSIVE_DEFAULT });
}

// ─────────────────────────────────────────────────────────────
// 진행 단계: 수정안 만들기 → 파일에 적용 → 재검증
// ─────────────────────────────────────────────────────────────

/** done = 끝남, failed = 하지 못함/문제가 남음, unknown = 결론 없음, running = 진행 중, todo = 아직 안 함. */
export type FixStepState = "done" | "failed" | "unknown" | "running" | "todo";

export interface FixStep {
  id: "generate" | "apply" | "verify";
  label: string;
  state: FixStepState;
  /** 색 없이 읽히는 결과 글자. */
  text: string;
}

export const FIX_STEP_MARK: Record<FixStepState, string> = {
  done: "✓",
  failed: "✕",
  unknown: "?",
  running: "…",
  todo: "○",
};

const STEP_LABEL = { generate: "수정안 만들기", apply: "파일에 적용", verify: "재검증" } as const;

/** AI 호출 자체가 실패해 수정안이 없는 경우(ai_invalid_fix는 수정안은 받았지만 적용 못 함). */
function generationFailed(item: FixStatusJobItem): boolean {
  if (item.outcome === "unsupported") return true;
  if (item.outcome !== "apply_failed") return false;
  const code = item.reasonCode ?? "";
  return code.startsWith("ai_") && code !== "ai_invalid_fix";
}

/**
 * 한 항목의 세 단계 상태. 전체 수정을 한 번도 하지 않았거나 오탐으로 판정된 항목은
 * 단계를 보여 주지 않도록 undefined를 돌려준다.
 */
export function fixStepsFor(findingId: string, input: FixStatusInput): FixStep[] | undefined {
  const { item, jobStatus, verification } = input;
  if (!item || input.adjudicatedFalsePositive) return undefined;
  const steps: FixStep[] = [];
  const step = (id: FixStep["id"], state: FixStepState, text: string) => steps.push({ id, label: STEP_LABEL[id], state, text });
  const pending = jobStatus === "running" && item.reasonCode === "pending";

  // 1) 수정안 만들기
  if (pending) step("generate", "running", "만드는 중");
  else if (item.outcome === "skipped") step("generate", "todo", "이번에 안 함");
  else if (generationFailed(item)) step("generate", "failed", "만들지 못함");
  else step("generate", "done", "만들었어요");

  // 2) 파일에 적용 (올린 원본이 아니라 고친 사본에 적용)
  if (pending) step("apply", "todo", "기다리는 중");
  else if (item.outcome === "applied") step("apply", "done", "적용했어요");
  else if (item.outcome === "apply_failed") step("apply", "failed", "적용하지 못함");
  else step("apply", "todo", "바뀐 파일 없음");

  // 3) 재검증
  if (item.outcome !== "applied") {
    step("verify", "todo", "대상 아님");
    return steps;
  }
  if (verification?.status === "running") {
    step("verify", "running", "확인하는 중");
    return steps;
  }
  const v = verification?.items.find((it) => it.findingId === findingId);
  if (!v) step("verify", "todo", "아직 안 함");
  else if (v.reasonCode === "disputed") step("verify", "unknown", "판단이 엇갈림");
  else if (v.verdict === "fixed_in_source") step("verify", "done", v.executed ? "테스트로 해결 확인" : v.method === "llm" ? "AI가 해결로 판단" : "코드 기준 해결 확인");
  else if (v.verdict === "still_present") step("verify", "failed", "문제가 남아 있음");
  else if (v.verdict === "false_positive") step("verify", "done", "오탐 판정");
  else step("verify", "unknown", "결론 없음");
  return steps;
}

// ─────────────────────────────────────────────────────────────
// 재검증 결과 요약(화면 맨 위): 저장된 verification만으로 센다.
// ─────────────────────────────────────────────────────────────

export interface ReverifySummary {
  state: "running" | "completed" | "failed";
  /** 해결 확인: 규칙 재검사 또는 공격 재현 테스트로 확인(fixStatusFor의 resolved). */
  resolvedConfirmed: number;
  /** 그중 공격 재현 테스트를 실행해 확인한 수. */
  resolvedExecuted: number;
  /** 해결 확인: AI가 코드를 읽고 판단(fixStatusFor의 resolved_ai). */
  resolvedAi: number;
  /** 아직 남음(still_present). */
  stillPresent: number;
  /** 확인 불가: 결론 없음(inconclusive) + 판단이 엇갈림(disputed). */
  unknown: number;
  /** AI가 오탐으로 판정(false_positive). 해결로 세지 않는다. */
  falsePositive: number;
  /** 실패했을 때 저장된 이유. */
  reason?: string;
}

/**
 * 저장된 재검증 결과를 화면 맨 위 요약용으로 센다. 분류는 fixStatusFor와 같다.
 * 재검증 기록이 없으면 undefined(예전 결과를 새 결과처럼 보여 주지 않는다).
 */
export function reverifySummaryFor(
  verification: { status: "running" | "completed" | "failed"; items: FixStatusVerifyItem[]; errorMessage?: string } | undefined
): ReverifySummary | undefined {
  if (!verification) return undefined;
  const out: ReverifySummary = {
    state: verification.status,
    resolvedConfirmed: 0,
    resolvedExecuted: 0,
    resolvedAi: 0,
    stillPresent: 0,
    unknown: 0,
    falsePositive: 0,
  };
  if (verification.status === "failed") {
    if (verification.errorMessage) out.reason = verification.errorMessage;
    return out;
  }
  if (verification.status === "running") return out;
  for (const it of verification.items) {
    if (it.reasonCode === "disputed") out.unknown += 1;
    else if (it.verdict === "fixed_in_source") {
      if (it.executed) {
        out.resolvedConfirmed += 1;
        out.resolvedExecuted += 1;
      } else if (it.method === "llm") out.resolvedAi += 1;
      else out.resolvedConfirmed += 1;
    } else if (it.verdict === "still_present") out.stillPresent += 1;
    else if (it.verdict === "false_positive") out.falsePositive += 1;
    else out.unknown += 1;
  }
  return out;
}

// ─────────────────────────────────────────────────────────────
// 수정 후 요약(화면 맨 위): 요약과 항목 카드가 같은 분류를 쓴다.
// ─────────────────────────────────────────────────────────────

export type VerifyBucket = "resolvedConfirmed" | "resolvedAi" | "stillPresent" | "needsCheck" | "falsePositive";

/** 재검증 항목 하나가 요약의 어느 칸에 들어가는지. fixStatusFor(statusFromVerifyItem)와 같은 순서다. */
export function verifyBucketFor(v: FixStatusVerifyItem): VerifyBucket {
  if (v.verdict === "false_positive") return "falsePositive";
  if (v.reasonCode === "disputed") return "needsCheck";
  if (v.verdict === "fixed_in_source") return v.executed || v.method !== "llm" ? "resolvedConfirmed" : "resolvedAi";
  if (v.verdict === "still_present") return "stillPresent";
  return "needsCheck";
}

export interface PostFixSummary {
  /** none = 재검증 기록 없음(수정본만 만듦). */
  state: "none" | "running" | "completed" | "failed";
  /** 처음 발견한 항목 수(기록). */
  originalTotal: number;
  /** 처음 점검 때 AI가 실제 문제 아님으로 판정한 항목 수(기록). */
  initialFalsePositive: number;
  /** 수정 내용을 파일에 적용한 항목 수. */
  appliedCount: number;
  resolvedConfirmed: number;
  resolvedExecuted: number;
  resolvedAi: number;
  stillPresent: number;
  /** 결론 없음 + 판단이 엇갈림. */
  needsCheck: number;
  /** 재검증에서 실제 문제 아님으로 판정. 해결로 세지 않는다. */
  falsePositive: number;
  /** 재검증을 마쳤지만 결과가 없는 항목. */
  notChecked: number;
  reason?: string;
}

/**
 * 수정 후 맨 위 요약. 재검증을 마쳤을 때만 상태별로 센다.
 * 불변식(completed): resolvedConfirmed + resolvedAi + stillPresent + needsCheck + falsePositive + notChecked === originalTotal.
 */
export function postFixSummaryFor(input: {
  findingIds: string[];
  jobItems?: { findingId: string; outcome: FixStatusJobItem["outcome"] }[];
  verification?: { status: "running" | "completed" | "failed"; items: FixStatusVerifyItem[]; errorMessage?: string };
  adjudicatedFalsePositiveIds?: Iterable<string>;
}): PostFixSummary {
  const ids = [...new Set(input.findingIds)];
  const idSet = new Set(ids);
  const fp = new Set(input.adjudicatedFalsePositiveIds ?? []);
  const appliedIds = new Set((input.jobItems ?? []).filter((it) => it.outcome === "applied" && idSet.has(it.findingId)).map((it) => it.findingId));
  const v = input.verification;
  const out: PostFixSummary = {
    state: v ? v.status : "none",
    originalTotal: ids.length,
    initialFalsePositive: ids.filter((id) => fp.has(id)).length,
    appliedCount: appliedIds.size,
    resolvedConfirmed: 0,
    resolvedExecuted: 0,
    resolvedAi: 0,
    stillPresent: 0,
    needsCheck: 0,
    falsePositive: 0,
    notChecked: 0,
  };
  if (v?.status === "failed" && v.errorMessage) out.reason = v.errorMessage;
  if (v?.status !== "completed") return out;
  const byId = new Map<string, FixStatusVerifyItem>();
  for (const it of v.items) if (idSet.has(it.findingId) && !byId.has(it.findingId)) byId.set(it.findingId, it);
  for (const id of ids) {
    const it = byId.get(id);
    if (!it) {
      out.notChecked += 1;
      continue;
    }
    const b = verifyBucketFor(it);
    out[b] += 1;
    if (b === "resolvedConfirmed" && it.executed) out.resolvedExecuted += 1;
  }
  return out;
}
