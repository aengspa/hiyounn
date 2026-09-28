/**
 * 항목 상태 라벨 (심각도와 별개).
 *
 *   fixing     "지금 수정해요"      전체 수정이 진행 중이고 아직 이 항목 차례를 마치지 않음
 *   needs_check"점검이 필요해요"    아직 고치지 않았거나, 고쳤지만 재검증 전이거나,
 *                                  자동으로 고칠 수 없거나, 재검증이 결론을 못 냄
 *   resolved   "해결 완료했어요"    수정본 코드 재검증에서 문제가 사라졌다는 근거가 확인됨
 *   failed     "해결 실패했어요"    수정을 적용하지 못했거나, 수정본에 문제가 남아 있음
 *
 * "해결 완료"는 수정본 코드 기준이다. 배포된 사이트에서 실행해 확인한 결과가
 * 아니므로 detail에 그 사실을 적는다. 서버·클라이언트 모두에서 쓸 수 있도록
 * 서버 전용 모듈을 가져오지 않는다.
 */

export type FixStatusKey = "fixing" | "needs_check" | "resolved" | "failed";

export const FIX_STATUS_LABEL: Record<FixStatusKey, string> = {
  fixing: "지금 수정해요",
  needs_check: "점검이 필요해요",
  resolved: "해결 완료했어요",
  failed: "해결 실패했어요",
};

export interface FixStatusJobItem {
  findingId: string;
  outcome: "applied" | "apply_failed" | "unsupported" | "skipped";
  reasonCode?: string;
  reason?: string;
}

export interface FixStatusVerifyItem {
  findingId: string;
  verdict: "fixed_in_source" | "still_present" | "inconclusive";
  reasonCode?: string;
}

export interface FixStatusInput {
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

export function fixStatusFor(findingId: string, input: FixStatusInput): FixStatus {
  const { item, jobStatus, verification } = input;
  if (!item) return make("needs_check", "아직 고치지 않았어요.");

  if (jobStatus === "running" && item.reasonCode === "pending") {
    return make("fixing", "이 항목을 고치고 있어요.");
  }
  if (item.outcome === "apply_failed") {
    return make("failed", item.reason ?? "수정을 적용하지 못했어요.");
  }
  if (item.outcome === "unsupported") {
    return make("needs_check", item.reason ?? "자동으로 고칠 수 없어 직접 확인이 필요해요.");
  }
  if (item.outcome === "skipped") {
    return make("needs_check", item.reason ?? "이번 수정에서 다루지 못했어요.");
  }

  // applied: 재검증 결과로만 해결/실패를 정한다.
  const v = verification?.items.find((it) => it.findingId === findingId);
  if (verification?.status === "running") return make("needs_check", "재검증하고 있어요.");
  if (!v) return make("needs_check", "수정했어요. 재검증으로 확인해 주세요.");
  if (v.verdict === "fixed_in_source") {
    return make("resolved", "수정본 코드에서 문제가 사라진 것을 확인했어요. 배포한 사이트는 다시 배포한 뒤 점검해 주세요.");
  }
  if (v.verdict === "still_present") {
    return make("failed", "수정본 코드에 문제가 아직 남아 있어요.");
  }
  if (v.reasonCode === "ai_failed") {
    return make("needs_check", "AI 재검증을 완료하지 못했어요. 다시 시도해 주세요.");
  }
  if (v.reasonCode === "ai_not_available") {
    return make("needs_check", "AI 재검증을 쓸 수 없어 확인하지 못했어요. 직접 확인해 주세요.");
  }
  return make("needs_check", "재검증에서 결론을 내리지 못했어요. 직접 확인해 주세요.");
}
