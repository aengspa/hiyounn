import { NextRequest } from "next/server";
import { requireUserId } from "@/lib/auth";
import { getCustomRule, saveCustomRule } from "@/lib/store/store";
import { ok, handleApiError } from "@/lib/api";
import { checkPattern } from "@/lib/rules/customRules";
import { now } from "@/lib/util";

/**
 * POST /api/custom-rules/[id]  { "decision": "approve" | "reject" }
 *
 * AI가 제안한 규칙은 사람이 승인해야 이후 점검에서 규칙(기준)으로 돈다.
 * 승인 직전에 패턴을 한 번 더 검사한다.
 */
export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const uid = await requireUserId();
    const body = await req.json().catch(() => ({}));
    const decision = body?.decision;
    if (decision !== "approve" && decision !== "reject") {
      return ok({ error: "invalid_decision", message: "승인 또는 거절만 할 수 있어요." }, 400);
    }
    const rule = await getCustomRule(params.id, uid);
    if (decision === "approve" && checkPattern(rule.pattern, rule.flags)) {
      return ok({ error: "invalid_pattern", message: "이 규칙의 패턴을 쓸 수 없어요." }, 400);
    }
    const updated = { ...rule, status: decision === "approve" ? ("approved" as const) : ("rejected" as const), decidedAt: now() };
    await saveCustomRule(updated);
    return ok({ rule: updated });
  } catch (err) {
    return handleApiError(err);
  }
}
