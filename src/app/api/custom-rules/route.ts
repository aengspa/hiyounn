import { NextRequest } from "next/server";
import { requireUserId } from "@/lib/auth";
import { listCustomRules } from "@/lib/store/store";
import { ok, handleApiError } from "@/lib/api";

export const dynamic = "force-dynamic";

/** GET /api/custom-rules?projectId= — 본인의 AI 제안·승인 규칙 목록. */
export async function GET(req: NextRequest) {
  try {
    const uid = await requireUserId();
    const projectId = req.nextUrl.searchParams.get("projectId") ?? undefined;
    const rules = await listCustomRules(uid, projectId);
    return ok({ rules });
  } catch (err) {
    return handleApiError(err);
  }
}
