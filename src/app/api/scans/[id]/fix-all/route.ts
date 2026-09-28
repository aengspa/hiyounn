import { NextRequest } from "next/server";
import { requireUserId } from "@/lib/auth";
import { ok, handleApiError } from "@/lib/api";
import { startFixAll } from "@/lib/fixjobs/fixAllService";
import { toPublicJob } from "@/lib/fixjobs/publicJob";

// 요청 안에서 동기로 처리한다. 내부 작업 예산(LIMITS.fixAllTimeBudgetMs, 기본
// 90초)이 이 값보다 짧아 응답을 보낼 여유가 남는다.
export const maxDuration = 120;
export const dynamic = "force-dynamic";

const MAX_FINDING_IDS = 500;

/**
 * POST /api/scans/[id]/fix-all
 * body: { findingIds?: string[] }   header: Idempotency-Key (optional)
 *
 * 같은 요청이 이미 실행 중이면 새로 시작하지 않고 그 작업을 202로 돌려준다.
 */
export async function POST(
  req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const uid = await requireUserId();
    const body = (await req.json().catch(() => ({}))) as { findingIds?: unknown };

    let findingIds: string[] | undefined;
    if (body.findingIds !== undefined) {
      if (
        !Array.isArray(body.findingIds) ||
        body.findingIds.length > MAX_FINDING_IDS ||
        !body.findingIds.every((v) => typeof v === "string" && v.length > 0 && v.length <= 128)
      ) {
        return ok({ error: "invalid_finding_ids", message: "고칠 항목 목록이 올바르지 않아요." }, 400);
      }
      findingIds = body.findingIds as string[];
    }

    const clientKey = req.headers.get("idempotency-key") ?? undefined;
    const { job, reused } = await startFixAll({
      ownerId: uid,
      scanId: params.id,
      findingIds,
      clientKey,
    });
    return ok({ job: toPublicJob(job), reused }, reused && job.status === "running" ? 202 : 200);
  } catch (err) {
    return handleApiError(err);
  }
}
