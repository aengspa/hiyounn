import { NextRequest } from "next/server";
import { requireUserId } from "@/lib/auth";
import { ok, handleApiError } from "@/lib/api";
import { reverifyFixJob } from "@/lib/fixjobs/reverifyService";
import { toPublicJob } from "@/lib/fixjobs/publicJob";

// 동기 처리. 내부 예산(LIMITS.verifyTimeBudgetMs, 기본 90초) < maxDuration.
export const maxDuration = 120;
export const dynamic = "force-dynamic";

/**
 * POST /api/fix-jobs/[id]/verify
 *
 * 전체 수정이 만든 수정본을 기준으로 재검증한다(원본을 보지 않음).
 * AI 호출이 실패하면 verification.status = "failed"로 돌려준다(성공으로 표시 안 함).
 */
export async function POST(
  _req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const uid = await requireUserId();
    const job = await reverifyFixJob(params.id, uid);
    const res = ok({ job: toPublicJob(job) });
    res.headers.set("cache-control", "no-store");
    return res;
  } catch (err) {
    return handleApiError(err);
  }
}
