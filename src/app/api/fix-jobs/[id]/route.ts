import { NextRequest } from "next/server";
import { requireUserId } from "@/lib/auth";
import { ok, handleApiError } from "@/lib/api";
import { loadFixJob } from "@/lib/fixjobs/fixAllService";
import { toPublicJob } from "@/lib/fixjobs/publicJob";

export const dynamic = "force-dynamic";

/** GET /api/fix-jobs/[id] — 작업 상태와 항목별 결과(본인 작업만). */
export async function GET(
  _req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const uid = await requireUserId();
    const job = await loadFixJob(params.id, uid);
    const res = ok({ job: toPublicJob(job) });
    res.headers.set("cache-control", "no-store");
    return res;
  } catch (err) {
    return handleApiError(err);
  }
}
