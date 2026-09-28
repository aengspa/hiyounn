import { NextRequest } from "next/server";
import { requireUserId } from "@/lib/auth";
import { ok, handleApiError } from "@/lib/api";
import { loadFixJob } from "@/lib/fixjobs/fixAllService";
import { getSourceVersion } from "@/lib/store/store";
import { fileDiff } from "@/lib/diff/lineDiff";
import { maskSecretValues, secretValues } from "@/lib/ui/codeContext";

export const dynamic = "force-dynamic";

/**
 * GET /api/fix-jobs/[id]/diff
 *
 * 전체 수정이 바꾼 파일마다 수정 전(점검한 원본)과 수정 후(수정본)의 줄 단위 비교.
 * 본인 작업만 볼 수 있고, 비밀값은 양쪽 모두 가린다.
 */
export async function GET(_req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const uid = await requireUserId();
    const job = await loadFixJob(params.id, uid);
    if (!job.resultVersionId) return ok({ files: [] });
    const [base, result] = await Promise.all([
      getSourceVersion(job.baseVersionId, uid),
      getSourceVersion(job.resultVersionId, uid),
    ]);
    const secrets = secretValues({ ...base.files, ...Object.fromEntries(Object.entries(result.files).map(([k, v]) => [`fixed:${k}`, v])) });
    const files = job.changedFiles.map((path) => {
      const before = maskSecretValues(base.files[path] ?? "", secrets);
      const after = maskSecretValues(result.files[path] ?? "", secrets);
      return { path, isNew: base.files[path] === undefined, ...fileDiff(before, after) };
    });
    const res = ok({ files });
    res.headers.set("cache-control", "no-store");
    return res;
  } catch (err) {
    return handleApiError(err);
  }
}
