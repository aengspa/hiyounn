import { NextRequest, NextResponse } from "next/server";
import { requireUserId } from "@/lib/auth";
import { handleApiError } from "@/lib/api";
import { loadFixJob, readFixJobArtifact } from "@/lib/fixjobs/fixAllService";

export const dynamic = "force-dynamic";

/**
 * GET /api/fix-jobs/[id]/download
 *
 * 바뀐 파일만 원래 상대 경로로 담은 ZIP(+ 요약 파일). 본인 작업만 받을 수
 * 있고, 저장된 SHA-256과 일치할 때만 내보낸다. 파일 이름은 서버가 만든
 * ASCII 이름만 쓴다.
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const uid = await requireUserId();
    const job = await loadFixJob(params.id, uid);
    const bytes = await readFixJobArtifact(job);
    const artifact = job.artifact!;
    const fileName = artifact.fileName.replace(/[^A-Za-z0-9._-]/g, "_");

    return new NextResponse(Buffer.from(bytes), {
      status: 200,
      headers: {
        "content-type": "application/zip",
        "content-length": String(bytes.byteLength),
        "content-disposition": `attachment; filename="${fileName}"`,
        "cache-control": "no-store, private",
        "x-content-type-options": "nosniff",
        "x-artifact-sha256": artifact.sha256,
      },
    });
  } catch (err) {
    return handleApiError(err);
  }
}
