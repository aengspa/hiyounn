import { NextRequest } from "next/server";
import { requireUserId } from "@/lib/auth";
import { createProject } from "@/lib/store/store";
import { ok, handleApiError } from "@/lib/api";
import { redactProject } from "@/lib/domain/scanMode";
import { getSampleApp } from "@/lib/samples";

/**
 * POST /api/projects/sample  { "sampleId": "memo-board" }
 * 체험용 샘플 앱의 소스로 보통 프로젝트를 만든다(미리 만든 결과 없음).
 */
export async function POST(req: NextRequest) {
  try {
    const uid = await requireUserId();
    const body = await req.json().catch(() => ({}));
    const sample = getSampleApp(typeof body?.sampleId === "string" ? body.sampleId : "memo-board");
    if (!sample) return ok({ error: "unknown_sample", message: "없는 샘플이에요." }, 400);
    const project = await createProject(uid, {
      name: sample.name,
      files: sample.files,
      sourceKind: "zip",
      sourceZipName: sample.zipPath.split("/").pop(),
    });
    return ok({ project: redactProject(project) }, 201);
  } catch (err) {
    return handleApiError(err);
  }
}
