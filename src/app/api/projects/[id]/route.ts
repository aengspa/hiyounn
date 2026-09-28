import { NextRequest } from "next/server";
import { requireUserId } from "@/lib/auth";
import { getProject, listScans } from "@/lib/store/store";
import { ok, handleApiError } from "@/lib/api";
import { redactProject } from "@/lib/domain/scanMode";

export async function GET(
  _req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const uid = await requireUserId();
    const project = await getProject(params.id, uid);
    const scans = await listScans(params.id, uid);
    return ok({ project: redactProject(project), scans });
  } catch (err) {
    return handleApiError(err);
  }
}
