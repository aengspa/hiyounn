import { NextRequest } from "next/server";
import { getCurrentUserId } from "@/lib/auth";
import { getProject, listScans } from "@/lib/store/store";
import { ok, handleApiError } from "@/lib/api";

export async function GET(
  _req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const uid = await getCurrentUserId();
    const project = getProject(params.id, uid);
    const scans = listScans(params.id, uid);
    return ok({ project, scans });
  } catch (err) {
    return handleApiError(err);
  }
}
