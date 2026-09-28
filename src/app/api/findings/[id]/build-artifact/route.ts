import { NextRequest } from "next/server";
import { getCurrentUserId } from "@/lib/auth";
import { buildFixArtifact } from "@/lib/store/store";
import { ok, handleApiError } from "@/lib/api";

/**
 * Build a downloadable, modified COPY of the project with this finding's fix
 * applied. The original upload is preserved untouched. Returns artifact
 * metadata (id, sha256, size, files); the ZIP is fetched via the download route.
 */
export async function POST(
  _req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const uid = await getCurrentUserId();
    const artifact = await buildFixArtifact(params.id, uid);
    return ok({ artifact }, 201);
  } catch (err) {
    return handleApiError(err);
  }
}
