import { NextRequest, NextResponse } from "next/server";
import { requireUserId } from "@/lib/auth";
import { getFixArtifact, getFixArtifactBytes } from "@/lib/store/store";
import { handleApiError } from "@/lib/api";

/**
 * Download the ZIP for a fix artifact. Ownership is enforced by the store
 * (returns 403 for another user's artifact, 404 if missing). The response
 * carries the stored SHA-256 so the client can verify integrity.
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const uid = await requireUserId();
    const artifact = await getFixArtifact(params.id, uid);
    if (!artifact) {
      return NextResponse.json({ error: "not_found" }, { status: 404 });
    }
    const bytes = await getFixArtifactBytes(params.id, uid);
    if (!bytes) {
      return NextResponse.json({ error: "not_found" }, { status: 404 });
    }

    // Guard the download file name against header injection / traversal.
    const safeName = artifact.fileName.replace(/[^a-zA-Z0-9._-]/g, "_");

    return new NextResponse(bytes, {
      status: 200,
      headers: {
        "content-type": "application/zip",
        "content-disposition": `attachment; filename="${safeName}"`,
        "content-length": String(bytes.length),
        "x-artifact-sha256": artifact.sha256,
        "cache-control": "private, no-store",
      },
    });
  } catch (err) {
    return handleApiError(err);
  }
}
