import { NextRequest } from "next/server";
import { getCurrentUserId } from "@/lib/auth";
import { applyFix } from "@/lib/store/store";
import { ok, handleApiError } from "@/lib/api";

/** Apply the generated fix. Moves finding to "fixed" — NOT resolved. */
export async function POST(
  _req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const uid = await getCurrentUserId();
    const finding = await applyFix(params.id, uid);
    return ok({ finding });
  } catch (err) {
    return handleApiError(err);
  }
}
