import { NextRequest } from "next/server";
import { getCurrentUserId } from "@/lib/auth";
import {
  getFinding,
  getFixForFinding,
  getVerification,
} from "@/lib/store/store";
import { ok, handleApiError } from "@/lib/api";

export async function GET(
  _req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const uid = await getCurrentUserId();
    const finding = getFinding(params.id, uid);
    const fix = getFixForFinding(params.id, uid);
    const verification = getVerification(params.id, uid);
    return ok({ finding, fix, verification });
  } catch (err) {
    return handleApiError(err);
  }
}
