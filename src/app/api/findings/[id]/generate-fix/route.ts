import { NextRequest } from "next/server";
import { getCurrentUserId } from "@/lib/auth";
import { generateFixForFinding } from "@/lib/store/store";
import { ok, handleApiError } from "@/lib/api";

/** Generate (but do NOT apply) a fix for a finding. */
export async function POST(
  _req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const uid = await getCurrentUserId();
    const fix = await generateFixForFinding(params.id, uid);
    return ok({ fix }, 201);
  } catch (err) {
    return handleApiError(err);
  }
}
