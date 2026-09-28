import { NextRequest } from "next/server";
import { requireUserId } from "@/lib/auth";
import { scanPlan } from "@/lib/store/store";
import { ok, handleApiError } from "@/lib/api";

export async function GET(
  _req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const uid = await requireUserId();
    const steps = await scanPlan(params.id, uid);
    return ok({ steps });
  } catch (err) {
    return handleApiError(err);
  }
}
