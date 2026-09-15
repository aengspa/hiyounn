import { NextRequest } from "next/server";
import { getCurrentUserId } from "@/lib/auth";
import { runScan } from "@/lib/store/store";
import { ok, handleApiError } from "@/lib/api";

/** Trigger a new security scan for the project. Ownership enforced in store. */
export async function POST(
  _req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const uid = await getCurrentUserId();
    const scan = await runScan(params.id, uid);
    return ok({ scan }, 201);
  } catch (err) {
    return handleApiError(err);
  }
}
