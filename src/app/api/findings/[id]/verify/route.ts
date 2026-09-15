import { NextRequest } from "next/server";
import { getCurrentUserId } from "@/lib/auth";
import { verifyFinding } from "@/lib/store/store";
import { ok, handleApiError } from "@/lib/api";

/**
 * Run deterministic verification: re-run the original attack (security) and
 * legitimate-behavior checks (regression). Only resolves the finding when both
 * pass. This is the core value of the product.
 */
export async function POST(
  _req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const uid = await getCurrentUserId();
    const { finding, result } = await verifyFinding(params.id, uid);
    return ok({ finding, result });
  } catch (err) {
    return handleApiError(err);
  }
}
