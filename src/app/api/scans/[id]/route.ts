import { NextRequest } from "next/server";
import { getCurrentUserId } from "@/lib/auth";
import { getScan, getFindingsForScan } from "@/lib/store/store";
import { ok, handleApiError } from "@/lib/api";

export async function GET(
  _req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const uid = await getCurrentUserId();
    const scan = await getScan(params.id, uid);
    const findings = await getFindingsForScan(params.id, uid);
    return ok({ scan, findings });
  } catch (err) {
    return handleApiError(err);
  }
}
