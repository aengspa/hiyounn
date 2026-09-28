import { NextRequest } from "next/server";
import { requireUserId } from "@/lib/auth";
import { runScan } from "@/lib/store/store";
import { ok, handleApiError } from "@/lib/api";

// 규칙 검사 뒤 AI 코드 분석(여러 묶음, 동시 호출)을 요청 안에서 끝낸다.
// 내부 예산(LIMITS.aiScanTimeBudgetMs, 기본 150초)보다 넉넉하게 둔다.
export const maxDuration = 300;

/** Trigger a new security scan for the project. Ownership enforced in store. */
export async function POST(
  _req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const uid = await requireUserId();
    const scan = await runScan(params.id, uid);
    return ok({ scan }, 201);
  } catch (err) {
    return handleApiError(err);
  }
}
