import { NextRequest } from "next/server";
import { ok, handleApiError } from "@/lib/api";
import { runQuickCheck } from "@/lib/scanners/quickCheck";

/** Max pasted source accepted for a quick check. */
const MAX_SOURCE_CHARS = 100_000;

/**
 * Stateless "quick code check". Runs passive static/secret analysis over pasted
 * source and returns findings inline. Creates no project/scan and stores
 * nothing. No auth needed - nothing is persisted or attributed to a user.
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const source = typeof body.source === "string" ? body.source : "";

    if (!source.trim()) {
      return ok({ error: "검사할 코드를 입력해 주세요." }, 400);
    }
    if (source.length > MAX_SOURCE_CHARS) {
      return ok({ error: "source_too_large" }, 400);
    }

    const result = await runQuickCheck(source);
    return ok(result);
  } catch (err) {
    return handleApiError(err);
  }
}
