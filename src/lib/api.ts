import { NextResponse } from "next/server";
import {
  NotAuthorizedError,
  NotFoundError,
  VerificationUnavailableError,
  UnauthenticatedError,
  AppError,
} from "@/lib/store/errors";

/** Map store errors to HTTP responses without leaking internals. */
export function handleApiError(err: unknown): NextResponse {
  if (err instanceof UnauthenticatedError) {
    return NextResponse.json(
      { error: "unauthenticated", message: "로그인이 필요해요.", loginPath: "/login" },
      { status: 401 }
    );
  }
  if (err instanceof NotAuthorizedError) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  if (err instanceof NotFoundError) {
    return NextResponse.json({ error: "not_found" }, { status: 404 });
  }
  if (err instanceof VerificationUnavailableError) {
    return NextResponse.json(
      {
        error:
          "자동 재검증을 완료할 충분한 근거를 확보하지 못했습니다. 수정된 소스·배포 권한·외부 검사 서비스 상태를 확인한 뒤 다시 시도해 주세요.",
      },
      { status: 422 }
    );
  }
  if (err instanceof AppError) {
    return NextResponse.json(
      { error: err.code, message: err.userMessage, ...(err.extra ?? {}) },
      { status: err.status }
    );
  }
  // Do not echo repo contents / secrets into logs or responses.
  console.error(`[api] unhandled ${err instanceof Error ? err.name : typeof err}`);
  return NextResponse.json({ error: "internal_error" }, { status: 500 });
}

export function ok(data: unknown, status = 200): NextResponse {
  return NextResponse.json(data, { status });
}
