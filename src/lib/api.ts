import { NextResponse } from "next/server";
import { NotAuthorizedError, NotFoundError } from "@/lib/store/store";

/** Map store errors to HTTP responses without leaking internals. */
export function handleApiError(err: unknown): NextResponse {
  if (err instanceof NotAuthorizedError) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  if (err instanceof NotFoundError) {
    return NextResponse.json({ error: "not_found" }, { status: 404 });
  }
  // Do not echo repo contents / secrets into logs or responses.
  return NextResponse.json({ error: "internal_error" }, { status: 500 });
}

export function ok(data: unknown, status = 200): NextResponse {
  return NextResponse.json(data, { status });
}
