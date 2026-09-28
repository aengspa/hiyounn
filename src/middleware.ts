import { NextResponse, type NextRequest } from "next/server";

/**
 * Dashboard pages require a login. This middleware only checks that a session
 * cookie is present (fast, edge-safe) and sends signed-out visitors to the
 * login page with a `next` return path. The cookie's signature is verified on
 * the server by every page (requirePageUserId) and API route (requireUserId),
 * so a forged cookie still gets rejected there.
 */
const SESSION_COOKIE = "vsa_session";

export function middleware(req: NextRequest) {
  if (req.cookies.get(SESSION_COOKIE)?.value) return NextResponse.next();

  const url = req.nextUrl.clone();
  const next = `${req.nextUrl.pathname}${req.nextUrl.search}`;
  url.pathname = "/login";
  url.search = `?next=${encodeURIComponent(next)}`;
  return NextResponse.redirect(url);
}

export const config = {
  matcher: ["/dashboard/:path*"],
};
