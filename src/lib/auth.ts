import { DEMO_USER } from "@/lib/store/store";

/**
 * Auth boundary.
 *
 * In the MVP the "current user" is a fixed demo user so the whole UX works
 * without a login wall. This function is the single seam where Supabase Auth
 * would be wired in: read the session cookie / JWT, verify it server-side, and
 * return the authenticated user's id.
 *
 * Every API route calls this and passes the id into the store, which enforces
 * per-user ownership. That keeps authorization checks in one place.
 */
export async function getCurrentUserId(): Promise<string> {
  // TODO(supabase): replace with verified session lookup.
  return DEMO_USER.id;
}
