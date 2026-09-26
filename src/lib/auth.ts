import { cookies } from "next/headers";
import { DEMO_USER, getUserById } from "@/lib/store/store";
import { readSessionToken, SESSION_COOKIE } from "@/lib/auth-core";
import type { User } from "@/lib/domain/types";

/**
 * Auth boundary.
 *
 * Reads the signed session cookie and returns the authenticated user. If there
 * is no valid session we fall back to the seeded demo user so the app remains
 * usable without a login wall (MVP behavior). This is the single seam where a
 * real provider (e.g. Supabase Auth) would be wired in.
 *
 * Every API route calls getCurrentUserId() and passes the id into the store,
 * which enforces per-user ownership — keeping authorization checks in one place.
 */

async function sessionUserId(): Promise<string | null> {
  const token = cookies().get(SESSION_COOKIE)?.value;
  const userId = readSessionToken(token);
  if (!userId) return null;
  // Confirm the user still exists in the store.
  return (await getUserById(userId)) ? userId : null;
}

export async function getCurrentUserId(): Promise<string> {
  return (await sessionUserId()) ?? DEMO_USER.id;
}

/** The authenticated user, or null when running as the anonymous demo user. */
export async function getCurrentUser(): Promise<User | null> {
  const uid = await sessionUserId();
  if (!uid) return null;
  return (await getUserById(uid)) ?? null;
}

/** True when a real (non-demo) user is signed in. */
export async function isAuthenticated(): Promise<boolean> {
  return (await sessionUserId()) !== null;
}
