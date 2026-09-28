import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { getUserById } from "@/lib/store/store";
import { UnauthenticatedError } from "@/lib/store/errors";
import { readSessionToken, SESSION_COOKIE } from "@/lib/auth-core";
import type { User } from "@/lib/domain/types";

/**
 * Auth boundary.
 *
 * Saved projects, uploaded source, scans, fix jobs and fixed-copy downloads all
 * require a real signed-in user. There is no anonymous fallback user anymore:
 * anonymous and real data never share the store.
 *
 * - API routes call requireUserId(); it throws UnauthenticatedError (→ 401).
 * - Server pages call requirePageUserId(path); it redirects to /login?next=path.
 *
 * The id is then passed into the store, which enforces per-user ownership.
 */

async function sessionUserId(): Promise<string | null> {
  const token = cookies().get(SESSION_COOKIE)?.value;
  const userId = readSessionToken(token);
  if (!userId) return null;
  // Confirm the user still exists in the store.
  return (await getUserById(userId)) ? userId : null;
}

/** The signed-in user's id, or UnauthenticatedError. */
export async function requireUserId(): Promise<string> {
  const uid = await sessionUserId();
  if (!uid) throw new UnauthenticatedError();
  return uid;
}

/**
 * @deprecated Use requireUserId(). Kept so any missed caller still enforces
 * login instead of silently falling back to a shared demo user.
 */
export const getCurrentUserId = requireUserId;

/** For server pages: the signed-in user's id, or a redirect to the login page. */
export async function requirePageUserId(nextPath: string): Promise<string> {
  const uid = await sessionUserId();
  if (!uid) redirect(loginPath(nextPath));
  return uid;
}

export function loginPath(nextPath: string): string {
  const next = safeNextPath(nextPath);
  return next ? `/login?next=${encodeURIComponent(next)}` : "/login";
}

/**
 * Only same-site dashboard paths are allowed as a post-login destination, so the
 * `next` parameter can't be used as an open redirect.
 */
export function safeNextPath(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const p = raw.trim();
  if (p.length === 0 || p.length > 300) return null;
  if (!p.startsWith("/dashboard")) return null;
  if (p.startsWith("//") || p.includes("\\") || /[\r\n\t]/.test(p)) return null;
  return p;
}

/** The authenticated user, or null when signed out. */
export async function getCurrentUser(): Promise<User | null> {
  const uid = await sessionUserId();
  if (!uid) return null;
  return (await getUserById(uid)) ?? null;
}

/** True when a user is signed in. */
export async function isAuthenticated(): Promise<boolean> {
  return (await sessionUserId()) !== null;
}
