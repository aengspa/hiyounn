import { randomBytes, scryptSync, timingSafeEqual, createHmac } from "crypto";

/**
 * Local, dependency-free auth primitives.
 *
 * No external domain/DB required. Passwords are hashed with scrypt (salted),
 * and sessions are stateless signed tokens stored in an HttpOnly cookie.
 *
 * When Supabase Auth is wired in later, this module can be dropped in favor of
 * verified provider sessions — the API surface (hash/verify/session) is the seam.
 */

// ── Password hashing (scrypt) ────────────────────────────────

const KEYLEN = 64;

export function hashPassword(password: string): string {
  const salt = randomBytes(16).toString("hex");
  const derived = scryptSync(password, salt, KEYLEN).toString("hex");
  return `${salt}:${derived}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [salt, key] = stored.split(":");
  if (!salt || !key) return false;
  const derived = scryptSync(password, salt, KEYLEN);
  const keyBuf = Buffer.from(key, "hex");
  if (keyBuf.length !== derived.length) return false;
  return timingSafeEqual(keyBuf, derived);
}

// ── Session tokens (HMAC-signed) ─────────────────────────────

export const SESSION_COOKIE = "vsa_session";
export const SESSION_MAX_AGE = 60 * 60 * 24 * 7; // 7 days (seconds)

/**
 * Secret for signing sessions. In production set AUTH_SECRET; for local dev a
 * stable per-process fallback keeps you logged in across hot reloads.
 */
function sessionSecret(): string {
  if (process.env.AUTH_SECRET) return process.env.AUTH_SECRET;
  const g = globalThis as unknown as { __vsa_auth_secret?: string };
  if (!g.__vsa_auth_secret) g.__vsa_auth_secret = randomBytes(32).toString("hex");
  return g.__vsa_auth_secret;
}

function sign(payload: string): string {
  return createHmac("sha256", sessionSecret()).update(payload).digest("hex");
}

/** Create a signed session token for a user id. */
export function createSessionToken(userId: string): string {
  const issuedAt = Date.now().toString(36);
  const payload = `${userId}.${issuedAt}`;
  const b64 = Buffer.from(payload).toString("base64url");
  return `${b64}.${sign(b64)}`;
}

/** Verify a session token and return the userId, or null if invalid/expired. */
export function readSessionToken(token: string | undefined): string | null {
  if (!token) return null;
  const [b64, sig] = token.split(".");
  if (!b64 || !sig) return null;

  const expected = sign(b64);
  const sigBuf = Buffer.from(sig, "hex");
  const expBuf = Buffer.from(expected, "hex");
  if (sigBuf.length !== expBuf.length || !timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }

  let payload: string;
  try {
    payload = Buffer.from(b64, "base64url").toString();
  } catch {
    return null;
  }
  const [userId, issuedAt] = payload.split(".");
  if (!userId || !issuedAt) return null;

  const issuedMs = parseInt(issuedAt, 36);
  if (Number.isNaN(issuedMs)) return null;
  if (Date.now() - issuedMs > SESSION_MAX_AGE * 1000) return null;

  return userId;
}
