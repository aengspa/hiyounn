/**
 * Minimal Supabase (PostgREST + Storage) client using fetch — no
 * @supabase/supabase-js dependency, matching this project's
 * zero-runtime-dependency philosophy (see src/lib/ai/llmClient.ts).
 *
 * SERVER ONLY. Uses the service-role key, which bypasses Row Level Security.
 * Never import this into client components. Ownership is enforced by the store
 * layer above it.
 */

function required(name: string): string {
  const v = process.env[name];
  if (!v) {
    throw new Error(
      `${name} is not set. DATA_STORE=supabase requires NEXT_PUBLIC_SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.`
    );
  }
  return v;
}

function projectBase(): string {
  return required("NEXT_PUBLIC_SUPABASE_URL").replace(/\/+$/, "");
}

function restBase(): string {
  return `${projectBase()}/rest/v1`;
}

function serviceKey(): string {
  return required("SUPABASE_SERVICE_ROLE_KEY");
}

/** True when the Supabase env is fully configured. */
export function isSupabaseConfigured(): boolean {
  return Boolean(
    process.env.NEXT_PUBLIC_SUPABASE_URL &&
      process.env.SUPABASE_SERVICE_ROLE_KEY
  );
}

/**
 * A non-2xx answer from Supabase. `code` is the PostgREST / Postgres error code
 * when the body carried one (e.g. PGRST204, 42P01, 23505). The message keeps
 * the old "Supabase METHOD table STATUS: body" shape so existing checks work.
 */
export class SupabaseHttpError extends Error {
  constructor(
    readonly method: string,
    readonly target: string,
    readonly status: number,
    readonly code: string | undefined,
    body: string
  ) {
    super(`Supabase ${method} ${target} ${status}: ${body}`);
    this.name = "SupabaseHttpError";
  }
}

/** Codes meaning "the table/column this code expects does not exist yet". */
const SCHEMA_ERROR_CODES = new Set(["PGRST204", "PGRST205", "42P01", "42703"]);

export function isSchemaError(e: unknown): boolean {
  if (e instanceof SupabaseHttpError) {
    return Boolean(e.code && SCHEMA_ERROR_CODES.has(e.code));
  }
  return e instanceof Error && /PGRST20[45]|42P01|42703/.test(e.message);
}

export function isUniqueViolation(e: unknown): boolean {
  if (e instanceof SupabaseHttpError) {
    return e.status === 409 || e.code === "23505";
  }
  return e instanceof Error && /\b409\b|23505|duplicate key/.test(e.message);
}

function parseErrorCode(body: string): string | undefined {
  try {
    const parsed = JSON.parse(body) as { code?: unknown };
    return typeof parsed.code === "string" ? parsed.code : undefined;
  } catch {
    return undefined;
  }
}

interface QueryOptions {
  /** PostgREST filter/select query string, e.g. "id=eq.123&select=*". */
  query?: string;
  /** Prefer header value, e.g. "return=representation" or "resolution=merge-duplicates". */
  prefer?: string;
  /** Request body for POST/PATCH. */
  body?: unknown;
  signal?: AbortSignal;
}

async function request<T>(
  method: "GET" | "POST" | "PATCH" | "DELETE",
  table: string,
  opts: QueryOptions = {}
): Promise<T> {
  const key = serviceKey();
  const q = opts.query ? `?${opts.query}` : "";
  const headers: Record<string, string> = {
    apikey: key,
    authorization: `Bearer ${key}`,
    "content-type": "application/json",
  };
  if (opts.prefer) headers.prefer = opts.prefer;

  const res = await fetch(`${restBase()}/${table}${q}`, {
    method,
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    signal: opts.signal,
    // Server-side data must never be cached by Next's fetch cache.
    cache: "no-store",
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new SupabaseHttpError(method, table, res.status, parseErrorCode(text), text);
  }

  // DELETE / minimal responses may have no body.
  const raw = await res.text();
  if (!raw) return undefined as unknown as T;
  return JSON.parse(raw) as T;
}

/** SELECT rows. `query` is a PostgREST query string (filters + select). */
export function selectRows<T>(
  table: string,
  query: string,
  signal?: AbortSignal
): Promise<T[]> {
  return request<T[]>("GET", table, { query, signal });
}

/** SELECT a single row or undefined. */
export async function selectOne<T>(
  table: string,
  query: string,
  signal?: AbortSignal
): Promise<T | undefined> {
  const rows = await request<T[]>("GET", table, {
    query: `${query}&limit=1`,
    signal,
  });
  return rows[0];
}

/** INSERT rows and return the inserted representation. */
export async function insertRows<T>(
  table: string,
  rows: unknown,
  signal?: AbortSignal
): Promise<T[]> {
  return request<T[]>("POST", table, {
    body: rows,
    prefer: "return=representation",
    signal,
  });
}

/** UPSERT rows (insert or merge on primary-key conflict). */
export async function upsertRows<T>(
  table: string,
  rows: unknown,
  signal?: AbortSignal
): Promise<T[]> {
  return request<T[]>("POST", table, {
    body: rows,
    prefer: "return=representation,resolution=merge-duplicates",
    signal,
  });
}

/** UPDATE rows matched by `query` and return the updated representation. */
export async function updateRows<T>(
  table: string,
  query: string,
  patch: unknown,
  signal?: AbortSignal
): Promise<T[]> {
  return request<T[]>("PATCH", table, {
    query,
    body: patch,
    prefer: "return=representation",
    signal,
  });
}

/** DELETE rows matched by `query`. */
export async function deleteRows(
  table: string,
  query: string,
  signal?: AbortSignal
): Promise<void> {
  await request<unknown>("DELETE", table, { query, signal });
}

// ── Storage (private bucket) ──

/** Object key segments are app-generated ids; encode each one anyway. */
function objectPath(bucket: string, key: string): string {
  const safe = key
    .split("/")
    .filter(Boolean)
    .map((seg) => encodeURIComponent(seg))
    .join("/");
  return `${encodeURIComponent(bucket)}/${safe}`;
}

/** Upload bytes to a (private) bucket. Never overwrites an existing object. */
export async function storageUpload(
  bucket: string,
  key: string,
  bytes: Uint8Array,
  contentType: string
): Promise<void> {
  const sk = serviceKey();
  const res = await fetch(`${projectBase()}/storage/v1/object/${objectPath(bucket, key)}`, {
    method: "POST",
    headers: {
      apikey: sk,
      authorization: `Bearer ${sk}`,
      "content-type": contentType,
      "x-upsert": "false",
    },
    body: bytes,
    cache: "no-store",
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new SupabaseHttpError("POST", `storage:${bucket}`, res.status, parseErrorCode(text), text);
  }
}

/** Download bytes from a private bucket; undefined when the object is missing. */
export async function storageDownload(
  bucket: string,
  key: string
): Promise<Uint8Array | undefined> {
  const sk = serviceKey();
  const res = await fetch(
    `${projectBase()}/storage/v1/object/authenticated/${objectPath(bucket, key)}`,
    {
      method: "GET",
      headers: { apikey: sk, authorization: `Bearer ${sk}` },
      cache: "no-store",
    }
  );
  if (res.status === 404 || res.status === 400) {
    // Supabase Storage answers a missing object with 400/404 "not_found".
    const text = await res.text().catch(() => "");
    if (res.status === 404 || /not.?found/i.test(text)) return undefined;
    throw new SupabaseHttpError("GET", `storage:${bucket}`, res.status, parseErrorCode(text), text);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new SupabaseHttpError("GET", `storage:${bucket}`, res.status, parseErrorCode(text), text);
  }
  return new Uint8Array(await res.arrayBuffer());
}
