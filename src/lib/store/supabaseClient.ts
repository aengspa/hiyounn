/**
 * Minimal Supabase (PostgREST) client using fetch — no @supabase/supabase-js
 * dependency, matching this project's zero-runtime-dependency philosophy
 * (see src/lib/ai/llmClient.ts, which talks to LLM providers the same way).
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

function restBase(): string {
  const url = required("NEXT_PUBLIC_SUPABASE_URL").replace(/\/+$/, "");
  return `${url}/rest/v1`;
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
    throw new Error(`Supabase ${method} ${table} ${res.status}: ${text}`);
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
