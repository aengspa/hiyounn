/**
 * Bundled vulnerable demo application.
 *
 * This is a self-contained, in-memory model of a small web app that the
 * Security Agent scans and verifies. It is NOT arbitrary user code and it is
 * never executed as a shell command — it's a deterministic simulation of an
 * HTTP API so the verification engine can reproduce attacks safely.
 *
 * The centerpiece is an IDOR (Broken Access Control) vulnerability on
 * GET /api/users/:id — a logged-in user can read any other user's record.
 */

export interface DemoUser {
  id: number;
  ownerAuthId: string; // the auth session that legitimately owns this record
  email: string;
  fullName: string;
  phone: string;
}

export const DEMO_USERS: DemoUser[] = [
  {
    id: 101,
    ownerAuthId: "session-user-a",
    email: "user-a@example.com",
    fullName: "User A",
    phone: "+1-202-555-0101",
  },
  {
    id: 102,
    ownerAuthId: "session-user-b",
    email: "victim@example.com",
    fullName: "User B",
    phone: "+1-202-555-0102",
  },
];

export interface DemoSession {
  authId: string;
  ownUserId: number;
}

export interface HttpRequest {
  method: string;
  path: string; // e.g. "/api/users/102"
  session: DemoSession;
}

export interface HttpResponse {
  status: number;
  body: unknown;
}

/**
 * The VULNERABLE handler. It looks up the record purely by the URL id and
 * never checks whether the record belongs to the caller. This is the bug.
 *
 * Represented as the "before fix" source so the static analyzer and the
 * verification engine share one source of truth.
 */
export const VULNERABLE_HANDLER_SOURCE = `export async function GET(req, { params }) {
  const session = await getSession(req);
  if (!session) return json({ error: "unauthorized" }, 401);

  // BUG: fetches by id only — no ownership check.
  const user = await db.users.findUnique({
    where: { id: params.id },
  });

  return json(user, 200);
}`;

/**
 * The FIXED handler adds an authorization check binding the record to the
 * caller's session.
 */
export const FIXED_HANDLER_SOURCE = `export async function GET(req, { params }) {
  const session = await getSession(req);
  if (!session) return json({ error: "unauthorized" }, 401);

  // FIX: only return the record if it belongs to the caller.
  const user = await db.users.findFirst({
    where: {
      id: params.id,
      ownerId: session.user.id,
    },
  });

  if (!user) return json({ error: "forbidden" }, 403);

  return json(user, 200);
}`;

export const HANDLER_FILE = "src/api/users/[id].ts";
export const HANDLER_VULNERABLE_LINE = 42;

/**
 * Simulate the users endpoint. `fixed` toggles between the vulnerable and
 * patched behavior so the verification engine can run the SAME attack against
 * both states deterministically.
 */
export function handleUsersRequest(
  req: HttpRequest,
  fixed: boolean
): HttpResponse {
  if (!req.session) {
    return { status: 401, body: { error: "unauthorized" } };
  }

  const idMatch = req.path.match(/\/api\/users\/(\d+)/);
  if (!idMatch) {
    return { status: 404, body: { error: "not found" } };
  }
  const requestedId = Number(idMatch[1]);
  const record = DEMO_USERS.find((u) => u.id === requestedId);
  if (!record) {
    return { status: 404, body: { error: "not found" } };
  }

  const isOwner = record.ownerAuthId === req.session.authId;

  if (fixed && !isOwner) {
    // Patched behavior: cross-user access is blocked.
    return { status: 403, body: { error: "forbidden" } };
  }

  // Vulnerable behavior (or legitimate access): returns the record.
  return {
    status: 200,
    body: {
      id: record.id,
      email: record.email,
      fullName: record.fullName,
      phone: record.phone,
    },
  };
}

/** Format an HttpRequest as a raw request string for evidence display. */
export function formatRequest(req: HttpRequest): string {
  return `${req.method} ${req.path} HTTP/1.1\nHost: demo-app.example.com\nAuthorization: Bearer <session:${req.session.authId}>`;
}

/** Format an HttpResponse as a raw response string for evidence display. */
export function formatResponse(res: HttpResponse): string {
  const statusText: Record<number, string> = {
    200: "OK",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
  };
  return `HTTP/1.1 ${res.status} ${statusText[res.status] ?? ""}\nContent-Type: application/json\n\n${JSON.stringify(res.body, null, 2)}`;
}
