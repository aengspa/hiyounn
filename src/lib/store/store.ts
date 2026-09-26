import type {
  Project,
  Scan,
  SecurityFinding,
  FixAttempt,
  VerificationResult,
  User,
} from "@/lib/domain/types";
import type { StoreBackend } from "./backend";
import { MemoryStore, DEMO_USER } from "./memoryStore";
import { SupabaseStore } from "./supabaseStore";

/**
 * Store facade.
 *
 * Picks a storage backend based on DATA_STORE and re-exports its async API as
 * the app's store. Every API route and server component imports from here, so
 * switching backends is a single environment variable — no caller changes.
 *
 *   DATA_STORE=memory    (default) in-process Map. Dev / demo only; on Vercel
 *                        state is NOT shared across serverless invocations.
 *   DATA_STORE=supabase  Postgres via the service-role key. Use in any
 *                        deployed environment so data survives across requests.
 *
 * Ownership (the IDOR defense) is enforced inside each backend, not here.
 */

export { NotAuthorizedError, NotFoundError, EmailInUseError } from "./errors";
export { DEMO_USER };

function selectBackend(): StoreBackend {
  const mode = (process.env.DATA_STORE ?? "memory").toLowerCase();
  if (mode === "supabase") return new SupabaseStore();
  return new MemoryStore();
}

/**
 * Reuse one backend instance per DATA_STORE mode. Keyed by mode (not a bare
 * singleton) so flipping DATA_STORE during a dev session picks up the new
 * backend on the next request. The MemoryStore keeps its own persistence in
 * globalThis.__vsa_db; SupabaseStore is stateless, so recreating it is cheap.
 */
const g = globalThis as unknown as {
  __vsa_store?: { mode: string; backend: StoreBackend };
};
const mode = (process.env.DATA_STORE ?? "memory").toLowerCase();
if (!g.__vsa_store || g.__vsa_store.mode !== mode) {
  g.__vsa_store = { mode, backend: selectBackend() };
}
const backend: StoreBackend = g.__vsa_store.backend;

// ── Users ──
export function findUserByEmail(email: string): Promise<User | undefined> {
  return backend.findUserByEmail(email);
}
export function getUserById(userId: string): Promise<User | undefined> {
  return backend.getUserById(userId);
}
export function createUser(input: {
  email: string;
  passwordHash: string;
  name?: string;
}): Promise<User> {
  return backend.createUser(input);
}

// ── Projects ──
export function listProjects(ownerId: string): Promise<Project[]> {
  return backend.listProjects(ownerId);
}
export function getProject(projectId: string, ownerId: string): Promise<Project> {
  return backend.getProject(projectId, ownerId);
}
export function createProject(
  ownerId: string,
  input: {
    name: string;
    repositoryUrl?: string;
    deploymentUrl?: string;
    sourceCode?: string;
  }
): Promise<Project> {
  return backend.createProject(ownerId, input);
}

// ── Scans ──
export function listScans(projectId: string, ownerId: string): Promise<Scan[]> {
  return backend.listScans(projectId, ownerId);
}
export function getScan(scanId: string, ownerId: string): Promise<Scan> {
  return backend.getScan(scanId, ownerId);
}
export function runScan(projectId: string, ownerId: string): Promise<Scan> {
  return backend.runScan(projectId, ownerId);
}
export function scanPlan(projectId: string, ownerId: string): Promise<unknown> {
  return backend.scanPlan(projectId, ownerId);
}

// ── Findings ──
export function getFinding(
  findingId: string,
  ownerId: string
): Promise<SecurityFinding> {
  return backend.getFinding(findingId, ownerId);
}
export function getFindingsForScan(
  scanId: string,
  ownerId: string
): Promise<SecurityFinding[]> {
  return backend.getFindingsForScan(scanId, ownerId);
}

// ── Fixes & verification ──
export function generateFixForFinding(
  findingId: string,
  ownerId: string
): Promise<FixAttempt> {
  return backend.generateFixForFinding(findingId, ownerId);
}
export function getFixForFinding(
  findingId: string,
  ownerId: string
): Promise<FixAttempt | undefined> {
  return backend.getFixForFinding(findingId, ownerId);
}
export function applyFix(
  findingId: string,
  ownerId: string
): Promise<SecurityFinding> {
  return backend.applyFix(findingId, ownerId);
}
export function verifyFinding(
  findingId: string,
  ownerId: string
): Promise<{ finding: SecurityFinding; result?: VerificationResult }> {
  return backend.verifyFinding(findingId, ownerId);
}
export function getVerification(
  findingId: string,
  ownerId: string
): Promise<VerificationResult | undefined> {
  return backend.getVerification(findingId, ownerId);
}
