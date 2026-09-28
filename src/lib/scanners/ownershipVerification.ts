import { resolveTxt } from "dns/promises";
import net from "net";
import type { ProjectContext } from "@/lib/scanners/types";
import { safeFetch } from "@/lib/net/safeFetch";
import { SCANNER_GUARDS } from "@/lib/scanners/definitions";

/** Consent alone is not target ownership. Recheck a server-held, unexpired token. */
export async function verifyTargetOwnership(context: ProjectContext): Promise<boolean> {
  const proof = context.ownershipProof;
  if (!context.deploymentAuthorized || !context.deploymentUrl || !proof) return false;
  try {
    const target = new URL(context.deploymentUrl);
    if (target.protocol !== "https:" || target.username || target.password || net.isIP(target.hostname.replace(/^\[|\]$/g, ""))) return false;
    if (proof.host !== target.hostname || !/^[A-Za-z0-9_-]{43,128}$/.test(proof.token) || Date.parse(proof.expiresAt) <= Date.now() || !Number.isFinite(Date.parse(proof.expiresAt))) return false;
    const guard = SCANNER_GUARDS.find((g) => g.id === "SCN-001")!;
    if (proof.method === "dns_txt") {
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        const records = await Promise.race([
          resolveTxt(`${guard.policy.dnsTxtRecordName}.${target.hostname}`),
          new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("DNS timeout")), 5000); }),
        ]);
        return records.some((record) => record.join("") === proof.token);
      } finally { clearTimeout(timer); }
    }
    if (proof.method !== "well_known_file") return false;
    const response = await safeFetch(new URL(String(guard.policy.wellKnownPath), target.origin).toString(), { timeoutMs: 5000, maxBytes: 1024, followRedirects: false });
    return response.status === 200 && !response.truncated && response.body.trim() === proof.token;
  } catch { return false; }
}
