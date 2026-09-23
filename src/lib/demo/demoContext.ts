import type { ProjectContext } from "@/lib/scanners/types";
import { VULNERABLE_HANDLER_SOURCE, HANDLER_FILE } from "@/lib/demo/vulnerableApp";

/**
 * Builds the ProjectContext for the bundled vulnerable demo project. In
 * production this would be hydrated from a cloned repository; here it's a fixed
 * fixture so the demo is fully deterministic.
 *
 * NOTE: the hardcoded secret below is intentional bait for the secret scanner.
 * It is a fake value, not a real credential.
 */
export function buildDemoContext(
  projectId: string,
  opts: {
    name: string;
    repositoryUrl?: string;
    deploymentUrl?: string;
    commitSha?: string;
    /** When true, the handler file reflects the applied fix. */
    fixedHandler?: boolean;
    /** 사용자가 붙여넣은 소스 코드(AI 스캔 대상). */
    userSource?: string;
  }
): ProjectContext {
  // The context always represents the on-disk (pre-fix) demo repo for scanning.
  // The verification engine toggles fixed behavior via handleUsersRequest(),
  // not by rewriting these files. `fixedHandler` is accepted for API symmetry.
  void opts.fixedHandler;
  const handlerSource = VULNERABLE_HANDLER_SOURCE;

  const files: Record<string, string> = {
    [HANDLER_FILE]: handlerSource,
      "src/lib/db.ts": `import { createClient } from "@supabase/supabase-js";

// BUG: service role secret hardcoded in client-reachable module.
const SUPABASE_SERVICE_KEY = "sbp_live_9f2c1a77e4b84d0e9a3c5f6d7b8e2a10";

export const admin = createClient(
  "https://demo.supabase.co",
  SUPABASE_SERVICE_KEY
);`,
      ".env": `NEXT_PUBLIC_SUPABASE_URL=https://demo.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo
DATABASE_PASSWORD=SuperSecretDbPass123!`,
      "next.config.js": `module.exports = {
  async headers() {
    return []; // BUG: no security headers configured
  },
};`,
    "package.json": JSON.stringify(
      {
        dependencies: {
          next: "13.4.1",
          "@supabase/supabase-js": "2.21.0",
          lodash: "4.17.19",
        },
      },
      null,
      2
    ),
  };

  // 사용자가 붙여넣은 실제 코드가 있으면 AI 스캔 대상으로 추가.
  if (opts.userSource && opts.userSource.trim()) {
    files["user-source:main"] = opts.userSource.trim();
  }

  return {
    projectId,
    name: opts.name,
    repositoryUrl: opts.repositoryUrl,
    deploymentUrl: opts.deploymentUrl,
    commitSha: opts.commitSha,
    stack: {
      frameworks: ["next.js", "react"],
      languages: ["typescript"],
      baas: ["supabase"],
      hasEnvFile: true,
    },
    files,
  };
}
