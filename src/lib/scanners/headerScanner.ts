import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import type { SecurityFinding, SecurityEvidence } from "@/lib/domain/types";
import { id, now } from "@/lib/util";

/**
 * REAL scanner (with safe fallback). Checks HTTP security headers and CORS.
 *
 * If a deployment URL is present it performs a single, non-destructive GET and
 * inspects the response headers — this is safe DAST (read-only, no attack
 * payloads). If the fetch fails or no URL is present, it analyzes the project's
 * next.config for a missing-headers signal instead. The two paths are clearly
 * separated and both produce real, evidence-backed findings.
 */

const REQUIRED_HEADERS: { header: string; label: string }[] = [
  { header: "content-security-policy", label: "Content-Security-Policy" },
  { header: "x-frame-options", label: "X-Frame-Options" },
  { header: "x-content-type-options", label: "X-Content-Type-Options" },
  { header: "strict-transport-security", label: "Strict-Transport-Security" },
];

export class HeaderScanner implements SecurityScanner {
  readonly name = "header-cors-scanner";
  readonly displayName = "Security header & CORS check";
  readonly step = "deployment_check" as const;
  readonly simulated = false;

  async isApplicable(context: ProjectContext): Promise<boolean> {
    return Boolean(context.deploymentUrl) || "next.config.js" in context.files;
  }

  async scan(context: ProjectContext): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    let headers: Record<string, string> | null = null;
    let rawHeaderDump = "";

    if (context.deploymentUrl) {
      try {
        const res = await fetchWithTimeout(context.deploymentUrl, 5000);
        headers = {};
        res.headers.forEach((v, k) => {
          headers![k.toLowerCase()] = v;
        });
        rawHeaderDump = Object.entries(headers)
          .map(([k, v]) => `${k}: ${v}`)
          .join("\n");
      } catch {
        headers = null; // fall through to static config analysis
      }
    }

    // Missing security headers
    const missing: string[] = [];
    if (headers) {
      for (const req of REQUIRED_HEADERS) {
        if (!headers[req.header]) missing.push(req.label);
      }
    } else if ("next.config.js" in context.files) {
      // Static signal: empty headers() array means none are set.
      const cfg = context.files["next.config.js"];
      if (/headers\(\)\s*{[^}]*return\s*\[\s*\]/s.test(cfg)) {
        missing.push(...REQUIRED_HEADERS.map((h) => h.label));
        rawHeaderDump = "Detected empty headers() in next.config.js";
      }
    }

    if (missing.length > 0) {
      const evidence: SecurityEvidence[] = [
        {
          id: id("ev"),
          kind: headers ? "http_response" : "configuration",
          label: headers
            ? `${context.deploymentUrl} 의 응답 헤더`
            : "next.config.js",
          content: rawHeaderDump || "(보안 관련 헤더가 없음)",
        },
        {
          id: id("ev"),
          kind: "scanner_output",
          label: "보안 헤더/CORS 스캐너 출력",
          content: `누락된 헤더:\n- ${missing.join("\n- ")}`,
        },
      ];

      findings.push({
        id: id("finding"),
        scanId: "",
        title: "사이트에 기본적인 브라우저 보호 설정이 빠져 있습니다",
        severity: "medium",
        category: "Security Headers",
        owasp: "A05 – Security Misconfiguration",
        cwe: "CWE-693",
        cvss: 5.3,
        description: `누락된 HTTP 보안 헤더: ${missing.join(", ")}.`,
        humanReadableImpact:
          "브라우저에게 사용자를 어떻게 보호할지 알려주는 설정이 빠져 있어, 일부 공격이 더 쉬워집니다.",
        whyItMatters:
          "이 설정이 없으면 공격자가 스크립트를 주입하거나 방문자의 브라우저를 속이기가 더 쉬워집니다.",
        evidence,
        remediation:
          "프레임워크 설정(예: Next.js headers())이나 호스팅 제공자에서 누락된 보안 헤더를 추가하세요.",
        status: "detected",
        simulated: false,
        verificationKey: `headers:${context.projectId}`,
        createdAt: now(),
        updatedAt: now(),
      });
    }

    // CORS: overly permissive wildcard
    if (headers) {
      const acao = headers["access-control-allow-origin"];
      const acac = headers["access-control-allow-credentials"];
      if (acao === "*" && acac === "true") {
        findings.push({
          id: id("finding"),
          scanId: "",
          title: "다른 웹사이트가 사용자의 로그인으로 API를 호출할 수 있습니다",
          severity: "high",
          category: "CORS",
          owasp: "A05 – Security Misconfiguration",
          cwe: "CWE-942",
          cvss: 7.1,
          description:
            "Access-Control-Allow-Origin이 '*'이면서 Access-Control-Allow-Credentials가 'true'로 설정되어 있습니다.",
          humanReadableImpact:
            "다른 웹사이트가 로그인한 사용자의 세션을 이용해 몰래 당신의 백엔드에 요청을 보낼 수 있습니다.",
          whyItMatters:
            "악성 사이트가 사용자의 기존 로그인을 타고 들어와 사용자 데이터를 읽어낼 수 있습니다.",
          evidence: [
            {
              id: id("ev"),
              kind: "http_response",
              label: "CORS 헤더",
              content: `access-control-allow-origin: ${acao}\naccess-control-allow-credentials: ${acac}`,
            },
          ],
          remediation:
            "와일드카드 origin과 credentials를 함께 쓰지 마세요. 신뢰하는 특정 origin만 허용하세요.",
          status: "detected",
          simulated: false,
          verificationKey: `cors:${context.projectId}`,
          createdAt: now(),
          updatedAt: now(),
        });
      }
    }

    return findings;
  }
}

async function fetchWithTimeout(url: string, ms: number): Promise<Response> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), ms);
  try {
    // Read-only GET. No attack payloads — safe DAST.
    return await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
    });
  } finally {
    clearTimeout(t);
  }
}
