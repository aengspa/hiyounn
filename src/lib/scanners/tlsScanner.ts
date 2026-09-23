import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import type {
  SecurityFinding,
  SecurityEvidence,
  VerificationResult,
  VerificationTest,
  RegressionTest,
} from "@/lib/domain/types";
import { id, now } from "@/lib/util";
import { safeFetch, SafeFetchError } from "@/lib/net/safeFetch";

/**
 * REAL active scanner (WEB-009 / 지식 베이스 C-2).
 *
 * 배포 origin에 대해 두 가지를 관측한다:
 *   1) http:// 로 접근 시 https:// 로 리다이렉트되는가 (평문 허용 여부)
 *   2) https:// 응답에 HSTS(Strict-Transport-Security) 헤더가 있는가
 *
 * 안전: safeFetch(SSRF 차단 + 상한) 사용. http 프로브는 리다이렉트를 따라가지
 * 않고(followRedirects:false) 3xx/Location만 관측한다.
 *
 * 배포 URL이 없으면 applicable=false → 규칙은 coverage_gap. 관측 없이 단정 금지.
 */

interface TlsObservation {
  httpRedirectsToHttps: boolean | null; // null = http 프로브 실패
  hstsPresent: boolean | null; // null = https 프로브 실패
  httpNote: string;
  httpsNote: string;
}

function toOrigin(raw: string, scheme: "http" | "https"): string | null {
  try {
    const u = new URL(raw);
    return `${scheme}://${u.host}/`;
  } catch {
    return null;
  }
}

async function observe(base: string): Promise<TlsObservation> {
  const obs: TlsObservation = {
    httpRedirectsToHttps: null,
    hstsPresent: null,
    httpNote: "",
    httpsNote: "",
  };

  // 1) http 프로브 — 리다이렉트를 따라가지 않고 관측.
  const httpUrl = toOrigin(base, "http");
  if (httpUrl) {
    try {
      const res = await safeFetch(httpUrl, {
        timeoutMs: 4000,
        maxBytes: 4 * 1024,
        maxRedirects: 1,
        followRedirects: false,
      });
      const loc = res.headers["location"] ?? "";
      const redirected =
        res.status >= 300 && res.status < 400 && /^https:/i.test(loc);
      obs.httpRedirectsToHttps = redirected;
      obs.httpNote = `HTTP ${res.status}${loc ? ` → ${loc}` : ""}`;
    } catch (e) {
      obs.httpNote = e instanceof SafeFetchError ? e.code : "요청 실패";
    }
  }

  // 2) https 프로브 — HSTS 헤더 관측.
  const httpsUrl = toOrigin(base, "https");
  if (httpsUrl) {
    try {
      const res = await safeFetch(httpsUrl, { timeoutMs: 4000, maxBytes: 4 * 1024 });
      obs.hstsPresent = Boolean(res.headers["strict-transport-security"]);
      obs.httpsNote = `HTTP ${res.status}, HSTS ${obs.hstsPresent ? "있음" : "없음"}`;
    } catch (e) {
      obs.httpsNote = e instanceof SafeFetchError ? e.code : "요청 실패";
    }
  }

  return obs;
}

/** 관측 결과가 취약(평문 허용 또는 HSTS 없음)인지. 관측 실패는 취약으로 보지 않는다. */
function isVulnerable(obs: TlsObservation): boolean {
  const plaintextAllowed = obs.httpRedirectsToHttps === false;
  const noHsts = obs.hstsPresent === false;
  return plaintextAllowed || noHsts;
}

export class TlsScanner implements SecurityScanner {
  readonly name = "tls-scanner";
  readonly displayName = "TLS/HTTPS enforcement check";
  readonly step = "deployment_check" as const;
  readonly simulated = false;

  async isApplicable(context: ProjectContext): Promise<boolean> {
    return Boolean(context.deploymentUrl);
  }

  async scan(context: ProjectContext): Promise<SecurityFinding[]> {
    const base = context.deploymentUrl;
    if (!base) return [];

    const obs = await observe(base);
    if (!isVulnerable(obs)) return [];

    const problems: string[] = [];
    if (obs.httpRedirectsToHttps === false)
      problems.push("평문 HTTP가 HTTPS로 리다이렉트되지 않음");
    if (obs.hstsPresent === false) problems.push("HSTS 헤더 없음");

    const evidence: SecurityEvidence[] = [
      {
        id: id("ev"),
        kind: "http_request",
        label: "HTTP 프로브(평문 접근)",
        content: `GET ${toOrigin(base, "http")}\n관측: ${obs.httpNote}`,
      },
      {
        id: id("ev"),
        kind: "http_response",
        label: "HTTPS 응답(HSTS)",
        content: `GET ${toOrigin(base, "https")}\n관측: ${obs.httpsNote}`,
      },
      {
        id: id("ev"),
        kind: "configuration",
        label: "TLS 강제 점검 결과",
        content: `문제:\n- ${problems.join("\n- ")}`,
      },
    ];

    return [
      {
        id: id("finding"),
        scanId: "",
        title: "사이트가 안전하지 않은 연결(HTTP)을 허용합니다",
        severity: "medium",
        category: "Transport Security",
        owasp: "A05 – Security Misconfiguration",
        cwe: "CWE-319",
        cvss: 5.9,
        description: `TLS 강제 점검에서 문제가 발견되었습니다: ${problems.join(", ")}.`,
        humanReadableImpact:
          "연결이 암호화되지 않으면 같은 네트워크의 공격자가 사용자의 데이터나 세션을 가로챌 수 있습니다.",
        whyItMatters:
          "로그인 정보·세션 쿠키가 평문으로 오갈 수 있고, 중간자 공격에 노출됩니다.",
        evidence,
        remediation:
          "모든 HTTP 요청을 HTTPS로 리다이렉트하고, HSTS(Strict-Transport-Security) 헤더를 설정하세요.",
        status: "verified",
        simulated: false,
        verificationKey: `tls:${context.projectId}`,
        createdAt: now(),
        updatedAt: now(),
      },
    ];
  }

  async verify(
    finding: SecurityFinding,
    context: ProjectContext
  ): Promise<VerificationResult> {
    const base = context.deploymentUrl;
    const obs = base
      ? await observe(base)
      : ({
          httpRedirectsToHttps: null,
          hstsPresent: null,
          httpNote: "배포 URL 없음",
          httpsNote: "배포 URL 없음",
        } as TlsObservation);
    const securityPass = base !== undefined && !isVulnerable(obs);

    const security: VerificationTest = {
      id: id("vtest"),
      findingId: finding.id,
      label: "TLS 강제 재점검",
      before: {
        label: "수정 전",
        request: `GET ${base ? toOrigin(base, "http") : "(unknown)"}`,
        response: "평문 허용 또는 HSTS 없음",
        attackSucceeded: true,
      },
      after: {
        label: "수정 후",
        request: `GET ${base ? toOrigin(base, "http") : "(unknown)"}`,
        response: `${obs.httpNote} / ${obs.httpsNote}`,
        attackSucceeded: isVulnerable(obs),
      },
      outcome: securityPass ? "pass" : "fail",
      createdAt: now(),
    };

    const regression: RegressionTest = {
      id: id("rtest"),
      findingId: finding.id,
      checks: [
        {
          label: "HTTPS 정상 응답 유지",
          expectation: "https 요청이 여전히 성공해야 함",
          outcome: obs.hstsPresent !== null ? "pass" : "fail",
          detail: obs.httpsNote,
        },
      ],
      outcome: obs.hstsPresent !== null ? "pass" : "fail",
      createdAt: now(),
    };

    const resolved =
      security.outcome === "pass" && regression.outcome === "pass";
    return { findingId: finding.id, security, regression, resolved };
  }
}
