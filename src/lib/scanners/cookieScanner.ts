import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import type {
  SecurityFinding,
  SecurityEvidence,
  VerificationResult,
  VerificationTest,
  RegressionTest,
} from "@/lib/domain/types";
import { id, now, maskSecret } from "@/lib/util";
import { safeFetch } from "@/lib/net/safeFetch";

/**
 * REAL active scanner (WEB-012 / 지식 베이스 B-4).
 *
 * 배포 origin의 응답 Set-Cookie를 관측해 세션 쿠키의 HttpOnly/Secure/SameSite
 * 속성 누락을 찾는다. 읽기 전용 GET(safeFetch)만 사용한다.
 *
 * 쿠키 값(세션 토큰)은 저장·표시 전 마스킹한다. Set-Cookie가 없으면 결과 없음
 * (coverage_gap). 세션 고정(로그인 후 토큰 미회전)은 향후 확장.
 */

interface CookieObservation {
  raw: string; // 마스킹된 Set-Cookie
  name: string;
  missing: string[]; // 누락 속성
}

function parseSetCookie(setCookie: string): CookieObservation[] {
  // fetch Headers는 여러 Set-Cookie를 콤마로 합칠 수 있다. 안전하게 분리:
  // "name=val; attrs, name2=val2; attrs" — 쿠키 경계는 ", <token>=" 패턴.
  const parts = setCookie.split(/,(?=[^;,\s]+=)/);
  const out: CookieObservation[] = [];
  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf("=");
    const name = eq > 0 ? trimmed.slice(0, eq) : trimmed.split(";")[0];
    const lower = trimmed.toLowerCase();
    const missing: string[] = [];
    if (!/;\s*httponly/.test(lower)) missing.push("HttpOnly");
    if (!/;\s*secure/.test(lower)) missing.push("Secure");
    if (!/;\s*samesite=/.test(lower)) missing.push("SameSite");

    // 쿠키 값 마스킹.
    const masked = trimmed.replace(
      /^([^=]+)=([^;]+)/,
      (_all, k: string, v: string) => `${k}=${maskSecret(v)}`
    );
    out.push({ raw: masked, name, missing });
  }
  return out;
}

async function observeCookies(base: string): Promise<CookieObservation[] | null> {
  try {
    const res = await safeFetch(base, { timeoutMs: 4000, maxBytes: 8 * 1024 });
    const setCookie = res.headers["set-cookie"];
    if (!setCookie) return null; // Set-Cookie 없음 → 관측 불가
    return parseSetCookie(setCookie);
  } catch {
    return null;
  }
}

export class CookieScanner implements SecurityScanner {
  readonly name = "cookie-scanner";
  readonly displayName = "Session cookie attribute check";
  readonly step = "deployment_check" as const;
  readonly simulated = false;

  async isApplicable(context: ProjectContext): Promise<boolean> {
    return Boolean(context.deploymentUrl);
  }

  async scan(context: ProjectContext): Promise<SecurityFinding[]> {
    const base = context.deploymentUrl;
    if (!base) return [];
    const cookies = await observeCookies(base);
    if (!cookies || cookies.length === 0) return []; // coverage_gap

    const insecure = cookies.filter((c) => c.missing.length > 0);
    if (insecure.length === 0) return [];

    const evidence: SecurityEvidence[] = [
      {
        id: id("ev"),
        kind: "http_response",
        label: "관측된 Set-Cookie (값 마스킹)",
        content: insecure.map((c) => c.raw).join("\n"),
        masked: true,
      },
      {
        id: id("ev"),
        kind: "configuration",
        label: "쿠키 속성 점검",
        content: insecure
          .map((c) => `${c.name}: 누락 → ${c.missing.join(", ")}`)
          .join("\n"),
      },
    ];

    return [
      {
        id: id("finding"),
        scanId: "",
        title: "세션 쿠키에 보안 속성이 빠져 있습니다",
        severity: "medium",
        category: "Session Management",
        owasp: "A05 – Security Misconfiguration",
        cwe: "CWE-1004",
        cvss: 5.4,
        description: `세션 쿠키에 보안 속성이 누락되었습니다: ${insecure
          .map((c) => `${c.name}(${c.missing.join("/")})`)
          .join(", ")}.`,
        humanReadableImpact:
          "쿠키에 보호 속성이 없으면 스크립트가 세션 쿠키를 훔치거나(HttpOnly 없음), 평문 연결로 새어나가거나(Secure 없음), 다른 사이트 요청에 실려 나갈 수 있습니다(SameSite 없음).",
        whyItMatters:
          "세션 쿠키 탈취는 곧 계정 탈취로 이어집니다.",
        evidence,
        remediation:
          "세션 쿠키에 HttpOnly, Secure, SameSite(Lax 또는 Strict) 속성을 모두 설정하세요.",
        status: "verified",
        simulated: false,
        verificationKey: `cookie:${context.projectId}`,
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
    const cookies = base ? await observeCookies(base) : null;
    const insecure = (cookies ?? []).filter((c) => c.missing.length > 0);
    const securityPass =
      base !== undefined && cookies !== null && insecure.length === 0;

    const security: VerificationTest = {
      id: id("vtest"),
      findingId: finding.id,
      label: "세션 쿠키 속성 재점검",
      before: {
        label: "수정 전",
        request: `GET ${base ?? "(unknown)"}`,
        response: "쿠키에 보안 속성 누락",
        attackSucceeded: true,
      },
      after: {
        label: "수정 후",
        request: `GET ${base ?? "(unknown)"}`,
        response:
          cookies === null
            ? "Set-Cookie 관측 불가 — 재검증 불가"
            : insecure.length === 0
              ? "모든 쿠키에 HttpOnly/Secure/SameSite 설정됨"
              : `여전히 누락: ${insecure.map((c) => c.name).join(", ")}`,
        attackSucceeded: insecure.length > 0,
      },
      outcome: securityPass ? "pass" : "fail",
      createdAt: now(),
    };

    const regression: RegressionTest = {
      id: id("rtest"),
      findingId: finding.id,
      checks: [
        {
          label: "세션 쿠키 발급 유지",
          expectation: "사이트가 여전히 세션 쿠키를 발급해야 함",
          outcome: cookies !== null && cookies.length > 0 ? "pass" : "fail",
          detail: `관측된 쿠키 ${cookies?.length ?? 0}개`,
        },
      ],
      outcome: cookies !== null && cookies.length > 0 ? "pass" : "fail",
      createdAt: now(),
    };

    const resolved =
      security.outcome === "pass" && regression.outcome === "pass";
    return { findingId: finding.id, security, regression, resolved };
  }
}
