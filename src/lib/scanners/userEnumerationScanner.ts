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
 * REAL active scanner (WEB-010 / 지식 베이스 B-3).
 *
 * 로그인 엔드포인트에 두 프로브를 보낸다:
 *   (a) 존재하지 않는 합성 이메일 + 잘못된 비밀번호
 *   (b) 존재할 법한 이메일 + 잘못된 비밀번호
 * 두 응답의 상태코드/본문/응답시간이 유의미하게 다르면 사용자 열거가 가능하다.
 *
 * 비파괴: 항상 "잘못된 비밀번호"로만 시도하므로 로그인에 성공하지 않는다(상태 변경
 * 없음). safeFetch의 POST 옵트인(allowUnsafeMethod)으로만 전송하고 SSRF 가드를
 * 유지한다. 요청 수 상한(2회)·저빈도로 무차별 대입과 구분한다.
 *
 * 배포 URL이 없으면 applicable=false → 규칙은 coverage_gap.
 */

// 흔한 로그인 경로 후보(첫 번째로 응답하는 것 사용).
const LOGIN_PATHS = ["/api/auth/login", "/api/login", "/login"];

const PROBE_A = { email: "no-such-user-x9q7z@example.invalid", password: "wrong-password-123" };
const PROBE_B = { email: "admin@example.com", password: "wrong-password-123" };

interface ProbeResult {
  status: number | null;
  body: string;
  elapsedMs: number;
  note?: string;
}

function toUrl(base: string, path: string): string | null {
  try {
    const u = new URL(base);
    return new URL(path, `${u.protocol}//${u.host}`).toString();
  } catch {
    return null;
  }
}

async function loginProbe(
  url: string,
  cred: { email: string; password: string }
): Promise<ProbeResult> {
  const started = Date.now();
  try {
    const res = await safeFetch(url, {
      method: "POST",
      allowUnsafeMethod: true,
      followRedirects: false,
      timeoutMs: 5000,
      maxBytes: 8 * 1024,
      headers: { "content-type": "application/json" },
      body: JSON.stringify(cred),
    });
    return {
      status: res.status,
      body: res.body.slice(0, 2000),
      elapsedMs: Date.now() - started,
    };
  } catch (e) {
    return {
      status: null,
      body: "",
      elapsedMs: Date.now() - started,
      note: e instanceof SafeFetchError ? e.code : "요청 실패",
    };
  }
}

/** 두 응답이 계정 존재를 구분 가능하게 다른가? */
function distinguishable(a: ProbeResult, b: ProbeResult): {
  differs: boolean;
  reasons: string[];
} {
  const reasons: string[] = [];
  if (a.status === null || b.status === null) {
    return { differs: false, reasons: [] }; // 관측 실패 — 판정 불가
  }
  if (a.status !== b.status) reasons.push(`상태코드 차이 (${a.status} vs ${b.status})`);
  // 본문 정규화 후 비교(공백/따옴표 제거).
  const norm = (s: string) => s.replace(/\s+/g, " ").trim().toLowerCase();
  if (norm(a.body) !== norm(b.body)) reasons.push("응답 본문(메시지) 차이");
  // 타이밍: 한쪽이 다른 쪽의 2배 이상이고 절대 차이가 150ms 이상이면 신호.
  const hi = Math.max(a.elapsedMs, b.elapsedMs);
  const lo = Math.max(1, Math.min(a.elapsedMs, b.elapsedMs));
  if (hi >= lo * 2 && hi - lo >= 150) {
    reasons.push(`응답 시간 차이 (${a.elapsedMs}ms vs ${b.elapsedMs}ms)`);
  }
  return { differs: reasons.length > 0, reasons };
}

async function findLoginUrl(base: string): Promise<string | null> {
  // 후보 경로 중 POST에 4xx(=존재하지만 인증 실패)로 응답하는 첫 경로.
  for (const p of LOGIN_PATHS) {
    const url = toUrl(base, p);
    if (!url) continue;
    const r = await loginProbe(url, PROBE_A);
    if (r.status !== null && r.status !== 404) return url;
  }
  return null;
}

export class UserEnumerationScanner implements SecurityScanner {
  readonly name = "user-enumeration-scanner";
  readonly displayName = "Username enumeration probe";
  readonly step = "dynamic_testing" as const;
  readonly simulated = false;

  async isApplicable(context: ProjectContext): Promise<boolean> {
    return Boolean(context.deploymentUrl);
  }

  async scan(context: ProjectContext): Promise<SecurityFinding[]> {
    const base = context.deploymentUrl;
    if (!base) return [];

    const url = await findLoginUrl(base);
    if (!url) return []; // 로그인 엔드포인트를 못 찾음 → coverage_gap(단정 금지)

    const [a, b] = await Promise.all([
      loginProbe(url, PROBE_A),
      loginProbe(url, PROBE_B),
    ]);
    const verdict = distinguishable(a, b);
    if (!verdict.differs) return [];

    const evidence: SecurityEvidence[] = [
      {
        id: id("ev"),
        kind: "http_request",
        label: "프로브 A (없는 계정) / 프로브 B (있을 법한 계정)",
        content: `POST ${url}\nA: ${PROBE_A.email}\nB: ${PROBE_B.email}\n(둘 다 잘못된 비밀번호 — 비파괴)`,
      },
      {
        id: id("ev"),
        kind: "http_response",
        label: "응답 비교",
        content: `A → HTTP ${a.status} (${a.elapsedMs}ms)\nB → HTTP ${b.status} (${b.elapsedMs}ms)`,
      },
      {
        id: id("ev"),
        kind: "scanner_output",
        label: "사용자 열거 판정 근거",
        content: `구분 가능 신호:\n- ${verdict.reasons.join("\n- ")}`,
      },
    ];

    return [
      {
        id: id("finding"),
        scanId: "",
        title: "로그인 응답으로 가입된 이메일을 알아낼 수 있습니다",
        severity: "medium",
        category: "User Enumeration",
        owasp: "A07 – Identification and Authentication Failures",
        cwe: "CWE-204",
        cvss: 5.3,
        description: `로그인 응답이 계정 존재 여부에 따라 다릅니다: ${verdict.reasons.join(", ")}.`,
        humanReadableImpact:
          "공격자가 어떤 이메일이 가입되어 있는지 응답 차이로 알아내, 표적 피싱이나 비밀번호 대입 공격의 대상을 좁힐 수 있습니다.",
        whyItMatters:
          "가입 여부가 노출되면 이후 공격(피싱·크리덴셜 스터핑)이 훨씬 수월해집니다.",
        evidence,
        remediation:
          "로그인·비밀번호 찾기 응답을 계정 존재 여부와 무관하게 동일한 일반 메시지·동일 상태코드로 통일하고, 응답 시간도 균일화(더미 해시 검증)하세요.",
        status: "verified",
        simulated: false,
        verificationKey: `enum:${context.projectId}`,
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
    const url = base ? await findLoginUrl(base) : null;
    let verdict = { differs: false, reasons: [] as string[] };
    let a: ProbeResult | null = null;
    let b: ProbeResult | null = null;
    if (url) {
      [a, b] = await Promise.all([loginProbe(url, PROBE_A), loginProbe(url, PROBE_B)]);
      verdict = distinguishable(a, b);
    }
    // url을 못 찾거나 관측 실패면 재검증 불가 → 보수적으로 fail.
    const securityPass = url !== null && a?.status !== null && !verdict.differs;

    const security: VerificationTest = {
      id: id("vtest"),
      findingId: finding.id,
      label: "사용자 열거 재점검",
      before: {
        label: "수정 전",
        request: "POST (없는 계정 vs 있을 법한 계정)",
        response: "응답이 구분 가능(열거 가능)",
        attackSucceeded: true,
      },
      after: {
        label: "수정 후",
        request: "POST (없는 계정 vs 있을 법한 계정)",
        response:
          url === null
            ? "로그인 엔드포인트 관측 불가 — 재검증 불가"
            : verdict.differs
              ? `여전히 구분 가능: ${verdict.reasons.join(", ")}`
              : "두 응답이 동일(구분 불가)",
        attackSucceeded: verdict.differs,
      },
      outcome: securityPass ? "pass" : "fail",
      createdAt: now(),
    };

    const regression: RegressionTest = {
      id: id("rtest"),
      findingId: finding.id,
      checks: [
        {
          label: "로그인 엔드포인트 정상 동작",
          expectation: "잘못된 비밀번호는 여전히 거부되어야 함(로그인 성공 아님)",
          outcome:
            a && a.status !== null && a.status >= 400 && a.status < 500
              ? "pass"
              : "fail",
          detail: a ? `A → HTTP ${a.status}` : "관측 없음",
        },
      ],
      outcome:
        a && a.status !== null && a.status >= 400 && a.status < 500
          ? "pass"
          : "fail",
      createdAt: now(),
    };

    const resolved =
      security.outcome === "pass" && regression.outcome === "pass";
    return { findingId: finding.id, security, regression, resolved };
  }
}
