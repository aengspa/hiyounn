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
 * REAL active scanner (WEB-011 / 지식 베이스 B-2).
 *
 * 하나의 합성 계정에 잘못된 비밀번호로 소수 회(ATTEMPTS) 연속 로그인 시도해
 * 레이트 리밋/계정 잠금(429/잠금 메시지/지연 증가) 존재 여부를 관측한다.
 * 방어 신호가 전혀 없으면 무차별 대입 방어 부재로 본다.
 *
 * 비파괴·저빈도: 항상 잘못된 비밀번호(로그인 성공 없음), 합성 이메일만, 소량.
 * 배포 URL 없으면 applicable=false → coverage_gap.
 */

const LOGIN_PATHS = ["/api/auth/login", "/api/login", "/login"];
const ATTEMPTS = 6;
const SYNTH = { email: "bruteforce-probe-x@example.invalid", password: "wrong-pass" };

interface Attempt {
  status: number | null;
  elapsedMs: number;
  rateLimited: boolean; // 429 또는 잠금 신호
}

function toUrl(base: string, path: string): string | null {
  try {
    const u = new URL(base);
    return new URL(path, `${u.protocol}//${u.host}`).toString();
  } catch {
    return null;
  }
}

async function attempt(url: string): Promise<Attempt> {
  const started = Date.now();
  try {
    const res = await safeFetch(url, {
      method: "POST",
      allowUnsafeMethod: true,
      followRedirects: false,
      timeoutMs: 5000,
      maxBytes: 4 * 1024,
      headers: { "content-type": "application/json" },
      body: JSON.stringify(SYNTH),
    });
    const lockSignal =
      res.status === 429 ||
      /too many|locked|잠금|rate limit|try again later/i.test(res.body);
    return { status: res.status, elapsedMs: Date.now() - started, rateLimited: lockSignal };
  } catch (e) {
    // 타임아웃/차단도 방어 신호로 볼 수 있으나, 여기선 관측 실패로 보수 처리.
    return {
      status: null,
      elapsedMs: Date.now() - started,
      rateLimited: e instanceof SafeFetchError && e.code === "TIMEOUT",
    };
  }
}

async function findLoginUrl(base: string): Promise<string | null> {
  for (const p of LOGIN_PATHS) {
    const url = toUrl(base, p);
    if (!url) continue;
    const a = await attempt(url);
    if (a.status !== null && a.status !== 404) return url;
  }
  return null;
}

/** 연속 시도 결과가 "방어 없음"을 나타내는가? */
function noProtection(attempts: Attempt[]): boolean {
  if (attempts.length === 0) return false;
  const anyLock = attempts.some((a) => a.rateLimited);
  if (anyLock) return false; // 어떤 형태로든 차단이 관측됨 → 방어 있음
  // 모든 시도가 관측되었고(성공 status) 차단이 전혀 없으면 방어 없음.
  const allObserved = attempts.every((a) => a.status !== null);
  return allObserved;
}

async function runAttempts(url: string): Promise<Attempt[]> {
  const out: Attempt[] = [];
  for (let i = 0; i < ATTEMPTS; i++) {
    out.push(await attempt(url));
  }
  return out;
}

export class BruteForceScanner implements SecurityScanner {
  readonly name = "bruteforce-scanner";
  readonly displayName = "Brute-force protection probe";
  readonly step = "dynamic_testing" as const;
  readonly simulated = false;

  async isApplicable(context: ProjectContext): Promise<boolean> {
    return Boolean(context.deploymentUrl);
  }

  async scan(context: ProjectContext): Promise<SecurityFinding[]> {
    const base = context.deploymentUrl;
    if (!base) return [];
    const url = await findLoginUrl(base);
    if (!url) return []; // 엔드포인트 못 찾음 → coverage_gap

    const attempts = await runAttempts(url);
    if (!noProtection(attempts)) return [];

    const evidence: SecurityEvidence[] = [
      {
        id: id("ev"),
        kind: "http_request",
        label: "연속 로그인 시도(합성 계정, 잘못된 비밀번호)",
        content: `POST ${url} × ${attempts.length} (비파괴)`,
      },
      {
        id: id("ev"),
        kind: "http_response",
        label: "시도별 응답",
        content: attempts
          .map((a, i) => `#${i + 1}: HTTP ${a.status} (${a.elapsedMs}ms)`)
          .join("\n"),
      },
      {
        id: id("ev"),
        kind: "scanner_output",
        label: "무차별 대입 방어 판정",
        content: `${attempts.length}회 연속 실패에도 429/잠금/지연 등 방어 신호가 관측되지 않음.`,
      },
    ];

    return [
      {
        id: id("finding"),
        scanId: "",
        title: "로그인에 무차별 대입(비밀번호 자동 시도) 방어가 없습니다",
        severity: "medium",
        category: "Authentication",
        owasp: "A07 – Identification and Authentication Failures",
        cwe: "CWE-307",
        cvss: 5.3,
        description: `${attempts.length}회 연속 로그인 실패에도 레이트 리밋/계정 잠금이 관측되지 않았습니다.`,
        humanReadableImpact:
          "공격자가 자동화 도구로 비밀번호를 무제한 반복 시도해 계정을 탈취할 수 있습니다.",
        whyItMatters:
          "레이트 리밋·잠금이 없으면 크리덴셜 스터핑·무차별 대입 공격에 그대로 노출됩니다.",
        evidence,
        remediation:
          "로그인 실패에 IP+계정 단위 레이트 리밋과 지수 백오프/잠금을 적용하고, 임계치 초과 시 CAPTCHA를 요구하세요.",
        status: "verified",
        simulated: false,
        verificationKey: `brute:${context.projectId}`,
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
    const attempts = url ? await runAttempts(url) : [];
    const anyLock = attempts.some((a) => a.rateLimited);
    const securityPass = url !== null && attempts.length > 0 && anyLock;

    const security: VerificationTest = {
      id: id("vtest"),
      findingId: finding.id,
      label: "무차별 대입 방어 재점검",
      before: {
        label: "수정 전",
        request: "연속 로그인 실패",
        response: "차단 신호 없음",
        attackSucceeded: true,
      },
      after: {
        label: "수정 후",
        request: "연속 로그인 실패",
        response:
          url === null
            ? "로그인 엔드포인트 관측 불가 — 재검증 불가"
            : anyLock
              ? "연속 실패가 차단됨(429/잠금)"
              : "여전히 차단 신호 없음",
        attackSucceeded: !anyLock,
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
          expectation: "첫 시도는 정상적으로 처리(인증 실패 응답)되어야 함",
          outcome:
            attempts[0] && attempts[0].status !== null ? "pass" : "fail",
          detail: attempts[0] ? `#1 → HTTP ${attempts[0].status}` : "관측 없음",
        },
      ],
      outcome:
        attempts[0] && attempts[0].status !== null ? "pass" : "fail",
      createdAt: now(),
    };

    const resolved =
      security.outcome === "pass" && regression.outcome === "pass";
    return { findingId: finding.id, security, regression, resolved };
  }
}
