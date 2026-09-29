import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import type {
  RegressionTest,
  SecurityEvidence,
  SecurityFinding,
  VerificationResult,
  VerificationTest,
} from "@/lib/domain/types";
import { id, now } from "@/lib/util";
import { safeFetch, type SafeFetchResult } from "@/lib/net/safeFetch";
import { VerificationUnavailableError } from "@/lib/store/errors";

/**
 * REAL scanner (with safe fallback). Checks HTTP security headers and CORS.
 *
 * If a deployment URL is present it performs a single, non-destructive GET via
 * the SSRF-safe fetch layer (src/lib/net/safeFetch) and inspects the response
 * headers — read-only, no attack payloads, internal address ranges blocked.
 * If the fetch fails or no URL is present, it analyzes the project's
 * next.config for a missing-headers signal instead. The two paths are clearly
 * separated and both produce real, evidence-backed findings.
 */

const REQUIRED_HEADERS: { header: string; label: string }[] = [
  { header: "content-security-policy", label: "Content-Security-Policy" },
  { header: "x-frame-options", label: "X-Frame-Options" },
  { header: "x-content-type-options", label: "X-Content-Type-Options" },
  { header: "strict-transport-security", label: "Strict-Transport-Security" },
];

/** 빠진 헤더마다 브라우저가 무엇을 해 주는 설정인지 쉬운 말로. */
const HEADER_PLAIN_KO: Record<string, string> = {
  "Content-Security-Policy": "허락한 곳의 스크립트만 실행하게 하는 설정(Content-Security-Policy)",
  "X-Frame-Options": "다른 사이트가 이 화면을 몰래 틀 안에 넣어 보여 주지 못하게 하는 설정(X-Frame-Options)",
  "X-Content-Type-Options": "파일 종류를 브라우저가 멋대로 짐작해 실행하지 않게 하는 설정(X-Content-Type-Options)",
  "Strict-Transport-Security": "다음 방문부터 항상 암호화된 연결(HTTPS)로만 접속하게 하는 설정(Strict-Transport-Security)",
};

const CORS_TEST_ORIGIN = "https://verification.invalid";

interface LiveObservation {
  result: SafeFetchResult | null;
  unavailableReason: string;
}

interface StaticHeaderObservation {
  configAvailable: boolean;
  hasHeadersFunction: boolean;
  values: Record<string, string[]>;
  recognizedCount: number;
}

function isValidHeaderValue(header: string, value: string): boolean {
  const normalized = value.trim();
  if (header === "content-security-policy") return normalized.length > 0;
  if (header === "x-frame-options") {
    return /^(DENY|SAMEORIGIN)$/i.test(normalized);
  }
  if (header === "x-content-type-options") {
    return /^nosniff$/i.test(normalized);
  }
  if (header === "strict-transport-security") {
    const maxAge = normalized.match(/(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)/i);
    return maxAge !== null && Number(maxAge[1]) > 0;
  }
  return false;
}

function invalidLiveHeaders(headers: Record<string, string>): string[] {
  return REQUIRED_HEADERS.filter(
    ({ header }) => !isValidHeaderValue(header, headers[header] ?? "")
  ).map(({ label }) => label);
}

/** Removes comments without interpreting comment markers inside string literals. */
function stripJavaScriptComments(source: string): string {
  let output = "";
  let quote: "\"" | "'" | "`" | null = null;
  let escaped = false;

  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    const next = source[index + 1];

    if (quote) {
      output += char;
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === quote) {
        quote = null;
      }
      continue;
    }

    if (char === "\"" || char === "'" || char === "`") {
      quote = char;
      output += char;
      continue;
    }
    if (char === "/" && next === "/") {
      while (index < source.length && source[index] !== "\n") index += 1;
      output += "\n";
      continue;
    }
    if (char === "/" && next === "*") {
      index += 2;
      while (
        index < source.length &&
        !(source[index] === "*" && source[index + 1] === "/")
      ) {
        if (source[index] === "\n") output += "\n";
        index += 1;
      }
      index += 1;
      continue;
    }
    output += char;
  }

  return output;
}

function extractBalanced(
  source: string,
  openingIndex: number,
  opener: "{" | "[",
  closer: "}" | "]"
): string | null {
  let depth = 0;
  let quote: "\"" | "'" | "`" | null = null;
  let escaped = false;

  for (let index = openingIndex; index < source.length; index += 1) {
    const char = source[index];
    if (quote) {
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === quote) {
        quote = null;
      }
      continue;
    }
    if (char === "\"" || char === "'" || char === "`") {
      quote = char;
      continue;
    }
    if (char === opener) depth += 1;
    if (char === closer) {
      depth -= 1;
      if (depth === 0) return source.slice(openingIndex, index + 1);
    }
  }

  return null;
}

function extractTopLevelReturnArray(methodBody: string): string | null {
  let braceDepth = 0;
  let quote: "\"" | "'" | "`" | null = null;
  let escaped = false;

  for (let index = 0; index < methodBody.length; index += 1) {
    const char = methodBody[index];
    if (quote) {
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === quote) {
        quote = null;
      }
      continue;
    }
    if (char === "\"" || char === "'" || char === "`") {
      quote = char;
      continue;
    }
    if (char === "{") {
      braceDepth += 1;
      continue;
    }
    if (char === "}") {
      braceDepth -= 1;
      continue;
    }
    if (braceDepth !== 1) continue;

    const returnMatch = /^return\b\s*\[/.exec(methodBody.slice(index));
    if (!returnMatch) continue;
    const arrayOpen = index + returnMatch[0].lastIndexOf("[");
    return extractBalanced(methodBody, arrayOpen, "[", "]");
  }

  return null;
}

function extractHeadersReturnArray(source: string): {
  hasHeadersFunction: boolean;
  returnedArray: string | null;
} {
  const methodMatch = /\b(?:async\s+)?headers\s*\(\s*\)\s*\{/m.exec(source);
  if (!methodMatch) {
    return { hasHeadersFunction: false, returnedArray: null };
  }

  const bodyOpen = methodMatch.index + methodMatch[0].lastIndexOf("{");
  const methodBody = extractBalanced(source, bodyOpen, "{", "}");
  if (!methodBody) {
    return { hasHeadersFunction: true, returnedArray: null };
  }

  // Only accept a literal array returned at the top level of headers().
  // Dynamic variables, nested helpers, or objects elsewhere are inconclusive.
  return {
    hasHeadersFunction: true,
    returnedArray: extractTopLevelReturnArray(methodBody),
  };
}

function observeStaticHeaders(config: string | undefined): StaticHeaderObservation {
  const configAvailable =
    typeof config === "string" && config.trim().length > 0;
  const values: Record<string, string[]> = {};
  if (!configAvailable) {
    return {
      configAvailable: false,
      hasHeadersFunction: false,
      values,
      recognizedCount: 0,
    };
  }

  const uncommented = stripJavaScriptComments(config);
  const { hasHeadersFunction, returnedArray } =
    extractHeadersReturnArray(uncommented);
  if (!hasHeadersFunction || !returnedArray) {
    return { configAvailable, hasHeadersFunction, values, recognizedCount: 0 };
  }

  // Search only the literal array returned by headers(), never unrelated
  // documentation/constants elsewhere in next.config.js.
  const objectPattern = /\{[^{}]*\}/gs;
  let objectMatch: RegExpExecArray | null;
  while ((objectMatch = objectPattern.exec(returnedArray)) !== null) {
    const body = objectMatch[0].slice(1, -1);
    const keyMatch = body.match(/\bkey\s*:\s*(["'`])([^"'`]*)\1\s*(?:,|$)/i);
    const valueMatch = body.match(
      /\bvalue\s*:\s*(["'`])([^"'`]*)\1\s*(?:,|$)/i
    );
    if (!keyMatch || !valueMatch) continue;

    const header = keyMatch[2].trim().toLowerCase();
    if (!REQUIRED_HEADERS.some((required) => required.header === header)) {
      continue;
    }

    const isExplicitLiteral =
      keyMatch[1] !== "`" || !keyMatch[2].includes("${");
    const valueIsExplicitLiteral =
      valueMatch[1] !== "`" || !valueMatch[2].includes("${");
    if (!isExplicitLiteral || !valueIsExplicitLiteral) continue;

    (values[header] ??= []).push(valueMatch[2]);
  }

  const recognizedCount = Object.values(values).reduce(
    (count, headerValues) => count + headerValues.length,
    0
  );
  return { configAvailable, hasHeadersFunction, values, recognizedCount };
}

function invalidStaticHeaders(observation: StaticHeaderObservation): string[] {
  return REQUIRED_HEADERS.filter(({ header }) => {
    const values = observation.values[header] ?? [];
    return (
      values.length === 0 ||
      values.some((value) => !isValidHeaderValue(header, value))
    );
  }).map(({ label }) => label);
}

async function observeAuthorizedDeployment(
  context: ProjectContext,
  headers?: Record<string, string>
): Promise<LiveObservation> {
  if (!context.deploymentUrl) {
    return { result: null, unavailableReason: "배포 URL이 없습니다." };
  }
  if (context.deploymentAuthorized !== true) {
    return {
      result: null,
      unavailableReason: "배포 대상에 대한 검사 권한이 확인되지 않았습니다.",
    };
  }

  try {
    return {
      result: await safeFetch(context.deploymentUrl, {
        timeoutMs: 5000,
        headers,
      }),
      unavailableReason: "",
    };
  } catch {
    return {
      result: null,
      unavailableReason: "안전한 네트워크 관측을 완료하지 못했습니다.",
    };
  }
}

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
        // SSRF 안전 계층 경유: 내부 대역 차단 + 리다이렉트 재검증 + 상한.
        const res = await safeFetch(context.deploymentUrl, { timeoutMs: 5000 });
        headers = res.headers;
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
        rawHeaderDump = "next.config.js의 headers()가 빈 목록을 돌려줘요.";
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
          label: "보안 헤더 점검 결과",
          content: `누락된 헤더:\n- ${missing.join("\n- ")}`,
        },
      ];

      const missingPlain = missing.map((label) => HEADER_PLAIN_KO[label] ?? label).join(", ");

      findings.push({
        id: id("finding"),
        scanId: "",
        title: "브라우저에 이 사이트를 지키는 방법을 알려 주는 설정이 빠져 있어요",
        severity: "medium",
        category: "Security Headers",
        owasp: "A05 – Security Misconfiguration",
        cwe: "CWE-693",
        cvss: 5.3,
        description: `응답에 없는 HTTP 보안 헤더: ${missing.join(", ")}.`,
        humanReadableImpact:
          "브라우저가 스스로 해 줄 수 있는 보호 동작 일부를 하지 않아요. 그래서 다른 사이트가 이 화면을 몰래 끼워 넣거나, 허락하지 않은 스크립트가 실행되는 공격을 브라우저가 막아 주지 못할 수 있어요.",
        whyItMatters: headers
          ? `배포된 사이트(${context.deploymentUrl})에 실제로 요청을 보내 응답을 확인했어요. 응답에 다음 설정이 없었어요: ${missingPlain}.`
          : `코드에서 확인했어요: next.config.js의 headers()가 빈 목록을 돌려줘서 다음 설정이 하나도 붙지 않아요: ${missingPlain}. 호스팅 서비스에서 따로 붙이고 있는지는 확인하지 않았어요.`,
        evidence,
        remediation: `next.config.js의 headers()나 호스팅 서비스 설정에서 빠진 항목(${missing.join(", ")})을 응답에 추가해 주세요. 예를 들어 X-Content-Type-Options: nosniff, X-Frame-Options: DENY를 넣을 수 있어요. Content-Security-Policy는 사이트가 불러오는 스크립트 주소를 확인한 뒤 값을 정해 주세요.`,
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
          title: "다른 웹사이트가 로그인한 사람 대신 이 API를 부를 수 있게 열려 있어요",
          severity: "high",
          category: "CORS",
          owasp: "A05 – Security Misconfiguration",
          cwe: "CWE-942",
          cvss: 7.1,
          description:
            "Access-Control-Allow-Origin이 '*'이면서 Access-Control-Allow-Credentials가 'true'로 설정되어 있어요.",
          humanReadableImpact:
            "사용자가 로그인한 상태로 악성 사이트를 열면, 그 사이트가 사용자의 로그인 정보를 실어 이 API에 요청하고 응답을 읽을 수 있어요.",
          whyItMatters:
            "배포된 사이트에 실제로 요청을 보내 응답을 확인했어요. 응답이 '모든 사이트의 요청 허용(Access-Control-Allow-Origin: *)'과 '로그인 정보도 함께 보내기 허용(Access-Control-Allow-Credentials: true)'을 동시에 켜고 있어요. 다른 사이트에서 실제로 데이터를 읽어 보는 시험은 하지 않았어요.",
          evidence: [
            {
              id: id("ev"),
              kind: "http_response",
              label: "다른 사이트의 요청 허용 설정(CORS 헤더)",
              content: `access-control-allow-origin: ${acao}\naccess-control-allow-credentials: ${acac}`,
            },
          ],
          remediation:
            "Access-Control-Allow-Origin에 '*' 대신 이 API를 불러도 되는 내 사이트 주소만 적어 주세요. 로그인 정보가 필요 없는 API라면 Access-Control-Allow-Credentials를 꺼 주세요.",
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

  async verify(
    finding: SecurityFinding,
    context: ProjectContext
  ): Promise<VerificationResult> {
    const key = finding.verificationKey ?? "";
    const expectedHeadersKey = `headers:${context.projectId}`;
    const expectedCorsKey = `cors:${context.projectId}`;
    const kind =
      key === expectedHeadersKey
        ? "headers"
        : key === expectedCorsKey
          ? "cors"
          : null;

    if (kind === null) throw new VerificationUnavailableError();

    const originalWasLive = finding.evidence.some(
      (evidence) => evidence.kind === "http_response"
    );
    const live = await observeAuthorizedDeployment(
      context,
      kind === "cors" ? { origin: CORS_TEST_ORIGIN } : undefined
    );
    if (live.result && (live.result.status < 200 || live.result.status >= 300)) {
      live.unavailableReason = `검증 대상이 정상 응답(2xx)을 반환하지 않았습니다: HTTP ${live.result.status}.`;
      live.result = null;
    }
    if (
      (kind === "cors" && !live.result) ||
      (kind === "headers" && originalWasLive && !live.result)
    ) {
      throw new VerificationUnavailableError();
    }
    const staticObservation = observeStaticHeaders(
      context.files["next.config.js"]
    );
    const liveInvalidHeaders = live.result
      ? invalidLiveHeaders(live.result.headers)
      : [];
    const staticInvalidHeaders = invalidStaticHeaders(staticObservation);
    const staticSecurityPass =
      staticObservation.configAvailable &&
      staticObservation.hasHeadersFunction &&
      staticInvalidHeaders.length === 0;

    const unsafeCors = live.result
      ? ["*", CORS_TEST_ORIGIN].includes(
          live.result.headers["access-control-allow-origin"]?.trim() ?? ""
        ) &&
        live.result.headers["access-control-allow-credentials"]
          ?.trim()
          .toLowerCase() === "true"
      : false;

    let securityPass = false;
    let requestDetail = "검증 가능한 대상 없음";
    let afterDetail: string;

    if (kind === "cors") {
      requestDetail = `허가된 읽기 전용 GET ${context.deploymentUrl} (Origin: ${CORS_TEST_ORIGIN})`;
      securityPass = !unsafeCors;
      afterDetail = unsafeCors
        ? "공격자 Origin에 대해 credentials가 허용되어 위험한 CORS 동작이 여전히 존재합니다."
        : "공격자 Origin을 보낸 정상 응답에서 wildcard/Origin 반사와 credentials=true 조합이 관측되지 않았습니다.";
    } else if (live.result) {
      requestDetail = `허가된 읽기 전용 GET ${context.deploymentUrl}`;
      securityPass = liveInvalidHeaders.length === 0;
      afterDetail = securityPass
        ? "허가된 라이브 응답에서 필수 보안 헤더 4개와 유효한 값을 확인했습니다."
        : `허가된 라이브 응답에서 값이 없거나 유효하지 않은 헤더: ${liveInvalidHeaders.join(", ")}.`;
    } else {
      if (
        !staticObservation.configAvailable ||
        !staticObservation.hasHeadersFunction ||
        staticObservation.recognizedCount === 0
      ) {
        throw new VerificationUnavailableError();
      }
      requestDetail = "next.config.js 정적 설정 검사";
      securityPass = staticSecurityPass;
      afterDetail = !staticObservation.configAvailable
        ? `${live.unavailableReason} next.config.js도 없거나 비어 있어 정적 검증에 실패했습니다.`
        : !staticObservation.hasHeadersFunction
          ? `${live.unavailableReason} next.config.js에서 명시적인 headers() 설정을 확인하지 못했습니다.`
          : securityPass
            ? "런타임 검사가 아닌 next.config.js 정적 검사에서 필수 보안 헤더 4개와 유효한 리터럴 값을 명시적으로 확인했습니다."
            : `런타임 검사가 아닌 next.config.js 정적 검사에서 값이 없거나 유효하지 않은 헤더: ${staticInvalidHeaders.join(", ")}.`;
    }

    const security: VerificationTest = {
      id: id("vtest"),
      findingId: finding.id,
      label:
        kind === "cors" ? "CORS 라이브 재점검" : "보안 헤더 수정 재점검",
      before: {
        label: "수정 전",
        request:
          kind === "cors"
            ? "최초 배포 응답의 CORS 헤더 검사"
            : "최초 배포 응답 또는 설정의 보안 헤더 검사",
        response:
          kind === "cors"
            ? "와일드카드 origin과 credentials=true 조합이 탐지되었습니다."
            : "필수 보안 헤더 누락이 탐지되었습니다.",
        attackSucceeded: true,
      },
      after: {
        label: "수정 후",
        request: requestDetail,
        response: afterDetail,
        // Missing, unauthorized, or otherwise inconclusive evidence fails closed.
        attackSucceeded: !securityPass,
      },
      outcome: securityPass ? "pass" : "fail",
      createdAt: now(),
    };

    const staticRegressionPass =
      staticObservation.configAvailable &&
      staticObservation.hasHeadersFunction &&
      staticObservation.recognizedCount > 0;
    const regressionPass = live.result
      ? live.result.status < 500
      : staticRegressionPass;
    const regressionDetail = live.result
      ? live.result.status < 500
        ? `허가된 라이브 응답 상태 ${live.result.status}을 확인했습니다.`
        : `허가된 라이브 응답이 5xx 상태(${live.result.status})입니다.`
      : staticRegressionPass
        ? `런타임 검사가 아닌 next.config.js 정적 확인에서 명시적인 보안 헤더 설정 ${staticObservation.recognizedCount}개를 확인했습니다.`
        : `${live.unavailableReason} 비어 있지 않고 명시적으로 인식 가능한 next.config.js 헤더 설정도 없습니다.`;

    const regression: RegressionTest = {
      id: id("rtest"),
      findingId: finding.id,
      checks: [
        {
          label: "배포 또는 정적 설정 유지",
          expectation:
            "허가된 라이브 응답이 5xx가 아니거나, 비어 있지 않은 next.config.js에서 명시적인 헤더 설정이 인식되어야 함",
          outcome: regressionPass ? "pass" : "fail",
          detail: regressionDetail,
        },
      ],
      outcome: regressionPass ? "pass" : "fail",
      createdAt: now(),
    };

    const resolved =
      live.result !== null &&
      security.outcome === "pass" &&
      regression.outcome === "pass";
    return { findingId: finding.id, security, regression, resolved };
  }
}
