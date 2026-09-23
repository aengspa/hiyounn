import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import type {
  SecurityFinding,
  SecurityEvidence,
  VerificationResult,
  VerificationTest,
  RegressionTest,
} from "@/lib/domain/types";
import { id, now } from "@/lib/util";

/**
 * REAL static analysis scanner (regex/signal based).
 *
 * 지식 베이스(docs/security/scan-knowledge-base.md)의 다음 규칙을 구현한다:
 *   - WEB-003 XSS (F-2)          verificationKey `xss:<file>:<line>`
 *   - WEB-004 Injection (F-1/F-3) verificationKey `inj:<file>:<line>`
 *   - WEB-005 Excessive exposure (D-2) verificationKey `expose:<file>:<line>`
 *
 * 모든 검사는 PASSIVE(읽기 전용) SAST다. 대상 앱의 가상 파일 맵(context.files)만
 * 읽고, 코드를 실행하거나 네트워크 요청을 보내지 않는다. 실제 도구(Semgrep 등)로
 * 교체할 때는 이 클래스의 탐지 본문만 바꾸면 된다(인터페이스 유지).
 *
 * 재검증(verify): 수정 후 소스에서 동일한 취약 신호가 사라졌는지 다시 스캔한다
 * (지식 베이스의 `changed-code-scan`). 상태 변경/공격 재현이 없는 정적 규칙이므로
 * 회귀 검사는 "코드가 여전히 파싱 가능한 형태로 남아있는지"의 최소 확인만 한다.
 */

// 소스 파일만 대상(가상 파일 맵에서 설정/락파일 제외).
function isSourceFile(path: string): boolean {
  return (
    /\.(ts|tsx|js|jsx)$/.test(path) || path.startsWith("user-source:")
  );
}

interface Signal {
  /** verificationKey 접두어: xss | inj | expose | trav */
  kind: "xss" | "inj" | "expose" | "trav";
  ruleTitleKo: string;
  regex: RegExp;
  severity: SecurityFinding["severity"];
  owasp: string;
  cwe: string;
  cvss: number;
  category: string;
  title: string;
  humanReadableImpact: string;
  whyItMatters: string;
  remediation: string;
  /** 매치가 안전한(상수만 있는) 경우 제외하기 위한 선택적 판정. */
  isVulnerable?: (line: string) => boolean;
}

// 사용자 제어로 볼 수 있는 표현이 라인에 있는지(변수 보간/연결). 순수 문자열 상수면 제외.
function looksDynamic(line: string): boolean {
  return /\$\{|\+\s*\w|\breq\.|\bparams\b|\bquery\b|\bbody\b|\bsearchParams\b/.test(
    line
  );
}

const MENTIONS_CONSTANT_ONLY = (line: string) =>
  !looksDynamic(line);

// 민감 필드 화이트리스트(WEB-005). 응답에 이 필드가 그대로 나가면 신호.
const SENSITIVE_FIELDS = [
  "password",
  "passwordhash",
  "password_hash",
  "ssn",
  "secret",
  "token",
  "creditcard",
  "credit_card",
];

const SIGNALS: Signal[] = [
  // ── WEB-003 XSS ──────────────────────────────────────────────
  {
    kind: "xss",
    ruleTitleKo: "XSS(교차 사이트 스크립팅)",
    regex: /dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\(/g,
    severity: "high",
    owasp: "A03 – Injection",
    cwe: "CWE-79",
    cvss: 6.8,
    category: "Cross-Site Scripting",
    title: "사용자 입력이 그대로 화면에 삽입될 수 있습니다 (XSS)",
    humanReadableImpact:
      "사용자가 입력한 값이 안전하게 처리되지 않고 페이지에 그대로 들어가면, 공격자가 심어둔 스크립트가 방문자의 브라우저에서 실행될 수 있습니다.",
    whyItMatters:
      "공격자가 다른 사용자의 세션을 탈취하거나 화면을 조작할 수 있습니다.",
    remediation:
      "HTML을 직접 삽입하지 말고 텍스트로 렌더링하거나, 신뢰할 수 있는 정제(sanitize) 라이브러리로 처리하세요.",
    isVulnerable: (line) => looksDynamic(line), // 동적 값이 들어갈 때만 취약으로 본다
  },

  // ── WEB-004 Injection: SQL ───────────────────────────────────
  {
    kind: "inj",
    ruleTitleKo: "인젝션(SQL·커맨드·eval)",
    // SQL 키워드를 포함하면서 보간(${})이나 문자열 연결(+)이 있는 라인.
    // (라인 단위로 실행되므로 isVulnerable에서 SQL 키워드 동반을 재확인한다.)
    regex:
      /(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|\bWHERE\b)[\s\S]*?(?:\$\{|["'`]\s*\+|\+\s*["'`])/gi,
    severity: "critical",
    owasp: "A03 – Injection",
    cwe: "CWE-89",
    cvss: 9.1,
    category: "Injection",
    title: "데이터베이스 쿼리에 입력값이 직접 조립됩니다 (SQL 인젝션)",
    humanReadableImpact:
      "사용자 입력을 그대로 붙여 쿼리를 만들면, 공격자가 쿼리 구조를 바꿔 데이터를 훔치거나 지울 수 있습니다.",
    whyItMatters:
      "데이터베이스 전체가 읽히거나 손상될 수 있는 매우 심각한 취약점입니다.",
    remediation:
      "문자열을 붙이지 말고 파라미터 바인딩(prepared statement)을 사용하세요.",
    isVulnerable: (line) =>
      /(?:SELECT|INSERT|UPDATE|DELETE|WHERE)/i.test(line) && looksDynamic(line),
  },

  // ── WEB-004 Injection: command / eval ────────────────────────
  {
    kind: "inj",
    ruleTitleKo: "인젝션(SQL·커맨드·eval)",
    regex: /\beval\s*\(|new\s+Function\s*\(|exec\s*\(|execSync\s*\(/g,
    severity: "critical",
    owasp: "A03 – Injection",
    cwe: "CWE-94",
    cvss: 8.8,
    category: "Injection",
    title: "코드/명령이 동적으로 실행됩니다 (코드·커맨드 인젝션)",
    humanReadableImpact:
      "입력값으로 코드나 시스템 명령을 만들어 실행하면, 공격자가 서버에서 임의 코드를 실행할 수 있습니다.",
    whyItMatters:
      "서버가 완전히 장악될 수 있습니다.",
    remediation:
      "eval/new Function/exec 사용을 제거하고, 안전한 API나 인자 배열 기반 실행으로 대체하세요.",
    isVulnerable: (line) => looksDynamic(line),
  },

  // ── WEB-006 Path traversal ───────────────────────────────────
  {
    kind: "trav",
    ruleTitleKo: "경로 트래버설(디렉터리 접근 우회)",
    // 실제 파일 시스템에 접근하는 싱크만 대상으로 한다. 경로 조립 함수
    // (path.join/resolve/basename)는 그 자체로 위험하지 않으므로 제외한다
    // (오히려 정규화·봉쇄에 쓰이므로 싱크로 보면 오탐이 난다).
    regex:
      /\b(?:readFileSync|readFile|createReadStream|createWriteStream|writeFileSync|writeFile|sendFile|unlinkSync|unlink)\s*\(/g,
    severity: "high",
    owasp: "A01 – Broken Access Control",
    cwe: "CWE-22",
    cvss: 7.5,
    category: "Path Traversal",
    title: "사용자 입력이 파일 경로로 그대로 사용됩니다 (경로 트래버설)",
    humanReadableImpact:
      "사용자가 준 값을 검증 없이 파일 경로로 쓰면, 공격자가 '../' 같은 값으로 서버의 다른 파일(설정·비밀 파일 등)을 읽어낼 수 있습니다.",
    whyItMatters:
      "허용된 폴더 밖의 파일이 노출되어 시스템 정보나 비밀 값이 유출될 수 있습니다.",
    remediation:
      "경로를 정규화(path.normalize/resolve)한 뒤 기준 디렉터리 안에 있는지 확인하고(startsWith), 파일명은 화이트리스트로 제한하세요.",
    // 판정은 taintedPathInput(창 단위)에서 수행 — 입력이 다른 줄에서 흐를 수 있음.
  },

  // ── WEB-005 Excessive data exposure ──────────────────────────
  {
    kind: "expose",
    ruleTitleKo: "민감정보 응답 과다 노출",
    // 응답 반환부에 민감 필드가 등장. (라인 단위 후처리에서 정밀 판정)
    regex:
      /(?:res\.json|NextResponse\.json|Response\.json|return\s+json|\.send)\s*\(/g,
    severity: "high",
    owasp: "A03:2023 – Excessive Data Exposure",
    cwe: "CWE-213",
    cvss: 6.5,
    category: "Excessive Data Exposure",
    title: "API 응답에 민감한 필드가 그대로 포함될 수 있습니다",
    humanReadableImpact:
      "응답에서 비밀번호 해시 같은 민감한 필드를 걸러내지 않으면, 그 값이 외부로 노출됩니다.",
    whyItMatters:
      "노출된 해시·토큰·개인정보가 공격에 재사용될 수 있습니다.",
    remediation:
      "응답 전 필요한 필드만 명시적으로 선택(화이트리스트)하고, 민감 필드는 제거하세요.",
  },
];

/** WEB-005 전용: 응답 반환 라인 주변에 민감 필드가 있는지 판정. */
function exposesSensitiveField(lines: string[], lineIdx: number): string[] {
  // 반환문과 같은 라인 및 인접 2줄을 함께 본다(객체가 여러 줄일 수 있음).
  const window = lines
    .slice(Math.max(0, lineIdx - 2), lineIdx + 3)
    .join("\n")
    .toLowerCase();
  return SENSITIVE_FIELDS.filter((f) => window.includes(f));
}

/**
 * WEB-006 전용: 파일/경로 API 호출이 "오염된 입력"을 받는지 판정.
 * 입력이 다른 줄에서 흘러들 수 있으므로 호출 라인 + 위쪽 4줄을 함께 본다.
 * 같은 창에 정규화(normalize/resolve) + 기준 디렉터리 봉쇄(startsWith)가
 * 이미 있으면 안전한 것으로 보고 제외한다.
 */
function taintedPathInput(lines: string[], lineIdx: number): boolean {
  const start = Math.max(0, lineIdx - 4);
  const windowLines = lines.slice(start, lineIdx + 1);
  const sinkLine = lines[lineIdx] ?? "";
  const windowText = windowLines.join("\n");

  // 호출 인자가 순수 문자열 리터럴만이면(동적 요소 없음) 안전.
  const sinkHasBareArg = /\(\s*[^)"'`]*[A-Za-z_$][\w$.]*\s*[),]/.test(sinkLine);
  const dynamicNearby = looksDynamic(windowText) || sinkHasBareArg;

  const contained =
    /normalize|resolve|basename/.test(windowText) &&
    /startsWith|includes\(/.test(windowText);

  return dynamicNearby && !contained;
}

function lineNumberAt(content: string, index: number): number {
  return content.slice(0, index).split("\n").length;
}

function scanFile(file: string, content: string): SecurityFinding[] {
  const out: SecurityFinding[] = [];
  const lines = content.split("\n");

  for (const sig of SIGNALS) {
    sig.regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = sig.regex.exec(content)) !== null) {
      const lineNo = lineNumberAt(content, m.index);
      const lineText = lines[lineNo - 1] ?? "";

      // WEB-005는 반환문 자체가 아니라 민감 필드 동반 여부로 판정.
      let exposedFields: string[] = [];
      if (sig.kind === "expose") {
        exposedFields = exposesSensitiveField(lines, lineNo - 1);
        if (exposedFields.length === 0) continue; // 민감 필드 없으면 신호 아님
      } else if (sig.kind === "trav") {
        // WEB-006은 입력이 다른 줄에서 흘러들 수 있어 창(window) 단위로 판정.
        if (!taintedPathInput(lines, lineNo - 1)) continue;
      } else if (sig.isVulnerable && !sig.isVulnerable(lineText)) {
        continue; // 상수만 있는 안전한 사용은 제외
      }

      const scannerDetail =
        sig.kind === "expose"
          ? `규칙: ${sig.ruleTitleKo}\n파일: ${file}\n줄: ${lineNo}\n노출 가능 필드: ${exposedFields.join(", ")}`
          : `규칙: ${sig.ruleTitleKo}\n파일: ${file}\n줄: ${lineNo}\n일치: ${lineText.trim().slice(0, 200)}`;

      const evidence: SecurityEvidence[] = [
        {
          id: id("ev"),
          kind: "source_code",
          label: `${file}:${lineNo}`,
          content: lineText.trim(),
          language: "typescript",
        },
        {
          id: id("ev"),
          kind: "scanner_output",
          label: "정적 분석 스캐너 출력",
          content: scannerDetail,
        },
      ];

      out.push({
        id: id("finding"),
        scanId: "",
        title: sig.title,
        severity: sig.severity,
        category: sig.category,
        owasp: sig.owasp,
        cwe: sig.cwe,
        cvss: sig.cvss,
        description: `${sig.ruleTitleKo} 신호가 ${file} ${lineNo}번째 줄에서 발견되었습니다.`,
        humanReadableImpact: sig.humanReadableImpact,
        whyItMatters: sig.whyItMatters,
        location: { file, line: lineNo },
        evidence,
        remediation: sig.remediation,
        status: "detected",
        simulated: false,
        verificationKey: `${sig.kind}:${file}:${lineNo}`,
        createdAt: now(),
        updatedAt: now(),
      });
    }
  }

  return out;
}

/** 단일 파일에서 특정 종류(kind)의 취약 신호가 남아있는지 재검사(verify용). */
function stillVulnerable(
  content: string,
  kind: "xss" | "inj" | "expose" | "trav"
): boolean {
  const lines = content.split("\n");
  for (const sig of SIGNALS) {
    if (sig.kind !== kind) continue;
    sig.regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = sig.regex.exec(content)) !== null) {
      const lineNo = lineNumberAt(content, m.index);
      const lineText = lines[lineNo - 1] ?? "";
      if (kind === "expose") {
        if (exposesSensitiveField(lines, lineNo - 1).length > 0) return true;
      } else if (kind === "trav") {
        if (taintedPathInput(lines, lineNo - 1)) return true;
      } else if (!sig.isVulnerable || sig.isVulnerable(lineText)) {
        return true;
      }
    }
  }
  return false;
}

export class StaticWebScanner implements SecurityScanner {
  readonly name = "static-web-scanner";
  readonly displayName = "Static web code analysis";
  readonly step = "static_analysis" as const;
  readonly simulated = false;

  async isApplicable(context: ProjectContext): Promise<boolean> {
    return Object.keys(context.files).some(isSourceFile);
  }

  async scan(context: ProjectContext): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    for (const [file, content] of Object.entries(context.files)) {
      if (!isSourceFile(file)) continue;
      findings.push(...scanFile(file, content));
    }
    return findings;
  }

  /**
   * changed-code-scan 재검증. 수정 후 소스에서 동일 신호가 사라졌으면 통과.
   * context.files는 수정 반영본이어야 한다(현재 데모 컨텍스트는 정적 픽스처라,
   * 수정 반영 소스가 없으면 이 검사는 보수적으로 fail로 남긴다 — "안전 오판" 금지).
   */
  async verify(
    finding: SecurityFinding,
    context: ProjectContext
  ): Promise<VerificationResult> {
    const key = finding.verificationKey ?? "";
    const kind = key.split(":")[0] as "xss" | "inj" | "expose" | "trav";
    const file = finding.location?.file;
    const source = file ? context.files[file] : undefined;

    const before = true; // 최초 탐지 시 취약했음(스캔에서 확정)
    const after =
      source !== undefined ? stillVulnerable(source, kind) : true;
    const securityPass = before && !after;

    const security: VerificationTest = {
      id: id("vtest"),
      findingId: finding.id,
      label: "수정 후 정적 재스캔(changed-code-scan)",
      before: {
        label: "수정 전",
        request: `SAST re-scan: ${file ?? "(unknown)"}`,
        response: "취약 신호 존재",
        attackSucceeded: true,
      },
      after: {
        label: "수정 후",
        request: `SAST re-scan: ${file ?? "(unknown)"}`,
        response:
          source === undefined
            ? "수정 반영 소스가 없어 재스캔 불가"
            : after
              ? "취약 신호가 여전히 존재"
              : "취약 신호 사라짐",
        attackSucceeded: after,
      },
      outcome: securityPass ? "pass" : "fail",
      createdAt: now(),
    };

    // 정적 규칙은 실행 흐름을 바꾸지 않으므로 회귀 검사는 최소 확인만.
    const regression: RegressionTest = {
      id: id("rtest"),
      findingId: finding.id,
      checks: [
        {
          label: "소스가 유효하게 유지됨",
          expectation: "수정된 파일이 여전히 존재하고 비어있지 않아야 함",
          outcome: source && source.trim().length > 0 ? "pass" : "fail",
          detail: file
            ? `${file} 길이 ${source?.length ?? 0}`
            : "파일 위치 불명",
        },
      ],
      outcome: source && source.trim().length > 0 ? "pass" : "fail",
    createdAt: now(),
    };

    const resolved =
      security.outcome === "pass" && regression.outcome === "pass";

    return { findingId: finding.id, security, regression, resolved };
  }
}
