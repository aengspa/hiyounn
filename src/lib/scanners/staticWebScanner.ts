import type { SecurityScanner, ProjectContext } from "@/lib/scanners/types";
import type {
  SecurityFinding,
  SecurityEvidence,
  VerificationResult,
  VerificationTest,
  RegressionTest,
} from "@/lib/domain/types";
import { id, now } from "@/lib/util";
import { stillPresentAfterFix } from "@/lib/scanners/findingPresence";

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
  /** verificationKey 접두어: xss | inj | expose | trav | sidor */
  kind: "xss" | "inj" | "expose" | "trav" | "sidor";
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

const SQL_KEYWORD = /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|WHERE)\b/i;

/**
 * SQL 문자열 자체가 값과 이어 붙거나 보간되는지 본다. 같은 줄의 바인딩 인자
 * (예: `.all(id, "%" + q + "%")`)에서 일어나는 연결은 쿼리 구조를 바꾸지 못하므로
 * 취약으로 보지 않는다. 줄 안에 SQL 문자열이 온전히 없으면(여러 줄 템플릿의 중간 줄 등)
 * 줄 전체로 판단한다.
 */
function sqlStringIsBuilt(line: string): boolean {
  let sawSql = false;
  for (const m of line.matchAll(/(["'`])((?:\\.|(?!\1)[^\\\n])*)\1/g)) {
    if (!SQL_KEYWORD.test(m[2])) continue;
    sawSql = true;
    if (m[1] === "`" && m[2].includes("${")) return true;
    const before = line.slice(0, m.index);
    const after = line.slice((m.index ?? 0) + m[0].length);
    if (/\+\s*$/.test(before) || /^\s*\+(?!=)/.test(after)) return true;
  }
  return sawSql ? false : looksDynamic(line);
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

// 두 XSS 신호는 같은 문제이므로 제목·영향 문구를 같이 쓴다.
const XSS_TITLE = "사용자가 입력한 글이 화면에서 코드처럼 실행될 수 있어요 (XSS)";
const XSS_IMPACT =
  "누군가 심어 둔 스크립트가 이 화면을 여는 사람의 브라우저에서 실행될 수 있어요. 그러면 화면 내용이 바뀌거나 그 사람의 로그인 상태가 다른 사람에게 넘어갈 수 있어요.";

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
    title: XSS_TITLE,
    humanReadableImpact: XSS_IMPACT,
    whyItMatters:
      "코드에서 확인했어요: 이 줄은 HTML을 화면에 직접 넣는 코드(innerHTML, dangerouslySetInnerHTML, document.write 중 하나)이고, 같은 줄에 바깥에서 들어온 값이 섞여 있어요. 그 값이 실제로 사용자 입력인지, 앞에서 걸러지는지는 확인하지 못했어요.",
    remediation:
      "사용자가 입력한 글을 HTML로 넣지 말고 글자로만 표시하도록 바꿔 주세요(예: textContent 사용, React에서는 {값} 형태로 출력). 꼭 HTML을 보여 줘야 한다면 DOMPurify 같은 검증된 도구로 위험한 태그를 지운 뒤 넣어 주세요.",
    isVulnerable: (line) => looksDynamic(line), // 동적 값이 들어갈 때만 취약으로 본다
  },

  // ── WEB-003 XSS (서버가 만든 HTML 응답) ─────────────────────────
  {
    kind: "xss",
    ruleTitleKo: "XSS(교차 사이트 스크립팅)",
    // res.send/write/end에 HTML 태그 문자열과 요청 값이 한 줄에서 이어 붙는 경우.
    regex: /\bres\.(?:send|write|end)\s*\([^\n]*<[a-zA-Z!/][^\n]*/g,
    severity: "high",
    owasp: "A03 – Injection",
    cwe: "CWE-79",
    cvss: 6.8,
    category: "Cross-Site Scripting",
    title: XSS_TITLE,
    humanReadableImpact: XSS_IMPACT,
    whyItMatters:
      "코드에서 확인했어요: 서버가 HTML 응답을 만들 때 요청으로 받은 값(req.query 등)을 그대로 이어 붙이고 있어요. 이 줄에서는 특수문자를 글자로 바꿔 주는 처리(이스케이프)를 찾지 못했어요.",
    remediation:
      "응답 HTML에 넣기 전에 값의 <, >, \", ', & 같은 특수문자를 글자로 바꿔(HTML 이스케이프) 주세요. 템플릿 엔진을 쓴다면 자동 이스케이프가 켜진 출력 방식으로 넣어 주세요.",
    isVulnerable: (line) =>
      /(?:\+|\$\{)/.test(line) &&
      /\breq\.(?:query|params|body|cookies|headers)\b|\brequest\.|searchParams/.test(line) &&
      !/escape|sanitize|encode|DOMPurify|&lt;|xss\(/i.test(line),
  },

  // ── WEB-004 Injection: SQL ───────────────────────────────────
  {
    kind: "inj",
    ruleTitleKo: "인젝션(SQL·커맨드·eval)",
    // SQL 키워드를 포함하면서 보간(${})이나 문자열 연결(+)이 있는 라인.
    // 한 줄 안에서만 찾는다([^\n]). 줄을 넘어가면 바인딩 파라미터로 고친 쿼리가
    // 아래쪽 다른 줄의 문자열 연결과 이어져 "아직 취약"으로 잘못 잡힌다.
    regex:
      /(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|\bWHERE\b)[^\n]*?(?:\$\{|["'`]\s*\+|\+\s*["'`])/gi,
    severity: "critical",
    owasp: "A03 – Injection",
    cwe: "CWE-89",
    cvss: 9.1,
    category: "Injection",
    title: "사용자가 보낸 값으로 데이터베이스 쿼리를 직접 만들고 있어요 (SQL 인젝션)",
    humanReadableImpact:
      "누군가 입력값에 쿼리 조각을 섞어 보내면 데이터베이스가 원래 의도와 다른 일을 할 수 있어요. 그러면 저장된 데이터가 밖으로 새거나 지워질 수 있어요.",
    whyItMatters:
      "코드에서 확인했어요: SQL 문장을 만들 때 문자열 이어 붙이기(+)나 ${...} 끼워 넣기로 값을 직접 넣고 있어요. 그 값이 실제로 사용자 입력에서 오는지는 주변 코드까지 확인하지 못했어요.",
    remediation:
      "값을 SQL 문장에 직접 이어 붙이지 말고, 자리 표시자(? 또는 $1)를 쓰고 값은 따로 넘기는 방식(파라미터 바인딩)으로 바꿔 주세요.",
    isVulnerable: (line) => /(?:SELECT|INSERT|UPDATE|DELETE|WHERE)/i.test(line) && sqlStringIsBuilt(line),
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
    title: "입력값으로 서버에서 코드나 명령이 실행될 수 있어요 (코드·커맨드 인젝션)",
    humanReadableImpact:
      "누군가 값을 조작해 보내면 서버에서 원하지 않는 코드나 시스템 명령이 실행될 수 있어요. 그러면 서버의 파일과 데이터를 다른 사람이 마음대로 다룰 수 있게 돼요.",
    whyItMatters:
      "코드에서 확인했어요: eval, new Function, exec, execSync 중 하나를 쓰는 줄에 바깥에서 들어온 값이 섞여 있어요. 그 값이 실제로 사용자 입력인지는 주변 코드까지 확인하지 못했어요.",
    remediation:
      "eval과 new Function은 지우고 필요한 동작을 일반 함수로 직접 작성해 주세요. 시스템 명령이 꼭 필요하면 exec 대신 execFile처럼 명령과 값을 따로 넘기고, 허용할 값의 목록을 정해 그 밖의 값은 거절해 주세요.",
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
    title: "사용자가 보낸 값이 파일 경로로 그대로 쓰일 수 있어요 (경로 트래버설)",
    humanReadableImpact:
      "누군가 '../' 같은 값을 보내면 허용한 폴더 밖에 있는 서버 파일(설정 파일 등)을 읽거나 바꿀 수 있어요.",
    whyItMatters:
      "코드에서 확인했어요: 파일을 읽거나 쓰는 코드에 바깥에서 들어온 값이 경로로 들어가요. 바로 위 몇 줄에서 경로를 정리한 뒤 허용한 폴더 안인지 확인하는 처리를 찾지 못했어요.",
    remediation:
      "path.resolve로 경로를 정리한 뒤, 결과가 허용한 폴더 경로로 시작하는지(startsWith) 확인하고 아니면 거절해 주세요. 가능하면 파일 이름을 허용 목록이나 영문·숫자 형식으로만 받도록 제한해 주세요.",
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
    // 제목에 "비밀"·"경로" 같은 단어를 넣지 않는다(findingMerge의 문제 종류 분류가 바뀜).
    title: "API 응답에 민감한 값이 함께 나갈 수 있어요",
    humanReadableImpact:
      "응답을 받는 사람이 비밀번호 해시나 토큰처럼 보여 주면 안 되는 값을 볼 수 있어요.",
    // 실제 필드 이름은 scanFile에서 덧붙인다.
    whyItMatters:
      "코드에서 확인했어요: 응답을 보내는 줄 근처에 민감한 필드 이름이 있어요. 그 필드가 실제로 응답에 담기는지는 실행해 보지 않아 확인하지 못했어요.",
    remediation:
      "응답에는 화면에 꼭 필요한 필드만 골라 담아 주세요. 비밀번호 해시나 토큰 같은 값은 응답 객체에서 빼 주세요.",
  },

  // ── WEB-014 IDOR (static signal) ─────────────────────────────
  {
    kind: "sidor",
    ruleTitleKo: "IDOR(객체 수준 권한 확인 누락)",
    // id로 단일 리소스를 조회/반환하는 싱크. 소유자 검증 여부는 창(window)
    // 단위로 별도 판정한다(hasOwnershipCheck) — 검증이 다른 줄에 있을 수 있음.
    regex:
      /\b(?:findUnique|findFirst|findById|getById|getTodoById|getUserById|\.get\s*\(\s*(?:req\.params|params)\.[\w$]*id|res\.json\s*\(\s*\{?\s*(?:todo|user|record|item|order)\b)/g,
    severity: "critical",
    owasp: "A01 – Broken Access Control",
    cwe: "CWE-639",
    cvss: 8.1,
    category: "Broken Object Level Authorization",
    title: "다른 사람의 정보를 볼 수 있는지 확인이 필요해요 (IDOR)",
    humanReadableImpact:
      "로그인한 사람이 주소나 요청에 담긴 번호(id)만 바꿔서 다른 사람의 정보를 보거나 바꿀 수 있어요.",
    whyItMatters:
      "코드에서 확인했어요: 번호(id)로 정보 하나를 찾아 돌려주는데, 요청한 정보가 로그인한 사람의 것인지 확인하는 부분을 근처 코드에서 찾지 못했어요. 다른 파일에서 확인하고 있는지와 실제로 다른 사람의 정보가 보이는지는 실행해 확인하지 않았어요.",
    remediation:
      "정보를 보여 주기 전에 그 정보가 현재 로그인한 사람의 것인지 확인하도록 바꿔 주세요. 예를 들어 정보의 주인(ownerId, userId)이 로그인한 사람의 id와 다르면 403 응답으로 거절해 주세요.",
    // 판정은 hasOwnershipCheck(창 단위)에서 수행.
  },
];

// 소유자(권한) 검증으로 볼 만한 표현. 이게 리소스 조회 주변에 있으면 IDOR가 아님.
const OWNERSHIP_CHECK =
  /ownerId|owner_id|userId\s*[!=]==|user_id|session\.user|currentUser|req\.user|auth\.uid|\.owner\b|belongsTo|assertOwner|isOwner|403|Forbidden|Unauthorized/i;

// id 기반 단일 리소스 조회로 볼 만한 표현.
const FETCH_BY_ID =
  /findUnique|findFirst|findById|getById|getTodoById|getUserById|where\s*:\s*\{\s*id|params\.[\w$]*id|params\[["']id/i;

/**
 * WEB-014 전용: id로 리소스를 조회/반환하는 지점 주변에 소유자 검증이 있는지
 * 판정. 검증이 다른 줄(핸들러 상단 등)에 있을 수 있어 위/아래를 함께 본다.
 * 조회 신호는 있는데 창(window) 안에 소유자 검증이 전혀 없으면 IDOR로 본다.
 */
function missingOwnershipCheck(lines: string[], lineIdx: number): boolean {
  const start = Math.max(0, lineIdx - 6);
  const end = Math.min(lines.length, lineIdx + 7);
  const rawWindow = lines.slice(start, end);

  // 주석은 제거하고 판정한다. 주석에 적힌 "todo.ownerId === ..." 같은 설명이
  // 실제 소유자 검증으로 오인되어 IDOR를 놓치는 오탐(false negative)을 막는다.
  const codeWindow = stripComments(rawWindow).join("\n");

  // 이 지점이 실제로 id 기반 단일 리소스 접근인지 재확인(오탐 억제).
  const isFetchById = FETCH_BY_ID.test(codeWindow);
  if (!isFetchById) return false;

  // 창 안(주석 제외)에 소유자 검증 흔적이 있으면 안전한 것으로 본다.
  return !OWNERSHIP_CHECK.test(codeWindow);
}

/** 라인 배열에서 주석(//... 및 /* ... *&#47; 한 줄 형태)을 제거한다. */
function stripComments(lines: string[]): string[] {
  return lines.map((l) =>
    l
      .replace(/\/\*.*?\*\//g, "") // 인라인 블록 주석
      .replace(/\/\/.*$/, "") // 라인 주석
      .replace(/^\s*\*.*$/, "") // JSDoc 본문 줄
  );
}

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
  // IDOR(sidor)는 한 핸들러에서 여러 신호가 겹칠 수 있어 파일당 1건만 보고한다.
  const reportedKinds = new Set<string>();

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
      } else if (sig.kind === "sidor") {
        // WEB-014는 소유자 검증이 다른 줄에 있을 수 있어 창(window) 단위로 판정.
        if (!missingOwnershipCheck(lines, lineNo - 1)) continue;
        if (reportedKinds.has("sidor")) continue; // 파일당 1건만
      } else if (sig.isVulnerable && !sig.isVulnerable(lineText)) {
        continue; // 상수만 있는 안전한 사용은 제외
      }
      if (sig.kind === "sidor") reportedKinds.add("sidor");

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
          label: "코드 점검 결과",
          content: scannerDetail,
        },
      ];

      const whyItMatters =
        sig.kind === "expose"
          ? `${sig.whyItMatters} 찾은 필드 이름: ${exposedFields.join(", ")}.`
          : sig.whyItMatters;

      out.push({
        id: id("finding"),
        scanId: "",
        title: sig.title,
        severity: sig.severity,
        category: sig.category,
        owasp: sig.owasp,
        cwe: sig.cwe,
        cvss: sig.cvss,
        description: `${sig.ruleTitleKo} 신호를 ${file} ${lineNo}번째 줄에서 찾았어요. 코드 모양으로 찾은 결과라 실행해 확인하지는 않았어요.`,
        humanReadableImpact: sig.humanReadableImpact,
        whyItMatters,
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

/**
 * 재검증용: 이 항목(같은 신호)이 수정본에 아직 남았는지. 원래 문제가 된 줄을
 * 따라가며, 같은 파일의 다른 항목이나 다른 신호에 끌려가지 않는다.
 */
function stillVulnerableFor(
  finding: SecurityFinding,
  fixedContent: string,
  baselineContent: string | undefined
): boolean {
  const file = finding.location?.file ?? "";
  // 같은 신호인지는 verificationKey의 종류(xss/inj/…)와 CWE로 가린다. 제목으로 비교하면
  // 안내 문구를 바꿨을 때 예전에 저장된 항목이 "사라짐"으로 잘못 판정된다.
  // (종류+CWE 묶음은 이전의 제목+CWE 묶음과 같다.)
  const kindOf = (f: SecurityFinding) => (f.verificationKey ?? "").split(":")[0];
  const hits = scanFile(file, fixedContent)
    .filter((f) => kindOf(f) === kindOf(finding) && f.cwe === finding.cwe)
    .map((f) => ({ line: f.location?.line ?? 0, text: f.evidence.find((e) => e.kind === "source_code")?.content ?? "" }));
  return stillPresentAfterFix({
    hits,
    originalLineText: finding.evidence.find((e) => e.kind === "source_code")?.content,
    originalLine: finding.location?.line,
    baselineContent,
    fixedLineCount: fixedContent.split("\n").length,
  });
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
    const kind = key.split(":")[0] as
      | "xss"
      | "inj"
      | "expose"
      | "trav"
      | "sidor";
    const file = finding.location?.file;
    const source = file ? context.files[file] : undefined;

    const before = true; // 최초 탐지 시 취약했음(스캔에서 확정)
    const after =
      source !== undefined
        ? stillVulnerableFor(finding, source, file ? context.baselineFiles?.[file] : undefined)
        : true;
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
