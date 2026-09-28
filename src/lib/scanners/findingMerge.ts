import type { SecurityFinding } from "@/lib/domain/types";

/**
 * 규칙 결과와 AI 결과 합치기.
 *
 * 같은 파일의 가까운 줄(±3)에서 같은 종류의 문제를 가리키면 한 항목으로 본다.
 * 규칙 항목이 기준이라 규칙 항목을 남기고, AI가 같은 문제를 찾았다는 사실은
 * aiReview("confirmed")로 붙인다. AI만 찾은 항목은 그대로 둔다.
 */

const NEAR_LINES = 3;

/**
 * 도구마다 다르게 분류하는 가까운 종류. 정확히 같은 줄일 때만 같은 문제로 본다
 * (예: Math.random을 한 도구는 CWE-338 약한 난수, 다른 도구는 CWE-327 약한 암호로 분류).
 */
const RELATED_ON_SAME_LINE: Array<[string, string]> = [["random", "crypto"]];

function sameIssue(a: SecurityFinding, b: SecurityFinding, cls: string): boolean {
  if (a.location?.file !== b.location?.file) return false;
  const distance = Math.abs((a.location?.line ?? -99) - (b.location?.line ?? -99));
  const other = issueClass(a);
  if (other === cls) return distance <= NEAR_LINES;
  return distance === 0 && RELATED_ON_SAME_LINE.some(([x, y]) => (x === cls && y === other) || (y === cls && x === other));
}

const CWE_CLASS: Record<string, string> = {
  "89": "sqli", "564": "sqli", "943": "sqli",
  "77": "cmd", "78": "cmd", "94": "cmd", "95": "cmd",
  "79": "xss", "80": "xss",
  "22": "path", "23": "path", "35": "path", "73": "path",
  "639": "authz", "284": "authz", "285": "authz", "862": "authz", "863": "authz", "566": "authz",
  "798": "secret", "259": "secret", "321": "secret",
  "918": "ssrf",
  "347": "jwt", "345": "jwt",
  "330": "random", "338": "random",
  "326": "crypto", "327": "crypto", "328": "crypto",
  "601": "redirect",
  "502": "deser",
  "915": "massassign",
  "1321": "proto",
  "352": "csrf",
  "307": "bruteforce",
  "209": "info", "200": "info", "532": "info",
};

const KEYWORD_CLASS: Array<[RegExp, string]> = [
  [/sql|쿼리|query/i, "sqli"],
  [/command|명령|커맨드|\beval\b/i, "cmd"],
  [/xss|스크립트|innerhtml/i, "xss"],
  [/traversal|경로/i, "path"],
  [/idor|권한|authoriz|access control|관리자|admin|다른 사용자/i, "authz"],
  [/secret|비밀|api key|자격 증명|credential/i, "secret"],
  [/ssrf|외부 (주소|요청)|server-side request/i, "ssrf"],
  [/jwt|서명/i, "jwt"],
  [/random|난수|예측 가능/i, "random"],
  [/mass assignment|대량 할당/i, "massassign"],
];

export function issueClass(f: Pick<SecurityFinding, "cwe" | "title" | "category">): string | null {
  const cwe = (f.cwe ?? "").match(/\d+/)?.[0];
  if (cwe && CWE_CLASS[cwe]) return CWE_CLASS[cwe];
  const text = `${f.title} ${f.category}`;
  for (const [re, cls] of KEYWORD_CLASS) if (re.test(text)) return cls;
  return null;
}

/** 같은 파일·가까운 줄·같은 종류면 base 쪽 항목을 남기고 onMatch로 표시한다. */
export function mergeFindings(
  base: SecurityFinding[],
  incoming: SecurityFinding[],
  onMatch: (kept: SecurityFinding, dropped: SecurityFinding) => void
): { kept: SecurityFinding[]; merged: number } {
  const kept: SecurityFinding[] = [];
  let merged = 0;
  for (const f of incoming) {
    const cls = issueClass(f);
    const match = cls && f.location ? base.find((b) => sameIssue(b, f, cls)) : undefined;
    if (!match) {
      kept.push(f);
      continue;
    }
    merged += 1;
    onMatch(match, f);
  }
  return { kept, merged };
}

export function mergeAiIntoRules(
  ruleFindings: SecurityFinding[],
  aiFindings: SecurityFinding[]
): { aiKept: SecurityFinding[]; merged: number } {
  // 독립적으로 같은 문제를 찾았으므로 "확인"으로 본다(오탐 의견보다 우선).
  const { kept, merged } = mergeFindings(ruleFindings, aiFindings, (match, ai) => {
    // AI가 따로 같은 문제를 찾았으면 앞선 오탐 의견·재판정은 더 이상 맞지 않는다.
    match.aiReview = { verdict: "confirmed", reason: ai.title };
    match.corroboratedBy = [...new Set([...(match.corroboratedBy ?? []), "ai"])];
  });
  return { aiKept: kept, merged };
}

/** 다른 검사기(예: Semgrep, 권한 표)가 같은 문제를 찾았다는 표시만 남기고 합친다. */
export function mergeCorroborating(base: SecurityFinding[], incoming: SecurityFinding[], source: string): { kept: SecurityFinding[]; merged: number } {
  return mergeFindings(base, incoming, (match) => {
    match.corroboratedBy = [...new Set([...(match.corroboratedBy ?? []), source])];
  });
}
