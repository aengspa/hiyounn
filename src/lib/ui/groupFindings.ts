/**
 * 화면 표시용 묶기: 여러 곳에서 발견된 "같은 취약점"을 카드 하나로 보여 준다.
 *
 * 저장·점검·수정·재검증은 그대로 항목(id)마다 한다. 이 모듈은 화면에서만 쓰고,
 * 서버·클라이언트 모두에서 쓸 수 있도록 서버 전용 모듈을 가져오지 않는다.
 *
 * 같은 취약점 판단(묶음 키), 앞에서부터 처음 맞는 것 하나만 쓴다:
 *   1) 규칙 ID가 있으면        rule:<ruleId>
 *   2) CWE가 있으면            cwe-class:<종류>  (findingMerge.issueClass의 CWE 표, 예: CWE-89·564 → sqli)
 *                              표에 없는 CWE는 cwe:<번호>
 *   3) 그 밖에는               title:<정규화한 제목>
 * 종류가 다르면 절대 합치지 않는다. 심각도는 묶음을 나누지 않고, 묶음은 가장 높은 심각도를 쓴다.
 */
import type { Severity } from "@/lib/domain/types";
// findingMerge는 타입만 가져오는 순수 모듈이라 클라이언트에서도 쓸 수 있다.
import { issueClass } from "@/lib/scanners/findingMerge";
import { FIX_STATUS_LABEL, type FixStatusKey } from "@/lib/ui/fixStatus";

export interface GroupableFinding {
  id: string;
  title: string;
  severity: Severity;
  ruleId?: string;
  cwe?: string;
  location?: { file: string; line: number };
}

export interface FindingGroup<T extends GroupableFinding> {
  key: string;
  /** 설명(제목·영향·이유·바꿀 점)을 가져오는 항목: 가장 심각한 항목(같으면 먼저 나온 항목). */
  representative: T;
  /** 원래 순서를 유지한 모든 항목(대표 포함). */
  members: T[];
  severity: Severity;
  ids: string[];
  /** 위치가 있는 항목의 위치(중복 제거). */
  locations: { file: string; line: number }[];
}

const SEV_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const rank = (s: Severity) => SEV_RANK[s] ?? 4;

function normTitle(t: string): string {
  return t
    .toLowerCase()
    .replace(/[\s\p{P}]+/gu, " ")
    .trim();
}

export function groupKey(f: Pick<GroupableFinding, "ruleId" | "cwe" | "title">): string {
  const rule = f.ruleId?.trim();
  if (rule) return `rule:${rule}`;
  const cweNum = (f.cwe ?? "").match(/\d+/)?.[0];
  if (cweNum) {
    // 제목·분류는 넘기지 않아 CWE 표만 쓴다(단어 추측으로 다른 종류가 합쳐지지 않게).
    const cls = issueClass({ cwe: `CWE-${cweNum}`, title: "", category: "" });
    return cls ? `cwe-class:${cls}` : `cwe:${cweNum}`;
  }
  return `title:${normTitle(f.title)}`;
}

/** 같은 취약점끼리 묶는다. 묶음 순서는 처음 나온 순서(이미 심각도로 정렬돼 있으면 그대로 유지). */
export function groupFindings<T extends GroupableFinding>(items: readonly T[]): FindingGroup<T>[] {
  const byKey = new Map<string, FindingGroup<T>>();
  const out: FindingGroup<T>[] = [];
  for (const f of items) {
    const key = groupKey(f);
    let g = byKey.get(key);
    if (!g) {
      g = { key, representative: f, members: [], severity: f.severity, ids: [], locations: [] };
      byKey.set(key, g);
      out.push(g);
    }
    g.members.push(f);
    g.ids.push(f.id);
    if (rank(f.severity) < rank(g.representative.severity)) g.representative = f;
    if (rank(f.severity) < rank(g.severity)) g.severity = f.severity;
    const loc = f.location;
    if (loc && !g.locations.some((l) => l.file === loc.file && l.line === loc.line)) g.locations.push(loc);
  }
  // 묶은 뒤 가장 높은 심각도가 앞서도록 안정 정렬한다.
  return out
    .map((g, i) => ({ g, i }))
    .sort((a, b) => rank(a.g.severity) - rank(b.g.severity) || a.i - b.i)
    .map((x) => x.g);
}

export function formatLocation(loc: { file: string; line: number }): string {
  return `${loc.file}:${loc.line}`;
}

// ─────────────────────────────────────────────────────────────
// 묶음 상태: 항목 상태 중 가장 나쁜 것을 라벨로, 다르면 내역을 짧게
// ─────────────────────────────────────────────────────────────

/** 작을수록 나쁘다(먼저 보여 줄 상태). false_positive는 모두 오탐일 때만 묶음 상태가 된다. */
const STATUS_RANK: Record<FixStatusKey, number> = {
  fixing: 0,
  still_present: 1,
  not_fixed: 2,
  disputed: 3,
  needs_check: 4,
  resolved_ai: 5,
  resolved: 6,
  false_positive: 7,
};

const STATUS_SHORT: Record<FixStatusKey, string> = {
  fixing: "수정 중",
  still_present: "아직 남아 있음",
  not_fixed: "자동으로 못 고침",
  disputed: "판단이 엇갈림",
  needs_check: "점검 필요",
  resolved_ai: "AI가 해결로 판단",
  resolved: "해결 확인",
  false_positive: "오탐 판정",
};

export interface GroupStatus {
  key: FixStatusKey;
  label: string;
  /** 항목 상태가 서로 다를 때만: "해결 확인 2곳 · 아직 남아 있음 1곳" (나쁜 상태부터). */
  breakdown?: string;
}

export function aggregateStatus(keys: readonly FixStatusKey[]): GroupStatus {
  if (keys.length === 0) return { key: "needs_check", label: FIX_STATUS_LABEL.needs_check };
  const counts = new Map<FixStatusKey, number>();
  for (const k of keys) counts.set(k, (counts.get(k) ?? 0) + 1);
  const ordered = [...counts.keys()].sort((a, b) => STATUS_RANK[a] - STATUS_RANK[b]);
  const worst = ordered[0];
  const out: GroupStatus = { key: worst, label: FIX_STATUS_LABEL[worst] };
  if (ordered.length > 1) out.breakdown = ordered.map((k) => `${STATUS_SHORT[k]} ${counts.get(k)}곳`).join(" · ");
  return out;
}
