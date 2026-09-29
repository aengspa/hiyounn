/**
 * 점검 규칙이 근거로 삼는 공개 기준과, 규칙을 세울 때 참고한 문서 목록.
 *
 * - 숫자(점검 항목 수, 기준별 인용 수 등)는 RULES에서 매번 계산한다. 규칙을 바꾸면 소개글 숫자도 같이 바뀐다.
 * - 서버·클라이언트 어디서나 쓸 수 있는 순수 모듈이다(node:fs 등 서버 전용 모듈 없음).
 * - 버전은 definitions.ts·asvs5Catalog.ts가 실제로 쓰는 값과 맞춘다.
 */
import { RULES } from "@/lib/rules/definitions";
import { ASVS_VERSION } from "@/lib/rules/asvs5Catalog";
import type { Framework, StandardRef } from "@/lib/rules/types";

export type SourceKind = "standard" | "catalog" | "guide";

export const KIND_LABEL_KO: Record<SourceKind, string> = {
  standard: "보안 기준",
  catalog: "분류 체계",
  guide: "테스트 가이드",
};

export interface SourceDoc {
  id: string;
  /** 규칙의 standards[].framework와 연결될 때만 채운다(인용 수 계산에 쓴다). */
  framework?: Framework;
  name: string;
  publisher: string;
  version?: string;
  url?: string;
  kind: SourceKind;
  /** 이 문서가 무엇인지 한 줄 */
  whatKo?: string;
  /** 이 서비스에서 어디에 썼는지 한 줄 */
  usedForKo: string;
}

/** 규칙의 standards에 실제로 인용하는 공개 기준(표시 순서 = 이 배열 순서). */
const ALL_CITED_SOURCES: SourceDoc[] = [
  {
    id: "cwe",
    framework: "CWE",
    name: "CWE (Common Weakness Enumeration)",
    publisher: "MITRE",
    url: "https://cwe.mitre.org/",
    kind: "catalog",
    whatKo: "소프트웨어에서 자주 생기는 결함 유형을 번호로 정리한 목록이에요.",
    usedForKo: "규칙이 찾는 문제가 어떤 종류의 결함인지 나타내는 1차 근거로 써요.",
  },
  {
    id: "capec",
    framework: "CAPEC",
    name: "CAPEC (Common Attack Pattern Enumeration and Classification)",
    publisher: "MITRE",
    version: "3.9",
    url: "https://capec.mitre.org/",
    kind: "catalog",
    whatKo: "결함을 노리는 공격 방식을 정리한 목록이에요.",
    usedForKo: "그 결함이 실제로 어떻게 악용될 수 있는지 설명할 때 써요.",
  },
  {
    id: "owasp-top10",
    framework: "OWASP_TOP_10",
    name: "OWASP Top 10",
    publisher: "OWASP",
    version: "2025",
    url: "https://owasp.org/www-project-top-ten/",
    kind: "standard",
    whatKo: "웹 서비스에서 가장 흔하고 위험한 보안 문제 10가지를 정리한 문서예요.",
    usedForKo: "각 규칙이 어떤 위험 분야에 속하는지 묶어서 보여 줄 때 써요.",
  },
  {
    id: "owasp-api-top10",
    framework: "OWASP_API_SECURITY_TOP_10",
    name: "OWASP API Security Top 10",
    publisher: "OWASP",
    version: "2023",
    url: "https://owasp.org/www-project-api-security/",
    kind: "standard",
    whatKo: "API에서 자주 생기는 보안 문제 10가지를 정리한 문서예요.",
    usedForKo: "다른 사람의 데이터에 접근하는 문제처럼 API에 특화된 점검의 근거로 써요.",
  },
  {
    id: "owasp-asvs",
    framework: "OWASP_ASVS",
    name: "OWASP ASVS (Application Security Verification Standard)",
    publisher: "OWASP",
    version: ASVS_VERSION,
    url: "https://owasp.org/www-project-application-security-verification-standard/",
    kind: "standard",
    whatKo: "웹 애플리케이션이 갖춰야 할 보안 요구사항을 항목별로 정리한 검증 기준이에요.",
    usedForKo: "코드만 보고 자동으로 확인할 수 있는 요구사항을 골라 점검 항목으로 옮겼어요.",
  },
  {
    id: "owasp-llm-top10",
    framework: "OWASP_LLM_TOP_10",
    name: "OWASP Top 10 for LLM Applications",
    publisher: "OWASP",
    version: "2025",
    url: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    kind: "standard",
    whatKo: "AI(LLM)를 쓰는 서비스에서 생기기 쉬운 보안 문제 10가지를 정리한 문서예요.",
    usedForKo: "프롬프트에 비밀값을 넣거나 AI 응답을 그대로 실행하는 문제를 점검할 때 써요.",
  },
  {
    id: "mitre-attack",
    framework: "MITRE_ATTACK",
    name: "MITRE ATT&CK",
    publisher: "MITRE",
    version: "Enterprise",
    url: "https://attack.mitre.org/",
    kind: "catalog",
    whatKo: "실제 공격자들이 쓰는 기술을 단계별로 정리한 지식 베이스예요.",
    usedForKo: "문제가 공격 흐름의 어느 지점에 해당하는지 보조 근거로 써요.",
  },
  {
    id: "mitre-atlas",
    framework: "MITRE_ATLAS",
    name: "MITRE ATLAS",
    publisher: "MITRE",
    url: "https://atlas.mitre.org/",
    kind: "catalog",
    whatKo: "AI 시스템을 노리는 공격 기술을 정리한 지식 베이스예요.",
    usedForKo: "CAPEC에 대응 패턴이 없는 AI 관련 공격(프롬프트 인젝션 등)을 보완할 때 써요.",
  },
];

/** 인용 기준 중 실제 규칙이 하나라도 쓰는 것만 보여 준다. */
export const CITED_SOURCES: SourceDoc[] = ALL_CITED_SOURCES.filter(
  (s) => !s.framework || RULES.some((r) => r.standards.some((ref) => ref.framework === s.framework)),
);

/** 규칙을 직접 인용하지는 않지만 점검 항목을 정리할 때 참고한 문서(docs/security/scan-knowledge-base.md). */
export const REFERENCE_SOURCES: SourceDoc[] = [
  {
    id: "owasp-wstg",
    name: "OWASP Web Security Testing Guide (WSTG)",
    publisher: "OWASP",
    version: "v4.2",
    url: "https://owasp.org/www-project-web-security-testing-guide/",
    kind: "guide",
    usedForKo: "무엇을 어떤 순서로 확인할지 점검 항목을 정리할 때 참고했어요.",
  },
  {
    id: "owasp-asvs-4",
    name: "OWASP ASVS (이전 버전)",
    publisher: "OWASP",
    version: "4.0.3",
    url: "https://owasp.org/www-project-application-security-verification-standard/",
    kind: "standard",
    usedForKo: "처음 점검 항목을 세울 때 참고했고, 지금 규칙은 5.0.0 기준으로 옮겼어요.",
  },
];

export interface FrameworkStat {
  /** 이 기준을 인용하는 점검 항목(규칙) 수 */
  items: number;
  /** 인용한 서로 다른 근거 번호 수 */
  distinctIds: number;
}

export function frameworkStats(): Map<Framework, FrameworkStat> {
  const items = new Map<Framework, number>();
  const ids = new Map<Framework, Set<string>>();
  for (const rule of RULES) {
    const seen = new Set<Framework>();
    for (const ref of rule.standards) {
      if (!seen.has(ref.framework)) {
        seen.add(ref.framework);
        items.set(ref.framework, (items.get(ref.framework) ?? 0) + 1);
      }
      if (!ids.has(ref.framework)) ids.set(ref.framework, new Set());
      ids.get(ref.framework)!.add(ref.id);
    }
  }
  const out = new Map<Framework, FrameworkStat>();
  for (const [framework, count] of items) {
    out.set(framework, { items: count, distinctIds: ids.get(framework)?.size ?? 0 });
  }
  return out;
}

/** 소개글 상단 숫자: 점검 항목 수, 근거 삼은 공개 기준 수, 연결된 CWE 수. */
export function introStats(): { items: number; frameworks: number; cweIds: number } {
  const stats = frameworkStats();
  return {
    items: RULES.length,
    frameworks: CITED_SOURCES.filter((s) => s.framework && stats.has(s.framework)).length,
    cweIds: stats.get("CWE")?.distinctIds ?? 0,
  };
}

const FRAMEWORK_PREFIX: Record<Framework, string> = {
  CWE: "",
  CAPEC: "",
  OWASP_TOP_10: "OWASP ",
  OWASP_ASVS: "ASVS ",
  OWASP_API_SECURITY_TOP_10: "OWASP ",
  OWASP_LLM_TOP_10: "OWASP ",
  MITRE_ATTACK: "ATT&CK ",
  MITRE_ATLAS: "ATLAS ",
};

/** 근거 칩에 보여 줄 이름. 예: "CWE-639", "OWASP API1:2023", "ASVS V8.2.1". */
export function standardLabel(ref: StandardRef): string {
  return `${FRAMEWORK_PREFIX[ref.framework] ?? ""}${ref.id}`;
}

/** 근거 원문 주소. 항목별 주소가 확실한 것만 만들고, 나머지는 기준 문서 주소를 쓴다. */
export function standardUrl(ref: StandardRef): string | undefined {
  const num = ref.id.match(/^(?:CWE|CAPEC)-(\d+)$/)?.[1];
  if (ref.framework === "CWE" && num) return `https://cwe.mitre.org/data/definitions/${num}.html`;
  if (ref.framework === "CAPEC" && num) return `https://capec.mitre.org/data/definitions/${num}.html`;
  if (ref.framework === "MITRE_ATTACK" && /^T\d{4}(\.\d{3})?$/.test(ref.id)) {
    return `https://attack.mitre.org/techniques/${ref.id.replace(".", "/")}/`;
  }
  return ALL_CITED_SOURCES.find((s) => s.framework === ref.framework)?.url;
}
