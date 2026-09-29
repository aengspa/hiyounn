import type { SecurityFinding } from "@/lib/domain/types";
import type { Check, SecurityRule } from "@/lib/rules/types";
import type { ProjectContext } from "@/lib/scanners/types";
import { safeFetch, type SafeFetchOptions, type SafeFetchResult } from "@/lib/net/safeFetch";
import { id, now } from "@/lib/util";

export const SCANNER_USER_AGENT = "VibeSecurityAgent/0.2 (+https://github.com/aengspa/hiyounn)";
export type ProbeFetch = (url: string, options?: SafeFetchOptions) => Promise<SafeFetchResult>;
export interface ToolResult {
  findings: SecurityFinding[];
  gap?: string;
  linkedBaasProjects?: NonNullable<ProjectContext["linkedBaasProjects"]>;
}

/** Each rule gets a shared server-enforced request/time budget, including controls. */
export class RuleToolRuntime {
  private requests = 0;
  private readonly deadline: number;
  readonly cache = new Map<string, unknown>();

  constructor(
    readonly context: ProjectContext,
    readonly rule: SecurityRule,
    private readonly fetcher: ProbeFetch = safeFetch
  ) {
    this.deadline = Date.now() + (rule.execution.timeoutSeconds ?? 60) * 1000;
  }

  async request(url: string, options: SafeFetchOptions = {}): Promise<SafeFetchResult> {
    if (++this.requests > (this.rule.execution.maxRequests ?? 60)) {
      throw new Error("이 검사에 정해 둔 요청 횟수 상한을 다 써서 나머지는 확인하지 못했어요.");
    }
    const remaining = this.deadline - Date.now();
    if (remaining <= 0) throw new Error("이 검사에 정해 둔 시간이 지나 나머지는 확인하지 못했어요.");
    const result = await this.fetcher(url, {
      ...options,
      timeoutMs: Math.min(options.timeoutMs ?? 5000, remaining),
      maxBytes: Math.min(options.maxBytes ?? 128 * 1024, 1024 * 1024),
      followRedirects: false,
      maxRedirects: 0,
      headers: { "user-agent": SCANNER_USER_AGENT, ...options.headers },
    });
    if (result.truncated) throw new Error("응답이 너무 커서 전체 내용을 확인하지 못했어요.");
    return result;
  }

  targetUrl(raw: string): string {
    const base = this.context.deploymentUrl;
    if (!base) throw new Error("배포 주소가 없어 실제 사이트를 확인하지 못했어요.");
    const target = new URL(raw, base);
    if (target.origin !== new URL(base).origin || target.username || target.password) {
      throw new Error("소유를 확인한 배포 주소 밖이라 요청을 보내지 않았어요.");
    }
    return target.toString();
  }

  /** Reserve an independent recovery budget: normal timeout/quota must not prevent rollback. */
  async restore(url: string, options: SafeFetchOptions): Promise<SafeFetchResult> {
    return this.fetcher(url, { ...options, timeoutMs: 5000, maxBytes: 16 * 1024, maxRedirects: 0,
      followRedirects: false, headers: { "user-agent": SCANNER_USER_AGENT, ...options.headers } });
  }

  finding(
    check: Check,
    description: string,
    evidence: string,
    options: { confirmed?: boolean; file?: string; line?: number; key?: string } = {}
  ): SecurityFinding {
    const confirmed = options.confirmed && check.confidence !== "tentative";
    const timestamp = now();
    return {
      id: id("finding"),
      scanId: "",
      title: this.rule.titleKo,
      severity: this.rule.severity,
      category: this.rule.family,
      ruleId: this.rule.id,
      family: this.rule.family,
      cwe: this.rule.standards.find((s) => s.framework === "CWE")?.id,
      standards: this.rule.standards.map((s) => `${s.framework} ${s.id}`),
      executionTier: this.rule.execution.tier,
      description,
      humanReadableImpact: this.rule.summaryKo,
      // 규칙 요약(영향)을 되풀이하지 않고, 이번에 무엇을 보고 판단했는지와 확인 수준을 적는다.
      whyItMatters: `${description} ${howChecked(check, Boolean(confirmed))}`,
      remediation:
        this.rule.remediation.manualStepsKo?.join("\n") ??
        "근거에 적힌 위치의 코드나 설정을 고친 뒤 다시 점검해 주세요.",
      evidence: [{ id: id("ev"), kind: "scanner_output", label: `점검 결과 (${check.id})`, content: evidence, masked: true }],
      location: options.file ? { file: options.file, line: options.line ?? 1 } : undefined,
      status: confirmed ? "verified" : "detected",
      testStatus: confirmed ? "CONFIRMED" : "SUSPECTED",
      simulated: false,
      verificationKey: options.key ?? `tool:${this.rule.id}:${check.id}:${options.file ?? this.context.projectId}`,
      createdAt: timestamp,
      updatedAt: timestamp,
    };
  }
}

/** 코드만 읽었는지, 실제 요청으로 확인했는지 구분해 알린다. */
function howChecked(check: Check, confirmed: boolean): string {
  if (check.method === "SAST") return "코드에서 확인한 결과이고, 실제로 문제가 생기는지는 실행해 확인하지 않았어요.";
  if (check.toolId === "package_provenance_checker") {
    return confirmed
      ? "npm 공개 저장소에 실제로 조회해 확인했어요."
      : "npm 공개 저장소 정보를 보고 판단했어요. 이 패키지가 실제로 위험한지는 직접 확인해 주세요.";
  }
  if (confirmed) return "실제로 요청을 보내 응답으로 확인했어요.";
  return "실제로 요청을 보내 확인했어요. 의도한 동작인지는 근거를 보고 직접 판단해 주세요.";
}

export function gap(reason: string): ToolResult {
  return { findings: [], gap: reason };
}

/** Remote bodies and source lines never go into evidence; only bounded metadata does. */
export function safeLabel(raw: string): string {
  return raw.replace(/[\r\n\x00-\x1f]/g, "").slice(0, 120);
}
