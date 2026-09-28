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
      throw new Error("규칙의 요청 수 상한에 도달했습니다.");
    }
    const remaining = this.deadline - Date.now();
    if (remaining <= 0) throw new Error("규칙의 실행 시간 상한에 도달했습니다.");
    const result = await this.fetcher(url, {
      ...options,
      timeoutMs: Math.min(options.timeoutMs ?? 5000, remaining),
      maxBytes: Math.min(options.maxBytes ?? 128 * 1024, 1024 * 1024),
      followRedirects: false,
      maxRedirects: 0,
      headers: { "user-agent": SCANNER_USER_AGENT, ...options.headers },
    });
    if (result.truncated) throw new Error("응답 크기 상한으로 인해 전체 응답을 검사하지 못했습니다.");
    return result;
  }

  targetUrl(raw: string): string {
    const base = this.context.deploymentUrl;
    if (!base) throw new Error("배포 URL이 없습니다.");
    const target = new URL(raw, base);
    if (target.origin !== new URL(base).origin || target.username || target.password) {
      throw new Error("검증한 배포 origin 밖의 점검 대상입니다.");
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
      whyItMatters: this.rule.summaryKo,
      remediation: this.rule.remediation.manualStepsKo?.join("\n") ?? "규칙의 허용 경로에서 원인을 수정하고 다시 점검하세요.",
      evidence: [{ id: id("ev"), kind: "scanner_output", label: check.id, content: evidence, masked: true }],
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

export function gap(reason: string): ToolResult {
  return { findings: [], gap: reason };
}

/** Remote bodies and source lines never go into evidence; only bounded metadata does. */
export function safeLabel(raw: string): string {
  return raw.replace(/[\r\n\x00-\x1f]/g, "").slice(0, 120);
}
