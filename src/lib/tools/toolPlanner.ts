import type { ScanToolItem, ScanToolsReport } from "@/lib/domain/types";
import { callLlm } from "@/lib/ai/llmClient";
import { isLlmConfigured } from "@/lib/ai/llmConfig";
import { parseJsonObject } from "@/lib/ai/jsonResponse";
import { LIMITS } from "@/lib/config/limits";
import {
  SEMGREP_CODE,
  getInstallableTool,
  listInstallableTools,
  type InstallableToolId,
  type ProjectSignals,
} from "@/lib/tools/installableTools";
import { ensureTool, toolInstallAllowed, type EnsureResult, type InstallerDeps } from "@/lib/tools/toolInstaller";

/**
 * 점검 시작 때 추가 도구 고르기.
 *
 * AI에게는 파일 내용 없이 프로젝트 요약(확장자별 파일 수, 프레임워크, .git 여부,
 * 파일 수)과 허용 목록(id + 쓰임)만 보낸다. AI 응답에서는 허용 목록의 id만
 * 남기고 중복을 없앤다. 저장소 글이나 AI 응답이 목록 밖의 도구를 더할 수 없다.
 * AI를 못 쓰거나 호출이 실패하면 목록에 적힌 조건으로 결정적으로 고른다.
 */

export interface ToolPlanItem {
  id: InstallableToolId;
  reason: string;
}

export interface ToolPlan {
  planner: "ai" | "heuristic";
  fallbackReason?: "not_configured" | "call_failed" | "invalid_response";
  items: ToolPlanItem[];
}

type Complete = (system: string, user: string, timeoutMs: number) => Promise<string>;

export interface PlanOptions {
  llmConfigured?: boolean;
  complete?: Complete;
}

const PLAN_TIMEOUT_MS = 15_000;
const SKIP_DIR = /(^|\/)(node_modules|\.git|\.next|dist|build|vendor|coverage)\//;

/** 파일 내용 없이 경로·스택만으로 만든 프로젝트 요약. */
export function projectSignals(files: Record<string, string>, stack?: { frameworks?: string[]; languages?: string[] }): ProjectSignals {
  const paths = Object.keys(files);
  const extensions: Record<string, number> = {};
  for (const p of paths) {
    if (SKIP_DIR.test(p)) continue;
    const m = p.match(/(\.[A-Za-z0-9]{1,8})$/);
    const ext = m ? m[1].toLowerCase() : "(없음)";
    extensions[ext] = (extensions[ext] ?? 0) + 1;
  }
  return {
    fileCount: paths.filter((p) => !SKIP_DIR.test(p)).length,
    extensions,
    frameworks: (stack?.frameworks ?? []).slice(0, 10),
    languages: (stack?.languages ?? []).slice(0, 10),
    hasGitDir: paths.some((p) => p === ".git/HEAD" || p.endsWith("/.git/HEAD")),
    hasCode: paths.some((p) => !SKIP_DIR.test(p) && SEMGREP_CODE.test(p)),
  };
}

export function heuristicPlan(signals: ProjectSignals): ToolPlanItem[] {
  return listInstallableTools()
    .filter((t) => t.usefulFor(signals))
    .map((t) => ({ id: t.id, reason: t.purposeKo }));
}

/** 사용자에게 보여 줄 이유 글을 정리한다(제어 문자 제거·길이 제한). */
function cleanReason(v: unknown): string | undefined {
  if (typeof v !== "string") return undefined;
  const t = v.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim();
  return t ? t.slice(0, 200) : undefined;
}

/**
 * AI 응답에서 허용 목록 id만 남긴다. 형식이 틀리면 null.
 * 목록 밖 id(예: "curl", "__proto__")는 조용히 버린다.
 */
export function filterAiToolChoice(parsed: Record<string, unknown> | undefined): ToolPlanItem[] | null {
  if (!parsed || !Array.isArray(parsed.tools)) return null;
  const out: ToolPlanItem[] = [];
  const seen = new Set<string>();
  for (const item of parsed.tools.slice(0, 20)) {
    const raw = item && typeof item === "object" ? (item as { id?: unknown; reason?: unknown }) : undefined;
    const tool = getInstallableTool(raw?.id);
    if (!tool || seen.has(tool.id)) continue;
    seen.add(tool.id);
    out.push({ id: tool.id, reason: cleanReason(raw?.reason) ?? tool.purposeKo });
  }
  return out;
}

const SYSTEM = `Task: choose which extra security tools would help scan this project.
You may choose ONLY from the supplied "allowlist" by exact "id". Never invent tool ids or commands.
Choose a tool only when the project summary shows it is useful. Choosing none is allowed.
For each chosen tool, "reason" is one short sentence in plain Korean for a non-developer explaining why it helps this project.
Response schema: {"tools":[{"id":"<allowlist id>","reason":"<Korean sentence>"}]}`;

export async function planTools(signals: ProjectSignals, opts: PlanOptions = {}): Promise<ToolPlan> {
  const llmOn = opts.llmConfigured ?? isLlmConfigured();
  if (!llmOn) return { planner: "heuristic", fallbackReason: "not_configured", items: heuristicPlan(signals) };
  const complete: Complete =
    opts.complete ??
    ((system, user, timeoutMs) => callLlm({ system, user, json: true, temperature: 0, timeoutMs, purpose: "tool-plan" }).then((r) => r.text));
  const user = JSON.stringify({
    project: signals,
    allowlist: listInstallableTools().map((t) => ({ id: t.id, purpose: t.purposeKo, usefulWhen: t.usefulWhenKo })),
  });
  let raw: string;
  try {
    raw = await complete(SYSTEM, user, PLAN_TIMEOUT_MS);
  } catch {
    return { planner: "heuristic", fallbackReason: "call_failed", items: heuristicPlan(signals) };
  }
  const items = filterAiToolChoice(parseJsonObject(raw));
  if (!items) return { planner: "heuristic", fallbackReason: "invalid_response", items: heuristicPlan(signals) };
  return { planner: "ai", items };
}

export interface PrepareOptions extends PlanOptions {
  budgetMs?: number;
  installer?: InstallerDeps;
  /** 테스트용: ensureTool 대체. */
  ensure?: (toolId: string) => Promise<EnsureResult>;
}

function toItem(plan: ToolPlanItem, r: EnsureResult | undefined): ScanToolItem {
  const tool = getInstallableTool(plan.id)!;
  if (!r) {
    return {
      id: tool.id,
      displayName: tool.displayName,
      reason: plan.reason,
      status: "timed_out",
      version: tool.version,
      detail: "준비 시간 안에 설치가 끝나지 않아 이번 점검에서는 쓰지 않았어요. 설치가 끝나면 다음 점검부터 써요.",
    };
  }
  return {
    id: tool.id,
    displayName: tool.displayName,
    reason: plan.reason,
    status: r.status,
    ...(r.version ? { version: r.version } : {}),
    ...(r.reason ? { detail: r.reason } : {}),
  };
}

/** 도구 고르기 → 준비(시간 한도 안에서). 실패해도 점검은 계속한다. */
export async function prepareScanTools(
  files: Record<string, string>,
  stack: { frameworks?: string[]; languages?: string[] } | undefined,
  opts: PrepareOptions = {}
): Promise<ScanToolsReport> {
  const env = opts.installer?.env ?? process.env;
  const ensure = opts.ensure ?? ((toolId: string) => ensureTool(toolId, opts.installer));
  const signals = projectSignals(files, stack);
  let report: Omit<ScanToolsReport, "items">;
  let chosen: ToolPlanItem[];
  if (!toolInstallAllowed(env)) {
    // 설치를 꺼 두었으면 AI를 부르지 않는다. 이미 있는 도구인지만 기록한다.
    report = { planner: "disabled" };
    chosen = heuristicPlan(signals);
  } else {
    const plan = await planTools(signals, opts);
    report = { planner: plan.planner, ...(plan.fallbackReason ? { fallbackReason: plan.fallbackReason } : {}) };
    chosen = plan.items;
  }
  const budget = opts.budgetMs ?? LIMITS.toolPrepBudgetMs;
  const results = new Map<string, EnsureResult>();
  const work = Promise.all(
    chosen.map((c) =>
      ensure(c.id)
        .then((r) => void results.set(c.id, r))
        .catch(() => void results.set(c.id, { id: c.id, status: "install_failed", version: "", reason: "설치 중 오류가 나서 이 도구는 쓰지 않았어요." }))
    )
  );
  let timer: ReturnType<typeof setTimeout> | undefined;
  await Promise.race([work, new Promise<void>((resolve) => (timer = setTimeout(resolve, budget)))]);
  if (timer) clearTimeout(timer);
  return { ...report, items: chosen.map((c) => toItem(c, results.get(c.id))) };
}
