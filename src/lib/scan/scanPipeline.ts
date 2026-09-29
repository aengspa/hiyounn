import type { CustomRule, Project, RouteAuthzEntry, Scan, ScanPlan, ScanScope, SecurityFinding, SourceVersion } from "@/lib/domain/types";
import { toTestStatus } from "@/lib/domain/types";
import type { StoreBackend } from "@/lib/store/backend";
import { contextForProject } from "@/lib/scanners/contextFor";
import type { SecurityOrchestrator } from "@/lib/scanners/orchestrator";
import { mergeAiIntoRules } from "@/lib/scanners/findingMerge";
import { isLlmConfigured } from "@/lib/ai/llmConfig";
import { callLlm } from "@/lib/ai/llmClient";
import { parseJsonObject } from "@/lib/ai/jsonResponse";
import { redactSecrets } from "@/lib/ai/redact";
import { PROPOSE_SYSTEM_PROMPT, validateProposal } from "@/lib/rules/customRules";
import { SEVERITY_ORDER } from "@/lib/domain/types";
import { id } from "@/lib/util";
import { prepareScanTools } from "@/lib/tools/toolPlanner";

/**
 * 한 번의 점검(두 저장소가 함께 쓰는 흐름).
 *
 *  1) 승인한 AI 제안 규칙을 기준 규칙으로 함께 돌린다.
 *  2) 재업로드 버전이면 이전 점검과 비교해 바뀐 파일만 AI가 새로 본다(규칙은 전체).
 *     바뀌지 않은 파일의 이전 AI 결과는 "이어옴"으로 가져온다.
 *  3) AI만 찾은 문제에서 규칙을 제안받는다(사람이 승인해야 돈다).
 */

export interface ScanPipelineResult {
  findings: SecurityFinding[];
  scope: ScanScope;
  plan: ScanPlan;
  /** 새로 제안된 규칙(저장은 호출부가 점검 id를 붙여서 한다). */
  proposals: CustomRule[];
}

export interface ScanPipelineOptions {
  /** 테스트용: 규칙 제안 LLM 대체(모델 원문을 돌려줌). */
  proposeComplete?: (system: string, user: string, timeoutMs: number) => Promise<string>;
  llmConfigured?: boolean;
  /** 테스트용: 추가 도구 준비 대체. */
  prepareTools?: (files: Record<string, string>, stack: { frameworks?: string[]; languages?: string[] }) => Promise<ScanScope["tools"]>;
}

const CARRY_PREFIXES = ["ai:", "authz:"];
const MAX_PROPOSALS = 5;

function isCarryable(f: SecurityFinding): boolean {
  return CARRY_PREFIXES.some((p) => (f.verificationKey ?? "").startsWith(p));
}

/** 바뀌지 않은 파일에 대한 이전 점검의 AI 결과를 이어 온다. */
function carryOver(previous: SecurityFinding[], unchanged: Set<string>, previousScanId: string): SecurityFinding[] {
  return previous
    .filter((f) => isCarryable(f) && f.location && unchanged.has(f.location.file))
    .map((f) => {
      const copy = structuredClone(f);
      copy.id = id("finding");
      copy.scanId = "";
      copy.status = "detected";
      copy.testStatus = toTestStatus("detected");
      copy.carriedOverFromScanId = previousScanId;
      return copy;
    });
}

async function proposeRules(
  findings: SecurityFinding[],
  files: Record<string, string>,
  owner: { ownerId: string; projectId: string },
  existing: CustomRule[],
  complete: (system: string, user: string, timeoutMs: number) => Promise<string>
): Promise<CustomRule[]> {
  const candidates = findings
    .filter((f) => (f.verificationKey ?? "").startsWith("ai:") && !f.carriedOverFromScanId && f.location && files[f.location.file] !== undefined)
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
    .slice(0, MAX_PROPOSALS);
  if (candidates.length === 0) return [];
  const redacted = redactSecrets(files).files;
  const user = JSON.stringify({
    findings: candidates.map((f) => {
      const lines = redacted[f.location!.file].split("\n");
      const i = f.location!.line - 1;
      return {
        id: f.id,
        title: f.title,
        cwe: f.cwe ?? null,
        file: f.location!.file,
        line: f.location!.line,
        code: lines[i] ?? "",
        context: lines.slice(Math.max(0, i - 3), i + 4).join("\n"),
      };
    }),
  });
  let raw: string;
  try {
    raw = await complete(PROPOSE_SYSTEM_PROMPT, user, 45_000);
  } catch {
    return [];
  }
  const parsed = parseJsonObject(raw);
  const list = parsed && Array.isArray(parsed.proposals) ? parsed.proposals : [];
  const byId = new Map(candidates.map((f) => [f.id, f]));
  const seenPatterns = new Set(existing.map((r) => `${r.pattern}\u0000${r.flags}`));
  const out: CustomRule[] = [];
  for (const p of list) {
    const finding = byId.get(String((p as { findingId?: unknown })?.findingId ?? ""));
    if (!finding) continue;
    const rule = validateProposal(p, finding, redacted, owner);
    if (!rule) continue;
    const key = `${rule.pattern}\u0000${rule.flags}`;
    if (seenPatterns.has(key)) continue;
    seenPatterns.add(key);
    out.push(rule);
  }
  return out;
}

/** 이전 표의 행 중 바뀌지 않은 파일의 행을 이어 붙인다(같은 라우트는 새 표 우선). */
function mergeMatrix(current: RouteAuthzEntry[] | undefined, previous: RouteAuthzEntry[] | undefined, unchanged: Set<string>): RouteAuthzEntry[] | undefined {
  const carried = (previous ?? []).filter((r) => unchanged.has(r.file)).map((r) => ({ ...r, findingIds: [] }));
  if (!current && carried.length === 0) return undefined;
  const key = (r: RouteAuthzEntry) => `${r.method} ${r.path}`;
  const have = new Set((current ?? []).map(key));
  return [...(current ?? []), ...carried.filter((r) => !have.has(key(r)))];
}

export async function runScanPipeline(input: {
  backend: StoreBackend;
  project: Project;
  version: SourceVersion | undefined;
  ownerId: string;
  orchestrator: SecurityOrchestrator;
  opts?: ScanPipelineOptions;
}): Promise<ScanPipelineResult> {
  const { backend, project, version, ownerId, orchestrator } = input;
  const opts = input.opts ?? {};
  const context = contextForProject(project, { files: version?.files });

  // 1) 승인한 규칙(같은 사용자의 모든 프로젝트에 적용).
  const allRules = project.isDemo ? [] : await backend.listCustomRules(ownerId).catch(() => [] as CustomRule[]);
  context.customRules = allRules.filter((r) => r.status === "approved");

  // 2) 재업로드 증분 점검.
  let previous: Scan | undefined;
  let changed: string[] | undefined;
  if (version?.kind === "reupload") {
    const scans = await backend.listScans(project.id, ownerId);
    const sameVersionScanned = scans.some((s) => s.sourceVersionId === version.id);
    previous = sameVersionScanned ? undefined : scans.find((s) => s.status === "completed" && s.sourceVersionId && s.sourceVersionId !== version.id);
    if (previous?.sourceVersionId) {
      const prevVersion = await backend.getSourceVersion(previous.sourceVersionId, ownerId).catch(() => undefined);
      if (prevVersion) {
        changed = Object.keys(version.files).filter((p) => prevVersion.files[p] !== version.files[p]).sort();
        context.aiScope = changed;
      } else {
        previous = undefined;
      }
    }
  }

  // 추가 도구 준비: 허용 목록 안에서 고르고(AI 또는 규칙) 시간 한도 안에서 설치한다.
  // 실패해도 점검은 계속하고, 결과는 scope.tools에 남긴다.
  const llmOn = opts.llmConfigured ?? isLlmConfigured();
  let tools: ScanScope["tools"];
  if (!project.isDemo && context.isUserProject !== false && Object.keys(context.files).length > 0) {
    tools = await (opts.prepareTools ?? ((files, stack) => prepareScanTools(files, stack, { llmConfigured: llmOn })))(context.files, context.stack).catch(
      () => undefined
    );
  }

  const { findings, scope, plan } = await orchestrator.run(context);
  if (tools) scope.tools = tools;

  if (previous && changed && version) {
    const changedSet = new Set(changed);
    const unchanged = new Set(Object.keys(version.files).filter((p) => !changedSet.has(p)));
    const prevFindings = await backend.getFindingsForScan(previous.id, ownerId).catch(() => [] as SecurityFinding[]);
    // 바뀌지 않은 파일의 규칙 항목에는 이전 AI 의견을 그대로 붙인다(같은 줄·같은 규칙).
    const prevByKey = new Map(prevFindings.filter((f) => f.aiReview).map((f) => [f.verificationKey, f.aiReview]));
    for (const f of findings) {
      if (!f.aiReview && f.location && unchanged.has(f.location.file) && prevByKey.has(f.verificationKey)) f.aiReview = prevByKey.get(f.verificationKey);
    }
    const carried = carryOver(prevFindings, unchanged, previous.id);
    const merged = mergeAiIntoRules(findings, carried);
    findings.push(...merged.aiKept);
    scope.authzMatrix = mergeMatrix(scope.authzMatrix, previous.scope.authzMatrix, unchanged);
    scope.incremental = { previousScanId: previous.id, changedFiles: changed, unchangedFiles: unchanged.size, carriedOver: merged.aiKept.length };
  }

  // 3) 규칙 제안.
  let proposals: CustomRule[] = [];
  if (llmOn && !project.isDemo && version) {
    const complete =
      opts.proposeComplete ??
      ((system: string, user: string, timeoutMs: number) =>
        callLlm({ system, user, json: true, temperature: 0, timeoutMs, purpose: "propose-rules" }).then((r) => r.text));
    proposals = await proposeRules(findings, version.files, { ownerId, projectId: project.id }, allRules, complete);
  }

  return { findings, scope, plan, proposals };
}
