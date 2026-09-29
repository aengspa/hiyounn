import { createHash } from "crypto";
import type {
  FixAttempt,
  FixJob,
  FixJobItem,
  Project,
  SecurityFinding,
  SourceVersion,
} from "@/lib/domain/types";
import { SEVERITY_ORDER } from "@/lib/domain/types";
import {
  getScan,
  getProject,
  getSourceVersion,
  getFindingsForScan,
  insertFixJob,
  updateFixJob,
  findFixJobByKey,
  getFixJob,
  saveSourceVersion,
} from "@/lib/store/store";
import { AppError } from "@/lib/store/errors";
import { LIMITS, type Limits } from "@/lib/config/limits";
import { isLlmConfigured } from "@/lib/ai/llmConfig";
import { deterministicFixFor } from "@/lib/remediation/deterministicFix";
import { generateLlmFileFix } from "@/lib/remediation/llmFileFix";
import { redactSecrets, scrubPlaceholders } from "@/lib/ai/redact";
import { buildProjectMap } from "@/lib/scanners/aiScanPlanner";
import {
  applyDiffsAtomically,
  safeProjectPath,
  textsFromPatch,
  PATCH_FAILURE_MESSAGE,
} from "@/lib/remediation/patchEngine";
import { maskSecretValues, secretValues } from "@/lib/ui/codeContext";
import { requiredEnvForFix } from "@/lib/remediation/requiredEnv";
import { buildChangedFilesZip } from "@/lib/remediation/artifactBuilder";
import { makeSourceVersion } from "@/lib/source/sourceVersion";
import { artifactKey, getArtifactStorage, type ArtifactStorage } from "@/lib/storage/artifactStorage";
import { id, runPool } from "@/lib/util";

/**
 * 전체 수정 (fix-all).
 *
 * 한 스캔이 찾은 항목들을 그 스캔이 읽은 불변 소스 버전(base) 위에서 한 번에
 * 고친다. 요청 안에서 동기로 처리하고(큐 없음), 다음을 지킨다.
 *  - 항목마다 원자적 적용: 한 항목의 diff가 하나라도 안 맞으면 그 항목 전체를
 *    적용하지 않는다. 다른 항목은 계속 진행한다.
 *  - 결과는 새 불변 버전(kind "fixed")으로 저장하고, 바뀐 파일만 담은 ZIP을
 *    비공개 저장소에 둔다. 원본 버전은 건드리지 않는다.
 *  - 항목 수·시간 한도를 넘는 항목은 "skipped"로 남긴다(조용히 버리지 않음).
 *  - 같은 요청은 idempotency key로 한 번만 실행한다.
 *  - 어떤 경우에도 finding을 resolved로 바꾸지 않는다. 해결 여부는 재검증이
 *    정한다.
 */

/**
 * 규칙 기반 수정(deterministicFix)이 먼저다. 비밀값·의존성 항목은 규칙으로만
 * 고치고 AI로 보내지 않는다. 나머지는 AI가 실제 파일을 보고 수정안을 만든다.
 * AI에 보내는 코드와 근거에서는 비밀값을 가린다(redactSecrets).
 */

/** 이 오류가 나면 같은 작업의 남은 AI 호출도 실패하므로 더 부르지 않는다. */
const AI_BLOCKING_ERRORS = new Set(["auth_failed", "not_configured"]);

function aiErrorReason(code: string): string {
  switch (code) {
    case "auth_failed":
      return "AI 키가 올바르지 않거나 권한이 없어 AI 수정 기능에 연결하지 못했어요. 그래서 이 항목의 수정안을 만들지 못했고, 파일은 바뀌지 않았어요. 서비스 관리자에게 AI 키 설정을 확인해 달라고 요청해 주세요.";
    case "not_configured":
      return "AI 수정 기능이 설정돼 있지 않아 이 항목의 수정안을 만들지 못했어요. 파일은 바뀌지 않았어요. 점검 결과의 수정 방법을 보고 직접 고치거나, 관리자에게 AI 설정을 요청해 주세요.";
    case "rate_limited":
      return "AI 요청이 몰려 사용 한도에 걸렸어요. 이 항목의 수정안을 만들지 못했고, 파일은 바뀌지 않았어요. 몇 분 뒤 다시 시도해 주세요.";
    case "timeout":
      return "AI가 정해진 시간 안에 수정안을 보내지 않았어요. 파일은 바뀌지 않았어요. 잠시 후 다시 시도해 주세요.";
    default:
      return "AI 수정안을 받지 못했어요. 파일은 바뀌지 않았어요. 잠시 후 다시 시도해 주세요.";
  }
}

/** 같은 파일을 고치는 항목은 한 줄로 묶는다(서로 다른 파일은 동시에 처리). */
function fileGroupKey(f: SecurityFinding, index: number): string {
  if ((f.verificationKey ?? "").startsWith("dep:")) return "package.json";
  const file = f.location?.file ? safeProjectPath(f.location.file) : null;
  return file ?? `\u0000nofile:${index}`;
}

/** 남은 시간이 이보다 적으면 새 항목을 시작하지 않는다. */
const MIN_ITEM_BUDGET_MS = 5_000;
/** 같은 요청의 재시도(이전 작업이 실패한 경우) 최대 횟수. */
const MAX_RETRY_ATTEMPTS = 5;

export const FIX_GUIDANCE =
  "받은 파일을 프로젝트에 반영해주세요. 공개한 웹사이트도 적용하려면 다시 배포해야 해요.";

/**
 * 수정본에 적용은 했지만 재검증 전인 항목의 안내. 해결 여부는 재검증이 정하므로
 * 여기서는 "해결했다"고 말하지 않는다.
 */
export const APPLIED_UNVERIFIED_REASON = "수정 내용을 적용했어요. 문제가 해결됐는지 다시 확인해 주세요.";
const ALREADY_APPLIED_REASON =
  "앞 항목의 수정으로 이 부분도 이미 바뀌었어요. 문제가 해결됐는지 다시 확인해 주세요.";

export interface FixAllRequest {
  ownerId: string;
  scanId: string;
  /** 고칠 항목. 없으면 스캔의 해결되지 않은 모든 항목. */
  findingIds?: string[];
  /** 클라이언트가 보낸 Idempotency-Key 헤더(선택). */
  clientKey?: string;
}

export interface FixAllOptions {
  limits?: Limits;
  llmConfigured?: boolean;
  llmFix?: typeof generateLlmFileFix;
  storage?: ArtifactStorage;
  nowMs?: () => number;
}

export interface FixAllResult {
  job: FixJob;
  /** true면 이미 있던 작업을 돌려준 것(새로 실행하지 않음). */
  reused: boolean;
}

const CLIENT_KEY = /^[A-Za-z0-9_-]{8,128}$/;

const STALE_JOB_MESSAGE =
  "수정 작업이 제한 시간 안에 끝나지 않아 중단됐어요. 원본 코드는 그대로예요. 전체 수정을 다시 실행해 주세요.";

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

export function deriveIdempotencyKey(scanId: string, baseVersionId: string, findingIds: string[]): string {
  const h = createHash("sha256");
  h.update(`fixall:v1\u0000${scanId}\u0000${baseVersionId}\u0000${[...findingIds].sort().join(",")}`);
  return `fa_${h.digest("hex").slice(0, 48)}`;
}

export function isStale(job: FixJob, nowMs: number, staleMs: number): boolean {
  return job.status === "running" && nowMs - Date.parse(job.updatedAt) > staleMs;
}

function safeAsciiName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "project";
}

function itemBase(f: SecurityFinding): Pick<FixJobItem, "findingId" | "title" | "severity" | "ruleId" | "files"> {
  return { findingId: f.id, title: f.title, severity: f.severity, ruleId: f.ruleId, files: [] };
}

/** 스캔·소유권·원본 버전을 확인하고 대상 항목을 고른다. */
async function loadContext(req: FixAllRequest) {
  const scan = await getScan(req.scanId, req.ownerId);
  const project = await getProject(scan.projectId, req.ownerId);
  if (!scan.sourceVersionId) {
    throw new AppError(
      409,
      "scan_source_unknown",
      "이 점검 기록은 어떤 코드를 검사했는지 남아 있지 않아 전체 수정을 할 수 없어요. 다시 점검한 뒤 시도해 주세요."
    );
  }
  const base = await getSourceVersion(scan.sourceVersionId, req.ownerId);
  if (scan.sourceContentHash && scan.sourceContentHash !== base.contentHash) {
    throw new AppError(409, "source_integrity_mismatch", "점검한 코드와 저장된 코드가 달라 수정할 수 없어요. 다시 점검해 주세요.");
  }
  const all = await getFindingsForScan(scan.id, req.ownerId);
  let targets: SecurityFinding[];
  if (req.findingIds && req.findingIds.length > 0) {
    const byId = new Map(all.map((f) => [f.id, f]));
    const unknown = req.findingIds.filter((fid) => !byId.has(fid));
    if (unknown.length > 0) {
      throw new AppError(400, "unknown_finding", "이 점검 기록에 없는 항목이 포함돼 있어요.", { unknownCount: unknown.length });
    }
    targets = [...new Set(req.findingIds)].map((fid) => byId.get(fid)!);
  } else {
    targets = all.filter((f) => f.status !== "resolved");
  }
  if (targets.length === 0) {
    throw new AppError(400, "nothing_to_fix", "고칠 항목이 없어요.");
  }
  targets.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  return { scan, project, base, targets };
}

/**
 * 같은 요청의 기존 작업을 찾는다. 이미 끝났거나 실행 중이면 그 작업을 돌려주고,
 * 실패했으면 다음 재시도 키를 쓴다. 오래 멈춘 실행 중 작업은 실패로 정리한다.
 */
async function resolveKey(
  ownerId: string,
  baseKey: string,
  allowRetry: boolean,
  nowMs: number,
  limits: Limits
): Promise<{ key: string } | { existing: FixJob }> {
  for (let attempt = 0; attempt <= MAX_RETRY_ATTEMPTS; attempt++) {
    const key = attempt === 0 ? baseKey : `${baseKey}.r${attempt}`;
    const found = await findFixJobByKey(ownerId, key);
    if (!found) return { key };
    let job = found;
    if (isStale(job, nowMs, limits.staleJobMs)) {
      job = {
        ...job,
        status: "failed",
        errorCode: "timeout",
        errorMessage: STALE_JOB_MESSAGE,
        updatedAt: iso(nowMs),
        completedAt: iso(nowMs),
      };
      await updateFixJob(job);
    }
    if (job.status !== "failed" || !allowRetry) return { existing: job };
  }
  throw new AppError(
    429,
    "too_many_retries",
    "같은 수정을 여러 번 다시 시도했지만 계속 끝내지 못했어요. 잠시 후 다시 점검해서 최신 결과로 수정을 시작해 주세요."
  );
}

export async function startFixAll(req: FixAllRequest, opts: FixAllOptions = {}): Promise<FixAllResult> {
  const limits = opts.limits ?? LIMITS;
  const clock = opts.nowMs ?? Date.now;
  const { scan, project, base, targets } = await loadContext(req);

  const selected = targets.slice(0, limits.fixAllMaxItems);
  const overLimit = targets.slice(limits.fixAllMaxItems);

  let resolved: { key: string } | { existing: FixJob };
  if (req.clientKey !== undefined) {
    if (!CLIENT_KEY.test(req.clientKey)) {
      throw new AppError(400, "invalid_idempotency_key", "요청 키 형식이 올바르지 않아요.");
    }
    resolved = await resolveKey(req.ownerId, `ck_${req.clientKey}`, false, clock(), limits);
  } else {
    const baseKey = deriveIdempotencyKey(scan.id, base.id, targets.map((f) => f.id));
    resolved = await resolveKey(req.ownerId, baseKey, true, clock(), limits);
  }
  if ("existing" in resolved) return { job: resolved.existing, reused: true };

  const startedMs = clock();
  const job: FixJob = {
    id: id("fixjob"),
    projectId: project.id,
    ownerId: req.ownerId,
    scanId: scan.id,
    baseVersionId: base.id,
    baseContentHash: base.contentHash,
    idempotencyKey: resolved.key,
    status: "running",
    items: [
      ...selected.map((f) => ({ ...itemBase(f), outcome: "skipped" as const, reasonCode: "pending", reason: "아직 처리하지 않았어요." })),
      ...overLimit.map((f) => ({
        ...itemBase(f),
        outcome: "skipped" as const,
        reasonCode: "item_limit",
        reason: `한 번에 ${limits.fixAllMaxItems}개까지만 고칠 수 있어 이번에는 다루지 않았어요. 심각한 항목부터 먼저 처리했어요. 이번 수정본을 반영하고 다시 점검한 뒤 남은 항목을 고쳐 주세요.`,
      })),
    ],
    changedFiles: [],
    skippedForLimit: overLimit.length,
    createdAt: iso(startedMs),
    updatedAt: iso(startedMs),
  };

  const inserted = await insertFixJob(job);
  if (!inserted.created) return { job: inserted.job, reused: true };

  try {
    await processJob(job, { project, base, selected, limits, clock, startedMs, opts });
  } catch (e) {
    // 예상하지 못한 오류: 완료로 보이지 않게 실패로 기록한다(내부 내용은 숨김).
    const t = clock();
    job.status = "failed";
    job.errorCode = "internal_error";
    job.errorMessage = "수정 중 예상하지 못한 문제가 생겨 작업을 끝내지 못했어요. 원본 코드는 그대로예요. 다시 시도해 주세요.";
    job.updatedAt = iso(t);
    job.completedAt = iso(t);
    console.error(`[fix-all] job ${job.id} failed: ${e instanceof Error ? e.name : typeof e}`);
    await updateFixJob(job).catch(() => {});
  }
  return { job, reused: false };
}

interface ProcessCtx {
  project: Project;
  base: SourceVersion;
  selected: SecurityFinding[];
  limits: Limits;
  clock: () => number;
  startedMs: number;
  opts: FixAllOptions;
}

async function processJob(job: FixJob, ctx: ProcessCtx): Promise<void> {
  const { base, limits, clock } = ctx;
  const deadline = ctx.startedMs + limits.fixAllTimeBudgetMs;
  const llmOn = ctx.opts.llmConfigured ?? isLlmConfigured();
  const llmFix = ctx.opts.llmFix ?? generateLlmFileFix;
  const working: Record<string, string> = { ...base.files };
  // AI 수정안이 다른 파일에 있는 미들웨어·헬퍼를 알 수 있게 지도를 한 번 만든다.
  const ai: AiGate = { projectMap: buildProjectMap(redactSecrets(base.files).files), secrets: secretValues(base.files) };

  // 파일별로 묶어 서로 다른 파일은 동시에, 같은 파일은 심각도 순서대로 고친다.
  // 한 묶음은 자기 파일만 바꾸므로 묶음끼리 충돌하지 않는다.
  const groups = new Map<string, number[]>();
  ctx.selected.forEach((f, i) => {
    const key = fileGroupKey(f, i);
    groups.set(key, [...(groups.get(key) ?? []), i]);
  });

  await runPool([...groups.values()], limits.fixAllConcurrency, async (indices) => {
    for (const i of indices) {
      const finding = ctx.selected[i];
      const remaining = deadline - clock();
      let item: FixJobItem;
      if (remaining < MIN_ITEM_BUDGET_MS) {
        item = {
          ...itemBase(finding),
          outcome: "skipped",
          reasonCode: "time_budget",
          reason:
            "한 번의 수정 작업에 쓸 수 있는 시간을 다 써서 이 항목은 다루지 못했어요. 이 항목의 파일은 바뀌지 않았어요. 이번 수정본을 반영하고 다시 점검한 뒤 남은 항목을 고쳐 주세요.",
        };
      } else {
        item = await fixOne(finding, working, base, {
          llmOn,
          llmFix,
          ai,
          timeoutMs: Math.min(limits.llmCallTimeoutMs, remaining - 1_000),
          llmFileChars: limits.llmFileChars,
        });
      }
      job.items[i] = item;
      job.updatedAt = iso(clock());
      await updateFixJob(job);
    }
  });

  const changedFiles = Object.keys(working)
    .filter((p) => working[p] !== base.files[p])
    .sort();
  job.changedFiles = changedFiles;
  job.requiredEnv = requiredEnvForFix(base.files, working, changedFiles);
  const applied = job.items.filter((it) => it.outcome === "applied").length;

  if (changedFiles.length > 0) {
    const result = makeSourceVersion({
      projectId: base.projectId,
      ownerId: base.ownerId,
      kind: "fixed",
      files: working,
      parentVersionId: base.id,
      fixJobId: job.id,
    });
    await saveSourceVersion(result);
    job.resultVersionId = result.id;
    job.resultContentHash = result.contentHash;

    const changed: Record<string, string> = {};
    for (const p of changedFiles) changed[p] = working[p];
    const built = buildChangedFilesZip(changed, { text: summaryText(job, ctx.project, base, result) });
    const artifactId = id("fixart");
    const storageKey = artifactKey({ ownerId: job.ownerId, projectId: job.projectId, jobId: job.id, artifactId });
    try {
      await (ctx.opts.storage ?? getArtifactStorage()).put(storageKey, built.zip, "application/zip");
      job.artifact = {
        id: artifactId,
        fileName: `${safeAsciiName(ctx.project.name)}-hoi-fix-${job.id.slice(-8)}.zip`,
        size: built.size,
        sha256: built.sha256,
        changedFiles,
        storageKey,
        createdAt: iso(clock()),
      };
    } catch (e) {
      console.error(`[fix-all] artifact save failed for ${job.id}: ${e instanceof Error ? e.name : typeof e}`);
      job.status = "failed";
      job.errorCode = "artifact_save_failed";
      job.errorMessage = "수정한 파일을 저장하지 못해 내려받을 파일을 만들지 못했어요. 원본 코드는 그대로예요. 다시 시도해 주세요.";
    }
  }

  if (job.status !== "failed") {
    if (applied === 0) {
      job.status = "failed";
      job.errorCode = "nothing_applied";
      job.errorMessage = "자동으로 적용한 수정이 하나도 없어요. 파일은 바뀌지 않았어요. 항목마다 적힌 이유와 해야 할 일을 확인해 주세요.";
    } else if (applied === job.items.length) {
      job.status = "completed";
    } else {
      job.status = "partial";
    }
  }
  const t = clock();
  job.updatedAt = iso(t);
  job.completedAt = iso(t);
  await updateFixJob(job);
}

/** 작업 안에서 공유하는 AI 상태. 키 오류가 한 번 나면 남은 호출을 막는다. */
interface AiGate {
  blocked?: string;
  projectMap?: string;
  /** 화면에 남길 수정 내용에서 가릴 비밀값. */
  secrets?: string[];
}

async function fixOne(
  finding: SecurityFinding,
  working: Record<string, string>,
  base: SourceVersion,
  o: { llmOn: boolean; llmFix: typeof generateLlmFileFix; ai: AiGate; timeoutMs: number; llmFileChars: number }
): Promise<FixJobItem> {
  const head = itemBase(finding);

  // 1) 규칙 기반 수정. 이 경로의 항목(비밀값·의존성)은 AI로 넘기지 않는다.
  const det = deterministicFixFor(finding, working);
  if (det) {
    if (det.kind === "unsupported") {
      return { ...head, outcome: "unsupported", reasonCode: det.reasonCode, reason: det.reason };
    }
    const snapshot = { ...working };
    const r = applyDiffsAtomically(working, base.files, det.fix.diffs);
    if (!r.ok) return { ...head, outcome: "apply_failed", reasonCode: r.failure, reason: PATCH_FAILURE_MESSAGE[r.failure] };
    return appliedItem(head, det.fix, r.changedFiles, "deterministic", false, o.ai.secrets, snapshot);
  }

  // 2) 규칙은 문제로 봤지만 AI가 오탐 가능성이 높다고 본 항목은 코드를 자동으로
  //    바꾸지 않는다. 항목은 그대로 남기고(규칙이 기준), 판단은 사람에게 맡긴다.
  //    (오탐을 "고치면" 멀쩡한 동작을 바꿔 운영을 깨뜨릴 수 있다.)
  // 재판정에서 AI가 "실제 취약점"이라고 바꿔 말했으면 고친다.
  if (finding.aiReview?.verdict === "likely_false_positive" && finding.aiReview.adjudication?.verdict !== "vulnerable") {
    return {
      ...head,
      outcome: "unsupported",
      reasonCode: "disputed_at_scan",
      reason:
        finding.aiReview.adjudication?.verdict === "not_vulnerable"
          ? `AI가 근거 코드를 확인해 실제 문제가 아니라고 판정해서 코드를 바꾸지 않았어요. ${finding.aiReview.adjudication.reason}`.trim()
          : `규칙은 문제로 봤지만 AI는 실제 문제가 아닐 가능성이 높다고 봐서 자동으로 고치지 않았어요${
              finding.aiReview.reason ? ` (${finding.aiReview.reason})` : ""
            }. 문제가 없는 코드를 바꾸면 정상 기능이 깨질 수 있어서예요. 코드를 직접 보고 고칠지 판단해 주세요.`,
    };
  }

  // 3) 실제 파일 내용을 보고 만드는 AI 수정안.
  if (!o.llmOn) {
    return {
      ...head,
      outcome: "unsupported",
      reasonCode: "no_auto_fix",
      reason:
        "이 항목은 정해진 규칙으로 안전하게 고칠 방법이 없고, AI 수정 기능도 설정돼 있지 않아 수정안을 만들지 않았어요. 점검 결과의 수정 방법을 보고 직접 고친 뒤 다시 점검해 주세요.",
    };
  }
  if (o.ai.blocked) {
    return { ...head, outcome: "skipped", reasonCode: "ai_unavailable", reason: aiErrorReason(o.ai.blocked) };
  }
  const file = finding.location?.file ? safeProjectPath(finding.location.file) : null;
  if (!file || working[file] === undefined) {
    return {
      ...head,
      outcome: "unsupported",
      reasonCode: "no_file_location",
      reason:
        "이 항목은 문제가 된 파일 위치가 없어 코드를 자동으로 고치지 않았어요. 서버 설정이나 배포 환경처럼 코드 밖에서 생긴 문제일 수 있어요. 점검 결과의 설명을 보고 해당 설정을 직접 확인해 주세요.",
    };
  }
  if (working[file].length > o.llmFileChars) {
    return {
      ...head,
      outcome: "unsupported",
      reasonCode: "file_too_large_for_ai",
      reason: `이 파일은 ${o.llmFileChars.toLocaleString("ko-KR")}자보다 길어서 AI에 보내지 않았어요. 일부만 잘라 보내면 잘못된 수정안이 나올 수 있어서예요. 문제가 된 부분을 직접 고치거나, 파일을 더 작은 파일 여러 개로 나눈 뒤 다시 점검해 주세요.`,
      files: [file],
    };
  }

  // 비밀값은 가려서 보내고, 돌아온 수정안은 원래 값으로 되돌려 실제 파일과 대조한다.
  const redaction = redactSecrets(working);
  const aiFinding: SecurityFinding = {
    ...finding,
    description: redaction.redactText(finding.description),
    remediation: finding.remediation ? redaction.redactText(finding.remediation) : undefined,
    evidence: finding.evidence.map((e) => ({ ...e, content: redaction.redactText(e.content) })),
  };
  const res = await o.llmFix({
    finding: aiFinding,
    filePath: file,
    fileContent: redaction.files[file],
    timeoutMs: o.timeoutMs,
    projectMap: o.ai.projectMap,
  });
  if (res.kind === "error") {
    if (AI_BLOCKING_ERRORS.has(res.code)) o.ai.blocked = res.code;
    return {
      ...head,
      outcome: "apply_failed",
      reasonCode: `ai_${res.code}`,
      reason: aiErrorReason(res.code),
      llmCorrelationId: res.correlationId ?? undefined,
    };
  }
  if (res.kind === "declined") {
    return {
      ...head,
      outcome: "unsupported",
      reasonCode: "ai_declined",
      reason: scrubPlaceholders(
        res.reason ||
          "AI가 이 파일만 바꿔서는 안전하게 고칠 수 없다고 판단했어요. 다른 파일이나 배포 설정을 함께 바꿔야 할 수 있어요. 점검 결과의 설명을 보고 필요한 부분을 직접 확인해 주세요."
      ),
      llmCorrelationId: res.correlationId,
    };
  }
  if (res.kind === "invalid") {
    return {
      ...head,
      outcome: "apply_failed",
      reasonCode: "ai_invalid_fix",
      reason:
        "AI가 보낸 수정안을 실제 파일 내용에 정확히 맞출 수 없어 적용하지 않았어요. 엉뚱한 곳을 바꾸지 않으려고 멈춘 거예요. 파일은 바뀌지 않았어요. 다시 시도하거나 직접 고쳐 주세요.",
      llmCorrelationId: res.correlationId,
    };
  }
  const fix: FixAttempt = {
    ...res.fix,
    summary: scrubPlaceholders(res.fix.summary),
    plainExplanation: scrubPlaceholders(res.fix.plainExplanation),
    diffs: res.fix.diffs.map((d) => ({
      ...d,
      patch: scrubPlaceholders(d.patch ?? ""),
      beforeText: d.beforeText === undefined ? undefined : redaction.restore(d.beforeText),
      afterText: d.afterText === undefined ? undefined : redaction.restore(d.afterText),
    })),
  };
  const snapshot = { ...working };
  const r = applyDiffsAtomically(working, base.files, fix.diffs);
  if (!r.ok) {
    return {
      ...head,
      outcome: "apply_failed",
      reasonCode: r.failure,
      reason: PATCH_FAILURE_MESSAGE[r.failure],
      fixSource: "llm",
      llmCorrelationId: res.correlationId,
    };
  }
  return {
    ...appliedItem(head, fix, r.changedFiles, "llm", finding.category === "secrets", o.ai.secrets, snapshot),
    llmCorrelationId: res.correlationId,
  };
}

function appliedItem(
  head: ReturnType<typeof itemBase>,
  fix: FixAttempt,
  changedFiles: string[],
  source: "deterministic" | "llm",
  /** 노출된 비밀값 항목이면 키 교체 안내를 붙인다. */
  rotate = false,
  secrets: string[] = [],
  /** 이 항목을 적용하기 직전의 파일들(수정 조각의 줄 번호를 찾는 데 쓴다). */
  before: Record<string, string> = {}
): FixJobItem {
  // 이 항목이 바꾼 코드(전·후). 화면의 diff에 쓰며 비밀값은 가린다.
  const edits = fix.diffs.slice(0, 8).map((d) => {
    const t = d.beforeText !== undefined || d.afterText !== undefined
      ? { before: d.beforeText ?? "", after: d.afterText ?? "" }
      : textsFromPatch(d.patch ?? "");
    const at = t.before ? (before[d.file] ?? "").indexOf(t.before) : -1;
    return {
      file: d.file,
      before: maskSecretValues(t.before, secrets).slice(0, 6000),
      after: maskSecretValues(t.after, secrets).slice(0, 6000),
      line: at >= 0 ? before[d.file].slice(0, at).split("\n").length : undefined,
    };
  });
  return {
    ...head,
    outcome: "applied",
    fixSource: source,
    files: changedFiles.length > 0 ? changedFiles : [...new Set(fix.diffs.map((d) => d.file))],
    summary: fix.summary,
    plainExplanation: rotate
      ? `${fix.plainExplanation} 이미 공개된 키라면 코드만 바꿔서는 막을 수 없어요. 새 키를 발급하고 기존 키는 사용할 수 없게 해 주세요.`
      : fix.plainExplanation,
    // 같은 수정이 앞 항목에서 이미 적용된 경우도 applied다(파일은 한 번만 바뀜).
    reasonCode: changedFiles.length === 0 ? "same_fix_already_applied" : undefined,
    // 적용했지만 재검증 전: 해결됐다고 말하지 않는다.
    reason: changedFiles.length === 0 ? ALREADY_APPLIED_REASON : APPLIED_UNVERIFIED_REASON,
    edits,
  };
}

const OUTCOME_LABEL: Record<FixJobItem["outcome"], string> = {
  applied: "수정 적용(재검증 전)",
  apply_failed: "적용하지 못함",
  unsupported: "자동으로 못 고침(직접 수정 필요)",
  skipped: "이번에 다루지 않음",
};

function summaryText(job: FixJob, project: Project, base: SourceVersion, result: SourceVersion): string {
  const lines: string[] = [
    `# 호이 보안 코치 수정 요약`,
    ``,
    `- 프로젝트: ${project.name}`,
    `- 수정 작업: ${job.id}`,
    `- 기준 코드 해시(SHA-256): ${base.contentHash}`,
    `- 수정본 코드 해시(SHA-256): ${result.contentHash}`,
    ``,
    FIX_GUIDANCE,
    ``,
    `이 파일들에 수정 내용을 적용했어요. 아직 재검증 전이라 문제가 해결됐는지는 확인되지 않았어요.`,
    `반영하기 전에 바뀐 코드를 직접 확인하고, 호이의 재검증 결과도 함께 확인해 주세요.`,
    ``,
    ...(job.requiredEnv && job.requiredEnv.length > 0
      ? [
          `## 반영 전에 설정할 환경변수 (${job.requiredEnv.length}개)`,
          `설정하지 않으면 해당 기능이 안전하게 멈추도록(요청 거절) 고쳐져 있어요.`,
          ...job.requiredEnv.map((e) => `- ${e.name} (${e.files.join(", ")}): ${e.guidance}`),
          ``,
        ]
      : []),
    `## 바뀐 파일 (${job.changedFiles.length}개)`,
    ...job.changedFiles.map((p) => `- ${p}`),
    ``,
    `## 항목별 결과`,
  ];
  for (const it of job.items) {
    const why = it.outcome === "applied" ? it.summary ?? "" : it.reason ?? "";
    lines.push(`- [${OUTCOME_LABEL[it.outcome]}] ${it.title}${why ? ` — ${why}` : ""}`);
  }
  lines.push("");
  return lines.join("\n");
}

/** 작업 조회. 오래 멈춘 실행 중 작업은 이 시점에 실패로 정리한다. */
export async function loadFixJob(
  jobId: string,
  ownerId: string,
  opts: { limits?: Limits; nowMs?: () => number } = {}
): Promise<FixJob> {
  const limits = opts.limits ?? LIMITS;
  const t = (opts.nowMs ?? Date.now)();
  const job = await getFixJob(jobId, ownerId);
  if (!isStale(job, t, limits.staleJobMs)) return job;
  const failed: FixJob = {
    ...job,
    status: "failed",
    errorCode: "timeout",
    errorMessage: STALE_JOB_MESSAGE,
    updatedAt: iso(t),
    completedAt: iso(t),
  };
  await updateFixJob(failed);
  return failed;
}

/**
 * 다운로드할 ZIP 바이트. 저장된 SHA-256과 다르면 내보내지 않는다(손상·변조 방지).
 */
export async function readFixJobArtifact(
  job: FixJob,
  storage: ArtifactStorage = getArtifactStorage()
): Promise<Uint8Array> {
  if (!job.artifact) {
    throw new AppError(404, "artifact_not_found", "내려받을 수정 파일이 없어요.");
  }
  const bytes = await storage.get(job.artifact.storageKey);
  if (!bytes) {
    throw new AppError(410, "artifact_missing", "수정 파일을 찾을 수 없어요. 전체 수정을 다시 실행해 주세요.");
  }
  const sha = createHash("sha256").update(bytes).digest("hex");
  if (sha !== job.artifact.sha256) {
    throw new AppError(500, "artifact_integrity_failed", "수정 파일이 손상돼 내려받을 수 없어요. 전체 수정을 다시 실행해 주세요.");
  }
  return bytes;
}
