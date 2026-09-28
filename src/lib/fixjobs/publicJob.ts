import type { FixJob } from "@/lib/domain/types";

/**
 * What the browser may see of a fix job. Internal fields (owner, storage key,
 * idempotency key, LLM correlation ids) stay on the server.
 */
export function toPublicJob(job: FixJob) {
  const counts = { applied: 0, apply_failed: 0, unsupported: 0, skipped: 0 };
  for (const it of job.items) counts[it.outcome] += 1;
  return {
    id: job.id,
    projectId: job.projectId,
    scanId: job.scanId,
    status: job.status,
    baseContentHash: job.baseContentHash,
    resultContentHash: job.resultContentHash,
    hasResultVersion: Boolean(job.resultVersionId),
    changedFiles: job.changedFiles,
    requiredEnv: job.requiredEnv ?? [],
    skippedForLimit: job.skippedForLimit,
    counts,
    items: job.items.map((it) => ({
      findingId: it.findingId,
      title: it.title,
      severity: it.severity,
      ruleId: it.ruleId,
      outcome: it.outcome,
      reasonCode: it.reasonCode,
      reason: it.reason,
      fixSource: it.fixSource,
      files: it.files,
      summary: it.summary,
      plainExplanation: it.plainExplanation,
      edits: it.edits ?? [],
    })),
    artifact: job.artifact
      ? {
          fileName: job.artifact.fileName,
          size: job.artifact.size,
          sha256: job.artifact.sha256,
          changedFiles: job.artifact.changedFiles,
          createdAt: job.artifact.createdAt,
          downloadPath: `/api/fix-jobs/${encodeURIComponent(job.id)}/download`,
        }
      : undefined,
    verification: job.verification
      ? {
          status: job.verification.status,
          aiStatus: job.verification.aiStatus,
          sentFiles: job.verification.sentFiles,
          omittedFiles: job.verification.omittedFiles,
          items: job.verification.items,
          errorCode: job.verification.errorCode,
          errorMessage: job.verification.errorMessage,
          startedAt: job.verification.startedAt,
          completedAt: job.verification.completedAt,
        }
      : undefined,
    errorCode: job.errorCode,
    errorMessage: job.errorMessage,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
    completedAt: job.completedAt,
  };
}

export type PublicFixJob = ReturnType<typeof toPublicJob>;
