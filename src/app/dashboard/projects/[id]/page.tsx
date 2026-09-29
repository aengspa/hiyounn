import Link from "next/link";
import { notFound } from "next/navigation";
import { PageHeader } from "@/components/PageHeader";
import { EmptyState } from "@/components/ui";
import { requirePageUserId } from "@/lib/auth";
import {
  getProject,
  listScans,
  listFixJobsForScan,
  NotFoundError,
  NotAuthorizedError,
} from "@/lib/store/store";
import { RunScanButton } from "@/components/RunScanButton";
import { ReuploadForm } from "@/components/ReuploadForm";
import { formatKstDateTime } from "@/lib/time";

export const dynamic = "force-dynamic";

/** 파일에 적용한 것과 해결 확인(재검증)은 다르다. 여기서는 적용 상태만 말한다. */
const JOB_LABEL: Record<string, string> = {
  running: "수정안을 만드는 중이에요",
  completed: "모든 항목에 수정 적용",
  partial: "일부 항목에 수정 적용",
  failed: "수정 적용 못 함",
};

function jobSummary(job: { status: string; verification?: { status: string } }): string {
  const base = JOB_LABEL[job.status] ?? "";
  if (!base || job.status === "running" || job.status === "failed") return base;
  if (job.verification?.status === "completed") return `${base} · 재검증함`;
  if (job.verification?.status === "running") return `${base} · 재검증 중`;
  if (job.verification?.status === "failed") return `${base} · 재검증 못 끝냄`;
  return `${base} · 재검증 전`;
}

/** 프로젝트 상세: 점검 시작 버튼 + "점검 기록" 목록 하나. */
export default async function ProjectPage({ params }: { params: { id: string } }) {
  const uid = await requirePageUserId(`/dashboard/projects/${params.id}`);
  let project;
  try {
    project = await getProject(params.id, uid);
  } catch (e) {
    if (e instanceof NotFoundError || e instanceof NotAuthorizedError) notFound();
    throw e;
  }

  const scans = await listScans(project.id, uid);
  const rows = await Promise.all(
    scans.map(async (scan) => {
      const jobs = await listFixJobsForScan(scan.id, uid);
      return { scan, latestJob: jobs[0] };
    })
  );
  const source = project.sourceZipName ? `${project.sourceZipName}에서 받은 코드` : "붙여 넣은 코드";

  return (
    <>
      <PageHeader title={project.name} subtitle={`점검 대상: ${source}`} backHref="/dashboard" backLabel="이전">
        <RunScanButton projectId={project.id} label={rows.length > 0 ? "다시 점검하기" : "점검 시작하기"} />
      </PageHeader>

      <div className="mx-auto max-w-4xl px-4 py-8 sm:px-6">
        {!project.isDemo && (
          <div className="mb-8">
            <ReuploadForm projectId={project.id} />
          </div>
        )}
        <section aria-labelledby="history-title">
          <h2 id="history-title" className="text-xl font-extrabold text-ink sm:text-2xl">
            점검 기록
          </h2>
          {rows.length === 0 ? (
            <EmptyState
              className="mt-4"
              title="아직 점검 기록이 없어요"
              description="호이가 아직 살펴보지 않았어요. 위험이 없다는 뜻은 아니에요. 위의 ‘점검 시작하기’로 같이 확인해 봐요."
            />
          ) : (
            <ol className="mt-4 space-y-3">
              {rows.map(({ scan, latestJob }, index) => (
                <li key={scan.id}>
                  <Link
                    href={`/dashboard/scans/${scan.id}`}
                    className="hoi-card-3d hoi-card-link group flex min-h-20 flex-col gap-3 p-5 sm:flex-row sm:items-center sm:justify-between sm:p-6"
                  >
                    <div className="flex min-w-0 items-start gap-4">
                      <span
                        aria-hidden="true"
                        className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl text-base font-extrabold ${
                          index === 0 ? "bg-sun-soft text-brand-900" : "bg-surface-warm text-ink-subtle"
                        }`}
                      >
                        {rows.length - index}
                      </span>
                      <div className="min-w-0">
                        <p className="font-extrabold text-ink">
                          {formatKstDateTime(scan.completedAt ?? scan.startedAt)}
                          {index === 0 && (
                            <span className="ml-2 inline-flex rounded-full border-2 border-brand-300 bg-primary-soft px-2.5 py-0.5 text-[13px] font-bold text-brand-900">
                              가장 최근
                            </span>
                          )}
                        </p>
                        <p className="mt-1 text-sm font-semibold text-ink-subtle">
                          확인할 부분 {scan.findingIds.length}개
                          {latestJob && jobSummary(latestJob) ? ` · ${jobSummary(latestJob)}` : ""}
                        </p>
                      </div>
                    </div>
                    <span className="inline-flex min-h-11 items-center gap-1 self-start rounded-full bg-primary-soft px-4 text-sm font-bold text-brand-900 sm:self-auto">
                      결과 보기 <span aria-hidden="true">→</span>
                    </span>
                  </Link>
                </li>
              ))}
            </ol>
          )}
        </section>
      </div>
    </>
  );
}
