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

export const dynamic = "force-dynamic";

const JOB_LABEL: Record<string, string> = {
  running: "수정 중",
  completed: "수정 완료",
  partial: "일부 수정",
  failed: "수정 실패",
};

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
        <section aria-labelledby="history-title">
          <h2 id="history-title" className="text-lg font-bold text-ink">
            점검 기록
          </h2>
          {rows.length === 0 ? (
            <EmptyState
              className="mt-4"
              title="아직 점검 기록이 없어요"
              description="점검 전이라 결과가 없어요. 위험이 없다는 뜻은 아니에요. 위의 ‘점검 시작하기’로 확인해 주세요."
            />
          ) : (
            <ol className="mt-4 space-y-3">
              {rows.map(({ scan, latestJob }, index) => (
                <li key={scan.id}>
                  <Link
                    href={`/dashboard/scans/${scan.id}`}
                    className="group flex min-h-20 flex-col gap-2 rounded-3xl border border-line bg-surface p-5 shadow-warm transition-colors hover:border-brand-300 motion-reduce:transition-none sm:flex-row sm:items-center sm:justify-between"
                  >
                    <div className="min-w-0">
                      <p className="font-bold text-ink">
                        {new Date(scan.completedAt ?? scan.startedAt).toLocaleString("ko-KR")}
                        {index === 0 && <span className="ml-2 text-sm font-semibold text-brand-800">가장 최근</span>}
                      </p>
                      <p className="mt-1 text-sm text-ink-subtle">
                        확인할 부분 {scan.findingIds.length}개
                        {latestJob ? ` · ${JOB_LABEL[latestJob.status] ?? ""}` : ""}
                      </p>
                    </div>
                    <span className="text-sm font-bold text-brand-800 group-hover:underline">
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
