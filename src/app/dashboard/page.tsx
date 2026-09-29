import Link from "next/link";
import { listProjects, listScans } from "@/lib/store/store";
import { requirePageUserId } from "@/lib/auth";
import { PageHeader } from "@/components/PageHeader";
import { Hoi } from "@/components/mascot/Hoi";
import { EmptyState, buttonClassName } from "@/components/ui";
import { formatKstDateTime } from "@/lib/time";

export const dynamic = "force-dynamic";

function formatDate(value?: string) {
  if (!value) return "아직 점검 전";
  return formatKstDateTime(value, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** 내 프로젝트 목록만 보여 준다. 새 프로젝트는 사이드바 아래 버튼으로 만든다. */
export default async function DashboardPage() {
  const uid = await requirePageUserId("/dashboard");
  const projects = await listProjects(uid);
  const rows = await Promise.all(
    projects.map(async (project) => {
      const scans = await listScans(project.id, uid);
      const latest = scans[0];
      return { project, scanCount: scans.length, lastCheckedAt: latest?.completedAt ?? latest?.startedAt };
    })
  );

  return (
    <>
      <PageHeader
        title="어떤 서비스를 튼튼하게 만들어 볼까요?"
        subtitle="프로젝트를 고르면 호이가 최근 점검 결과부터 알려드려요."
        backHref="/"
        backLabel="이전"
      />
      <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6">
        {rows.length === 0 ? (
          <EmptyState
            title="아직 호이에게 소개한 프로젝트가 없어요"
            description="첫 프로젝트를 연결하면 약한 곳부터 차근차근 살펴드릴게요."
            illustration={<Hoi mood="rest" size="lg" />}
            action={
              <Link href="/dashboard/new" className={buttonClassName({ size: "lg" })}>
                첫 프로젝트 데려오기
              </Link>
            }
          />
        ) : (
          <ul className="grid gap-4 sm:grid-cols-2" aria-label="프로젝트 목록">
            {rows.map(({ project, scanCount, lastCheckedAt }) => (
              <li key={project.id}>
                <Link
                  href={`/dashboard/projects/${project.id}`}
                  className="hoi-card-3d hoi-card-link group flex min-h-28 flex-col justify-between gap-3 p-5 sm:p-6"
                >
                  <span className="flex items-start justify-between gap-3">
                    <span className="min-w-0 break-words text-lg font-extrabold text-ink">{project.name}</span>
                    <span
                      aria-hidden="true"
                      className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-primary-soft font-bold text-brand-900 transition-transform group-hover:translate-x-0.5 motion-reduce:transition-none"
                    >
                      →
                    </span>
                  </span>
                  <span className="flex items-center gap-2 text-sm font-semibold text-ink-subtle">
                    <span
                      aria-hidden="true"
                      className={`h-2.5 w-2.5 shrink-0 rounded-full ${scanCount > 0 ? "bg-success" : "bg-line-strong"}`}
                    />
                    {scanCount > 0
                      ? `점검 ${scanCount}번 · 마지막 ${formatDate(lastCheckedAt)}`
                      : "호이가 아직 살펴보지 않았어요"}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>
    </>
  );
}
