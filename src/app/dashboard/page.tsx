import Link from "next/link";
import { listProjects, listScans } from "@/lib/store/store";
import { requirePageUserId } from "@/lib/auth";
import { PageHeader } from "@/components/PageHeader";
import { Hoi } from "@/components/mascot/Hoi";
import { EmptyState, buttonClassName } from "@/components/ui";

export const dynamic = "force-dynamic";

function formatDate(value?: string) {
  if (!value) return "아직 점검 전";
  return new Intl.DateTimeFormat("ko-KR", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
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
      <PageHeader title="내 프로젝트" backHref="/" backLabel="이전" />
      <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6">
        {rows.length === 0 ? (
          <EmptyState
            title="아직 호이에게 소개한 프로젝트가 없어요"
            description="코드를 올려 첫 프로젝트를 만들면 호이가 약한 곳부터 살펴볼게요."
            illustration={<Hoi mood="rest" size="lg" />}
            action={
              <Link href="/dashboard/new" className={buttonClassName({ size: "lg" })}>
                새 프로젝트 데려오기
              </Link>
            }
          />
        ) : (
          <ul className="grid gap-3 sm:grid-cols-2" aria-label="프로젝트 목록">
            {rows.map(({ project, scanCount, lastCheckedAt }) => (
              <li key={project.id}>
                <Link
                  href={`/dashboard/projects/${project.id}`}
                  className="flex min-h-24 flex-col justify-between rounded-3xl border border-line bg-surface p-5 shadow-warm transition-colors hover:border-brand-300 motion-reduce:transition-none"
                >
                  <span className="break-words text-lg font-bold text-ink">{project.name}</span>
                  <span className="mt-2 text-sm text-ink-muted">
                    {scanCount > 0 ? `점검 ${scanCount}번 · 마지막 ${formatDate(lastCheckedAt)}` : "아직 점검 전"}
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
