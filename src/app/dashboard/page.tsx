import Link from "next/link";
import { listProjects, listScans, getFindingsForScan } from "@/lib/store/store";
import { getCurrentUserId } from "@/lib/auth";
import { SeverityStrip } from "@/components/SeverityStrip";
import { PageHeader } from "@/components/PageHeader";
import type { SeverityCounts } from "@/lib/domain/types";

export const dynamic = "force-dynamic";

function emptyCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0 };
}

export default async function DashboardPage() {
  const uid = await getCurrentUserId();
  const projects = listProjects(uid);

  const rows = projects.map((p) => {
    const scans = listScans(p.id, uid);
    const latest = scans[0];
    const counts = emptyCounts();
    let resolved = 0;
    if (latest) {
      const findings = getFindingsForScan(latest.id, uid);
      for (const f of findings) {
        counts[f.severity] += 1;
        if (f.status === "resolved") resolved += 1;
      }
    }
    const drift =
      p.lastScannedCommit && p.currentCommit
        ? p.lastScannedCommit !== p.currentCommit
        : false;
    return { project: p, latest, counts, resolved, drift };
  });

  return (
    <>
      <PageHeader
        title="프로젝트"
        subtitle="프로젝트를 등록한 뒤 보안 스캔을 실행하세요."
        action={{ href: "/dashboard/new", label: "프로젝트 추가" }}
      />
      <main className="mx-auto max-w-6xl px-6 py-8">
        {rows.length === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-300 bg-white p-12 text-center">
            <p className="text-slate-600">아직 등록된 프로젝트가 없습니다.</p>
            <Link
              href="/dashboard/new"
              className="mt-4 inline-block rounded-lg bg-brand-600 px-4 py-2 font-medium text-white hover:bg-brand-700"
            >
              첫 프로젝트 추가하기
            </Link>
          </div>
        ) : (
          <div className="grid gap-5 md:grid-cols-2">
            {rows.map(({ project, latest, counts, resolved, drift }) => (
              <Link
                key={project.id}
                href={`/dashboard/projects/${project.id}`}
                className="block rounded-xl border border-slate-200 bg-white p-5 shadow-sm transition hover:border-brand-300 hover:shadow"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <h2 className="text-lg font-semibold text-slate-900">
                      {project.name}
                    </h2>
                    <p className="mt-0.5 text-sm text-slate-500">
                      {project.repositoryUrl ?? "저장소 없음"}
                    </p>
                  </div>
                  {drift && (
                    <span className="rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-800">
                      검증 결과가 오래됐을 수 있음
                    </span>
                  )}
                </div>

                <dl className="mt-4 grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
                  <Meta label="배포 주소" value={project.deploymentUrl ?? "—"} />
                  <Meta
                    label="마지막 스캔 커밋"
                    value={project.lastScannedCommit ?? "—"}
                    mono
                  />
                  <Meta
                    label="마지막 스캔"
                    value={
                      project.lastScanDate
                        ? new Date(project.lastScanDate).toLocaleString("ko-KR")
                        : "없음"
                    }
                  />
                  <Meta
                    label="현재 커밋"
                    value={project.currentCommit ?? "—"}
                    mono
                  />
                </dl>

                <div className="mt-4 flex items-center justify-between border-t border-slate-100 pt-4">
                  {latest ? (
                    <SeverityStrip counts={counts} resolved={resolved} />
                  ) : (
                    <span className="text-sm text-slate-500">아직 스캔하지 않음</span>
                  )}
                </div>
              </Link>
            ))}
          </div>
        )}
      </main>
    </>
  );
}

function Meta({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div>
      <dt className="text-xs tracking-wide text-slate-400">{label}</dt>
      <dd className={`truncate text-slate-700 ${mono ? "font-mono text-xs" : ""}`}>
        {value}
      </dd>
    </div>
  );
}
