import Link from "next/link";
import { notFound } from "next/navigation";
import { PageHeader } from "@/components/PageHeader";
import { getCurrentUserId } from "@/lib/auth";
import {
  getProject,
  listScans,
  getFindingsForScan,
  NotFoundError,
  NotAuthorizedError,
} from "@/lib/store/store";
import { RunScanButton } from "@/components/RunScanButton";

export const dynamic = "force-dynamic";

export default async function ProjectPage({
  params,
}: {
  params: { id: string };
}) {
  const uid = await getCurrentUserId();
  let project;
  try {
    project = await getProject(params.id, uid);
  } catch (e) {
    if (e instanceof NotFoundError || e instanceof NotAuthorizedError)
      notFound();
    throw e;
  }
  const scans = await listScans(params.id, uid);
  // Precompute per-scan finding counts (JSX can't await).
  const scanSummaries = await Promise.all(
    scans.map(async (scan) => {
      const findings = await getFindingsForScan(scan.id, uid);
      return {
        scan,
        total: findings.length,
        crit: findings.filter((f) => f.severity === "critical").length,
        resolved: findings.filter((f) => f.status === "resolved").length,
      };
    })
  );
  const drift =
    project.lastScannedCommit &&
    project.currentCommit &&
    project.lastScannedCommit !== project.currentCommit;

  return (
    <>
      <PageHeader
        title={project.name}
        subtitle={project.repositoryUrl ?? "저장소 없음"}
        backHref="/dashboard"
        backLabel="프로젝트"
      >
        <RunScanButton projectId={project.id} />
      </PageHeader>

      <main className="mx-auto max-w-5xl px-6 py-8">
        {drift && (
          <div className="mb-6 rounded-xl border border-amber-200 bg-amber-50 p-4">
            <p className="font-medium text-amber-900">
              보안 검증 결과가 오래됐을 수 있습니다
            </p>
            <p className="mt-1 text-sm text-amber-800">
              마지막으로 검증한 이후 코드가 변경되었습니다. 마지막 검증 커밋{" "}
              <code className="font-mono">{project.lastScannedCommit}</code>, 현재
              커밋 <code className="font-mono">{project.currentCommit}</code>. 다시
              스캔해 재검증하세요.
            </p>
          </div>
        )}

        {/* 입력 연결 상태를 정직하게 표시 — 무엇이 검사되고 무엇이 안 되는지. */}
        {!project.isDemo && (
          <div className="mb-6 space-y-2">
            {!project.sourceCode && (
              <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                <p className="font-medium text-slate-800">소스가 연결되지 않았습니다</p>
                <p className="mt-1 text-sm text-slate-600">
                  이 프로젝트에는 검사할 소스 코드가 없습니다. 정적 분석(IDOR·XSS·
                  인젝션·시크릿)을 실행하려면 프로젝트를 다시 만들 때 ZIP을 업로드하거나
                  코드를 붙여넣으세요.
                </p>
              </div>
            )}
            {project.deploymentUrl && !project.deploymentAuthorized && (
              <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                <p className="font-medium text-slate-800">배포 능동 점검 미승인</p>
                <p className="mt-1 text-sm text-slate-600">
                  배포 주소가 있지만 소유권 확인을 하지 않아 능동(네트워크) 점검은
                  실행되지 않습니다. 소스 정적 분석만 수행됩니다.
                </p>
              </div>
            )}
          </div>
        )}

        <div className="grid gap-4 sm:grid-cols-4">
          <Stat label="배포 주소" value={project.deploymentUrl ?? "—"} />
          <Stat
            label="마지막 스캔 커밋"
            value={project.lastScannedCommit ?? "—"}
            mono
          />
          <Stat label="현재 커밋" value={project.currentCommit ?? "—"} mono />
          <Stat
            label="마지막 스캔"
            value={
              project.lastScanDate
                ? new Date(project.lastScanDate).toLocaleString("ko-KR")
                : "없음"
            }
          />
        </div>

        <h2 className="mt-10 text-lg font-semibold text-slate-900">스캔 기록</h2>
        {scans.length === 0 ? (
          <p className="mt-2 text-slate-600">
            아직 스캔 기록이 없습니다. 첫 보안 스캔을 실행하세요.
          </p>
        ) : (
          <div className="mt-3 divide-y divide-slate-100 overflow-hidden rounded-xl border border-slate-200 bg-white">
            {scanSummaries.map(({ scan, total, crit, resolved }) => {
              return (
                <Link
                  key={scan.id}
                  href={`/dashboard/scans/${scan.id}`}
                  className="flex items-center justify-between px-5 py-4 hover:bg-slate-50"
                >
                  <div>
                    <p className="font-medium text-slate-900">
                      {new Date(scan.startedAt).toLocaleString("ko-KR")}
                    </p>
                    <p className="text-sm text-slate-500">
                      커밋 <span className="font-mono">{scan.commitSha}</span> ·{" "}
                      {total}건 발견
                    </p>
                  </div>
                  <div className="text-sm text-slate-600">
                    {crit > 0 ? (
                      <span className="font-medium text-red-600">
                        심각 {crit}건
                      </span>
                    ) : (
                      <span>심각 없음</span>
                    )}
                    {resolved > 0 && (
                      <span className="ml-3 text-emerald-600">
                        검증 완료 {resolved}건
                      </span>
                    )}
                  </div>
                </Link>
              );
            })}
          </div>
        )}
      </main>
    </>
  );
}

function Stat({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4">
      <p className="text-xs tracking-wide text-slate-400">{label}</p>
      <p className={`mt-1 truncate text-slate-800 ${mono ? "font-mono text-sm" : ""}`}>
        {value}
      </p>
    </div>
  );
}
