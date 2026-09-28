import Link from "next/link";
import { notFound } from "next/navigation";
import { PageHeader } from "@/components/PageHeader";
import { HoiSpeech } from "@/components/mascot/HoiSpeech";
import {
  Badge,
  Card,
  EmptyState,
  MetricCard,
  SectionHeader,
  buttonClassName,
} from "@/components/ui";
import { requirePageUserId } from "@/lib/auth";
import {
  getProject,
  listScans,
  getFindingsForScan,
  NotFoundError,
  NotAuthorizedError,
} from "@/lib/store/store";
import { RunScanButton } from "@/components/RunScanButton";
import { ScanScopeMeter } from "@/components/ScanScopeMeter";
import { SCAN_MODE_INFO } from "@/lib/domain/scanMode";

export const dynamic = "force-dynamic";

export default async function ProjectPage({
  params,
}: {
  params: { id: string };
}) {
  const uid = await requirePageUserId(`/dashboard/projects/${params.id}`);
  let project;
  try {
    project = await getProject(params.id, uid);
  } catch (e) {
    if (e instanceof NotFoundError || e instanceof NotAuthorizedError) notFound();
    throw e;
  }

  const scans = await listScans(params.id, uid);
  const scanSummaries = await Promise.all(
    scans.map(async (scan) => {
      const findings = await getFindingsForScan(scan.id, uid);
      return {
        scan,
        total: findings.length,
        crit: findings.filter((finding) => finding.severity === "critical").length,
        resolved: findings.filter((finding) => finding.status === "resolved").length,
      };
    }),
  );

  const latest = scanSummaries[0];
  const latestOpen = latest ? latest.total - latest.resolved : 0;
  const drift =
    project.lastScannedCommit &&
    project.currentCommit &&
    project.lastScannedCommit !== project.currentCommit;
  const sourceReady = project.isDemo || Boolean(project.sourceCode);
  const activeCheckReady =
    Boolean(project.deploymentUrl) && Boolean(project.deploymentAuthorized);
  const modeInfo = project.scanMode ? SCAN_MODE_INFO[project.scanMode] : null;
  const testAccountCount = project.testAccounts?.length ?? 0;

  return (
    <>
      <PageHeader
        title={project.name}
        subtitle="현재 상태를 확인하고, 호이와 함께 다음 점검을 시작해요."
        backHref="/dashboard"
        backLabel="내 프로젝트"
      >
        <RunScanButton projectId={project.id} />
      </PageHeader>

      <div className="mx-auto max-w-6xl px-4 py-7 sm:px-6 sm:py-10">
        <nav
          aria-label="프로젝트 상세 바로가기"
          className="mb-7 flex gap-2 overflow-x-auto pb-2"
        >
          {[
            ["#overview", "한눈에 보기"],
            ["#findings", "찾은 내용"],
            ["#history", "점검 기록"],
            ["#settings", "설정"],
          ].map(([href, label]) => (
            <a
              key={href}
              href={href}
              className="inline-flex min-h-11 shrink-0 items-center rounded-full border border-line bg-white px-4 text-sm font-bold text-ink-subtle hover:border-brand-300 hover:text-brand-800"
            >
              {label}
            </a>
          ))}
        </nav>

        <section id="overview" className="scroll-mt-32" aria-labelledby="overview-title">
          <HoiSpeech mood={drift || latestOpen > 0 ? "guide" : "cheer"} size="md">
            <span id="overview-title">
              {drift
                ? "코드가 마지막 점검 뒤 바뀌었어요. 최신 코드로 다시 확인하는 게 가장 먼저예요."
                : latestOpen > 0
                  ? `최근 점검에서 아직 확인할 내용이 ${latestOpen}건 있어요. 급한 항목부터 하나씩 해결해요.`
                  : latest
                    ? "최근 점검에서 해결을 기다리는 항목이 없어요. 코드가 바뀌면 다시 점검해 주세요."
                    : "아직 첫 점검 전이에요. 준비된 범위를 확인한 뒤 보안 점검을 시작해요."}
            </span>
          </HoiSpeech>

          {drift && (
            <Card variant="danger" className="mt-5 p-5" role="status">
              <p className="font-semibold text-red-800">최근 결과가 현재 코드와 다를 수 있어요</p>
              <p className="mt-1 text-sm leading-relaxed text-red-700">
                마지막 점검 커밋 <code className="break-all font-mono">{project.lastScannedCommit}</code> 이후
                현재 커밋 <code className="break-all font-mono">{project.currentCommit}</code>으로 바뀌었어요.
                새 점검으로 다시 확인해 주세요.
              </p>
            </Card>
          )}

          <div className="mt-6 grid gap-4 sm:grid-cols-3">
            <MetricCard
              label="프로젝트 상태"
              value={drift ? "다시 점검해요" : sourceReady ? "점검 준비됨" : "소스 연결 필요"}
              hint={drift ? "현재 코드와 최근 결과가 달라요" : "연결된 입력 기준"}
              tone={drift ? "warning" : sourceReady ? "success" : "neutral"}
            />
            <MetricCard
              label="최근 점검"
              value={latest ? `${latest.total}건 발견` : "기록 없음"}
              hint={latest ? new Date(latest.scan.startedAt).toLocaleString("ko-KR") : "첫 점검을 시작해 보세요"}
              tone={latest?.crit ? "danger" : "neutral"}
            />
            <MetricCard
              label="실제 해결 진행"
              value={latest ? `${latest.resolved} / ${latest.total}건` : "—"}
              hint={latest ? "수정 후 재검증까지 마친 항목" : "점검 뒤 표시돼요"}
              tone={latest && latest.total > 0 && latest.resolved === latest.total ? "success" : "primary"}
            />
          </div>
        </section>

        <section id="findings" className="scroll-mt-32 pt-12" aria-labelledby="findings-title">
          <SectionHeader
            eyebrow="지금 볼 내용"
            title={<span id="findings-title">찾은 내용</span>}
            description="가장 최근 점검에서 확인한 결과예요. 해결 완료는 재검증까지 통과한 항목만 셉니다."
          />
          {latest ? (
            <Card variant="raised" className="mt-5 p-5 sm:p-6">
              <div className="flex flex-col gap-5 sm:flex-row sm:items-center sm:justify-between">
                <div className="min-w-0">
                  <div className="flex flex-wrap gap-2">
                    <Badge tone={latest.crit > 0 ? "danger" : "success"}>
                      {latest.crit > 0 ? `매우 급한 항목 ${latest.crit}건` : "매우 급한 항목 없음"}
                    </Badge>
                    <Badge tone={latestOpen > 0 ? "warning" : "success"}>
                      {latestOpen > 0 ? `해결 대기 ${latestOpen}건` : "모두 해결 확인"}
                    </Badge>
                  </div>
                  <h3 className="mt-3 text-xl font-bold text-ink">
                    {new Date(latest.scan.startedAt).toLocaleString("ko-KR")} 점검
                  </h3>
                  <p className="mt-1 break-words text-sm text-ink-subtle">
                    점검 커밋 <code className="break-all font-mono">{latest.scan.commitSha ?? "기록 없음"}</code>
                  </p>
                </div>
                <Link
                  href={`/dashboard/scans/${latest.scan.id}`}
                  className={buttonClassName({ className: "w-full sm:w-auto" })}
                >
                  최근 결과 보기
                </Link>
              </div>
            </Card>
          ) : (
            <EmptyState
              className="mt-5"
              title="아직 찾은 내용이 없어요"
              description="아직 점검하지 않았다는 뜻이며, 위험이 없다는 결과는 아니에요. 위의 ‘보안 점검 시작’으로 확인해 주세요."
            />
          )}
        </section>

        <section id="history" className="scroll-mt-32 pt-12" aria-labelledby="history-title">
          <SectionHeader
            eyebrow="변화 확인"
            title={<span id="history-title">점검 기록</span>}
            description="점검 시점의 코드와 해결 진행을 비교할 수 있어요."
          />
          {scanSummaries.length === 0 ? (
            <p className="mt-4 text-ink-subtle">첫 점검을 실행하면 기록이 여기에 쌓여요.</p>
          ) : (
            <div className="mt-5 space-y-3">
              {scanSummaries.map(({ scan, total, crit, resolved }, index) => (
                <Link
                  key={scan.id}
                  href={`/dashboard/scans/${scan.id}`}
                  className="group flex min-h-20 flex-col gap-3 rounded-xl border border-line bg-white p-5 shadow-warm transition hover:border-brand-300 sm:flex-row sm:items-center sm:justify-between"
                >
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      {index === 0 && <Badge tone="primary">가장 최근</Badge>}
                      <p className="font-semibold text-ink">
                        {new Date(scan.startedAt).toLocaleString("ko-KR")}
                      </p>
                    </div>
                    <p className="mt-1 break-words text-sm text-ink-muted">
                      커밋 <span className="break-all font-mono">{scan.commitSha ?? "기록 없음"}</span>
                    </p>
                  </div>
                  <div className="flex flex-wrap items-center gap-2 text-sm">
                    <Badge tone={crit > 0 ? "danger" : "neutral"}>매우 급함 {crit}건</Badge>
                    <Badge tone={resolved === total && total > 0 ? "success" : "info"}>
                      해결 확인 {resolved}/{total}건
                    </Badge>
                    <span className="font-bold text-brand-700 group-hover:underline">결과 보기 →</span>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </section>

        <section id="settings" className="scroll-mt-32 pt-12" aria-labelledby="settings-title">
          <SectionHeader
            eyebrow="점검 입력"
            title={<span id="settings-title">설정</span>}
            description="어떤 자료와 권한으로 점검하는지 확인해요. 기술 식별자는 필요할 때만 펼쳐보세요."
          />
          {modeInfo && (
            <Card variant="raised" className="mt-5 p-5">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <p className="font-semibold text-ink">
                  보안 스캔 방식: <span className="text-brand-800">{modeInfo.letter} · {modeInfo.title}</span>
                </p>
                <Badge tone={project.scanMode === "isolated_active" ? "danger" : project.scanMode === "safe_active" ? "warning" : "success"}>
                  {modeInfo.tagline}
                </Badge>
              </div>
              <ScanScopeMeter scope={modeInfo.scope} className="mt-3 max-w-sm" />
              {project.scanMode === "isolated_active" && (
                <p className="mt-3 text-sm leading-relaxed text-ink-subtle">
                  격리 서버 테스트 계정 {testAccountCount}개가 연결되어 있어요
                  {project.testAccounts?.length
                    ? ` (${project.testAccounts.map((a) => a.label).join(", ")})`
                    : ""}
                  . 비밀번호는 화면에 표시하지 않아요.
                </p>
              )}
            </Card>
          )}
          <div className="mt-5 grid gap-4 md:grid-cols-2">
            <Card variant="warm" className="p-5">
              <p className="font-semibold text-ink">소스 코드 점검</p>
              <p className="mt-2 text-sm leading-relaxed text-ink-subtle">
                {sourceReady
                  ? project.isDemo
                    ? "데모 전용 예제 소스를 읽기 전용으로 점검해요."
                    : project.sourceZipName
                      ? `${project.sourceZipName}에서 제공된 소스를 읽기 전용으로 점검해요.`
                      : "붙여넣은 소스를 읽기 전용으로 점검해요."
                  : project.scanMode && project.scanMode !== "static"
                    ? "소스 없이 연결했어요. 정적 분석은 건너뛰고 배포 주소 동적 분석만 진행해요."
                    : "연결된 소스가 없어 정적 분석을 실행할 수 없어요. 새 프로젝트에서 ZIP을 올리거나 코드를 붙여넣어 주세요."}
              </p>
            </Card>
            <Card variant="warm" className="p-5">
              <p className="font-semibold text-ink">배포 주소 능동 점검</p>
              <p className="mt-2 text-sm leading-relaxed text-ink-subtle">
                {!project.deploymentUrl
                  ? "배포 주소가 없어 네트워크 점검 대상이 없어요."
                  : activeCheckReady
                    ? project.scanMode === "isolated_active"
                      ? "격리된 테스트 서버에 테스트 계정으로 공격 재현(IDOR·권한 상승 등)까지 실행해요."
                      : "소유·점검 권한을 확인한 배포 주소에 허용된 비파괴 점검만 실행해요."
                    : "배포 주소는 있지만 소유·점검 권한 승인이 없어 능동 점검은 실행하지 않아요. 소스 정적 분석만 진행해요."}
              </p>
            </Card>
          </div>
          <details className="mt-4 rounded-2xl border border-line bg-white px-5 py-3">
            <summary className="flex min-h-11 cursor-pointer items-center font-bold text-ink">기술 메타데이터 보기</summary>
            <dl className="grid gap-4 border-t border-line py-4 text-sm sm:grid-cols-2">
              <Meta label="저장소" value={project.repositoryUrl ?? "연결 안 됨"} />
              <Meta label="배포 주소" value={project.deploymentUrl ?? "연결 안 됨"} />
              <Meta label="마지막 점검 커밋" value={project.lastScannedCommit ?? "기록 없음"} mono />
              <Meta label="현재 커밋" value={project.currentCommit ?? "기록 없음"} mono />
            </dl>
          </details>
        </section>
      </div>
    </>
  );
}

function Meta({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="font-bold text-ink-muted">{label}</dt>
      <dd className={`mt-1 break-all text-ink ${mono ? "font-mono text-xs" : ""}`}>{value}</dd>
    </div>
  );
}
