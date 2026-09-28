import Link from "next/link";
import { listProjects, listScans, getFindingsForScan } from "@/lib/store/store";
import { getCurrentUserId } from "@/lib/auth";
import { SeverityStrip } from "@/components/SeverityStrip";
import { PageHeader } from "@/components/PageHeader";
import { Hoi } from "@/components/mascot/Hoi";
import { HoiSpeech } from "@/components/mascot/HoiSpeech";
import {
  Badge,
  Card,
  Disclosure,
  EmptyState,
  MetricCard,
  buttonClassName,
} from "@/components/ui";
import type { SeverityCounts } from "@/lib/domain/types";

export const dynamic = "force-dynamic";

function emptyCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0 };
}

function formatDate(value?: string) {
  if (!value) return "아직 없어요";
  return new Intl.DateTimeFormat("ko-KR", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

export default async function DashboardPage() {
  const uid = await getCurrentUserId();
  const projects = await listProjects(uid);

  const rows = await Promise.all(
    projects.map(async (project) => {
      const scans = await listScans(project.id, uid);
      const latest = scans[0];
      const counts = emptyCounts();
      let resolved = 0;
      let urgentOpen = 0;
      let openTotal = 0;

      if (latest) {
        const findings = await getFindingsForScan(latest.id, uid);
        for (const finding of findings) {
          counts[finding.severity] += 1;
          if (finding.status === "resolved") {
            resolved += 1;
          } else {
            openTotal += 1;
            if (finding.severity === "critical" || finding.severity === "high") {
              urgentOpen += 1;
            }
          }
        }
      }

      const drift = Boolean(
        project.lastScannedCommit &&
          project.currentCommit &&
          project.lastScannedCommit !== project.currentCommit,
      );
      const lastCheckedAt = project.lastScanDate ?? latest?.completedAt ?? latest?.startedAt;

      return { project, latest, counts, resolved, urgentOpen, openTotal, drift, lastCheckedAt };
    }),
  );

  const resolvedTotal = rows.reduce((sum, row) => sum + row.resolved, 0);
  const urgentTotal = rows.reduce((sum, row) => sum + row.urgentOpen, 0);
  const waitingTotal = rows.filter((row) => !row.latest).length;
  const recentCheckedAt = rows
    .map((row) => row.lastCheckedAt)
    .filter((value): value is string => Boolean(value))
    .sort((a, b) => new Date(b).getTime() - new Date(a).getTime())[0];

  return (
    <>
      <PageHeader
        title="어떤 서비스를 튼튼하게 만들어 볼까요?"
        subtitle="프로젝트를 고르면 호이가 최근 점검 결과부터 알려드려요."
        action={{ href: "/dashboard/new", label: "새 프로젝트 데려오기" }}
      >
        <Link
          href="/dashboard/quick-check"
          className={buttonClassName({ variant: "secondary", size: "sm" })}
        >
          코드만 빠르게 보기
        </Link>
      </PageHeader>

      <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6">
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
          <div className="space-y-10">
            <section aria-labelledby="today-summary-title">
              <HoiSpeech mood={urgentTotal > 0 ? "concerned" : "guide"} size="md">
                {urgentTotal > 0
                  ? `먼저 살펴볼 항목이 ${urgentTotal}개 있어요. 가장 중요한 프로젝트부터 같이 확인해요.`
                  : waitingTotal > 0
                    ? `아직 첫 점검을 기다리는 프로젝트가 ${waitingTotal}개 있어요.`
                    : "최근 점검 결과를 정리했어요. 프로젝트를 골라 다음 단계를 이어가요."}
              </HoiSpeech>
              <h2 id="today-summary-title" className="sr-only">
                최근 점검 요약
              </h2>
              <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <MetricCard
                  label="잘 해결했어요"
                  value={`${resolvedTotal}개`}
                  hint="최신 점검에서 해결 상태인 항목"
                  tone="success"
                />
                <MetricCard
                  label="먼저 살펴봐요"
                  value={`${urgentTotal}개`}
                  hint="아직 해결되지 않은 심각·높음 항목"
                  tone={urgentTotal > 0 ? "danger" : "neutral"}
                />
                <MetricCard
                  label="점검 기다리는 중"
                  value={`${waitingTotal}개`}
                  hint="점검 기록이 없는 프로젝트"
                  tone={waitingTotal > 0 ? "warning" : "neutral"}
                />
                <MetricCard
                  label="최근 점검"
                  value={recentCheckedAt ? formatDate(recentCheckedAt) : "아직 없어요"}
                  hint="등록된 프로젝트 중 가장 최근 시점"
                  tone="info"
                  className="[&>div:nth-child(2)>div]:break-keep [&>div:nth-child(2)>div]:text-xl"
                />
              </div>
            </section>

            <section aria-labelledby="project-list-title">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
                <div>
                  <p className="text-sm font-extrabold text-brand-700">내 프로젝트</p>
                  <h2 id="project-list-title" className="text-2xl font-black tracking-tight text-ink">
                    어디부터 살펴볼까요?
                  </h2>
                </div>
                <p className="text-sm text-ink-muted">총 {rows.length}개 프로젝트</p>
              </div>

              <div className="mt-5 grid gap-5 md:grid-cols-2">
                {rows.map(({ project, latest, counts, resolved, urgentOpen, openTotal, drift, lastCheckedAt }) => {
                  const status = !latest
                    ? "호이가 아직 살펴보지 않았어요"
                    : drift
                      ? "코드가 바뀌었어요. 다시 살펴보는 게 좋아요"
                      : urgentOpen > 0
                        ? `먼저 고치면 좋은 곳이 ${urgentOpen}개 있어요`
                        : openTotal > 0
                          ? `차근차근 다듬을 곳이 ${openTotal}개 있어요`
                          : "이번 점검 범위의 항목을 모두 해결했어요";
                  const address = project.repositoryUrl ?? project.deploymentUrl;

                  return (
                    <Card key={project.id} variant="raised" className="flex min-w-0 flex-col p-5 sm:p-6">
                      <div className="flex min-w-0 flex-wrap items-start justify-between gap-3">
                        <div className="min-w-0 flex-1">
                          <h3 className="break-words text-xl font-black text-ink">{project.name}</h3>
                          <p className="mt-1 truncate text-sm text-ink-muted" title={address}>
                            {address ?? "연결된 저장소·서비스 주소가 없어요"}
                          </p>
                        </div>
                        {drift ? <Badge tone="warning">다시 점검 권장</Badge> : latest ? <Badge tone="info">점검 기록 있음</Badge> : <Badge>첫 점검 전</Badge>}
                      </div>

                      <div className="mt-5 rounded-2xl bg-surface-warm p-4">
                        <p className="font-extrabold leading-relaxed text-ink">{status}</p>
                        <p className="mt-1 text-sm text-ink-subtle">
                          마지막 점검 · {formatDate(lastCheckedAt)}
                        </p>
                      </div>

                      {latest && (
                        <div className="mt-5 overflow-x-auto pb-1">
                          <SeverityStrip counts={counts} resolved={resolved} />
                        </div>
                      )}

                      {(project.lastScannedCommit || project.currentCommit) && (
                        <Disclosure summary="커밋 정보 보기" className="mt-5">
                          <dl className="grid gap-3 text-sm sm:grid-cols-2">
                            <Meta label="마지막 점검 커밋" value={project.lastScannedCommit ?? "기록 없음"} mono />
                            <Meta label="현재 커밋" value={project.currentCommit ?? "기록 없음"} mono />
                          </dl>
                        </Disclosure>
                      )}

                      <div className="mt-auto pt-5">
                        <Link
                          href={`/dashboard/projects/${project.id}`}
                          className={buttonClassName({ className: "w-full" })}
                        >
                          {latest ? "최근 결과와 다음 단계 보기" : "첫 점검 준비하기"}
                        </Link>
                      </div>
                    </Card>
                  );
                })}
              </div>
            </section>
          </div>
        )}
      </div>
    </>
  );
}

function Meta({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs font-bold text-ink-muted">{label}</dt>
      <dd className={`mt-1 break-all text-ink ${mono ? "font-mono text-xs" : ""}`}>{value}</dd>
    </div>
  );
}
