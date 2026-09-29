"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { PlusIcon } from "@/components/icons";
import { buttonClassName } from "@/components/ui";
import { formatKstDateTime } from "@/lib/time";

export interface SidebarScan {
  id: string;
  /** 점검을 마친 시각(없으면 시작 시각). ISO 문자열 */
  at: string;
  findingCount: number;
}

export interface SidebarProject {
  id: string;
  name: string;
  /** 최신순 점검 기록 */
  scans?: SidebarScan[];
}

/** 하위 트리에 바로 보여 줄 점검 기록 수. 나머지는 프로젝트 화면의 "점검 기록"에서 본다. */
const MAX_SCANS_SHOWN = 5;

function scanTime(at: string): string {
  // 예: "9월 29일 오후 3:00" (KST)
  return formatKstDateTime(at, { month: "long", day: "numeric", hour: "numeric", minute: "2-digit" });
}

/**
 * 대시보드 사이드바: 내 프로젝트 목록(스크롤) + 맨 아래 고정 "새 프로젝트 데려오기".
 * 프로젝트마다 점검 기록을 하위 트리로 펼쳐 볼 수 있고, 기록을 누르면 그 점검 결과 화면으로 간다.
 * 목록은 서버 레이아웃이 넘기며, 새 프로젝트·새 점검 뒤 router.refresh()로 다시 불러온다.
 */
export function Sidebar({ projects }: { projects: SidebarProject[] }) {
  const pathname = usePathname();
  const activeProjectId = pathname.match(/^\/dashboard\/projects\/([^/]+)/)?.[1];
  const activeScanId = pathname.match(/^\/dashboard\/scans\/([^/]+)/)?.[1];
  const addActive = pathname.startsWith("/dashboard/new");

  // 지금 보고 있는 프로젝트(또는 보고 있는 점검 결과가 속한 프로젝트)
  const currentProjectId =
    activeProjectId ?? projects.find((p) => p.scans?.some((s) => s.id === activeScanId))?.id;

  const [expanded, setExpanded] = useState<Set<string>>(
    () => new Set(currentProjectId ? [currentProjectId] : []),
  );

  // 다른 프로젝트·점검 결과로 이동하면 그 프로젝트의 트리를 펼친다(사용자가 연 트리는 그대로 둔다).
  useEffect(() => {
    if (!currentProjectId) return;
    setExpanded((prev) => (prev.has(currentProjectId) ? prev : new Set(prev).add(currentProjectId)));
  }, [currentProjectId]);

  function toggle(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  return (
    // 바깥 칸은 페이지 전체 높이로 늘어나 배경·테두리를 끝까지 칠하고,
    // 안쪽 패널은 화면 높이로 고정(sticky)돼 아래 버튼이 항상 보인다.
    <div className="z-20 w-full min-w-0 shrink-0 border-b-2 border-line bg-surface-warm lg:w-64 lg:border-b-0 lg:border-r-2">
    <aside
      aria-label="내 프로젝트"
      className="flex w-full min-w-0 flex-col lg:sticky lg:top-[65px] lg:h-[calc(100vh-65px)]"
    >
      <div className="flex items-center justify-between px-4 pb-2 pt-4">
        <Link href="/dashboard" className="inline-flex min-h-11 items-center rounded-xl text-sm font-extrabold text-ink hover:text-brand-800 hover:underline">
          내 프로젝트
        </Link>
        <span className="rounded-full border-2 border-line bg-surface px-2.5 py-0.5 text-[13px] font-bold text-ink-subtle">{projects.length}개</span>
      </div>

      <nav aria-label="프로젝트 목록" className="max-h-72 min-h-0 flex-1 overflow-y-auto px-3 pb-3 lg:max-h-none">
        {projects.length === 0 ? (
          <p className="px-2 py-3 text-sm leading-relaxed text-ink-muted">아직 프로젝트가 없어요.</p>
        ) : (
          <ul className="space-y-1">
            {projects.map((p) => {
              const active = p.id === activeProjectId;
              const inProject = p.id === currentProjectId;
              const scans = p.scans ?? [];
              const open = expanded.has(p.id);
              const treeId = `sidebar-scans-${p.id}`;
              const shown = scans.slice(0, MAX_SCANS_SHOWN);
              return (
                <li key={p.id}>
                  <div className="flex min-w-0 items-center gap-1">
                    {/* 하위 트리 여닫기. 점검 기록이 없어도 자리를 맞춰 목록 정렬을 유지한다. */}
                    {scans.length > 0 ? (
                      <button
                        type="button"
                        onClick={() => toggle(p.id)}
                        aria-expanded={open}
                        aria-controls={treeId}
                        aria-label={`${p.name} 점검 기록 ${open ? "접기" : "펼치기"}`}
                        className="flex h-11 w-8 shrink-0 items-center justify-center rounded-xl text-ink-subtle hover:bg-surface hover:text-ink"
                      >
                        <span
                          aria-hidden="true"
                          className={`text-xs transition-transform motion-reduce:transition-none ${open ? "rotate-90" : ""}`}
                        >
                          ▶
                        </span>
                      </button>
                    ) : (
                      <span aria-hidden="true" className="w-8 shrink-0" />
                    )}
                    <Link
                      href={`/dashboard/projects/${p.id}`}
                      aria-current={active ? "page" : undefined}
                      title={p.name}
                      className={`relative flex min-h-11 min-w-0 flex-1 items-center gap-2 rounded-2xl border-2 px-3 py-2 pl-4 text-sm font-bold transition-colors motion-reduce:transition-none ${
                        active
                          ? "border-brand-300 bg-primary-soft text-ink shadow-[0_3px_0_var(--border-strong)]"
                          : inProject
                            ? "border-line bg-surface text-ink"
                            : "border-transparent text-ink-subtle hover:border-line hover:bg-surface hover:text-ink"
                      }`}
                    >
                      {/* 색 외에 형태로도 현재 위치를 알린다(왼쪽 막대) */}
                      {active && <span aria-hidden="true" className="absolute inset-y-2 left-1 w-1 rounded-full bg-brand-700" />}
                      <span
                        aria-hidden="true"
                        className={`h-2.5 w-2.5 shrink-0 rounded-full ${active || inProject ? "bg-brand-700" : "bg-line-strong"}`}
                      />
                      <span className="min-w-0 flex-1 truncate">{p.name}</span>
                      {scans.length > 0 && (
                        <span className="shrink-0 rounded-full bg-surface-warm px-2 text-[12px] font-bold text-ink-subtle">
                          <span className="sr-only">점검 기록 </span>
                          {scans.length}
                        </span>
                      )}
                    </Link>
                  </div>

                  {scans.length > 0 && (
                    <ul
                      id={treeId}
                      hidden={!open}
                      aria-label={`${p.name} 점검 기록`}
                      className="ml-[1.1rem] mt-1 space-y-0.5 border-l-2 border-dashed border-line-strong pl-3"
                    >
                      {shown.map((s, index) => {
                        const current = s.id === activeScanId;
                        return (
                          <li key={s.id}>
                            <Link
                              href={`/dashboard/scans/${s.id}`}
                              aria-current={current ? "page" : undefined}
                              className={`flex min-h-10 min-w-0 flex-col justify-center rounded-xl border-2 px-2.5 py-1 text-[13px] leading-snug transition-colors motion-reduce:transition-none ${
                                current
                                  ? "border-brand-300 bg-primary-soft font-bold text-ink"
                                  : "border-transparent text-ink-subtle hover:border-line hover:bg-surface hover:text-ink"
                              }`}
                            >
                              <span className="flex items-center gap-1.5">
                                <span className="truncate font-semibold">{scanTime(s.at)}</span>
                                {index === 0 && (
                                  <span className="shrink-0 rounded-full bg-sun-soft px-1.5 text-[11px] font-bold text-brand-900">
                                    최근
                                  </span>
                                )}
                              </span>
                              <span className="text-[12px] text-ink-muted">
                                {s.findingCount > 0 ? `확인할 부분 ${s.findingCount}개` : "찾은 항목 없음"}
                              </span>
                            </Link>
                          </li>
                        );
                      })}
                      {scans.length > MAX_SCANS_SHOWN && (
                        <li>
                          <Link
                            href={`/dashboard/projects/${p.id}`}
                            className="flex min-h-10 items-center rounded-xl px-2.5 text-[13px] font-bold text-brand-800 hover:underline"
                          >
                            점검 기록 모두 보기 ({scans.length}개)
                          </Link>
                        </li>
                      )}
                    </ul>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </nav>

      <div className="shrink-0 border-t-2 border-line bg-surface-warm p-3 pb-4">
        <Link
          href="/dashboard/new"
          aria-current={addActive ? "page" : undefined}
          className={buttonClassName({ variant: "primary", size: "sm", className: "w-full" })}
        >
          <PlusIcon className="h-4 w-4" />
          <span>새 프로젝트 데려오기</span>
        </Link>
      </div>
    </aside>
    </div>
  );
}
