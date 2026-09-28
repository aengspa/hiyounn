"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { PlusIcon } from "@/components/icons";
import { buttonClassName } from "@/components/ui";

export interface SidebarProject {
  id: string;
  name: string;
}

/**
 * 대시보드 사이드바: 내 프로젝트 목록(스크롤) + 맨 아래 고정 "새 프로젝트 데려오기".
 * 계정 버튼은 상단 헤더 오른쪽에만 있다. 프로젝트 목록은 서버 레이아웃이 넘기며,
 * 새 프로젝트를 만든 뒤 router.refresh()로 다시 불러온다.
 */
export function Sidebar({ projects }: { projects: SidebarProject[] }) {
  const pathname = usePathname();
  const activeId = pathname.match(/^\/dashboard\/projects\/([^/]+)/)?.[1];
  const addActive = pathname.startsWith("/dashboard/new");

  return (
    <aside
      aria-label="내 프로젝트"
      className="z-20 flex w-full min-w-0 shrink-0 flex-col border-b border-line bg-surface-warm lg:sticky lg:top-[65px] lg:h-[calc(100vh-65px)] lg:w-64 lg:border-b-0 lg:border-r"
    >
      <div className="flex items-center justify-between px-4 pb-2 pt-4">
        <Link href="/dashboard" className="rounded-xl text-sm font-bold text-ink-subtle hover:text-ink hover:underline">
          내 프로젝트
        </Link>
        <span className="text-xs text-ink-muted">{projects.length}개</span>
      </div>

      <nav aria-label="프로젝트 목록" className="max-h-48 min-h-0 flex-1 overflow-y-auto px-3 pb-3 lg:max-h-none">
        {projects.length === 0 ? (
          <p className="px-2 py-3 text-sm leading-relaxed text-ink-muted">아직 프로젝트가 없어요.</p>
        ) : (
          <ul className="space-y-1">
            {projects.map((p) => {
              const active = p.id === activeId;
              return (
                <li key={p.id}>
                  <Link
                    href={`/dashboard/projects/${p.id}`}
                    aria-current={active ? "page" : undefined}
                    title={p.name}
                    className={`relative flex min-h-11 min-w-0 items-center rounded-2xl border px-3 py-2 pl-4 text-sm font-semibold transition-colors motion-reduce:transition-none ${
                      active
                        ? "border-line bg-primary-soft text-ink"
                        : "border-transparent text-ink-subtle hover:border-line hover:bg-surface hover:text-ink"
                    }`}
                  >
                    {/* 색 외에 형태로도 현재 위치를 알린다(왼쪽 막대) */}
                    {active && <span aria-hidden="true" className="absolute inset-y-2 left-1 w-1 rounded-full bg-brand-700" />}
                    <span className="min-w-0 truncate">{p.name}</span>
                  </Link>
                </li>
              );
            })}
          </ul>
        )}
      </nav>

      <div className="shrink-0 border-t border-line bg-surface-warm p-3">
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
  );
}
