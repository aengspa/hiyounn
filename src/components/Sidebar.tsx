"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { GridIcon, PlusIcon, SearchIcon } from "@/components/icons";
import { Hoi } from "@/components/mascot/Hoi";
import { buttonClassName } from "@/components/ui";
import { logoutAction } from "@/lib/authActions";

const SERVICE_NAME = "호이 보안 코치";

// 메뉴 링크 2개(설계 5-1). "프로젝트 추가"는 Primary 스타일 링크로 따로 그린다.
const NAV = [
  { href: "/dashboard", label: "내 프로젝트", icon: GridIcon, kind: "projects" },
  { href: "/dashboard/quick-check", label: "빠른 점검", icon: SearchIcon, kind: "exact" },
] as const;

const ADD_PROJECT = { href: "/dashboard/new", label: "프로젝트 추가", icon: PlusIcon, kind: "exact" } as const;

type NavItem = (typeof NAV)[number] | typeof ADD_PROJECT;

function isActive(pathname: string, item: NavItem) {
  if (item.kind === "exact") return pathname === item.href;
  return (
    pathname === "/dashboard" ||
    pathname.startsWith("/dashboard/projects/") ||
    pathname.startsWith("/dashboard/scans/") ||
    pathname.startsWith("/dashboard/findings/")
  );
}

export function Sidebar({
  user,
}: {
  user?: { email: string; name?: string } | null;
}) {
  const pathname = usePathname();
  const addActive = isActive(pathname, ADD_PROJECT);
  const AddIcon = ADD_PROJECT.icon;

  return (
    <aside className="z-20 flex w-full min-w-0 shrink-0 flex-col border-b border-line bg-surface lg:sticky lg:top-0 lg:h-screen lg:w-60 lg:border-b-0 lg:border-r lg:bg-surface-warm">
      {/* 상단 바: 로고 + (모바일) 프로젝트 추가·로그아웃 */}
      <div className="flex min-w-0 items-center gap-2 px-3 py-2 lg:px-4 lg:py-4">
        <Link
          href="/dashboard"
          aria-label={SERVICE_NAME}
          title={SERVICE_NAME}
          className="flex min-h-11 min-w-0 flex-1 items-center gap-1.5 rounded-2xl pr-1 font-bold text-ink"
        >
          <Hoi mood="guide" size="sm" decorative />
          <span className="min-w-0 truncate leading-tight">{SERVICE_NAME}</span>
        </Link>

        <div className="flex shrink-0 items-center gap-2 lg:hidden">
          <Link
            href={ADD_PROJECT.href}
            aria-current={addActive ? "page" : undefined}
            className={buttonClassName({ variant: "primary", size: "sm", className: "!px-3" })}
          >
            <AddIcon className="hidden h-4 w-4 sm:block" />
            <span className="whitespace-nowrap">{ADD_PROJECT.label}</span>
          </Link>
          {user ? (
            <form action={logoutAction}>
              <button
                type="submit"
                className={buttonClassName({ variant: "secondary", size: "sm", className: "!px-3 whitespace-nowrap" })}
              >
                로그아웃
              </button>
            </form>
          ) : (
            <Link
              href="/login"
              className={buttonClassName({ variant: "secondary", size: "sm", className: "!px-3 whitespace-nowrap" })}
            >
              로그인
            </Link>
          )}
        </div>
      </div>

      <nav
        aria-label="대시보드 메뉴"
        className="grid grid-cols-2 gap-2 px-3 pb-3 lg:flex lg:flex-1 lg:flex-col lg:gap-1 lg:px-3 lg:pb-3"
      >
        {NAV.map((item) => {
          const active = isActive(pathname, item);
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              aria-current={active ? "page" : undefined}
              className={`relative flex min-h-11 min-w-0 items-center justify-center gap-2 rounded-2xl border px-3 py-2 text-sm font-semibold transition-colors lg:justify-start lg:pl-4 ${
                active
                  ? "border-line bg-primary-soft text-ink"
                  : "border-transparent text-ink-subtle hover:border-line hover:bg-canvas-soft hover:text-ink"
              }`}
            >
              {/* 색 외에 형태로도 현재 위치를 알린다(왼쪽 막대) */}
              {active && (
                <span
                  aria-hidden="true"
                  className="absolute inset-y-2 left-1 w-1 rounded-full bg-brand-700"
                />
              )}
              <Icon
                className={active ? "h-5 w-5 shrink-0 text-brand-800" : "h-5 w-5 shrink-0 text-ink-muted"}
              />
              <span className="min-w-0 truncate">{item.label}</span>
            </Link>
          );
        })}

        <Link
          href={ADD_PROJECT.href}
          aria-current={addActive ? "page" : undefined}
          className={buttonClassName({
            variant: "primary",
            size: "sm",
            className: "mt-2 hidden w-full lg:inline-flex",
          })}
        >
          <AddIcon className="h-4 w-4" />
          <span>{ADD_PROJECT.label}</span>
        </Link>
      </nav>

      <div className="hidden space-y-3 border-t border-line p-4 lg:block">
        {user ? (
          <div className="space-y-2">
            <div className="truncate text-[13px] font-medium text-ink-subtle" title={user.email}>
              {user.name || user.email}
            </div>
            <form action={logoutAction}>
              <button
                type="submit"
                className={buttonClassName({ variant: "secondary", size: "sm", className: "w-full" })}
              >
                로그아웃
              </button>
            </form>
          </div>
        ) : (
          <Link href="/login" className={buttonClassName({ variant: "secondary", size: "sm", className: "w-full" })}>
            로그인
          </Link>
        )}

        <p className="rounded-2xl border border-line bg-surface p-3 text-[13px] leading-relaxed text-ink-muted">
          점검한 시점과 범위 안에서 확인한 결과예요. 자동 점검만으로 모든 문제를 찾는다고 보장하지 않아요.
        </p>
      </div>
    </aside>
  );
}
