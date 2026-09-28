"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { GridIcon, PlusIcon, SearchIcon } from "@/components/icons";
import { Hoi } from "@/components/mascot/Hoi";
import { buttonClassName } from "@/components/ui";
import { logoutAction } from "@/lib/authActions";

const NAV = [
  { href: "/dashboard", label: "내 프로젝트", icon: GridIcon, kind: "projects" },
  { href: "/dashboard/quick-check", label: "빠른 점검", icon: SearchIcon, kind: "exact" },
  { href: "/dashboard/new", label: "프로젝트 추가", icon: PlusIcon, kind: "exact" },
] as const;

function isActive(pathname: string, item: (typeof NAV)[number]) {
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

  return (
    <aside className="z-20 flex w-full shrink-0 flex-col border-b border-line bg-white/95 lg:sticky lg:top-0 lg:h-screen lg:w-64 lg:border-b-0 lg:border-r">
      <div className="flex items-center justify-between gap-3 border-b border-line px-3 py-2 lg:px-4 lg:py-3">
        <Link
          href="/"
          className="flex min-h-11 min-w-0 items-center gap-2 rounded-2xl pr-2 font-black text-ink"
          aria-label="호이 보안 코치 홈"
        >
          <Hoi mood="guide" size="sm" decorative className="-my-1" />
          <span className="min-w-0 leading-tight">
            <span className="block truncate">호이 보안 코치</span>
            <span className="block truncate text-[11px] font-medium text-ink-muted">
              같이 튼튼하게 만들어요
            </span>
          </span>
        </Link>
        {user && (
          <span className="max-w-24 truncate text-xs font-bold text-ink-subtle lg:hidden" title={user.email}>
            {user.name || user.email}
          </span>
        )}
      </div>

      <nav
        aria-label="대시보드 메뉴"
        className="flex flex-wrap gap-1 overflow-x-auto p-2 lg:flex-1 lg:content-start lg:flex-col lg:overflow-visible lg:p-3"
      >
        {NAV.map((item) => {
          const active = isActive(pathname, item);
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              aria-current={active ? "page" : undefined}
              className={`flex min-h-11 min-w-fit flex-1 items-center justify-center gap-2 rounded-2xl px-3 py-2 text-sm font-bold transition-colors lg:flex-none lg:justify-start ${
                active
                  ? "bg-primary-soft text-brand-900"
                  : "text-ink-subtle hover:bg-surface-warm hover:text-ink"
              }`}
            >
              <Icon className={active ? "h-5 w-5 text-brand-700" : "h-5 w-5 text-ink-muted"} />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>

      <div className="hidden space-y-3 border-t border-line p-4 lg:block">
        {user ? (
          <div className="space-y-2">
            <div className="truncate text-xs font-bold text-ink-subtle" title={user.email}>
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
          <Link href="/login" className={buttonClassName({ size: "sm", className: "w-full" })}>
            로그인
          </Link>
        )}

        <p className="rounded-2xl border border-line bg-surface-warm p-3 text-[11px] leading-relaxed text-ink-muted">
          호이는 점검한 시점과 범위 안에서 살펴봐요. 자동 점검만으로 모든 문제를 찾는다고 보장하지 않아요.
        </p>
      </div>
    </aside>
  );
}
