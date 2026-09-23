"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldIcon } from "@/components/icons";

const NAV = [
  { href: "/dashboard", label: "프로젝트", icon: GridIcon, exact: true },
  { href: "/dashboard/new", label: "프로젝트 추가", icon: PlusIcon, exact: true },
];

type ProjectItem = { id: string; name: string };

export function Sidebar({ projects = [] }: { projects?: ProjectItem[] }) {
  const pathname = usePathname();

  return (
    <aside className="flex w-60 shrink-0 flex-col border-r border-slate-200 bg-white">
      <Link
        href="/"
        className="flex items-center gap-2 border-b border-slate-100 px-5 py-4 font-semibold"
      >
        <ShieldIcon className="h-5 w-5 text-slate-700" />
        <span className="leading-tight">
          바이브 보안 에이전트
          <span className="block text-[11px] font-normal text-slate-400">
            Vibe Security Agent
          </span>
        </span>
      </Link>

      <nav className="flex-1 space-y-1 overflow-y-auto p-3">
        {NAV.map((item) => {
          const active = item.exact
            ? pathname === item.href
            : pathname.startsWith(item.href);
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition ${
                active
                  ? "bg-slate-100 text-slate-900"
                  : "text-slate-600 hover:bg-slate-50"
              }`}
            >
              <Icon className={active ? "text-slate-700" : "text-slate-400"} />
              {item.label}
            </Link>
          );
        })}

        {projects.length > 0 && (
          <div className="pt-4">
            <p className="px-3 pb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-400">
              내 프로젝트
            </p>
            {projects.map((p) => {
              const href = `/dashboard/projects/${p.id}`;
              const active = pathname === href;
              return (
                <Link
                  key={p.id}
                  href={href}
                  title={p.name}
                  className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition ${
                    active
                      ? "bg-slate-100 font-medium text-slate-900"
                      : "text-slate-600 hover:bg-slate-50"
                  }`}
                >
                  <span
                    className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                      active ? "bg-slate-700" : "bg-slate-300"
                    }`}
                  />
                  <span className="truncate">{p.name}</span>
                </Link>
              );
            })}
          </div>
        )}
      </nav>

      <div className="border-t border-slate-100 p-4">
        <div className="rounded-lg bg-slate-50 p-3 text-[11px] leading-relaxed text-red-400">
          자동 보안 점검은 모든 취약점을 찾아내지 못합니다. 결과는 점검한 시점과
          범위에 한정됩니다.
        </div>
      </div>
    </aside>
  );
}

function GridIcon({ className = "" }) {
  return (
    <svg viewBox="0 0 20 20" fill="none" className={`h-4 w-4 ${className}`}>
      <rect x="2.5" y="2.5" width="6" height="6" rx="1.5" stroke="currentColor" strokeWidth="1.5" />
      <rect x="11.5" y="2.5" width="6" height="6" rx="1.5" stroke="currentColor" strokeWidth="1.5" />
      <rect x="2.5" y="11.5" width="6" height="6" rx="1.5" stroke="currentColor" strokeWidth="1.5" />
      <rect x="11.5" y="11.5" width="6" height="6" rx="1.5" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}

function PlusIcon({ className = "" }) {
  return (
    <svg viewBox="0 0 20 20" fill="none" className={`h-4 w-4 ${className}`}>
      <path d="M10 4v12M4 10h12" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
    </svg>
  );
}
