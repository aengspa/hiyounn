import Link from "next/link";

export function TopNav() {
  return (
    <header className="sticky top-0 z-10 border-b border-slate-200 bg-white/80 backdrop-blur">
      <div className="flex w-full items-center justify-between px-8 py-3">
        <Link href="/" className="flex items-center gap-2 font-semibold">
          <ShieldIcon />
          <span>바이브 보안 에이전트</span>
        </Link>
        <nav className="flex items-center gap-1 text-sm">
          <Link
            href="/dashboard"
            className="rounded-md px-3 py-1.5 text-slate-600 hover:bg-slate-100"
          >
            프로젝트
          </Link>
          <Link
            href="/dashboard/new"
            className="rounded-md bg-brand-600 px-3 py-1.5 font-medium text-white hover:bg-brand-700"
          >
            프로젝트 추가
          </Link>
        </nav>
      </div>
    </header>
  );
}

export function ShieldIcon({ className = "h-5 w-5 text-brand-600" }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={className}>
      <path
        d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <path
        d="M9 12l2 2 4-4"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
