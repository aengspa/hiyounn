import Link from "next/link";
import { getCurrentUser } from "@/lib/auth";
import { logoutAction } from "@/lib/authActions";
import { ShieldIcon } from "@/components/icons";

export async function TopNav() {
  const user = await getCurrentUser();

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
            className="rounded-md px-3 py-1.5 text-slate-600 hover:bg-slate-100"
          >
            프로젝트 추가
          </Link>

          {user ? (
            <div className="ml-2 flex items-center gap-2 border-l border-slate-200 pl-3">
              <span className="hidden text-slate-500 sm:inline">
                {user.name || user.email}
              </span>
              <form action={logoutAction}>
                <button
                  type="submit"
                  className="rounded-md border border-slate-300 px-3 py-1.5 font-medium text-slate-700 hover:bg-slate-50"
                >
                  로그아웃
                </button>
              </form>
            </div>
          ) : (
            <div className="ml-2 flex items-center gap-1 border-l border-slate-200 pl-3">
              <Link
                href="/login"
                className="rounded-md px-3 py-1.5 text-slate-600 hover:bg-slate-100"
              >
                로그인
              </Link>
              <Link
                href="/signup"
                className="rounded-md bg-brand-600 px-3 py-1.5 font-medium text-white hover:bg-brand-700"
              >
                회원가입
              </Link>
            </div>
          )}
        </nav>
      </div>
    </header>
  );
}
