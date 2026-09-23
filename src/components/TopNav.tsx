import Link from "next/link";
import { getCurrentUser } from "@/lib/auth";
import { LogoutButton } from "@/components/LogoutButton";
import { ShieldIcon } from "@/components/icons";

export { ShieldIcon };

export async function TopNav() {
  const user = await getCurrentUser();

  return (
    <header className="sticky top-0 z-10 border-b border-slate-200 bg-white/80 backdrop-blur">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
        <Link href="/" className="flex items-center gap-2 font-semibold">
          <ShieldIcon className="h-5 w-5 text-slate-700" />
          <span>바이브 보안 에이전트</span>
        </Link>
        <nav className="flex items-center gap-2 text-sm">
          {user ? (
            <>
              <span className="hidden text-slate-500 sm:inline">
                {user.name || user.email}
              </span>
              <LogoutButton />
            </>
          ) : (
            <>
              <Link
                href="/login"
                className="rounded-md border border-slate-800 bg-slate-800 px-4 py-1.5 font-medium text-white hover:bg-slate-900"
              >
                로그인
              </Link>
              <Link
                href="/signup"
                className="rounded-md border border-slate-300 bg-slate-100 px-4 py-1.5 font-medium text-slate-700 hover:bg-slate-200"
              >
                회원가입
              </Link>
            </>
          )}
        </nav>
      </div>
    </header>
  );
}
