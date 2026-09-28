import Link from "next/link";
import { getCurrentUser } from "@/lib/auth";
import { logoutAction } from "@/lib/authActions";
import { Hoi } from "@/components/mascot/Hoi";
import { buttonClassName } from "@/components/ui";

const navLink =
  "inline-flex min-h-11 items-center rounded-2xl px-3 text-sm font-bold text-ink-subtle hover:bg-primary-soft/60 hover:text-ink";

export async function TopNav() {
  const user = await getCurrentUser();

  return (
    <header className="sticky top-0 z-30 border-b border-line bg-white/90 backdrop-blur-lg">
      <div className="mx-auto flex w-full max-w-7xl flex-wrap items-center justify-between gap-2 px-3 py-2 sm:px-6 lg:px-8">
        <Link
          href="/"
          className="flex min-h-11 items-center gap-2 rounded-2xl pr-2 font-black text-ink"
          aria-label="호이 보안 코치 홈"
        >
          <Hoi mood="welcome" size="sm" decorative className="-my-1" />
          <span className="whitespace-nowrap">호이 보안 코치</span>
        </Link>

        <nav
          aria-label="주요 메뉴"
          className="order-3 flex w-full flex-wrap items-center gap-1 border-t border-line pt-2 sm:order-none sm:w-auto sm:border-0 sm:pt-0"
        >
          <Link href="/dashboard" className={navLink}>
            내 프로젝트
          </Link>
          <Link href="/dashboard/quick-check" className={navLink}>
            빠른 점검
          </Link>
          <Link
            href="/dashboard/new"
            className={buttonClassName({ size: "sm", className: "ml-auto sm:ml-1" })}
          >
            프로젝트 추가
          </Link>
        </nav>

        <div className="flex min-h-11 items-center gap-1">
          {user ? (
            <>
              <span className="hidden max-w-40 truncate px-2 text-sm font-medium text-ink-subtle lg:inline" title={user.email}>
                {user.name || user.email}
              </span>
              <form action={logoutAction}>
                <button
                  type="submit"
                  className="inline-flex min-h-11 items-center rounded-2xl px-3 text-sm font-bold text-ink-subtle hover:bg-surface-warm hover:text-ink"
                  aria-label={`${user.name || user.email} 계정에서 로그아웃`}
                >
                  로그아웃
                </button>
              </form>
            </>
          ) : (
            <>
              <Link href="/login" className={navLink}>
                로그인
              </Link>
              <Link
                href="/signup"
                className={buttonClassName({ variant: "secondary", size: "sm" })}
              >
                회원가입
              </Link>
            </>
          )}
        </div>
      </div>
    </header>
  );
}
