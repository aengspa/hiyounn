import Link from "next/link";
import { getCurrentUser } from "@/lib/auth";
import { logoutAction } from "@/lib/authActions";
import { Hoi } from "@/components/mascot/Hoi";
import { buttonClassName } from "@/components/ui";

const navLink =
  "hidden min-h-11 items-center rounded-xl px-3 text-sm font-medium text-ink-subtle hover:bg-primary-soft/60 hover:text-ink sm:inline-flex";

/**
 * 공개 헤더. 명세 3-1: 왼쪽 로고(작은 캐릭터), 가운데 같은 페이지 앵커 링크,
 * 오른쪽 로그인/내 프로젝트 + 스캔 시작하기. 모바일에서는 가운데 메뉴를 접는다.
 */
export async function TopNav() {
  const user = await getCurrentUser();

  return (
    <header className="sticky top-0 z-30 border-b border-line bg-white/95 backdrop-blur">
      <div className="mx-auto flex w-full max-w-6xl items-center justify-between gap-3 px-4 py-3 sm:px-6 lg:px-8">
        <Link
          href="/"
          className="flex min-h-11 shrink-0 items-center gap-2 rounded-xl font-bold text-ink"
          aria-label="호이 보안 코치 홈"
        >
          <Hoi mood="welcome" size="sm" decorative className="h-7 w-7" />
          <span className="whitespace-nowrap">호이 보안 코치</span>
        </Link>

        <nav aria-label="주요 메뉴" className="flex items-center gap-1">
          <a href="#features" className={navLink}>기능 소개</a>
          <a href="#how-it-works" className={navLink}>사용 방법</a>
          <a href="#sample-result" className={navLink}>결과 예시</a>
        </nav>

        <div className="flex min-h-11 shrink-0 items-center gap-2">
          {user ? (
            <>
              <Link
                href="/dashboard"
                className="hidden min-h-11 items-center rounded-xl px-3 text-sm font-medium text-ink-subtle hover:bg-surface-warm hover:text-ink sm:inline-flex"
              >
                내 프로젝트
              </Link>
              <form action={logoutAction} className="hidden sm:block">
                <button
                  type="submit"
                  className="inline-flex min-h-11 items-center rounded-xl px-3 text-sm font-medium text-ink-subtle hover:bg-surface-warm hover:text-ink"
                  aria-label={`${user.name || user.email} 계정에서 로그아웃`}
                >
                  로그아웃
                </button>
              </form>
            </>
          ) : (
            <Link href="/login" className="hidden min-h-11 items-center rounded-xl px-3 text-sm font-medium text-ink-subtle hover:bg-surface-warm hover:text-ink sm:inline-flex">
              로그인
            </Link>
          )}
          <Link href="/dashboard/quick-check" className={buttonClassName({ size: "sm" })}>
            스캔 시작하기 →
          </Link>
        </div>
      </div>
    </header>
  );
}
