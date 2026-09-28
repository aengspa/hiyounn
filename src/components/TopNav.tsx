import Link from "next/link";
import { getCurrentUser } from "@/lib/auth";
import { logoutAction } from "@/lib/authActions";
import { Hoi } from "@/components/mascot/Hoi";
import { buttonClassName } from "@/components/ui";

// 따뜻한 hover: 연주황 배경 위에서는 대비를 위해 글자를 text-ink로 바꾼다.
const navLink =
  "inline-flex min-h-11 items-center rounded-2xl px-3 text-sm font-semibold text-ink-subtle hover:bg-primary-soft hover:text-ink";

/**
 * 공개 헤더(설계 5-1). 왼쪽 로고(작은 호이 + 이름), 가운데 랜딩 섹션 앵커,
 * 오른쪽 로그인 여부에 따른 "내 프로젝트"/"로그인" secondary 링크.
 * 랜딩의 Primary 버튼은 히어로 1개뿐이므로 여기에는 Primary를 두지 않는다.
 * 640px 미만에서는 앵커와 로그아웃을 숨겨 320px에서도 가로 스크롤이 생기지 않게 한다.
 */
export async function TopNav() {
  const user = await getCurrentUser();

  return (
    <header className="sticky top-0 z-30 border-b border-line bg-[#fffaf2]/90 backdrop-blur">
      <div className="mx-auto flex w-full max-w-6xl items-center justify-between gap-3 px-4 py-2 sm:px-6 lg:px-8">
        <Link
          href="/"
          className="flex min-h-11 min-w-0 items-center gap-2 rounded-2xl font-bold text-ink"
          aria-label="호이 보안 코치 홈"
        >
          <Hoi mood="welcome" size="sm" decorative />
          <span className="truncate">호이 보안 코치</span>
        </Link>

        {/* 앵커는 로그인·회원가입 화면에서도 랜딩 섹션으로 가도록 "/" 기준으로 둔다. */}
        <nav aria-label="주요 메뉴" className="hidden items-center gap-1 sm:flex">
          <Link href="/#features" className={navLink}>기능 소개</Link>
          <Link href="/#how-it-works" className={navLink}>사용 방법</Link>
        </nav>

        <div className="flex shrink-0 items-center gap-2">
          {user ? (
            <>
              <form action={logoutAction} className="hidden sm:block">
                <button
                  type="submit"
                  className={navLink}
                  aria-label={`${user.name || user.email} 계정에서 로그아웃`}
                >
                  로그아웃
                </button>
              </form>
              <Link
                href="/dashboard"
                className={buttonClassName({ variant: "secondary", size: "sm", className: "whitespace-nowrap" })}
              >
                내 프로젝트
              </Link>
            </>
          ) : (
            <Link
              href="/login"
              className={buttonClassName({ variant: "secondary", size: "sm", className: "whitespace-nowrap" })}
            >
              로그인
            </Link>
          )}
        </div>
      </div>
    </header>
  );
}
