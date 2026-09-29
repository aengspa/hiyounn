import Link from "next/link";
import { getCurrentUser } from "@/lib/auth";
import { logoutAction } from "@/lib/authActions";
import { Hoi } from "@/components/mascot/Hoi";
import { buttonClassName } from "@/components/ui";

// 따뜻한 hover: 연주황 배경 위에서는 대비를 위해 글자를 text-ink로 바꾼다.
const navLink =
  "inline-flex min-h-11 items-center rounded-2xl px-3 text-sm font-semibold text-ink-subtle hover:bg-primary-soft hover:text-ink";

/**
 * 공통 헤더(랜딩·대시보드). 화면 전체 폭을 쓰는 3칸 격자다.
 * 왼쪽 끝: 호이 이미지 + "코치코치 호이" 전체가 홈("/") 링크. 가운데: 사용 방법 → 기능 소개.
 * 오른쪽 끝: 계정 버튼(로그인 또는 로그아웃·내 프로젝트).
 * 640px 미만에서는 앵커를 숨겨 320px에서도 가로 스크롤이 생기지 않게 한다.
 */
export async function TopNav() {
  const user = await getCurrentUser();

  return (
    <header className="sticky top-0 z-30 h-[65px] border-b-2 border-line bg-[#fffaf2]/90 backdrop-blur">
      {/* 화면 전체 폭을 쓴다: 홈은 왼쪽 끝, 계정 버튼은 오른쪽 끝, 메뉴는 가운데. */}
      <div className="grid h-full w-full grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-center gap-3 px-4 sm:px-6">
        <Link
          href="/"
          className="flex min-h-11 min-w-0 items-center gap-2 justify-self-start rounded-2xl pr-2 text-lg font-extrabold tracking-tight text-ink"
          aria-label="코치코치 호이 홈"
        >
          <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-sun-soft">
            <Hoi mood="welcome" size="sm" decorative />
          </span>
          <span className="truncate">
            코치코치 <span className="text-brand-800">호이</span>
          </span>
        </Link>

        {/* 앵커는 로그인·회원가입 화면에서도 랜딩 섹션으로 가도록 "/" 기준으로 둔다. */}
        <nav aria-label="주요 메뉴" className="hidden items-center gap-1 sm:flex">

        </nav>

        <div className="col-start-3 flex shrink-0 items-center gap-2 justify-self-end">
          {user ? (
            <>
              <form action={logoutAction}>
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
