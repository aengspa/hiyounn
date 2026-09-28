import Link from "next/link";
import { HoiScene } from "@/components/mascot/HoiScene";
import { buttonClassName } from "@/components/ui";

export default function NotFound() {
  return (
    <main
      id="main-content"
      tabIndex={-1}
      className="mx-auto flex min-h-screen max-w-4xl items-center px-4 py-10 outline-none sm:px-6"
    >
      <HoiScene
        headingLevel="h1"
        mood="thinking"
        className="w-full"
        title="호이가 이 페이지를 찾지 못했어요"
        description="주소가 바뀌었거나 페이지가 이동했을 수 있어요. 아래에서 다시 출발해 주세요."
        action={
          <>
            <Link href="/" className={buttonClassName({ variant: "secondary" })}>
              처음으로 돌아가기
            </Link>
            <Link href="/dashboard" className={buttonClassName()}>
              내 프로젝트 보기
            </Link>
          </>
        }
      />
    </main>
  );
}
