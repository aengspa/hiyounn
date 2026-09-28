"use client";

import { useEffect } from "react";
import Link from "next/link";
import { HoiScene } from "@/components/mascot/HoiScene";
import { Button, buttonClassName } from "@/components/ui";

/**
 * 최상위 렌더링 오류 화면 (요구사항 10.7, 10.8).
 * 오류 원문·digest·스택은 화면과 스크린리더 텍스트 어디에도 넣지 않고 콘솔에만 남긴다.
 */
export default function ErrorBoundary({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <main
      id="main-content"
      tabIndex={-1}
      className="mx-auto flex min-h-screen max-w-4xl items-center px-4 py-10 outline-none sm:px-6"
    >
      <div role="alert" className="w-full">
        <HoiScene
          headingLevel="h1"
          mood="concerned"
          className="w-full"
          title="잠시 문제가 생겼어요"
          description="호이가 이 화면을 보여드리는 중에 멈췄어요. 인터넷 연결을 확인한 뒤 다시 시도해 주세요."
          action={
            <>
              <Button onClick={() => reset()}>다시 시도하기</Button>
              <Link href="/" className={buttonClassName({ variant: "secondary" })}>
                처음으로 돌아가기
              </Link>
            </>
          }
        />
      </div>
    </main>
  );
}
