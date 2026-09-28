"use client";

import { useEffect } from "react";
import Link from "next/link";
import { HoiScene } from "@/components/mascot/HoiScene";
import { Button, buttonClassName } from "@/components/ui";

/**
 * 대시보드 영역 렌더링 오류 화면 (요구사항 10.7, 10.8).
 * 대시보드 레이아웃이 `#main-content` 영역을 이미 제공하므로 id를 다시 쓰지 않는다.
 * 오류 원문·digest·스택은 화면과 스크린리더 텍스트 어디에도 넣지 않고 콘솔에만 남긴다.
 */
export default function DashboardError({
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
    <div className="mx-auto max-w-4xl px-4 py-10 sm:px-6">
      <div role="alert">
        <HoiScene
          headingLevel="h1"
          mood="concerned"
          title="잠시 문제가 생겼어요"
          description="호이가 이 화면을 준비하다가 멈췄어요. 잠시 뒤 다시 시도하거나 내 프로젝트 목록으로 돌아갈 수 있어요."
          action={
            <>
              <Button onClick={() => reset()}>다시 시도하기</Button>
              <Link href="/dashboard" className={buttonClassName({ variant: "secondary" })}>
                내 프로젝트로 돌아가기
              </Link>
            </>
          }
        />
      </div>
    </div>
  );
}
