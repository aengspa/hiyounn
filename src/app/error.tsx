"use client";

import { Button } from "@/components/ui";
import { FriendlyError } from "@/components/ui";
import { HoiScene } from "@/components/mascot/HoiScene";

export default function ErrorBoundary({
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const offline = typeof navigator !== "undefined" && !navigator.onLine;

  function goBack() {
    if (window.history.length > 1) window.history.back();
    else window.location.assign("/");
  }

  return (
    <main
      id="main-content"
      tabIndex={-1}
      aria-live="assertive"
      className="mx-auto flex min-h-screen max-w-4xl items-center px-4 py-10 outline-none sm:px-6"
    >
      <HoiScene
        headingLevel="h1"
        mood="concerned"
        className="w-full"
        title={offline ? "인터넷 연결을 확인해 주세요" : "호이가 페이지를 마치지 못했어요"}
        description={
          <FriendlyError
            title={offline ? "연결이 잠깐 끊겼어요" : "요청 중 문제가 생겼어요"}
            description={
              offline
                ? "Wi-Fi나 네트워크 연결을 확인한 뒤 다시 시도해 주세요. 입력하거나 저장한 상태는 화면을 떠나기 전에 확인해 주세요."
                : "기술 오류 내용은 화면에 표시하지 않았어요. 잠시 뒤 다시 시도하거나 이전 화면으로 돌아갈 수 있어요."
            }
            action={
              <div className="flex flex-col gap-2 sm:flex-row">
                <Button onClick={reset}>다시 시도하기</Button>
                <Button variant="secondary" onClick={goBack}>이전 화면으로 돌아가기</Button>
              </div>
            }
          />
        }
      />
    </main>
  );
}
