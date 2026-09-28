"use client";

import { HoiScene } from "@/components/mascot/HoiScene";
import { Button, FriendlyError } from "@/components/ui";

export default function DashboardError({
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const offline = typeof navigator !== "undefined" && !navigator.onLine;

  function goBack() {
    if (window.history.length > 1) window.history.back();
    else window.location.assign("/dashboard");
  }

  return (
    <div aria-live="assertive" className="mx-auto max-w-4xl px-4 py-10 sm:px-6">
      <HoiScene
        headingLevel="h1"
        mood="concerned"
        title={offline ? "연결이 잠깐 끊겼어요" : "이 화면을 마치지 못했어요"}
        description={
          <FriendlyError
            title={offline ? "인터넷 연결을 확인해 주세요" : "호이가 요청 중 멈췄어요"}
            description={
              offline
                ? "네트워크를 다시 연결한 뒤 같은 작업을 시도해 주세요."
                : "상세 오류나 기술 정보는 화면에 표시하지 않았어요. 잠시 뒤 다시 시도해 주세요."
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
    </div>
  );
}
