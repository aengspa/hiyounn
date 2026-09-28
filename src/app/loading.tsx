import { HoiScene } from "@/components/mascot/HoiScene";

export default function Loading() {
  return (
    <main
      id="main-content"
      tabIndex={-1}
      role="status"
      aria-live="polite"
      aria-busy="true"
      className="mx-auto flex min-h-screen max-w-4xl items-center px-4 py-10 outline-none sm:px-6"
    >
      <HoiScene
        headingLevel="h1"
        mood="searching"
        className="w-full"
        title="호이가 페이지를 준비하고 있어요"
        description="필요한 내용을 불러오는 동안 잠시만 기다려 주세요."
      />
    </main>
  );
}
