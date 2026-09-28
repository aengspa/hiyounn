import { HoiScene } from "@/components/mascot/HoiScene";

export default function DashboardLoading() {
  return (
    <div
      role="status"
      aria-live="polite"
      aria-busy="true"
      className="mx-auto max-w-4xl px-4 py-10 sm:px-6"
    >
      <HoiScene
        headingLevel="h1"
        mood="searching"
        title="호이가 필요한 내용을 불러오고 있어요"
        description="확인한 내용만 보여드릴 수 있도록 잠시 정리하고 있어요."
      />
    </div>
  );
}
