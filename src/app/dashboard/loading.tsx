import { Hoi } from "@/components/mascot/Hoi";

/**
 * 대시보드 영역 로딩 화면 (요구사항 10.10).
 * 대시보드 레이아웃이 `#main-content` 영역을 이미 제공하므로 id를 다시 쓰지 않는다.
 * 퍼센트 진행률은 표시하지 않는다.
 */
export default function DashboardLoading() {
  return (
    <div className="mx-auto max-w-4xl px-4 py-10 sm:px-6">
      <div
        role="status"
        aria-live="polite"
        className="hoi-decoration flex flex-col items-center gap-5 rounded-3xl border border-line bg-surface-warm px-5 py-9 text-center shadow-warm sm:px-8"
      >
        <Hoi mood="searching" size="lg" />
        <p className="break-keep text-xl font-bold tracking-tight text-ink">
          호이가 화면을 준비하고 있어요…
        </p>
      </div>
    </div>
  );
}
