import { Hoi } from "@/components/mascot/Hoi";

/**
 * 최상위 로딩 화면 (요구사항 10.10).
 * `main` 랜드마크를 유지하고, 그 안의 `role="status"` 영역에서 호이와 안내 문구를 함께 알린다.
 * 퍼센트 진행률은 표시하지 않는다.
 */
export default function Loading() {
  return (
    <main
      id="main-content"
      tabIndex={-1}
      className="mx-auto flex min-h-screen max-w-4xl items-center px-4 py-10 outline-none sm:px-6"
    >
      <div
        role="status"
        aria-live="polite"
        className="hoi-decoration flex w-full flex-col items-center gap-5 rounded-3xl border border-line bg-surface-warm px-5 py-9 text-center shadow-warm sm:px-8"
      >
        <Hoi mood="searching" size="lg" />
        <p className="break-keep text-xl font-bold tracking-tight text-ink">
          호이가 화면을 준비하고 있어요…
        </p>
      </div>
    </main>
  );
}
