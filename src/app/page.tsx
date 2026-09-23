import Link from "next/link";
import { TopNav } from "@/components/TopNav";
import { ShieldIcon } from "@/components/icons";
import { FeatureCards } from "@/components/FeatureCards";

const WORKFLOW = ["스캔", "공격 재현", "보고서", "수정", "재검증"];

export default function LandingPage() {
  return (
    <>
      <TopNav />
      <main className="mx-auto max-w-6xl px-6">
        {/* Hero */}
        <section className="pt-28 pb-20 text-left">
          <div className="mb-6 flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-100">
            <ShieldIcon className="h-8 w-8 text-slate-700" />
          </div>
          <h1 className="max-w-3xl text-5xl font-bold leading-tight tracking-tight text-slate-900">
            바이브 코딩 에이전트
            <br />
            사용하기
          </h1>
          <p className="mt-6 max-w-2xl text-lg text-slate-600">
            취약점을 찾고, 수정하고, 실제로 같은 공격을 다시 재현해 막혔는지, 그리고
            앱의 정상 기능이 여전히 잘 동작하는지까지 검증하는 독립형 보안
            에이전트입니다.
          </p>
          <p className="mt-2 max-w-2xl text-sm text-slate-400">
            AI로 서비스를 만들 수 있지만, 보안 전문가처럼 코드를 검토하긴 어려운
            개발자를 위해 만들었습니다.
          </p>
          <div className="mt-10 flex items-center gap-4">
            <Link
              href="/dashboard/new"
              className="rounded-lg border border-slate-800 bg-slate-800 px-8 py-3 text-base font-semibold text-white shadow-sm hover:bg-slate-900"
            >
              새 프로젝트
            </Link>
            <Link
              href="/dashboard"
              className="rounded-lg border border-slate-300 bg-slate-100 px-8 py-3 text-base font-semibold text-slate-700 shadow-sm hover:bg-slate-200"
            >
              대시보드 열기
            </Link>
          </div>
        </section>

        {/* Value props */}
        <FeatureCards />

        {/* Workflow (5 steps) — moved to the bottom, calmer palette */}
        <section className="pb-24">
          <div className="flex flex-wrap items-center justify-center gap-3">
            {WORKFLOW.map((step, i) => (
              <div key={step} className="flex items-center gap-3">
                <div className="rounded-full border border-slate-200 bg-slate-100 px-5 py-2 font-medium text-slate-600">
                  {step}
                </div>
                {i < WORKFLOW.length - 1 && (
                  <span className="text-slate-300">&rarr;</span>
                )}
              </div>
            ))}
          </div>
        </section>
      </main>

      <footer className="border-t border-slate-200 py-8 text-center text-sm text-slate-500">
        자동 보안 점검은 모든 취약점을 찾아내지 못합니다.
      </footer>
    </>
  );
}
