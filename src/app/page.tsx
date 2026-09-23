import Link from "next/link";
import { TopNav, ShieldIcon } from "@/components/TopNav";

const WORKFLOW = ["스캔", "공격 재현", "수정", "재검증", "확인"];

export default function LandingPage() {
  return (
    <>
      <TopNav />
      <main className="mx-auto max-w-6xl px-6">
        {/* Hero */}
        <section className="py-20 text-center">
          <div className="mx-auto mb-6 flex h-14 w-14 items-center justify-center rounded-2xl bg-brand-50">
            <ShieldIcon className="h-8 w-8 text-brand-600" />
          </div>
          <h1 className="mx-auto max-w-3xl text-5xl font-bold tracking-tight text-slate-900">
            수정했다고 믿지 마세요. 검증하세요.
          </h1>
          <p className="mx-auto mt-6 max-w-2xl text-lg text-slate-600">
            취약점을 찾고, 수정하고, 실제로 같은 공격을 다시 재현해 막혔는지, 그리고
            앱의 정상 기능이 여전히 잘 동작하는지까지 검증하는 독립형 보안
            에이전트입니다.
          </p>
          <div className="mt-8 flex items-center justify-center gap-3">
            <Link
              href="/dashboard"
              className="rounded-lg bg-brand-600 px-5 py-3 font-medium text-white hover:bg-brand-700"
            >
              대시보드 열기
            </Link>
            <Link
              href="/dashboard/new"
              className="rounded-lg border border-slate-300 px-5 py-3 font-medium text-slate-700 hover:bg-slate-50"
            >
              프로젝트 추가
            </Link>
          </div>
        </section>

        {/* Workflow */}
        <section className="pb-16">
          <div className="flex flex-wrap items-center justify-center gap-3">
            {WORKFLOW.map((step, i) => (
              <div key={step} className="flex items-center gap-3">
                <div className="rounded-full border border-brand-200 bg-brand-50 px-5 py-2 font-medium text-brand-700">
                  {step}
                </div>
                {i < WORKFLOW.length - 1 && (
                  <span className="text-slate-400">&rarr;</span>
                )}
              </div>
            ))}
          </div>
        </section>

        {/* Value props */}
        <section className="grid gap-6 pb-20 md:grid-cols-3">
          <Feature
            title="추측이 아니라 근거"
            body="모든 발견은 실제 근거로 뒷받침됩니다. 정확한 코드, HTTP 요청과 응답, 그리고 재현된 공격까지 — AI의 짐작이 아닙니다."
          />
          <Feature
            title="검증되기 전엔 끝난 게 아닙니다"
            body="수정 후 똑같은 공격을 다시 실행합니다. 공격이 막히고 정상 기능도 그대로 동작할 때에만 '검증 완료'로 표시합니다."
          />
          <Feature
            title="쉬운 말로 설명"
            body="전문 용어(CWE, OWASP)를 보여주기 전에, 당신과 사용자에게 실제로 어떤 피해가 생길 수 있는지 먼저 설명합니다."
          />
        </section>

        <section className="mb-24 rounded-2xl border border-slate-200 bg-white p-10 text-center shadow-sm">
          <p className="mx-auto max-w-2xl text-xl font-medium text-slate-800">
            AI로 서비스를 만들 수 있지만, 보안 전문가처럼 코드를 검토하긴 어려운
            개발자를 위해 만들었습니다.
          </p>
        </section>
      </main>

      <footer className="border-t border-slate-200 py-8 text-center text-sm text-slate-500">
        자동 보안 점검은 모든 취약점을 찾아내지 못합니다.
      </footer>
    </>
  );
}

function Feature({ title, body }: { title: string; body: string }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <h3 className="text-lg font-semibold text-slate-900">{title}</h3>
      <p className="mt-2 text-slate-600">{body}</p>
    </div>
  );
}
