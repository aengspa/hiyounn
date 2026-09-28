import Link from "next/link";
import { TopNav } from "@/components/TopNav";
import { Card, buttonClassName } from "@/components/ui";

const STEPS = [
  {
    title: "코드 넣기",
    description: "확인할 코드를 붙여넣거나 프로젝트 파일을 준비하세요.",
  },
  {
    title: "결과 이해하기",
    description: "어떤 문제가 있고, 왜 중요한지 쉬운 말로 확인하세요.",
  },
  {
    title: "수정하고 다시 확인하기",
    description: "수정 방법을 확인하고, 고친 코드를 다시 점검하세요.",
  },
];

const FEATURES = [
  {
    title: "놓치기 쉬운 문제 찾기",
    body: "비밀키 노출이나 접근 권한 누락처럼 바이브 코딩에서 자주 놓치는 부분을 확인해요.",
  },
  {
    title: "쉬운 설명과 수정 방법",
    body: "전문 용어보다 실제로 어떤 영향이 있는지, 어디를 어떻게 고치면 되는지 먼저 알려드려요.",
  },
  {
    title: "확인한 범위와 근거 보기",
    body: "무엇을 점검했고 무엇은 점검하지 못했는지 함께 보여드려요. 근거도 언제든 확인할 수 있어요.",
  },
];

const SAMPLE_FINDINGS = [
  { title: "비밀키가 코드에 포함되어 있어요", tag: "우선 확인" },
  { title: "다른 사람의 정보를 볼 수 있는지 확인이 필요해요", tag: "확인 필요" },
  { title: "수정 방법을 확인할 수 있어요", tag: "안내" },
];

export default async function LandingPage() {
  return (
    <>
      <TopNav />
      <main id="main-content">
        {/* 히어로 */}
        <section className="mx-auto max-w-3xl px-4 py-16 text-center sm:px-6 sm:py-24">
          <p className="text-sm font-semibold text-brand-600">
            비전공자를 위한 코드 보안 점검
          </p>
          <h1 className="mt-4 break-keep text-3xl font-bold leading-[1.3] tracking-tight text-ink sm:text-5xl">
            마음껏 만들고,
            <br />
            보안은 쉽게 확인하세요.
          </h1>
          <p className="mx-auto mt-5 max-w-xl break-keep text-base leading-relaxed text-ink-subtle sm:text-lg">
            AI로 만든 코드에서 놓치기 쉬운 보안 문제를 찾아드려요.
            <br />
            어디를 왜 고쳐야 하는지 쉬운 말로 확인하세요.
          </p>
          <div className="mt-8 flex justify-center">
            <Link href="/dashboard/quick-check" className={buttonClassName({ size: "lg" })}>
              스캔 시작하기 →
            </Link>
          </div>
          <p className="mt-3 text-sm text-ink-muted">
            코드를 붙여넣어 바로 시작할 수 있어요.
          </p>
        </section>

        {/* 결과 예시 */}
        <section id="sample-result" className="mx-auto max-w-3xl px-4 pb-16 sm:px-6">
          <p className="text-center text-xs font-semibold uppercase tracking-wide text-ink-muted">
            결과 예시 · 실제 점검 결과가 아니에요
          </p>
          <Card variant="default" className="mt-4 divide-y divide-line p-0">
            {SAMPLE_FINDINGS.map((item) => (
              <div key={item.title} className="flex items-center justify-between gap-4 px-5 py-4">
                <p className="text-sm font-medium text-ink sm:text-base">{item.title}</p>
                <span className="shrink-0 rounded-full border border-line bg-surface-warm px-3 py-1 text-xs font-semibold text-ink-subtle">
                  {item.tag}
                </span>
              </div>
            ))}
          </Card>
        </section>

        {/* 사용 방법: 세 단계 */}
        <section id="how-it-works" className="border-t border-line bg-surface-warm px-4 py-16 sm:px-6">
          <div className="mx-auto max-w-5xl">
            <h2 className="text-center text-2xl font-bold tracking-tight text-ink sm:text-3xl">
              세 단계로 확인해요
            </h2>
            <ol className="mt-10 grid gap-5 sm:grid-cols-3">
              {STEPS.map((step, index) => (
                <li key={step.title}>
                  <Card variant="default" className="h-full p-6">
                    <span className="flex h-8 w-8 items-center justify-center rounded-full bg-primary-soft text-sm font-bold text-brand-700">
                      {index + 1}
                    </span>
                    <h3 className="mt-4 text-lg font-bold text-ink">{step.title}</h3>
                    <p className="mt-2 break-keep text-sm leading-relaxed text-ink-subtle">
                      {step.description}
                    </p>
                  </Card>
                </li>
              ))}
            </ol>
          </div>
        </section>

        {/* 핵심 기능 */}
        <section id="features" className="mx-auto max-w-5xl px-4 py-16 sm:px-6">
          <h2 className="text-center text-2xl font-bold tracking-tight text-ink sm:text-3xl">
            무엇을 도와드릴까요?
          </h2>
          <div className="mt-10 grid gap-5 md:grid-cols-3">
            {FEATURES.map((feature) => (
              <Card key={feature.title} variant="default" className="p-6">
                <h3 className="text-lg font-bold text-ink">{feature.title}</h3>
                <p className="mt-2 break-keep leading-relaxed text-ink-subtle">{feature.body}</p>
              </Card>
            ))}
          </div>
        </section>

        {/* 하단 안내 */}
        <section className="mx-auto max-w-3xl px-4 pb-20 sm:px-6">
          <div className="flex justify-center">
            <Link href="/dashboard/quick-check" className={buttonClassName({ size: "lg" })}>
              스캔 시작하기 →
            </Link>
          </div>
        </section>
      </main>

      <footer className="border-t border-line px-4 py-8 text-center text-sm text-ink-muted">
        자동 점검은 입력한 자료와 지원하는 검사 범위 안에서 이루어져요.
      </footer>
    </>
  );
}
