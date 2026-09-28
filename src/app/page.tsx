import Link from "next/link";
import { TopNav } from "@/components/TopNav";
import { HoiSpeech } from "@/components/mascot/HoiSpeech";
import { Card, buttonClassName } from "@/components/ui";

const WORKFLOW = [
  { title: "찾아봐요", description: "코드와 설정에서 살펴볼 곳 찾기" },
  { title: "영향을 확인해요", description: "내 서비스에 어떤 영향이 있는지 읽기" },
  { title: "수정안을 만들어요", description: "이해하기 쉬운 수정 방법 받기" },
  { title: "변경을 검토해요", description: "영향과 되돌림 방법을 직접 확인하기" },
  { title: "고친 뒤 다시 봐요", description: "같은 문제와 기본 기능을 함께 확인하기" },
  { title: "결과를 정리해요", description: "확인한 범위와 남은 일을 살펴보기" },
];

const VALUES = [
  {
    number: "01",
    title: "쉬운 말로 알려드려요",
    body: "어려운 용어보다 내 서비스와 사용자에게 어떤 영향이 있는지 먼저 설명해 드려요.",
  },
  {
    number: "02",
    title: "근거를 함께 보여드려요",
    body: "어디에서 무엇을 확인했는지 살펴볼 수 있도록 코드와 검사 근거를 함께 남겨요.",
  },
  {
    number: "03",
    title: "고친 뒤 한 번 더 확인해요",
    body: "같은 문제가 막혔는지와 확인한 정상 기능이 그대로 동작하는지 다시 살펴봐요.",
  },
];

export default async function LandingPage() {
  return (
    <>
      <TopNav />
      <main id="main-content" className="overflow-hidden">
        <section className="hoi-decoration mx-auto grid max-w-7xl gap-10 px-4 py-14 sm:px-6 sm:py-20 lg:grid-cols-[1.15fr_0.85fr] lg:items-center lg:px-8 lg:py-24">
          <div className="relative z-10 min-w-0">
            <p className="text-sm font-extrabold tracking-wide text-brand-700">
              바이브 코더를 위한 보안 친구
            </p>
            <h1 className="mt-3 max-w-3xl break-keep text-4xl font-black leading-tight tracking-tight text-ink sm:text-5xl lg:text-6xl">
              내 서비스, 호이와 함께 튼튼하게 만들어요
            </h1>
            <p className="mt-6 max-w-2xl break-keep text-lg leading-relaxed text-ink-subtle sm:text-xl">
              호이가 코드의 약한 곳을 찾아 쉬운 말로 알려드리고, 고친 뒤 같은 문제가
              잘 막혔는지 한 번 더 확인해요.
            </p>
            <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:items-center">
              <Link
                href="/dashboard/new"
                className={buttonClassName({ size: "lg", className: "w-full sm:w-auto" })}
              >
                내 프로젝트 점검하기
              </Link>
              <Link
                href="/dashboard/quick-check"
                className={buttonClassName({
                  variant: "secondary",
                  size: "lg",
                  className: "w-full sm:w-auto",
                })}
              >
                코드만 빠르게 확인하기
              </Link>
            </div>
            <p className="mt-4 text-sm font-bold text-ink-muted">
              어려운 보안 용어는 쉽게 풀어드려요.
            </p>
          </div>

          <div className="relative z-10 mx-auto w-full max-w-xl">
            <HoiSpeech mood="welcome" size="lg" className="items-center">
              어려운 건 제가 쉽게 설명해 드릴게요!
            </HoiSpeech>
            <Card variant="warm" className="mt-5 p-5 sm:ml-16 sm:p-6">
              <p className="font-extrabold text-ink">고쳤다면 끝! …이 아니라</p>
              <p className="mt-1 text-sm leading-relaxed text-ink-subtle sm:text-base">
                정말 잘 막혔는지 호이가 한 번 더 확인해요. 확인한 범위와 자동 점검의
                한계도 숨기지 않고 함께 알려드릴게요.
              </p>
            </Card>
          </div>
        </section>

        <section aria-labelledby="workflow-title" className="mx-auto max-w-7xl px-4 py-14 sm:px-6 lg:px-8">
          <div className="text-center">
            <p className="text-sm font-extrabold text-brand-700">호이와 걷는 점검 길</p>
            <h2 id="workflow-title" className="mt-2 text-3xl font-black tracking-tight text-ink sm:text-4xl">
              한 번에 하나씩, 여섯 걸음으로 확인해요
            </h2>
          </div>
          <ol className="mt-9 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {WORKFLOW.map((step, index) => (
              <li key={step.title} className="relative min-w-0">
                <Card variant="raised" className="h-full p-5">
                  <div className="flex items-start gap-3 lg:block">
                    <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-primary-soft text-sm font-black text-brand-900">
                      {index + 1}
                    </span>
                    <div className="min-w-0 lg:mt-4">
                      <h3 className="text-lg font-black text-ink">{step.title}</h3>
                      <p className="mt-1 break-keep text-sm leading-relaxed text-ink-subtle">
                        {step.description}
                      </p>
                    </div>
                  </div>
                </Card>
              </li>
            ))}
          </ol>
        </section>

        <section aria-labelledby="value-title" className="mx-auto max-w-7xl px-4 py-14 sm:px-6 lg:px-8">
          <h2 id="value-title" className="text-center text-3xl font-black tracking-tight text-ink sm:text-4xl">
            결과는 친절하게, 근거는 분명하게
          </h2>
          <div className="mt-9 grid gap-5 md:grid-cols-3">
            {VALUES.map((value) => (
              <Card key={value.title} variant="raised" className="p-6">
                <span className="text-sm font-black text-brand-700">{value.number}</span>
                <h3 className="mt-3 text-xl font-black text-ink">{value.title}</h3>
                <p className="mt-2 break-keep leading-relaxed text-ink-subtle">{value.body}</p>
              </Card>
            ))}
          </div>
        </section>

        <section className="mx-auto max-w-5xl px-4 pb-20 pt-8 sm:px-6">
          <Card variant="warm" className="p-6 text-center sm:p-8">
            <h2 className="text-xl font-black text-ink">자동 점검이 볼 수 있는 범위가 있어요</h2>
            <p className="mx-auto mt-2 max-w-3xl break-keep leading-relaxed text-ink-subtle">
              호이가 열심히 살펴보지만 자동 점검만으로 모든 위험을 찾을 수는 없어요.
              중요한 서비스는 보안 전문가의 검토도 함께 받아보세요.
            </p>
          </Card>
        </section>
      </main>

      <footer className="border-t border-line bg-white/70 px-4 py-8 text-center text-sm text-ink-muted">
        확인한 시점과 범위 안의 결과를 솔직하게 안내해 드려요.
      </footer>
    </>
  );
}
