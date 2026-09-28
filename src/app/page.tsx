import Link from "next/link";
import { TopNav } from "@/components/TopNav";
import { HoiSpeech } from "@/components/mascot/HoiSpeech";
import { Card, buttonClassName } from "@/components/ui";
import { LIMIT_NOTICE } from "@/lib/ui/presentation";

// 5단계 흐름(요구사항 5.8). 순서가 곧 의미이므로 바꾸지 않는다.
const STEPS = [
  { title: "찾아봐요", description: "호이가 코드와 설정을 차근차근 살펴봐요." },
  { title: "확인해요", description: "찾은 내용이 실제로 문제가 되는지 확인해요." },
  { title: "고쳐봐요", description: "이해하기 쉬운 수정 방법을 알려드려요." },
  { title: "다시 봐요", description: "고친 뒤 같은 문제가 막혔는지 다시 봐요." },
  { title: "튼튼해졌어요", description: "기존 기능이 잘 동작하는지까지 보고 마무리해요." },
] as const;

// 가치 카드 3개(요구사항 5.9). 순서 고정.
const FEATURES = [
  {
    title: "쉬운 말로 알려드려요",
    body: "어려운 보안 용어 대신, 어떤 일이 생길 수 있고 어디를 고치면 되는지 먼저 알려드려요.",
  },
  {
    title: "근거를 함께 보여드려요",
    body: "호이가 무엇을 보고 그렇게 판단했는지, 어느 파일의 몇 번째 줄인지 함께 보여드려요.",
  },
  {
    title: "고친 뒤 한 번 더 확인해요",
    body: "고쳤다면 끝이 아니라, 정말 잘 막혔는지 호이가 같은 방식으로 한 번 더 살펴봐요.",
  },
] as const;

export default async function LandingPage() {
  return (
    <>
      <TopNav />
      <main id="main-content">
        {/* 히어로: 1280×720, 375×667 첫 화면 안에 들어가도록 높이를 콘텐츠에 맞춘다(요구사항 5.1~5.6) */}
        <section className="bg-gradient-to-b from-canvas-soft to-canvas px-4 py-10 text-center sm:px-6 sm:py-14">
          <div className="mx-auto max-w-3xl">
            <p className="text-sm font-bold text-brand-800">바이브 코더를 위한 보안 친구</p>
            <h1 className="mt-2 break-keep text-[1.75rem] font-bold leading-[1.3] tracking-tight text-ink sm:text-5xl sm:leading-tight">
              내 서비스, 호이와 함께 튼튼하게 만들어요
            </h1>
            <p className="mx-auto mt-3 max-w-xl break-keep text-base leading-relaxed text-ink-subtle">
              호이가 약한 곳을 찾아 쉬운 말로 알려드리고, 고친 뒤 한 번 더 확인해요.
            </p>

            <HoiSpeech mood="welcome" size="lg" className="mt-4 justify-center">
              어려운 건 제가 쉽게 설명해 드릴게요!
            </HoiSpeech>

            <div className="mt-5 flex justify-center">
              <Link
                href="/dashboard"
                className={buttonClassName({ variant: "primary", size: "lg", className: "w-full sm:w-auto" })}
              >
                내 프로젝트 점검하기
              </Link>
            </div>
          </div>
        </section>

        {/* 5단계 흐름: 1024px 이상 가로, 그 미만 세로 타임라인(요구사항 5.8) */}
        <section
          id="how-it-works"
          aria-labelledby="how-it-works-title"
          className="border-t border-line bg-surface-warm px-4 py-14 sm:px-6"
        >
          <div className="mx-auto max-w-5xl">
            <h2
              id="how-it-works-title"
              className="text-center text-2xl font-bold tracking-tight text-ink sm:text-3xl"
            >
              호이와 함께 이렇게 진행해요
            </h2>
            <ol className="mx-auto mt-10 grid max-w-md gap-6 lg:max-w-none lg:grid-cols-5 lg:gap-4">
              {STEPS.map((step, index) => {
                const isLast = index === STEPS.length - 1;
                return (
                  <li
                    key={step.title}
                    className="relative flex gap-4 lg:flex-col lg:items-center lg:text-center"
                  >
                    {!isLast && (
                      <>
                        {/* 세로 타임라인 선(1024px 미만) */}
                        <span
                          aria-hidden="true"
                          className="absolute -bottom-6 left-5 top-10 w-0.5 -translate-x-1/2 bg-line-strong lg:hidden"
                        />
                        {/* 가로 연결선(1024px 이상): 다음 번호 원까지 잇는다 */}
                        <span
                          aria-hidden="true"
                          className="absolute left-[calc(50%+1.75rem)] right-[calc(-50%+0.75rem)] top-5 hidden h-0.5 bg-line-strong lg:block"
                        />
                      </>
                    )}
                    <span
                      aria-hidden="true"
                      className="relative z-10 flex h-10 w-10 shrink-0 items-center justify-center rounded-full border-2 border-brand-300 bg-surface text-base font-bold text-brand-800"
                    >
                      {index + 1}
                    </span>
                    <div className="min-w-0 pb-1 lg:mt-3">
                      <h3 className="text-lg font-bold text-ink">{step.title}</h3>
                      <p className="mt-1 break-keep text-sm leading-relaxed text-ink-subtle">
                        {step.description}
                      </p>
                    </div>
                  </li>
                );
              })}
            </ol>
          </div>
        </section>

        {/* 가치 카드 3개 + 한계 고지(요구사항 5.9, 5.10) */}
        <section
          id="features"
          aria-labelledby="features-title"
          className="mx-auto max-w-5xl px-4 py-14 sm:px-6"
        >
          <h2
            id="features-title"
            className="text-center text-2xl font-bold tracking-tight text-ink sm:text-3xl"
          >
            호이가 이렇게 도와드려요
          </h2>
          <ul className="mt-10 grid gap-5 md:grid-cols-3">
            {FEATURES.map((feature) => (
              <li key={feature.title}>
                <Card variant="raised" className="h-full rounded-3xl p-6">
                  <h3 className="text-lg font-bold text-ink">{feature.title}</h3>
                  <p className="mt-2 break-keep leading-relaxed text-ink-subtle">{feature.body}</p>
                </Card>
              </li>
            ))}
          </ul>
          <p className="mx-auto mt-8 max-w-2xl break-keep rounded-2xl border border-line bg-surface-warm px-5 py-4 text-center text-sm leading-relaxed text-ink-subtle">
            {LIMIT_NOTICE}
          </p>
        </section>
      </main>

      <footer className="border-t border-line bg-canvas-soft px-4 py-8 text-center text-sm text-ink-subtle">
        <p className="font-bold text-ink">호이 보안 코치</p>
        <p className="mt-1">자동 점검은 입력한 자료와 지원하는 검사 범위 안에서 이루어져요.</p>
      </footer>
    </>
  );
}
