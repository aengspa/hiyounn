import Link from "next/link";
import { TopNav } from "@/components/TopNav";
import { HoiSpeech } from "@/components/mascot/HoiSpeech";
import { ServiceIntro } from "@/components/ServiceIntro";
import { Card, buttonClassName } from "@/components/ui";
import { ArrowRightIcon, ChatIcon, SearchIcon, ShieldIcon } from "@/components/icons";

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

// 가치 카드 아이콘 배경·글자색(장식)
const FEATURE_ICON_TONE = [
  "bg-sun-soft text-brand-900",
  "bg-primary-soft text-brand-900",
  "bg-success-soft text-success",
] as const;

export default async function LandingPage() {
  return (
    <>
      <TopNav />
      <main id="main-content">
        {/* 히어로: 1280×720, 375×667 첫 화면 안에 들어가도록 높이를 콘텐츠에 맞춘다(요구사항 5.1~5.6) */}
        <section className="relative overflow-hidden bg-gradient-to-b from-canvas-soft to-canvas px-4 py-10 text-center sm:px-6 sm:py-16">
          {/* 햇살 원 장식 */}
          <span
            aria-hidden="true"
            className="pointer-events-none absolute left-1/2 top-24 -z-10 h-[28rem] w-[28rem] -translate-x-1/2 rounded-full bg-sun-soft opacity-70 blur-2xl"
          />
          <div className="mx-auto max-w-3xl">
            <p className="inline-flex items-center gap-2 rounded-full border-2 border-brand-300 bg-surface px-4 py-1 text-sm font-bold text-brand-900 shadow-[0_3px_0_var(--border-strong)]">
              <span aria-hidden="true" className="h-2 w-2 rounded-full bg-crimson" />
              바이브 코더를 위한 보안 친구
            </p>
            <h1 className="mt-5 break-keep text-[2rem] font-extrabold leading-[1.25] tracking-tight text-ink sm:text-6xl sm:leading-[1.15]">
              내 서비스, 호이와 함께 <br />
              <span className="relative inline-block">
                <span className="relative z-10">튼튼하게</span>
                <span aria-hidden="true" className="absolute inset-x-0 bottom-1 -z-0 h-3 rounded-full bg-sun sm:h-4" />
              </span>{" "}
              만들어요
            </h1>
            <p className="mx-auto mt-4 max-w-xl break-keep text-lg leading-relaxed text-ink-subtle">
              호이가 약한 곳을 찾아 쉽게 설명해드리고, 직접 고친 뒤 잘 막혔는지 한 번 더 확인해요.
            </p>

            <HoiSpeech mood="welcome" size="lg" className="mt-6 justify-center">
              어려운 건 제가 쉽게 설명해 드릴게요!
            </HoiSpeech>

            <div className="mt-8 flex justify-center">
              <Link
                href="/dashboard"
                className={buttonClassName({ variant: "primary", size: "lg", className: "w-full sm:w-auto" })}
              >
                <ShieldIcon className="h-6 w-6" />
                내 프로젝트 점검하기
                <ArrowRightIcon className="h-5 w-5" />
              </Link>
            </div>
          </div>
        </section>

        {/* 가치 카드 3개(요구사항 5.9). 자동 점검의 한계 고지는 아래 서비스 소개의 유의사항에 있다. */}
        <section
          id="features"
          aria-labelledby="features-title"
          className="mx-auto max-w-5xl px-4 py-16 sm:px-6"
        >
          <h2
            id="features-title"
            className="text-center text-2xl font-extrabold tracking-tight text-ink sm:text-4xl"
          >
            호이가 이렇게 도와드려요
          </h2>
          <ul className="mt-10 grid gap-5 md:grid-cols-3">
            {FEATURES.map((feature, index) => (
              <li key={feature.title}>
                <Card variant="raised" className="h-full rounded-3xl p-6 sm:p-7">
                  <span
                    aria-hidden="true"
                    className={`mb-4 flex h-12 w-12 items-center justify-center rounded-2xl ${FEATURE_ICON_TONE[index]}`}
                  >
                    {index === 0 && <ChatIcon className="h-6 w-6" />}
                    {index === 1 && <SearchIcon className="h-6 w-6" />}
                    {index === 2 && <ShieldIcon className="h-6 w-6" />}
                  </span>
                  <h3 className="text-xl font-extrabold text-ink">{feature.title}</h3>
                  <p className="mt-2 break-keep leading-relaxed text-ink-subtle">{feature.body}</p>
                </Card>
              </li>
            ))}
          </ul>
        </section>

        {/* 서비스 소개: 점검이 어떤 순서로 진행되는지(7단계), 근거 기준, 결과 예시, 유의사항 */}
        <ServiceIntro startHref="/dashboard" />
      </main>

      <footer className="border-t-2 border-line bg-canvas-soft px-4 py-10 text-center text-sm text-ink-subtle">
        <p className="font-extrabold text-ink">
          코치코치 <span className="text-brand-800">호이</span>
        </p>
        <p className="mx-auto mt-2 max-w-xl break-keep leading-relaxed">
          본 서비스의 자동 점검 결과는 참고용 정보이며, 존재하는 모든 취약점과 보안 위험 탐지를 보장하지 않습니다. 본 서비스의 이용, 점검 결과에 따른 판단 및 조치, 그리고 배포로 인해 발생하는 결과에 대한 책임은 이용자에게 있습니다.
        </p>
        <p className="mt-2 text-[13px] text-ink-muted">호이 캐릭터에 관한 권리는 고려대학교에 귀속됩니다.</p>
      </footer>
    </>
  );
}
