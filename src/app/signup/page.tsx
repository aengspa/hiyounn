import Link from "next/link";
import { redirect } from "next/navigation";
import { TopNav } from "@/components/TopNav";
import { HoiSpeech } from "@/components/mascot/HoiSpeech";
import { AuthForm } from "@/components/AuthForm";
import { Card } from "@/components/ui";
import { signupAction } from "@/lib/authActions";
import { isAuthenticated, safeNextPath } from "@/lib/auth";

export const metadata = { title: "회원가입" };

export default async function SignupPage({
  searchParams,
}: {
  searchParams?: { next?: string };
}) {
  const next = safeNextPath(searchParams?.next) ?? undefined;
  if (await isAuthenticated()) redirect(next ?? "/dashboard");

  return (
    <>
      <TopNav />
      <main id="main-content" className="mx-auto grid min-h-[calc(100vh-5rem)] max-w-6xl items-center gap-8 px-4 py-10 sm:px-6 lg:grid-cols-[0.85fr_1.15fr] lg:px-8 lg:py-16">
        <div className="mx-auto w-full max-w-md lg:order-2">
          <p className="inline-flex rounded-full border-2 border-brand-300 bg-surface px-3 py-0.5 text-sm font-bold text-brand-900">첫 걸음을 함께해요</p>
          <h1 className="mt-2 break-keep text-3xl font-extrabold tracking-tight text-ink sm:text-[2.6rem] sm:leading-tight">
            호이와 첫 점검을 시작해요
          </h1>
          <p className="mt-3 text-lg text-ink-subtle">
            계정을 만들고 프로젝트의 약한 곳부터 하나씩 살펴봐요.
          </p>
          <Card variant="raised" className="mt-7 p-5 sm:p-8">
            <AuthForm mode="signup" action={signupAction} next={next} />
          </Card>
          <Link
            href="/"
            className="mt-5 inline-flex min-h-11 items-center gap-1 rounded-full border-2 border-line bg-surface px-3 text-sm font-bold text-brand-800 hover:border-brand-300"
          >
            <span aria-hidden="true">←</span>&nbsp;홈으로
          </Link>
        </div>

        <div className="mx-auto w-full max-w-lg lg:order-1">
          <HoiSpeech mood="guide" size="lg" className="items-center">
            어려운 보안 용어는 제가 풀어드릴게요. 프로젝트만 소개해 주세요!
          </HoiSpeech>
          <Card variant="warm" className="mt-6 border-dashed p-5 text-sm leading-relaxed text-ink-subtle sm:ml-16">
            비밀번호는 8자 이상으로 만들어 주세요. 가입 뒤에는 바로 내 프로젝트
            화면으로 안내해 드려요.
          </Card>
        </div>
      </main>
    </>
  );
}
