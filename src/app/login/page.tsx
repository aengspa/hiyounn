import Link from "next/link";
import { redirect } from "next/navigation";
import { TopNav } from "@/components/TopNav";
import { HoiSpeech } from "@/components/mascot/HoiSpeech";
import { AuthForm } from "@/components/AuthForm";
import { Card } from "@/components/ui";
import { loginAction } from "@/lib/authActions";
import { isAuthenticated, safeNextPath } from "@/lib/auth";

export const metadata = { title: "로그인" };

export default async function LoginPage({
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
          <p className="inline-flex rounded-full border-2 border-brand-300 bg-surface px-3 py-0.5 text-sm font-bold text-brand-900">다시 이어서 살펴봐요</p>
          <h1 className="mt-2 break-keep text-3xl font-extrabold tracking-tight text-ink sm:text-[2.6rem] sm:leading-tight">
            다시 만나서 반가워요!
          </h1>
          <p className="mt-3 text-lg text-ink-subtle">
            호이와 점검하던 프로젝트로 돌아가요.
          </p>
          <Card variant="raised" className="mt-7 p-5 sm:p-8">
            <AuthForm mode="login" action={loginAction} next={next} />
          </Card>
          <Link
            href="/"
            className="mt-5 inline-flex min-h-11 items-center gap-1 rounded-full border-2 border-line bg-surface px-3 text-sm font-bold text-brand-800 hover:border-brand-300"
          >
            <span aria-hidden="true">←</span>&nbsp;홈으로
          </Link>
        </div>

        <div className="mx-auto w-full max-w-lg lg:order-1">
          <HoiSpeech mood="welcome" size="lg" className="items-center">
            돌아오셨군요! 하던 점검부터 차근차근 이어가요.
          </HoiSpeech>
          <Card variant="warm" className="mt-6 border-dashed p-5 text-sm leading-relaxed text-ink-subtle sm:ml-16">
            로그인 정보는 기존 인증 정책에 따라 확인해요. 계정을 찾을 수 있는지 같은
            상세 정보는 따로 드러내지 않아요.
          </Card>
        </div>
      </main>
    </>
  );
}
