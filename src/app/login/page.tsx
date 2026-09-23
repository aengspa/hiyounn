import Link from "next/link";
import { redirect } from "next/navigation";
import { TopNav } from "@/components/TopNav";
import { ShieldIcon } from "@/components/icons";
import { AuthForm } from "@/components/AuthForm";
import { loginAction } from "@/lib/authActions";
import { isAuthenticated } from "@/lib/auth";

export const metadata = { title: "로그인 — 바이브 보안 에이전트" };

export default async function LoginPage() {
  if (await isAuthenticated()) redirect("/dashboard");

  return (
    <>
      <TopNav />
      <main className="mx-auto flex max-w-md flex-col items-center px-6 py-16">
        <div className="mb-6 flex h-14 w-14 items-center justify-center rounded-2xl bg-brand-50">
          <ShieldIcon className="h-8 w-8 text-brand-600" />
        </div>
        <h1 className="text-2xl font-bold text-slate-900">다시 오셨네요</h1>
        <p className="mt-2 text-center text-slate-600">
          로그인하고 프로젝트 보안 검증을 이어가세요.
        </p>

        <div className="mt-8 w-full rounded-2xl border border-slate-200 bg-white p-8 shadow-sm">
          <AuthForm mode="login" action={loginAction} />
        </div>

        <Link href="/" className="mt-6 text-sm text-slate-500 hover:text-slate-700">
          ← 홈으로
        </Link>
      </main>
    </>
  );
}
