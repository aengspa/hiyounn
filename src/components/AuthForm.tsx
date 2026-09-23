"use client";

import { useFormState, useFormStatus } from "react-dom";
import Link from "next/link";
import type { AuthState } from "@/lib/authActions";

type Mode = "login" | "signup";

function SubmitButton({ label }: { label: string }) {
  const { pending } = useFormStatus();
  return (
    <button
      type="submit"
      disabled={pending}
      className="w-full rounded-lg bg-brand-600 px-4 py-2.5 font-medium text-white hover:bg-brand-700 disabled:opacity-60"
    >
      {pending ? "처리 중…" : label}
    </button>
  );
}

export function AuthForm({
  mode,
  action,
}: {
  mode: Mode;
  action: (prev: AuthState, formData: FormData) => Promise<AuthState>;
}) {
  const [state, formAction] = useFormState<AuthState, FormData>(
    action,
    undefined
  );
  const isSignup = mode === "signup";

  return (
    <form action={formAction} className="space-y-4">
      {state?.error && (
        <div
          role="alert"
          className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700"
        >
          {state.error}
        </div>
      )}

      {isSignup && (
        <Field
          id="name"
          label="이름 (선택)"
          type="text"
          autoComplete="name"
          placeholder="홍길동"
        />
      )}

      <Field
        id="email"
        label="이메일"
        type="email"
        autoComplete="email"
        required
        placeholder="you@example.com"
      />

      <Field
        id="password"
        label="비밀번호"
        type="password"
        autoComplete={isSignup ? "new-password" : "current-password"}
        required
        placeholder={isSignup ? "8자 이상" : "비밀번호"}
        minLength={isSignup ? 8 : undefined}
      />

      {isSignup && (
        <Field
          id="confirm"
          label="비밀번호 확인"
          type="password"
          autoComplete="new-password"
          required
          placeholder="비밀번호 재입력"
          minLength={8}
        />
      )}

      <SubmitButton label={isSignup ? "회원가입" : "로그인"} />

      <p className="text-center text-sm text-slate-500">
        {isSignup ? (
          <>
            이미 계정이 있나요?{" "}
            <Link href="/login" className="font-medium text-brand-600 hover:text-brand-700">
              로그인
            </Link>
          </>
        ) : (
          <>
            계정이 없나요?{" "}
            <Link href="/signup" className="font-medium text-brand-600 hover:text-brand-700">
              회원가입
            </Link>
          </>
        )}
      </p>
    </form>
  );
}

function Field({
  id,
  label,
  ...props
}: {
  id: string;
  label: string;
} & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-sm font-medium text-slate-700">
        {label}
      </label>
      <input
        id={id}
        name={id}
        className="w-full rounded-lg border border-slate-300 px-3 py-2 text-slate-900 outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-100"
        {...props}
      />
    </div>
  );
}
