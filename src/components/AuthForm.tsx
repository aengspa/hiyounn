"use client";

import { useFormState, useFormStatus } from "react-dom";
import Link from "next/link";
import { Button } from "@/components/ui";
import type { AuthState } from "@/lib/authActions";

type Mode = "login" | "signup";

function SubmitButton({ label }: { label: string }) {
  const { pending } = useFormStatus();
  return (
    <Button
      type="submit"
      size="lg"
      disabled={pending}
      aria-disabled={pending}
      className="w-full"
    >
      <span aria-live="polite">{pending ? "잠시만요, 확인하고 있어요…" : label}</span>
    </Button>
  );
}

export function AuthForm({
  mode,
  action,
}: {
  mode: Mode;
  action: (prev: AuthState, formData: FormData) => Promise<AuthState>;
}) {
  const [state, formAction] = useFormState<AuthState, FormData>(action, undefined);
  const isSignup = mode === "signup";
  const errorId = state?.error ? `${mode}-form-error` : undefined;

  return (
    <form action={formAction} className="space-y-5" aria-describedby={errorId}>
      {state?.error && (
        <div
          id={errorId}
          role="alert"
          aria-live="assertive"
          className="rounded-xl border border-red-200 bg-danger-soft px-4 py-3 text-sm font-medium leading-relaxed text-danger"
        >
          <p className="font-semibold">입력한 내용을 다시 확인해 주세요</p>
          <p className="mt-1">{state.error}</p>
        </div>
      )}

      {isSignup && (
        <Field
          id="name"
          label="이름"
          optional
          type="text"
          autoComplete="name"
          placeholder="예: 홍길동"
        />
      )}

      <Field
        id="email"
        label="이메일 주소"
        type="email"
        inputMode="email"
        autoComplete="email"
        required
        placeholder="you@example.com"
        aria-invalid={state?.error ? true : undefined}
        aria-describedby={errorId}
      />

      <Field
        id="password"
        label="비밀번호"
        type="password"
        autoComplete={isSignup ? "new-password" : "current-password"}
        required
        placeholder={isSignup ? "8자 이상 입력해 주세요" : "비밀번호를 입력해 주세요"}
        minLength={isSignup ? 8 : undefined}
        aria-invalid={state?.error ? true : undefined}
        aria-describedby={errorId}
        hint={isSignup ? "8자 이상으로 만들어 주세요." : undefined}
      />

      {isSignup && (
        <Field
          id="confirm"
          label="비밀번호 확인"
          type="password"
          autoComplete="new-password"
          required
          placeholder="비밀번호를 한 번 더 입력해 주세요"
          minLength={8}
          aria-invalid={state?.error ? true : undefined}
          aria-describedby={errorId}
        />
      )}

      <SubmitButton label={isSignup ? "계정 만들고 시작하기" : "로그인하고 이어가기"} />

      <p className="text-center text-sm text-ink-subtle">
        {isSignup ? (
          <>
            이미 계정이 있나요?{" "}
            <Link href="/login" className="inline-flex min-h-11 items-center font-semibold text-brand-700 hover:underline">
              로그인하기
            </Link>
          </>
        ) : (
          <>
            아직 계정이 없나요?{" "}
            <Link href="/signup" className="inline-flex min-h-11 items-center font-semibold text-brand-700 hover:underline">
              계정 만들기
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
  hint,
  optional,
  ...props
}: {
  id: string;
  label: string;
  hint?: string;
  optional?: boolean;
} & React.InputHTMLAttributes<HTMLInputElement>) {
  const hintId = hint ? `${id}-hint` : undefined;
  const describedBy = [props["aria-describedby"], hintId].filter(Boolean).join(" ") || undefined;

  return (
    <div>
      <label htmlFor={id} className="mb-2 flex items-baseline justify-between gap-3 text-base font-semibold text-ink">
        <span>{label}</span>
        {optional && <span className="text-xs font-medium text-ink-muted">선택</span>}
      </label>
      <input
        id={id}
        name={id}
        className="min-h-12 w-full rounded-xl border border-line-strong bg-white px-4 py-3 text-base text-ink shadow-sm outline-none transition-colors hover:border-brand-500 focus:border-brand-600 focus:ring-2 focus:ring-primary-soft"
        {...props}
        aria-describedby={describedBy}
      />
      {hint && (
        <p id={hintId} className="mt-2 text-sm text-ink-muted">
          {hint}
        </p>
      )}
    </div>
  );
}
