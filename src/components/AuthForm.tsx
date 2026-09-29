"use client";

import { useEffect, useRef } from "react";
import { useFormState, useFormStatus } from "react-dom";
import Link from "next/link";
import { Button } from "@/components/ui";
import type { AuthState } from "@/lib/authActions";

type Mode = "login" | "signup";

/** 오류 문장 다음에 붙는 다음 행동 안내. 이메일 등록 여부를 드러내지 않는 일반 문장만 쓴다(요구사항 10.5). */
const NEXT_ACTION = "입력한 내용을 확인하고 다시 시도해 주세요.";

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
  next,
}: {
  mode: Mode;
  action: (prev: AuthState, formData: FormData) => Promise<AuthState>;
  /** 로그인 후 돌아갈 대시보드 경로. 서버에서 다시 검증한다. */
  next?: string;
}) {
  const nextQuery = next ? `?next=${encodeURIComponent(next)}` : "";
  const [state, formAction] = useFormState<AuthState, FormData>(action, undefined);
  const formRef = useRef<HTMLFormElement>(null);
  const isSignup = mode === "signup";
  const errorId = state?.error ? `${mode}-form-error` : undefined;

  // 검증 실패 시 입력값은 그대로 두고, 오류가 연결된 첫 입력 필드로 포커스를 옮긴다(요구사항 11.9).
  useEffect(() => {
    if (!state?.error) return;
    const firstInvalid = formRef.current?.querySelector<HTMLInputElement>('input[aria-invalid="true"]');
    firstInvalid?.focus();
  }, [state]);

  return (
    <form ref={formRef} action={formAction} className="space-y-5" aria-describedby={errorId}>
      {next && <input type="hidden" name="next" value={next} />}
      {state?.error && (
        <div
          id={errorId}
          role="alert"
          aria-live="assertive"
          className="rounded-2xl border-2 border-[#f3c4bd] bg-danger-soft px-4 py-3 text-base leading-relaxed"
        >
          <p className="font-bold text-danger">{state.error}</p>
          <p className="mt-1 text-ink">{NEXT_ACTION}</p>
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

      <p className="text-center text-base text-ink-subtle">
        {isSignup ? (
          <>
            이미 계정이 있나요?{" "}
            <Link href={`/login${nextQuery}`} className="inline-flex min-h-11 items-center font-bold text-brand-800 underline-offset-4 hover:underline">
              로그인하기
            </Link>
          </>
        ) : (
          <>
            아직 계정이 없나요?{" "}
            <Link href={`/signup${nextQuery}`} className="inline-flex min-h-11 items-center font-bold text-brand-800 underline-offset-4 hover:underline">
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
      <label htmlFor={id} className="mb-2 flex items-baseline justify-between gap-3 text-base font-bold text-ink">
        <span>{label}</span>
        {optional && <span className="text-sm font-medium text-ink-muted">선택</span>}
      </label>
      {/* outline-none을 쓰지 않아 전역 포커스 링(--focus)이 그대로 보인다(요구사항 11.3). */}
      <input
        id={id}
        name={id}
        className="min-h-12 w-full rounded-2xl border-2 border-line-input bg-surface px-4 py-3 text-base text-ink transition-colors placeholder:text-ink-muted hover:border-brand-700 focus:border-brand-700 focus:bg-surface-warm aria-[invalid=true]:border-danger"
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
