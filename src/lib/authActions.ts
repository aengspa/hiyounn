"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import {
  createUser,
  findUserByEmail,
  EmailInUseError,
} from "@/lib/store/store";
import {
  hashPassword,
  verifyPassword,
  createSessionToken,
  SESSION_COOKIE,
  SESSION_MAX_AGE,
} from "@/lib/auth-core";

export type AuthState = { error?: string } | undefined;

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function setSessionCookie(userId: string) {
  cookies().set(SESSION_COOKIE, createSessionToken(userId), {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: SESSION_MAX_AGE,
  });
}

export async function signupAction(
  _prev: AuthState,
  formData: FormData
): Promise<AuthState> {
  const email = String(formData.get("email") ?? "").trim();
  const password = String(formData.get("password") ?? "");
  const confirm = String(formData.get("confirm") ?? "");
  const name = String(formData.get("name") ?? "").trim();

  if (!EMAIL_RE.test(email)) return { error: "올바른 이메일 주소를 입력하세요." };
  if (password.length < 8)
    return { error: "비밀번호는 8자 이상이어야 합니다." };
  if (password !== confirm)
    return { error: "비밀번호가 일치하지 않습니다." };

  try {
    const user = createUser({
      email,
      passwordHash: hashPassword(password),
      name: name || undefined,
    });
    setSessionCookie(user.id);
  } catch (e) {
    if (e instanceof EmailInUseError)
      return { error: "이미 가입된 이메일입니다. 로그인해 주세요." };
    return { error: "가입 중 문제가 발생했습니다. 다시 시도해 주세요." };
  }

  redirect("/dashboard");
}

export async function loginAction(
  _prev: AuthState,
  formData: FormData
): Promise<AuthState> {
  const email = String(formData.get("email") ?? "").trim();
  const password = String(formData.get("password") ?? "");

  if (!email || !password)
    return { error: "이메일과 비밀번호를 입력하세요." };

  const user = findUserByEmail(email);
  // Generic message so we don't reveal whether an email is registered.
  const invalid = { error: "이메일 또는 비밀번호가 올바르지 않습니다." };
  if (!user || !user.passwordHash) return invalid;
  if (!verifyPassword(password, user.passwordHash)) return invalid;

  setSessionCookie(user.id);
  redirect("/dashboard");
}

export async function logoutAction(): Promise<void> {
  cookies().delete(SESSION_COOKIE);
  redirect("/");
}
