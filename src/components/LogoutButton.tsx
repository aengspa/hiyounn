"use client";

import { logoutAction } from "@/lib/authActions";

export function LogoutButton() {
  return (
    <form action={logoutAction}>
      <button
        type="submit"
        className="rounded-md border border-slate-300 px-3 py-1.5 text-slate-600 hover:bg-slate-100"
      >
        로그아웃
      </button>
    </form>
  );
}
