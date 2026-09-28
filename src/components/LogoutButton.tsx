"use client";

import { logoutAction } from "@/lib/authActions";
import { Button } from "@/components/ui";

export function LogoutButton() {
  return (
    <form action={logoutAction}>
      <Button type="submit" variant="secondary" size="sm">
        로그아웃
      </Button>
    </form>
  );
}
