import type { Metadata } from "next";
import { Sidebar } from "@/components/Sidebar";
import { getCurrentUser } from "@/lib/auth";

export const metadata: Metadata = {
  title: "내 프로젝트",
};

export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const user = await getCurrentUser();

  return (
    <div className="flex min-h-screen min-w-0 flex-col bg-canvas lg:flex-row">
      <Sidebar
        user={user ? { email: user.email, name: user.name } : null}
      />
      <div
        id="main-content"
        tabIndex={-1}
        className="min-w-0 flex-1 overflow-x-hidden outline-none"
      >
        {children}
      </div>
    </div>
  );
}
