import type { Metadata } from "next";
import { Sidebar, type SidebarProject } from "@/components/Sidebar";
import { TopNav } from "@/components/TopNav";
import { getCurrentUser } from "@/lib/auth";
import { listProjects } from "@/lib/store/store";

export const metadata: Metadata = {
  title: "내 프로젝트",
};

export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // 로그인 확인은 middleware와 각 페이지(requirePageUserId)가 맡는다.
  const user = await getCurrentUser();
  let projects: SidebarProject[] = [];
  if (user) {
    try {
      projects = (await listProjects(user.id)).map((p) => ({ id: p.id, name: p.name }));
    } catch {
      // 목록을 못 불러와도 본문은 보여 준다.
      projects = [];
    }
  }

  return (
    <div className="flex min-h-screen min-w-0 flex-col bg-canvas">
      <TopNav />
      <div className="flex min-w-0 flex-1 flex-col lg:flex-row">
        <Sidebar projects={projects} />
        <div
          id="main-content"
          tabIndex={-1}
          className="min-w-0 flex-1 overflow-x-hidden outline-none"
        >
          {children}
        </div>
      </div>
    </div>
  );
}
