import type { Metadata } from "next";
import { Sidebar, type SidebarProject } from "@/components/Sidebar";
import { TopNav } from "@/components/TopNav";
import { getCurrentUser } from "@/lib/auth";
import { listProjects, listScans } from "@/lib/store/store";

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
      const list = await listProjects(user.id);
      projects = await Promise.all(
        list.map(async (p) => {
          // 점검 기록은 사이드바 하위 트리로 보여 준다(최신순). 기록을 못 불러와도 프로젝트는 보여 준다.
          const scans = await listScans(p.id, user.id).catch(() => []);
          return {
            id: p.id,
            name: p.name,
            scans: scans.map((s) => ({
              id: s.id,
              at: s.completedAt ?? s.startedAt,
              findingCount: s.findingIds.length,
            })),
          };
        }),
      );
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
