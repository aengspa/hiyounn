import { Sidebar } from "@/components/Sidebar";
import { listProjects } from "@/lib/store/store";
import { getCurrentUserId } from "@/lib/auth";

export const dynamic = "force-dynamic";

export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const uid = await getCurrentUserId();
  const projects = listProjects(uid).map((p) => ({ id: p.id, name: p.name }));

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar projects={projects} />
      <div className="flex-1 overflow-x-hidden">{children}</div>
    </div>
  );
}
