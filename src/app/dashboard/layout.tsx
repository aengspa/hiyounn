import { Sidebar } from "@/components/Sidebar";
import { getCurrentUser } from "@/lib/auth";

export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const user = await getCurrentUser();

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar
        user={user ? { email: user.email, name: user.name } : null}
      />
      <div className="flex-1 overflow-x-hidden">{children}</div>
    </div>
  );
}
