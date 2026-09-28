import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "새 프로젝트",
};

export default function NewProjectLayout({ children }: { children: React.ReactNode }) {
  return children;
}
