import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "프로젝트",
};

export default function ProjectLayout({ children }: { children: React.ReactNode }) {
  return children;
}
