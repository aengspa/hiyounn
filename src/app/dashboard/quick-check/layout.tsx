import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "빠른 코드 점검",
};

export default function QuickCheckLayout({ children }: { children: React.ReactNode }) {
  return children;
}
