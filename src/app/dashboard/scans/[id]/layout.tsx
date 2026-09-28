import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "점검 결과",
};

export default function ScanLayout({ children }: { children: React.ReactNode }) {
  return children;
}
