import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "발견한 내용",
};

export default function FindingLayout({ children }: { children: React.ReactNode }) {
  return children;
}
