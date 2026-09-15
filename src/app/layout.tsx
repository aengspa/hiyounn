import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "바이브 보안 에이전트 — 수정했다고 믿지 마세요. 검증하세요.",
  description:
    "취약점을 찾고, 수정하고, 같은 공격을 다시 재현해 막혔는지, 정상 기능은 그대로인지까지 검증하는 독립형 보안 에이전트입니다.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
