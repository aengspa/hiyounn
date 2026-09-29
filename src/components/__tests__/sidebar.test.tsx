import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

let pathname = "/dashboard";
vi.mock("next/navigation", () => ({ usePathname: () => pathname }));

const { Sidebar } = await import("@/components/Sidebar");

const projects = [
  {
    id: "p1",
    name: "메모 앱",
    scans: [
      { id: "s2", at: "2026-09-29T06:00:00Z", findingCount: 3 },
      { id: "s1", at: "2026-09-28T06:00:00Z", findingCount: 0 },
    ],
  },
  { id: "p2", name: "쇼핑몰", scans: [] },
];

describe("사이드바 점검 기록 하위 트리", () => {
  it("프로젝트 아래에 점검 기록을 결과 화면 링크로 보여 준다", () => {
    pathname = "/dashboard/projects/p1";
    const html = renderToStaticMarkup(<Sidebar projects={projects} />);
    expect(html).toContain('href="/dashboard/scans/s2"');
    expect(html).toContain('href="/dashboard/scans/s1"');
    // 보고 있는 프로젝트의 트리는 펼쳐져 있다
    expect(html).toMatch(/aria-controls="sidebar-scans-p1"[^>]*aria-label="메모 앱 점검 기록 접기"|aria-expanded="true"[^>]*aria-controls="sidebar-scans-p1"/);
    // 시각은 KST: 06:00Z → 오후 3:00
    expect(html).toContain("9월 29일 오후 3:00");
    // 점검 기록이 없는 프로젝트에는 여닫기 버튼이 없다
    expect(html).not.toContain('aria-controls="sidebar-scans-p2"');
  });

  it("점검 결과 화면에 있으면 그 기록을 현재 위치로 표시하고 소속 프로젝트 트리를 펼친다", () => {
    pathname = "/dashboard/scans/s1";
    const html = renderToStaticMarkup(<Sidebar projects={projects} />);
    expect(html).toMatch(/href="\/dashboard\/scans\/s1"[^>]*aria-current="page"|aria-current="page"[^>]*href="\/dashboard\/scans\/s1"/);
    expect(html).toContain('aria-expanded="true"');
  });

  it("다른 곳에 있으면 트리는 접혀 있다", () => {
    pathname = "/dashboard";
    const html = renderToStaticMarkup(<Sidebar projects={projects} />);
    expect(html).toContain('aria-expanded="false"');
    expect(html).toMatch(/<ul id="sidebar-scans-p1" hidden/);
  });
});
