import { redirect } from "next/navigation";
import { parseScanMode } from "@/lib/domain/scanMode";
import { NewProjectForm } from "./NewProjectForm";

/** 새 프로젝트 2단계: 선택한 스캔 방식에 맞는 입력 폼. */
export default function NewProjectSetupPage({
  searchParams,
}: {
  searchParams: { mode?: string | string[] };
}) {
  const raw = Array.isArray(searchParams.mode) ? searchParams.mode[0] : searchParams.mode;
  const mode = parseScanMode(raw);
  // 공개 웹사이트 점검(safe_active)은 제공하지 않는다. 예전 링크로 들어오면 1단계로 돌려보낸다.
  if (!mode || mode === "safe_active") redirect("/dashboard/new");
  return <NewProjectForm mode={mode} />;
}
