import { notFound, redirect } from "next/navigation";
import { requirePageUserId } from "@/lib/auth";
import { getFinding, NotAuthorizedError, NotFoundError } from "@/lib/store/store";

export const dynamic = "force-dynamic";

/**
 * 예전 항목별 화면(6단계 수정 UI)은 없앴다. 기존 링크는 그 항목이 속한
 * 점검 보고서로 보낸다. 설명은 보고서의 "더보기"에서 볼 수 있다.
 */
export default async function FindingRedirectPage({ params }: { params: { id: string } }) {
  const uid = await requirePageUserId(`/dashboard/findings/${params.id}`);
  let finding;
  try {
    finding = await getFinding(params.id, uid);
  } catch (e) {
    if (e instanceof NotFoundError || e instanceof NotAuthorizedError) notFound();
    throw e;
  }
  redirect(`/dashboard/scans/${encodeURIComponent(finding.scanId)}`);
}
