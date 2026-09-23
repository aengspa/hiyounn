"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { PageHeader } from "@/components/PageHeader";

export default function NewProjectPage() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [deploymentUrl, setDeploymentUrl] = useState("");
  const [sourceCode, setSourceCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const res = await fetch("/api/projects", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name, repositoryUrl, deploymentUrl, sourceCode }),
      });
      const data = await res.json();
      if (!res.ok || data.error) {
        setError(data.error ?? "프로젝트를 만들 수 없습니다.");
        setSubmitting(false);
        return;
      }
      router.push(`/dashboard/projects/${data.project.id}`);
    } catch {
      setError("네트워크 오류입니다. 다시 시도해 주세요.");
      setSubmitting(false);
    }
  }

  return (
    <>
      <PageHeader
        title="프로젝트 추가"
        subtitle="저장소와 배포 주소를 연결하면 에이전트가 무엇을 점검할지 파악합니다."
        backHref="/dashboard"
        backLabel="프로젝트"
      />
      <main className="mx-auto max-w-2xl px-6 py-8">
        <form
          onSubmit={submit}
          className="space-y-5 rounded-xl border border-slate-200 bg-white p-6 shadow-sm"
        >
          <Field label="프로젝트 이름" required>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="예: 내 노트 앱"
              className="w-full rounded-lg border border-slate-300 px-3 py-2 outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-100"
            />
          </Field>

          <Field
            label="GitHub 저장소 주소"
            hint="소스 코드를 점검하고 기술 스택을 자동으로 감지합니다."
          >
            <input
              value={repositoryUrl}
              onChange={(e) => setRepositoryUrl(e.target.value)}
              placeholder="https://github.com/내계정/내저장소"
              className="w-full rounded-lg border border-slate-300 px-3 py-2 outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-100"
            />
          </Field>

          <Field
            label="배포된 앱 주소"
            hint="본인이 소유한 대상만 입력하세요. 읽기 전용 헤더/CORS 점검에 사용됩니다."
          >
            <input
              value={deploymentUrl}
              onChange={(e) => setDeploymentUrl(e.target.value)}
              placeholder="https://내앱.example.com"
              className="w-full rounded-lg border border-slate-300 px-3 py-2 outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-100"
            />
          </Field>

          <Field
            label="소스 코드 붙여넣기 (선택)"
            hint="바이브코딩으로 만든 서비스의 코드를 붙여넣으면 AI가 직접 분석합니다. 여러 파일은 '// file: 경로' 주석으로 구분하세요."
          >
            <textarea
              value={sourceCode}
              onChange={(e) => setSourceCode(e.target.value)}
              rows={10}
              placeholder={`// file: app/api/users/[id]/route.ts\nexport async function GET(req, { params }) {\n  const user = await db.users.findUnique({ where: { id: params.id } });\n  return Response.json(user);\n}`}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-100"
            />
          </Field>

          <p className="rounded-lg bg-slate-50 p-3 text-xs text-slate-500">
            앞으로 Supabase, Firebase, AWS 연결을 추가할 수 있도록 설계되어 있으며,
            이 화면을 바꾸지 않고 확장할 수 있습니다.
          </p>

          {error && (
            <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full rounded-lg bg-brand-600 px-4 py-2.5 font-medium text-white hover:bg-brand-700 disabled:opacity-60"
          >
            {submitting ? "생성 중…" : "프로젝트 만들기"}
          </button>
        </form>
      </main>
    </>
  );
}

function Field({
  label,
  hint,
  required,
  children,
}: {
  label: string;
  hint?: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-sm font-medium text-slate-700">
        {label} {required && <span className="text-red-500">*</span>}
      </span>
      {children}
      {hint && <span className="mt-1 block text-xs text-slate-500">{hint}</span>}
    </label>
  );
}
