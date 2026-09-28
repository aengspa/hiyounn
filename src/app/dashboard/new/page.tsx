"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { PageHeader } from "@/components/PageHeader";
import { HoiSpeech } from "@/components/mascot/HoiSpeech";
import { Button, Card, Disclosure } from "@/components/ui";

const MAX_ZIP_SIZE = 8 * 1024 * 1024;
const inputClassName =
  "min-h-12 w-full rounded-2xl border border-line-strong bg-white px-4 py-3 text-base text-ink shadow-sm outline-none transition-colors hover:border-brand-500 focus:border-brand-700 focus:ring-2 focus:ring-primary-soft disabled:cursor-not-allowed disabled:bg-surface-warm disabled:text-ink-muted";

export default function NewProjectPage() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [deploymentUrl, setDeploymentUrl] = useState("");
  const [sourceCode, setSourceCode] = useState("");
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [deploymentAuthorized, setDeploymentAuthorized] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!name.trim()) {
      setError("프로젝트 이름을 입력해 주세요.");
      return;
    }
    if (zipFile && zipFile.size > MAX_ZIP_SIZE) {
      setError("ZIP 파일은 8MB 이하로 선택해 주세요.");
      return;
    }

    setSubmitting(true);
    try {
      const authorized = Boolean(deploymentUrl.trim()) && deploymentAuthorized;
      const res = zipFile
        ? await fetch("/api/projects/upload", {
            method: "POST",
            body: buildUploadForm({
              name,
              repositoryUrl,
              deploymentUrl,
              zipFile,
              deploymentAuthorized: authorized,
            }),
          })
        : await fetch("/api/projects", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              name,
              repositoryUrl,
              deploymentUrl,
              sourceCode,
              deploymentAuthorized: authorized,
            }),
          });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data || data.error) {
        setError(friendlyProjectError(data?.error));
        setSubmitting(false);
        return;
      }
      router.push(`/dashboard/projects/${data.project.id}`);
    } catch {
      setError("연결이 잠깐 끊겼어요. 인터넷 연결을 확인하고 다시 시도해 주세요.");
      setSubmitting(false);
    }
  }

  function chooseZip(file: File | null, input: HTMLInputElement) {
    setError(null);
    if (file && file.size > MAX_ZIP_SIZE) {
      input.value = "";
      setZipFile(null);
      setError("ZIP 파일은 8MB 이하로 선택해 주세요.");
      return;
    }
    setZipFile(file);
  }

  return (
    <>
      <PageHeader
        title="호이에게 프로젝트를 소개해 주세요"
        subtitle="점검에 필요한 코드와 선택 정보를 차근차근 연결해요."
        backHref="/dashboard"
        backLabel="내 프로젝트"
      />
      <div className="mx-auto max-w-3xl px-4 py-8 sm:px-6">
        <HoiSpeech mood="guide" size="md">
          ZIP 파일을 올리는 방법이 가장 정확해요. 여러 파일의 경로를 그대로 살펴볼 수 있어요.
        </HoiSpeech>

        <form
          onSubmit={submit}
          className="mt-6 space-y-5"
          aria-busy={submitting}
          aria-describedby={error ? "project-form-error" : undefined}
        >
          <StepCard number="1" title="프로젝트 이름" description="목록에서 알아보기 쉬운 이름을 적어 주세요.">
            <Field id="name" label="프로젝트 이름" required>
              <input
                id="name"
                name="name"
                value={name}
                onChange={(e) => {
                  setName(e.target.value);
                  if (error === "프로젝트 이름을 입력해 주세요.") setError(null);
                }}
                required
                aria-invalid={error === "프로젝트 이름을 입력해 주세요."}
                aria-describedby={error === "프로젝트 이름을 입력해 주세요." ? "project-form-error" : undefined}
                autoComplete="off"
                placeholder="예: 우리 동네 일정 앱"
                className={inputClassName}
              />
            </Field>
          </StepCard>

          <StepCard number="2" title="코드가 있는 곳" description="ZIP을 우선 사용하고, 없다면 코드를 직접 붙여 넣을 수 있어요.">
            <Field
              id="file"
              label="프로젝트 ZIP"
              hint="권장 · 8MB 이하의 .zip 파일을 올려 주세요. node_modules, 빌드 결과물, 바이너리는 자동으로 제외해요."
            >
              <input
                id="file"
                name="file"
                type="file"
                accept=".zip,application/zip"
                onChange={(e) => chooseZip(e.target.files?.[0] ?? null, e.currentTarget)}
                aria-invalid={error === "ZIP 파일은 8MB 이하로 선택해 주세요."}
                aria-describedby={`file-hint${error === "ZIP 파일은 8MB 이하로 선택해 주세요." ? " project-form-error" : ""}`}
                className={`${inputClassName} p-2 text-sm file:mr-3 file:min-h-10 file:rounded-xl file:border-0 file:bg-primary-soft file:px-4 file:font-extrabold file:text-brand-900`}
              />
            </Field>
            {zipFile && (
              <p className="mt-3 break-all rounded-2xl border border-green-200 bg-success-soft px-4 py-3 text-sm font-bold text-success" role="status">
                {zipFile.name}을 선택했어요. 붙여 넣은 코드보다 이 ZIP을 먼저 사용해요.
              </p>
            )}

            <Disclosure summary="다른 코드 제공 방법과 저장소 링크" className="mt-4">
              <div className="space-y-5">
                <Field
                  id="sourceCode"
                  label="소스 코드 직접 붙여넣기"
                  hint="ZIP이 없을 때만 사용해요. 여러 파일은 ‘// file: 경로’로 구분해 주세요. 서버는 입력의 앞 100,000자까지 검사해요."
                >
                  <textarea
                    id="sourceCode"
                    name="sourceCode"
                    value={sourceCode}
                    onChange={(e) => setSourceCode(e.target.value)}
                    rows={9}
                    disabled={Boolean(zipFile)}
                    aria-describedby="sourceCode-hint"
                    placeholder={`// file: src/lib/profile.ts\nexport function publicProfile(user) {\n  return { name: user.name };\n}`}
                    className={`${inputClassName} min-h-52 resize-y font-mono text-sm`}
                  />
                </Field>
                <Field
                  id="repositoryUrl"
                  label="GitHub 저장소 주소"
                  hint="선택 · 지금은 참고 링크로만 기록하며, 저장소를 자동으로 내려받지는 않아요."
                >
                  <input
                    id="repositoryUrl"
                    name="repositoryUrl"
                    type="url"
                    value={repositoryUrl}
                    onChange={(e) => setRepositoryUrl(e.target.value)}
                    placeholder="https://github.com/example/project"
                    aria-describedby="repositoryUrl-hint"
                    className={inputClassName}
                  />
                </Field>
              </div>
            </Disclosure>
          </StepCard>

          <StepCard number="3" title="실행 중인 서비스 주소" description="선택 사항이에요. 입력하지 않아도 코드 점검을 시작할 수 있어요.">
            <Field
              id="deploymentUrl"
              label="서비스 주소"
              hint="본인이 소유하거나 점검 권한이 있는 http(s) 주소만 입력해 주세요."
            >
              <input
                id="deploymentUrl"
                name="deploymentUrl"
                type="url"
                value={deploymentUrl}
                onChange={(e) => setDeploymentUrl(e.target.value)}
                placeholder="https://app.example.com"
                aria-describedby="deploymentUrl-hint"
                className={inputClassName}
              />
            </Field>
          </StepCard>

          <StepCard number="4" title="검사 범위를 확인해요" description="코드는 정적으로 살펴보고, 서비스 주소는 권한 확인 여부에 따라 범위를 정해요.">
            <ul className="space-y-2 text-sm leading-relaxed text-ink-subtle">
              <li>• ZIP이 있으면 ZIP 속 지원 파일을 우선 검사해요.</li>
              <li>• 저장소 주소만으로 코드를 가져오지는 않아요.</li>
              <li>• 자동 점검만으로 모든 위험을 찾을 수는 없어요.</li>
            </ul>

            {deploymentUrl.trim() && (
              <label className="mt-4 flex min-h-11 cursor-pointer items-start gap-3 rounded-2xl border border-amber-300 bg-warning-soft p-4 text-sm leading-relaxed text-ink">
                <input
                  name="deploymentAuthorized"
                  type="checkbox"
                  checked={deploymentAuthorized}
                  onChange={(e) => setDeploymentAuthorized(e.target.checked)}
                  className="mt-1 h-5 w-5 shrink-0 accent-brand-700"
                />
                <span>
                  이 주소를 <strong>본인이 소유</strong>하거나 능동 보안 테스트 권한이 있음을 확인해요.
                  확인하지 않으면 배포 환경 점검은 실행하지 않고 코드 정적 분석만 진행해요.
                </span>
              </label>
            )}
          </StepCard>

          <Card variant="raised" className="p-5 sm:p-6">
            <div className="flex items-start gap-3">
              <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-primary-soft text-sm font-black text-brand-900">5</span>
              <div>
                <h2 className="text-xl font-black text-ink">준비되면 연결해요</h2>
                <p className="mt-1 text-sm text-ink-subtle">연결이 끝나면 프로젝트 화면으로 이동해 첫 점검을 준비해요.</p>
              </div>
            </div>

            {error && (
              <div id="project-form-error" role="alert" aria-live="assertive" className="mt-5 rounded-2xl border border-red-200 bg-danger-soft p-4 text-sm text-danger">
                <p className="font-extrabold">입력한 내용을 한 번만 확인해 주세요</p>
                <p className="mt-1">{error}</p>
              </div>
            )}

            <Button type="submit" size="lg" disabled={submitting} aria-busy={submitting} className="mt-5 w-full">
              <span aria-live="polite">{submitting ? "프로젝트를 연결하고 있어요…" : "프로젝트 연결하기"}</span>
            </Button>
          </Card>
        </form>
      </div>
    </>
  );
}

function buildUploadForm(input: {
  name: string;
  repositoryUrl: string;
  deploymentUrl: string;
  zipFile: File;
  deploymentAuthorized: boolean;
}): FormData {
  const fd = new FormData();
  fd.set("name", input.name);
  fd.set("repositoryUrl", input.repositoryUrl);
  fd.set("deploymentUrl", input.deploymentUrl);
  fd.set("file", input.zipFile);
  fd.set("deploymentAuthorized", String(input.deploymentAuthorized));
  return fd;
}

function friendlyProjectError(error: unknown) {
  if (error === "forbidden") return "이 프로젝트를 만들 권한을 확인할 수 없어요. 로그인 상태를 확인해 주세요.";
  if (error === "invalid_url") return "입력한 주소 형식을 확인해 주세요. http 또는 https 주소를 사용할 수 있어요.";
  if (error === "file_too_large") return "ZIP 파일은 8MB 이하로 선택해 주세요.";
  if (error === "internal_error") return "지금은 프로젝트를 연결하기 어려워요. 잠시 후 다시 시도해 주세요.";
  return "프로젝트를 연결할 수 없어요. 입력한 주소와 파일을 확인한 뒤 다시 시도해 주세요.";
}

function StepCard({
  number,
  title,
  description,
  children,
}: {
  number: string;
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <Card variant="raised" className="p-5 sm:p-6">
      <div className="flex items-start gap-3">
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-primary-soft text-sm font-black text-brand-900">{number}</span>
        <div className="min-w-0">
          <h2 className="text-xl font-black text-ink">{title}</h2>
          <p className="mt-1 text-sm leading-relaxed text-ink-subtle">{description}</p>
        </div>
      </div>
      <div className="mt-5">{children}</div>
    </Card>
  );
}

function Field({
  id,
  label,
  hint,
  required,
  children,
}: {
  id: string;
  label: string;
  hint?: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label htmlFor={id} className="mb-2 block text-base font-extrabold text-ink">
        {label} {required && <span className="text-danger">(필수)</span>}
      </label>
      {children}
      {hint && <p id={`${id}-hint`} className="mt-2 text-sm leading-relaxed text-ink-muted">{hint}</p>}
    </div>
  );
}
