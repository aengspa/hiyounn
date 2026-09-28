"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { PageHeader } from "@/components/PageHeader";
import { Button, Card, Disclosure } from "@/components/ui";
import {
  REQUIRED_TEST_ACCOUNTS,
  SCAN_MODE_ERROR_MESSAGE,
  SCAN_MODE_INFO,
  validateScanModeInput,
  type ScanMode,
  type ScanModeValidationError,
} from "@/lib/domain/scanMode";

const MAX_ZIP_SIZE = 8 * 1024 * 1024;
const inputClassName =
  "min-h-12 w-full rounded-xl border border-line-strong bg-white px-4 py-3 text-base text-ink shadow-sm outline-none transition-colors hover:border-brand-500 focus:border-brand-600 focus:ring-2 focus:ring-primary-soft disabled:cursor-not-allowed disabled:bg-surface-warm disabled:text-ink-muted";

type SourceTab = "zip" | "paste";

interface AccountInput {
  username: string;
  password: string;
}

const MODE_TITLE: Record<ScanMode, string> = {
  static: "코드와 파일 확인",
  safe_active: "공개한 웹사이트도 확인",
  isolated_active: "테스트 사이트에서 추가 확인",
};

export function NewProjectForm({ mode }: { mode: ScanMode }) {
  const info = SCAN_MODE_INFO[mode];
  const dynamic = mode !== "static";
  const isolated = mode === "isolated_active";

  const router = useRouter();
  const [name, setName] = useState("");
  const [sourceTab, setSourceTab] = useState<SourceTab>("zip");
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [deploymentUrl, setDeploymentUrl] = useState("");
  const [sourceCode, setSourceCode] = useState("");
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [deploymentAuthorized, setDeploymentAuthorized] = useState(false);
  const [accounts, setAccounts] = useState<AccountInput[]>(
    Array.from({ length: REQUIRED_TEST_ACCOUNTS }, () => ({ username: "", password: "" })),
  );
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  function updateAccount(index: number, patch: Partial<AccountInput>) {
    setAccounts((prev) => prev.map((a, i) => (i === index ? { ...a, ...patch } : a)));
  }

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

    const testAccounts = isolated
      ? accounts.map((a, i) => ({
          label: `계정 ${String.fromCharCode(65 + i)}`,
          username: a.username.trim(),
          password: a.password,
        }))
      : [];
    if (isolated && testAccounts.some((a) => !a.username || !a.password)) {
      setError(SCAN_MODE_ERROR_MESSAGE.test_accounts_required);
      return;
    }

    const url = dynamic ? deploymentUrl.trim() : "";
    const authorized = Boolean(url) && deploymentAuthorized;
    const invalid = validateScanModeInput(mode, {
      hasSource: Boolean(zipFile) || Boolean(sourceCode.trim()),
      deploymentUrl: url || undefined,
      deploymentAuthorized: authorized,
      testAccounts,
    });
    if (invalid) {
      setError(SCAN_MODE_ERROR_MESSAGE[invalid]);
      return;
    }

    setSubmitting(true);
    try {
      const res = zipFile
        ? await fetch("/api/projects/upload", {
            method: "POST",
            body: buildUploadForm({
              name,
              repositoryUrl,
              deploymentUrl: url,
              zipFile,
              deploymentAuthorized: authorized,
              scanMode: mode,
              testAccounts,
            }),
          })
        : await fetch("/api/projects", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              name,
              repositoryUrl,
              deploymentUrl: url,
              sourceCode,
              deploymentAuthorized: authorized,
              scanMode: mode,
              testAccounts,
            }),
          });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data || data.error) {
        setError(friendlyProjectError(data?.error, data?.message));
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
        title={MODE_TITLE[mode]}
        subtitle="필요한 자료를 입력하면 프로젝트를 만들어요."
        backHref="/dashboard/new"
        backLabel="방법 다시 고르기"
      />
      <div className="mx-auto max-w-2xl px-4 py-8 sm:px-6">
        <form
          onSubmit={submit}
          className="space-y-5"
          aria-busy={submitting}
          aria-describedby={error ? "project-form-error" : undefined}
        >
          <Card variant="default" className="p-6">
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
                autoComplete="off"
                placeholder="예: 우리 동네 일정 앱"
                className={inputClassName}
              />
            </Field>
          </Card>

          <Card variant="default" className="p-6">
            <h2 className="text-lg font-bold text-ink">코드 자료</h2>
            <p className="mt-1 text-sm leading-relaxed text-ink-subtle">
              {dynamic
                ? "ZIP을 올리면 코드 분석도 함께 진행해요. 없어도 괜찮아요."
                : "ZIP 파일 또는 붙여넣은 코드 중 하나가 필요해요."}
            </p>

            <div className="mt-4 inline-flex rounded-xl border border-line bg-surface-warm p-1" role="tablist" aria-label="코드 제공 방법">
              <TabButton active={sourceTab === "zip"} onClick={() => setSourceTab("zip")}>
                ZIP 파일
              </TabButton>
              <TabButton active={sourceTab === "paste"} onClick={() => setSourceTab("paste")}>
                코드 붙여넣기
              </TabButton>
            </div>

            {sourceTab === "zip" ? (
              <div className="mt-4">
                <Field
                  id="file"
                  label="프로젝트 ZIP"
                  hint="8MB 이하의 .zip 파일을 올려 주세요."
                >
                  <input
                    id="file"
                    name="file"
                    type="file"
                    accept=".zip,application/zip"
                    onChange={(e) => chooseZip(e.target.files?.[0] ?? null, e.currentTarget)}
                    aria-describedby="file-hint"
                    className={`${inputClassName} p-2 text-sm file:mr-3 file:min-h-10 file:rounded-lg file:border-0 file:bg-primary-soft file:px-4 file:font-semibold file:text-brand-700`}
                  />
                </Field>
                {zipFile && (
                  <p className="mt-3 break-all rounded-xl border border-green-200 bg-success-soft px-4 py-3 text-sm font-semibold text-success" role="status">
                    {zipFile.name}을 선택했어요. 이 ZIP으로 점검해요.
                  </p>
                )}
                <Disclosure summary="어떤 파일이 제외되나요?" className="mt-3">
                  <p className="text-sm leading-relaxed text-ink-subtle">
                    node_modules, 빌드 결과물, 이미지 등 바이너리 파일은 자동으로 제외하고 코드만 읽어요.
                  </p>
                </Disclosure>
              </div>
            ) : (
              <div className="mt-4">
                <Field
                  id="sourceCode"
                  label="소스 코드 붙여넣기"
                  hint="여러 파일은 '// file: 경로'로 구분해 주세요. 앞 100,000자까지 검사해요."
                >
                  <textarea
                    id="sourceCode"
                    name="sourceCode"
                    value={sourceCode}
                    onChange={(e) => setSourceCode(e.target.value)}
                    rows={9}
                    aria-describedby="sourceCode-hint"
                    placeholder={"// file: src/lib/profile.ts\nexport function publicProfile(user) {\n  return { name: user.name };\n}"}
                    className={`${inputClassName} min-h-52 resize-y font-mono text-sm`}
                  />
                </Field>
              </div>
            )}

            <Disclosure summary="참고용 GitHub 주소(선택)" className="mt-4">
              <Field
                id="repositoryUrl"
                label="GitHub 저장소 주소"
                hint="참고 링크로만 기록해요. 저장소를 자동으로 내려받지는 않아요."
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
            </Disclosure>
          </Card>

          {dynamic && (
            <Card variant="default" className="p-6">
              <h2 className="text-lg font-bold text-ink">
                {isolated ? "테스트 서버 주소" : "서비스 주소"}
              </h2>
              <p className="mt-1 text-sm leading-relaxed text-ink-subtle">
                {isolated
                  ? "운영 서버와 데이터베이스가 분리된 스테이징/테스트 서버 주소를 입력해 주세요."
                  : "실제로 접속할 수 있는 서비스 주소예요. 조회 요청만 보내요."}
              </p>
              <Field
                id="deploymentUrl"
                label={isolated ? "테스트 서버 주소" : "서비스 주소"}
                required
                hint="본인이 소유하거나 점검 권한이 있는 http(s) 주소만 입력해 주세요."
                className="mt-4"
              >
                <input
                  id="deploymentUrl"
                  name="deploymentUrl"
                  type="url"
                  required
                  value={deploymentUrl}
                  onChange={(e) => setDeploymentUrl(e.target.value)}
                  placeholder={isolated ? "https://staging.example.com" : "https://app.example.com"}
                  aria-describedby="deploymentUrl-hint"
                  className={inputClassName}
                />
              </Field>

              <label
                className={`mt-4 flex min-h-11 cursor-pointer items-start gap-3 rounded-xl border p-4 text-sm leading-relaxed text-ink ${
                  isolated ? "border-red-200 bg-danger-soft" : "border-amber-200 bg-warning-soft"
                }`}
              >
                <input
                  name="deploymentAuthorized"
                  type="checkbox"
                  checked={deploymentAuthorized}
                  onChange={(e) => setDeploymentAuthorized(e.target.checked)}
                  className="mt-1 h-5 w-5 shrink-0 accent-brand-600"
                />
                <span>
                  이 사이트를 관리하는 사람인지 확인할게요. 이 주소를 <strong>본인이 소유</strong>하거나 능동 보안 테스트 권한이 있음을 확인해요.
                  {isolated && (
                    <>
                      {" "}또한 이 서버가 <strong>운영 환경과 격리</strong>되어 있고, 점검 중 데이터가 바뀌어도 괜찮음을 확인해요.
                    </>
                  )}
                </span>
              </label>
              <p className="mt-3 text-sm leading-relaxed text-ink-muted">
                권한 확인과 별개로, 실제 요청을 보내기 전에 DNS TXT 레코드나 파일 토큰으로 URL 소유권을 인증해요.
                인증이 끝나기 전에는 동적 점검 항목이 확인하지 못한 항목으로 표시돼요.
              </p>
            </Card>
          )}

          {isolated && (
            <Card variant="default" className="p-6">
              <h2 className="text-lg font-bold text-ink">테스트 계정 2개</h2>
              <p className="mt-1 text-sm leading-relaxed text-ink-subtle">
                서로 다른 일반 사용자 계정 두 개가 필요해요. 계정 A로 계정 B의 데이터에 접근할 수 있는지 확인해요.
              </p>
              <div className="mt-4 grid gap-4 sm:grid-cols-2">
                {accounts.map((acc, i) => {
                  const letter = String.fromCharCode(65 + i);
                  return (
                    <fieldset key={letter} className="rounded-xl border border-line bg-white p-4">
                      <legend className="px-1 text-base font-bold text-ink">계정 {letter}</legend>
                      <div className="space-y-3">
                        <Field id={`account-${i}-username`} label="아이디 또는 이메일" required>
                          <input
                            id={`account-${i}-username`}
                            value={acc.username}
                            onChange={(e) => updateAccount(i, { username: e.target.value })}
                            required
                            autoComplete="off"
                            placeholder={`tester-${letter.toLowerCase()}@example.com`}
                            className={inputClassName}
                          />
                        </Field>
                        <Field id={`account-${i}-password`} label="비밀번호" required>
                          <input
                            id={`account-${i}-password`}
                            type="password"
                            value={acc.password}
                            onChange={(e) => updateAccount(i, { password: e.target.value })}
                            required
                            autoComplete="new-password"
                            className={inputClassName}
                          />
                        </Field>
                      </div>
                    </fieldset>
                  );
                })}
              </div>
              <p className="mt-3 text-sm leading-relaxed text-ink-muted">
                실제 사용자 계정이 아닌 테스트 전용 계정을 사용해 주세요. 비밀번호는 점검에만 쓰고 다시 보여주지 않아요.
              </p>
            </Card>
          )}

          <Card variant="default" className="p-6">
            <h2 className="text-lg font-bold text-ink">준비되면 만들어요</h2>
            <ul className="mt-3 space-y-1.5 text-sm leading-relaxed text-ink-subtle">
              {info.covers.map((c) => (
                <li key={c}>• {c}</li>
              ))}
              <li>• 자동 점검만으로 모든 위험을 찾을 수는 없어요.</li>
            </ul>

            {error && (
              <div id="project-form-error" role="alert" aria-live="assertive" className="mt-5 rounded-xl border border-red-200 bg-danger-soft p-4 text-sm text-danger">
                {error}
              </div>
            )}

            <Button type="submit" size="lg" disabled={submitting} aria-busy={submitting} className="mt-5 w-full">
              <span aria-live="polite">
                {submitting ? "프로젝트를 만들고 있어요…" : "프로젝트 만들기"}
              </span>
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
  scanMode: ScanMode;
  testAccounts: { label: string; username: string; password: string }[];
}): FormData {
  const fd = new FormData();
  fd.set("name", input.name);
  fd.set("repositoryUrl", input.repositoryUrl);
  fd.set("deploymentUrl", input.deploymentUrl);
  fd.set("file", input.zipFile);
  fd.set("deploymentAuthorized", String(input.deploymentAuthorized));
  fd.set("scanMode", input.scanMode);
  if (input.testAccounts.length) fd.set("testAccounts", JSON.stringify(input.testAccounts));
  return fd;
}

function friendlyProjectError(error: unknown, message?: unknown) {
  if (typeof error === "string" && error in SCAN_MODE_ERROR_MESSAGE) {
    return SCAN_MODE_ERROR_MESSAGE[error as ScanModeValidationError];
  }
  if (error === "invalid_test_accounts") return "테스트 계정은 아이디와 비밀번호를 모두 입력해 주세요.";
  if (error === "invalid_scan_mode") return "점검 방법을 다시 선택해 주세요.";
  if (error === "forbidden") return "이 프로젝트를 만들 권한을 확인할 수 없어요. 로그인 상태를 확인해 주세요.";
  if (error === "invalid_url") return "입력한 주소 형식을 확인해 주세요. http 또는 https 주소를 사용할 수 있어요.";
  if (error === "file_too_large") return "ZIP 파일은 8MB 이하로 선택해 주세요.";
  if (error === "internal_error") return "지금은 프로젝트를 만들기 어려워요. 잠시 후 다시 시도해 주세요.";
  if (typeof message === "string" && message) return message;
  if (typeof error === "string" && /[가-힣]/.test(error)) return error;
  return "프로젝트를 만들 수 없어요. 입력한 주소와 파일을 확인한 뒤 다시 시도해 주세요.";
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      onClick={onClick}
      className={`min-h-9 rounded-lg px-4 text-sm font-semibold transition-colors ${
        active ? "bg-white text-brand-700 shadow-sm" : "text-ink-subtle hover:text-ink"
      }`}
    >
      {children}
    </button>
  );
}

function Field({
  id,
  label,
  hint,
  required,
  className = "",
  children,
}: {
  id: string;
  label: string;
  hint?: string;
  required?: boolean;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={className}>
      <label htmlFor={id} className="mb-2 block text-sm font-semibold text-ink">
        {label} {required && <span className="text-danger">(필수)</span>}
      </label>
      {children}
      {hint && <p id={`${id}-hint`} className="mt-2 text-sm leading-relaxed text-ink-muted">{hint}</p>}
    </div>
  );
}
