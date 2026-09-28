"use client";

import { useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { PageHeader } from "@/components/PageHeader";
import { Button, Card, Disclosure, FriendlyError } from "@/components/ui";
import {
  REQUIRED_TEST_ACCOUNTS,
  SCAN_MODE_ERROR_MESSAGE,
  SCAN_MODE_INFO,
  validateScanModeInput,
  type ScanMode,
  type ScanModeValidationError,
} from "@/lib/domain/scanMode";
import {
  MAX_ZIP_BYTES,
  nextTabIndex,
  projectEndpoint,
  validateProjectDraft,
  type TabKey,
} from "@/lib/ui/presentation";

// 밝은 입력 표면. 포커스 링은 globals.css의 :focus-visible(3px --focus)을 그대로 쓴다.
const inputClassName =
  "min-h-12 w-full rounded-2xl border-2 border-line-input bg-surface px-4 py-3 text-base text-ink transition-colors hover:border-line-strong aria-[invalid=true]:border-danger disabled:cursor-not-allowed disabled:bg-surface-warm disabled:text-ink-muted";

const ERROR_ID = "project-form-error";
const ZIP_TOO_LARGE_MESSAGE = "ZIP 파일은 8MB 이하로 선택해 주세요.";

type SourceTab = "zip" | "paste";
const SOURCE_TABS: readonly { key: SourceTab; label: string }[] = [
  { key: "zip", label: "ZIP 파일" },
  { key: "paste", label: "코드 붙여넣기" },
];
const TAB_KEYS: readonly TabKey[] = ["ArrowLeft", "ArrowRight", "Home", "End"];

interface AccountInput {
  username: string;
  password: string;
}

/** 제출 버튼 위에 FriendlyError로 보여줄 오류. `field`가 있으면 그 입력에 연결하고 포커스한다. */
interface FormError {
  title: string;
  description: string;
  field: string | null;
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
  const [error, setError] = useState<FormError | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);

  /** 입력의 설명(hint)과, 그 입력에 걸린 오류를 함께 연결한다. */
  function fieldA11y(id: string) {
    const invalid = error?.field === id;
    return {
      "aria-describedby": invalid ? `${id}-hint ${ERROR_ID}` : `${id}-hint`,
      "aria-invalid": invalid ? true : undefined,
    } as const;
  }

  function clearFieldError(id: string) {
    setError((prev) => (prev?.field === id ? null : prev));
  }

  /** 오류를 보여주고, 연결된 입력이 있으면 (필요 시 탭을 바꾼 뒤) 그 입력으로 포커스를 옮긴다. */
  function showError(next: FormError) {
    setError(next);
    const field = next.field;
    if (!field) return;
    if (field === "file") setSourceTab("zip");
    if (field === "sourceCode") setSourceTab("paste");
    // 탭 전환·aria-invalid 반영이 렌더링된 뒤 포커스한다.
    requestAnimationFrame(() => document.getElementById(field)?.focus());
  }

  function clearZip() {
    if (fileInputRef.current) fileInputRef.current.value = "";
    setZipFile(null);
  }

  function updateAccount(index: number, patch: Partial<AccountInput>) {
    setAccounts((prev) => prev.map((a, i) => (i === index ? { ...a, ...patch } : a)));
  }

  function selectTab(index: number) {
    const tab = SOURCE_TABS[index];
    if (!tab) return;
    setSourceTab(tab.key);
    tabRefs.current[index]?.focus();
  }

  function onTabKeyDown(e: React.KeyboardEvent<HTMLButtonElement>, index: number) {
    if (!(TAB_KEYS as readonly string[]).includes(e.key)) return;
    e.preventDefault();
    selectTab(nextTabIndex(index, e.key as TabKey, SOURCE_TABS.length));
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (submitting) return;
    setError(null);

    // 1) 이름·ZIP 크기: 서버로 보내기 전에 확인한다.
    const draftError = validateProjectDraft({ name, zipSize: zipFile?.size ?? null });
    if (draftError === "name_required") {
      showError({
        title: "프로젝트 이름이 비어 있어요",
        description: "프로젝트 이름을 입력한 뒤 다시 눌러 주세요.",
        field: "name",
      });
      return;
    }
    if (draftError === "zip_too_large") {
      clearZip();
      showError({
        title: "ZIP 파일이 너무 커요",
        description: `${ZIP_TOO_LARGE_MESSAGE} 다른 입력값은 그대로 두었어요.`,
        field: "file",
      });
      return;
    }

    // 2) 점검 방식별 입력 확인(기존 규칙 그대로).
    const testAccounts = isolated
      ? accounts.map((a, i) => ({
          label: `계정 ${String.fromCharCode(65 + i)}`,
          username: a.username.trim(),
          password: a.password,
        }))
      : [];
    if (isolated && testAccounts.some((a) => !a.username || !a.password)) {
      const emptyIndex = testAccounts.findIndex((a) => !a.username || !a.password);
      const emptyField = testAccounts[emptyIndex]?.username ? "password" : "username";
      showError({
        title: "테스트 계정 정보가 부족해요",
        description: `${SCAN_MODE_ERROR_MESSAGE.test_accounts_required} 비어 있는 칸을 채워 주세요.`,
        field: `account-${emptyIndex}-${emptyField}`,
      });
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
      showError({
        title: "입력을 조금만 더 채워 주세요",
        description: SCAN_MODE_ERROR_MESSAGE[invalid],
        field: scanModeErrorField(invalid, sourceTab),
      });
      return;
    }

    // 3) 기존 두 경로·본문 필드 그대로 요청한다.
    setSubmitting(true);
    const endpoint = projectEndpoint(Boolean(zipFile));
    try {
      const res = zipFile
        ? await fetch(endpoint, {
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
        : await fetch(endpoint, {
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
        setError({
          title: "프로젝트를 만들지 못했어요",
          description: friendlyProjectError(data?.error, data?.message),
          field: null,
        });
        setSubmitting(false);
        return;
      }
      router.push(`/dashboard/projects/${data.project.id}`);
    } catch {
      setError({
        title: "연결이 잠깐 끊겼어요",
        description: "인터넷 연결을 확인하고 다시 시도해 주세요. 입력한 내용은 그대로 두었어요.",
        field: null,
      });
      setSubmitting(false);
    }
  }

  function chooseZip(file: File | null) {
    clearFieldError("file");
    if (file && file.size > MAX_ZIP_BYTES) {
      clearZip();
      showError({
        title: "ZIP 파일이 너무 커요",
        description: ZIP_TOO_LARGE_MESSAGE,
        field: "file",
      });
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
        <form onSubmit={submit} noValidate className="space-y-5" aria-busy={submitting}>
          <Card variant="default" className="p-6">
            <Field
              id="name"
              label="프로젝트 이름"
              required
              hint="목록에서 이 프로젝트를 알아볼 수 있게 이름이 필요해요."
            >
              <input
                id="name"
                name="name"
                value={name}
                onChange={(e) => {
                  setName(e.target.value);
                  clearFieldError("name");
                }}
                required
                autoComplete="off"
                placeholder="예: 우리 동네 일정 앱"
                {...fieldA11y("name")}
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

            <div
              role="tablist"
              aria-label="코드 제공 방법"
              className="mt-4 inline-flex max-w-full gap-1 rounded-2xl border-2 border-line bg-surface-warm p-1"
            >
              {SOURCE_TABS.map((tab, index) => {
                const selected = sourceTab === tab.key;
                return (
                  <button
                    key={tab.key}
                    ref={(el) => {
                      tabRefs.current[index] = el;
                    }}
                    type="button"
                    role="tab"
                    id={`source-tab-${tab.key}`}
                    aria-selected={selected}
                    aria-controls={`source-panel-${tab.key}`}
                    tabIndex={selected ? 0 : -1}
                    onClick={() => setSourceTab(tab.key)}
                    onKeyDown={(e) => onTabKeyDown(e, index)}
                    className={`min-h-11 rounded-xl border-2 px-4 text-sm font-bold transition-colors ${
                      selected
                        ? "border-line-input bg-surface text-brand-800 shadow-[0_2px_0_var(--border-strong)]"
                        : "border-transparent text-ink-subtle hover:bg-surface hover:text-ink"
                    }`}
                  >
                    {tab.label}
                  </button>
                );
              })}
            </div>

            {/* 두 패널을 모두 렌더링하고 선택하지 않은 쪽은 hidden으로 숨겨 값(선택한 ZIP 포함)을 유지한다. */}
            <div
              id="source-panel-zip"
              role="tabpanel"
              aria-labelledby="source-tab-zip"
              hidden={sourceTab !== "zip"}
              className="mt-4"
            >
              <Field
                id="file"
                label="프로젝트 ZIP"
                hint="호이가 코드를 읽을 수 있게 8MB 이하의 .zip 파일을 올려 주세요."
              >
                <input
                  ref={fileInputRef}
                  id="file"
                  name="file"
                  type="file"
                  accept=".zip,application/zip"
                  onChange={(e) => chooseZip(e.target.files?.[0] ?? null)}
                  {...fieldA11y("file")}
                  className={`${inputClassName} p-2 text-sm file:mr-3 file:min-h-10 file:rounded-xl file:border-0 file:bg-primary-soft file:px-4 file:font-bold file:text-brand-800`}
                />
              </Field>
              {zipFile && (
                <p
                  className="mt-3 break-all rounded-2xl border border-[#bfe0c8] bg-success-soft px-4 py-3 text-sm font-semibold text-success"
                  role="status"
                >
                  {zipFile.name}을 선택했어요. 이 ZIP으로 점검해요.
                </p>
              )}
              <Disclosure summary="어떤 파일이 제외되나요?" className="mt-3">
                <p className="text-sm leading-relaxed text-ink-subtle">
                  node_modules, 빌드 결과물, 이미지 등 바이너리 파일은 자동으로 제외하고 코드만 읽어요.
                </p>
              </Disclosure>
            </div>

            <div
              id="source-panel-paste"
              role="tabpanel"
              aria-labelledby="source-tab-paste"
              hidden={sourceTab !== "paste"}
              className="mt-4"
            >
              <Field
                id="sourceCode"
                label="소스 코드 붙여넣기"
                hint="ZIP이 없을 때 호이가 코드를 직접 읽으려고 필요해요(여러 파일은 '// file: 경로'로 구분, 앞 100,000자까지 확인)."
              >
                <textarea
                  id="sourceCode"
                  name="sourceCode"
                  value={sourceCode}
                  onChange={(e) => {
                    setSourceCode(e.target.value);
                    clearFieldError("sourceCode");
                  }}
                  rows={9}
                  {...fieldA11y("sourceCode")}
                  placeholder={"// file: src/lib/profile.ts\nexport function publicProfile(user) {\n  return { name: user.name };\n}"}
                  className={`${inputClassName} min-h-52 resize-y font-mono text-sm`}
                />
              </Field>
            </div>

            <Field
              id="repositoryUrl"
              label="참고용 GitHub 주소(선택)"
              hint="어떤 저장소인지 참고로 기록해 두려고 받아요(저장소를 자동으로 내려받지는 않아요)."
              className="mt-5"
            >
              <input
                id="repositoryUrl"
                name="repositoryUrl"
                type="url"
                value={repositoryUrl}
                onChange={(e) => setRepositoryUrl(e.target.value)}
                placeholder="https://github.com/example/project"
                {...fieldA11y("repositoryUrl")}
                className={inputClassName}
              />
            </Field>
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
                hint="실제 서비스 응답을 확인하려면 본인이 소유하거나 점검 권한이 있는 http(s) 주소가 필요해요."
                className="mt-4"
              >
                <input
                  id="deploymentUrl"
                  name="deploymentUrl"
                  type="url"
                  required
                  value={deploymentUrl}
                  onChange={(e) => {
                    setDeploymentUrl(e.target.value);
                    clearFieldError("deploymentUrl");
                  }}
                  placeholder={isolated ? "https://staging.example.com" : "https://app.example.com"}
                  {...fieldA11y("deploymentUrl")}
                  className={inputClassName}
                />
              </Field>

              <label
                htmlFor="deploymentAuthorized"
                className={`mt-4 flex min-h-11 cursor-pointer items-start gap-3 rounded-2xl border-2 p-4 text-sm leading-relaxed text-ink ${
                  isolated ? "border-[#f3c4bd] bg-danger-soft" : "border-[#f0d9a6] bg-warning-soft"
                }`}
              >
                <input
                  id="deploymentAuthorized"
                  name="deploymentAuthorized"
                  type="checkbox"
                  checked={deploymentAuthorized}
                  onChange={(e) => {
                    setDeploymentAuthorized(e.target.checked);
                    clearFieldError("deploymentAuthorized");
                  }}
                  {...fieldA11y("deploymentAuthorized")}
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
              <p id="deploymentAuthorized-hint" className="mt-2 text-sm leading-relaxed text-ink-muted">
                권한이 있는 주소에만 요청을 보내려고 확인해요.
              </p>
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
                  const usernameId = `account-${i}-username`;
                  const passwordId = `account-${i}-password`;
                  return (
                    <fieldset key={letter} className="min-w-0 rounded-2xl border-2 border-line bg-surface p-4">
                      <legend className="px-1 text-base font-bold text-ink">계정 {letter}</legend>
                      <div className="space-y-3">
                        <Field
                          id={usernameId}
                          label="아이디 또는 이메일"
                          required
                          hint={`계정 ${letter}로 로그인해 다른 계정의 데이터가 보이는지 확인하려고 필요해요.`}
                        >
                          <input
                            id={usernameId}
                            value={acc.username}
                            onChange={(e) => {
                              updateAccount(i, { username: e.target.value });
                              clearFieldError(usernameId);
                            }}
                            required
                            autoComplete="off"
                            placeholder={`tester-${letter.toLowerCase()}@example.com`}
                            {...fieldA11y(usernameId)}
                            className={inputClassName}
                          />
                        </Field>
                        <Field
                          id={passwordId}
                          label="비밀번호"
                          required
                          hint="테스트 계정으로 로그인할 때만 쓰고 화면에 다시 보여주지 않아요."
                        >
                          <input
                            id={passwordId}
                            type="password"
                            value={acc.password}
                            onChange={(e) => {
                              updateAccount(i, { password: e.target.value });
                              clearFieldError(passwordId);
                            }}
                            required
                            autoComplete="new-password"
                            {...fieldA11y(passwordId)}
                            className={inputClassName}
                          />
                        </Field>
                      </div>
                    </fieldset>
                  );
                })}
              </div>
              <p className="mt-3 text-sm leading-relaxed text-ink-muted">
                실제 사용자 계정이 아닌 테스트 전용 계정을 사용해 주세요.
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
              <div id={ERROR_ID} className="mt-5">
                <FriendlyError title={error.title} description={error.description} />
              </div>
            )}

            <Button
              type="submit"
              size="lg"
              disabled={submitting}
              aria-busy={submitting}
              className="mt-5 w-full"
            >
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

/** 점검 방식 검증 오류를 연결할 입력 id. 소스 누락은 현재 보고 있는 탭의 입력으로 보낸다. */
function scanModeErrorField(error: ScanModeValidationError, tab: SourceTab): string {
  switch (error) {
    case "source_required":
      return tab === "zip" ? "file" : "sourceCode";
    case "deployment_required":
      return "deploymentUrl";
    case "authorization_required":
      return "deploymentAuthorized";
    case "test_accounts_required":
      return "account-0-username";
    case "test_accounts_distinct":
      return "account-1-username";
  }
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
  hint: string;
  required?: boolean;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={className}>
      <label htmlFor={id} className="mb-2 block text-sm font-bold text-ink">
        {label} {required && <span className="text-danger">(필수)</span>}
      </label>
      {children}
      <p id={`${id}-hint`} className="mt-2 text-sm leading-relaxed text-ink-muted">
        {hint}
      </p>
    </div>
  );
}
