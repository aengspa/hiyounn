import type { Condition, ScanMode, Selector } from "@/lib/rules/types";
import type { ProjectContext } from "@/lib/scanners/types";

export function modeForContext(context: ProjectContext): ScanMode {
  return context.scanMode ?? (context.isUserProject === false ? "C" : context.deploymentUrl ? "B" : "A");
}

function fieldValue(field: string, context: ProjectContext): unknown {
  const paths = Object.keys(context.files);
  const source = Object.values(context.files).join("\n");
  const providers = [...new Set([...(context.stack.baas ?? []), ...(context.linkedBaasProjects ?? []).map((p) => p.provider)])];
  if (field === "source.access") return paths.length ? "read_only" : undefined;
  if (field === "source.gitHistory") return context.gitHistoryAvailable ? true : undefined;
  if (field === "environment.testOrigin") return context.deploymentUrl;
  if (field === "components.provider") return providers;
  if (field === "components.kind") {
    const kinds = ["web"];
    if (/\/api\/|(?:^|\/)api\//.test(paths.join(" ")) || /express|NextResponse|Response\.json|res\.json|createServer|app\.(?:get|post)/.test(source)) kinds.push("api");
    if (providers.length) kinds.push("baas");
    return kinds;
  }
  const capabilities: Record<string, boolean> = {
    dependency_manifest: paths.some((p) => /(?:^|\/)(?:package\.json|requirements\.txt|pyproject\.toml)$/.test(p)),
    lockfile: paths.some((p) => /(?:^|\/)(?:package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lock|poetry\.lock|uv\.lock)$/.test(p)),
    authentication: /auth|session|jwt|login|currentUser/i.test(source) || Boolean(context.testSessions),
    custom_password_auth: /password.*(?:hash|bcrypt|argon|scrypt)|(?:hash|bcrypt|argon|scrypt).*password/i.test(source),
    user_owned_data: /owner_id|ownerId|user_id|userId|auth\.uid|where\s*:\s*\{\s*id/.test(source) || Boolean(context.testObjects),
    jwt_auth: /jwt|jsonwebtoken|jose|Bearer|eyJ/i.test(source) || Boolean(context.testSessions),
    cookie_auth: /cookie|session|Set-Cookie/i.test(source),
    llm_usage: /openai|anthropic|langchain|generateText|chat\.completions|responses\.create/i.test(source) || Boolean(context.llmProbeEndpoint),
    outbound_messaging: /twilio|sendgrid|resend|nodemailer|sendSms/i.test(source),
    file_upload: /multer|multipart|upload|formData/i.test(source),
    webhook_receiver: /webhook/i.test(source),
    object_storage: /storage|bucket|supabase|firebase/i.test(source) || providers.length > 0,
    firebase_rules_file: paths.some((p) => /(?:firestore\.rules|storage\.rules|database\.rules\.json)$/.test(p)),
  };
  if (field.startsWith("capabilities.")) {
    const key = field.slice("capabilities.".length);
    return capabilities[key] ? "detected" : paths.length && key in capabilities ? "not_detected" : "unknown";
  }
  return undefined;
}

export function conditionMatches(condition: Condition, context: ProjectContext): boolean {
  const actual = fieldValue(condition.field, context);
  switch (condition.op) {
    case "equals": return actual === condition.value;
    case "not_equals": return actual !== condition.value;
    case "exists": return actual !== undefined && actual !== null && actual !== "";
    case "contains": return Array.isArray(actual) ? actual.includes(condition.value) : typeof actual === "string" && typeof condition.value === "string" && actual.includes(condition.value);
    case "in": return Array.isArray(condition.value) && condition.value.includes(actual);
  }
}

export function selectorMatches(selector: Selector, context: ProjectContext): boolean {
  const match = (clause: Condition | Selector) => "field" in clause ? conditionMatches(clause, context) : selectorMatches(clause, context);
  return (selector.all?.every(match) ?? true) && (selector.any?.some(match) ?? true);
}
