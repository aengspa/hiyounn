import type { Check } from "@/lib/rules/types";
import { executeSourceTool } from "@/lib/scanners/sourceRuleTools";
import { executeDeployedTool } from "@/lib/scanners/deployedRuleTools";
import { executeAccountTool } from "@/lib/scanners/accountRuleTools";
import { gap, type RuleToolRuntime, type ToolResult } from "@/lib/scanners/ruleToolRuntime";

/** A catalog registration must have an executable handler and explicit check support. */
export const NEW_TOOL_CHECKS: Readonly<Record<string, readonly string[]>> = {
  package_provenance_checker: ["registry-existence", "typosquat-similarity", "install-script-audit", "package-age-popularity"],
  llm_integration_analyzer: ["scan-secret-in-system-prompt", "scan-llm-output-to-sink", "scan-llm-tool-permissions", "scan-llm-output-rendered-html"],
  bundle_secret_scanner: ["fetch-and-scan-bundles", "extract-baas-public-config"],
  redirect_probe: ["probe-open-redirect"],
  error_probe: ["probe-error-leak"],
  llm_prompt_probe: ["probe-system-prompt-leak"],
  baas_access_probe: ["supabase-list-exposed-tables", "supabase-anon-select", "firebase-anon-read", "storage-anon-list", "rls-cross-user-read", "rls-cross-user-update", "rls-owner-read"],
  jwt_tamper_probe: ["jwt-alg-none", "jwt-signature-stripped", "jwt-subject-swapped"],
};

export function supportsNewToolCheck(check: Check): boolean {
  return NEW_TOOL_CHECKS[check.toolId]?.includes(check.id) ?? false;
}

export async function executeNewToolCheck(runtime: RuleToolRuntime, check: Check): Promise<ToolResult> {
  if (!supportsNewToolCheck(check)) return gap(`구현되지 않은 체크: ${check.toolId}/${check.id}`);
  try {
    if (["package_provenance_checker", "llm_integration_analyzer"].includes(check.toolId)) return await executeSourceTool(runtime, check);
    if (["baas_access_probe", "jwt_tamper_probe"].includes(check.toolId)) return await executeAccountTool(runtime, check);
    return await executeDeployedTool(runtime, check);
  } catch (error) {
    if (error instanceof SyntaxError) return gap("도구 입력/응답 JSON을 해석하지 못했습니다.");
    return gap(error instanceof Error ? error.message : "도구 실행 실패 — 점검하지 못했습니다.");
  }
}
