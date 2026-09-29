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
  if (!supportsNewToolCheck(check)) return gap(`아직 만들지 않은 검사라 하지 않았어요: ${check.toolId}/${check.id}`);
  try {
    if (["package_provenance_checker", "llm_integration_analyzer"].includes(check.toolId)) return await executeSourceTool(runtime, check);
    if (["baas_access_probe", "jwt_tamper_probe"].includes(check.toolId)) return await executeAccountTool(runtime, check);
    return await executeDeployedTool(runtime, check);
  } catch (error) {
    if (error instanceof SyntaxError) return gap("받은 데이터(JSON)의 형식을 읽지 못해 이 검사는 끝내지 못했어요.");
    return gap(error instanceof Error ? error.message : "검사 도구를 실행하지 못해 이 검사는 하지 않았어요.");
  }
}
