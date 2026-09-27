import type { Project } from "@/lib/domain/types";
import type { ProjectContext } from "@/lib/scanners/types";
import { buildDemoContext } from "@/lib/demo/demoContext";
import { buildProjectContext } from "@/lib/demo/sourceFiles";

/**
 * Build the scan context for a project.
 *
 * - Demo project (project.isDemo): the bundled vulnerable fixture, so the IDOR
 *   full-loop demo works. The demo fixture is used ONLY here.
 * - Real project: a context built from the project's OWN source only (pasted
 *   blob split on `// file:` markers, or an uploaded file map). No demo
 *   vulnerabilities are ever mixed into a real project's results.
 */
export function contextForProject(
  project: Project,
  opts?: {
    /** Demo-only: reflect the applied fix in the handler. */
    fixedHandler?: boolean;
    /** Pre-split file map for real projects (e.g. from a ZIP upload). */
    files?: Record<string, string>;
  }
): ProjectContext {
  const commit = project.currentCommit ?? "b72c42d";

  if (project.isDemo) {
    return buildDemoContext(project.id, {
      name: project.name,
      repositoryUrl: project.repositoryUrl,
      deploymentUrl: project.deploymentUrl,
      commitSha: commit,
      fixedHandler: opts?.fixedHandler,
    });
  }

  return buildProjectContext(project.id, {
    name: project.name,
    repositoryUrl: project.repositoryUrl,
    deploymentUrl: project.deploymentUrl,
    commitSha: commit,
    files: opts?.files,
    sourceBlob: project.sourceCode,
    deploymentAuthorized: project.deploymentAuthorized,
  });
}
