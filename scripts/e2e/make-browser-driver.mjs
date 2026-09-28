// Writes .local/e2e-driver.js: a script to run inside a logged-in browser tab
// (e.g. `browse eval .local/e2e-driver.js`). It drives the full loop through the
// HTTP API for each benchmark app and stores a summary on window.__e2e.
import { mkdirSync, writeFileSync } from "node:fs";
import { loadFixture } from "./fixtures.mjs";

const apps = { "vuln-express": loadFixture("vuln-express.txt"), "shop-api": loadFixture("shop-api.txt") };

const driver = `
window.__e2e = {}; window.__e2eDone = false;
(async () => {
  const APPS = ${JSON.stringify(apps)};
  const j = async (r) => { try { return await r.json(); } catch { return null; } };
  const post = (url, body) => fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body ?? {}) });
  const summarize = (d) => (d.findings || []).map((f) => ({ id: f.id, key: (f.verificationKey || "").split(":")[0], cwe: f.cwe || "", sev: f.severity,
    loc: f.location ? f.location.file + ":" + f.location.line : "-", title: f.title.slice(0, 40), review: f.aiReview ? f.aiReview.verdict + (f.aiReview.adjudication ? "/" + f.aiReview.adjudication.verdict : "") : "",
    also: (f.corroboratedBy || []).join("+"), carried: Boolean(f.carriedOverFromScanId) }));
  for (const [name, src] of Object.entries(APPS)) {
    const out = { steps: {} };
    try {
      const p = await j(await post("/api/projects", { name: name + " (e2e)", sourceCode: src }));
      out.projectId = p.project.id;
      let t = Date.now();
      const s = await j(await post("/api/projects/" + p.project.id + "/scan"));
      out.steps.scan = Date.now() - t;
      const d = await j(await fetch("/api/scans/" + s.scan.id));
      const scope = (d.scan || d).scope;
      out.scanId = s.scan.id;
      out.coverage = scope.aiCoverage; out.semgrep = scope.semgrep; out.routes = (scope.authzMatrix || []).length;
      out.findings = summarize(d);
      t = Date.now();
      const f = await j(await post("/api/scans/" + s.scan.id + "/fix-all"));
      out.steps.fixAll = Date.now() - t;
      out.jobId = f.job.id; out.fixStatus = f.job.status;
      out.fix = f.job.items.map((i) => ({ id: i.findingId, outcome: i.outcome, how: i.fixSource || i.reasonCode || "", edits: (i.edits || []).length }));
      const diff = await j(await fetch("/api/fix-jobs/" + f.job.id + "/diff"));
      out.diffFiles = (diff.files || []).map((x) => x.path + " -" + x.removed + "+" + x.added);
      if (f.job.artifact) {
        t = Date.now();
        const v = await j(await fetch("/api/fix-jobs/" + f.job.id + "/verify", { method: "POST" }));
        out.steps.reverify = Date.now() - t;
        const ver = v.job.verification;
        out.verifyStatus = ver.status + "/" + ver.aiStatus;
        out.verify = ver.items.map((i) => ({ id: i.findingId, verdict: i.verdict, method: i.method || "", code: i.reasonCode || "", rule: i.ruleVerdict || "", ai: i.aiVerdict || "",
          exploit: i.exploit ? i.exploit.status : "", comments: [i.ruleSummary ? "rule" : "", i.aiSummary ? "ai" : ""].filter(Boolean).join("+") }));
      }
      if (name === "vuln-express") {
        const changed = src.replace("app.listen(3000);", "app.get(\\"/health\\", (req, res) => res.json({ ok: true }));\\napp.listen(3000);");
        const up = await j(await post("/api/projects/" + p.project.id + "/versions", { sourceCode: changed }));
        out.reupload = up.changedFiles;
        const s2 = await j(await post("/api/projects/" + p.project.id + "/scan"));
        const d2 = await j(await fetch("/api/scans/" + s2.scan.id));
        out.incremental = (d2.scan || d2).scope.incremental;
        out.incrementalFindings = summarize(d2).length;
      }
    } catch (e) { out.error = String(e && e.stack || e); }
    window.__e2e[name] = out;
  }
  window.__e2eDone = true;
})();
"started";
`;
mkdirSync(new URL("../../.local/", import.meta.url), { recursive: true });
writeFileSync(new URL("../../.local/e2e-driver.js", import.meta.url), driver);
console.log("wrote .local/e2e-driver.js");
