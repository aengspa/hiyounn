// Benchmark fixtures for the scan → fix-all → re-verify loop.
// Fake secrets are assembled at runtime so no secret-shaped string is committed.
import { readFileSync } from "node:fs";

const here = (name) => new URL(`./fixtures/${name}`, import.meta.url);

export const FAKE_STRIPE_KEY = ["sk", "live", "51HxQpLKj3n4Vb8ZtQwErTyUiOpAsDfGh"].join("_");

export function loadFixture(name) {
  return readFileSync(here(name), "utf8").replaceAll("{{FAKE_STRIPE_KEY}}", FAKE_STRIPE_KEY);
}

/**
 * Planted bugs in shop-api.txt (ground truth for the benchmark):
 *   jwt-decode   src/lib/auth.js        jwt.decode instead of verify
 *   idor         src/routes/orders.js   GET /:orderId without owner check
 *   mass-assign  src/routes/profile.js  updateUser(id, req.body)
 *   bfla         src/routes/admin.js    DELETE /users/:userId without requireAdmin
 *   ssrf         src/routes/preview.js  fetch(req.query.url)
 *   weak-token   src/routes/reset.js    Math.random reset token
 *   dom-xss      public/comments.js     innerHTML with comment fields
 */
export const SHOP_PLANTED = [
  { id: "jwt-decode", file: "src/lib/auth.js", cls: ["jwt"] },
  { id: "idor", file: "src/routes/orders.js", cls: ["authz"] },
  { id: "mass-assign", file: "src/routes/profile.js", cls: ["massassign", "authz"] },
  { id: "bfla", file: "src/routes/admin.js", cls: ["authz"] },
  { id: "ssrf", file: "src/routes/preview.js", cls: ["ssrf"] },
  { id: "weak-token", file: "src/routes/reset.js", cls: ["random"] },
  { id: "dom-xss", file: "public/comments.js", cls: ["xss"] },
];
