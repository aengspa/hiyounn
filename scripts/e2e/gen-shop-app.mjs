// Generates fixtures/shop-api.txt: a 19-file Express shop API with 7 planted bugs
// (see SHOP_PLANTED in fixtures.mjs). Output uses the paste format ("// file: path").
import { writeFileSync } from "node:fs";

const files = {};
files["package.json"] = JSON.stringify({ name: "shop-api", dependencies: { express: "4.21.2", jsonwebtoken: "9.0.2", "node-fetch": "3.3.2" } }, null, 2);
files["src/app.js"] = `const express = require("express");
const { requireLogin } = require("./lib/auth");
const app = express();
app.use(express.json({ limit: "100kb" }));
app.use("/api/orders", requireLogin, require("./routes/orders"));
app.use("/api/profile", requireLogin, require("./routes/profile"));
app.use("/api/admin", requireLogin, require("./routes/admin"));
app.use("/api/preview", requireLogin, require("./routes/preview"));
app.use("/api/reset", require("./routes/reset"));
app.listen(process.env.PORT || 3000);
`;
files["src/lib/auth.js"] = `const jwt = require("jsonwebtoken");
const { findUserById } = require("../db/users");

async function requireLogin(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "login required" });
  const claims = jwt.decode(token);
  if (!claims || !claims.sub) return res.status(401).json({ error: "invalid token" });
  const user = await findUserById(claims.sub);
  if (!user) return res.status(401).json({ error: "unknown user" });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user && req.user.role === "admin") return next();
  return res.status(403).json({ error: "forbidden" });
}

module.exports = { requireLogin, requireAdmin };
`;
files["src/routes/orders.js"] = `const router = require("express").Router();
const orders = require("../db/orders");
const { toPublicOrder } = require("../lib/serializers");

router.get("/", async (req, res) => {
  const list = await orders.listByOwner(req.user.id);
  res.json(list.map(toPublicOrder));
});

router.get("/:orderId", async (req, res) => {
  const order = await orders.findById(req.params.orderId);
  if (!order) return res.status(404).json({ error: "not found" });
  res.json(toPublicOrder(order));
});

router.post("/:orderId/cancel", async (req, res) => {
  const order = await orders.findById(req.params.orderId);
  if (!order || order.ownerId !== req.user.id) return res.status(404).json({ error: "not found" });
  if (order.status !== "pending") return res.status(409).json({ error: "cannot cancel" });
  await orders.updateStatus(order.id, "cancelled");
  res.json({ ok: true });
});

module.exports = router;
`;
files["src/routes/profile.js"] = `const router = require("express").Router();
const users = require("../db/users");

router.get("/", (req, res) => {
  const { id, email, displayName } = req.user;
  res.json({ id, email, displayName });
});

router.patch("/", async (req, res) => {
  const updated = await users.updateUser(req.user.id, req.body);
  res.json({ id: updated.id, email: updated.email, displayName: updated.displayName });
});

module.exports = router;
`;
files["src/routes/admin.js"] = `const router = require("express").Router();
const users = require("../db/users");
const { requireAdmin } = require("../lib/auth");

router.get("/users", requireAdmin, async (req, res) => {
  res.json(await users.listUsers());
});

router.delete("/users/:userId", async (req, res) => {
  await users.deleteUser(req.params.userId);
  res.status(204).end();
});

module.exports = router;
`;
files["src/routes/preview.js"] = `const router = require("express").Router();

router.get("/", async (req, res) => {
  const target = req.query.url;
  if (typeof target !== "string") return res.status(400).json({ error: "url required" });
  const r = await fetch(target);
  const html = await r.text();
  const title = (html.match(/<title>([^<]*)<\\/title>/i) || [])[1] || "";
  res.json({ title: title.slice(0, 200) });
});

module.exports = router;
`;
files["src/routes/reset.js"] = `const router = require("express").Router();
const users = require("../db/users");
const { sendMail } = require("../lib/mail");

router.post("/request", async (req, res) => {
  const user = await users.findUserByEmail(String(req.body.email || ""));
  if (user) {
    const token = Math.random().toString(36).slice(2);
    await users.saveResetToken(user.id, token, Date.now() + 15 * 60 * 1000);
    await sendMail(user.email, "Reset your password", "Token: " + token);
  }
  res.json({ ok: true });
});

module.exports = router;
`;
files["public/comments.js"] = `async function loadComments(orderId) {
  const res = await fetch("/api/orders/" + encodeURIComponent(orderId) + "/comments");
  const comments = await res.json();
  const list = document.getElementById("comments");
  list.innerHTML = "";
  for (const c of comments) {
    const item = document.createElement("li");
    item.innerHTML = \`<strong>\${c.author}</strong><p>\${c.body}</p>\`;
    list.appendChild(item);
  }
}
`;
files["src/lib/serializers.js"] = `function toPublicOrder(o) {
  return { id: o.id, status: o.status, total: o.total, items: o.items.map((i) => ({ sku: i.sku, qty: i.qty })) };
}
module.exports = { toPublicOrder };
`;
files["src/lib/mail.js"] = `async function sendMail(to, subject, text) {
  if (!process.env.MAIL_API_URL) throw new Error("mail not configured");
  await fetch(process.env.MAIL_API_URL, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ to, subject, text }) });
}
module.exports = { sendMail };
`;
for (const name of ["catalog", "inventory", "pricing", "shipping", "tax", "coupons", "reviews", "analytics"]) {
  const Cap = name[0].toUpperCase() + name.slice(1);
  files[`src/services/${name}.js`] = `// ${name} service: pure helpers, no I/O.
function normalize${Cap}Input(input) {
  const out = {};
  for (const [k, v] of Object.entries(input || {})) {
    if (typeof v === "string") out[k] = v.trim().slice(0, 200);
    else if (typeof v === "number" && Number.isFinite(v)) out[k] = v;
  }
  return out;
}

function summarize(items) {
  let count = 0;
  let total = 0;
  for (const item of items) {
    if (!item || typeof item.amount !== "number") continue;
    count += 1;
    total += Math.round(item.amount * 100) / 100;
  }
  return { count, total, average: count ? Math.round((total / count) * 100) / 100 : 0 };
}

function paginate(list, page = 1, size = 20) {
  const safeSize = Math.min(Math.max(1, size | 0), 100);
  const safePage = Math.max(1, page | 0);
  const start = (safePage - 1) * safeSize;
  return { page: safePage, size: safeSize, total: list.length, items: list.slice(start, start + safeSize) };
}

function groupBy(list, key) {
  const groups = new Map();
  for (const item of list) {
    const k = item[key];
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(item);
  }
  return Object.fromEntries(groups);
}

module.exports = { normalize${Cap}Input, summarize, paginate, groupBy };
`;
}

const blob = Object.entries(files).map(([p, c]) => `// file: ${p}\n${c.trimEnd()}`).join("\n");
writeFileSync(new URL("./fixtures/shop-api.txt", import.meta.url), blob + "\n");
console.log(`shop-api fixture: ${Object.keys(files).length} files, ${blob.length} chars`);
