// 메모 보드: 보안 점검 연습용으로 일부러 취약하게 만든 작은 앱이에요. 인터넷에 공개하지 마세요.
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { DatabaseSync } = require("node:sqlite");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const EXPORT_SECRET = "memo-board-export-secret-2026";
const db = new DatabaseSync(":memory:");
db.exec(`
  CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, password TEXT, role TEXT);
  CREATE TABLE memos (id INTEGER PRIMARY KEY, owner_id INTEGER, text TEXT);
  INSERT INTO users VALUES (1, 'alice', 'alice123', 'user'), (2, 'bob', 'bob123', 'user'), (3, 'admin', 'admin123', 'admin');
  INSERT INTO memos VALUES (1, 1, '앨리스의 장보기 목록'), (2, 2, '밥의 비밀 메모: 금고 번호 4321'), (3, 3, '관리자 공지 초안');
`);
const sessions = new Map();

function requireLogin(req, res, next) {
  const sid = (req.headers.cookie || "").match(/sid=(\w+)/)?.[1];
  req.user = sessions.get(sid);
  if (!req.user) return res.status(401).json({ error: "로그인이 필요해요" });
  next();
}

app.post("/api/login", (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE name = ?").get(String(req.body.name));
  if (!user || user.password !== req.body.password) return res.status(401).json({ error: "이름이나 비밀번호가 틀렸어요" });
  const token = Math.random().toString(36).slice(2);
  sessions.set(token, { id: user.id, name: user.name, role: user.role });
  res.cookie("sid", token);
  res.json({ name: user.name, role: user.role });
});

app.get("/api/memos", requireLogin, (req, res) => {
  const q = req.query.q || "";
  const rows = db.prepare("SELECT id, text FROM memos WHERE owner_id = " + req.user.id + " AND text LIKE '%" + q + "%'").all();
  res.json(rows);
});

app.post("/api/memos", requireLogin, (req, res) => {
  const info = db.prepare("INSERT INTO memos (owner_id, text) VALUES (?, ?)").run(req.user.id, String(req.body.text || ""));
  res.json({ id: Number(info.lastInsertRowid) });
});

app.get("/api/memos/:id", requireLogin, (req, res) => {
  const memo = db.prepare("SELECT * FROM memos WHERE id = ?").get(req.params.id);
  if (!memo) return res.status(404).json({ error: "메모가 없어요" });
  res.json(memo);
});

app.delete("/api/admin/memos/:id", requireLogin, (req, res) => {
  db.prepare("DELETE FROM memos WHERE id = ?").run(req.params.id);
  res.json({ ok: true });
});

app.get("/api/preview", requireLogin, async (req, res) => {
  const r = await fetch(req.query.url);
  const html = await r.text();
  res.json({ title: (html.match(/<title>([^<]*)<\/title>/i) || [])[1] || "" });
});

app.get("/api/export", requireLogin, (req, res) => {
  const body = JSON.stringify(db.prepare("SELECT * FROM memos WHERE owner_id = ?").all(req.user.id));
  const signature = crypto.createHash("md5").update(body + EXPORT_SECRET).digest("hex");
  res.json({ body, signature });
});

app.get("/hello", (req, res) => {
  res.send("<h1>안녕하세요, " + req.query.name + "님</h1>");
});

app.listen(process.env.PORT || 4000, () => console.log("메모 보드: http://localhost:" + (process.env.PORT || 4000)));
