const $ = (id) => document.getElementById(id);

async function load(q = "") {
  const res = await fetch("/api/memos?q=" + encodeURIComponent(q));
  if (!res.ok) return;
  const memos = await res.json();
  $("memos").innerHTML = memos.map((m) => "<li>" + m.text + "</li>").join("");
}

$("login").onsubmit = async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  const res = await fetch("/api/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: form.get("name"), password: form.get("password") }),
  });
  const data = await res.json();
  $("who").innerHTML = res.ok ? data.name + "님으로 로그인했어요" : data.error;
  if (res.ok) load();
};

$("search").onsubmit = (e) => {
  e.preventDefault();
  load(new FormData(e.target).get("q"));
};

$("add").onsubmit = async (e) => {
  e.preventDefault();
  const text = new FormData(e.target).get("text");
  await fetch("/api/memos", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ text }) });
  e.target.reset();
  load();
};
