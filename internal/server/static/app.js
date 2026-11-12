"use strict";
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
const SEV = ["", "info", "low", "high", "critical"];
const clock = (iso) => new Date(iso).toISOString().slice(11, 19);

function row(e, fresh) {
  const r = el("div", "row"); if (!fresh) r.style.animation = "none";
  r.append(el("span", "pill s" + e.severity, SEV[e.severity]));
  const mid = el("div"); mid.append(el("div", "t", `${e.summary}`), el("div", "m mono", `${e.service} · ${e.source}${e.detail ? " · " + e.detail : ""}`));
  r.append(mid, el("span", "m", clock(e.time)));
  return r;
}
function bars(target, items, cls) {
  const max = Math.max(1, ...items.map((i) => i.count));
  target.replaceChildren(...items.map((i) => {
    const b = el("div", "bar"), t = el("div", "tr"), f = el("div", "f"); f.style.width = (i.count / max) * 100 + "%"; t.append(f);
    const nm = el("span", (cls || "") + " nm", i.name); nm.title = i.name; b.append(nm, t, el("span", "n", String(i.count))); return b;
  }));
}
function spark(vals) {
  const c = $("spark"), x = c.getContext("2d"), w = c.width, h = c.height, max = Math.max(1, ...vals);
  x.clearRect(0, 0, w, h); x.strokeStyle = "#f5a524"; x.lineWidth = 2; x.beginPath();
  vals.forEach((v, i) => { const px = (i / Math.max(1, vals.length - 1)) * (w - 10) + 5, py = h - 8 - (v / max) * (h - 18); i ? x.lineTo(px, py) : x.moveTo(px, py); }); x.stroke();
  x.lineTo(w - 5, h - 4); x.lineTo(5, h - 4); x.closePath(); x.fillStyle = "#f5a52422"; x.fill();
}
async function refresh() {
  try {
    const s = await (await fetch("/api/stats")).json();
    $("k-total").textContent = s.total; $("k-src").textContent = s.sources;
    $("k-cred").textContent = s.top_credentials.length; $("k-ioc").textContent = s.iocs.length;
    spark(s.per_minute);
    bars($("kinds"), s.by_kind); bars($("sources"), s.top_sources, "mono"); bars($("creds"), s.top_credentials, "mono"); bars($("paths"), s.top_paths, "mono"); bars($("iocs"), s.iocs, "mono");
  } catch (_) {}
}
(async () => {
  const first = await (await fetch("/api/events?limit=40")).json();
  $("feed").replaceChildren(...first.map((e) => row(e, false)));
  const es = new EventSource("/events");
  es.onopen = () => { $("dot").classList.add("on"); $("livetxt").textContent = "capturing"; };
  es.onerror = () => { $("dot").classList.remove("on"); $("livetxt").textContent = "reconnecting"; };
  es.onmessage = (m) => { const f = $("feed"); f.prepend(row(JSON.parse(m.data), true)); while (f.children.length > 60) f.lastChild.remove(); };
  refresh(); setInterval(refresh, 1500);
})();
