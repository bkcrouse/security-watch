"use strict";

// Every string from the feeds goes through textContent, never innerHTML:
// advisory text is attacker-influenced.
const $ = (s) => document.querySelector(s);
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false)
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  return el;
}
const safeUrl = (u) => (/^https?:\/\//i.test(u || "") ? u : null);

const state = { q: "", sort: "priority", vendor: "", tier: "", hideWp: true, watched: false, limit: 150 };
let DATA = null;

const PREF_KEY = "security-watch:prefs";
try {
  const saved = JSON.parse(localStorage.getItem(PREF_KEY) || "{}");
  if (typeof saved.hideWp === "boolean") state.hideWp = saved.hideWp;
  if (saved.sort) state.sort = saved.sort;
} catch (_) { /* storage unavailable */ }
function savePrefs() {
  try { localStorage.setItem(PREF_KEY, JSON.stringify({ hideWp: state.hideWp, sort: state.sort })); } catch (_) {}
}

const isWp = (r) => (r.why || []).some((w) => w.startsWith("WordPress"));
const vendorOf = (r) => r.vendor || (r.products && r.products[0] && r.products[0].vendor) || "";

function ago(iso) {
  const s = (Date.now() - Date.parse(iso)) / 1000;
  if (s < 90) return "just now";
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 86400 * 2) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}
const daysUntil = (d) => Math.round((Date.parse(d + "T00:00:00Z") - Date.now()) / 86400000);

function filtered() {
  const q = state.q.trim().toLowerCase();
  let rows = DATA.items.filter((r) => {
    if (state.tier && r.tier !== state.tier) return false;
    if (state.watched && !r.watched) return false;
    if (state.hideWp && isWp(r)) return false;
    if (state.vendor && vendorOf(r).toLowerCase() !== state.vendor) return false;
    if (!q) return true;
    const hay = [r.id, r.ghsa, r.title, r.vendor, r.product,
      ...(r.products || []).flatMap((p) => [p.vendor, p.product])].join(" ").toLowerCase();
    return q.split(/\s+/).every((t) => hay.includes(t));
  });
  const by = {
    priority: (a, b) => b.priority - a.priority,
    date: (a, b) => (b.date || "").localeCompare(a.date || "") || b.priority - a.priority,
    score: (a, b) => (b.score || 0) - (a.score || 0) || b.priority - a.priority,
    epss: (a, b) => (b.epss || 0) - (a.epss || 0) || b.priority - a.priority,
  }[state.sort];
  return rows.sort(by);
}

function flags(r) {
  const f = [];
  if (r.watched) f.push(h("span", { class: "flag me", text: "watchlist" }));
  if (r.kind === "malware") f.push(h("span", { class: "flag hot", text: "malware" }));
  else if (r.exploited) f.push(h("span", { class: "flag hot", text: "exploited" }));
  if (r.ransomware) f.push(h("span", { class: "flag hot", text: "ransomware" }));
  if (r.kevDue) {
    const d = daysUntil(r.kevDue);
    if (d >= 0) f.push(h("span", { class: "flag" + (d <= 7 ? " hot" : ""), text: `due ${d}d` }));
  }
  if (r.epss != null && r.epss >= 0.1) f.push(h("span", { class: "flag", text: `EPSS ${Math.round(r.epss * 100)}%` }));
  if (!r.hasFix) f.push(h("span", { class: "flag", text: "no fix listed" }));
  f.push(h("span", { class: "date", text: r.date || "" }));
  return f;
}

function detail(r) {
  const prods = (r.products || []).filter((p) => p.product);
  const box = h("div", { class: "detail" },
    r.why && r.why.length ? h("ul", { class: "why" }, r.why.map((w) => h("li", { text: w }))) : null,
    r.note ? h("p", { class: "note", text: r.note }) : null,
    r.description ? h("p", { class: "desc", text: r.description }) : null,
    prods.length ? h("table", {},
      h("thead", {}, h("tr", {}, h("th", { text: "Product" }), h("th", { text: "Affected" }), h("th", { text: "Fixed in" }))),
      h("tbody", {}, prods.map((p) => h("tr", {},
        h("td", { text: [p.vendor, p.product].filter(Boolean).join(" / ") }),
        h("td", { class: "v", text: (p.affected || []).join(", ") || "see advisory" }),
        h("td", { class: "v", text: (p.fixed || []).join(", ") || "—" }))))) : null,
    r.action ? h("p", { class: "action", text: "CISA required action: " + r.action }) : null,
    h("div", { class: "links" },
      safeUrl(r.url) ? h("a", { href: r.url, target: "_blank", rel: "noopener", text: "Advisory ↗" }) : null,
      r.ghsa ? h("a", { href: `https://github.com/advisories/${encodeURIComponent(r.ghsa)}`, target: "_blank", rel: "noopener", text: r.ghsa + " ↗" }) : null,
      r.id.startsWith("CVE-") ? h("a", { href: `https://www.cve.org/CVERecord?id=${encodeURIComponent(r.id)}`, target: "_blank", rel: "noopener", text: "CVE.org ↗" }) : null,
      r.kevAdded ? h("a", { href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", target: "_blank", rel: "noopener", text: "CISA KEV ↗" }) : null));
  return box;
}

function label(r) {
  const v = vendorOf(r), p = r.product || "";
  if (!v && !p) return "Unassigned product";
  if (!p || p.toLowerCase() === v.toLowerCase() || p.toLowerCase().startsWith(v.toLowerCase() + " ")) return p || v;
  return `${v} ${p}`;
}
function shortTitle(r) {
  let t = r.title || r.id;
  const l = label(r);
  if (t.toLowerCase().startsWith(l.toLowerCase())) t = t.slice(l.length).replace(/^[\s:–—-]+/, "");
  return t || r.title || r.id;
}

function row(r) {
  const d = h("details", { class: "row", id: r.id },
    h("summary", {},
      h("span", { class: "tier " + r.tier, text: r.tier }),
      r.kind === "malware"
        ? h("span", { class: "sev" }, h("small", { text: "malware" }))
        : h("span", { class: "sev" }, r.score != null ? r.score.toFixed(1) : "—", " ",
            h("small", { text: r.severity ? r.severity.slice(0, 4).toLowerCase() : "" })),
      h("span", { class: "main" },
        h("span", { class: "t" },
          h("span", { class: "prod", text: label(r) }),
          " — ", shortTitle(r)),
        h("span", { class: "id", text: r.id })),
      h("span", { class: "flags" }, flags(r))));
  d.addEventListener("toggle", () => {
    if (d.open && !d.querySelector(".detail")) d.append(detail(r));
  }, { once: false });
  return d;
}

function render() {
  const rows = filtered();
  const list = $("#rows");
  list.replaceChildren();
  if (!rows.length) list.append(h("li", { class: "empty", text: "Nothing matches these filters." }));
  rows.slice(0, state.limit).forEach((r) => list.append(h("li", {}, row(r))));
  if (rows.length > state.limit) {
    const more = h("li", { class: "empty" }, h("button", { class: "link", text: `Show ${Math.min(150, rows.length - state.limit)} more` }));
    more.querySelector("button").onclick = () => { state.limit += 150; render(); };
    list.append(more);
  }
  $("#count").textContent = `${rows.length} of ${DATA.items.length} shown`;
  document.querySelectorAll(".tiers button").forEach((b) => b.classList.toggle("on", b.dataset.t === state.tier));
}

function header() {
  const s = DATA.summary;
  $("#s-act").textContent = s.actNow;
  $("#s-watched").textContent = s.watched;
  $("#s-kev").textContent = s.exploited7d;
  $("#s-crit").textContent = s.critical24h;
  $("#s-due").textContent = s.nextDue ? s.nextDue.slice(5) : "none";
  const upd = $("#updated");
  upd.textContent = `Updated ${ago(DATA.generated)}`;
  upd.title = DATA.generated;

  const vendors = [...new Set(DATA.items.map(vendorOf).filter(Boolean))]
    .sort((a, b) => a.localeCompare(b));
  const sel = $("#vendor");
  vendors.forEach((v) => sel.append(h("option", { value: v.toLowerCase(), text: v })));

  const dl = $("#deadlines");
  dl.replaceChildren();
  if (!DATA.deadlines.length) dl.append(h("li", {}, h("span", { class: "p small", text: "No open deadlines." })));
  DATA.deadlines.forEach((d) => {
    const n = daysUntil(d.due);
    const a = h("a", { href: "#" + d.id, text: d.id });
    a.onclick = (e) => { e.preventDefault(); openRow(d.id); };
    dl.append(h("li", {},
      h("span", { class: "d" + (n <= 7 ? " soon" : ""), text: d.due.slice(5) }),
      h("span", { class: "p" }, [d.vendor, d.product].filter(Boolean).join(" "), a)));
  });

  const w = DATA.windows;
  $("#method").textContent =
    `Shows everything CISA added to its exploited list in the last ${w.kevDays} days, CVEs rated critical (CVSS 9+) ` +
    `in the last ${w.criticalDays} days, and malicious npm/PyPI packages with at least ${w.malwareMinDownloads.toLocaleString()} ` +
    `monthly downloads. "Most important" weighs exploitation in the wild, ransomware use, EPSS, CVSS, how widely used and ` +
    `internet-facing the product is, your watchlist, CISA deadlines and age. WordPress plugin flaws rank lower.`;
}

function openRow(id) {
  Object.assign(state, { q: "", tier: "", vendor: "", watched: false, hideWp: false });
  syncControls(); render();
  const el = document.getElementById(id);
  if (el) { el.open = true; el.scrollIntoView({ behavior: "smooth", block: "center" }); }
}

function syncControls() {
  $("#q").value = state.q;
  $("#sort").value = state.sort;
  $("#vendor").value = state.vendor;
  $("#hidewp").checked = state.hideWp;
}

function wire() {
  let t;
  $("#q").addEventListener("input", (e) => { clearTimeout(t); t = setTimeout(() => { state.q = e.target.value; state.limit = 150; render(); }, 120); });
  $("#sort").addEventListener("change", (e) => { state.sort = e.target.value; savePrefs(); render(); });
  $("#vendor").addEventListener("change", (e) => { state.vendor = e.target.value; render(); });
  $("#hidewp").addEventListener("change", (e) => { state.hideWp = e.target.checked; savePrefs(); render(); });
  document.querySelectorAll(".tiers button").forEach((b) =>
    b.addEventListener("click", () => { state.tier = b.dataset.t; state.watched = false; render(); }));
  document.querySelector('.stat[data-tier="act"]').addEventListener("click", () => { state.tier = "act"; state.watched = false; render(); });
  document.querySelector('.stat[data-filter="watched"]').addEventListener("click", () => { state.watched = true; state.tier = ""; render(); });
  $("#reset").addEventListener("click", () => {
    Object.assign(state, { q: "", sort: "priority", vendor: "", tier: "", hideWp: true, watched: false, limit: 150 });
    savePrefs(); syncControls(); render();
  });
}

async function load() {
  try {
    const res = await fetch("data.json", { cache: "no-cache" });
    if (!res.ok) throw new Error(res.status);
    DATA = await res.json();
  } catch (e) {
    $("#updated").textContent = "Couldn't load data";
    $("#rows").replaceChildren(h("li", { class: "empty", text: "data.json didn't load. The first build may still be running." }));
    return;
  }
  header(); syncControls(); wire(); render();
  if (location.hash.length > 1) openRow(decodeURIComponent(location.hash.slice(1)));
  // Pick up the next build without a manual reload.
  setInterval(async () => {
    try {
      const r = await fetch("data.json", { cache: "no-cache" });
      const fresh = await r.json();
      if (fresh.generated !== DATA.generated) { DATA = fresh; $("#updated").textContent = `Updated ${ago(DATA.generated)}`; render(); }
      else $("#updated").textContent = `Updated ${ago(DATA.generated)}`;
    } catch (_) {}
  }, 5 * 60 * 1000);
}
load();
