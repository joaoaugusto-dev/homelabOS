"use strict";
/* homelabOS: painel. JS puro, sem dependências. */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
const EASE = "cubic-bezier(0.23, 1, 0.32, 1)";

function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const k in attrs || {}) {
    if (k === "class") e.className = attrs[k];
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), attrs[k]);
    else e.setAttribute(k, attrs[k]);
  }
  for (const c of kids) if (c != null) e.append(c.nodeType ? c : document.createTextNode(c));
  return e;
}
const icon = (id, cls = "") => {
  const s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  s.setAttribute("class", "ic " + cls);
  s.innerHTML = `<use href="#i-${id}"/>`;
  return s;
};

/* ---------- formatação (pt-BR) ---------- */
const nf = (d) => new Intl.NumberFormat("pt-BR", { minimumFractionDigits: d, maximumFractionDigits: d });
const nf0 = nf(0), nf1 = nf(1), nf2 = nf(2), nf3 = nf(3);
const brl = (d) => new Intl.NumberFormat("pt-BR", { style: "currency", currency: "BRL", minimumFractionDigits: d, maximumFractionDigits: d });
const brl2 = brl(2), brl3 = brl(3);
const money = (v) => (v < 1 ? brl3 : brl2).format(v);
const fWatts = (v) => (v < 100 ? nf1 : nf0).format(v);
function bytes(n) {
  const u = ["B", "KB", "MB", "GB", "TB", "PB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${(n < 10 && i ? nf1 : nf0).format(n)} ${u[i]}`;
}
function rateUnit(b) { return b < 1024 ? ["B/s", 1] : b < 1048576 ? ["KB/s", 1024] : ["MB/s", 1048576]; }
function dur(s) {
  const d = Math.floor(s / 86400), hh = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d} d ${hh} h` : hh ? `${hh} h ${m} min` : `${m} min`;
}
const ago = (k) => (k < 1 ? "agora" : k < 60 ? `há ${k} s` : `há ${Math.round(k / 60)} min`);
const fDate = (ms) => new Date(ms * 1000).toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit", year: "2-digit" }) + " " + new Date(ms * 1000).toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" });

/* ---------- estado ---------- */
const CAP = 600;
const H = { end: 0, cpu: [], temp: [], w: [], rx: [], tx: [], mem: [] };
let S = null, lastSample = performance.now(), days = [];

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast.t);
  toast.t = setTimeout(() => t.classList.remove("show"), 2600);
}

async function api(url, opt) {
  const r = await fetch(url, { credentials: "same-origin", ...opt, headers: { "X-Requested-With": "homelabos", ...(opt && opt.headers) } });
  if (r.status === 401 && !url.startsWith("/api/login")) { showLogin(); throw new Error("login"); }
  return r;
}
async function errMsg(r) { try { return (await r.json()).error; } catch { return "erro inesperado"; } }

/* ---------- números animados ---------- */
const tweens = new Map();
function num(el, v, fmt) {
  if (!el) return;
  let t = tweens.get(el);
  if (!t) { tweens.set(el, { cur: v, from: v, to: v, t0: 0, fmt }); el.textContent = fmt(v); return; }
  t.fmt = fmt;
  if (reduce) { t.cur = t.to = v; el.textContent = fmt(v); return; }
  if (t.to === v) return;
  t.from = t.cur; t.to = v; t.t0 = performance.now();
}
function stepTweens(now) {
  for (const [el, t] of tweens) {
    if (!t.t0) continue;
    const p = Math.min(1, (now - t.t0) / 650), e = 1 - Math.pow(1 - p, 3);
    t.cur = t.from + (t.to - t.from) * e;
    el.textContent = t.fmt(t.cur);
    if (p === 1) t.t0 = 0;
  }
}

/* ---------- gráfico em canvas ---------- */
const charts = [];
const C1 = "#f5f5f6", C2 = "#6c6c73", GRID = "#1d1d20", TXT = "#6c6c73";
const nice = (v) => { const e = Math.pow(10, Math.floor(Math.log10(v || 1))), f = v / e; return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * e; };

class Chart {
  constructor(id, o) {
    this.cv = $(id); this.ctx = this.cv.getContext("2d"); this.o = { grid: true, live: false, ...o };
    this.range = o.range || 300; this.dirty = true; this.intro = performance.now(); this.hover = null;
    this.hi = null; this.lo = 0;
    new ResizeObserver(() => { this.size(); this.dirty = true; }).observe(this.cv);
    if (this.o.grid) {
      this.tip = h("div", { class: "tip" });
      this.cv.parentElement.append(this.tip);
      this.cv.addEventListener("pointermove", (e) => { this.hover = e.clientX - this.cv.getBoundingClientRect().left; this.dirty = true; });
      this.cv.addEventListener("pointerleave", () => { this.hover = null; this.tip.style.opacity = 0; this.dirty = true; });
    }
    charts.push(this);
  }
  size() {
    const r = this.cv.getBoundingClientRect(), d = devicePixelRatio || 1;
    this.W = r.width; this.Hh = r.height;
    this.cv.width = Math.round(r.width * d); this.cv.height = Math.round(r.height * d);
    this.ctx.setTransform(d, 0, 0, d, 0, 0);
  }
  draw(frac, now) {
    const { ctx, o } = this, W = this.W, Hh = this.Hh;
    if (!W) return;
    const first = H[o.series[0].k], k = Math.min(first.length, this.range + 1);
    ctx.clearRect(0, 0, W, Hh);
    if (k < 2) return;
    const step = W / (this.range - 1), sh = o.live ? (1 - frac) * step : 0;
    let mx = -Infinity, mn = Infinity;
    for (const s of o.series) { const a = H[s.k]; for (let i = a.length - k; i < a.length; i++) { if (a[i] > mx) mx = a[i]; if (a[i] < mn) mn = a[i]; } }
    let hi, lo;
    if (o.max) { hi = o.max; lo = 0; }
    else if (o.zero) { lo = 0; hi = nice(Math.max(mx * 1.15, o.minSpan || 1)); }
    else { const span = Math.max(mx - mn, o.minSpan || 5); lo = Math.floor(mn - span * 0.25); hi = Math.ceil(mx + span * 0.25); }
    if (this.hi == null || reduce) { this.hi = hi; this.lo = lo; }
    else { this.hi += (hi - this.hi) * 0.12; this.lo += (lo - this.lo) * 0.12; if (Math.abs(hi - this.hi) > 0.002 * hi) this.dirty = true; }
    hi = this.hi; lo = this.lo;
    const pt = o.grid ? 14 : 4, pb = o.grid ? 8 : 4, y = (v) => pt + (1 - (v - lo) / (hi - lo || 1)) * (Hh - pt - pb);

    if (o.grid) {
      ctx.font = '11px "Geist", system-ui, sans-serif'; ctx.textBaseline = "bottom";
      for (let g = 0; g <= 3; g++) {
        const v = lo + ((hi - lo) * g) / 3, yy = Math.round(y(v)) + 0.5;
        ctx.strokeStyle = GRID; ctx.lineWidth = 1; ctx.setLineDash(g ? [3, 5] : []);
        ctx.beginPath(); ctx.moveTo(0, yy); ctx.lineTo(W, yy); ctx.stroke();
        ctx.fillStyle = TXT; ctx.fillText(o.axis(v), 8, yy - 3);
      }
      ctx.setLineDash([]);
    }
    ctx.save();
    const rv = reduce ? 1 : Math.min(1, (now - this.intro) / 1000);
    if (rv < 1) { ctx.beginPath(); ctx.rect(0, 0, W * (1 - Math.pow(1 - rv, 3)), Hh); ctx.clip(); this.dirty = true; }
    const px = (j) => W - (k - 1 - j) * step + sh;
    for (const [si, s] of o.series.entries()) {
      const a = H[s.k], b = a.length - k;
      ctx.beginPath();
      ctx.moveTo(px(0), y(a[b]));
      for (let j = 1; j < k; j++) {
        const x0 = px(j - 1), y0 = y(a[b + j - 1]), x1 = px(j), y1 = y(a[b + j]);
        ctx.quadraticCurveTo(x0, y0, (x0 + x1) / 2, (y0 + y1) / 2);
      }
      ctx.lineTo(px(k - 1), y(a[a.length - 1]));
      ctx.lineJoin = "round"; ctx.lineCap = "round";
      ctx.lineWidth = o.grid ? 1.8 : 1.5; ctx.strokeStyle = s.color || C1;
      if (o.glow) { ctx.shadowColor = "rgba(255,255,255,.4)"; ctx.shadowBlur = 10; }
      ctx.stroke(); ctx.shadowBlur = 0;
      if (s.fill !== false && si === 0) {
        ctx.lineTo(px(k - 1), Hh); ctx.lineTo(px(0), Hh); ctx.closePath();
        const g = ctx.createLinearGradient(0, pt, 0, Hh);
        g.addColorStop(0, "rgba(255,255,255,.17)"); g.addColorStop(1, "rgba(255,255,255,0)");
        ctx.fillStyle = g; ctx.fill();
      }
    }
    ctx.restore();

    if (o.grid && this.hover != null) {
      let j = Math.round(k - 1 - (W + sh - this.hover) / step);
      j = Math.max(0, Math.min(k - 1, j));
      const xx = px(j);
      ctx.strokeStyle = "rgba(255,255,255,.25)"; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(Math.round(xx) + 0.5, 0); ctx.lineTo(Math.round(xx) + 0.5, Hh); ctx.stroke();
      for (const s of o.series) {
        const a = H[s.k], v = a[a.length - k + j];
        ctx.fillStyle = "#000"; ctx.strokeStyle = s.color || C1; ctx.lineWidth = 2;
        ctx.beginPath(); ctx.arc(xx, y(v), 4, 0, 7); ctx.fill(); ctx.stroke();
      }
      const lines = o.series.map((s) => (o.series.length > 1 ? s.label + " " : "") + o.fmt(H[s.k][H[s.k].length - k + j]));
      this.tip.innerHTML = "";
      this.tip.append(...lines.map((t) => h("div", {}, t)), h("small", {}, ago(k - 1 - j)));
      const tw = this.tip.offsetWidth;
      this.tip.style.transform = `translate(${Math.max(4, Math.min(W - tw - 4, xx - tw / 2))}px, 6px)`;
      this.tip.style.opacity = 1;
    }
  }
}

const fW = (v) => `${fWatts(v)} W`;
const fRate = (v) => { const [u, d] = rateUnit(v); return `${(v < 1024 ? nf0 : nf1).format(v / d)} ${u}`; };
const cPower = new Chart("#c-power", { series: [{ k: "w" }], live: true, glow: true, zero: true, minSpan: 10, axis: (v) => `${nf0.format(v)} W`, fmt: fW });
const cPower2 = new Chart("#c-power2", { series: [{ k: "w" }], live: true, zero: true, minSpan: 10, axis: (v) => `${nf0.format(v)} W`, fmt: fW });
const cCpu = new Chart("#c-cpu", { series: [{ k: "cpu" }], live: true, max: 100, axis: (v) => `${nf0.format(v)}%`, fmt: (v) => `${nf1.format(v)}%` });
const cNet = new Chart("#c-net", { series: [{ k: "rx", label: "Recebido", color: C1 }, { k: "tx", label: "Enviado", color: C2, fill: false }], live: true, zero: true, minSpan: 2048, axis: (v) => fRate(v), fmt: fRate });
const sCpu = new Chart("#s-cpu", { series: [{ k: "cpu" }], grid: false, max: 100, range: 60 });
const sTemp = new Chart("#s-temp", { series: [{ k: "temp" }], grid: false, minSpan: 8, range: 120 });
const sTemp2 = new Chart("#s-temp2", { series: [{ k: "temp" }], grid: false, minSpan: 8, range: 300 });
const sNet = new Chart("#s-net", { series: [{ k: "rx" }, { k: "tx", color: C2, fill: false }], grid: false, zero: true, minSpan: 2048, range: 60 });
const cmap = { power: cPower, power2: cPower2 };
$$(".seg[data-range-for]").forEach((seg) => seg.addEventListener("click", (e) => {
  const b = e.target.closest("button"); if (!b) return;
  $$("button", seg).forEach((x) => x.classList.toggle("on", x === b));
  const c = cmap[seg.dataset.rangeFor]; c.range = +b.dataset.r; c.dirty = true; c.intro = performance.now();
}));

function frame(now) {
  const frac = Math.min(1, (now - lastSample) / 1000);
  stepTweens(now);
  for (const c of charts) if (c.cv.offsetParent && (c.o.live || c.dirty)) { c.dirty = false; c.draw(frac, now); }
  requestAnimationFrame(frame);
}
requestAnimationFrame(frame);

/* ---------- atualização da interface ---------- */
const sinceLabel = () => {
  if (!S || !S.en.since) return "Total";
  const [y, m, d] = S.en.since.split("-");
  return `Total desde ${d}/${m}`;
};
function renderDisks(box, list) {
  const sig = list.map((d) => d.m).join("|");
  if (box.dataset.sig !== sig) {
    box.dataset.sig = sig; box.innerHTML = "";
    for (const d of list) box.append(h("div", { class: "disk" },
      h("div", { class: "disk-top" }, h("b", {}, d.m), h("span", { class: "muted small" }, d.d)),
      h("div", { class: "bar" }, h("i")),
      h("div", { class: "disk-meta" }, h("span"), h("span"), h("span"))));
  }
  list.forEach((d, i) => {
    const el = box.children[i], p = d.u / d.t, sp = $$(".disk-meta span", el);
    $(".bar", el).classList.toggle("crit", p > 0.9);
    $(".bar i", el).style.transform = `scaleX(${p})`;
    sp[0].textContent = `${bytes(d.u)} usados (${nf0.format(p * 100)}%)`;
    sp[1].textContent = `${bytes(d.f)} livres`;
    sp[2].textContent = `de ${bytes(d.t)}`;
  });
}
function renderKV(el, rows) {
  if (el.children.length !== rows.length) { el.innerHTML = ""; for (const r of rows) el.append(h("div", {}, h("dt", {}, r[0]), h("dd"))); }
  rows.forEach((r, i) => { $("dd", el.children[i]).textContent = r[1]; });
}

function costs(s) {
  const e = s.en, mean = H.w.length ? H.w.reduce((a, b) => a + b, 0) / H.w.length : s.pw.w;
  const now = new Date(), end = new Date(now.getFullYear(), now.getMonth() + 1, 1);
  const proj = e.month + (mean * (end - now)) / 3.6e9;
  const v = { today: e.today, month: e.month, proj, total: e.total };
  for (const key in v) {
    $$(`[data-cost="${key}"]`).forEach((el) => num(el, v[key] * e.price, money));
    $$(`[data-kwh="${key}"]`).forEach((el) => { el.textContent = `${nf3.format(v[key])} kWh`; });
  }
  $$("[data-since]").forEach((el) => { el.textContent = sinceLabel(); });
  $$("[data-price]").forEach((i) => { if (document.activeElement !== i) i.value = nf2.format(e.price); });
}

function onSnap(s) {
  S = s; lastSample = performance.now();
  if (s.t > H.end) {
    H.end = s.t;
    const used = s.mem.t ? (100 * (s.mem.t - s.mem.a)) / s.mem.t : 0;
    for (const [k, v] of [["w", s.pw.w], ["cpu", s.cpu.u], ["temp", s.temp], ["rx", s.net.rx], ["tx", s.net.tx], ["mem", used]]) {
      H[k].push(v); if (H[k].length > CAP) H[k].shift();
    }
  }
  charts.forEach((c) => { c.dirty = true; });
  setLive(true);
  render(s);
}

function render(s) {
  $("#side-host").textContent = s.host; $("#side-os").textContent = s.os; $("#side-up").textContent = `Ligado há ${dur(s.up)}`;
  $("#side-dot").classList.add("on");
  const bat = $("#bat");
  bat.hidden = !s.bat || s.bat.p < 0;
  if (!bat.hidden) {
    const chg = s.bat.s === "Charging", full = s.bat.s === "Full" || (s.bat.s === "Not charging" && s.bat.p >= 95);
    $("#bat-t").textContent = `${s.bat.p}%`;
    $("#bat-s").textContent = chg ? " · carregando" : full ? " · carregada" : s.bat.s === "Discharging" ? " · na bateria" : "";
    $("#bat-f").style.transform = `scaleX(${Math.max(0.04, s.bat.p / 100)})`;
    bat.classList.toggle("chg", chg); bat.classList.toggle("low", s.bat.s === "Discharging" && s.bat.p <= 20);
    bat.title = `Bateria ${s.bat.p}% · ${chg ? "carregando na tomada" : full ? "carregada, na tomada" : s.bat.s === "Discharging" ? "descarregando (sem energia da tomada)" : s.bat.s}`;
  }

  num($("#pw-now"), s.pw.w, fWatts);
  const src = { rapl: ["Medido · RAPL", "Leitura do contador de energia do processador"], medidor: ["Medido · tomada", "Leitura de um medidor externo"], estimativa: ["Estimado", "Sem sensor de energia: valor estimado pela carga do processador"] }[s.pw.src];
  $("#pw-src").textContent = src[0]; $("#pw-src").title = src[1];
  $("#pw-note").textContent = { rapl: "Medido pelo contador de energia do processador (RAPL), somado a uma estimativa do resto do equipamento.", medidor: "Leitura de um medidor externo.", estimativa: "Sem sensor de energia disponível. O valor é estimado pela carga do processador." }[s.pw.src];
  const perH = (s.pw.w / 1000) * s.en.price;
  $("#pw-sub").textContent = `${money(perH)} por hora · ${money(perH * 24 * 30)} por mês neste ritmo`;
  costs(s);

  const used = s.mem.t - s.mem.a, mp = s.mem.t ? (used / s.mem.t) * 100 : 0;
  num($("#cpu-now"), s.cpu.u, nf1.format.bind(nf1));
  $("#cpu-mhz").textContent = s.cpu.mhz ? `${nf2.format(s.cpu.mhz / 1000)} GHz` : "";
  num($("#temp-now"), s.temp, (v) => (s.temp > 0 ? nf1.format(v) : "—"));
  $("#temp-flag").hidden = s.temp < 80;
  num($("#mem-now"), mp, nf0.format.bind(nf0));
  $("#mem-bar").style.transform = `scaleX(${mp / 100})`; $("#mem-bar").parentElement.classList.toggle("crit", mp > 90);
  $("#mem-detail").textContent = `${bytes(used * 1024)} de ${bytes(s.mem.t * 1024)}`;
  $("#mem-sub").textContent = `Cache ${bytes(s.mem.c * 1024)}`;
  const [ru, rd] = rateUnit(s.net.rx), [tu, td] = rateUnit(s.net.tx);
  num($("#rx-now"), s.net.rx / rd, (v) => (rd === 1 ? nf0 : nf1).format(v)); $("#rx-u").textContent = ru;
  num($("#tx-now"), s.net.tx / td, (v) => (td === 1 ? nf0 : nf1).format(v)); $("#tx-u").textContent = tu;

  $$("[data-disks]").forEach((b) => renderDisks(b, s.disks));
  renderKV($("#kv-sys"), [["Nome", s.host], ["Sistema", s.os], ["Kernel", s.kernel], ["Ligado há", dur(s.up)], ["Carga (1, 5, 15 min)", s.load.map((x) => nf2.format(x)).join("  ")], ["Núcleos", String(s.ncpu)]]);

  if (!$("#v-sistema").hidden) {
    $("#cpu-info").textContent = `${s.ncpu} núcleos${s.cpu.mhz ? " · " + nf2.format(s.cpu.mhz / 1000) + " GHz" : ""}`;
    const box = $("#cores");
    if (box.children.length !== s.cpu.cores.length) { box.innerHTML = ""; s.cpu.cores.forEach((_, i) => box.append(h("div", { class: "core" }, h("div", {}, h("i")), h("span", {}, String(i + 1))))); }
    s.cpu.cores.forEach((v, i) => { $("i", box.children[i]).style.transform = `scaleY(${v / 100})`; box.children[i].title = `Núcleo ${i + 1}: ${v}%`; });
    num($("#temp2"), s.temp, (v) => (s.temp > 0 ? nf1.format(v) : "—"));
    $("#dtemp").textContent = s.dtemp ? `Disco NVMe ${nf0.format(s.dtemp)} °C` : "Sem sensor de disco";
    num($("#mem2"), mp, nf0.format.bind(nf0)); $("#mem2-bar").style.transform = `scaleX(${mp / 100})`;
    renderKV($("#kv-mem"), [["Em uso", bytes(used * 1024)], ["Cache", bytes(s.mem.c * 1024)], ["Disponível", bytes(s.mem.a * 1024)], ["Total", bytes(s.mem.t * 1024)], ["Swap em uso", s.mem.st ? `${bytes((s.mem.st - s.mem.sf) * 1024)} de ${bytes(s.mem.st * 1024)}` : "Sem swap"]]);
    $("#net-tot").textContent = `Recebido desde a inicialização: ${bytes(s.net.rxt)} · Enviado: ${bytes(s.net.txt)}`;
  }
}

function renderDays() {
  const box = $("#days");
  if (!days.length) { box.innerHTML = ""; return; }
  const mx = Math.max(...days.map((d) => d.k), 0.001), price = S ? S.en.price : 0;
  box.innerHTML = "";
  days.forEach((d, i) => {
    const [, m, dd] = d.d.split("-");
    box.append(h("div", { class: "day" + (i === days.length - 1 ? " today" : "") },
      h("i"), h("div", { class: "tip" }, `${dd}/${m}`, h("small", {}, `${money(d.k * price)} · ${nf3.format(d.k)} kWh`))));
  });
  requestAnimationFrame(() => requestAnimationFrame(() => $$(".day i", box).forEach((el, i) => { el.style.transform = `scaleY(${days[i].k / mx})`; })));
  $("#days-note").textContent = `${days.length} ${days.length === 1 ? "dia" : "dias"} com medição`;
}

/* preço do kWh */
$$("[data-price]").forEach((inp) => {
  inp.addEventListener("focus", () => inp.select());
  inp.addEventListener("keydown", (e) => { if (e.key === "Enter") inp.blur(); });
  inp.addEventListener("change", async () => {
    const v = parseFloat(inp.value.replace(",", "."));
    if (!(v >= 0 && v <= 100)) { toast("Digite um valor válido, por exemplo 0,95"); if (S) inp.value = nf2.format(S.en.price); return; }
    try {
      const r = await api("/api/settings", { method: "POST", body: JSON.stringify({ price: v }) });
      if (!r.ok) throw 0;
      if (S) { S.en.price = v; costs(S); renderDays(); }
      toast("Valor do kWh salvo");
    } catch { toast("Não foi possível salvar o valor do kWh"); }
  });
});

/* ---------- conexão ---------- */
let watchdog;
function setLive(on) {
  $("#live").classList.toggle("on-live", on);
  $("#live-t").textContent = on ? "Ao vivo" : "Sem conexão";
  if (!on) $("#side-dot").classList.remove("on");
  clearTimeout(watchdog);
  if (on) watchdog = setTimeout(() => setLive(false), 6000);
}
function connect() {
  const es = new EventSource("/api/stream");
  es.onmessage = (e) => onSnap(JSON.parse(e.data));
  es.onerror = () => {
    setLive(false); es.close();
    fetch("/api/me").then((r) => (r.status === 401 ? showLogin() : setTimeout(connect, 2000))).catch(() => setTimeout(connect, 2000));
  };
}
async function loadHistory() {
  const j = await (await api("/api/history")).json();
  for (const k of ["cpu", "temp", "w", "rx", "tx", "mem"]) H[k] = j[k];
  H.end = j.end; days = j.days; renderDays();
}

/* ---------- login ---------- */
let booted = false, ME = { user: "", role: "" }, setupMode = false;
function loginMode(setup) { // "primeiro acesso": só aparece quando o administrador abriu um convite para esta conta
  setupMode = setup;
  $("#login-h").textContent = setup ? "Defina sua senha" : "homelabOS";
  $("#login-p").textContent = setup ? `Primeiro acesso de ${$("#login-user").value.trim().toLowerCase()}. Digite o código de convite que o administrador te passou e escolha uma senha com pelo menos 8 caracteres.` : "Entre com seu usuário e senha.";
  $("#login-pwl").textContent = setup ? "Nova senha" : "Senha";
  $("#login-pw").autocomplete = setup ? "new-password" : "current-password";
  $("#login-pw2w").hidden = $("#login-codew").hidden = !setup; $("#login-pw2").required = $("#login-code").required = setup;
  $("#login-btn").textContent = setup ? "Definir senha e entrar" : "Entrar";
}
function showLogin() {
  $("#app").hidden = true; $("#login").hidden = false; document.body.removeAttribute("data-role");
  loginMode(false); $("#login-pw").value = $("#login-pw2").value = $("#login-code").value = "";
  ($("#login-user").value ? $("#login-pw") : $("#login-user")).focus();
}
$("#login-user").addEventListener("input", () => { if (setupMode) loginMode(false); });
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("#login-err"); err.textContent = "";
  const user = $("#login-user").value.trim().toLowerCase(), pw = $("#login-pw").value;
  if (setupMode) {
    if (pw.length < 8) { err.textContent = "A senha precisa ter pelo menos 8 caracteres."; return; }
    if (pw !== $("#login-pw2").value) { err.textContent = "As senhas não são iguais."; $("#login-pw2").select(); return; }
  }
  try {
    const body = setupMode ? { user, password: pw, code: $("#login-code").value.trim() } : { user, password: pw };
    const r = await api(setupMode ? "/api/setup" : "/api/login", { method: "POST", body: JSON.stringify(body) });
    if (r.status === 409 && !setupMode && (await r.clone().json()).setup) { loginMode(true); $("#login-pw").value = ""; $("#login-pw").focus(); return; }
    if (!r.ok) { err.textContent = await errMsg(r); if (!setupMode) $("#login-pw").select(); return; }
    $("#login-pw").value = $("#login-pw2").value = $("#login-code").value = ""; boot();
  } catch { err.textContent = "Não foi possível falar com o servidor."; }
});
$("#logout").addEventListener("click", async () => { await api("/api/logout", { method: "POST" }); location.reload(); });

/* ---------- energia: desligar e reiniciar ---------- */
for (const [id, op, t] of [["#pw-reboot", "reboot", { title: "Reiniciar o servidor?", text: "Os serviços ficam fora do ar por cerca de um minuto e o painel volta sozinho.", ok: "Reiniciar", done: "Reiniciando… o painel volta em cerca de um minuto." }],
  ["#pw-off", "poweroff", { title: "Desligar o servidor?", text: "Ele só volta a ligar apertando o botão de ligar na máquina. Pelo painel não dá para ligar de novo.", ok: "Desligar", done: "Desligando o servidor…" }]]) {
  $(id).addEventListener("click", async () => {
    if (!(await confirmDlg(t))) return;
    try {
      const r = await api(`/api/power/${op}`, { method: "POST" });
      toast(r.ok ? t.done : await errMsg(r));
    } catch { toast("Não foi possível enviar o comando"); }
  });
}

/* ---------- rotas ---------- */
const TITLES = { geral: "Visão geral", energia: "Energia", sistema: "Sistema", arquivos: "Arquivos", atalhos: "Atalhos" };
const seen = new Set();
function route() {
  let v = TITLES[location.hash.slice(1)] ? location.hash.slice(1) : "geral";
  if (ME.role !== "admin" && v === "arquivos") { v = "geral"; history.replaceState(null, "", "#geral"); }
  $$(".view").forEach((s) => { s.hidden = s.id !== "v-" + v; });
  $$("#nav a").forEach((a) => a.classList.toggle("on", a.dataset.v === v));
  $("#title").textContent = TITLES[v]; document.title = `${TITLES[v]} · homelabOS`;
  const view = $("#v-" + v);
  if (!seen.has(v) && !reduce) {
    seen.add(v);
    $$(".reveal", view).forEach((el, i) => el.animate([{ opacity: 0, transform: "translateY(10px)" }, { opacity: 1, transform: "none" }], { duration: 520, delay: i * 45, easing: EASE, fill: "backwards" }));
  }
  charts.forEach((c) => { c.dirty = true; c.hi = null; if (c.cv.closest("#v-" + v)) c.intro = performance.now(); });
  if (v === "arquivos") loadDir(cwd);
  if (v === "energia") loadHistory().catch(() => {});
  if (v === "atalhos") renderApps();
  if (S) render(S);
  scrollTo(0, 0);
}
addEventListener("hashchange", route);

/* ---------- diálogos ---------- */
function askInput(o) {
  return new Promise((res) => {
    const d = $("#dlg-input"), v = $("#dlg-input-v"), v2 = $("#dlg-input-v2"), err = $("#dlg-input-e");
    $("#dlg-input-t").textContent = o.title; $("#dlg-input-l").textContent = o.label;
    $("#dlg-input-ok").textContent = o.ok; v.value = o.value || ""; err.textContent = "";
    $("#dlg-input-2w").hidden = !o.label2; v2.value = o.value2 || ""; if (o.label2) $("#dlg-input-l2").textContent = o.label2;
    const ck = $("#dlg-input-c"); $("#dlg-input-3w").hidden = !o.label3; ck.checked = !!o.value3;
    if (o.label3) { $("#dlg-input-l3").textContent = o.label3; $("#dlg-input-h3").textContent = o.hint3 || ""; }
    const form = $("form", d);
    form.onsubmit = (e) => {
      if (e.submitter && e.submitter.value !== "ok") return;
      const msg = o.validate ? o.validate(v.value.trim(), v2.value.trim()) : "";
      if (msg) { e.preventDefault(); err.textContent = msg; }
    };
    v.onkeydown = v2.onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); $("#dlg-input-ok").click(); } };
    const done = () => { d.removeEventListener("close", done); res(d.returnValue === "ok" ? [v.value.trim(), v2.value.trim(), ck.checked] : null); };
    d.returnValue = ""; d.addEventListener("close", done); d.showModal(); v.focus(); v.select();
  });
}
function confirmDlg(o) {
  return new Promise((res) => {
    const d = $("#dlg-confirm");
    $("#dlg-confirm-t").textContent = o.title; $("#dlg-confirm-p").textContent = o.text; $("#dlg-confirm-ok").textContent = o.ok;
    const done = () => { d.removeEventListener("close", done); res(d.returnValue === "ok"); };
    d.returnValue = ""; d.addEventListener("close", done); d.showModal();
  });
}
const nameCheck = (n) => (!n ? "Digite um nome." : /[\/\x00-\x1f]/.test(n) || n === "." || n === ".." ? "O nome não pode ter “/” nem ser “.” ou “..”." : "");

/* ---------- arquivos ---------- */
let cwd = "/", items = [];
try { cwd = sessionStorage.getItem("cwd") || "/"; } catch {}
const join = (n) => (cwd === "/" ? "/" + n : cwd + "/" + n);
const ext = (n) => (n.includes(".") ? n.split(".").pop().toLowerCase() : "");
const KIND = { image: "png jpg jpeg gif webp avif svg", video: "mp4 webm mov mkv m4v", audio: "mp3 ogg wav flac m4a", pdf: "pdf", text: "txt md json log csv conf yml yaml ini xml sh py js ts c h" };
const kindOf = (n) => { const e = ext(n); for (const k in KIND) if (KIND[k].split(" ").includes(e)) return k; return ""; };
const fsUrl = (p, dl) => `/api/fs/get?path=${encodeURIComponent(p)}${dl ? "&dl=1" : ""}`;

async function loadDir(p) {
  try {
    const r = await api("/api/fs/list?path=" + encodeURIComponent(p));
    if (!r.ok) {
      toast(await errMsg(r));
      if (p !== "/") { cwd = "/"; return loadDir("/"); }
      items = []; renderFiles(); return;
    }
    const j = await r.json();
    cwd = j.path; items = j.items; try { sessionStorage.setItem("cwd", cwd); } catch {}
    renderCrumbs(); renderFiles();
  } catch {}
}
function renderCrumbs() {
  const box = $("#crumbs"); box.innerHTML = "";
  const parts = cwd.split("/").filter(Boolean);
  box.append(h("button", { onclick: () => loadDir("/") }, "compartilhado"));
  parts.forEach((p, i) => { box.append(h("span", {}, "/"), h("button", { onclick: () => loadDir("/" + parts.slice(0, i + 1).join("/")) }, p)); });
  $("#drop-to").textContent = `para ${parts.length ? parts[parts.length - 1] : "compartilhado"}`;
}
function renderFiles() {
  const box = $("#f-list"), q = $("#f-filter").value.trim().toLowerCase();
  const list = items.filter((i) => !q || i.n.toLowerCase().includes(q));
  box.innerHTML = "";
  if (!list.length) {
    box.append(q
      ? h("div", { class: "empty" }, h("b", {}, "Nada encontrado"), h("span", {}, `Nenhum item com “${$("#f-filter").value.trim()}” nesta pasta.`))
      : h("div", { class: "empty" }, h("b", {}, "Esta pasta está vazia"), h("span", {}, "Arraste arquivos para cá ou use Enviar arquivos.")));
    return;
  }
  for (const it of list) {
    const act = h("div", { class: "f-act" });
    if (!it.d) act.append(h("a", { class: "icon-btn", href: fsUrl(join(it.n), true), title: "Baixar", "aria-label": `Baixar ${it.n}`, onclick: (e) => e.stopPropagation() }, icon("down")));
    act.append(
      h("button", { class: "icon-btn", title: "Renomear", "aria-label": `Renomear ${it.n}`, onclick: (e) => { e.stopPropagation(); renameItem(it); } }, icon("edit")),
      h("button", { class: "icon-btn", title: "Excluir", "aria-label": `Excluir ${it.n}`, onclick: (e) => { e.stopPropagation(); deleteItem(it); } }, icon("trash")));
    const row = h("div", { class: "f-row" + (it.d ? " dir" : ""), role: "listitem", tabindex: "0" },
      h("div", { class: "f-name" }, icon(it.d ? "folder" : "file"), h("span", {}, it.n)),
      h("span", { class: "sz" }, it.d ? "—" : bytes(it.s)),
      h("span", { class: "dt" }, fDate(it.m)), act);
    const open = () => openItem(it);
    row.addEventListener("click", open);
    row.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target === row) open(); });
    box.append(row);
  }
}
$("#f-filter").addEventListener("input", renderFiles);

function openItem(it) {
  const p = join(it.n);
  if (it.d) { $("#f-filter").value = ""; return loadDir(p); }
  const k = kindOf(it.n);
  if (!k || (k === "text" && it.s > 400000)) { location.href = fsUrl(p, true); return; }
  const body = $("#viewer-body"); body.innerHTML = "";
  const src = fsUrl(p);
  if (k === "image") body.append(h("img", { src, alt: it.n }));
  else if (k === "video") body.append(h("video", { src, controls: "", autoplay: "", playsinline: "" }));
  else if (k === "audio") body.append(h("audio", { src, controls: "", autoplay: "" }));
  else if (k === "pdf") body.append(h("iframe", { src, title: it.n }));
  else { const pre = h("pre", {}, "Carregando…"); body.append(pre); fetch(src).then((r) => r.text()).then((t) => { pre.textContent = t; }); }
  $("#viewer-cap").textContent = `${it.n} · ${bytes(it.s)}`;
  $("#dlg-view").showModal();
}
$("#dlg-view").addEventListener("close", () => { $("#viewer-body").innerHTML = ""; });
$("#dlg-view").addEventListener("click", (e) => { if (e.target === e.currentTarget) e.currentTarget.close(); });
$("#viewer-x").addEventListener("click", () => $("#dlg-view").close());

async function renameItem(it) {
  const r = await askInput({ title: "Renomear", label: "Novo nome", value: it.n, ok: "Renomear", validate: nameCheck });
  if (!r || r[0] === it.n) return;
  const res = await api(`/api/fs/rename?path=${encodeURIComponent(join(it.n))}&name=${encodeURIComponent(r[0])}`, { method: "POST" });
  if (res.ok) { toast("Renomeado"); loadDir(cwd); } else toast(await errMsg(res));
}
async function deleteItem(it) {
  const ok = await confirmDlg({ title: `Excluir ${it.d ? "pasta" : "arquivo"}?`, text: it.d ? `“${it.n}” e tudo o que está dentro dela serão apagados. Isso não pode ser desfeito.` : `“${it.n}” será apagado. Isso não pode ser desfeito.`, ok: "Excluir" });
  if (!ok) return;
  const res = await api(`/api/fs/delete?path=${encodeURIComponent(join(it.n))}`, { method: "POST" });
  if (res.ok) { toast("Excluído"); loadDir(cwd); } else toast(await errMsg(res));
}
$("#f-mkdir").addEventListener("click", async () => {
  const r = await askInput({ title: "Nova pasta", label: "Nome da pasta", ok: "Criar", validate: nameCheck });
  if (!r) return;
  const res = await api(`/api/fs/mkdir?path=${encodeURIComponent(cwd)}&name=${encodeURIComponent(r[0])}`, { method: "POST" });
  if (res.ok) { toast("Pasta criada"); loadDir(cwd); } else toast(await errMsg(res));
});

/* upload */
const queue = []; let running = 0;
function enqueue(files) {
  for (const f of files) {
    const bar = h("i"), st = h("span", {}, "Na fila");
    const el = h("div", { class: "up" }, h("div", { class: "up-t" }, h("span", {}, f.name), st), h("div", { class: "bar" }, bar));
    $("#uploads").append(el); $("#uploads").hidden = false;
    queue.push({ f, el, bar, st, dir: cwd });
  }
  pump();
}
function pump() {
  while (running < 2 && queue.length) {
    const u = queue.shift(); running++;
    const x = new XMLHttpRequest();
    x.open("POST", `/api/fs/upload?path=${encodeURIComponent(u.dir)}&name=${encodeURIComponent(u.f.name)}`);
    x.setRequestHeader("X-Requested-With", "homelabos");
    x.upload.onprogress = (e) => { if (e.lengthComputable) { u.bar.style.transform = `scaleX(${e.loaded / e.total})`; u.st.textContent = `${nf0.format((e.loaded / e.total) * 100)}%`; } };
    const end = (ok, msg) => {
      running--; u.el.classList.toggle("err", !ok);
      u.st.textContent = ok ? "Pronto" : msg || "Falhou"; if (ok) u.bar.style.transform = "scaleX(1)";
      if (ok && u.dir === cwd) loadDir(cwd);
      setTimeout(() => { u.el.remove(); if (!$("#uploads").children.length) $("#uploads").hidden = true; }, ok ? 1500 : 6000);
      pump();
    };
    x.onload = () => { let m; try { m = JSON.parse(x.responseText).error; } catch {} end(x.status === 200, m); };
    x.onerror = () => end(false, "Conexão perdida");
    u.bar.parentElement.style.display = ""; u.st.textContent = "0%";
    x.send(u.f);
  }
}
$("#f-upload").addEventListener("click", () => $("#f-input").click());
$("#f-input").addEventListener("change", (e) => { enqueue([...e.target.files]); e.target.value = ""; });
const drop = $("#drop"); let dc = 0;
const hasFiles = (e) => e.dataTransfer && [...e.dataTransfer.types].includes("Files");
drop.addEventListener("dragenter", (e) => { if (hasFiles(e)) { dc++; drop.classList.add("drag"); } });
drop.addEventListener("dragleave", () => { if (--dc <= 0) { dc = 0; drop.classList.remove("drag"); } });
drop.addEventListener("dragover", (e) => { if (hasFiles(e)) e.preventDefault(); });
drop.addEventListener("drop", (e) => { e.preventDefault(); dc = 0; drop.classList.remove("drag"); enqueue([...e.dataTransfer.files].filter((f) => f.size || f.type)); });
addEventListener("dragover", (e) => { if (hasFiles(e)) e.preventDefault(); });
addEventListener("drop", (e) => { if (hasFiles(e)) e.preventDefault(); });

/* ---------- atalhos ---------- */
let apps = [];
// só a porta (":8421" ou "8421") fica guardada assim e vale para o endereço usado para abrir o painel
// só http(s) vira link: o que vem salvo no servidor não é confiável o bastante para um javascript: ou data: virar href
const resolveURL = (u) => { const r = u[0] === ":" ? `${location.protocol === "https:" ? "http:" : location.protocol}//${location.hostname}${u}` : u; return /^https?:\/\//i.test(r) ? r : "#"; };
function normURL(u) {
  u = u.trim();
  if (/^:?\d{2,5}(\/.*)?$/.test(u)) return ":" + u.replace(/^:/, "");
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(u)) return /^https?:\/\//i.test(u) ? u : "";
  return /^[^\s/]+\.?[^\s]*$/.test(u) ? "http://" + u : "";
}
async function loadApps() { try { apps = await (await api("/api/apps")).json(); } catch { apps = []; } }
const saveApps = () => api("/api/apps", { method: "POST", body: JSON.stringify(apps) }).then((r) => { if (!r.ok) toast("Não foi possível salvar os atalhos"); });
function monoEl(a) {
  const src = a.icon || (!a.wake && /^https?:/i.test(resolveURL(a.u)) ? new URL("/favicon.ico", resolveURL(a.u)).href : "");
  const d = h("div", { class: "mono" }, (a.n || "?")[0]);
  if (src) { const img = h("img", { src, alt: "", referrerpolicy: "no-referrer" }); img.onload = () => { if (img.naturalWidth !== 1) { d.textContent = ""; d.classList.add("ico"); d.append(img); } }; }
  return d;
}
const hostOf = (u) => { try { return new URL(resolveURL(u)).host; } catch { return u; } };

function renderApps() {
  const box = $("#apps"); box.innerHTML = "";
  apps.forEach((a, i) => {
    const act = ME.role !== "admin" ? null : h("div", { class: "f-act" },
      h("button", { class: "icon-btn", title: "Editar", "aria-label": `Editar ${a.n}`, onclick: (e) => { e.preventDefault(); e.stopPropagation(); editApp(i); } }, icon("edit")),
      h("button", { class: "icon-btn", title: "Remover", "aria-label": `Remover ${a.n}`, onclick: (e) => { e.preventDefault(); e.stopPropagation(); removeApp(i); } }, icon("trash")));
    box.append(h("a", { class: "app-tile", href: resolveURL(a.u), ...(a.wake ? {} : { target: "_blank", rel: "noopener" }), onclick: a.wake ? (e) => { e.preventDefault(); openWake(a); } : null },
      monoEl(a), h("div", {}, h("b", {}, a.n), h("small", {}, hostOf(a.u) + (a.wake ? " · sob demanda" : ""))), act));
  });
  if (ME.role === "admin") box.append(h("button", { class: "app-tile add", onclick: () => editApp(-1) }, icon("plus"), "Adicionar atalho"));
  renderStrip();
}
function renderStrip() {
  const box = $("[data-apps-strip]"); box.innerHTML = "";
  $("#apps-strip-card").hidden = ME.role !== "admin" && !apps.length; // gestor sem atalhos liberados não vê o cartão vazio
  if (!apps.length) { box.append(h("span", { class: "muted" }, "Nenhum atalho ainda. Adicione os serviços que rodam neste servidor.")); return; }
  for (const a of apps.slice(0, 8)) box.append(h("a", { class: "chip", href: resolveURL(a.u), ...(a.wake ? {} : { target: "_blank", rel: "noopener" }), onclick: a.wake ? (e) => { e.preventDefault(); openWake(a); } : null }, monoEl(a), a.n));
}
async function editApp(i) {
  const cur = apps[i] || {};
  const r = await askInput({
    title: i < 0 ? "Novo atalho" : "Editar atalho", label: "Nome", value: cur.n, label2: "Endereço (ex.: 8096 ou http://192.168.1.10:8096)", value2: cur.u || "",
    label3: "Liga sob demanda", hint3: "Mostra uma animação de carregamento enquanto o app liga. Para programas que desligam sozinhos quando ninguém usa.", value3: cur.wake,
    ok: i < 0 ? "Adicionar" : "Salvar",
    validate: (n, u) => (!n ? "Digite um nome." : !normURL(u) ? "Digite um endereço válido, como 8096 ou http://servidor:8096." : ""),
  });
  if (!r) return;
  const item = { n: r[0], u: normURL(r[1]) };
  if (r[2]) item.wake = true;
  if (cur.icon) item.icon = cur.icon;
  if (cur.all) item.all = true; // "visível ao gestor": o formulário não edita, só preserva
  if (i < 0) apps.push(item); else apps[i] = item;
  await saveApps(); renderApps();
}
async function removeApp(i) {
  if (!(await confirmDlg({ title: "Remover atalho?", text: `“${apps[i].n}” sai da lista. O programa em si não é afetado.`, ok: "Remover" }))) return;
  apps.splice(i, 1); await saveApps(); renderApps();
}

/* ---------- atalho sob demanda ---------- */
// Abre o app depois de acordá-lo: o primeiro acesso liga o processo (o systemd segura a porta),
// e a contagem dá o tempo de a conexão responder. Nada fica rodando quando ninguém usa.
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let waking = 0;
async function openWake(a) {
  const id = ++waking, url = resolveURL(a.u), W = $("#wake");
  W.className = "wake"; W.hidden = true; $("#wake-b").hidden = true;
  const showT = setTimeout(() => { if (id === waking) W.hidden = false; }, 400); // app já ligado: abre direto, sem tela de espera
  $("#wake-t").textContent = `Abrindo ${a.n}`;
  const msg = (t) => { $("#wake-s").textContent = t; }, digit = $("#wake-n");
  digit.textContent = ""; msg("Ligando o app");
  const fail = (t) => { clearTimeout(showT); W.hidden = false; W.classList.add("fail"); digit.textContent = "!"; $("#wake-t").textContent = `Não consegui abrir ${a.n}`; msg(t); $("#wake-b").hidden = false; };
  $("#wake-x").onclick = () => { waking++; clearTimeout(showT); W.hidden = true; };
  $("#wake-retry").onclick = () => openWake(a);
  const t0 = performance.now(), blocked = location.protocol === "https:" && url.startsWith("http:"); // página https não consegue sondar um endereço http
  let ready = blocked;
  while (!ready && performance.now() - t0 < 20000 && id === waking) {
    const ac = new AbortController(), to = setTimeout(() => ac.abort(), 4000);
    try { await fetch(url, { mode: "no-cors", cache: "no-store", signal: ac.signal }); ready = true; } catch { await sleep(400); }
    clearTimeout(to);
    if (!ready && performance.now() - t0 > 1200) msg("Esperando o app responder");
  }
  if (id !== waking) return;
  if (!ready) { fail("O app não respondeu em 20 segundos. Confira se ele está instalado no servidor."); return; }
  clearTimeout(showT);
  location.href = url;
}
addEventListener("pageshow", () => { waking++; $("#wake").hidden = true; });

/* ---------- início ---------- */
function tick() { $("#clock").textContent = new Date().toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" }); }
setInterval(tick, 10000); tick();
setInterval(() => { if (booted) loadHistory().catch(() => {}); }, 300000);

async function boot() {
  try { ME = await (await api("/api/me")).json(); } catch { return; }
  document.body.dataset.role = ME.role;
  $("#side-user").textContent = `${ME.user} · ${ME.role === "admin" ? "Administrador" : "Gestão do servidor"}`;
  $$("[data-price]").forEach((i) => { i.readOnly = ME.role !== "admin"; });
  $("#login").hidden = true; $("#app").hidden = false;
  if (booted) { connect(); route(); return; }
  booted = true;
  await Promise.all([loadHistory().catch(() => {}), loadApps()]);
  renderStrip(); connect(); route();
}
fetch("/api/me", { credentials: "same-origin" }).then((r) => (r.ok ? boot() : showLogin())).catch(showLogin);
