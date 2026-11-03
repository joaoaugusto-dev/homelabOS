"use strict";
/* hospedagem: painel. JS puro, sem dependências. Mesma linguagem visual do homelabOS. */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const k in attrs || {}) {
    if (k === "class") e.className = attrs[k];
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), attrs[k]);
    else e.setAttribute(k, attrs[k]);
  }
  for (const c of kids.flat()) if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(c));
  return e;
}
const icon = (id) => {
  const s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  s.setAttribute("class", "ic s");
  s.innerHTML = `<use href="#i-${id}"/>`;
  return s;
};
const btn = (label, ic, opt = {}) => h("button", { class: "btn sm" + (opt.primary ? " primary" : ""), type: "button", ...(opt.title ? { title: opt.title } : {}), onclick: opt.onclick, ...(opt.disabled ? { disabled: "" } : {}) }, ic ? icon(ic) : null, label);
const iconBtn = (ic, title, onclick) => h("button", { class: "icon-btn", type: "button", title, "aria-label": title, onclick }, icon(ic));

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg; t.classList.add("show");
  clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove("show"), 3200);
}
const nf0 = new Intl.NumberFormat("pt-BR", { maximumFractionDigits: 0 });
function ago(ts) {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 45) return "agora há pouco";
  if (s < 3600) return `há ${Math.round(s / 60)} min`;
  if (s < 86400) return `há ${Math.round(s / 3600)} h`;
  return `há ${Math.round(s / 86400)} d`;
}
function upFor(ts) {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts)), d = Math.floor(s / 86400), hh = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d} d ${hh} h` : hh ? `${hh} h ${m} min` : m ? `${m} min` : "menos de 1 min";
}
const fdate = (ts) => new Date(ts * 1000).toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });

/* ---------- rede ---------- */
let D = null, lastJSON = "";
async function api(url, opt = {}) {
  const { timeout = 20000, ...rest } = opt, ac = new AbortController(), tm = setTimeout(() => ac.abort(), timeout);
  let r;
  try { r = await fetch(url, { credentials: "same-origin", signal: ac.signal, ...rest, headers: { "X-Requested-With": "hosting", ...(rest.headers || {}) } }); }
  finally { clearTimeout(tm); }
  if (r.status === 401) { showGate(); throw new Error("login"); }
  return r;
}
const post = (url, data) => api(url, { method: "POST", body: data ? new URLSearchParams(data).toString() : "" });
async function errMsg(r) { try { return (await r.json()).error || "erro inesperado"; } catch { return "erro inesperado"; } }
// POST que mostra o erro como toast; devolve o JSON em caso de sucesso
async function act(url, data, okMsg) {
  try {
    const r = await post(url, data);
    if (!r.ok) { toast(await errMsg(r)); return null; }
    const j = await r.json().catch(() => ({}));
    if (okMsg) toast(j.warn ? `${okMsg} (${j.warn})` : okMsg);
    refresh();
    return j;
  } catch { return null; }
}

function showGate() {
  $("#app").hidden = true; $("#gate").hidden = false;
  $("#gate-link").href = `${location.protocol}//${location.hostname}/`;
}

/* ---------- diálogos ---------- */
function confirmDlg(o) {
  return new Promise((res) => {
    const d = $("#dlg-confirm");
    $("#dlg-confirm-t").textContent = o.title; $("#dlg-confirm-p").textContent = o.text; $("#dlg-confirm-ok").textContent = o.ok;
    const done = () => { d.removeEventListener("close", done); res(d.returnValue === "ok"); };
    d.returnValue = ""; d.addEventListener("close", done); d.showModal();
  });
}
document.addEventListener("click", (e) => { const c = e.target.closest("[data-close]"); if (c) c.closest("dialog").close(); });
$("#dlg-log").addEventListener("click", (e) => { if (e.target === e.currentTarget) e.currentTarget.close(); });
function segValue(seg, attr) { return $("button.on", seg).dataset[attr]; }
function segSet(seg, attr, v) { $$("button", seg).forEach((b) => b.classList.toggle("on", b.dataset[attr] === v)); }
$$(".seg[id]").forEach((seg) => { if (seg.id.startsWith("f-") || seg.id === "log-tabs") return; seg.addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) { $$("button", seg).forEach((x) => x.classList.toggle("on", x === b)); seg.dispatchEvent(new Event("change")); } }); });

async function copy(text, what = "Copiado") {
  try { await navigator.clipboard.writeText(text); } catch { // página em http comum: sem clipboard API
    const t = h("textarea", { style: "position:fixed;opacity:0" }); t.value = text; document.body.append(t); t.select(); document.execCommand("copy"); t.remove();
  }
  toast(what);
}
const copyField = (value, secret) => {
  const code = h("code", {}, secret ? "••••••••••••" : value);
  let shown = !secret;
  const row = h("div", { class: "cf" }, code);
  if (secret) row.append(iconBtn("eye", "Mostrar", () => { shown = !shown; code.textContent = shown ? value : "••••••••••••"; }));
  row.append(iconBtn("copy", "Copiar", () => copy(value)));
  return row;
};

/* ---------- aplicações ---------- */
const STATE = { running: "Rodando", building: "Construindo", stopped: "Parado", restarting: "Reiniciando", pending: "Aguardando", new: "Novo" };
const SCOPE = (o) => (o === "shared" ? "Compartilhado" : "Privado");
let filter = "all";

function visible(a) { return filter === "all" || (filter === "mine" ? a.owner === D.me : a.owner === "shared"); }
function appCard(a) {
  const busy = a.state === "building";
  const st = a.state === "running" ? `Rodando há ${upFor(a.started)}` : STATE[a.state];
  const bad = a.last && a.last !== "ok" && a.last !== "novo";
  const net = a.expose && a.state === "running";
  const portLine = h("div", {}, icon("lock"), h("span", {}, net ? ["Rede local · ", h("a", { href: `http://${location.hostname}:${a.port}`, target: "_blank", rel: "noopener" }, `${location.hostname}:${a.port}`)] : `${a.expose ? "Na rede" : "Só neste servidor"} · porta ${a.port}`));
  const lines = h("div", { class: "acard-l" },
    a.host ? h("div", {}, icon("globe"), h("a", { href: `https://${a.host}`, target: "_blank", rel: "noopener" }, a.host)) : null,
    portLine,
    h("div", {}, icon("rocket"), h("span", {}, a.commit ? [a.zip ? null : h("code", {}, a.commit.slice(0, 7)), `${a.zip ? "" : " "}${a.msg}`, ` · ${ago(a.deployed)}`] : "Nenhum deploy ainda")),
    h("div", {}, icon("layers"), h("span", {}, `${a.zip ? `Arquivo: ${a.upname || "nenhum enviado"}` : `${a.repo} · ${a.branch}`} · ${a.rt === "podman" ? "container" : a.rt === "native" ? "processo" : a.runtime === "podman" ? "container" : a.runtime === "native" ? "processo" : "automático"}`)),
    h("div", {}, icon("pulse"), h("span", {}, st)),
    a.online || a.vis ? h("div", {}, icon("eye"), h("a", { href: "#estatisticas", onclick: () => { stSel = a.id; } }, `${a.online} online agora · ${nf0.format(a.vis)} visitantes hoje`)) : null,
    bad ? h("div", { class: "err" }, h("span", {}, a.last)) : null);
  const acts = h("div", { class: "acard-b" },
    a.zip ? btn("Enviar zip", "up", { primary: !a.commit, disabled: busy, onclick: () => pickUpload(a) }) : null,
    btn(a.zip ? "Refazer" : "Deploy", "rocket", { primary: !a.commit && !a.zip, disabled: busy, onclick: () => act(`/api/app/deploy?id=${a.id}`, null, "Deploy iniciado").then((j) => j && openLogs(a.id, "deploy")) }),
    btn("Logs", "term", { onclick: () => openLogs(a.id, "deploy") }),
    a.state === "running" || a.state === "restarting" ? iconBtn("stop", "Parar", () => act(`/api/app/stop?id=${a.id}`, null, "Parando")) : null,
    a.commit && a.state !== "running" && a.state !== "restarting" && !busy ? iconBtn("play", "Iniciar", () => act(`/api/app/start?id=${a.id}`, null, "Iniciando")) : null,
    a.state === "running" ? iconBtn("redo", "Reiniciar", () => act(`/api/app/restart?id=${a.id}`, null, "Reiniciando")) : null,
    h("span", { class: "sp" }),
    iconBtn("edit", "Editar", () => openAppForm(a)),
    iconBtn("trash", "Excluir", () => delApp(a)));
  return h("article", { class: "card acard" }, h("div", { class: "acard-h" }, h("i", { class: "st-dot " + a.state }), h("b", {}, a.name), h("span", { class: "tag" }, SCOPE(a.owner))), lines, acts);
}
function renderApps() {
  const box = $("#apps"); box.replaceChildren();
  const list = D.apps.filter(visible).sort((x, y) => x.name.localeCompare(y.name, "pt-BR"));
  if (!list.length) {
    box.append(h("div", { class: "card empty", style: "grid-column:1/-1" }, h("b", {}, filter === "all" ? "Nenhuma aplicação ainda" : "Nada por aqui"),
      h("span", {}, "Conecte um repositório do GitHub e o servidor constrói, publica e atualiza a cada push."), btn("Nova aplicação", "plus", { primary: true, onclick: () => openAppForm() })));
    return;
  }
  list.forEach((a) => box.append(appCard(a)));
}
async function delApp(a) {
  if (!(await confirmDlg({ title: `Excluir “${a.name}”?`, text: "Para o app e apaga código, logs, imagem e volume. O registro DNS no Cloudflare continua lá. Não dá para desfazer.", ok: "Excluir" }))) return;
  await act(`/api/app/delete?id=${a.id}`, null, "Aplicação excluída");
}

/* envio de arquivo: XHR para ter a barra de progresso */
function uploadFile(id, file, onprog) {
  return new Promise((res) => {
    const x = new XMLHttpRequest();
    x.open("POST", `/api/app/upload?id=${encodeURIComponent(id)}&name=${encodeURIComponent(file.name)}`);
    x.setRequestHeader("X-Requested-With", "hosting");
    x.upload.onprogress = (e) => { if (e.lengthComputable && onprog) onprog(e.loaded / e.total); };
    x.onload = () => { let m; try { m = JSON.parse(x.responseText).error; } catch {} res(x.status === 200 ? null : m || "falha no envio"); };
    x.onerror = () => res("conexão perdida durante o envio");
    x.send(file);
  });
}
function pickUpload(a) {
  const inp = h("input", { type: "file", accept: ".zip,.tar.gz,.tgz", hidden: "" });
  inp.onchange = async () => {
    const f = inp.files[0]; if (!f) return;
    const err = await uploadFile(a.id, f, (p) => toast(`Enviando ${f.name}… ${nf0.format(p * 100)}%`));
    if (err) { toast(err); return; }
    toast("Arquivo recebido, construindo"); await refresh(); openLogs(a.id, "deploy");
  };
  document.body.append(inp); inp.click(); setTimeout(() => inp.remove(), 60000);
}

/* formulário */
let editing = null;
function dbOptions(scope, cur) {
  const sel = $("#app-db"); sel.replaceChildren(h("option", { value: "" }, "Nenhum"));
  D.dbs.filter((d) => scope !== "shared" || d.owner === "shared").forEach((d) => sel.append(h("option", { value: d.id }, `${d.name} · ${d.engine === "postgres" ? "PostgreSQL" : "MySQL"}${d.owner === "shared" ? " · compartilhado" : ""}`)));
  sel.value = cur || "";
}
function bucketOptions(scope, cur) {
  const sel = $("#app-bucket"); sel.replaceChildren(h("option", { value: "" }, "Nenhum"));
  D.buckets.filter((b) => scope !== "shared" || b.owner === "shared").forEach((b) => sel.append(h("option", { value: b.id }, `${b.name}${b.owner === "shared" ? " · compartilhado" : ""}`)));
  sel.value = cur || "";
}
function setSource(k) {
  segSet($("#app-src"), "k", k);
  const zip = k === "zip";
  $("#src-gh").hidden = zip; $("#src-zip").hidden = !zip; $("#deploy-w").hidden = zip;
  $("#app-form").elements.repo.required = !zip;
}
$("#app-src").addEventListener("change", () => setSource(segValue($("#app-src"), "k")));
// com arquivo escolhido o botão deixa claro que envia também
function okLabel() { const f = $("#app-form").elements; $("#app-ok").textContent = f.file.files[0] ? "Salvar e enviar" : editing ? "Salvar" : "Criar"; }
$("#app-form").elements.file.addEventListener("change", okLabel);
function openAppForm(a) {
  editing = a || null;
  const f = $("#app-form"), el = f.elements;
  f.reset(); $("#app-err").textContent = "";
  $("#app-t").textContent = a ? "Editar aplicação" : "Nova aplicação";
  $("#app-ok").textContent = a ? "Salvar" : "Criar";
  segSet($("#app-scope"), "s", a ? (a.owner === "shared" ? "shared" : "private") : "private");
  el.name.value = a?.name || ""; el.repo.value = a?.repo || ""; el.branch.value = a?.branch || "main";
  el.host.value = a?.host || ""; el.env.value = a?.env || ""; el.runtime.value = a?.runtime || "auto";
  el.build.value = a?.build || ""; el.start.value = a?.start || ""; el.cport.value = a?.cport || 3000; el.mem.value = a?.mem || 512; el.volume.value = a?.volume || "";
  el.autodeploy.checked = a ? !!a.autodeploy : true; el.deploy.checked = !a;
  el.expose.checked = a ? !!a.expose : true; el.port.value = a ? a.port : "";
  setSource(a?.zip ? "zip" : "github"); okLabel();
  $("#app-src").style.pointerEvents = a ? "none" : ""; $("#app-src").style.opacity = a ? ".55" : ""; // a origem não muda depois de criado
  $("#zip-hint").textContent = a?.zip ? `Atual: ${a.upname || "nenhum"}. Escolha um arquivo para enviar uma nova versão (ou deixe vazio para manter).` : "O servidor extrai, entende a estrutura (Dockerfile, Node, Python, Go ou site estático) e sobe. Pasta única por fora do zip é descartada.";
  $("#tok-hint").textContent = a?.has_token ? "Há um token salvo. Deixe em branco para manter, ou digite “-” para remover." : "";
  $("#dom-list").replaceChildren(...D.domains.map((d) => h("option", { value: d.name })));
  const names = D.domains.map((d) => d.name).join(", ");
  $("input[name=host]").nextElementSibling.nextElementSibling.textContent = names ? `Termina em um dos seus domínios: ${names}. O servidor cria o DNS e a rota sozinho.` : "Você ainda não tem domínio cadastrado: adicione um na aba Domínios.";
  dbOptions(segValue($("#app-scope"), "s"), a?.db); bucketOptions(segValue($("#app-scope"), "s"), a?.bucket);
  const nat = !!D.native; // sem direito a comandos no servidor: só container (o servidor também impõe isso)
  for (const k of ["runtime", "build", "start"]) el[k].disabled = !nat;
  if (!nat) el.runtime.value = "podman";
  $("#nat-note").hidden = nat;
  $(".adv").open = !nat || !!(a && (a.build || a.start || a.volume || a.runtime !== "auto"));
  $("#dlg-app").showModal(); el.name.focus();
}
$("#app-scope").addEventListener("change", () => { dbOptions(segValue($("#app-scope"), "s"), $("#app-db").value); bucketOptions(segValue($("#app-scope"), "s"), $("#app-bucket").value); });
$("#app-new").addEventListener("click", () => openAppForm());
$("#app-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const el = e.target.elements, b = $("#app-ok"), err = $("#app-err");
  err.textContent = "";
  const zip = segValue($("#app-src"), "k") === "zip", file = el.file.files[0];
  if (zip && !editing && !file) { err.textContent = "Escolha o arquivo .zip ou .tar.gz do projeto."; return; }
  const data = {
    name: el.name.value, scope: segValue($("#app-scope"), "s"), source: zip ? "zip" : "github", repo: el.repo.value, branch: el.branch.value, token: el.token.value, host: el.host.value, db: el.db.value, bucket: el.bucket.value,
    env: el.env.value, runtime: el.runtime.value, build: el.build.value, start: el.start.value, cport: el.cport.value, mem: el.mem.value, volume: el.volume.value,
    port: el.port.value, expose: el.expose.checked ? "1" : "0",
    autodeploy: el.autodeploy.checked && !zip ? "1" : "0", deploy: el.deploy.checked && !zip ? "1" : "0",
  };
  if (editing) data.id = editing.id;
  b.disabled = true; const t0 = b.textContent; b.textContent = "Salvando…";
  try {
    const r = await post("/api/app/save", data);
    if (!r.ok) { err.textContent = await errMsg(r); return; }
    const j = await r.json();
    if (zip && file) { // envia o arquivo; o servidor extrai e faz o deploy sozinho
      const e2 = await uploadFile(j.id, file, (p) => { b.textContent = `Enviando ${nf0.format(p * 100)}%`; });
      if (e2) { err.textContent = `Salvo, mas o envio falhou: ${e2}`; await refresh(); return; }
    }
    $("#dlg-app").close();
    toast(j.warn ? `Salvo, mas o endereço falhou: ${j.warn}` : "Salvo");
    await refresh();
    if (data.deploy === "1" || (zip && file)) openLogs(j.id, "deploy");
  } catch { err.textContent = "Não foi possível falar com o servidor."; }
  finally { b.disabled = false; b.textContent = t0; }
});

/* logs / histórico / webhook */
let L = { id: null, tab: "deploy", timer: 0 };
const TRIG = { manual: "Manual", webhook: "Webhook", poll: "Verificação" };
function openLogs(id, tab) {
  L.id = id; $("#log-t").textContent = D.apps.find((a) => a.id === id)?.name || id;
  setTab(tab); const d = $("#dlg-log"); if (!d.open) d.showModal();
  clearInterval(L.timer); L.timer = setInterval(loadLog, 1500);
}
$("#dlg-log").addEventListener("close", () => clearInterval(L.timer));
$("#log-tabs").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) setTab(b.dataset.t); });
function setTab(t) {
  L.tab = t; segSet($("#log-tabs"), "t", t);
  $("#log-pre").textContent = LOG_WAIT; $("#log-hist").replaceChildren(h("div", { class: "empty" }, h("b", {}, LOG_WAIT)));
  $("#log-pre").hidden = !(t === "deploy" || t === "run"); $("#log-hist").hidden = t !== "hist"; $("#log-hook").hidden = t !== "hook";
  if (t === "hook") renderHook(); else loadLog();
}
let logKey = "";
const LOG_WAIT = "Carregando…", LOG_FAIL = "Sem resposta do servidor (a conexão pode estar lenta). Tentando de novo…";
async function loadLog() {
  const id = L.id, tab = L.tab, key = id + "/" + tab;
  if (!id || tab === "hook" || logKey === key) return; // uma busca por vez: link lento não pode empilhar requisições
  logKey = key;
  const same = () => id === L.id && tab === L.tab;
  try {
    const r = await api(`/api/app/log?id=${id}&which=${tab}`, { timeout: 12000 });
    if (!r.ok) throw new Error("http " + r.status);
    const txt = await r.text();
    if (!same()) return; // o usuário trocou de aba/app enquanto esperava
    if (tab === "hist") {
      const rows = txt.trim().split("\n").filter(Boolean).reverse().map((l) => l.split("\t"));
      const box = $("#log-hist"); box.replaceChildren();
      if (!rows.length) { box.append(h("div", { class: "empty" }, h("b", {}, "Sem deploys ainda"))); return; }
      box.append(h("table", { class: "hist" }, h("thead", {}, h("tr", {}, ...["Quando", "Commit", "Origem", "Resultado", "Mensagem", "Tempo"].map((x) => h("th", {}, x)))),
        h("tbody", {}, ...rows.map((c) => h("tr", {}, h("td", {}, fdate(+c[0])), h("td", {}, h("code", {}, c[1])), h("td", {}, TRIG[c[2]] || c[2]), h("td", {}, c[3] === "ok" ? "Ok" : "Erro"), h("td", {}, c[4]), h("td", {}, `${c[5]} s`))))));
      return;
    }
    const pre = $("#log-pre"), stick = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 40;
    const out = txt || (tab === "run" ? "O app ainda não escreveu nada." : "Nenhum deploy foi feito ainda.");
    if (pre.textContent !== out) { pre.textContent = out; if (stick) pre.scrollTop = pre.scrollHeight; }
  } catch (e) {
    if (e.message === "login" || !same()) return;
    // não apaga o que já está na tela; só avisa quando ainda não há nada para mostrar
    if (tab === "hist") { const box = $("#log-hist"); if (!box.querySelector("table")) box.replaceChildren(h("div", { class: "empty" }, h("b", {}, LOG_FAIL))); }
    else { const pre = $("#log-pre"); if (pre.textContent === LOG_WAIT || pre.textContent === LOG_FAIL) pre.textContent = LOG_FAIL; }
  } finally { if (logKey === key) logKey = ""; }
}
function renderHook() {
  const a = D.apps.find((x) => x.id === L.id), box = $("#log-hook"); box.replaceChildren();
  if (!a) return;
  if (a.zip) { box.append(h("div", { class: "notice" }, h("b", {}, "Este app é enviado por arquivo. "), "Não usa GitHub: para atualizar, use “Enviar zip” no cartão.")); return; }
  const url = D.hook_host ? `https://${D.hook_host}/hook/${a.id}` : "";
  box.append(
    h("div", { class: "notice" }, D.hook_host ? h("span", {}, h("b", {}, "Webhook ativo no servidor. "), "Cada push na branch ", h("b", {}, a.branch), " dispara um deploy na hora.") : h("span", {}, h("b", {}, "Sem endereço de webhooks. "), "Enquanto isso, o servidor confere o GitHub a cada 2 minutos. Para deploy instantâneo, defina o endereço na aba Domínios.")),
    h("label", { class: "field" }, h("span", {}, "URL do payload"), url ? copyField(url) : h("div", { class: "cf" }, h("code", {}, "defina o endereço de webhooks primeiro"))),
    h("label", { class: "field" }, h("span", {}, "Secret"), copyField(a.secret, true)),
    h("div", {}, btn("Criar o webhook no GitHub", "rocket", { primary: true, disabled: !url || !a.has_token, onclick: async (ev) => { ev.currentTarget.disabled = true; await act(`/api/app/webhook?id=${a.id}`, null, "Webhook criado no GitHub"); ev.currentTarget.disabled = false; } }),
      h("p", { class: "hint", style: "margin-top:8px" }, !a.has_token ? "Precisa de um token do GitHub com permissão de webhooks salvo neste app (Editar)." : !url ? "Precisa do endereço de webhooks." : "Usa o token salvo neste app.")),
    h("div", {}, h("p", { class: "hint", style: "margin-bottom:6px" }, "Ou, manualmente, em GitHub → repositório → Settings → Webhooks → Add webhook:"),
      h("ol", {}, h("li", {}, "Payload URL: a URL acima"), h("li", {}, "Content type: application/json"), h("li", {}, "Secret: o secret acima"), h("li", {}, "Evento: apenas “push”"))));
}

/* ---------- bancos ---------- */
const ENG = { postgres: "PostgreSQL", mysql: "MySQL" };
function renderDbs() {
  const notes = $("#db-notes"); notes.replaceChildren();
  const t = D.tools;
  for (const [k, name, has, up] of [["pg", "PostgreSQL", t.psql, t.pg_up], ["my", "MySQL", t.mysql, t.my_up]]) notes.append(h("span", { class: "tag" + (up ? " hot" : "") }, `${name} ${up ? "ativo" : has ? "parado" : "não instalado"}`));
  const box = $("#dbs"); box.replaceChildren();
  if (!D.dbs.length) box.append(h("div", { class: "card empty", style: "grid-column:1/-1" }, h("b", {}, "Nenhum banco ainda"), h("span", {}, "Crie um PostgreSQL ou MySQL interno e ligue a uma aplicação: ela recebe a conexão pronta.")));
  for (const d of D.dbs.slice().sort((x, y) => x.name.localeCompare(y.name, "pt-BR"))) {
    const pg = d.engine === "postgres", url = `${pg ? "postgres" : "mysql"}://${d.user}:${d.password}@127.0.0.1:${d.port}/${d.user}`;
    const users = D.apps.filter((a) => a.db === d.id).map((a) => a.name);
    box.append(h("article", { class: "card acard" },
      h("div", { class: "acard-h" }, icon("db"), h("b", {}, d.name), h("span", { class: "tag" }, ENG[d.engine] + " · " + SCOPE(d.owner))),
      h("div", { class: "acard-l" }, h("div", {}, h("span", {}, "Servidor "), h("code", {}, `127.0.0.1:${d.port}`)), h("div", {}, h("span", {}, "Usuário e banco "), h("code", {}, d.user)),
        h("div", { class: "dbpw" }, h("span", {}, "Senha"), copyField(d.password, true)),
        h("div", {}, h("span", { class: "apps-in" }, users.length ? `Usado por ${users.join(", ")}` : "Não está ligado a nenhuma aplicação")),
        h("div", {}, h("span", { class: "apps-in" }, "Dentro de container, o servidor é host.containers.internal"))),
      h("div", { class: "acard-b" }, btn("Explorar", "table", { primary: true, onclick: () => { location.hash = `#bancos/${enc(d.id)}`; } }), btn("Copiar URL", "copy", { onclick: () => copy(url, "URL copiada") }), h("span", { class: "sp" }),
        iconBtn("trash", "Excluir", async () => {
          if (!(await confirmDlg({ title: `Excluir o banco “${d.name}”?`, text: "Apaga o banco e o usuário com todos os dados. Não dá para desfazer.", ok: "Excluir" }))) return;
          await act(`/api/db/delete?id=${d.id}`, null, "Banco excluído");
        }))));
  }
}
$("#db-new").addEventListener("click", () => { $("#db-form").reset(); $("#db-err").textContent = ""; segSet($("#db-engine"), "e", D.tools.pg_up || !D.tools.my_up ? "postgres" : "mysql"); segSet($("#db-scope"), "s", "private"); $("#dlg-db").showModal(); $("#db-form").elements.name.focus(); });
$("#db-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const b = $("#db-ok"); b.disabled = true; $("#db-err").textContent = "";
  try {
    const r = await post("/api/db/create", { name: e.target.elements.name.value, engine: segValue($("#db-engine"), "e"), scope: segValue($("#db-scope"), "s") });
    if (!r.ok) { $("#db-err").textContent = await errMsg(r); return; }
    $("#dlg-db").close(); toast("Banco criado"); refresh();
  } catch { $("#db-err").textContent = "Não foi possível falar com o servidor."; } finally { b.disabled = false; }
});

/* ---------- domínios ---------- */
function renderDoms() {
  const box = $("#doms"); box.replaceChildren();
  for (const d of D.domains) {
    const n = D.apps.filter((a) => a.host && (a.host === d.name || a.host.endsWith("." + d.name))).length;
    box.append(h("article", { class: "card acard" },
      h("div", { class: "acard-h" }, icon("globe"), h("b", {}, d.name), h("span", { class: "tag" }, SCOPE(d.owner))),
      h("div", { class: "acard-l" }, h("div", {}, h("span", {}, d.cert ? "Conectado a este servidor pelo login do cloudflared" : "Acesso por token da API do Cloudflare")), h("div", {}, h("span", {}, n ? `${n} aplicaç${n > 1 ? "ões" : "ão"} usando` : "Nenhuma aplicação usando"))),
      h("div", { class: "acard-b" }, h("span", { class: "sp" }), iconBtn("trash", "Remover", async () => {
        if (!(await confirmDlg({ title: `Remover “${d.name}”?`, text: "Só tira o domínio desta lista. Nada muda no Cloudflare.", ok: "Remover" }))) return;
        await act(`/api/domain/delete?name=${encodeURIComponent(d.name)}`, null, "Domínio removido");
      }))));
  }
  if (!D.domains.length) box.append(h("div", { class: "card empty", style: "grid-column:1/-1" }, h("b", {}, "Nenhum domínio"), h("span", {}, "Adicione um domínio do Cloudflare para publicar aplicações nele.")));
  const hf = $("#hook-host"); if (document.activeElement !== hf && hf.dataset.v !== D.hook_host) { hf.value = D.hook_host; hf.dataset.v = D.hook_host; }
  const tg = $("#hook-tag"); tg.textContent = D.hook_host ? "Webhook instantâneo" : "Verificação a cada 2 min"; tg.classList.toggle("hot", !!D.hook_host);
}
$("#dom-new").addEventListener("click", () => { $("#dom-form").reset(); $("#dom-err").textContent = ""; segSet($("#dom-scope"), "s", "private"); $("#dlg-dom").showModal(); $("#dom-form").elements.name.focus(); });
$("#dom-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const b = $("#dom-ok"); b.disabled = true; b.textContent = "Verificando…"; $("#dom-err").textContent = "";
  try {
    const el = e.target.elements;
    const r = await post("/api/domain/add", { name: el.name.value, token: el.token.value, scope: segValue($("#dom-scope"), "s") });
    if (!r.ok) { $("#dom-err").textContent = await errMsg(r); return; }
    $("#dlg-dom").close(); toast("Domínio adicionado"); refresh();
  } catch { $("#dom-err").textContent = "Não foi possível falar com o servidor."; } finally { b.disabled = false; b.textContent = "Adicionar"; }
});
$("#hook-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("#hook-err"); err.textContent = "";
  try {
    const r = await post("/api/settings", { hook_host: $("#hook-host").value });
    if (!r.ok) { err.textContent = await errMsg(r); return; }
    toast("Salvo"); refresh();
  } catch {}
});

/* ---------- estatísticas ---------- */
let S = null, stBusy = false, stSel = "all";
const bytesF = (n) => (n < 1024 ? `${n} B` : n < 1048576 * 0.995 ? `${(n / 1024).toFixed(1)} KB` : n < 1073741824 * 0.995 ? `${(n / 1048576).toFixed(1)} MB` : `${(n / 1073741824).toFixed(2)} GB`);
const msF = (n) => (!n ? "–" : n >= 1000 ? `${n / 1000} s` : `${n} ms`);
const pct = (a, b) => (!b || !a ? "0%" : `${((a / b) * 100).toFixed(a / b < 0.01 ? 2 : a / b < 0.1 ? 1 : 0)}%`);
function stFill() {
  const sel = $("#st-app"); if (!D) return;
  const want = ["all", ...D.apps.map((a) => a.id)].join(",");
  if (sel.dataset.k !== want) {
    sel.dataset.k = want; sel.replaceChildren(h("option", { value: "all" }, "Todas as aplicações"), ...D.apps.map((a) => h("option", { value: a.id }, a.name)));
  }
  sel.value = D.apps.some((a) => a.id === stSel) ? stSel : "all";
}
async function loadStats() {
  if (location.hash !== "#estatisticas" || stBusy || !D) return;
  stBusy = true;
  try {
    const r = await api(`/api/stats?app=${encodeURIComponent($("#st-app").value || "all")}&range=${segValue($("#st-range"), "r")}`);
    if (r.ok) { S = await r.json(); drawStats(); } else toast(await errMsg(r));
  } catch { /* próxima volta tenta de novo */ } finally { stBusy = false; }
}
$("#st-app").addEventListener("change", () => { stSel = $("#st-app").value; loadStats(); });
$("#st-range").addEventListener("change", loadStats);
addEventListener("resize", () => { if (S && location.hash === "#estatisticas") drawStats(); });
setInterval(() => { if (!document.hidden) loadStats(); }, 10000);

const kpi = (label, value, sub) => h("div", { class: "kpi" }, h("span", { class: "kpi-l" }, label), h("b", { class: "kpi-v" }, value), sub ? h("span", { class: "kpi-s" }, sub) : null);
function buckets() { // 24h e 7d: uma barra por hora; 30d: uma por dia
  if (S.range !== "30d") return S.hours.map(([t, r, v]) => ({ t, r, v, label: new Date(t * 1000).toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" }).replace(",", "") }));
  const d0 = S.days[0][0], out = S.days.map(([t, v]) => ({ t, r: 0, v, label: new Date(t * 1000).toLocaleDateString("pt-BR", { weekday: "short", day: "2-digit", month: "2-digit" }) }));
  for (const [t, r] of S.hours) out[Math.min(out.length - 1, Math.max(0, Math.floor((t - d0 + 43200) / 86400)))].r += r;
  return out;
}
function chart(bs) {
  const W = Math.max(300, Math.min(800, ($("#st-body").clientWidth || 840) - 42)), narrow = W < 500, H = 220, L = 38, R = 6, T = 8, B = 22, n = bs.length, bw = (W - L - R) / n; // W segue o container: o texto dos eixos não encolhe no celular
  const mx = Math.max(1, ...bs.map((b) => b.r)), top = mx <= 4 ? mx : Math.ceil(mx / 4) * 4, y = (v) => T + (H - T - B) * (1 - v / top);
  const NS = "http://www.w3.org/2000/svg", svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`); svg.setAttribute("class", "st-svg"); svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", `Requisições e visitantes por ${S.range === "30d" ? "dia" : "hora"}`);
  let g = "";
  for (const f of [0, 0.5, 1]) g += `<line class="gl" x1="${L}" x2="${W - R}" y1="${y(top * f)}" y2="${y(top * f)}"/><text class="ax" x="${L - 6}" y="${y(top * f) + 4}" text-anchor="end">${nf0.format(top * f)}</text>`;
  const step = S.range === "24h" ? 3 : S.range === "7d" ? 24 : 5;
  bs.forEach((b, i) => {
    const x = L + i * bw, w = Math.max(1.5, bw * (n > 100 ? 0.8 : 0.66)), x0 = x + (bw - w) / 2;
    if (b.r) g += `<rect class="b-req" x="${x0}" y="${y(b.r)}" width="${w}" height="${y(0) - y(b.r)}" rx="${Math.min(2, w / 2)}"/>`;
    if (b.v) { const vw = w * 0.55; g += `<rect class="b-vis" x="${x0 + (w - vw) / 2}" y="${y(b.v)}" width="${vw}" height="${y(0) - y(b.v)}" rx="${Math.min(2, vw / 2)}"/>`; }
    const d = new Date(b.t * 1000);
    const lab = S.range === "24h" ? (d.getHours() % step === 0 && `${String(d.getHours()).padStart(2, "0")}h`) : S.range === "7d" ? (d.getHours() === 0 && d.toLocaleDateString("pt-BR", narrow ? { day: "2-digit" } : { weekday: "short", day: "2-digit" })) : (i % step === 0 && d.toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit" }));
    if (lab) g += `<text class="ax" x="${x + bw / 2}" y="${H - 6}" text-anchor="middle">${lab}</text>`;
  });
  svg.innerHTML = g;
  const wrap = h("div", { class: "st-chart" }), tip = h("div", { class: "st-tip", hidden: "" });
  wrap.append(svg, tip);
  const show = (e) => {
    const r = svg.getBoundingClientRect(), i = Math.floor(((e.clientX - r.left) / r.width * W - L) / bw);
    if (i < 0 || i >= n) { tip.hidden = true; return; }
    const b = bs[i]; tip.hidden = false;
    tip.replaceChildren(h("b", {}, b.label), h("span", {}, `${nf0.format(b.r)} requisições`), h("span", {}, `${nf0.format(b.v)} visitantes`));
    const x = (L + (i + 0.5) * bw) / W * r.width;
    tip.style.left = `${Math.min(Math.max(x, 70), r.width - 70)}px`;
  };
  wrap.addEventListener("pointermove", show); wrap.addEventListener("pointerleave", () => { tip.hidden = true; });
  return wrap;
}
function topList(title, rows, hint) {
  const mx = Math.max(1, ...rows.map((r) => r[1]));
  return h("div", { class: "card st-top" }, h("div", { class: "card-h" }, h("span", {}, title), hint ? h("span", { class: "muted small" }, hint) : null),
    rows.length ? h("ul", {}, rows.map(([k, n]) => h("li", {}, h("i", { style: `width:${(n / mx) * 100}%` }), h("span", { class: "k", title: k }, k), h("b", {}, nf0.format(n))))) : h("p", { class: "muted small" }, "Ainda sem dados neste período."));
}
function drawStats() {
  const body = $("#st-body"), bs = buckets(), all = $("#st-app").value === "all", per = S.range === "24h" ? "hoje" : S.range === "7d" ? "em 7 dias" : "em 30 dias";
  const err5 = S.s5;
  const box = h("div", {},
    h("div", { class: "kpis" },
      kpi("Online agora", nf0.format(S.online), "visitantes nos últimos 5 min"),
      kpi("Visitantes hoje", nf0.format(S.visitors_today), "únicos, sem contar bots"),
      S.range === "24h" ? null : kpi("Visitantes", nf0.format(S.visitors), `somando os únicos de cada dia ${per}`),
      kpi("Requisições", nf0.format(S.req), `${nf0.format(S.pages)} páginas · ${nf0.format(S.bots)} de bots`),
      kpi("Erros do servidor", pct(err5, S.req), `${nf0.format(err5)} respostas 5xx · ${nf0.format(S.s4)} 4xx`),
      kpi("Resposta (p95)", S.p95 ? `≤ ${msF(S.p95)}` : "–", `mediana ≤ ${msF(S.p50)} · média ${msF(S.avg)}`),
      kpi("Tráfego enviado", bytesF(S.bout), `${bytesF(S.bin)} recebidos`)),
    h("div", { class: "card st-main" },
      h("div", { class: "card-h" }, h("span", {}, `Por ${S.range === "30d" ? "dia" : "hora"}`),
        h("span", { class: "legend" }, h("i", { class: "sw req" }), "Requisições", h("i", { class: "sw vis" }), "Visitantes")),
      S.req ? chart(bs) : h("div", { class: "empty st-empty" }, h("b", {}, "Nenhuma visita ainda neste período"), h("span", {}, "Assim que alguém abrir o app (pelo domínio, pela porta ou pelo Tailscale) os números aparecem aqui.")),
      S.req ? h("details", { class: "st-table" }, h("summary", {}, "Ver como tabela"),
        h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, S.range === "30d" ? "Dia" : "Hora"), h("th", {}, "Requisições"), h("th", {}, "Visitantes"))),
          h("tbody", {}, bs.filter((b) => b.r || b.v).reverse().map((b) => h("tr", {}, h("td", {}, b.label), h("td", {}, nf0.format(b.r)), h("td", {}, nf0.format(b.v))))))) : null),
    h("div", { class: "st-grid" },
      topList("Páginas mais vistas", S.top.pages), topList("De onde vêm", S.top.refs, "referências"), topList("Países", S.top.countries),
      topList("Navegadores", S.top.browsers), topList("Dispositivos", S.top.devices),
      h("div", { class: "card st-top" }, h("div", { class: "card-h" }, h("span", {}, "Respostas")),
        h("ul", {}, [["Sucesso (2xx)", S.s2], ["Redirecionamento (3xx)", S.s3], ["Erro do visitante (4xx)", S.s4], ["Erro do servidor (5xx)", S.s5]].map(([k, n]) => h("li", {}, h("i", { style: `width:${S.req ? (n / S.req) * 100 : 0}%` }), h("span", { class: "k" }, k), h("b", {}, nf0.format(n))))))),
    all && S.apps && S.apps.length > 1 ? h("div", { class: "card st-apps" }, h("div", { class: "card-h" }, h("span", {}, "Por aplicação")),
      h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Aplicação"), h("th", {}, "Online"), h("th", {}, "Visitantes hoje"))),
        h("tbody", {}, S.apps.map((a) => h("tr", {}, h("td", {}, h("a", { href: "#estatisticas", onclick: (e) => { e.preventDefault(); stSel = a.id; stFill(); loadStats(); } }, a.name)), h("td", {}, nf0.format(a.online)), h("td", {}, nf0.format(a.vis))))))) : null);
  body.replaceChildren(box);
}

/* ---------- histórico de deploys ---------- */
let DP = null, dpBusy = false;
const dpDur = (s) => (s < 60 ? `${s} s` : `${Math.floor(s / 60)} min ${s % 60} s`);
function dpFill() {
  const sel = $("#dp-app"); if (!D) return;
  const want = D.apps.map((a) => a.id).join(",");
  if (sel.dataset.k === want) return;
  const cur = sel.value; sel.dataset.k = want;
  sel.replaceChildren(h("option", { value: "" }, "Todas as aplicações"), ...D.apps.map((a) => h("option", { value: a.id }, a.name)));
  sel.value = D.apps.some((a) => a.id === cur) ? cur : "";
}
async function loadDeploys() {
  if (!location.hash.startsWith("#deploys") || dpBusy || !D) return;
  dpBusy = true;
  try {
    const app = $("#dp-app").value, r = await api(`/api/deploys?limit=200${app ? `&app=${encodeURIComponent(app)}` : ""}`);
    if (r.ok) { DP = await r.json(); drawDeploys(); }
  } catch { /* a próxima volta tenta de novo */ } finally { dpBusy = false; }
}
function openDeployLog(x) {
  $("#dl-t").textContent = `${x.name} · ${fdate(x.ts)}`; $("#dl-pre").textContent = "Carregando…";
  $("#dlg-dl").showModal();
  api(`/api/deploy/log?id=${encodeURIComponent(x.app)}&ts=${x.ts}`).then(async (r) => { $("#dl-pre").textContent = r.ok ? (await r.text()) || "(log vazio)" : await errMsg(r); }).catch(() => {});
}
function drawDeploys() {
  const res = segValue($("#dp-res"), "r"), body = $("#dp-body");
  const oks = DP.deploys.filter((x) => x.res === "ok"), rows = DP.deploys.filter((x) => !res || x.res === res);
  const avg = oks.length ? Math.round(oks.reduce((n, x) => n + x.secs, 0) / oks.length) : 0, last = DP.deploys[0];
  const stat = (x) => (x.res === "ok" ? h("span", { class: "dp-st ok" }, h("i", {}), "Ok") : h("span", { class: "dp-st bad" }, h("i", {}), "Erro"));
  const tr = (x) => h("tr", { class: x.log ? "click" : "", ...(x.log ? { tabindex: "0", role: "button", onclick: () => openDeployLog(x), onkeydown: (e) => { if (e.key === "Enter") openDeployLog(x); } } : { title: "O log deste deploy não foi guardado" }) },
    h("td", {}, stat(x)), h("td", {}, h("b", {}, x.name)),
    h("td", { class: "dp-msg" }, x.sha !== "-" && x.sha !== "0000000" ? h("code", {}, x.sha) : null, x.msg && x.msg !== "-" ? ` ${x.msg}` : ""),
    h("td", {}, TRIG[x.trig] || (x.trig === "upload" ? "Envio de arquivo" : x.trig)), h("td", { class: "r" }, dpDur(x.secs)), h("td", { class: "r", title: new Date(x.ts * 1000).toLocaleString("pt-BR") }, ago(x.ts)));
  const live = DP.building.filter((b) => !$("#dp-app").value || b.app === $("#dp-app").value).map((b) =>
    h("tr", { class: "click", tabindex: "0", role: "button", onclick: () => openLogs(b.app, "deploy") }, h("td", {}, h("span", { class: "dp-st run" }, h("i", {}), "Em andamento")), h("td", {}, h("b", {}, b.name)), h("td", { class: "dp-msg" }, "Construindo agora… clique para acompanhar o log"), h("td", {}), h("td", { class: "r" }, dpDur(Math.max(0, Math.floor(Date.now() / 1000 - b.since)))), h("td", { class: "r" }, ago(b.since))));
  body.replaceChildren(h("div", {},
    h("div", { class: "kpis" },
      kpi("Deploys", nf0.format(DP.deploys.length), "no histórico carregado"),
      kpi("Taxa de sucesso", DP.deploys.length ? `${Math.round((oks.length / DP.deploys.length) * 100)}%` : "–", `${nf0.format(DP.deploys.length - oks.length)} com erro`),
      kpi("Duração média", oks.length ? dpDur(avg) : "–", "só deploys com sucesso"),
      kpi("Último deploy", last ? ago(last.ts) : "–", last ? `${last.name} · ${last.res === "ok" ? "ok" : "erro"}` : "nenhum ainda")),
    rows.length || live.length ? h("div", { class: "card dp-card" }, h("table", { class: "hist dp" }, h("thead", {}, h("tr", {}, ...["Resultado", "Aplicação", "Commit", "Origem", "Duração", "Quando"].map((x, i) => h("th", { class: i > 3 ? "r" : "" }, x)))), h("tbody", {}, ...live, ...rows.map(tr))))
      : h("div", { class: "card empty" }, h("b", {}, res ? "Nenhum deploy com esse filtro" : "Nenhum deploy ainda"), h("span", {}, "Cada deploy, manual, por webhook ou por envio de arquivo, aparece aqui com o log completo."))));
}
$("#dp-app").addEventListener("change", loadDeploys);
$("#dp-res").addEventListener("change", () => { if (DP) drawDeploys(); });
setInterval(() => { if (!document.hidden) loadDeploys(); }, 4000);

/* ---------- explorador de banco ---------- */
let X = null; // {id, db, tables, sel, tab, page, sort, dir, seq, sql}
const enc = encodeURIComponent;
function grid(g, o = {}) {
  if (!g.columns.length) return h("div", { class: "card empty" }, h("b", {}, g.msg || "Comando executado"), h("span", {}, "Sem linhas para mostrar."));
  return h("div", { class: "grid-w" }, h("table", { class: "grid" },
    h("thead", {}, h("tr", {}, ...g.columns.map((c) => h("th", o.sort ? { class: "srt", tabindex: "0", onclick: () => o.sort(c), onkeydown: (e) => { if (e.key === "Enter") o.sort(c); } } : {}, c, o.col === c ? (o.dir === "desc" ? " ↓" : " ↑") : "")))),
    h("tbody", {}, g.rows.length ? g.rows.map((r) => h("tr", {}, r.map((v) => (v === null ? h("td", {}, h("i", { class: "nul" }, "NULL")) : h("td", { title: v, onclick: () => copy(v, "Valor copiado") }, v))))) : h("tr", {}, h("td", { colspan: g.columns.length, class: "muted" }, "Nenhuma linha")))));
}
const xErr = (m) => h("div", { class: "notice err" }, m);
async function xget(url) { const r = await api(url, { timeout: 40000 }); if (!r.ok) throw new Error(await errMsg(r)); return r.json(); }
function openDbx(id) {
  const db = D.dbs.find((d) => d.id === id);
  if (!db) { location.hash = "#bancos"; return; }
  if (!X || X.id !== id) X = { id, db, tables: null, sel: null, tab: "data", page: 0, sort: "", dir: "asc", seq: 0, sql: "" };
  $("#dbx-name").textContent = db.name; $("#dbx-eng").textContent = ENG[db.engine];
  segSet($("#dbx-tabs"), "t", X.tab);
  if (!X.tables) xTables(); else { xList(); xLoad(); }
}
async function xTables() {
  const box = $("#dbx-tables"); box.replaceChildren(h("p", { class: "muted small" }, "Carregando tabelas…"));
  try {
    const g = await xget(`/api/db/view?id=${enc(X.id)}&what=tables`);
    X.tables = g.rows.map(([s, name, kind, est, bytes]) => ({ s, name, kind, est: +est, bytes: +bytes }));
    if (!X.sel && X.tables.length) X.sel = X.tables[0];
    xList(); xLoad();
  } catch (e) { if (e.message !== "login") { box.replaceChildren(xErr(e.message)); $("#dbx-body").replaceChildren(); } }
}
function xList() {
  const box = $("#dbx-tables");
  box.replaceChildren(h("div", { class: "card-h" }, h("span", {}, "Tabelas"), h("span", { class: "muted small" }, X.tables.length)),
    X.tables.length ? h("ul", {}, X.tables.map((t) => h("li", {}, h("button", { type: "button", class: X.sel === t ? "on" : "", onclick: () => { X.sel = t; X.page = 0; X.sort = ""; if (X.tab === "sql") { X.tab = "data"; segSet($("#dbx-tabs"), "t", "data"); } xList(); xLoad(); } },
      icon(t.kind === "view" ? "eye" : "table"), h("span", { class: "k" }, (t.s && t.s !== "public" ? `${t.s}.` : "") + t.name), h("small", {}, t.kind === "view" ? "view" : t.est >= 0 ? `~${nf0.format(t.est)}` : "")))))
      : h("p", { class: "muted small" }, "Este banco ainda não tem tabelas."));
}
async function xLoad() {
  const body = $("#dbx-body"), seq = ++X.seq;
  if (X.tab === "sql") return xSql();
  if (!X.sel) { body.replaceChildren(h("div", { class: "card empty" }, h("b", {}, "Escolha uma tabela"))); return; }
  const q = `&s=${enc(X.sel.s || "")}&t=${enc(X.sel.name)}`;
  try {
    if (X.tab === "cols") { const g = await xget(`/api/db/view?id=${enc(X.id)}&what=cols${q}`); if (seq === X.seq) body.replaceChildren(grid(g)); return; }
    const g = await xget(`/api/db/view?id=${enc(X.id)}&what=rows${q}&page=${X.page}${X.sort ? `&sort=${enc(X.sort)}&dir=${X.dir}` : ""}`);
    if (seq !== X.seq) return;
    const from = g.page * g.size + 1, to = g.page * g.size + g.count, pages = g.total > 0 ? Math.ceil(g.total / g.size) : 1;
    body.replaceChildren(grid(g, { col: X.sort, dir: X.dir, sort: (c) => { X.dir = X.sort === c && X.dir === "asc" ? "desc" : "asc"; X.sort = c; X.page = 0; xLoad(); } }),
      h("div", { class: "pager" }, h("span", { class: "muted small" }, g.count ? `${nf0.format(from)}–${nf0.format(to)}${g.total >= 0 ? ` de ${nf0.format(g.total)}` : ""} · ${g.ms} ms` : `0 linhas · ${g.ms} ms`),
        h("span", { class: "sp" }), btn("Anterior", null, { disabled: g.page <= 0, onclick: () => { X.page--; xLoad(); } }), h("span", { class: "muted small" }, `${g.page + 1} / ${pages}`), btn("Próxima", null, { disabled: g.total >= 0 ? g.page + 1 >= pages : g.count < g.size, onclick: () => { X.page++; xLoad(); } })));
  } catch (e) { if (e.message !== "login" && seq === X.seq) body.replaceChildren(xErr(e.message)); }
}
function xSql() {
  const ta = h("textarea", { class: "sqlbox", rows: "7", spellcheck: "false", autocapitalize: "none", placeholder: X.db.engine === "postgres" ? "SELECT * FROM tabela LIMIT 20" : "SELECT * FROM tabela LIMIT 20", "aria-label": "Comando SQL" });
  ta.value = X.sql;
  const ro = h("input", { type: "checkbox", checked: "" }), out = h("div", { class: "sql-out" });
  const run = async () => {
    X.sql = ta.value; const w = !ro.checked;
    if (w && /^\s*(drop|truncate|delete|alter)\b/i.test(ta.value) && !(await confirmDlg({ title: "Executar este comando?", text: "Ele altera ou apaga dados do banco e não dá para desfazer.", ok: "Executar" }))) return;
    b.disabled = true; out.replaceChildren(h("p", { class: "muted small" }, "Executando…"));
    try {
      const r = await post("/api/db/sql", { id: X.id, sql: ta.value, ro: w ? "0" : "1" });
      if (!r.ok) { out.replaceChildren(xErr(await errMsg(r))); return; }
      const g = await r.json();
      out.replaceChildren(h("p", { class: "muted small" }, `${g.msg ? `${g.msg} · ` : ""}${g.columns.length ? `${nf0.format(g.count)} linha${g.count === 1 ? "" : "s"}${g.truncated ? " (resultado cortado)" : ""} · ` : ""}${g.ms} ms`), g.columns.length || !g.msg ? grid(g) : null);
      if (w) xTables();
    } catch (e) { if (e.message !== "login") out.replaceChildren(xErr("Sem resposta do servidor.")); } finally { b.disabled = false; }
  };
  const b = btn("Executar", "play", { primary: true, onclick: run });
  ta.addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); run(); } });
  $("#dbx-body").replaceChildren(h("div", { class: "card sqlcard" }, ta,
    h("div", { class: "sql-bar" }, b, h("label", { class: "inl" }, ro, h("span", {}, "Somente leitura")), h("span", { class: "sp" }), h("span", { class: "muted small" }, "Ctrl+Enter executa · um comando por vez")),
    h("p", { class: "hint" }, "Roda com o usuário do próprio banco, nunca como administrador. Desmarque “somente leitura” para alterar dados.")), out);
}
$("#dbx-tabs").addEventListener("change", () => { if (!X) return; X.tab = segValue($("#dbx-tabs"), "t"); xLoad(); });

/* ---------- buckets (arquivos) ---------- */
let BK = { id: "", path: "", list: null, seq: 0 };
const bkUrl = (id, key, dl) => `/api/bucket/file?id=${enc(id)}&key=${enc(key)}${dl ? "&dl=1" : ""}`;
const bkHash = (id, path) => `#arquivos${id ? `/${enc(id)}${path ? `/${path.split("/").map(enc).join("/")}` : ""}` : ""}`;
const EXT = (n) => (n.includes(".") ? n.split(".").pop().toLowerCase() : "");
const KIND = (n) => { const e = EXT(n); return ["png", "jpg", "jpeg", "gif", "webp", "avif", "bmp", "ico", "svg"].includes(e) ? "img" : ["mp4", "m4v", "webm", "mov"].includes(e) ? "vid" : ["mp3", "wav", "ogg", "m4a", "flac"].includes(e) ? "aud" : e === "pdf" ? "pdf" : "file"; };
function askName(o) {
  return new Promise((res) => {
    const d = $("#dlg-name"); $("#nm-t").textContent = o.title; $("#nm-l").textContent = o.label || "Nome"; $("#nm-in").value = o.value || ""; $("#nm-ok").textContent = o.ok || "OK";
    const done = () => { d.removeEventListener("close", done); res(d.returnValue === "ok" ? $("#nm-in").value.trim() : null); };
    d.returnValue = ""; d.addEventListener("close", done); d.showModal(); $("#nm-in").focus(); $("#nm-in").select();
  });
}
function renderBuckets() {
  const bar = $("#bk-bar"), body = $("#bk-body");
  if (!BK.id) {
    bar.replaceChildren(h("div", { class: "notes muted" }, "Guarde fotos, documentos e arquivos de qualquer tipo. Organize em pastas e abra pelo painel."), h("button", { class: "btn primary", onclick: openBkForm }, icon("plus"), "Novo bucket"));
    body.replaceChildren(h("div", { class: "cards" }, D.buckets.length ? D.buckets.slice().sort((a, b) => a.name.localeCompare(b.name, "pt-BR")).map((b) => h("article", { class: "card acard click", tabindex: "0", role: "link", onclick: () => { location.hash = bkHash(b.id, ""); }, onkeydown: (e) => { if (e.key === "Enter") location.hash = bkHash(b.id, ""); } },
      h("div", { class: "acard-h" }, icon("folder"), h("b", {}, b.name), h("span", { class: "tag" }, SCOPE(b.owner))),
      h("div", { class: "acard-l" }, h("div", {}, h("span", {}, `${nf0.format(b.files)} arquivo${b.files === 1 ? "" : "s"} · ${bytesF(b.bytes)}`)), h("div", {}, icon(b.public ? "globe" : "lock"), h("span", {}, b.public ? "Público na rede local" : "Privado")))))
      : h("div", { class: "card empty", style: "grid-column:1/-1" }, h("b", {}, "Nenhum bucket ainda"), h("span", {}, "Crie um bucket para guardar imagens e arquivos."), btn("Novo bucket", "plus", { primary: true, onclick: openBkForm }))));
    return;
  }
  const b = D.buckets.find((x) => x.id === BK.id);
  if (!b) { location.hash = "#arquivos"; return; }
  const parts = BK.path ? BK.path.split("/") : [];
  const crumbs = h("div", { class: "crumbs" }, h("a", { href: "#arquivos" }, "Arquivos"), h("span", {}, "/"), parts.length ? h("a", { href: bkHash(b.id, "") }, b.name) : h("b", {}, b.name),
    ...parts.flatMap((p, i) => [h("span", {}, "/"), i === parts.length - 1 ? h("b", {}, p) : h("a", { href: bkHash(b.id, parts.slice(0, i + 1).join("/")) }, p)]));
  const pick = (dir) => { const inp = h("input", { type: "file", multiple: "", hidden: "", ...(dir ? { webkitdirectory: "" } : {}) }); inp.onchange = () => { bkUpload([...inp.files]); inp.remove(); }; document.body.append(inp); inp.click(); };
  bar.replaceChildren(crumbs, h("div", { class: "bk-actions" },
    btn("Enviar arquivos", "up", { primary: true, onclick: () => pick(false) }), btn("Enviar pasta", "folder", { onclick: () => pick(true) }),
    btn("Nova pasta", "plus", { onclick: async () => { const n = await askName({ title: "Nova pasta", ok: "Criar" }); if (n) bkOp("mkdir", { key: BK.path ? `${BK.path}/${n}` : n }, "Pasta criada"); } }),
    btn(b.public ? "Público" : "Privado", b.public ? "globe" : "lock", { title: b.public ? "Qualquer pessoa na rede local abre /b/" + b.id + "/…. Clique para tornar privado." : "Clique para abrir os arquivos na rede local sem login.", onclick: () => act("/api/bucket/update", { id: b.id, pub: b.public ? "0" : "1" }, b.public ? "Bucket agora é privado" : "Bucket público na rede local") }),
    btn("API", "term", { title: "Como um app acessa este bucket (URL, token e exemplos)", onclick: () => openBkApi(b) }),
    iconBtn("trash", "Excluir bucket", async () => { if (await confirmDlg({ title: `Excluir o bucket “${b.name}”?`, text: `Apaga ${nf0.format(b.files)} arquivo(s) (${bytesF(b.bytes)}). Não dá para desfazer.`, ok: "Excluir" })) { const j = await act("/api/bucket/delete", { id: b.id }, "Bucket excluído"); if (j) location.hash = "#arquivos"; } })));
  if (!BK.list) { body.replaceChildren(h("p", { class: "muted" }, "Carregando…")); return; }
  const es = BK.list.slice().sort((x, y) => y.dir - x.dir || x.name.localeCompare(y.name, "pt-BR", { numeric: true }));
  const key = (n) => (BK.path ? `${BK.path}/${n}` : n);
  body.replaceChildren(h("div", { class: "bk-drop", id: "bk-drop" },
    h("div", { id: "bk-up", class: "bk-up", hidden: "" }),
    es.length ? h("div", { class: "bk-grid" }, es.map((e) => {
      const k = key(e.name), kind = e.dir ? "dir" : KIND(e.name);
      const prev = h("div", { class: "bk-prev " + kind }, kind === "img" ? h("img", { src: bkUrl(b.id, k), alt: "", loading: "lazy", draggable: "false" }) : kind === "dir" ? icon("folder") : h("span", {}, EXT(e.name).slice(0, 4) || "arq"));
      const open = () => (e.dir ? (location.hash = bkHash(b.id, k)) : bkPreview(b, k, e, kind));
      return h("article", { class: "bk-tile" }, h("div", { class: "bk-hit", tabindex: "0", role: "button", "aria-label": `${e.dir ? "Abrir pasta" : "Abrir"} ${e.name}`, onclick: open, onkeydown: (ev) => { if (ev.key === "Enter") open(); } }, prev, h("b", { title: e.name }, e.name), h("small", {}, e.dir ? "pasta" : `${bytesF(e.size)} · ${ago(e.mtime)}`)),
        h("div", { class: "bk-tb" }, e.dir ? null : h("a", { class: "icon-btn", href: bkUrl(b.id, k, true), title: "Baixar", "aria-label": "Baixar", download: e.name }, icon("down")),
          b.public && !e.dir ? iconBtn("copy", "Copiar link público", () => copy(`${location.origin}/b/${enc(b.id)}/${k.split("/").map(enc).join("/")}`, "Link copiado")) : null,
          iconBtn("edit", "Renomear ou mover", async () => { const n = await askName({ title: "Renomear ou mover", label: "Novo caminho dentro do bucket", value: k, ok: "Salvar" }); if (n && n !== k) bkOp("mv", { key: k, to: n }, "Renomeado"); }),
          iconBtn("trash", "Excluir", async () => { if (await confirmDlg({ title: `Excluir “${e.name}”?`, text: e.dir ? "Apaga a pasta e tudo que está dentro dela." : "Não dá para desfazer.", ok: "Excluir" })) bkOp("rm", { key: k }, "Excluído"); })));
    })) : h("div", { class: "card empty" }, h("b", {}, BK.path ? "Pasta vazia" : "Bucket vazio"), h("span", {}, "Arraste arquivos para cá ou use “Enviar arquivos”."))));
  const dz = $("#bk-drop");
  dz.addEventListener("dragover", (e) => { e.preventDefault(); dz.classList.add("over"); });
  dz.addEventListener("dragleave", (e) => { if (e.target === dz) dz.classList.remove("over"); });
  dz.addEventListener("drop", (e) => { e.preventDefault(); dz.classList.remove("over"); if (e.dataTransfer.files.length) bkUpload([...e.dataTransfer.files]); });
}
async function bkLoad() {
  if (!BK.id || !D) return;
  const seq = ++BK.seq;
  try {
    const r = await api(`/api/bucket/list?id=${enc(BK.id)}&prefix=${enc(BK.path)}`);
    if (seq !== BK.seq) return;
    if (!r.ok) { toast(await errMsg(r)); location.hash = bkHash(BK.id, ""); return; }
    BK.list = (await r.json()).entries; renderBuckets();
  } catch { /* sem resposta: mantém o que já está na tela */ }
}
async function bkOp(op, data, okMsg) {
  const j = await act(`/api/bucket/${op}`, { id: BK.id, ...data }, okMsg);
  if (j) bkLoad();
}
let bkBusy = false;
async function bkUpload(files) {
  if (bkBusy || !files.length) return;
  bkBusy = true; const id = BK.id, path = BK.path; let okN = 0, fail = "";
  const line = () => $("#bk-up");
  for (let i = 0; i < files.length; i++) {
    const f = files[i], rel = f.webkitRelativePath || f.name, key = path ? `${path}/${rel}` : rel;
    const err = await new Promise((res) => {
      const x = new XMLHttpRequest();
      x.open("POST", `/api/bucket/upload?id=${enc(id)}&key=${enc(key)}`); x.setRequestHeader("X-Requested-With", "hosting");
      x.upload.onprogress = (e) => { const el = line(); if (el && e.lengthComputable) { el.hidden = false; el.replaceChildren(h("span", {}, `Enviando ${i + 1}/${files.length}: ${f.name}`), h("progress", { max: "1", value: String(e.loaded / e.total) })); } };
      x.onload = () => { let m; try { m = JSON.parse(x.responseText).error; } catch {} res(x.status === 200 ? null : m || "falha no envio"); };
      x.onerror = () => res("conexão perdida durante o envio");
      x.send(f);
    });
    if (err) { fail = `${f.name}: ${err}`; break; }
    okN++;
  }
  bkBusy = false;
  toast(fail ? `${okN} enviado(s). Parou em ${fail}` : `${okN} arquivo${okN === 1 ? "" : "s"} enviado${okN === 1 ? "" : "s"}`);
  await refresh(); if (BK.id === id) bkLoad();
}
function bkPreview(b, k, e, kind) {
  const u = bkUrl(b.id, k);
  if (kind === "pdf" || kind === "file") { if (kind === "pdf" || ["txt", "md", "json", "csv", "log", "yml", "yaml", "xml", "html", "css", "js"].includes(EXT(e.name))) window.open(u, "_blank", "noopener"); else location.href = bkUrl(b.id, k, true); return; }
  $("#pv-t").textContent = e.name;
  $("#pv-body").replaceChildren(kind === "img" ? h("img", { src: u, alt: e.name }) : kind === "vid" ? h("video", { src: u, controls: "", autoplay: "" }) : h("audio", { src: u, controls: "", autoplay: "" }));
  $("#dlg-pv").showModal();
}
$("#dlg-pv").addEventListener("close", () => $("#pv-body").replaceChildren());
function openBkApi(b) {
  const users = D.apps.filter((a) => a.bucket === b.id).map((a) => a.name), base = `http://${location.hostname}:${location.port || 80}`;
  const code = (t) => h("pre", { class: "logbox", style: "margin:0;height:auto;max-height:160px" }, t);
  $("#api-t").textContent = `API do bucket “${b.name}”`;
  $("#api-body").replaceChildren(
    h("div", { class: "notice" }, users.length ? h("span", {}, h("b", {}, `Ligado a ${users.join(", ")}. `), "O app já recebe BUCKET_URL, BUCKET_NAME e BUCKET_TOKEN no ambiente (reinicie-o depois de gerar um token novo).") : h("span", {}, h("b", {}, "Nenhum app ligado. "), "Em Editar aplicação escolha este bucket e o app recebe as variáveis sozinho; ou use o token abaixo de fora.")),
    h("label", { class: "field" }, h("span", {}, "URL da API (rede local)"), copyField(base)),
    h("label", { class: "field" }, h("span", {}, "Token deste bucket (só abre este bucket)"), copyField(b.token, true)),
    h("div", { class: "field" }, h("span", {}, "Listar"), code(`curl -H "Authorization: Bearer $BUCKET_TOKEN" "$BUCKET_URL/api/bucket/list?id=${b.id}&prefix=pasta"`)),
    h("div", { class: "field" }, h("span", {}, "Enviar (cria as pastas; substitui o arquivo de mesmo nome)"), code(`curl -X POST -H "Authorization: Bearer $BUCKET_TOKEN" -H "X-Requested-With: hosting" \\\n  --data-binary @foto.jpg "$BUCKET_URL/api/bucket/upload?id=${b.id}&key=fotos/foto.jpg"`)),
    h("div", { class: "field" }, h("span", {}, "Baixar / mostrar"), code(`curl -H "Authorization: Bearer $BUCKET_TOKEN" "$BUCKET_URL/api/bucket/file?id=${b.id}&key=fotos/foto.jpg"`)),
    h("p", { class: "hint" }, "Também: POST /api/bucket/rm, /mv e /mkdir (corpo id=…&key=…), sempre com X-Requested-With: hosting. O token não consegue criar nem apagar buckets, nem ver bancos ou apps. Dentro de container o endereço é host.containers.internal."),
    h("div", {}, btn("Gerar novo token", "redo", { onclick: async () => { if (await confirmDlg({ title: "Gerar um token novo?", text: "O token atual deixa de valer na hora. Apps ligados recebem o novo ao reiniciar.", ok: "Gerar" })) { const j = await act("/api/bucket/update", { id: b.id, rotate: "1" }, "Token novo gerado"); if (j) { await refresh(); const nb = D.buckets.find((x) => x.id === b.id); if (nb) openBkApi(nb); } } } })));
  $("#dlg-api").showModal();
}
function openBkForm() { $("#bk-form").reset(); $("#bk-err").textContent = ""; segSet($("#bk-scope"), "s", "private"); $("#dlg-bk").showModal(); $("#bk-form").elements.name.focus(); }
$("#bk-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const b = $("#bk-ok"); b.disabled = true; $("#bk-err").textContent = "";
  try {
    const el = e.target.elements, r = await post("/api/bucket/create", { name: el.name.value, scope: segValue($("#bk-scope"), "s"), pub: el.pub.checked ? "1" : "0" });
    if (!r.ok) { $("#bk-err").textContent = await errMsg(r); return; }
    $("#dlg-bk").close(); toast("Bucket criado"); refresh();
  } catch { $("#bk-err").textContent = "Não foi possível falar com o servidor."; } finally { b.disabled = false; }
});

/* ---------- rotas e atualização ---------- */
const TITLES = { apps: "Aplicações", estatisticas: "Estatísticas", deploys: "Histórico de deploys", bancos: "Bancos de dados", arquivos: "Arquivos", dominios: "Domínios" };
function route() {
  const [h0, ...sub] = location.hash.slice(1).split("/"), v = TITLES[h0] ? h0 : "apps";
  const dec = (x) => { try { return decodeURIComponent(x); } catch { return x; } };
  const dbx = v === "bancos" && sub[0] && D, view = dbx ? "dbx" : v;
  $$(".view").forEach((s) => { s.hidden = s.id !== "v-" + view; });
  $$("#nav a").forEach((a) => a.classList.toggle("on", a.dataset.v === v));
  const title = dbx ? "Explorar banco" : TITLES[v];
  $("#title").textContent = title; document.title = `${title} · Hospedagem`;
  scrollTo(0, 0);
  if (v === "estatisticas") { stFill(); loadStats(); }
  if (v === "deploys") { dpFill(); loadDeploys(); }
  if (dbx) openDbx(dec(sub[0]));
  if (v === "arquivos" && D) {
    const id = dec(sub[0] || ""), path = sub.slice(1).map(dec).join("/");
    if (id !== BK.id || path !== BK.path) BK = { id, path, list: null, seq: BK.seq };
    renderBuckets(); bkLoad();
  }
}
addEventListener("hashchange", route);
$("#f-apps").addEventListener("click", (e) => { const b = e.target.closest("button"); if (!b) return; filter = b.dataset.f; segSet($("#f-apps"), "f", filter); if (D) renderApps(); });

function render() {
  $("#side-user").textContent = D.me;
  const t = $("#tun"), using = D.apps.some((a) => a.host) || D.hook_host;
  $(".dot", t).classList.toggle("on", D.tunnel.up);
  $("#tun-t").textContent = D.tunnel.up ? "Túnel ativo" : using ? "Túnel parado" : "Sem endereços públicos";
  renderApps(); renderDbs(); renderDoms(); stFill(); dpFill();
  if (location.hash.startsWith("#arquivos")) renderBuckets();
}
let offline = false;
async function refresh() {
  try {
    const r = await api("/api/overview", { timeout: 15000 });
    const txt = await r.text();
    $("#gate").hidden = true; $("#app").hidden = false;
    if (offline) { offline = false; toast("Conexão restabelecida"); }
    if (txt === lastJSON) return;
    lastJSON = txt; D = JSON.parse(txt); render();
    if (!$("#dlg-log").open) return;
    if (L.tab === "hook") renderHook();
  } catch (e) { if (e.message !== "login" && !offline) { offline = true; toast("Sem resposta do servidor. A conexão pode estar lenta; tentando de novo."); } }
}
(async function loop() {
  await refresh();
  if (!location.hash) history.replaceState(null, "", "#apps");
  route();
  const next = () => setTimeout(async () => { await refresh(); next(); }, D && D.apps.some((a) => a.state === "building" || a.state === "restarting") ? 1500 : 4000);
  next();
})();
// relógio dos "há X min" sem esperar mudança no servidor
setInterval(() => { if (D && !document.hidden && !$("dialog[open]")) renderApps(); }, 30000);
