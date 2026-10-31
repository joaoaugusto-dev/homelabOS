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
  dbOptions(segValue($("#app-scope"), "s"), a?.db);
  const nat = !!D.native; // sem direito a comandos no servidor: só container (o servidor também impõe isso)
  for (const k of ["runtime", "build", "start"]) el[k].disabled = !nat;
  if (!nat) el.runtime.value = "podman";
  $("#nat-note").hidden = nat;
  $(".adv").open = !nat || !!(a && (a.build || a.start || a.volume || a.runtime !== "auto"));
  $("#dlg-app").showModal(); el.name.focus();
}
$("#app-scope").addEventListener("change", () => dbOptions(segValue($("#app-scope"), "s"), $("#app-db").value));
$("#app-new").addEventListener("click", () => openAppForm());
$("#app-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const el = e.target.elements, b = $("#app-ok"), err = $("#app-err");
  err.textContent = "";
  const zip = segValue($("#app-src"), "k") === "zip", file = el.file.files[0];
  if (zip && !editing && !file) { err.textContent = "Escolha o arquivo .zip ou .tar.gz do projeto."; return; }
  const data = {
    name: el.name.value, scope: segValue($("#app-scope"), "s"), source: zip ? "zip" : "github", repo: el.repo.value, branch: el.branch.value, token: el.token.value, host: el.host.value, db: el.db.value,
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
      h("div", { class: "acard-b" }, btn("Copiar URL de conexão", "copy", { onclick: () => copy(url, "URL copiada") }), h("span", { class: "sp" }),
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

/* ---------- rotas e atualização ---------- */
const TITLES = { apps: "Aplicações", estatisticas: "Estatísticas", bancos: "Bancos de dados", dominios: "Domínios" };
function route() {
  const v = TITLES[location.hash.slice(1)] ? location.hash.slice(1) : "apps";
  $$(".view").forEach((s) => { s.hidden = s.id !== "v-" + v; });
  $$("#nav a").forEach((a) => a.classList.toggle("on", a.dataset.v === v));
  $("#title").textContent = TITLES[v]; document.title = `${TITLES[v]} · Hospedagem`;
  scrollTo(0, 0);
  if (v === "estatisticas") { stFill(); loadStats(); }
}
addEventListener("hashchange", route);
$("#f-apps").addEventListener("click", (e) => { const b = e.target.closest("button"); if (!b) return; filter = b.dataset.f; segSet($("#f-apps"), "f", filter); if (D) renderApps(); });

function render() {
  $("#side-user").textContent = D.me;
  const t = $("#tun"), using = D.apps.some((a) => a.host) || D.hook_host;
  $(".dot", t).classList.toggle("on", D.tunnel.up);
  $("#tun-t").textContent = D.tunnel.up ? "Túnel ativo" : using ? "Túnel parado" : "Sem endereços públicos";
  renderApps(); renderDbs(); renderDoms(); stFill();
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
