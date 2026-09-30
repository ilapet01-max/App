const $ = (id) => document.getElementById(id);
let state = null;

function send(msg) {
  return chrome.runtime.sendMessage(msg).then((r) => {
    if (!r?.ok) throw new Error(r?.error || "Error");
    return r.result;
  });
}

function say(text, err) {
  $("msg").textContent = text || "";
  $("msg").className = err ? "err" : "";
}

async function act(msg, okText) {
  try {
    const r = await send(msg);
    if (r?.state) state = r.state; else if (r?.domains) state = r;
    if (msg.action === "change") {
      say(r.applied ? okText : `Solicitud registrada. Podrás confirmarla en ${state.cooldownMin} minutos.`);
    } else say(okText);
    render();
  } catch (e) { say(e.message, true); }
}

const change = (type, value, okText) => act({ action: "change", change: { type, value } }, okText);

function fmt(ms) {
  const s = Math.max(0, Math.ceil(ms / 1000));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), r = s % 60;
  return (h ? h + ":" + String(m).padStart(2, "0") : m) + ":" + String(r).padStart(2, "0");
}

const LABEL = {
  removeDomain: (v) => `Quitar el sitio ${v}`,
  setEnabled: () => "Desactivar el bloqueo",
  setKeywords: () => "Desactivar palabras clave",
  setCooldown: (v) => `Bajar la espera a ${v} min`,
};

function render() {
  if (!state) return;
  $("status").textContent = state.enabled ? "Bloqueo ACTIVO" : "Bloqueo DESACTIVADO";
  $("toggle").textContent = state.enabled ? "Desactivar (con espera)" : "Activar";
  $("keywords").checked = state.keywords;
  if (document.activeElement !== $("cooldown")) $("cooldown").value = state.cooldownMin;
  $("count").textContent = state.domains.length;

  const dl = $("domains");
  dl.replaceChildren(...state.domains.slice().sort().map((d) => {
    const li = document.createElement("li");
    const b = document.createElement("button");
    b.textContent = "Quitar";
    b.onclick = () => change("removeDomain", d);
    li.append(d, b);
    return li;
  }));
  renderPending();
}

function renderPending() {
  const now = Date.now();
  const ul = $("pending");
  $("noPending").hidden = state.pending.length > 0;
  ul.replaceChildren(...state.pending.map((p) => {
    const li = document.createElement("li");
    const ready = now >= p.unlockAt;
    const label = document.createElement("span");
    label.append(LABEL[p.change.type](p.change.value) + " — ");
    const t = document.createElement("span");
    t.className = "timer";
    t.textContent = ready ? `confirma en ${fmt(p.expiresAt - now)}` : `faltan ${fmt(p.unlockAt - now)}`;
    label.append(t);
    const box = document.createElement("span");
    const apply = document.createElement("button");
    apply.textContent = "Confirmar";
    apply.className = "primary";
    apply.disabled = !ready;
    apply.onclick = () => act({ action: "apply", id: p.id }, "Cambio aplicado.");
    const cancel = document.createElement("button");
    cancel.textContent = "Cancelar";
    cancel.onclick = () => act({ action: "cancel", id: p.id }, "Solicitud cancelada. ¡Bien hecho!");
    box.append(apply, " ", cancel);
    li.append(label, box);
    return li;
  }));
}

async function refresh() {
  try { state = await send({ action: "getState" }); render(); } catch (e) { say(e.message, true); }
}

$("toggle").onclick = () => change("setEnabled", !state.enabled, "Bloqueo activado.");
$("keywords").onchange = (e) => change("setKeywords", e.target.checked, "Palabras clave activadas.").then(refresh);
$("setCooldown").onclick = () => change("setCooldown", $("cooldown").value, "Tiempo de espera actualizado.");
$("addForm").onsubmit = (e) => {
  e.preventDefault();
  change("addDomain", $("newDomain").value, "Sitio añadido.");
  $("newDomain").value = "";
};

refresh();
setInterval(() => state && renderPending(), 1000);
setInterval(refresh, 15000);
