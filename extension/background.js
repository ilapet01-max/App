// Cooldown Blocker — service worker.
// Toda la lógica de "esperar antes de debilitar el bloqueo" vive aquí, no en la UI.

const COOLDOWN_MIN = 30; // mínimo absoluto
const COOLDOWN_MAX = 24 * 60;
const APPLY_WINDOW_MIN = 10; // tras la espera, tienes 10 min para confirmar
const MIN = 60 * 1000;

const DEFAULT_DOMAINS = [
  "pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com", "redtube.com",
  "youporn.com", "spankbang.com", "eporner.com", "tube8.com", "tnaflix.com",
  "beeg.com", "motherless.com", "brazzers.com", "chaturbate.com", "stripchat.com",
  "bongacams.com", "livejasmin.com", "camsoda.com", "onlyfans.com", "fansly.com",
  "erome.com", "rule34.xxx", "e-hentai.org", "nhentai.net", "hentaihaven.xxx",
  "fapello.com", "sex.com", "porn.com", "thumbzilla.com", "4tube.com",
];

// Palabras clave que se buscan SOLO en el nombre de host (evita falsos positivos en rutas).
const KEYWORD_REGEX = "^https?://[^/?#]*(porn|xxx|hentai|xvideos|xnxx|xhamster|nsfw)[^/?#]*";

const DEFAULT_STATE = {
  enabled: true,
  keywords: true,
  cooldownMin: COOLDOWN_MIN,
  domains: DEFAULT_DOMAINS,
  pending: [], // {id, change, requestedAt, unlockAt, expiresAt}
  lastTick: 0,
};

// ---------- estado (con cola para evitar condiciones de carrera) ----------

let queue = Promise.resolve();
function serial(fn) {
  const run = queue.then(fn, fn);
  queue = run.catch(() => {});
  return run;
}

async function load() {
  const stored = await chrome.storage.local.get(null);
  const state = { ...DEFAULT_STATE, ...stored };
  const now = Date.now();

  // Si el reloj retrocede, desplazamos los temporizadores para no regalar tiempo.
  if (state.lastTick && now < state.lastTick - 30 * 1000) {
    const delta = state.lastTick - now;
    for (const p of state.pending) {
      p.unlockAt += delta;
      p.expiresAt += delta;
    }
  }
  state.lastTick = now;

  state.pending = state.pending.filter((p) => p.expiresAt > now);

  await chrome.storage.local.set(state);
  return state;
}

async function save(state) {
  await chrome.storage.local.set(state);
  await syncRules(state);
  await syncAlarms(state);
}

// ---------- bloqueo ----------

async function syncRules(state) {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const rules = [];
  if (state.enabled) {
    const redirect = { type: "redirect", redirect: { extensionPath: "/blocked.html" } };
    const resourceTypes = ["main_frame", "sub_frame"];
    if (state.domains.length) {
      rules.push({
        id: 1,
        priority: 1,
        action: redirect,
        condition: { requestDomains: state.domains, resourceTypes },
      });
    }
    if (state.keywords) {
      rules.push({
        id: 2,
        priority: 1,
        action: redirect,
        condition: { regexFilter: KEYWORD_REGEX, isUrlFilterCaseSensitive: false, resourceTypes },
      });
    }
  }
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: existing.map((r) => r.id),
    addRules: rules,
  });
}

async function syncAlarms(state) {
  const alarms = await chrome.alarms.getAll();
  const wanted = new Set(state.pending.map((p) => "unlock:" + p.id));
  for (const a of alarms) {
    if (a.name.startsWith("unlock:") && !wanted.has(a.name)) chrome.alarms.clear(a.name);
  }
  for (const p of state.pending) {
    if (p.unlockAt > Date.now()) chrome.alarms.create("unlock:" + p.id, { when: p.unlockAt });
  }
}

// ---------- cambios ----------

function normalizeDomain(input) {
  let d = String(input || "").trim().toLowerCase();
  d = d.replace(/^[a-z]+:\/\//, "").replace(/^www\./, "").split(/[/?#:]/)[0];
  return /^([a-z0-9-]+\.)+[a-z]{2,}$/.test(d) ? d : null;
}

// ¿Este cambio debilita el bloqueo? Si sí, requiere cooldown.
function weakens(state, c) {
  switch (c.type) {
    case "removeDomain": return state.domains.includes(c.value);
    case "setEnabled": return c.value === false && state.enabled;
    case "setKeywords": return c.value === false && state.keywords;
    case "setCooldown": return c.value < state.cooldownMin;
    default: return false;
  }
}

function validate(c) {
  switch (c.type) {
    case "addDomain":
    case "removeDomain": {
      const d = normalizeDomain(c.value);
      if (!d) throw new Error("Dominio no válido");
      return { type: c.type, value: d };
    }
    case "setEnabled":
    case "setKeywords":
      return { type: c.type, value: !!c.value };
    case "setCooldown": {
      const n = Math.round(Number(c.value));
      if (!(n >= COOLDOWN_MIN && n <= COOLDOWN_MAX))
        throw new Error(`La espera debe estar entre ${COOLDOWN_MIN} y ${COOLDOWN_MAX} minutos`);
      return { type: c.type, value: n };
    }
    default:
      throw new Error("Cambio desconocido");
  }
}

function applyChange(state, c) {
  switch (c.type) {
    case "addDomain":
      if (!state.domains.includes(c.value)) state.domains = [...state.domains, c.value];
      break;
    case "removeDomain": state.domains = state.domains.filter((d) => d !== c.value); break;
    case "setEnabled": state.enabled = c.value; break;
    case "setKeywords": state.keywords = c.value; break;
    case "setCooldown": state.cooldownMin = c.value; break;
  }
}

const sameChange = (a, b) => a.type === b.type && a.value === b.value;

async function requestChange(raw) {
  const state = await load();
  const change = validate(raw);
  if (!weakens(state, change)) {
    applyChange(state, change);
    await save(state);
    return { applied: true, state };
  }
  if (!state.pending.some((p) => sameChange(p.change, change))) {
    const now = Date.now();
    const unlockAt = now + state.cooldownMin * MIN;
    state.pending.push({
      id: crypto.randomUUID(),
      change,
      requestedAt: now,
      unlockAt,
      expiresAt: unlockAt + APPLY_WINDOW_MIN * MIN,
    });
  }
  await save(state);
  return { applied: false, state };
}

async function applyPending(id) {
  const state = await load();
  const p = state.pending.find((x) => x.id === id);
  if (!p) throw new Error("La solicitud ya no existe o caducó");
  if (Date.now() < p.unlockAt) throw new Error("Todavía no ha pasado el tiempo de espera");
  applyChange(state, p.change);
  state.pending = state.pending.filter((x) => x.id !== id);
  await save(state);
  return state;
}

async function cancelPending(id) {
  const state = await load();
  state.pending = state.pending.filter((x) => x.id !== id);
  await save(state);
  return state;
}

// ---------- eventos ----------

const handlers = {
  getState: () => load(),
  change: (m) => requestChange(m.change),
  apply: (m) => applyPending(m.id),
  cancel: (m) => cancelPending(m.id),
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Solo aceptamos mensajes de las páginas de esta extensión.
  if (sender.id !== chrome.runtime.id || !handlers[msg?.action]) return false;
  serial(() => handlers[msg.action](msg))
    .then((r) => sendResponse({ ok: true, result: r }))
    .catch((e) => sendResponse({ ok: false, error: e.message }));
  return true;
});

chrome.alarms.onAlarm.addListener((alarm) => {
  serial(async () => {
    const state = await load();
    await syncAlarms(state);
    if (alarm.name.startsWith("unlock:")) {
      chrome.notifications.create(alarm.name, {
        type: "basic",
        iconUrl: "icon.png",
        title: "Cooldown Blocker",
        message: `Ya pasó la espera. Tienes ${APPLY_WINDOW_MIN} min para confirmar el cambio. ¿De verdad lo necesitas?`,
      });
    }
  });
});

function boot() {
  chrome.alarms.create("tick", { periodInMinutes: 1 });
  return serial(async () => {
    const state = await load();
    await save(state);
  });
}
chrome.runtime.onInstalled.addListener(boot);
chrome.runtime.onStartup.addListener(boot);
