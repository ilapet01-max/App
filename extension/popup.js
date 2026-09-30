chrome.runtime.sendMessage({ action: "getState" }).then((r) => {
  const s = r.result;
  document.getElementById("s").textContent =
    (s.enabled ? "Bloqueo activo" : "Bloqueo desactivado") +
    (s.pending.length ? ` · ${s.pending.length} solicitud(es) pendiente(s)` : "");
});
document.getElementById("o").onclick = () => chrome.runtime.openOptionsPage();
