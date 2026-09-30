#!/usr/bin/env python3
"""extlock — congela las extensiones de Chrome ya instaladas.

Usa las políticas administradas de Chrome (solo modificables por root/administrador):
  * force_installed: las extensiones no se pueden desactivar ni quitar.
  * URLBlocklist: bloquea chrome://extensions (no se puede abrir el panel de gestión).

Bloquear es inmediato. Desbloquear exige: request-unlock -> esperar 30 min ->
confirm-unlock (dentro de los 10 min siguientes).

Soporta Linux y Windows. Requiere root / administrador.
"""
import argparse, ctypes, json, os, re, sys, time
from pathlib import Path

COOLDOWN = 30 * 60
WINDOW = 10 * 60
WEBSTORE_UPDATE_URL = "https://clients2.google.com/service/update2/crx"
BLOCKED_URLS = ["chrome://extensions", "chrome://extensions/*"]
ID_RE = re.compile(r"^[a-p]{32}$")
IS_WIN = os.name == "nt"

POLICY_DIRS = ["/etc/opt/chrome/policies/managed", "/etc/chromium/policies/managed"]
POLICY_FILE = "extlock.json"


def state_path(args):
    if args.state_dir:
        return Path(args.state_dir) / "state.json"
    base = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "extlock" if IS_WIN else Path("/var/lib/extlock")
    return base / "state.json"


def require_admin(args):
    if args.state_dir or args.policy_dir:  # modo de pruebas
        return
    ok = ctypes.windll.shell32.IsUserAnAdmin() if IS_WIN else os.geteuid() == 0
    if not ok:
        sys.exit("Ejecuta este programa como root (sudo) o administrador.")


# ---------- estado ----------

def load_state(args):
    p = state_path(args)
    st = {"locked_ids": [], "pending": None, "last_seen": 0}
    if p.exists():
        st.update(json.loads(p.read_text()))
    now = time.time()
    # Si el reloj retrocede, desplazamos los temporizadores para no regalar tiempo.
    if st["last_seen"] and now < st["last_seen"] - 30 and st["pending"]:
        delta = st["last_seen"] - now
        st["pending"]["unlock_at"] += delta
        st["pending"]["expires_at"] += delta
    st["last_seen"] = now
    if st["pending"] and now > st["pending"]["expires_at"]:
        st["pending"] = None  # la ventana de confirmación caducó
    return st


def save_state(args, st):
    p = state_path(args)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(st, indent=2))
    if not IS_WIN:
        os.chmod(p, 0o644)


# ---------- detección de extensiones ----------

def profile_roots(user):
    if IS_WIN:
        return [Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/User Data"]
    if user:
        home = Path(f"~{user}").expanduser()
    else:
        home = Path(f"~{os.environ['SUDO_USER']}").expanduser() if os.environ.get("SUDO_USER") else Path.home()
    return [home / ".config/google-chrome", home / ".config/chromium"]


def find_installed(user):
    """IDs de extensiones de la Chrome Web Store instaladas en algún perfil."""
    found, skipped = set(), set()
    for root in profile_roots(user):
        for ext_dir in root.glob("*/Extensions/*"):
            if not ID_RE.match(ext_dir.name):
                continue
            store = False
            for mf in ext_dir.glob("*/manifest.json"):
                try:
                    store |= "google.com" in json.loads(mf.read_text(encoding="utf-8-sig")).get("update_url", "")
                except (OSError, ValueError):
                    pass
            (found if store else skipped).add(ext_dir.name)
    return sorted(found), sorted(skipped - found)


# ---------- aplicar política ----------

def build_policy(ids):
    return {
        "ExtensionSettings": {
            i: {"installation_mode": "force_installed", "update_url": WEBSTORE_UPDATE_URL} for i in ids
        },
        "URLBlocklist": BLOCKED_URLS,
    }


def apply_policy(args, ids):
    if IS_WIN and not args.policy_dir:
        import winreg
        base = r"SOFTWARE\Policies\Google\Chrome"
        for sub in ("ExtensionSettings", "URLBlocklist"):  # limpiar versión anterior
            try: winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, base + "\\" + sub)
            except OSError: pass
        try: winreg.DeleteValue(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base, 0, winreg.KEY_SET_VALUE), "ExtensionSettings")
        except OSError: pass
        if not ids:
            return
        pol = build_policy(ids)
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, base, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "ExtensionSettings", 0, winreg.REG_SZ, json.dumps(pol["ExtensionSettings"]))
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, base + r"\URLBlocklist") as k:
            for n, u in enumerate(pol["URLBlocklist"], 1):
                winreg.SetValueEx(k, str(n), 0, winreg.REG_SZ, u)
        return
    dirs = [args.policy_dir] if args.policy_dir else POLICY_DIRS
    for d in dirs:
        f = Path(d) / POLICY_FILE
        if ids:
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(json.dumps(build_policy(ids), indent=2))
            os.chmod(f, 0o644)
        elif f.exists():
            f.unlink()


# ---------- comandos ----------

def cmd_lock(args):
    st = load_state(args)
    found, skipped = find_installed(args.user)
    extra = [i.strip() for i in (args.ids or "").split(",") if i.strip()]
    for i in extra:
        if not ID_RE.match(i):
            sys.exit(f"ID no válido: {i}")
    # Solo crece: volver a bloquear nunca quita extensiones ya protegidas.
    ids = sorted(set(st["locked_ids"]) | set(found) | set(extra))
    if not ids:
        sys.exit("No encontré extensiones de la Web Store. Usa --ids ID1,ID2 o --user NOMBRE.")
    st["locked_ids"], st["pending"] = ids, None  # bloquear cancela cualquier desbloqueo pendiente
    apply_policy(args, ids)
    save_state(args, st)
    print(f"Bloqueadas {len(ids)} extensiones y chrome://extensions.")
    if skipped:
        print(f"Omitidas (no son de la Web Store, no se pueden proteger por política): {', '.join(skipped)}")
    print("Reinicia Chrome (o abre chrome://policy y pulsa 'Volver a cargar políticas') para que surta efecto.")


def fmt(s):
    s = max(0, int(s)); return f"{s // 60}:{s % 60:02d}"


def cmd_request(args):
    st = load_state(args)
    if not st["locked_ids"]:
        sys.exit("No hay nada bloqueado.")
    if not st["pending"]:
        now = time.time()
        st["pending"] = {"requested_at": now, "unlock_at": now + COOLDOWN, "expires_at": now + COOLDOWN + WINDOW}
    save_state(args, st)
    print(f"Desbloqueo solicitado. Podrás confirmarlo en {fmt(st['pending']['unlock_at'] - time.time())} (mm:ss).")


def cmd_confirm(args):
    st = load_state(args)
    p = st["pending"]
    if not p:
        save_state(args, st)
        sys.exit("No hay solicitud pendiente (o caducó). Empieza de nuevo con request-unlock.")
    remaining = p["unlock_at"] - time.time()
    if remaining > 0:
        save_state(args, st)
        sys.exit(f"Todavía no. Faltan {fmt(remaining)} (mm:ss).")
    apply_policy(args, [])
    st["locked_ids"], st["pending"] = [], None
    save_state(args, st)
    print("Desbloqueado. Reinicia Chrome para que se apliquen los cambios.")


def cmd_cancel(args):
    st = load_state(args)
    st["pending"] = None
    save_state(args, st)
    print("Solicitud cancelada.")


def cmd_status(args):
    st = load_state(args)
    save_state(args, st)
    print("Bloqueadas:", len(st["locked_ids"]), "extensiones" if st["locked_ids"] else "(nada bloqueado)")
    p = st["pending"]
    if p:
        now = time.time()
        if now < p["unlock_at"]:
            print(f"Desbloqueo pendiente: faltan {fmt(p['unlock_at'] - now)} (mm:ss).")
        else:
            print(f"Ya puedes confirmar el desbloqueo; caduca en {fmt(p['expires_at'] - now)} (mm:ss).")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--policy-dir", help=argparse.SUPPRESS)  # solo para pruebas
    ap.add_argument("--state-dir", help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd", required=True)
    l = sub.add_parser("lock", help="bloquear las extensiones instaladas (inmediato)")
    l.add_argument("--ids", help="IDs adicionales separados por comas")
    l.add_argument("--user", help="usuario cuyo perfil de Chrome se analiza")
    for name, fn, h in [("request-unlock", cmd_request, "iniciar la espera de 30 min"),
                        ("confirm-unlock", cmd_confirm, "desbloquear tras la espera"),
                        ("cancel", cmd_cancel, "cancelar la solicitud"),
                        ("status", cmd_status, "ver estado")]:
        sub.add_parser(name, help=h).set_defaults(fn=fn)
    l.set_defaults(fn=cmd_lock)
    args = ap.parse_args()
    require_admin(args)
    args.fn(args)


if __name__ == "__main__":
    main()
