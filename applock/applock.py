#!/usr/bin/env python3
"""applock — pide una contraseña de seguridad antes de instalar cualquier aplicación (Linux Debian/Ubuntu).

Capas (todas se activan con `enable`):
  * apt/apt-get/dpkg: un hook (DPkg::Pre-Invoke) pide la contraseña antes de instalar o quitar
    paquetes; sin contraseña correcta la operación se aborta.
  * PackageKit (Centro de software), Snap y Flatpak: una regla de polkit deniega la instalación
    a todos los usuarios mientras el bloqueo esté activo (hay que usar `disable` con contraseña).

La contraseña se guarda con PBKDF2-HMAC-SHA256 (sal aleatoria) en /etc/applock/password.json (modo 600).
Requiere root. Sin dependencias.
"""
import argparse, getpass, hashlib, hmac, json, os, secrets, sys
from pathlib import Path

ITER = 600_000
ATTEMPTS = 3
SELF = "/usr/local/sbin/applock"
APT_HOOK = "00applock"
POLKIT_RULE = "00-applock.rules"

APT_CONF = f'''// Gestionado por applock
DPkg::Pre-Invoke {{ "{SELF} check --hook"; }};
'''

POLKIT = '''// Gestionado por applock: deniega instalar aplicaciones por GUI / snap / flatpak
polkit.addRule(function(action, subject) {
    var id = action.id;
    if (id.indexOf("org.freedesktop.packagekit.package-install") === 0 ||
        id.indexOf("org.freedesktop.packagekit.package-eula-accept") === 0 ||
        id.indexOf("org.freedesktop.packagekit.localize-install") === 0 ||
        id.indexOf("org.freedesktop.packagekit.system-update") === 0 ||
        id === "io.snapcraft.snapd.manage" ||
        id === "io.snapcraft.snapd.manage-interfaces" ||
        id.indexOf("org.freedesktop.Flatpak.app-install") === 0 ||
        id.indexOf("org.freedesktop.Flatpak.runtime-install") === 0 ||
        id.indexOf("org.freedesktop.Flatpak.install-bundle") === 0) {
        return polkit.Result.NO;
    }
});
'''


class Paths:
    def __init__(self, a):
        t = a.test_dir
        self.conf = Path(t) / "etc/applock" if t else Path("/etc/applock")
        self.apt = Path(t) / "etc/apt/apt.conf.d" if t else Path("/etc/apt/apt.conf.d")
        self.polkit = Path(t) / "etc/polkit-1/rules.d" if t else Path("/etc/polkit-1/rules.d")
        self.pw = self.conf / "password.json"


def require_root(a):
    if not a.test_dir and os.geteuid() != 0:
        sys.exit("Ejecuta este programa como root (sudo).")


# ---------- contraseña ----------

def hash_pw(pw, salt=None, it=ITER):
    salt = salt or secrets.token_bytes(16)
    return {"salt": salt.hex(), "iter": it,
            "hash": hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, it).hex()}


def verify(rec, pw):
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(rec["salt"]), rec["iter"])
    return hmac.compare_digest(h.hex(), rec["hash"])


def ask(prompt, a):
    if a.test_dir and os.environ.get("APPLOCK_TEST_PASSWORD") is not None:
        return os.environ["APPLOCK_TEST_PASSWORD"]
    return getpass.getpass(prompt)  # usa /dev/tty aunque stdin sea una tubería


def load_rec(p):
    if not p.pw.exists():
        sys.exit("No hay contraseña. Ejecuta primero: sudo applock set-password")
    return json.loads(p.pw.read_text())


def prompt_verify(p, a, why):
    rec = load_rec(p)
    for i in range(ATTEMPTS):
        try:
            pw = ask(f"[applock] {why}\nContraseña de seguridad: ", a)
        except (EOFError, OSError, getpass.GetPassWarning):
            return False  # sin terminal no se puede pedir contraseña → denegado
        if verify(rec, pw):
            return True
        print(f"Contraseña incorrecta ({i + 1}/{ATTEMPTS}).", file=sys.stderr)
    return False


# ---------- comandos ----------

def cmd_set_password(a, p):
    if p.pw.exists() and not prompt_verify(p, a, "Cambiar la contraseña."):
        sys.exit("Denegado.")
    pw = ask("Nueva contraseña: ", a)
    if len(pw) < 8:
        sys.exit("Usa al menos 8 caracteres.")
    if not (a.test_dir and os.environ.get("APPLOCK_TEST_PASSWORD") is not None) and ask("Repite la contraseña: ", a) != pw:
        sys.exit("No coinciden.")
    p.conf.mkdir(parents=True, exist_ok=True)
    os.chmod(p.conf, 0o700)
    fd = os.open(p.pw, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(hash_pw(pw), f)
    print("Contraseña guardada.")


def cmd_enable(a, p):
    load_rec(p)
    for d in (p.apt, p.polkit):
        d.mkdir(parents=True, exist_ok=True)
    (p.apt / APT_HOOK).write_text(APT_CONF)
    (p.polkit / POLKIT_RULE).write_text(POLKIT)
    if not a.test_dir:
        src = Path(__file__).resolve()
        if str(src) != SELF:
            Path(SELF).write_bytes(src.read_bytes())
            os.chmod(SELF, 0o755)
    print("Bloqueo ACTIVADO: apt pedirá contraseña; GUI/snap/flatpak denegados.")


def cmd_disable(a, p):
    if not is_enabled(p):
        return print("Ya estaba desactivado.")
    if not prompt_verify(p, a, "Desactivar el bloqueo de instalación."):
        sys.exit("Denegado.")
    (p.apt / APT_HOOK).unlink(missing_ok=True)
    (p.polkit / POLKIT_RULE).unlink(missing_ok=True)
    print("Bloqueo DESACTIVADO.")


def is_enabled(p):
    return (p.apt / APT_HOOK).exists() and (p.polkit / POLKIT_RULE).exists()


def cmd_status(a, p):
    print("Contraseña:", "definida" if p.pw.exists() else "NO definida")
    print("Bloqueo:", "ACTIVO" if is_enabled(p) else "inactivo")


def cmd_check(a, p):
    """Lo llama apt antes de cada operación de dpkg. Código ≠ 0 aborta la instalación."""
    if prompt_verify(p, a, "Se va a instalar/modificar software."):
        return
    print("[applock] Instalación bloqueada.", file=sys.stderr)
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser(prog="applock", description=__doc__.split("\n")[0])
    ap.add_argument("--test-dir", help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in [("set-password", cmd_set_password), ("enable", cmd_enable),
                     ("disable", cmd_disable), ("status", cmd_status), ("check", cmd_check)]:
        s = sub.add_parser(name)
        s.set_defaults(fn=fn)
        if name == "check":
            s.add_argument("--hook", action="store_true")
    a = ap.parse_args()
    require_root(a)
    a.fn(a, Paths(a))


if __name__ == "__main__":
    main()
