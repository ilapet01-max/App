# applock — contraseña de seguridad para instalar aplicaciones (Linux Debian/Ubuntu)

Programa de línea de comandos (Python 3, sin dependencias). Mientras está activo:

- **apt / apt-get / dpkg**: antes de instalar o quitar paquetes pide la contraseña (3 intentos); si falla, se aborta.
- **Centro de software (PackageKit), Snap y Flatpak**: una regla de polkit deniega la instalación.

La contraseña se guarda con PBKDF2-SHA256 y sal aleatoria en `/etc/applock/password.json` (modo 600).

## Uso (como root)
```
sudo python3 applock.py set-password   # define la contraseña (mín. 8 caracteres)
sudo python3 applock.py enable         # activa el bloqueo (instala el hook y la regla)
sudo python3 applock.py status
sudo python3 applock.py disable        # pide la contraseña
```
Para instalar algo con el bloqueo activo: `sudo apt install paquete` → te pedirá la contraseña.
Para Snap/Flatpak/Centro de software: `disable`, instalar, y `enable` de nuevo.

## Límites
- **Solo es una barrera real si la contraseña de root no la conoces tú.** Quien sea root puede borrar
  `/etc/apt/apt.conf.d/00applock` y `/etc/polkit-1/rules.d/00-applock.rules`, o ejecutar `dpkg` con el hook
  desactivado. Para protección real, usa una cuenta estándar y que otra persona tenga el root.
- No cubre instalar binarios a mano (`./instalador`, `pip`, AppImage, compilar desde fuente) ni otros sistemas
  (Windows/macOS). Sin terminal (`/dev/tty`) la instalación por apt se deniega.
