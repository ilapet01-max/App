# extlock — congelar extensiones de Chrome durante 30 minutos

Programa de línea de comandos (Python 3, sin dependencias) que usa las **políticas
administradas de Chrome** para que las extensiones instaladas no se puedan desactivar,
quitar ni gestionar. Solo root/administrador puede cambiar esas políticas, y este programa
solo las retira tras una espera de 30 minutos.

Qué aplica:
- `force_installed` a cada extensión de la Chrome Web Store instalada → sin botón de quitar ni interruptor.
- `URLBlocklist` de `chrome://extensions` → no se puede abrir el panel de gestión
  (esto también protege a extensiones cargadas sin empaquetar, como *Cooldown Blocker*).

## Uso (Linux o Windows, como root / administrador)

```
sudo python3 extlock.py lock              # bloquear (inmediato). Vuelve a ejecutarlo para añadir más; nunca quita.
sudo python3 extlock.py status
sudo python3 extlock.py request-unlock    # empieza la espera de 30 min
sudo python3 extlock.py confirm-unlock    # tras 30 min, y dentro de los 10 min siguientes
sudo python3 extlock.py cancel            # cancela la solicitud
```
Opciones de `lock`: `--user NOMBRE` (perfil de Chrome a analizar, útil si usas `sudo`) y
`--ids ID1,ID2` (IDs extra). Después de `lock` o `confirm-unlock`, reinicia Chrome
(o `chrome://policy` → *Volver a cargar políticas*).

## Límites
- **La protección es real solo si tú no puedes ser administrador.** Si conoces la contraseña de
  root/administrador puedes borrar la política a mano (`/etc/opt/chrome/policies/managed/extlock.json`
  o el registro de Windows). Pide a otra persona que ponga esa contraseña, o usa una cuenta estándar.
- Solo cubre extensiones de la Web Store; las cargadas sin empaquetar se ocultan tras el bloqueo
  de `chrome://extensions`, pero se pueden quitar desde el menú del icono ("Quitar de Chrome").
- No hay soporte para macOS. Otros navegadores no quedan cubiertos.
- Retroceder el reloj está detectado; adelantarlo acorta la espera.
