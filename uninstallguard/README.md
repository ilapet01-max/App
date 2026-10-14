# UninstallGuard — impide desinstalar los programas que elijas (Windows 10/11)

Un solo `uninstallguard.exe`. Al abrirlo pide permisos de administrador y muestra un panel (se abre en tu
navegador, solo accesible desde tu propio equipo).

## Uso
1. Crea tu contraseña (≥ 8 caracteres) la primera vez.
2. **+ Añadir programa** → elige de la lista de programas instalados. Proteger es inmediato.
3. Activa el interruptor **Protección**. Se instala una tarea programada (SYSTEM, arranca con Windows).
4. Para dejar de proteger un programa o desactivar todo hace falta la contraseña (desbloqueo de 10 min;
   5 fallos = 1 min de espera).

## Qué hace con cada programa protegido
- Pone `NoRemove=1` en su clave de desinstalación: desaparece/queda desactivado el botón **Desinstalar** de
  Configuración → Aplicaciones y del Panel de control (se vuelve a poner cada 30 s si la app lo reescribe).
- Un vigilante (cada 0,2 s) **cierra al instante** cualquier proceso que sea su desinstalador: su cadena de
  desinstalación exacta (también tras actualizaciones), `unins000.exe`/`uninstall*.exe` de su carpeta, la 2.ª fase de
  Inno Setup y `msiexec /x {GUID}` del producto. Cada intento queda registrado en el panel.
- **Protección reforzada** (opcional por programa): además deniega *borrar* archivos en su carpeta de instalación
  (a todos, incluido SYSTEM), lo que frena métodos raros como borrar la carpeta a mano o MSI que se escapen.
  **Ojo:** también impide que el programa se actualice o borre sus propios archivos temporales; actívala solo
  si no te importa. Se rechazan carpetas del sistema o demasiado generales.

## Límites (léelo)
- **Un administrador puede saltárselo todo** (parar la tarea, borrar la clave `NoRemove`, quitar la ACL). Usa una cuenta
  estándar y que otra persona guarde la de administrador.
- Solo programas «de escritorio» (Win32/MSI) que aparecen en la lista. No cubre apps de Microsoft Store (UWP) ni
  programas sin entrada de desinstalación. Los instalados solo para *otro* usuario (su rama HKCU) no aparecen.
- El vigilante detecta *procesos nuevos* cada 0,2 s: un proceso que viva menos que eso podría escaparse. Con MSI, si la
  orden ya llegó al servicio de Windows Installer antes de cerrar el cliente, la desinstalación puede continuar: ahí
  sirve la protección reforzada.
- **No lo he podido probar en Windows** (compilado desde Linux). Tienen tests y se probaron en Linux: las reglas que
  deciden si un proceso es un desinstalador, la API y el panel. Sin probar: la lectura de línea de comandos de
  procesos, `reg`, `icacls`, `schtasks` y PowerShell. Pruébalo primero con un programa sin importancia.
- Si algo sale mal: desactiva desde el panel o, como administrador, `schtasks /delete /tn UninstallGuard /f` y
  `reg delete "<clave del programa>" /v NoRemove /f`; para la reforzada: `icacls "<carpeta>" /remove:d *S-1-1-0`.

## Compilar / probar
`./build.sh` (Go ≥ 1.24) · `go test ./...`. En Linux/macOS `go run . ui -nobrowser` y `go run . run` sirven para
desarrollo con datos de ejemplo (no tocan el sistema).
