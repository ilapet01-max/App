# applock.exe — contraseña de seguridad para instalar aplicaciones (Windows 10/11)

Un solo `.exe` (sin dependencias). Al hacer doble clic pide permisos de administrador y abre un menú.

## Qué hace mientras está activo
- **Instaladores `.msi`**: bloqueados por la política `DisableMSI`.
- **Microsoft Store y winget**: bloqueados por política.
- **Instaladores `.exe`**: una tarea programada (SYSTEM, arranca con Windows) vigila los procesos nuevos y
  **cierra** los que parecen instaladores: nombre con `setup`/`install` (salvo `unins…`), cualquier `.exe`
  lanzado desde `Descargas`, y los temporales de Inno Setup (`…\Temp\…tmp…`). Registro en
  `C:\ProgramData\applock\watch.log`.
- Para instalar: **«Permitir instalar unos minutos»** (pide la contraseña; 15 min por defecto, máx. 120).
  Pasado ese tiempo el bloqueo se reactiva solo.

## Uso
Doble clic en `applock.exe`: 1) definir contraseña (≥ 8 caracteres) → 2) activar bloqueo.
También por consola (como administrador): `applock.exe set-password | enable | allow [minutos] | disable | status`.

La contraseña se guarda con PBKDF2-SHA256 y sal en `C:\ProgramData\applock\password.json`, carpeta accesible
solo por Administradores y SYSTEM.

## Límites (léelo)
- **Solo es una barrera real si tu cuenta diaria NO es administrador.** Un administrador puede borrar la tarea
  programada, las claves de registro o `password.json`. Lo ideal: usa una cuenta estándar y que otra persona
  guarde la cuenta de administrador (así, además, Windows pide su propia contraseña para instalar).
- Es heurístico: un instalador con otro nombre y fuera de `Descargas` (p. ej. `zoom.exe` en el Escritorio)
  no se detecta. Los programas portables y los que se instalan solos en tu carpeta de usuario sin instalador tampoco.
- Las políticas de Microsoft Store pueden no aplicar en Windows Home.
- **No he podido probarlo en Windows** (compilado cruzado desde Linux; la lógica de contraseña y detección
  tiene tests). Prueba primero en un equipo no crítico. Si algo sale mal: `applock.exe disable`, o borra a mano la
  tarea `applock` (`schtasks /delete /tn applock /f`) y las tres claves de `build`/políticas listadas en `main_windows.go`.

## Compilar
`./build.sh` (requiere Go ≥ 1.24). El manifiesto de administrador está en `applock.manifest` (ya incluido como `.syso`).
