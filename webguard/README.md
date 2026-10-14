# WebGuard — bloqueo de webs y palabras clave en todos los navegadores (Windows 10/11)

Un solo `webguard.exe`. Al abrirlo pide permisos de administrador y muestra un panel (se abre en tu navegador,
solo accesible desde tu propio equipo).

## Cómo funciona
Un servicio (tarea programada como SYSTEM, arranca con Windows) actúa como **servidor DNS local** y se pone como
DNS de todos los adaptadores de red. Por eso vale para *cualquier* navegador o programa:
- **Sitios**: bloquea el dominio y todos sus subdominios.
- **Palabras clave**: bloquea cualquier dominio que *contenga* la palabra (p. ej. `casino` → `mi-casino.net`).
  Lista de **excepciones** por si una palabra bloquea algo legítimo.
- **SafeSearch forzado**: modo seguro en Google, Bing, DuckDuckGo y YouTube (restringido).
- Cierra las vías para saltarse el filtro: bloquea resolutores DNS-sobre-HTTPS conocidos, desactiva DoH en
  Chrome/Edge/Brave/Firefox por política y recoloca el DNS cada 45 s si alguien lo cambia.
- Las webs bloqueadas muestran una página de «bloqueado» (HTTP) o error de conexión (HTTPS).

## Contraseña
Lo que **refuerza** el bloqueo (añadir sitios/palabras, activar protección o SafeSearch, quitar excepciones) es
inmediato. Lo que lo **debilita** (quitar sitios/palabras, añadir excepciones, desactivar protección/SafeSearch)
pide la contraseña (desbloqueo de 10 min; 5 fallos = 1 min de espera). Se guarda con PBKDF2-SHA256.

## Límites (léelo)
- **Las palabras clave solo miran el nombre del dominio**, no el contenido de la página ni lo que buscas:
  con HTTPS nadie puede ver la URL completa sin interceptar el tráfico. Para el contenido de las búsquedas usa SafeSearch.
- Un **administrador** puede saltarse todo (quitar la tarea, cambiar el DNS, borrar la configuración). Usa una cuenta
  estándar y que otra persona guarde la de administrador.
- Una VPN, un proxy o un DNS configurado dentro de una app pueden evitar el filtro. Al desactivar, el DNS vuelve a
  «automático» (si tenías DNS fijo propio, hay que volver a ponerlo).
- Necesita el puerto 53 libre en 127.0.0.1 (si usas Hyper-V/ICS/otro servidor DNS local puede fallar; saldrá «Servicio no responde»).
- **No lo he podido probar en Windows** (compilado desde Linux). El filtro DNS, SafeSearch, las reglas y la API sí
  tienen tests y se probaron en Linux. Los comandos de Windows (PowerShell para el DNS, `schtasks`, `reg`) están sin probar.
  Si algo falla: desactiva desde el panel, o en una consola de administrador:
  `schtasks /delete /tn WebGuard /f` y `powershell -c "Get-NetAdapter | % { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }"`.

## Compilar / probar
`./build.sh` (Go ≥ 1.24) · `go test ./...`. En Linux/macOS `go run . ui -nobrowser` y `go run . run -dns 127.0.0.1:5353 -dns6 "" -page ""`
sirven para desarrollo (no tocan la configuración del sistema; datos en `~/.webguard` o `$WEBGUARD_DIR`).
