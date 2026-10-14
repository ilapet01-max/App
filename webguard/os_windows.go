//go:build windows

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const taskName = "WebGuard"

func dataDir() string {
	if d := os.Getenv("WEBGUARD_DIR"); d != "" {
		return d
	}
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "webguard")
}

func installedExe() string { return filepath.Join(dataDir(), "webguard.exe") }

func run(name string, args ...string) (string, error) {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var out bytes.Buffer
	c.Stdout, c.Stderr = &out, &out
	err := c.Run()
	return out.String(), err
}

func ps(script string) (string, error) {
	return run("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}

// Solo Administradores y SYSTEM pueden modificar la carpeta (config, contraseña cifrada, programa).
func hardenDir(dir string) {
	run("icacls", dir, "/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F")
}

func openBrowser(url string) { run("rundll32", "url.dll,FileProtocolHandler", url) }

var dohPolicies = []struct{ key, name, typ, val string }{
	{`HKLM\SOFTWARE\Policies\Google\Chrome`, "DnsOverHttpsMode", "REG_SZ", "off"},
	{`HKLM\SOFTWARE\Policies\Microsoft\Edge`, "DnsOverHttpsMode", "REG_SZ", "off"},
	{`HKLM\SOFTWARE\Policies\BraveSoftware\Brave`, "DnsOverHttpsMode", "REG_SZ", "off"},
	{`HKLM\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS`, "Enabled", "REG_DWORD", "0"},
	{`HKLM\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS`, "Locked", "REG_DWORD", "1"},
}

const setDNS = `Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
  try { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses ('127.0.0.1','::1') -ErrorAction Stop }
  catch { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses '127.0.0.1' } }`

// DNS IPv4 reales (no de bucle) de adaptadores activos: se usarán como servidores de reenvío.
const learnDNS = `Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
  (Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4).ServerAddresses } |
  Where-Object { $_ -and $_ -ne '127.0.0.1' } | Select-Object -Unique`

func learnUpstreams(dir string) {
	out, err := ps(learnDNS)
	if err != nil {
		return
	}
	var ups []string
	for _, l := range strings.Fields(out) {
		ups = append(ups, l+":53")
	}
	if len(ups) > 0 {
		os.WriteFile(filepath.Join(dir, "upstreams.txt"), []byte(strings.Join(ups, "\n")), 0o600)
	}
}

func loadUpstreams(dir string) []string {
	b, _ := os.ReadFile(filepath.Join(dir, "upstreams.txt"))
	return strings.Fields(string(b))
}

// Cada 45 s: aprende los DNS reales de redes nuevas y vuelve a forzar 127.0.0.1 en todos los adaptadores.
func watchdog(d *Daemon, dir string) {
	learnUpstreams(dir)
	d.SetUpstreams(loadUpstreams(dir))
	ps(setDNS)
}

func enableProtection() error {
	dir := dataDir()
	self, _ := os.Executable()
	if !strings.EqualFold(self, installedExe()) {
		b, err := os.ReadFile(self)
		if err == nil {
			err = os.WriteFile(installedExe(), b, 0o755)
		}
		if err != nil {
			return fmt.Errorf("no se pudo copiar el programa: %v", err)
		}
	}
	hardenDir(dir)
	learnUpstreams(dir) // antes de cambiar el DNS
	for _, p := range dohPolicies {
		run("reg", "add", p.key, "/v", p.name, "/t", p.typ, "/d", p.val, "/f")
	}
	if out, err := run("schtasks", "/create", "/tn", taskName, "/tr", `"`+installedExe()+`" run`,
		"/sc", "onstart", "/ru", "SYSTEM", "/rl", "highest", "/f"); err != nil {
		return fmt.Errorf("no se pudo crear la tarea: %s", strings.TrimSpace(out))
	}
	run("schtasks", "/run", "/tn", taskName)
	time.Sleep(1500 * time.Millisecond) // deja que el demonio abra el puerto 53 antes de apuntar el DNS a él
	if out, err := ps(setDNS); err != nil {
		return fmt.Errorf("no se pudo cambiar el DNS: %s", strings.TrimSpace(out))
	}
	return nil
}

func disableProtection() error {
	run("schtasks", "/delete", "/tn", taskName, "/f")
	run("taskkill", "/f", "/im", "webguard.exe", "/fi", fmt.Sprintf("PID ne %d", os.Getpid()))
	// Vuelve al DNS automático (DHCP) en todos los adaptadores.
	ps(`Get-NetAdapter | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }`)
	for _, p := range dohPolicies {
		run("reg", "delete", p.key, "/v", p.name, "/f")
	}
	run("reg", "delete", `HKLM\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS`, "/f")
	return nil
}
