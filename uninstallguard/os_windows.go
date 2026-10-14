//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const taskName = "UninstallGuard"

var (
	k32        = syscall.NewLazyDLL("kernel32.dll")
	ntdll      = syscall.NewLazyDLL("ntdll.dll")
	queryImage = k32.NewProc("QueryFullProcessImageNameW")
	readMem    = k32.NewProc("ReadProcessMemory")
	ntQueryInf = ntdll.NewProc("NtQueryInformationProcess")
)

func dataDir() string {
	if d := os.Getenv("WEBGUARD_DIR"); d != "" {
		return d
	}
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "uninstallguard")
}

func installedExe() string { return filepath.Join(dataDir(), "uninstallguard.exe") }

func run(name string, args ...string) (string, error) {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var out bytes.Buffer
	c.Stdout, c.Stderr = &out, &out
	err := c.Run()
	return out.String(), err
}

func ps(script string) (string, error) {
	return run("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		"[Console]::OutputEncoding=[Text.Encoding]::UTF8;"+script)
}

// Solo Administradores y SYSTEM pueden modificar la carpeta (config, contraseña cifrada, programa).
func hardenDir(dir string) {
	run("icacls", dir, "/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F")
}

func openBrowser(url string) { run("rundll32", "url.dll,FileProtocolHandler", url) }

// ---------- lista de programas instalados ----------

const listScript = `$p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
$l=@(Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } | ForEach-Object {
 [pscustomobject]@{ name=[string]$_.DisplayName; key=(($_.PSPath -replace '^[^:]*::','') -replace 'HKEY_LOCAL_MACHINE','HKLM' -replace 'HKEY_CURRENT_USER','HKCU');
  uninstall=[string]$_.UninstallString; quiet=[string]$_.QuietUninstallString; dir=[string]$_.InstallLocation; version=[string]$_.DisplayVersion } })
ConvertTo-Json -InputObject $l -Compress`

func listPrograms() ([]Program, error) {
	out, err := ps(listScript)
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(out))
	}
	var all, res []Program
	if err := json.Unmarshal(bytes.TrimPrefix([]byte(strings.TrimSpace(out)), []byte("\xef\xbb\xbf")), &all); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, p := range all {
		if p.Name == "" || (p.Uninstall == "" && p.Quiet == "") || seen[p.Key] {
			continue
		}
		seen[p.Key] = true
		res = append(res, p)
	}
	return res, nil
}

// ---------- aplicar / quitar protección ----------

func regHasNoRemove(key string) bool {
	out, err := run("reg", "query", key, "/v", "NoRemove")
	return err == nil && strings.Contains(out, "0x1")
}

func lock(it Item) {
	run("reg", "add", it.Key, "/v", "NoRemove", "/t", "REG_DWORD", "/d", "1", "/f")
}

// checkStrongDir evita denegar borrado sobre carpetas del sistema o raíces enteras.
func checkStrongDir(dir string) error {
	dir = strings.TrimRight(strings.TrimSpace(dir), `\/`)
	if dir == "" {
		return fmt.Errorf("este programa no declara su carpeta de instalación")
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return fmt.Errorf("la carpeta de instalación no existe: %s", dir)
	}
	d := strings.ToLower(dir)
	if len(d) <= 3 {
		return fmt.Errorf("no se puede proteger una unidad completa")
	}
	for _, v := range []string{"SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData", "USERPROFILE", "PUBLIC"} {
		s := strings.ToLower(strings.TrimRight(os.Getenv(v), `\/`))
		if s != "" && (d == s || strings.HasPrefix(s, d+`\`) || (v == "SystemRoot" && strings.HasPrefix(d, s+`\`))) {
			return fmt.Errorf("carpeta demasiado general o del sistema: %s", dir)
		}
	}
	return nil
}

// applyItem pone NoRemove y, si it.Strong, deniega borrar en su carpeta. Devuelve si NoRemove ya existía.
func applyItem(it Item, strongOnly bool) (hadLock bool) {
	if !strongOnly {
		hadLock = regHasNoRemove(it.Key)
		lock(it)
	}
	if it.Strong && checkStrongDir(it.Dir) == nil {
		run("icacls", it.Dir, "/deny", "*S-1-1-0:(OI)(CI)(DE,DC)")
	}
	return hadLock
}

func releaseStrong(it Item) {
	if it.Dir != "" && checkStrongDir(it.Dir) == nil {
		run("icacls", it.Dir, "/remove:d", "*S-1-1-0")
	}
}

func releaseItem(it Item) {
	if !it.HadLock {
		run("reg", "delete", it.Key, "/v", "NoRemove", "/f")
	}
	releaseStrong(it)
}

func enableService(items []Item) error {
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
	if out, err := run("schtasks", "/create", "/tn", taskName, "/tr", `"`+installedExe()+`" run`,
		"/sc", "onstart", "/ru", "SYSTEM", "/rl", "highest", "/f"); err != nil {
		return fmt.Errorf("no se pudo crear la tarea: %s", strings.TrimSpace(out))
	}
	for i := range items {
		items[i].HadLock = applyItem(items[i], false)
	}
	os.Remove(filepath.Join(dir, "heartbeat.txt"))
	run("schtasks", "/run", "/tn", taskName)
	for i := 0; i < 20; i++ { // el servicio debe dar señales de vida
		time.Sleep(500 * time.Millisecond)
		if heartbeatFresh() {
			return nil
		}
	}
	run("schtasks", "/delete", "/tn", taskName, "/f")
	for _, it := range items {
		releaseItem(it)
	}
	return fmt.Errorf("el servicio de vigilancia no arrancó (puede que el antivirus haya bloqueado %s). Mira «Diagnóstico»", installedExe())
}

func heartbeatFresh() bool {
	b, err := os.ReadFile(filepath.Join(dataDir(), "heartbeat.txt"))
	var n int64
	fmt.Sscan(strings.TrimSpace(string(b)), &n)
	return err == nil && time.Since(time.Unix(n, 0)) < 30*time.Second
}

func diagnose(cfg Config) string {
	var b strings.Builder
	sec := func(t, body string) { fmt.Fprintf(&b, "== %s ==\n%s\n\n", t, strings.TrimSpace(body)) }
	out, _ := run("schtasks", "/query", "/tn", taskName, "/fo", "LIST", "/v")
	sec("Tarea programada "+taskName, out)
	if fi, err := os.Stat(installedExe()); err == nil {
		sec("Programa instalado", fmt.Sprintf("%s (%d bytes)", installedExe(), fi.Size()))
	} else {
		sec("Programa instalado", "NO existe: "+installedExe()+" (¿lo borró el antivirus?)")
	}
	sec("El servicio da señales de vida", fmt.Sprint(heartbeatFresh()))
	sec("Protección activada en la configuración", fmt.Sprint(cfg.Enabled))
	for _, it := range cfg.Items {
		var t strings.Builder
		o, err := run("reg", "query", it.Key, "/v", "NoRemove")
		fmt.Fprintf(&t, "NoRemove: %v %s\n", err == nil && strings.Contains(o, "0x1"), strings.TrimSpace(o))
		exe, args := splitCmd(it.Uninstall)
		_, serr := os.Stat(exe)
		fmt.Fprintf(&t, "Desinstalador: %q args=%q existe=%v\n", exe, args, serr == nil)
		fmt.Fprintf(&t, "Se reconocería su desinstalador: %v\n", it.Matches(exe, it.Uninstall))
		fmt.Fprintf(&t, "Carpeta: %q reforzada=%v", it.Dir, it.Strong)
		sec("Programa protegido: "+it.Name, t.String())
	}
	return b.String()
}

func disableService(items []Item) error {
	run("schtasks", "/delete", "/tn", taskName, "/f")
	run("taskkill", "/f", "/im", "uninstallguard.exe", "/fi", fmt.Sprintf("PID ne %d", os.Getpid()))
	for _, it := range items {
		releaseItem(it)
	}
	return nil
}

// ---------- vigilante (tarea programada como SYSTEM) ----------

type procInfo struct {
	ExitStatus, Peb, Affinity, BasePriority, Pid, ParentPid uintptr
}

func snapshot() map[uint32]bool {
	out := map[uint32]bool{}
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return out
	}
	defer syscall.CloseHandle(snap)
	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = syscall.Process32First(snap, &pe); err == nil; err = syscall.Process32Next(snap, &pe) {
		out[pe.ProcessID] = true
	}
	return out
}

func imageOf(h syscall.Handle) string {
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	if r, _, _ := queryImage.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n))); r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:n])
}

func readAt(h syscall.Handle, addr uintptr, buf []byte) bool {
	var n uintptr
	r, _, _ := readMem.Call(uintptr(h), addr, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)))
	return r != 0 && int(n) == len(buf)
}

// cmdlineOf lee la línea de comandos del PEB del proceso (x64).
func cmdlineOf(h syscall.Handle) string {
	var pbi procInfo
	var ret uint32
	if r, _, _ := ntQueryInf.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&pbi)), unsafe.Sizeof(pbi), uintptr(unsafe.Pointer(&ret))); r != 0 || pbi.Peb == 0 {
		return ""
	}
	var ptr [8]byte
	if !readAt(h, pbi.Peb+0x20, ptr[:]) { // PEB.ProcessParameters
		return ""
	}
	params := *(*uintptr)(unsafe.Pointer(&ptr[0]))
	var us [16]byte // UNICODE_STRING en RTL_USER_PROCESS_PARAMETERS+0x70
	if !readAt(h, params+0x70, us[:]) {
		return ""
	}
	length := int(*(*uint16)(unsafe.Pointer(&us[0])))
	buf := *(*uintptr)(unsafe.Pointer(&us[8]))
	if length == 0 || length > 32768 || buf == 0 {
		return ""
	}
	raw := make([]byte, length)
	if !readAt(h, buf, raw) {
		return ""
	}
	u := make([]uint16, length/2)
	for i := range u {
		u[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	return syscall.UTF16ToString(u)
}

func runDaemon() {
	dir := dataDir()
	os.MkdirAll(dir, 0o700)
	store := NewStore(dir)
	logf, _ := os.OpenFile(filepath.Join(dir, "blocked.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	known := snapshot()
	var items []Item
	var lastRefresh, lastLock, lastBeat time.Time
	for {
		time.Sleep(200 * time.Millisecond)
		cfg := store.Get()
		if time.Since(lastBeat) > 5*time.Second {
			os.WriteFile(filepath.Join(dir, "heartbeat.txt"), []byte(fmt.Sprint(time.Now().Unix())), 0o600)
			lastBeat = time.Now()
		}
		if time.Since(lastRefresh) > time.Minute || len(items) != len(cfg.Items) {
			items = append([]Item{}, cfg.Items...)
			if list, err := listPrograms(); err == nil { // una actualización puede mover el desinstalador
				for i := range items {
					for _, p := range list {
						if p.Key == items[i].Key {
							items[i].Uninstall, items[i].Quiet = p.Uninstall, p.Quiet
							if p.Dir != "" {
								items[i].Dir = p.Dir
							}
						}
					}
				}
			}
			lastRefresh = time.Now()
		}
		if cfg.Enabled && time.Since(lastLock) > 30*time.Second { // las apps a veces reescriben su clave
			for _, it := range items {
				lock(it)
			}
			lastLock = time.Now()
		}
		cur := snapshot()
		for pid := range cur {
			if known[pid] || !cfg.Enabled || len(items) == 0 {
				continue
			}
			h, err := syscall.OpenProcess(0x1411, false, pid) // TERMINATE | QUERY_INFORMATION | VM_READ | QUERY_LIMITED
			if err != nil {
				continue
			}
			img, cmd := imageOf(h), cmdlineOf(h)
			for _, it := range items {
				if it.Matches(img, cmd) {
					syscall.TerminateProcess(h, 1)
					if logf != nil {
						fmt.Fprintf(logf, "%s\t%s\t%s\n", time.Now().Format(time.RFC3339), it.Name, img)
					}
					break
				}
			}
			syscall.CloseHandle(h)
		}
		known = cur
	}
}
