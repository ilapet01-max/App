//go:build windows

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	maxAllow   = 120 // minutos
	taskName   = "applock"
	attempts   = 3
	policyTick = 60 * time.Second
)

var (
	k32         = syscall.NewLazyDLL("kernel32.dll")
	shell32     = syscall.NewLazyDLL("shell32.dll")
	getMode     = k32.NewProc("GetConsoleMode")
	setMode     = k32.NewProc("SetConsoleMode")
	queryImage  = k32.NewProc("QueryFullProcessImageNameW")
	isUserAdmin = shell32.NewProc("IsUserAnAdmin")
	stdin       = bufio.NewReader(os.Stdin)
)

func dataDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "applock")
}

func installedExe() string { return filepath.Join(dataDir(), "applock.exe") }

// ---------- utilidades ----------

func run(name string, args ...string) error {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return c.Run()
}

func isAdmin() bool { r, _, _ := isUserAdmin.Call(); return r != 0 }

func readLine() string {
	s, _ := stdin.ReadString('\n')
	return strings.TrimSpace(s)
}

func readPassword(prompt string) string {
	fmt.Print(prompt)
	h := uintptr(syscall.Stdin)
	var mode uint32
	ok, _, _ := getMode.Call(h, uintptr(unsafe.Pointer(&mode)))
	if ok != 0 {
		setMode.Call(h, uintptr(mode&^0x0004)) // sin eco
		defer setMode.Call(h, uintptr(mode))
	}
	s := readLine()
	fmt.Println()
	return s
}

func loadRec() (Rec, bool) {
	var r Rec
	b, err := os.ReadFile(filepath.Join(dataDir(), "password.json"))
	if err != nil || json.Unmarshal(b, &r) != nil {
		return r, false
	}
	return r, true
}

func loadState() State {
	var s State
	if b, err := os.ReadFile(filepath.Join(dataDir(), "state.json")); err == nil {
		json.Unmarshal(b, &s)
	}
	return s
}

func saveState(s State) {
	b, _ := json.Marshal(s)
	os.WriteFile(filepath.Join(dataDir(), "state.json"), b, 0o600)
}

func askPassword(why string) bool {
	rec, ok := loadRec()
	if !ok {
		fmt.Println("No hay contraseña definida. Usa primero «Definir contraseña».")
		return false
	}
	fmt.Println(why)
	for i := 1; i <= attempts; i++ {
		if rec.verify(readPassword("Contraseña de seguridad: ")) {
			return true
		}
		fmt.Printf("Contraseña incorrecta (%d/%d).\n", i, attempts)
	}
	return false
}

// ---------- políticas de Windows ----------

type policy struct{ key, name, val string }

var policies = []policy{
	{`HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`, "DisableMSI", "2"},            // bloquea todos los .msi
	{`HKLM\SOFTWARE\Policies\Microsoft\WindowsStore`, "RemoveWindowsStore", "1"},         // Microsoft Store
	{`HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller`, "EnableAppInstaller", "0"}, // winget
}

func applyPolicies(block bool) {
	for _, p := range policies {
		if block {
			run("reg", "add", p.key, "/v", p.name, "/t", "REG_DWORD", "/d", p.val, "/f")
		} else {
			run("reg", "delete", p.key, "/v", p.name, "/f")
		}
	}
}

// ---------- comandos ----------

func needAdmin() bool {
	if !isAdmin() {
		fmt.Println("Ejecuta applock.exe como administrador (clic derecho → Ejecutar como administrador).")
		return false
	}
	os.MkdirAll(dataDir(), 0o700)
	return true
}

func cmdSetPassword() {
	if !needAdmin() {
		return
	}
	if _, ok := loadRec(); ok && !askPassword("Para cambiar la contraseña, escribe la actual.") {
		fmt.Println("Denegado.")
		return
	}
	pw := readPassword("Nueva contraseña (mín. 8 caracteres): ")
	if len(pw) < 8 {
		fmt.Println("Demasiado corta.")
		return
	}
	if readPassword("Repite la contraseña: ") != pw {
		fmt.Println("No coinciden.")
		return
	}
	b, _ := json.Marshal(newRec(pw))
	if err := os.WriteFile(filepath.Join(dataDir(), "password.json"), b, 0o600); err != nil {
		fmt.Println("Error:", err)
		return
	}
	harden()
	fmt.Println("Contraseña guardada.")
}

// Solo Administradores y SYSTEM pueden tocar la carpeta (ni siquiera leer la contraseña cifrada los demás).
func harden() {
	run("icacls", dataDir(), "/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F")
}

func cmdEnable() {
	if !needAdmin() {
		return
	}
	if _, ok := loadRec(); !ok {
		fmt.Println("Define primero la contraseña.")
		return
	}
	self, _ := os.Executable()
	if !strings.EqualFold(self, installedExe()) {
		b, err := os.ReadFile(self)
		if err == nil {
			err = os.WriteFile(installedExe(), b, 0o755)
		}
		if err != nil {
			fmt.Println("No se pudo copiar el programa:", err)
			return
		}
	}
	harden()
	saveState(State{})
	if err := run("schtasks", "/create", "/tn", taskName, "/tr", `"`+installedExe()+`" watch`,
		"/sc", "onstart", "/ru", "SYSTEM", "/rl", "highest", "/f"); err != nil {
		fmt.Println("No se pudo crear la tarea programada:", err)
		return
	}
	run("schtasks", "/run", "/tn", taskName)
	applyPolicies(true)
	fmt.Println("Bloqueo ACTIVADO (se mantiene tras reiniciar).")
}

func cmdAllow(arg string) {
	if !needAdmin() {
		return
	}
	mins := 15
	if n, err := strconv.Atoi(arg); err == nil && n > 0 {
		mins = min(n, maxAllow)
	}
	if !askPassword(fmt.Sprintf("Permitir instalar durante %d minutos.", mins)) {
		fmt.Println("Denegado.")
		return
	}
	saveState(State{AllowUntil: time.Now().Add(time.Duration(mins) * time.Minute).Unix()})
	applyPolicies(false)
	fmt.Printf("Instalaciones permitidas %d minutos; después se bloquea solo.\n", mins)
}

func cmdDisable() {
	if !needAdmin() {
		return
	}
	if !askPassword("Desactivar el bloqueo de instalación.") {
		fmt.Println("Denegado.")
		return
	}
	run("schtasks", "/delete", "/tn", taskName, "/f")
	run("taskkill", "/f", "/im", "applock.exe", "/fi", fmt.Sprintf("PID ne %d", os.Getpid()))
	applyPolicies(false)
	saveState(State{})
	fmt.Println("Bloqueo DESACTIVADO.")
}

func cmdStatus() {
	_, ok := loadRec()
	fmt.Println("Contraseña:", map[bool]string{true: "definida", false: "NO definida"}[ok])
	err := exec.Command("schtasks", "/query", "/tn", taskName).Run()
	if err != nil {
		fmt.Println("Bloqueo: inactivo")
		return
	}
	if left := time.Until(time.Unix(loadState().AllowUntil, 0)); left > 0 {
		fmt.Printf("Bloqueo: pausado, se reactiva en %d min\n", int(left.Minutes())+1)
	} else {
		fmt.Println("Bloqueo: ACTIVO")
	}
}

// ---------- vigilante (tarea programada como SYSTEM) ----------

func processes() map[uint32]string {
	out := map[uint32]string{}
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return out
	}
	defer syscall.CloseHandle(snap)
	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = syscall.Process32First(snap, &pe); err == nil; err = syscall.Process32Next(snap, &pe) {
		out[pe.ProcessID] = ""
	}
	return out
}

func imagePath(pid uint32) (string, syscall.Handle) {
	h, err := syscall.OpenProcess(0x1001, false, pid) // QUERY_LIMITED_INFORMATION | TERMINATE
	if err != nil {
		return "", 0
	}
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	if r, _, _ := queryImage.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n))); r == 0 {
		syscall.CloseHandle(h)
		return "", 0
	}
	return syscall.UTF16ToString(buf[:n]), h
}

func cmdWatch() {
	exclude := []string{os.Getenv("SystemRoot") + `\`, os.Getenv("ProgramFiles") + `\`, os.Getenv("ProgramFiles(x86)") + `\`, dataDir() + `\`}
	logf, _ := os.OpenFile(filepath.Join(dataDir(), "watch.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	known := processes()
	lastPolicy := time.Time{}
	for {
		time.Sleep(700 * time.Millisecond)
		enforcing := time.Now().Unix() >= loadState().AllowUntil
		if enforcing && time.Since(lastPolicy) > policyTick {
			applyPolicies(true)
			lastPolicy = time.Now()
		} else if !enforcing {
			lastPolicy = time.Time{}
		}
		cur := processes()
		for pid := range cur {
			if _, seen := known[pid]; seen || !enforcing {
				continue
			}
			if path, h := imagePath(pid); h != 0 {
				if isInstaller(path, exclude) {
					syscall.TerminateProcess(h, 1)
					if logf != nil {
						fmt.Fprintf(logf, "%s bloqueado: %s\n", time.Now().Format(time.RFC3339), path)
					}
				}
				syscall.CloseHandle(h)
			}
		}
		known = cur
	}
}

// ---------- menú interactivo (doble clic) ----------

func menu() {
	for {
		fmt.Print("\n=== applock: contraseña para instalar aplicaciones ===\n" +
			"1) Definir / cambiar contraseña\n2) Activar bloqueo\n3) Permitir instalar unos minutos (pide contraseña)\n" +
			"4) Desactivar bloqueo (pide contraseña)\n5) Estado\n0) Salir\n> ")
		switch readLine() {
		case "1":
			cmdSetPassword()
		case "2":
			cmdEnable()
		case "3":
			fmt.Print("¿Cuántos minutos? [15]: ")
			cmdAllow(readLine())
		case "4":
			cmdDisable()
		case "5":
			cmdStatus()
		case "0":
			return
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		menu()
		return
	}
	arg := ""
	if len(os.Args) > 2 {
		arg = os.Args[2]
	}
	switch os.Args[1] {
	case "set-password":
		cmdSetPassword()
	case "enable":
		cmdEnable()
	case "allow":
		cmdAllow(arg)
	case "disable":
		cmdDisable()
	case "status":
		cmdStatus()
	case "watch":
		cmdWatch()
	default:
		fmt.Println("Uso: applock.exe [set-password|enable|allow [minutos]|disable|status]")
	}
}
