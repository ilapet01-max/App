//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// En Linux/macOS solo sirve para desarrollo y pruebas: no toca nada del sistema.

func dataDir() string {
	if d := os.Getenv("WEBGUARD_DIR"); d != "" {
		return d
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".uninstallguard")
}

func hardenDir(string)       {}
func openBrowser(url string) { fmt.Println("Abre:", url) }

func listPrograms() ([]Program, error) {
	return []Program{
		{"Mozilla Firefox", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox`, `"C:\Program Files\Mozilla Firefox\uninstall\helper.exe"`, "", `C:\Program Files\Mozilla Firefox`, "131.0"},
		{"7-Zip", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip`, `"C:\Program Files\7-Zip\Uninstall.exe"`, "", `C:\Program Files\7-Zip`, "24.08"},
		{"Steam", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Steam`, `"C:\Program Files (x86)\Steam\uninstall.exe"`, "", `C:\Program Files (x86)\Steam`, ""},
		{"Discord", `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Discord`, `"C:\Users\u\AppData\Local\Discord\Update.exe" --uninstall -s`, "", "", "1.0.9"},
	}, nil
}

func checkStrongDir(dir string) error {
	if dir == "" {
		return fmt.Errorf("este programa no declara su carpeta de instalación")
	}
	return nil
}
func applyItem(Item, bool) bool   { return false }
func releaseItem(Item)            {}
func releaseStrong(Item)          {}
func enableService([]Item) error  { return nil }
func disableService([]Item) error { return nil }
func runDaemon() {
	dir := dataDir()
	os.MkdirAll(dir, 0o700)
	for {
		os.WriteFile(filepath.Join(dir, "heartbeat.txt"), []byte(fmt.Sprint(time.Now().Unix())), 0o600)
		time.Sleep(5 * time.Second)
	}
}
