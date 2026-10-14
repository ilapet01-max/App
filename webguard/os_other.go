//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// En Linux/macOS solo sirve para desarrollo y pruebas: no toca la configuración del sistema.

func dataDir() string {
	if d := os.Getenv("WEBGUARD_DIR"); d != "" {
		return d
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".webguard")
}
func hardenDir(string)              {}
func openBrowser(url string)        { fmt.Println("Abre:", url) }
func enableProtection() error       { return nil }
func disableProtection() error      { return nil }
func watchdog(*Daemon, string)      {}
func loadUpstreams(string) []string { return nil }

func diagnose(Config) string { return "El diagnóstico solo está disponible en Windows." }
