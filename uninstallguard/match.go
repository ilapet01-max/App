package main

import (
	"os"
	"regexp"
	"strings"
)

var (
	pctRe  = regexp.MustCompile(`%([^%]+)%`)
	guidRe = regexp.MustCompile(`\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}`)
	msiRm  = regexp.MustCompile(`(^|\s)[/-](x|uninstall)|remove=`)
)

func norm(s string) string { return strings.ToLower(strings.ReplaceAll(s, "/", `\`)) }

func expand(s string) string {
	return pctRe.ReplaceAllStringFunc(s, func(m string) string {
		if v := os.Getenv(m[1 : len(m)-1]); v != "" {
			return v
		}
		return m
	})
}

// splitCmd separa «"C:\ruta\x.exe" args» o «C:\ruta\x.exe args» en (exe, args).
func splitCmd(s string) (exe, args string) {
	s = strings.TrimSpace(expand(s))
	if strings.HasPrefix(s, `"`) {
		if i := strings.Index(s[1:], `"`); i >= 0 {
			return s[1 : i+1], strings.TrimSpace(s[i+2:])
		}
		return strings.Trim(s, `"`), ""
	}
	if i := strings.Index(strings.ToLower(s), ".exe"); i >= 0 {
		return s[:i+4], strings.TrimSpace(s[i+4:])
	}
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i], strings.TrimSpace(s[i+1:])
	}
	return s, ""
}

func baseName(p string) string { return p[strings.LastIndex(p, `\`)+1:] }

// Matches: ¿este proceso recién arrancado (imagen + línea de comandos) es una desinstalación de it?
func (it Item) Matches(image, cmdline string) bool {
	img, cmd := norm(image), strings.ToLower(cmdline)
	if img == "" {
		return false
	}
	// 1) Exactamente su cadena de desinstalación (mismo ejecutable y mismos argumentos).
	for _, s := range []string{it.Uninstall, it.Quiet} {
		exe, args := splitCmd(s)
		if exe == "" || norm(exe) != img {
			continue
		}
		args = strings.ToLower(args)
		if args == "" {
			if strings.HasPrefix(img, norm(os.Getenv("SystemRoot"))+`\`) && os.Getenv("SystemRoot") != "" {
				continue // nunca matar herramientas de Windows sin argumentos que las distingan
			}
			return true
		}
		ok := true
		for _, tok := range strings.Fields(args) {
			if !strings.Contains(cmd, tok) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	// 2) Paquete MSI: msiexec con el GUID del producto y orden de quitar.
	if strings.HasSuffix(img, `\msiexec.exe`) {
		for _, g := range guidRe.FindAllString(it.Key+" "+it.Uninstall+" "+it.Quiet, -1) {
			if strings.Contains(cmd, strings.ToLower(g)) && msiRm.MatchString(cmd) {
				return true
			}
		}
	}
	// 3) Desinstalador dentro de su carpeta (unins000.exe, uninstall.exe…) o la 2.ª fase de Inno Setup.
	if d := norm(strings.TrimRight(it.Dir, `\/`)); len(d) > 6 {
		if strings.HasPrefix(img, d+`\`) {
			n := baseName(img)
			if strings.HasPrefix(n, "unins") || strings.HasPrefix(n, "uninstall") {
				return true
			}
		}
		if strings.Contains(cmd, "/secondphase") && strings.Contains(norm(cmdline), d+`\`) {
			return true
		}
	}
	return false
}
