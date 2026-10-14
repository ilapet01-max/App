package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

const iterations = 600000

// Rec es la contraseña guardada (PBKDF2-HMAC-SHA256 con sal aleatoria).
type Rec struct {
	Salt string `json:"salt"`
	Iter int    `json:"iter"`
	Hash string `json:"hash"`
}

// State es el estado compartido entre los comandos y el vigilante.
type State struct {
	AllowUntil int64 `json:"allow_until"` // unix; mientras no pase, se permite instalar
}

func pbkdf2(pw, salt []byte, iter int) []byte {
	mac := hmac.New(sha256.New, pw)
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	u := mac.Sum(nil)
	t := append([]byte(nil), u...)
	for i := 1; i < iter; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(nil)
		for j := range t {
			t[j] ^= u[j]
		}
	}
	return t
}

func newRec(pw string) Rec {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	return Rec{hex.EncodeToString(salt), iterations, hex.EncodeToString(pbkdf2([]byte(pw), salt, iterations))}
}

func (r Rec) verify(pw string) bool {
	salt, err := hex.DecodeString(r.Salt)
	if err != nil || r.Iter < 1 {
		return false
	}
	got := hex.EncodeToString(pbkdf2([]byte(pw), salt, r.Iter))
	return subtle.ConstantTimeCompare([]byte(got), []byte(r.Hash)) == 1
}

// isInstaller decide si un proceso recién arrancado parece un instalador.
// path y exclude van en minúsculas; exclude son prefijos de carpetas del sistema.
func isInstaller(path string, exclude []string) bool {
	p := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	if !strings.HasSuffix(p, ".exe") {
		return false
	}
	for _, e := range exclude {
		if e != "" && strings.HasPrefix(p, strings.ToLower(e)) {
			return false
		}
	}
	name := p[strings.LastIndex(p, `\`)+1:]
	if name == "applock.exe" || name == "msiexec.exe" { // msiexec lo cubre la política DisableMSI
		return false
	}
	if strings.Contains(name, "unins") || strings.Contains(name, "uninstall") {
		return false
	}
	switch {
	case strings.Contains(name, "setup"), strings.Contains(name, "install"):
		return true
	case strings.Contains(p, `\downloads\`): // cualquier .exe lanzado desde Descargas
		return true
	case strings.Contains(p, `\temp\`) && strings.Contains(p, ".tmp"): // Inno Setup & cía.
		return true
	}
	return false
}
