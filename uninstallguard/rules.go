package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const iterations = 600000

// Rec es la contraseña guardada (PBKDF2-HMAC-SHA256 con sal aleatoria).
type Rec struct {
	Salt string `json:"salt"`
	Iter int    `json:"iter"`
	Hash string `json:"hash"`
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

// Item es un programa protegido contra desinstalación.
type Item struct {
	Name      string `json:"name"`
	Key       string `json:"key"`       // clave del registro, p. ej. HKLM\SOFTWARE\...\Uninstall\{GUID}
	Uninstall string `json:"uninstall"` // UninstallString
	Quiet     string `json:"quiet,omitempty"`
	Dir       string `json:"dir,omitempty"`
	Strong    bool   `json:"strong"`             // además, deniega borrar archivos de la carpeta de instalación
	HadLock   bool   `json:"had_lock,omitempty"` // NoRemove ya existía antes de protegerlo
}

// Config es todo lo que se guarda en config.json.
type Config struct {
	Password *Rec   `json:"password,omitempty"`
	Enabled  bool   `json:"enabled"`
	Items    []Item `json:"items"`
}

func (c Config) Find(key string) (Item, bool) {
	for _, it := range c.Items {
		if it.Key == key {
			return it, true
		}
	}
	return Item{}, false
}

// Store guarda Config en disco; Get recarga si otro proceso (la interfaz o el servicio) lo cambió.
type Store struct {
	mu    sync.Mutex
	path  string
	cfg   Config
	mtime time.Time
}

func NewStore(dir string) *Store { return &Store{path: filepath.Join(dir, "config.json")} }

func (s *Store) reload() {
	fi, err := os.Stat(s.path)
	if err != nil || fi.ModTime().Equal(s.mtime) {
		return
	}
	var c Config
	if b, err := os.ReadFile(s.path); err == nil && json.Unmarshal(b, &c) == nil {
		s.cfg, s.mtime = c, fi.ModTime()
	}
}

func (s *Store) Get() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reload()
	return s.cfg
}

func (s *Store) Update(f func(*Config)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reload()
	c := s.cfg
	c.Items = append([]Item{}, c.Items...)
	f(&c)
	b, _ := json.MarshalIndent(c, "", "  ")
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	s.cfg = c
	if fi, err := os.Stat(s.path); err == nil {
		s.mtime = fi.ModTime()
	}
	return nil
}
