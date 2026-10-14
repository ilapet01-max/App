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
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
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

// Config es todo lo que se guarda en config.json.
type Config struct {
	Password   *Rec     `json:"password,omitempty"`
	Enabled    bool     `json:"enabled"`
	SafeSearch bool     `json:"safesearch"`
	Domains    []string `json:"domains"`
	Keywords   []string `json:"keywords"`
	Allow      []string `json:"allow"`
}

// dohHosts: resolutores DNS-sobre-HTTPS conocidos; se bloquean para que ningún navegador se salte el filtro.
var dohHosts = []string{
	"dns.google", "dns.google.com", "cloudflare-dns.com", "chrome.cloudflare-dns.com",
	"mozilla.cloudflare-dns.com", "dns.quad9.net", "dns9.quad9.net", "doh.opendns.com",
	"dns.nextdns.io", "doh.cleanbrowsing.org", "dns.adguard-dns.com", "doh.dns.sb",
}

const firefoxCanary = "use-application-dns.net"

// hostIn: name es d o un subdominio de d.
func hostIn(name, d string) bool { return name == d || strings.HasSuffix(name, "."+d) }

// Decision resultado de evaluar un nombre de host.
type Decision struct {
	Block    bool
	NXDomain bool
	Reason   string
}

func (c Config) Decide(name string) Decision {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == firefoxCanary {
		return Decision{true, true, "DoH"}
	}
	for _, h := range dohHosts {
		if hostIn(name, h) {
			return Decision{true, false, "DoH"}
		}
	}
	for _, a := range c.Allow {
		if hostIn(name, a) {
			return Decision{}
		}
	}
	for _, d := range c.Domains {
		if hostIn(name, d) {
			return Decision{true, false, "sitio " + d}
		}
	}
	for _, k := range c.Keywords {
		if strings.Contains(name, k) {
			return Decision{true, false, "palabra «" + k + "»"}
		}
	}
	return Decision{}
}

var (
	domainRe  = regexp.MustCompile(`^([a-z0-9-]+\.)+[a-z0-9-]{2,}$`)
	keywordRe = regexp.MustCompile(`^[a-z0-9-]{3,40}$`)
)

func normDomain(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimPrefix(strings.TrimSuffix(s, "."), "www.")
	if a, err := idna.Lookup.ToASCII(s); err == nil {
		s = a
	}
	return s, domainRe.MatchString(s) && len(s) <= 253
}

func normKeyword(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	return s, keywordRe.MatchString(s)
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func remove(l []string, v string) []string {
	out := make([]string, 0, len(l))
	for _, x := range l {
		if x != v {
			out = append(out, x)
		}
	}
	return out
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
	c.Domains, c.Keywords, c.Allow = append([]string{}, c.Domains...), append([]string{}, c.Keywords...), append([]string{}, c.Allow...)
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
