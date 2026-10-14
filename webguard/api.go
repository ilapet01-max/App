package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

//go:embed web/index.html
var webFS embed.FS

const (
	tokenTTL    = 10 * time.Minute
	maxFails    = 5
	lockoutTime = time.Minute
)

// API es la interfaz web local (solo escucha en 127.0.0.1).
type API struct {
	store   *Store
	dir     string
	dnsAddr string // dónde está el demonio, para el indicador de estado

	mu     sync.Mutex
	tokens map[string]time.Time
	fails  int
	locked time.Time
}

func NewAPI(store *Store, dir, dnsAddr string) *API {
	return &API{store: store, dir: dir, dnsAddr: dnsAddr, tokens: map[string]time.Time{}}
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		b, _ := webFS.ReadFile("web/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(b)
	})
	mux.HandleFunc("GET /api/state", a.state)
	mux.HandleFunc("POST /api/setup", a.setup)
	mux.HandleFunc("POST /api/unlock", a.unlock)
	mux.HandleFunc("POST /api/lock", a.lock)
	mux.HandleFunc("POST /api/add", a.add)
	mux.HandleFunc("POST /api/remove", a.removeItem)
	mux.HandleFunc("POST /api/protection", a.protection)
	mux.HandleFunc("POST /api/safesearch", a.safesearch)
	mux.HandleFunc("GET /api/diagnose", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"text": diagnose(a.store.Get())})
	})
	mux.HandleFunc("POST /api/quit", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]bool{"ok": true})
		go func() { time.Sleep(200 * time.Millisecond); os.Exit(0) }()
	})
	return a.guard(mux)
}

// guard frena DNS-rebinding (Host) y CSRF (cabecera propia que fuerza preflight CORS).
func (a *API) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil || (host != "127.0.0.1" && host != "localhost") {
			http.Error(w, "host no permitido", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost && r.Header.Get("X-WG") != "1" {
			http.Error(w, "falta cabecera", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readBody(r *http.Request, v any) bool {
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<16)).Decode(v) == nil
}

func (a *API) valid(r *http.Request) bool {
	t := r.Header.Get("X-Token")
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, exp := range a.tokens {
		if time.Now().After(exp) {
			delete(a.tokens, k)
		}
	}
	_, ok := a.tokens[t]
	return ok && t != ""
}

func probeDaemon(addr string) bool {
	n, _ := dnsmessage.NewName(probeName + ".")
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 0x5757, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	pkt, _ := m.Pack()
	c, err := net.DialTimeout("udp", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(800 * time.Millisecond))
	c.Write(pkt)
	buf := make([]byte, 512)
	nr, err := c.Read(buf)
	var resp dnsmessage.Message
	return err == nil && resp.Unpack(buf[:nr]) == nil && len(resp.Answers) == 1
}

type recent struct {
	Time   string `json:"time"`
	Host   string `json:"host"`
	Reason string `json:"reason"`
}

func (a *API) recentBlocks() []recent {
	b, err := os.ReadFile(filepath.Join(a.dir, "blocked.log"))
	out := []recent{}
	if err != nil {
		return out
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	for i := len(lines) - 1; i >= 0 && len(out) < 30; i-- {
		f := strings.Split(lines[i], "\t")
		if len(f) == 3 {
			out = append(out, recent{f[0], f[1], f[2]})
		}
	}
	return out
}

func (a *API) state(w http.ResponseWriter, r *http.Request) {
	c := a.store.Get()
	nn := func(l []string) []string {
		if l == nil {
			return []string{}
		}
		return l
	}
	writeJSON(w, 200, map[string]any{
		"setup_needed": c.Password == nil, "enabled": c.Enabled, "safesearch": c.SafeSearch,
		"daemon": probeDaemon(a.dnsAddr), "unlocked": a.valid(r),
		"domains": nn(c.Domains), "keywords": nn(c.Keywords), "allow": nn(c.Allow), "recent": a.recentBlocks(),
	})
}

func (a *API) setup(w http.ResponseWriter, r *http.Request) {
	var b struct{ Password string }
	if !readBody(r, &b) || len(b.Password) < 8 {
		fail(w, 400, "La contraseña debe tener al menos 8 caracteres.")
		return
	}
	if a.store.Get().Password != nil {
		fail(w, 409, "Ya hay una contraseña.")
		return
	}
	rec := newRec(b.Password)
	if err := a.store.Update(func(c *Config) { c.Password = &rec }); err != nil {
		fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"token": a.newToken()})
}

func (a *API) newToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	t := hex.EncodeToString(b)
	a.mu.Lock()
	a.tokens[t] = time.Now().Add(tokenTTL)
	a.mu.Unlock()
	return t
}

func (a *API) unlock(w http.ResponseWriter, r *http.Request) {
	var b struct{ Password string }
	c := a.store.Get()
	if !readBody(r, &b) || c.Password == nil {
		fail(w, 400, "Solicitud no válida.")
		return
	}
	a.mu.Lock()
	if time.Now().Before(a.locked) {
		a.mu.Unlock()
		fail(w, 429, "Demasiados intentos. Espera un minuto.")
		return
	}
	a.mu.Unlock()
	if !c.Password.verify(b.Password) {
		a.mu.Lock()
		if a.fails++; a.fails >= maxFails {
			a.fails, a.locked = 0, time.Now().Add(lockoutTime)
		}
		a.mu.Unlock()
		fail(w, 401, "Contraseña incorrecta.")
		return
	}
	a.mu.Lock()
	a.fails = 0
	a.mu.Unlock()
	writeJSON(w, 200, map[string]string{"token": a.newToken()})
}

func (a *API) lock(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	delete(a.tokens, r.Header.Get("X-Token"))
	a.mu.Unlock()
	writeJSON(w, 200, map[string]bool{"ok": true})
}

type listReq struct{ List, Value string }

// Añadir a "domains" o "keywords" endurece el filtro → libre. Añadir a "allow" lo debilita → contraseña.
func (a *API) add(w http.ResponseWriter, r *http.Request) {
	var b listReq
	if !readBody(r, &b) {
		fail(w, 400, "Solicitud no válida.")
		return
	}
	if b.List == "allow" && !a.valid(r) {
		fail(w, 401, "Desbloquea con la contraseña para añadir excepciones.")
		return
	}
	var v string
	var ok bool
	switch b.List {
	case "domains", "allow":
		v, ok = normDomain(b.Value)
	case "keywords":
		v, ok = normKeyword(b.Value)
	default:
		fail(w, 400, "Lista desconocida.")
		return
	}
	if !ok {
		fail(w, 400, map[string]string{"keywords": "Palabra clave: 3–40 caracteres (letras, números o guion).",
			"domains": "Dominio no válido (ej. ejemplo.com).", "allow": "Dominio no válido (ej. ejemplo.com)."}[b.List])
		return
	}
	a.store.Update(func(c *Config) {
		switch b.List {
		case "domains":
			if !contains(c.Domains, v) {
				c.Domains = append(c.Domains, v)
			}
		case "keywords":
			if !contains(c.Keywords, v) {
				c.Keywords = append(c.Keywords, v)
			}
		case "allow":
			if !contains(c.Allow, v) {
				c.Allow = append(c.Allow, v)
			}
		}
	})
	writeJSON(w, 200, map[string]string{"added": v})
}

// Quitar de "domains"/"keywords" debilita → contraseña. Quitar una excepción endurece → libre.
func (a *API) removeItem(w http.ResponseWriter, r *http.Request) {
	var b listReq
	if !readBody(r, &b) {
		fail(w, 400, "Solicitud no válida.")
		return
	}
	if b.List != "allow" && !a.valid(r) {
		fail(w, 401, "Desbloquea con la contraseña para quitar elementos.")
		return
	}
	a.store.Update(func(c *Config) {
		switch b.List {
		case "domains":
			c.Domains = remove(c.Domains, b.Value)
		case "keywords":
			c.Keywords = remove(c.Keywords, b.Value)
		case "allow":
			c.Allow = remove(c.Allow, b.Value)
		}
	})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *API) protection(w http.ResponseWriter, r *http.Request) {
	var b struct{ On bool }
	if !readBody(r, &b) {
		fail(w, 400, "Solicitud no válida.")
		return
	}
	if a.store.Get().Password == nil {
		fail(w, 400, "Define primero la contraseña.")
		return
	}
	if !b.On {
		if !a.valid(r) {
			fail(w, 401, "Desbloquea con la contraseña para desactivar la protección.")
			return
		}
		if err := disableProtection(); err != nil {
			fail(w, 500, err.Error())
			return
		}
	} else if err := enableProtection(); err != nil {
		fail(w, 500, err.Error())
		return
	}
	a.store.Update(func(c *Config) { c.Enabled = b.On })
	writeJSON(w, 200, map[string]bool{"enabled": b.On})
}

func (a *API) safesearch(w http.ResponseWriter, r *http.Request) {
	var b struct{ On bool }
	if !readBody(r, &b) {
		fail(w, 400, "Solicitud no válida.")
		return
	}
	if !b.On && !a.valid(r) {
		fail(w, 401, "Desbloquea con la contraseña para desactivar SafeSearch.")
		return
	}
	a.store.Update(func(c *Config) { c.SafeSearch = b.On })
	writeJSON(w, 200, map[string]bool{"safesearch": b.On})
}
