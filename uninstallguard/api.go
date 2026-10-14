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
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/index.html
var webFS embed.FS

const (
	tokenTTL    = 10 * time.Minute
	maxFails    = 5
	lockoutTime = time.Minute
)

// Program es una entrada de "Aplicaciones instaladas".
type Program struct {
	Name      string `json:"name"`
	Key       string `json:"key"`
	Uninstall string `json:"uninstall"`
	Quiet     string `json:"quiet"`
	Dir       string `json:"dir"`
	Version   string `json:"version"`
}

type API struct {
	store *Store
	dir   string

	mu     sync.Mutex
	tokens map[string]time.Time
	fails  int
	locked time.Time
}

func NewAPI(store *Store, dir string) *API {
	return &API{store: store, dir: dir, tokens: map[string]time.Time{}}
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
	mux.HandleFunc("GET /api/programs", a.programs)
	mux.HandleFunc("POST /api/setup", a.setup)
	mux.HandleFunc("POST /api/unlock", a.unlock)
	mux.HandleFunc("POST /api/lock", a.lock)
	mux.HandleFunc("POST /api/protect", a.protect)
	mux.HandleFunc("POST /api/unprotect", a.unprotect)
	mux.HandleFunc("POST /api/strong", a.strong)
	mux.HandleFunc("POST /api/protection", a.protection)
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

func (a *API) newToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	t := hex.EncodeToString(b)
	a.mu.Lock()
	a.tokens[t] = time.Now().Add(tokenTTL)
	a.mu.Unlock()
	return t
}

// El servicio escribe heartbeat.txt (unix) cada ciclo.
func (a *API) daemonAlive() bool {
	b, err := os.ReadFile(filepath.Join(a.dir, "heartbeat.txt"))
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return err == nil && time.Since(time.Unix(n, 0)) < 30*time.Second
}

type recent struct {
	Time string `json:"time"`
	Name string `json:"name"`
	What string `json:"what"`
}

func (a *API) recentBlocks() []recent {
	out := []recent{}
	b, err := os.ReadFile(filepath.Join(a.dir, "blocked.log"))
	if err != nil {
		return out
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	for i := len(lines) - 1; i >= 0 && len(out) < 30; i-- {
		if f := strings.Split(lines[i], "\t"); len(f) == 3 {
			out = append(out, recent{f[0], f[1], f[2]})
		}
	}
	return out
}

func (a *API) state(w http.ResponseWriter, r *http.Request) {
	c := a.store.Get()
	items := c.Items
	if items == nil {
		items = []Item{}
	}
	writeJSON(w, 200, map[string]any{
		"setup_needed": c.Password == nil, "enabled": c.Enabled, "daemon": a.daemonAlive(),
		"unlocked": a.valid(r), "items": items, "recent": a.recentBlocks(),
	})
}

func (a *API) programs(w http.ResponseWriter, r *http.Request) {
	list, err := listPrograms()
	if err != nil {
		fail(w, 500, "No se pudo leer la lista de programas: "+err.Error())
		return
	}
	if list == nil {
		list = []Program{}
	}
	writeJSON(w, 200, list)
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

// Proteger un programa refuerza → libre.
func (a *API) protect(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Key    string
		Strong bool
	}
	if !readBody(r, &b) {
		fail(w, 400, "Solicitud no válida.")
		return
	}
	c := a.store.Get()
	if c.Password == nil {
		fail(w, 400, "Define primero la contraseña.")
		return
	}
	if _, ok := c.Find(b.Key); ok {
		fail(w, 409, "Ya está protegido.")
		return
	}
	list, err := listPrograms()
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	var p *Program
	for i := range list {
		if list[i].Key == b.Key {
			p = &list[i]
		}
	}
	if p == nil {
		fail(w, 404, "Programa no encontrado.")
		return
	}
	it := Item{Name: p.Name, Key: p.Key, Uninstall: p.Uninstall, Quiet: p.Quiet, Dir: p.Dir, Strong: b.Strong}
	if b.Strong {
		if err := checkStrongDir(it.Dir); err != nil {
			fail(w, 400, err.Error())
			return
		}
	}
	if c.Enabled {
		it.HadLock = applyItem(it, false)
	}
	a.store.Update(func(c *Config) { c.Items = append(c.Items, it) })
	writeJSON(w, 200, map[string]string{"name": it.Name})
}

// Dejar de proteger debilita → contraseña.
func (a *API) unprotect(w http.ResponseWriter, r *http.Request) {
	var b struct{ Key string }
	if !readBody(r, &b) {
		fail(w, 400, "Solicitud no válida.")
		return
	}
	if !a.valid(r) {
		fail(w, 401, "Desbloquea con la contraseña para dejar de proteger.")
		return
	}
	c := a.store.Get()
	it, ok := c.Find(b.Key)
	if !ok {
		fail(w, 404, "No está en la lista.")
		return
	}
	releaseItem(it)
	a.store.Update(func(c *Config) {
		out := c.Items[:0]
		for _, x := range c.Items {
			if x.Key != b.Key {
				out = append(out, x)
			}
		}
		c.Items = out
	})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// Activar la protección reforzada refuerza → libre; quitarla → contraseña.
func (a *API) strong(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Key string
		On  bool
	}
	if !readBody(r, &b) {
		fail(w, 400, "Solicitud no válida.")
		return
	}
	if !b.On && !a.valid(r) {
		fail(w, 401, "Desbloquea con la contraseña para quitar la protección reforzada.")
		return
	}
	c := a.store.Get()
	it, ok := c.Find(b.Key)
	if !ok {
		fail(w, 404, "No está en la lista.")
		return
	}
	if b.On {
		if err := checkStrongDir(it.Dir); err != nil {
			fail(w, 400, err.Error())
			return
		}
		it.Strong = true
		if c.Enabled {
			applyItem(it, true)
		}
	} else {
		releaseStrong(it)
		it.Strong = false
	}
	a.store.Update(func(c *Config) {
		for i := range c.Items {
			if c.Items[i].Key == b.Key {
				c.Items[i].Strong = it.Strong
			}
		}
	})
	writeJSON(w, 200, map[string]bool{"strong": it.Strong})
}

func (a *API) protection(w http.ResponseWriter, r *http.Request) {
	var b struct{ On bool }
	if !readBody(r, &b) {
		fail(w, 400, "Solicitud no válida.")
		return
	}
	c := a.store.Get()
	if c.Password == nil {
		fail(w, 400, "Define primero la contraseña.")
		return
	}
	if !b.On {
		if !a.valid(r) {
			fail(w, 401, "Desbloquea con la contraseña para desactivar la protección.")
			return
		}
		if err := disableService(c.Items); err != nil {
			fail(w, 500, err.Error())
			return
		}
	} else {
		items := append([]Item{}, c.Items...)
		if err := enableService(items); err != nil {
			fail(w, 500, err.Error())
			return
		}
		a.store.Update(func(c *Config) { c.Items = items })
	}
	a.store.Update(func(c *Config) { c.Enabled = b.On })
	writeJSON(w, 200, map[string]bool{"enabled": b.On})
}
