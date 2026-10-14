package main

import (
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDecide(t *testing.T) {
	c := Config{Domains: []string{"bad.com"}, Keywords: []string{"casino"}, Allow: []string{"casinoroyale.edu"}}
	cases := map[string]bool{
		"bad.com": true, "www.bad.com": true, "notbad.com": false, "my-casino-x.net": true,
		"casinoroyale.edu": false, "a.casinoroyale.edu": false, "example.org": false,
		"dns.google": true, "use-application-dns.net": true,
	}
	for n, want := range cases {
		if got := c.Decide(n).Block; got != want {
			t.Errorf("%s: got %v want %v", n, got, want)
		}
	}
	if !c.Decide("use-application-dns.net").NXDomain {
		t.Error("canary debe ser NXDOMAIN")
	}
}

func TestNorm(t *testing.T) {
	for in, want := range map[string]string{"https://WWW.Ejemplo.com/ruta?x=1": "ejemplo.com", "bar.example.org:8080": "bar.example.org", "bücher.de": "xn--bcher-kva.de"} {
		if got, ok := normDomain(in); !ok || got != want {
			t.Errorf("%q → %q,%v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "localhost", "a b.com", "http://", "x..com"} {
		if _, ok := normDomain(bad); ok {
			t.Errorf("%q no debería ser válido", bad)
		}
	}
	if _, ok := normKeyword("ab"); ok {
		t.Error("keyword corta")
	}
}

func query(t *testing.T, d *Daemon, name string, typ dnsmessage.Type) dnsmessage.Message {
	n, _ := dnsmessage.NewName(name + ".")
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 7, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: n, Type: typ, Class: dnsmessage.ClassINET}}}
	pkt, _ := m.Pack()
	var out dnsmessage.Message
	r := d.Handle(pkt, false)
	if r == nil || out.Unpack(r) != nil {
		t.Fatalf("sin respuesta para %s", name)
	}
	return out
}

// upstream falso: responde 1.2.3.4 a cualquier A.
func fakeUpstream(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var m dnsmessage.Message
			if m.Unpack(buf[:n]) != nil {
				continue
			}
			q := m.Questions[0]
			r := dnsmessage.Message{Header: dnsmessage.Header{ID: m.ID, Response: true, RecursionAvailable: true}, Questions: m.Questions}
			if q.Type == dnsmessage.TypeA {
				r.Answers = []dnsmessage.Resource{rrA(q.Name, [4]byte{1, 2, 3, 4})}
			}
			b, _ := r.Pack()
			pc.WriteTo(b, from)
		}
	}()
	return pc.LocalAddr().String()
}

func newTestDaemon(t *testing.T, c Config) *Daemon {
	dir := t.TempDir()
	st := NewStore(dir)
	st.Update(func(x *Config) { *x = c })
	d := NewDaemon(st, dir)
	d.SetUpstreams([]string{fakeUpstream(t)})
	d.timeout = 500 * time.Millisecond
	return d
}

func TestDaemon(t *testing.T) {
	d := newTestDaemon(t, Config{Domains: []string{"bad.com"}, Keywords: []string{"casino"}, SafeSearch: true})
	if r := query(t, d, "www.bad.com", dnsmessage.TypeA); len(r.Answers) != 1 || r.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{127, 0, 0, 1} {
		t.Errorf("bloqueo A: %+v", r.Answers)
	}
	if r := query(t, d, "bad.com", dnsmessage.TypeAAAA); len(r.Answers) != 1 {
		t.Error("bloqueo AAAA")
	}
	if r := query(t, d, "bad.com", typeHTTPS); len(r.Answers) != 0 || r.RCode != dnsmessage.RCodeSuccess {
		t.Error("HTTPS debe ir vacío")
	}
	if r := query(t, d, "grancasino.es", dnsmessage.TypeA); r.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{127, 0, 0, 1} {
		t.Error("keyword")
	}
	if r := query(t, d, "use-application-dns.net", dnsmessage.TypeA); r.RCode != dnsmessage.RCodeNameError {
		t.Error("canary")
	}
	if r := query(t, d, "ok.example.org", dnsmessage.TypeA); len(r.Answers) != 1 || r.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{1, 2, 3, 4} {
		t.Errorf("reenvío: %+v", r.Answers)
	}
	// SafeSearch: el upstream falso responde 1.2.3.4 para forcesafesearch.google.com; el nombre debe conservarse.
	r := query(t, d, "www.google.es", dnsmessage.TypeA)
	if len(r.Answers) != 1 || r.Answers[0].Header.Name.String() != "www.google.es." || r.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{1, 2, 3, 4} {
		t.Errorf("safesearch: %+v", r.Answers)
	}
	if r := query(t, d, "www.youtube.com", typeHTTPS); len(r.Answers) != 0 {
		t.Error("safesearch HTTPS")
	}
	if r := query(t, d, probeName, dnsmessage.TypeA); len(r.Answers) != 1 {
		t.Error("probe")
	}
}

func TestAPIFlow(t *testing.T) {
	dir := t.TempDir()
	a := NewAPI(NewStore(dir), dir, "127.0.0.1:1")
	h := a.Handler()
	do := func(method, path, body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Host = "127.0.0.1:47653"
		r.Header.Set("X-WG", "1")
		r.Header.Set("X-Token", token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := do("POST", "/api/add", `{"List":"domains","Value":"x.com"}`, ""); w.Code != 200 {
		t.Fatalf("add: %d", w.Code)
	}
	if w := do("POST", "/api/remove", `{"List":"domains","Value":"x.com"}`, ""); w.Code != 401 {
		t.Fatalf("quitar sin token debe ser 401, fue %d", w.Code)
	}
	if w := do("POST", "/api/add", `{"List":"allow","Value":"y.com"}`, ""); w.Code != 401 {
		t.Fatalf("excepción sin token: %d", w.Code)
	}
	w := do("POST", "/api/setup", `{"Password":"corta"}`, "")
	if w.Code != 400 {
		t.Fatalf("contraseña corta: %d", w.Code)
	}
	w = do("POST", "/api/setup", `{"Password":"supersecreta"}`, "")
	if w.Code != 200 {
		t.Fatalf("setup: %d %s", w.Code, w.Body)
	}
	if w := do("POST", "/api/unlock", `{"Password":"mala"}`, ""); w.Code != 401 {
		t.Fatal("unlock mala")
	}
	w = do("POST", "/api/unlock", `{"Password":"supersecreta"}`, "")
	tok := strings.Split(w.Body.String(), `"`)[3]
	if w := do("POST", "/api/remove", `{"List":"domains","Value":"x.com"}`, tok); w.Code != 200 {
		t.Fatalf("quitar con token: %d", w.Code)
	}
	if w := do("GET", "/api/state", "", tok); !strings.Contains(w.Body.String(), `"unlocked":true`) {
		t.Fatal(w.Body.String())
	}
	// protecciones del servidor local
	r := httptest.NewRequest("POST", "/api/add", strings.NewReader(`{}`))
	r.Host = "evil.com:47653"
	r.Header.Set("X-WG", "1")
	ww := httptest.NewRecorder()
	h.ServeHTTP(ww, r)
	if ww.Code != 403 {
		t.Error("rebinding")
	}
	r = httptest.NewRequest("POST", "/api/add", strings.NewReader(`{}`))
	r.Host = "127.0.0.1:47653"
	ww = httptest.NewRecorder()
	h.ServeHTTP(ww, r)
	if ww.Code != 403 {
		t.Error("csrf")
	}
}
