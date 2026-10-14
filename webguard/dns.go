package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const probeName = "wg-probe.invalid"

const (
	typeSVCB  dnsmessage.Type = 64
	typeHTTPS dnsmessage.Type = 65
)

var fallbackUpstreams = []string{"1.1.1.1:53", "9.9.9.9:53", "8.8.8.8:53"}

// Daemon es el servidor DNS filtrante (corre como SYSTEM en 127.0.0.1:53).
type Daemon struct {
	store *Store
	dir   string

	mu        sync.Mutex
	upstreams []string
	lastLog   map[string]time.Time
	timeout   time.Duration
}

func NewDaemon(store *Store, dir string) *Daemon {
	return &Daemon{store: store, dir: dir, lastLog: map[string]time.Time{}, timeout: 1500 * time.Millisecond}
}

func (d *Daemon) SetUpstreams(u []string) { d.mu.Lock(); d.upstreams = u; d.mu.Unlock() }

func (d *Daemon) ups() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append(append([]string{}, d.upstreams...), fallbackUpstreams...)
}

// ---- reenvío ----

func (d *Daemon) forward(pkt []byte, tcp bool) []byte {
	for _, up := range d.ups() {
		var r []byte
		if tcp {
			r = d.exchangeTCP(up, pkt)
		} else {
			r = d.exchangeUDP(up, pkt)
		}
		if r != nil {
			return r
		}
	}
	return nil
}

func (d *Daemon) exchangeUDP(up string, pkt []byte) []byte {
	c, err := net.DialTimeout("udp", up, d.timeout)
	if err != nil {
		return nil
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(d.timeout))
	if _, err := c.Write(pkt); err != nil {
		return nil
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

func (d *Daemon) exchangeTCP(up string, pkt []byte) []byte {
	c, err := net.DialTimeout("tcp", up, d.timeout)
	if err != nil {
		return nil
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	hdr := make([]byte, 2, 2+len(pkt))
	binary.BigEndian.PutUint16(hdr, uint16(len(pkt)))
	if _, err := c.Write(append(hdr, pkt...)); err != nil {
		return nil
	}
	return readTCPMsg(c)
}

func readTCPMsg(c net.Conn) []byte {
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil
	}
	b := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(c, b); err != nil {
		return nil
	}
	return b
}

// ---- respuestas ----

func reply(id uint16, rd bool, q dnsmessage.Question, rcode dnsmessage.RCode, ans ...dnsmessage.Resource) []byte {
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, Response: true, RecursionDesired: rd, RecursionAvailable: true, RCode: rcode},
		Questions: []dnsmessage.Question{q}, Answers: ans,
	}
	b, _ := m.Pack()
	return b
}

func rrA(n dnsmessage.Name, ip [4]byte) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: ip}}
}

func rrAAAA(n dnsmessage.Name, ip [16]byte) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AAAAResource{AAAA: ip}}
}

// ---- SafeSearch ----

var googleRe = regexp.MustCompile(`^(www\.)?google\.(com|co\.[a-z]{2}|com\.[a-z]{2}|[a-z]{2})$`)

func safeTarget(name string) string {
	switch {
	case googleRe.MatchString(name):
		return "forcesafesearch.google.com"
	case name == "bing.com" || name == "www.bing.com":
		return "strict.bing.com"
	case name == "duckduckgo.com" || name == "www.duckduckgo.com":
		return "safe.duckduckgo.com"
	case name == "www.youtube.com" || name == "m.youtube.com" || name == "youtubei.googleapis.com" ||
		name == "youtube.googleapis.com" || name == "www.youtube-nocookie.com":
		return "restrict.youtube.com"
	}
	return ""
}

func (d *Daemon) safeSearch(id uint16, rd bool, q dnsmessage.Question, target string) []byte {
	tn, _ := dnsmessage.NewName(target + ".")
	var rid [2]byte
	rand.Read(rid[:])
	qm := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: binary.BigEndian.Uint16(rid[:]), RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: tn, Type: q.Type, Class: dnsmessage.ClassINET}},
	}
	raw, _ := qm.Pack()
	resp := d.forward(raw, false)
	var m dnsmessage.Message
	if resp == nil || m.Unpack(resp) != nil {
		return nil
	}
	var out []dnsmessage.Resource
	for _, a := range m.Answers {
		if a.Header.Type == dnsmessage.TypeA || a.Header.Type == dnsmessage.TypeAAAA {
			a.Header.Name = q.Name
			if a.Header.TTL > 300 {
				a.Header.TTL = 300
			}
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return reply(id, rd, q, dnsmessage.RCodeSuccess, out...)
}

// ---- núcleo ----

func (d *Daemon) Handle(pkt []byte, tcp bool) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(pkt)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return d.forward(pkt, tcp)
	}
	name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
	if name == probeName {
		return reply(h.ID, h.RecursionDesired, q, dnsmessage.RCodeSuccess, rrA(q.Name, [4]byte{127, 0, 0, 1}))
	}
	cfg := d.store.Get()
	if dec := cfg.Decide(name); dec.Block {
		d.logBlock(name, dec.Reason)
		if dec.NXDomain {
			return reply(h.ID, h.RecursionDesired, q, dnsmessage.RCodeNameError)
		}
		switch q.Type {
		case dnsmessage.TypeA:
			return reply(h.ID, h.RecursionDesired, q, dnsmessage.RCodeSuccess, rrA(q.Name, [4]byte{127, 0, 0, 1}))
		case dnsmessage.TypeAAAA:
			return reply(h.ID, h.RecursionDesired, q, dnsmessage.RCodeSuccess, rrAAAA(q.Name, [16]byte{15: 1}))
		}
		return reply(h.ID, h.RecursionDesired, q, dnsmessage.RCodeSuccess) // HTTPS/SVCB/etc.: vacío
	}
	if cfg.SafeSearch {
		if t := safeTarget(name); t != "" {
			switch q.Type {
			case dnsmessage.TypeA, dnsmessage.TypeAAAA:
				if r := d.safeSearch(h.ID, h.RecursionDesired, q, t); r != nil {
					return r
				}
			case typeSVCB, typeHTTPS: // evita pistas de IP que se saltan SafeSearch
				return reply(h.ID, h.RecursionDesired, q, dnsmessage.RCodeSuccess)
			}
		}
	}
	if r := d.forward(pkt, tcp); r != nil {
		return r
	}
	return reply(h.ID, h.RecursionDesired, q, dnsmessage.RCodeServerFailure)
}

func (d *Daemon) logBlock(host, reason string) {
	d.mu.Lock()
	if time.Since(d.lastLog[host]) < 10*time.Second {
		d.mu.Unlock()
		return
	}
	d.lastLog[host] = time.Now()
	if len(d.lastLog) > 2000 {
		d.lastLog = map[string]time.Time{host: time.Now()}
	}
	d.mu.Unlock()
	path := filepath.Join(d.dir, "blocked.log")
	if fi, err := os.Stat(path); err == nil && fi.Size() > 1<<20 {
		os.Rename(path, path+".old")
	}
	if f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
		fmt.Fprintf(f, "%s\t%s\t%s\n", time.Now().Format(time.RFC3339), host, reason)
		f.Close()
	}
}

// ---- servidores ----

func (d *Daemon) ServeUDP(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			go func() {
				if r := d.Handle(pkt, false); r != nil {
					pc.WriteTo(r, from)
				}
			}()
		}
	}()
	return nil
}

func (d *Daemon) ServeTCP(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					c.SetDeadline(time.Now().Add(10 * time.Second))
					pkt := readTCPMsg(c)
					if pkt == nil {
						return
					}
					r := d.Handle(pkt, true)
					if r == nil {
						return
					}
					out := make([]byte, 2, 2+len(r))
					binary.BigEndian.PutUint16(out, uint16(len(r)))
					if _, err := c.Write(append(out, r...)); err != nil {
						return
					}
				}
			}()
		}
	}()
	return nil
}

const blockedPage = `<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bloqueado</title><style>
:root{color-scheme:light dark}body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px system-ui,Segoe UI,sans-serif;background:#0f172a;color:#e2e8f0}
main{max-width:30rem;padding:2rem;text-align:center}.i{width:72px;height:72px;margin:0 auto 1rem;border-radius:20px;background:linear-gradient(135deg,#6366f1,#8b5cf6);display:grid;place-items:center}
h1{margin:.2rem 0;font-size:1.6rem}p{color:#94a3b8;line-height:1.5}code{background:#1e293b;padding:.15rem .5rem;border-radius:6px;color:#e2e8f0}
</style><main><div class="i"><svg width="38" height="38" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg></div>
<h1>Página bloqueada</h1><p><code>%s</code> está bloqueada por WebGuard.</p><p>Respira un momento: ya lo decidiste antes por una buena razón.</p></main></html>`

func ServeBlockPage(addr string) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusForbidden)
		host := r.Host
		if hh, _, err := net.SplitHostPort(host); err == nil {
			host = hh
		}
		fmt.Fprintf(w, blockedPage, html.EscapeString(host))
	})
	if l, err := net.Listen("tcp", addr); err == nil {
		go http.Serve(l, h)
	}
}
