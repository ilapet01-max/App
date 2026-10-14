package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

const uiAddr = "127.0.0.1:47653"

func main() {
	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	if cmd == "run" {
		runDaemon(os.Args[2:])
		return
	}
	runUI(os.Args[min(len(os.Args), 2):], cmd == "ui")
}

func runUI(args []string, explicit bool) {
	fs := flag.NewFlagSet("ui", flag.ExitOnError)
	addr := fs.String("addr", uiAddr, "dirección de la interfaz")
	dnsAddr := fs.String("dns", "127.0.0.1:53", "dirección del demonio (indicador de estado)")
	noBrowser := fs.Bool("nobrowser", false, "no abrir el navegador")
	fs.Parse(args)
	dir := dataDir()
	os.MkdirAll(dir, 0o700)
	l, err := net.Listen("tcp", *addr)
	if err != nil { // ya hay una ventana abierta: solo la mostramos
		openBrowser("http://" + *addr)
		return
	}
	hardenDir(dir)
	api := NewAPI(NewStore(dir), dir, *dnsAddr)
	if !*noBrowser {
		openBrowser("http://" + *addr)
	}
	_ = explicit
	srv := &http.Server{Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second}
	srv.Serve(l)
}

func runDaemon(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	dnsAddr := fs.String("dns", "127.0.0.1:53", "dirección DNS IPv4")
	dns6 := fs.String("dns6", "[::1]:53", "dirección DNS IPv6 (vacío para omitir)")
	httpAddrs := fs.String("page", "127.0.0.1:80", "página de bloqueo (vacío para omitir)")
	fs.Parse(args)
	dir := dataDir()
	os.MkdirAll(dir, 0o700)
	d := NewDaemon(NewStore(dir), dir)
	d.SetUpstreams(loadUpstreams(dir))
	for _, a := range []string{*dnsAddr, *dns6} {
		if a == "" {
			continue
		}
		if err := d.ServeUDP(a); err != nil && a == *dnsAddr {
			fmt.Fprintln(os.Stderr, "no se pudo abrir el puerto DNS:", err)
			os.Exit(1)
		}
		d.ServeTCP(a)
	}
	if *httpAddrs != "" {
		ServeBlockPage(*httpAddrs)
		ServeBlockPage("[::1]:80")
	}
	for {
		watchdog(d, dir)
		time.Sleep(45 * time.Second)
	}
}
