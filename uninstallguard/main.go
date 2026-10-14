package main

import (
	"flag"
	"net"
	"net/http"
	"os"
	"time"
)

const uiAddr = "127.0.0.1:47654"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "run" {
		runDaemon()
		return
	}
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "ui" {
		args = args[1:]
	}
	fs := flag.NewFlagSet("ui", flag.ExitOnError)
	addr := fs.String("addr", uiAddr, "dirección de la interfaz")
	noBrowser := fs.Bool("nobrowser", false, "no abrir el navegador")
	fs.Parse(args)
	dir := dataDir()
	os.MkdirAll(dir, 0o700)
	l, err := net.Listen("tcp", *addr)
	if err != nil { // ya hay un panel abierto: solo lo mostramos
		openBrowser("http://" + *addr)
		return
	}
	hardenDir(dir)
	if !*noBrowser {
		openBrowser("http://" + *addr)
	}
	srv := &http.Server{Handler: NewAPI(NewStore(dir), dir).Handler(), ReadHeaderTimeout: 5 * time.Second}
	srv.Serve(l)
}
