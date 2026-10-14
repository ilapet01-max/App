#!/bin/sh
# Compila webguard.exe para Windows (aplicación sin consola, pide administrador)
GOOS=windows GOARCH=amd64 go build -ldflags="-H=windowsgui -s -w" -o webguard.exe .
