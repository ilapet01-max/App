#!/bin/sh
# Compila applock.exe (desde Linux/macOS/Windows con Go instalado)
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o applock.exe .
