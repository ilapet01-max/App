package main

import "testing"

func TestVerify(t *testing.T) {
	r := newRec("secreto123")
	if !r.verify("secreto123") || r.verify("otra") {
		t.Fatal("verify")
	}
}

func TestPBKDF2Vector(t *testing.T) { // RFC 7914 §11 (PBKDF2-HMAC-SHA256, c=1, 32 bytes)
	got := pbkdf2([]byte("passwd"), []byte("salt"), 1)
	want := "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
	if h := hexs(got); h != want {
		t.Fatalf("%s != %s", h, want)
	}
}

func hexs(b []byte) string {
	const d = "0123456789abcdef"
	s := ""
	for _, x := range b {
		s += string(d[x>>4]) + string(d[x&15])
	}
	return s
}

func TestIsInstaller(t *testing.T) {
	ex := []string{`C:\Windows\`, `C:\Program Files\`}
	yes := []string{`C:\Users\a\Desktop\ChromeSetup.exe`, `C:\Users\a\Downloads\zoom.exe`,
		`C:\Users\a\AppData\Local\Temp\is-AB12.tmp\app.exe`, `C:\Users\a\x\Install-me.exe`}
	no := []string{`C:\Windows\System32\msiexec.exe`, `C:\Program Files\X\setup.exe`,
		`C:\Users\a\x\unins000.exe`, `C:\Users\a\x\notepad.exe`, `C:\Users\a\x\data.txt`}
	for _, p := range yes {
		if !isInstaller(p, ex) {
			t.Error("debería bloquear", p)
		}
	}
	for _, p := range no {
		if isInstaller(p, ex) {
			t.Error("no debería bloquear", p)
		}
	}
}
