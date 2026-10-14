package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPIFlow(t *testing.T) {
	dir := t.TempDir()
	a := NewAPI(NewStore(dir), dir)
	h := a.Handler()
	do := func(method, path, body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Host = "127.0.0.1:47654"
		r.Header.Set("X-WG", "1")
		r.Header.Set("X-Token", token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	progs, _ := listPrograms()
	kb, _ := json.Marshal(progs[0].Key)
	key := string(kb[1 : len(kb)-1]) // clave ya escapada para JSON
	if w := do("POST", "/api/protect", `{"Key":"`+key+`"}`, ""); w.Code != 400 {
		t.Fatalf("sin contraseña definida: %d", w.Code)
	}
	if w := do("POST", "/api/setup", `{"Password":"supersecreta"}`, ""); w.Code != 200 {
		t.Fatal("setup")
	}
	if w := do("POST", "/api/protect", `{"Key":"`+key+`"}`, ""); w.Code != 200 {
		t.Fatalf("proteger: %d %s", w.Code, w.Body)
	}
	if w := do("POST", "/api/protect", `{"Key":"`+key+`"}`, ""); w.Code != 409 {
		t.Fatal("duplicado")
	}
	if w := do("POST", "/api/unprotect", `{"Key":"`+key+`"}`, ""); w.Code != 401 {
		t.Fatalf("quitar sin token: %d", w.Code)
	}
	if w := do("POST", "/api/strong", `{"Key":"`+key+`","On":false}`, ""); w.Code != 401 {
		t.Fatal("quitar reforzada sin token")
	}
	if w := do("POST", "/api/protection", `{"On":false}`, ""); w.Code != 401 {
		t.Fatal("desactivar sin token")
	}
	w := do("POST", "/api/unlock", `{"Password":"supersecreta"}`, "")
	tok := strings.Split(w.Body.String(), `"`)[3]
	if w := do("POST", "/api/unprotect", `{"Key":"`+key+`"}`, tok); w.Code != 200 {
		t.Fatalf("quitar con token: %d", w.Code)
	}
	if w := do("GET", "/api/state", "", tok); !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatal(w.Body.String())
	}
}
