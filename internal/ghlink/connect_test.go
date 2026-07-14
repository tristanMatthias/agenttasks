package ghlink

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func connector(bind func(int64, string) error, ws func(*http.Request) (string, bool)) *Connector {
	return &Connector{
		AppSlug: "agenttasks", StateSecret: []byte("state-secret"),
		Workspace: ws, Bind: bind,
	}
}

func TestConnectRedirectsToInstall(t *testing.T) {
	c := connector(nil, func(*http.Request) (string, bool) { return "ws_1", true })
	mux := http.NewServeMux()
	c.Register(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/integrations/github/connect", nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://github.com/apps/agenttasks/installations/new?state=") {
		t.Fatalf("bad install redirect: %s", loc)
	}
}

func TestConnectUnauthedGoesToLogin(t *testing.T) {
	c := connector(nil, func(*http.Request) (string, bool) { return "", false })
	c.LoginPath = "/auth/github/login"
	rec := httptest.NewRecorder()
	c.connect(rec, httptest.NewRequest("GET", "/integrations/github/connect", nil))
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "/auth/github/login") {
		t.Fatalf("expected login redirect, got %s", loc)
	}
}

func TestSetupBindsInstallationToWorkspace(t *testing.T) {
	var boundID int64
	var boundWS string
	c := connector(func(id int64, ws string) error { boundID, boundWS = id, ws; return nil },
		func(*http.Request) (string, bool) { return "ws_42", true })

	// Mint a real state via connect, then feed it to setup with an installation id.
	rec := httptest.NewRecorder()
	c.connect(rec, httptest.NewRequest("GET", "/integrations/github/connect", nil))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	state := loc.Query().Get("state")

	rec2 := httptest.NewRecorder()
	c.setup(rec2, httptest.NewRequest("GET", "/integrations/github/setup?installation_id=555&state="+url.QueryEscape(state), nil))
	if rec2.Code != http.StatusSeeOther {
		t.Fatalf("setup status %d", rec2.Code)
	}
	if boundID != 555 || boundWS != "ws_42" {
		t.Fatalf("bind = (%d, %q), want (555, ws_42)", boundID, boundWS)
	}
	if loc := rec2.Header().Get("Location"); !strings.Contains(loc, "github=connected") {
		t.Fatalf("expected success redirect, got %s", loc)
	}
}

func TestSetupRejectsForgedState(t *testing.T) {
	called := false
	c := connector(func(int64, string) error { called = true; return nil },
		func(*http.Request) (string, bool) { return "ws", true })
	rec := httptest.NewRecorder()
	c.setup(rec, httptest.NewRequest("GET", "/integrations/github/setup?installation_id=1&state=forged.deadbeef", nil))
	if called {
		t.Fatal("forged state must not bind an installation")
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "github=error") {
		t.Fatalf("expected error redirect, got %s", loc)
	}
}
