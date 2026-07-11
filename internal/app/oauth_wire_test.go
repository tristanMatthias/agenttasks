package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestOAuthWiring confirms the control plane exposes the OAuth discovery surface
// (public) and advertises resource_metadata on the gated 401 when PublicURL is set.
func TestOAuthWiring(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, jwksJSON(&priv.PublicKey))
	}))
	defer jwks.Close()

	a, err := New(context.Background(), Config{
		JWKSURL:   jwks.URL,
		DataDir:   t.TempDir(),
		PublicURL: "https://tasks.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ts := httptest.NewServer(a.Handler)
	defer ts.Close()

	// Discovery is public and points back at this issuer.
	if code, body := req(t, ts, "GET", "/.well-known/oauth-protected-resource", "", ""); code != 200 || !strings.Contains(body, "https://tasks.test/mcp") {
		t.Fatalf("PRM = %d %s", code, body)
	}
	if code, body := req(t, ts, "GET", "/.well-known/oauth-authorization-server", "", ""); code != 200 || !strings.Contains(body, "/oauth/token") {
		t.Fatalf("AS metadata = %d %s", code, body)
	}
	// DCR is reachable.
	if code, _ := req(t, ts, "POST", "/oauth/register", "", `{"redirect_uris":["https://claude.ai/cb"]}`); code != 201 {
		t.Fatalf("register = %d", code)
	}

	// The gated 401 advertises where to discover the AS (RFC 9728).
	rq, _ := http.NewRequest("GET", ts.URL+"/api/v1/ready", nil)
	resp, err := http.DefaultClient.Do(rq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("ready = %d", resp.StatusCode)
	}
	if wa := resp.Header.Get("WWW-Authenticate"); !strings.Contains(wa, `resource_metadata="https://tasks.test/.well-known/oauth-protected-resource"`) {
		t.Fatalf("WWW-Authenticate = %q", wa)
	}
}
