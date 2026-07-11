package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const kid = "test-key"

// jwksJSON renders an RSA public key as a JWKS document.
func jwksJSON(pub *rsa.PublicKey) string {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	return fmt.Sprintf(`{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":%q,"n":%q,"e":%q}]}`, kid, n, e)
}

// mint signs a session JWT for a user in an org.
func mint(t *testing.T, priv *rsa.PrivateKey, sub, org string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub": sub, "org_id": org,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func req(t *testing.T, ts *httptest.Server, method, path, jwt, body string) (int, string) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	rq, _ := http.NewRequest(method, ts.URL+path, r)
	if jwt != "" {
		rq.Header.Set("Authorization", "Bearer "+jwt)
	}
	if body != "" {
		rq.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(rq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestTenantIsolation is the core mode-3 guarantee: each org gets its own DB,
// authorized by a JWT the control plane verifies against a JWKS.
func TestTenantIsolation(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, jwksJSON(&priv.PublicKey))
	}))
	defer jwks.Close()

	a, err := New(context.Background(), Config{JWKSURL: jwks.URL, DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ts := httptest.NewServer(a.Handler)
	defer ts.Close()

	tokA := mint(t, priv, "user_1", "org_A")
	tokB := mint(t, priv, "user_2", "org_B")

	// No token -> gated.
	if code, _ := req(t, ts, "GET", "/api/v1/ready", "", ""); code != http.StatusUnauthorized {
		t.Fatalf("no token should be 401, got %d", code)
	}
	// Garbage token -> 401.
	if code, _ := req(t, ts, "GET", "/api/v1/ready", "not.a.jwt", ""); code != http.StatusUnauthorized {
		t.Fatalf("bad token should be 401, got %d", code)
	}

	// org A creates a task.
	code, body := req(t, ts, "POST", "/api/v1/tasks", tokA, `{"title":"A private task","priority":1}`)
	if code != http.StatusCreated {
		t.Fatalf("orgA create = %d %s", code, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal([]byte(body), &created)

	// org A sees exactly its task.
	code, body = req(t, ts, "GET", "/api/v1/ready?limit=50", tokA, "")
	if code != 200 || !strings.Contains(body, created.ID) || !strings.Contains(body, "A private task") {
		t.Fatalf("orgA should see its task: %d %s", code, body)
	}

	// org B sees NOTHING (isolated DB).
	code, body = req(t, ts, "GET", "/api/v1/ready?limit=50", tokB, "")
	if code != 200 {
		t.Fatalf("orgB ready = %d", code)
	}
	if strings.Contains(body, created.ID) || strings.Contains(body, "A private task") {
		t.Fatalf("TENANT LEAK: orgB saw orgA's data: %s", body)
	}
	// org B's board is empty.
	var listB []any
	json.Unmarshal([]byte(body), &listB)
	if len(listB) != 0 {
		t.Fatalf("orgB should start empty, got %d", len(listB))
	}

	// org B creates its own, still can't see A's.
	req(t, ts, "POST", "/api/v1/tasks", tokB, `{"title":"B private task"}`)
	_, body = req(t, ts, "GET", "/api/v1/ready?limit=50", tokB, "")
	if strings.Contains(body, "A private task") {
		t.Fatalf("TENANT LEAK after B create: %s", body)
	}
	if !strings.Contains(body, "B private task") {
		t.Fatalf("orgB should see its own task: %s", body)
	}

	// org A unaffected by B.
	_, body = req(t, ts, "GET", "/api/v1/ready?limit=50", tokA, "")
	if strings.Contains(body, "B private task") || !strings.Contains(body, "A private task") {
		t.Fatalf("orgA view wrong: %s", body)
	}
}

// TestPublicUIStillWorks confirms the embedded tasks UI is served (public).
func TestPublicUIStillWorks(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, jwksJSON(&priv.PublicKey))
	}))
	defer jwks.Close()
	a, err := New(context.Background(), Config{JWKSURL: jwks.URL, DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ts := httptest.NewServer(a.Handler)
	defer ts.Close()

	if code, body := req(t, ts, "GET", "/", "", ""); code != 200 || !strings.Contains(body, `id="app"`) {
		t.Fatalf("UI should be public (SPA root): %d", code)
	}
	// authinfo reports custom mode (a provider owns login).
	if code, body := req(t, ts, "GET", "/api/authinfo", "", ""); code != 200 || !strings.Contains(body, `"mode":"custom"`) {
		t.Fatalf("authinfo custom: %d %s", code, body)
	}
}
