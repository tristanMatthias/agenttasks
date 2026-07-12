package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAPIKeyAuthRoutesToTenant proves a bot key (tasks_<workspace>_<secret>)
// minted in one workspace authenticates as that workspace, cannot reach another,
// and is killed by revocation — the same isolation guarantee as sessions. With
// no active-workspace cookie, the human is on their personal board (u_<sub>), so
// the key is minted there.
func TestAPIKeyAuthRoutesToTenant(t *testing.T) {
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

	// Seed user_1's personal board with a task and mint a key in it.
	tokA := mint(t, priv, "user_1", "org_A")
	code, body := req(t, ts, "POST", "/api/v1/tasks", tokA, `{"title":"A task"}`)
	if code != http.StatusCreated {
		t.Fatalf("seed A = %d %s", code, body)
	}
	_, body = req(t, ts, "POST", "/api/v1/keys", tokA, `{"label":"bot"}`)
	var mk struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	json.Unmarshal([]byte(body), &mk)
	if !strings.HasPrefix(mk.Secret, "tasks_u_user_1_") {
		t.Fatalf("minted token should embed the workspace selector: %q", mk.Secret)
	}

	// The KEY (no session) authenticates as user_1's board and sees its data.
	code, body = req(t, ts, "GET", "/api/v1/ready?limit=50", mk.Secret, "")
	if code != 200 || !strings.Contains(body, "A task") {
		t.Fatalf("key should see its workspace data: %d %s", code, body)
	}

	// A key with a WRONG workspace selector but a valid-looking secret must fail.
	tampered := "tasks_u_user_2_" + strings.TrimPrefix(mk.Secret, "tasks_u_user_1_")
	if code, _ := req(t, ts, "GET", "/api/v1/ready", tampered, ""); code != http.StatusUnauthorized {
		t.Fatalf("cross-workspace key must 401, got %d", code)
	}
	// A tasks_ token without a selector must fail (managed keys require routing).
	if code, _ := req(t, ts, "GET", "/api/v1/ready", "tasks_"+strings.TrimPrefix(mk.Secret, "tasks_u_user_1_"), ""); code != http.StatusUnauthorized {
		t.Fatalf("selector-less key must 401, got %d", code)
	}

	// Revoke via the key's own tenant, then it stops working.
	if code, _ := req(t, ts, "POST", "/api/v1/keys/"+mk.ID+"/revoke", tokA, ""); code != 200 {
		t.Fatalf("revoke = %d", code)
	}
	if code, _ := req(t, ts, "GET", "/api/v1/ready", mk.Secret, ""); code != http.StatusUnauthorized {
		t.Fatalf("revoked key must 401, got %d", code)
	}

	// JWT sessions still work alongside keys.
	if code, _ := req(t, ts, "GET", "/api/v1/ready", tokA, ""); code != 200 {
		t.Fatalf("JWT path broke: %d", code)
	}
}
