package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

// newClient is a per-user browser: it keeps the active-workspace cookie.
func newClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

func reqC(t *testing.T, client *http.Client, ts *httptest.Server, method, path, jwt, body string) (int, string) {
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
	resp, err := client.Do(rq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestWorkspaceFlow exercises the whole self-hosted workspace system end to end
// (no Clerk needed): create a workspace, get a slug-derived id prefix, isolation
// from non-members, invite-link acceptance, and admin-only gating.
func TestWorkspaceFlow(t *testing.T) {
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

	tokA := mint(t, priv, "user_1", "")
	tokB := mint(t, priv, "user_2", "")
	alice, bob := newClient(), newClient()

	// Alice creates a workspace; the active cookie is set and the prefix is the slug.
	code, body := reqC(t, alice, ts, "POST", "/api/workspaces", tokA, `{"name":"Acme Platform"}`)
	if code != http.StatusCreated {
		t.Fatalf("create workspace = %d %s", code, body)
	}
	var ws struct{ ID, Prefix string }
	json.Unmarshal([]byte(body), &ws)
	if ws.Prefix != "acme-platform" {
		t.Fatalf("prefix = %q, want acme-platform", ws.Prefix)
	}

	// A task created now lands in the workspace and its id carries the prefix.
	code, body = reqC(t, alice, ts, "POST", "/api/v1/tasks", tokA, `{"title":"Acme task"}`)
	if code != http.StatusCreated {
		t.Fatalf("create task = %d %s", code, body)
	}
	var task struct{ ID string }
	json.Unmarshal([]byte(body), &task)
	if !strings.HasPrefix(task.ID, "acme-platform-") {
		t.Fatalf("task id = %q, want acme-platform- prefix", task.ID)
	}

	// Bob is not a member: his board is personal and empty, and he can't switch in.
	if _, body := reqC(t, bob, ts, "GET", "/api/v1/ready?limit=50", tokB, ""); strings.Contains(body, "Acme task") {
		t.Fatalf("LEAK: non-member saw the workspace task: %s", body)
	}
	if code, _ := reqC(t, bob, ts, "POST", "/api/workspaces/switch", tokB, `{"id":"`+ws.ID+`"}`); code != http.StatusForbidden {
		t.Fatalf("non-member switch must 403, got %d", code)
	}

	// Alice invites; Bob accepts via the link and lands in the workspace.
	code, body = reqC(t, alice, ts, "POST", "/api/workspaces/"+ws.ID+"/invites", tokA, `{"role":"member"}`)
	if code != http.StatusCreated {
		t.Fatalf("create invite = %d %s", code, body)
	}
	var inv struct{ Token string }
	json.Unmarshal([]byte(body), &inv)

	// The GET link is a confirm page (no mutation); joining is an explicit POST.
	if code, _ := reqC(t, bob, ts, "GET", "/invite/"+inv.Token, tokB, ""); code != 200 {
		t.Fatalf("invite landing = %d", code)
	}
	if code, _ := reqC(t, bob, ts, "POST", "/invite/"+inv.Token+"/accept", tokB, ""); code != 200 {
		t.Fatalf("accept invite (follows redirect to board) = %d", code)
	}
	// Now Bob (member, active cookie set to the workspace) sees the task.
	if code, body := reqC(t, bob, ts, "GET", "/api/v1/ready?limit=50", tokB, ""); code != 200 || !strings.Contains(body, "Acme task") {
		t.Fatalf("member should see the workspace task: %d %s", code, body)
	}

	// Bob is a member, not an admin: he cannot invite.
	if code, _ := reqC(t, bob, ts, "POST", "/api/workspaces/"+ws.ID+"/invites", tokB, `{"role":"member"}`); code != http.StatusForbidden {
		t.Fatalf("member invite must 403, got %d", code)
	}

	// Alice's workspace list shows Personal + Acme, active = Acme.
	_, body = reqC(t, alice, ts, "GET", "/api/workspaces", tokA, "")
	if !strings.Contains(body, `"active":"`+ws.ID+`"`) || !strings.Contains(body, "Personal") {
		t.Fatalf("workspace list wrong: %s", body)
	}

	// Switching Bob back to personal isolates him from the workspace task again.
	reqC(t, bob, ts, "POST", "/api/workspaces/switch", tokB, `{"id":""}`)
	if _, body := reqC(t, bob, ts, "GET", "/api/v1/ready?limit=50", tokB, ""); strings.Contains(body, "Acme task") {
		t.Fatalf("personal board should not show workspace task: %s", body)
	}
}

// TestWorkspaceAdmin covers the admin-management endpoints and their gating.
func TestWorkspaceAdmin(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, jwksJSON(&priv.PublicKey))
	}))
	defer jwks.Close()
	a, _ := New(context.Background(), Config{JWKSURL: jwks.URL, DataDir: t.TempDir()})
	defer a.Close()
	ts := httptest.NewServer(a.Handler)
	defer ts.Close()

	tokA, tokB := mint(t, priv, "user_1", ""), mint(t, priv, "user_2", "")
	alice, bob := newClient(), newClient()

	_, body := reqC(t, alice, ts, "POST", "/api/workspaces", tokA, `{"name":"Acme"}`)
	var ws struct{ ID string }
	json.Unmarshal([]byte(body), &ws)

	// Invite + accept (bob joins as member).
	_, body = reqC(t, alice, ts, "POST", "/api/workspaces/"+ws.ID+"/invites", tokA, `{"role":"member"}`)
	var inv struct{ Token string }
	json.Unmarshal([]byte(body), &inv)
	reqC(t, bob, ts, "POST", "/invite/"+inv.Token+"/accept", tokB, "")

	// Members list has two, from the control DB.
	if code, body := reqC(t, alice, ts, "GET", "/api/workspaces/"+ws.ID+"/members", tokA, ""); code != 200 ||
		!strings.Contains(body, "user_1") || !strings.Contains(body, "user_2") {
		t.Fatalf("members = %d %s", code, body)
	}

	// A member cannot manage: demote/remove others, invite, rename, list invites.
	for _, c := range []struct{ m, p, b string }{
		{"PATCH", "/api/workspaces/" + ws.ID + "/members/user_1", `{"role":"member"}`},
		{"DELETE", "/api/workspaces/" + ws.ID + "/members/user_1", ""},
		{"POST", "/api/workspaces/" + ws.ID + "/invites", `{"role":"member"}`},
		{"PATCH", "/api/workspaces/" + ws.ID, `{"name":"x"}`},
		{"GET", "/api/workspaces/" + ws.ID + "/invites", ""},
	} {
		if code, _ := reqC(t, bob, ts, c.m, c.p, tokB, c.b); code != http.StatusForbidden {
			t.Fatalf("member %s %s = %d, want 403", c.m, c.p, code)
		}
	}

	// The sole admin cannot be demoted or removed.
	if code, _ := reqC(t, alice, ts, "PATCH", "/api/workspaces/"+ws.ID+"/members/user_1", tokA, `{"role":"member"}`); code != http.StatusBadRequest {
		t.Fatalf("demote last admin = %d, want 400", code)
	}

	// Admin promotes bob, renames, and creates+revokes an invite.
	if code, _ := reqC(t, alice, ts, "PATCH", "/api/workspaces/"+ws.ID+"/members/user_2", tokA, `{"role":"admin"}`); code != 200 {
		t.Fatalf("promote = %d", code)
	}
	if code, _ := reqC(t, alice, ts, "PATCH", "/api/workspaces/"+ws.ID, tokA, `{"name":"Acme Inc"}`); code != 200 {
		t.Fatalf("rename = %d", code)
	}
	_, body = reqC(t, alice, ts, "POST", "/api/workspaces/"+ws.ID+"/invites", tokA, `{"email":"z@x.com","role":"member"}`)
	var inv2 struct{ Token string }
	json.Unmarshal([]byte(body), &inv2)
	if code, body := reqC(t, alice, ts, "GET", "/api/workspaces/"+ws.ID+"/invites", tokA, ""); code != 200 || !strings.Contains(body, "z@x.com") {
		t.Fatalf("list invites = %d %s", code, body)
	}
	if code, _ := reqC(t, alice, ts, "DELETE", "/api/workspaces/"+ws.ID+"/invites/"+inv2.Token, tokA, ""); code != 200 {
		t.Fatalf("revoke invite = %d", code)
	}

	// Now that bob is an admin, alice (still admin) can be removed and it holds.
	if code, _ := reqC(t, bob, ts, "DELETE", "/api/workspaces/"+ws.ID+"/members/user_1", tokB, ""); code != 200 {
		t.Fatalf("remove co-admin = %d", code)
	}
	if _, body := reqC(t, alice, ts, "GET", "/api/workspaces", tokA, ""); strings.Contains(body, ws.ID) {
		t.Fatalf("removed admin still lists the workspace: %s", body)
	}
}
