package ghauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

// mockGitHub stands in for GitHub's token + user endpoints.
func mockGitHub(t *testing.T, user GitHubUser) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("code") != "good-code" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":"bad_verification_code"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"gho_test","token_type":"bearer"}`))
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gho_test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":` + strconv.FormatInt(user.ID, 10) + `,"login":"` + user.Login + `","name":"` + user.Name + `"}`))
	})
	return httptest.NewServer(mux)
}

func newAuth(t *testing.T, gh *httptest.Server, resolve func(GitHubUser) (string, error)) *Authenticator {
	t.Helper()
	insecure := false
	a, err := New(Config{
		ClientID: "cid", ClientSecret: "secret", PublicURL: "https://app.test",
		SessionSecret: []byte("test-session-secret-please"),
		TokenURL:      gh.URL + "/login/oauth/access_token",
		UserURL:       gh.URL + "/user",
		AuthorizeURL:  gh.URL + "/login/oauth/authorize",
		Resolve:       resolve,
		Secure:        &insecure,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// Drive the full login → callback → authenticated-request cycle.
func TestOAuthFlow_SetsSessionAndAuthorizes(t *testing.T) {
	gh := mockGitHub(t, GitHubUser{ID: 42, Login: "octocat", Name: "Octo Cat"})
	defer gh.Close()
	a := newAuth(t, gh, nil)

	mux := http.NewServeMux()
	a.Register(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	jar := &cookieJar{}

	// 1) /login → redirect to GitHub authorize, sets the state cookie.
	loginResp := do(t, ts.URL+"/auth/github/login?redirect_url=/tasks/x", jar)
	if loginResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status = %d, want 303", loginResp.StatusCode)
	}
	authorizeURL, _ := url.Parse(loginResp.Header.Get("Location"))
	state := authorizeURL.Query().Get("state")
	if state == "" || authorizeURL.Query().Get("client_id") != "cid" {
		t.Fatalf("bad authorize redirect: %s", authorizeURL)
	}

	// 2) GitHub redirects back to /callback?code&state.
	cbResp := do(t, ts.URL+"/auth/github/callback?code=good-code&state="+url.QueryEscape(state), jar)
	if cbResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback status = %d, want 303 (body: redirect)", cbResp.StatusCode)
	}
	if got := cbResp.Header.Get("Location"); got != "/tasks/x" {
		t.Fatalf("post-login redirect = %q, want /tasks/x", got)
	}
	if _, ok := jar.cookies[CookieName]; !ok {
		t.Fatal("session cookie was not set")
	}

	// 3) A request carrying the session cookie authorizes as gh_42.
	req, _ := http.NewRequest("GET", ts.URL+"/whatever", nil)
	req.Header.Set("Cookie", CookieName+"="+jar.cookies[CookieName])
	id, ok := a.Authorize(req)
	if !ok || id.Subject != "gh_42" {
		t.Fatalf("authorize = (%+v, %v), want gh_42", id, ok)
	}
	if id.Claims["login"] != "octocat" {
		t.Fatalf("login claim = %q", id.Claims["login"])
	}
}

// The Resolve hook preserves an existing tenant (the data-migration seam).
func TestOAuthFlow_ResolveMapsToExistingSubject(t *testing.T) {
	gh := mockGitHub(t, GitHubUser{ID: 99, Login: "owner", Name: "Owner"})
	defer gh.Close()
	a := newAuth(t, gh, func(u GitHubUser) (string, error) {
		if u.Login == "owner" {
			return "user_LEGACY_CLERK_SUB", nil // preserve the old board
		}
		return "", nil
	})
	mux := http.NewServeMux()
	a.Register(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	jar := &cookieJar{}
	loginResp := do(t, ts.URL+"/auth/github/login", jar)
	state, _ := url.Parse(loginResp.Header.Get("Location"))
	do(t, ts.URL+"/auth/github/callback?code=good-code&state="+url.QueryEscape(state.Query().Get("state")), jar)

	req, _ := http.NewRequest("GET", ts.URL+"/x", nil)
	req.Header.Set("Cookie", CookieName+"="+jar.cookies[CookieName])
	id, ok := a.Authorize(req)
	if !ok || id.Subject != "user_LEGACY_CLERK_SUB" {
		t.Fatalf("authorize subject = %q (ok=%v), want the mapped legacy subject", id.Subject, ok)
	}
}

func TestCallback_RejectsStateMismatch(t *testing.T) {
	gh := mockGitHub(t, GitHubUser{ID: 1, Login: "x"})
	defer gh.Close()
	a := newAuth(t, gh, nil)
	mux := http.NewServeMux()
	a.Register(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Callback with a forged state and no matching state cookie → rejected.
	forged := a.signState(stateClaims{Dest: "/", Nonce: "attacker", Exp: a.now().Add(time.Minute).Unix()})
	resp := do(t, ts.URL+"/auth/github/callback?code=good-code&state="+url.QueryEscape(forged), &cookieJar{})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("forged-state callback = %d, want 400", resp.StatusCode)
	}
}

func TestLogoutClearsCookie(t *testing.T) {
	gh := mockGitHub(t, GitHubUser{ID: 7, Login: "y"})
	defer gh.Close()
	a := newAuth(t, gh, nil)
	rec := httptest.NewRecorder()
	a.Logout(rec, httptest.NewRequest("POST", "/api/logout", nil))
	sc := rec.Result().Cookies()
	if len(sc) == 0 || sc[0].Name != CookieName || sc[0].MaxAge >= 0 {
		t.Fatalf("logout did not expire the session cookie: %+v", sc)
	}
}

func TestVerify_RejectsTamperedToken(t *testing.T) {
	gh := mockGitHub(t, GitHubUser{ID: 1, Login: "z"})
	defer gh.Close()
	a := newAuth(t, gh, nil)
	good := a.sign(sessionClaims{Sub: "gh_1", Exp: a.now().Add(time.Hour).Unix()})
	if _, err := a.verify(good); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if _, err := a.verify(good + "x"); err == nil {
		t.Fatal("tampered token accepted")
	}
	// A token signed with a different secret must not verify.
	other, _ := New(Config{ClientID: "c", ClientSecret: "s", SessionSecret: []byte("different-secret-entirely"), PublicURL: "https://x"})
	forged := other.sign(sessionClaims{Sub: "gh_evil", Exp: a.now().Add(time.Hour).Unix()})
	if _, err := a.verify(forged); err == nil {
		t.Fatal("token from a different secret accepted")
	}
}

// ---- tiny cookie-tracking client (follows nothing; we assert redirects) ----

type cookieJar struct{ cookies map[string]string }

func do(t *testing.T, rawurl string, jar *cookieJar) *http.Response {
	t.Helper()
	if jar.cookies == nil {
		jar.cookies = map[string]string{}
	}
	req, _ := http.NewRequest("GET", rawurl, nil)
	for k, v := range jar.cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 {
			delete(jar.cookies, c.Name)
		} else {
			jar.cookies[c.Name] = c.Value
		}
	}
	return resp
}
