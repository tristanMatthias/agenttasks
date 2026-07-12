package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func testProvider(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	minted := &[]string{}
	p := New(Config{
		Issuer:    "https://tasks.test",
		Resource:  "https://tasks.test/mcp",
		SignInURL: "/sign-in",
		HMACKey:   []byte("test-secret-key-0123456789"),
		// Signed in iff the request carries X-Test-Org.
		AuthUser: func(r *http.Request) (string, bool) {
			org := r.Header.Get("X-Test-Org")
			return org, org != ""
		},
		Workspaces: func(r *http.Request) []Workspace {
			org := r.Header.Get("X-Test-Org")
			if org == "" {
				return nil
			}
			return []Workspace{{ID: org, Name: "Acme"}, {ID: "org_OTHER", Name: "Other"}}
		},
		Mint: func(org string) (string, error) {
			tok := "tasks_" + org + "_secretmaterial"
			*minted = append(*minted, org)
			return tok, nil
		},
	})
	mux := http.NewServeMux()
	p.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, minted
}

// no-redirect client so we can inspect 302 Location headers.
func client() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestDiscovery(t *testing.T) {
	ts, _ := testProvider(t)
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		var m map[string]any
		getJSON(t, ts.URL+path, &m)
		if m["resource"] != "https://tasks.test/mcp" {
			t.Fatalf("%s resource = %v", path, m["resource"])
		}
		as := m["authorization_servers"].([]any)
		if as[0] != "https://tasks.test" {
			t.Fatalf("authorization_servers = %v", as)
		}
	}
	var as map[string]any
	getJSON(t, ts.URL+"/.well-known/oauth-authorization-server", &as)
	for _, k := range []string{"authorization_endpoint", "token_endpoint", "registration_endpoint"} {
		if _, ok := as[k]; !ok {
			t.Fatalf("AS metadata missing %s", k)
		}
	}
	if m := as["code_challenge_methods_supported"].([]any); m[0] != "S256" {
		t.Fatalf("PKCE method = %v", m)
	}
}

func TestFullAuthCodeFlow(t *testing.T) {
	ts, minted := testProvider(t)
	c := client()

	// 1) Dynamic client registration.
	clientID := register(t, ts.URL, `{"redirect_uris":["https://claude.ai/callback"],"client_name":"Claude"}`)

	// PKCE pair.
	verifier := "a-high-entropy-code-verifier-1234567890-abcdefghij"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	authURL := ts.URL + "/oauth/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"https://claude.ai/callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"xyz"},
		"resource":              {"https://tasks.test/mcp"},
	}.Encode()

	// 2) Unauthenticated -> redirect to sign-in with a return URL.
	resp, _ := c.Get(authURL)
	if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "/sign-in?redirect_url=") {
		t.Fatalf("unauth authorize = %d loc=%s", resp.StatusCode, resp.Header.Get("Location"))
	}

	// 3) Signed in -> consent page carrying a signed req.
	req, _ := http.NewRequest("GET", authURL, nil)
	req.Header.Set("X-Test-Org", "org_ACME")
	resp, _ = c.Do(req)
	body := readAll(resp)
	if resp.StatusCode != 200 || !strings.Contains(body, "org_ACME") {
		t.Fatalf("consent page = %d: %s", resp.StatusCode, body)
	}
	reqTok := regexp.MustCompile(`name="req" value="([^"]+)"`).FindStringSubmatch(body)
	if reqTok == nil {
		t.Fatalf("no req token in consent page")
	}

	// 4) Approve consent -> redirect to the client with an auth code.
	form := url.Values{"req": {reqTok[1]}, "decision": {"allow"}}
	preq, _ := http.NewRequest("POST", ts.URL+"/oauth/authorize", strings.NewReader(form.Encode()))
	preq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	preq.Header.Set("X-Test-Org", "org_ACME")
	resp, _ = c.Do(preq)
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, "https://claude.ai/callback?code=") {
		t.Fatalf("consent allow = %d loc=%s", resp.StatusCode, loc)
	}
	u, _ := url.Parse(loc)
	code := u.Query().Get("code")
	if u.Query().Get("state") != "xyz" {
		t.Fatalf("state not echoed: %s", loc)
	}

	// 5) Token exchange with the PKCE verifier.
	tok := tokenExchange(t, ts.URL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://claude.ai/callback"},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	})
	if tok["token_type"] != "Bearer" || !strings.HasPrefix(tok["access_token"].(string), "tasks_org_ACME_") {
		t.Fatalf("token response = %v", tok)
	}
	if len(*minted) != 1 || (*minted)[0] != "org_ACME" {
		t.Fatalf("minted for wrong org: %v", *minted)
	}

	// 6) Code is single-use.
	if again := tokenExchangeRaw(t, ts.URL, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://claude.ai/callback"}, "client_id": {clientID}, "code_verifier": {verifier},
	}); again != http.StatusBadRequest {
		t.Fatalf("reused code should fail, got %d", again)
	}
}

// The consent picker: a workspace the user belongs to is honored; a forged one
// falls back to the session's active workspace (never trust the form).
func TestConsentWorkspacePicker(t *testing.T) {
	ts, minted := testProvider(t)
	c := client()
	clientID := register(t, ts.URL, `{"redirect_uris":["https://claude.ai/callback"],"client_name":"Claude"}`)
	verifier := "a-high-entropy-code-verifier-1234567890-abcdefghij"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	run := func(chosen string) {
		authURL := ts.URL + "/oauth/authorize?" + url.Values{
			"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"https://claude.ai/callback"},
			"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "resource": {"https://tasks.test/mcp"},
		}.Encode()
		req, _ := http.NewRequest("GET", authURL, nil)
		req.Header.Set("X-Test-Org", "org_ACME")
		resp, _ := c.Do(req)
		body := readAll(resp)
		if !strings.Contains(body, "org_OTHER") || !strings.Contains(body, ">Other<") {
			t.Fatalf("consent picker missing options: %s", body)
		}
		reqTok := regexp.MustCompile(`name="req" value="([^"]+)"`).FindStringSubmatch(body)[1]
		form := url.Values{"req": {reqTok}, "decision": {"allow"}, "workspace": {chosen}}
		preq, _ := http.NewRequest("POST", ts.URL+"/oauth/authorize", strings.NewReader(form.Encode()))
		preq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		preq.Header.Set("X-Test-Org", "org_ACME")
		resp, _ = c.Do(preq)
		u, _ := url.Parse(resp.Header.Get("Location"))
		tokenExchange(t, ts.URL, url.Values{
			"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")},
			"redirect_uri": {"https://claude.ai/callback"}, "client_id": {clientID}, "code_verifier": {verifier},
		})
	}

	run("org_OTHER")
	if last := (*minted)[len(*minted)-1]; last != "org_OTHER" {
		t.Fatalf("chosen workspace not honored: minted %v", *minted)
	}
	run("org_FORGED")
	if last := (*minted)[len(*minted)-1]; last != "org_ACME" {
		t.Fatalf("forged workspace not rejected (want fallback to active): minted %v", *minted)
	}
}

func TestBadPKCEAndClient(t *testing.T) {
	ts, _ := testProvider(t)
	c := client()
	clientID := register(t, ts.URL, `{"redirect_uris":["https://claude.ai/callback"]}`)
	verifier := "correct-verifier-correct-verifier-correct-1234"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// unknown client_id -> 400 at authorize
	resp, _ := c.Get(ts.URL + "/oauth/authorize?response_type=code&client_id=bogus&redirect_uri=https://claude.ai/callback&code_challenge=x&code_challenge_method=S256")
	if resp.StatusCode != 400 {
		t.Fatalf("bogus client = %d", resp.StatusCode)
	}
	// unregistered redirect_uri -> 400
	resp, _ = c.Get(ts.URL + "/oauth/authorize?response_type=code&client_id=" + url.QueryEscape(clientID) + "&redirect_uri=https://evil.example/cb&code_challenge=x&code_challenge_method=S256")
	if resp.StatusCode != 400 {
		t.Fatalf("evil redirect = %d", resp.StatusCode)
	}

	// Get a real code, then present a WRONG verifier at token.
	authURL := ts.URL + "/oauth/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"https://claude.ai/callback"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode()
	req, _ := http.NewRequest("GET", authURL, nil)
	req.Header.Set("X-Test-Org", "org_1")
	resp, _ = c.Do(req)
	reqTok := regexp.MustCompile(`name="req" value="([^"]+)"`).FindStringSubmatch(readAll(resp))
	form := url.Values{"req": {reqTok[1]}, "decision": {"allow"}}
	preq, _ := http.NewRequest("POST", ts.URL+"/oauth/authorize", strings.NewReader(form.Encode()))
	preq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	preq.Header.Set("X-Test-Org", "org_1")
	resp, _ = c.Do(preq)
	code := mustQuery(resp.Header.Get("Location"), "code")

	if got := tokenExchangeRaw(t, ts.URL, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://claude.ai/callback"}, "client_id": {clientID}, "code_verifier": {"WRONG"},
	}); got != http.StatusBadRequest {
		t.Fatalf("wrong PKCE should 400, got %d", got)
	}
}

func TestConsentDeny(t *testing.T) {
	ts, _ := testProvider(t)
	c := client()
	clientID := register(t, ts.URL, `{"redirect_uris":["https://claude.ai/callback"]}`)
	authURL := ts.URL + "/oauth/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"https://claude.ai/callback"},
		"code_challenge": {"abc"}, "code_challenge_method": {"S256"}, "state": {"s1"},
	}.Encode()
	req, _ := http.NewRequest("GET", authURL, nil)
	req.Header.Set("X-Test-Org", "org_1")
	resp, _ := c.Do(req)
	reqTok := regexp.MustCompile(`name="req" value="([^"]+)"`).FindStringSubmatch(readAll(resp))
	form := url.Values{"req": {reqTok[1]}, "decision": {"deny"}}
	preq, _ := http.NewRequest("POST", ts.URL+"/oauth/authorize", strings.NewReader(form.Encode()))
	preq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	preq.Header.Set("X-Test-Org", "org_1")
	resp, _ = c.Do(preq)
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error=access_denied") {
		t.Fatalf("deny should redirect with error: %s", loc)
	}
}

// ---- helpers ----

func register(t *testing.T, base, body string) string {
	t.Helper()
	resp, err := http.Post(base+"/oauth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("register = %d", resp.StatusCode)
	}
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	resp.Body.Close()
	id, _ := m["client_id"].(string)
	if id == "" {
		t.Fatal("no client_id")
	}
	return id
}

func tokenExchange(t *testing.T, base string, form url.Values) map[string]any {
	t.Helper()
	resp, err := http.PostForm(base+"/oauth/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("token = %d: %s", resp.StatusCode, b)
	}
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	return m
}

func tokenExchangeRaw(t *testing.T, base string, form url.Values) int {
	t.Helper()
	resp, err := http.PostForm(base+"/oauth/token", form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func getJSON(t *testing.T, url string, v any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s = %d", url, resp.StatusCode)
	}
	json.NewDecoder(resp.Body).Decode(v)
}

func readAll(resp *http.Response) string {
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return string(b)
}

func mustQuery(loc, key string) string {
	u, _ := url.Parse(loc)
	return u.Query().Get(key)
}
