// Package oauth implements the minimal OAuth 2.1 authorization server that lets
// browser-based MCP clients (e.g. claude.ai Connectors) connect to a tenant's
// board. It is a thin AS in front of the existing identity + tenant layers:
//
//   - Dynamic Client Registration (RFC 7591) with stateless, HMAC-signed
//     client_ids (no client storage).
//   - Authorization Code + PKCE (S256 only). The /authorize endpoint authenticates
//     the human via their Clerk session (a cookie the host verifies) and shows a
//     consent screen; the org is taken from the SESSION, never from request input.
//   - /token exchanges the code for an access token that is a freshly-minted,
//     tenant-scoped API key (tasks_<org>_<secret>) — so the board's existing
//     authenticator validates it with no extra machinery. Tokens are revocable
//     from the board's API-keys pane.
//
// Discovery: RFC 9728 protected-resource metadata + RFC 8414 AS metadata.
package oauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config configures the provider.
type Config struct {
	Issuer    string // public base URL, e.g. https://agenttasks.sh
	Resource  string // protected resource id, e.g. https://agenttasks.sh/mcp
	SignInURL string // where to send an unauthenticated user (e.g. /sign-in)
	HMACKey   []byte // signs client_ids, request blobs, and codes
	Logger    *slog.Logger
	// AuthUser resolves the human's tenant (org) from their session (Clerk cookie).
	// ok=false means "not signed in" -> the user is sent to SignInURL.
	AuthUser func(r *http.Request) (org string, ok bool)
	// Mint returns a fresh access token (a tenant-scoped API key) for org.
	Mint func(org string) (token string, err error)
}

// Provider is the authorization server.
type Provider struct {
	cfg   Config
	mu    sync.Mutex
	codes map[string]codeData
}

type codeData struct {
	org, clientID, redirectURI, challenge, resource string
	exp                                             time.Time
}

// New builds a Provider.
func New(cfg Config) *Provider {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Provider{cfg: cfg, codes: map[string]codeData{}}
}

// Register mounts the OAuth endpoints on mux. All are public (each does its own
// checks); mount them ahead of the resource's auth gate.
func (p *Provider) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", p.protectedResource)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", p.protectedResource)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", p.authServerMeta)
	// Some clients probe the OIDC discovery path; serve the same document.
	mux.HandleFunc("GET /.well-known/openid-configuration", p.authServerMeta)
	mux.HandleFunc("POST /oauth/register", p.registerClient)
	mux.HandleFunc("GET /oauth/authorize", p.authorize)
	mux.HandleFunc("POST /oauth/authorize", p.consent)
	mux.HandleFunc("POST /oauth/token", p.token)
}

// ---- discovery ----

func (p *Provider) protectedResource(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"resource":                 p.cfg.Resource,
		"authorization_servers":    []string{p.cfg.Issuer},
		"scopes_supported":         []string{"tasks"},
		"bearer_methods_supported": []string{"header"},
	})
}

func (p *Provider) authServerMeta(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"issuer":                                p.cfg.Issuer,
		"authorization_endpoint":                p.cfg.Issuer + "/oauth/authorize",
		"token_endpoint":                        p.cfg.Issuer + "/oauth/token",
		"registration_endpoint":                 p.cfg.Issuer + "/oauth/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"tasks"},
	})
}

// ---- dynamic client registration (RFC 7591) ----

type clientMeta struct {
	RedirectURIs []string `json:"redirect_uris"`
	Name         string   `json:"client_name,omitempty"`
	IAT          int64    `json:"iat"`
}

func (p *Provider) registerClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeErr(w, 400, "invalid_client_metadata", "invalid JSON")
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeErr(w, 400, "invalid_redirect_uri", "redirect_uris required")
		return
	}
	for _, u := range req.RedirectURIs {
		if !validRedirect(u) {
			writeErr(w, 400, "invalid_redirect_uri", "redirect_uri must be https or localhost")
			return
		}
	}
	meta := clientMeta{RedirectURIs: req.RedirectURIs, Name: req.ClientName, IAT: time.Now().Unix()}
	blob, _ := json.Marshal(meta)
	clientID := p.sign(blob)
	writeJSON(w, 201, map[string]any{
		"client_id":                  clientID,
		"client_id_issued_at":        meta.IAT,
		"redirect_uris":              meta.RedirectURIs,
		"client_name":                meta.Name,
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
}

// ---- authorization endpoint ----

// authReq is the validated authorize request, signed into the consent form so we
// need not re-trust query params on submit.
type authReq struct {
	ClientID    string `json:"c"`
	RedirectURI string `json:"r"`
	Challenge   string `json:"h"`
	State       string `json:"s"`
	Resource    string `json:"a"`
	Exp         int64  `json:"e"`
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cm, ok := p.clientFromID(q.Get("client_id"))
	if !ok {
		httpError(w, 400, "unknown or invalid client_id")
		return
	}
	redirectURI := q.Get("redirect_uri")
	if !contains(cm.RedirectURIs, redirectURI) {
		httpError(w, 400, "redirect_uri not registered for this client")
		return
	}
	// From here, errors can be redirected back to the (trusted) client.
	if q.Get("response_type") != "code" {
		redirectErr(w, r, redirectURI, "unsupported_response_type", q.Get("state"))
		return
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		redirectErr(w, r, redirectURI, "invalid_request", q.Get("state"))
		return
	}

	org, signedIn := p.cfg.AuthUser(r)
	if !signedIn {
		// Send the user through Clerk sign-in, returning to this exact request.
		back := r.URL.RequestURI()
		http.Redirect(w, r, p.cfg.SignInURL+"?redirect_url="+url.QueryEscape(back), http.StatusFound)
		return
	}

	req := authReq{
		ClientID:    q.Get("client_id"),
		RedirectURI: redirectURI,
		Challenge:   q.Get("code_challenge"),
		State:       q.Get("state"),
		Resource:    q.Get("resource"),
		Exp:         time.Now().Add(10 * time.Minute).Unix(),
	}
	blob, _ := json.Marshal(req)
	p.renderConsent(w, cm.Name, org, p.sign(blob))
}

func (p *Provider) consent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpError(w, 400, "bad form")
		return
	}
	payload, ok := p.unsign(r.Form.Get("req"))
	if !ok {
		httpError(w, 400, "invalid request")
		return
	}
	var req authReq
	if err := json.Unmarshal(payload, &req); err != nil || time.Now().Unix() > req.Exp {
		httpError(w, 400, "request expired — start again")
		return
	}
	// Re-confirm the human is still signed in; the org comes from the session.
	org, signedIn := p.cfg.AuthUser(r)
	if !signedIn {
		back := "/oauth/authorize?" + authQuery(req)
		http.Redirect(w, r, p.cfg.SignInURL+"?redirect_url="+url.QueryEscape(back), http.StatusFound)
		return
	}
	if r.Form.Get("decision") != "allow" {
		redirectErr(w, r, req.RedirectURI, "access_denied", req.State)
		return
	}
	code := randToken()
	p.putCode(code, codeData{
		org: org, clientID: req.ClientID, redirectURI: req.RedirectURI,
		challenge: req.Challenge, resource: req.Resource,
		exp: time.Now().Add(2 * time.Minute),
	})
	u := req.RedirectURI + "?code=" + url.QueryEscape(code)
	if req.State != "" {
		u += "&state=" + url.QueryEscape(req.State)
	}
	http.Redirect(w, r, u, http.StatusFound)
}

// ---- token endpoint ----

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeErr(w, 400, "invalid_request", "bad form")
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		writeErr(w, 400, "unsupported_grant_type", "only authorization_code")
		return
	}
	cd, ok := p.takeCode(r.Form.Get("code"))
	if !ok {
		writeErr(w, 400, "invalid_grant", "unknown or expired code")
		return
	}
	if !constEq(cd.clientID, r.Form.Get("client_id")) || !constEq(cd.redirectURI, r.Form.Get("redirect_uri")) {
		writeErr(w, 400, "invalid_grant", "client/redirect mismatch")
		return
	}
	if !pkceOK(r.Form.Get("code_verifier"), cd.challenge) {
		writeErr(w, 400, "invalid_grant", "PKCE verification failed")
		return
	}
	tok, err := p.cfg.Mint(cd.org)
	if err != nil {
		p.cfg.Logger.Error("oauth mint", "err", err, "org", cd.org)
		writeErr(w, 500, "server_error", "could not issue token")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{
		"access_token": tok,
		"token_type":   "Bearer",
		"scope":        "tasks",
	})
}

// ---- code store ----

func (p *Provider) putCode(code string, d codeData) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for k, v := range p.codes { // opportunistic GC
		if now.After(v.exp) {
			delete(p.codes, k)
		}
	}
	p.codes[code] = d
}

func (p *Provider) takeCode(code string) (codeData, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	d, ok := p.codes[code]
	if !ok {
		return codeData{}, false
	}
	delete(p.codes, code) // single use
	if time.Now().After(d.exp) {
		return codeData{}, false
	}
	return d, true
}

// ---- signing + helpers ----

func (p *Provider) sign(payload []byte) string {
	b := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, p.cfg.HMACKey)
	mac.Write([]byte(b))
	return b + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (p *Provider) unsign(tok string) ([]byte, bool) {
	i := strings.LastIndexByte(tok, '.')
	if i < 0 {
		return nil, false
	}
	b, sig := tok[:i], tok[i+1:]
	mac := hmac.New(sha256.New, p.cfg.HMACKey)
	mac.Write([]byte(b))
	if !hmac.Equal([]byte(sig), []byte(base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))) {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(b)
	if err != nil {
		return nil, false
	}
	return payload, true
}

func (p *Provider) clientFromID(id string) (clientMeta, bool) {
	payload, ok := p.unsign(id)
	if !ok {
		return clientMeta{}, false
	}
	var cm clientMeta
	if err := json.Unmarshal(payload, &cm); err != nil || len(cm.RedirectURIs) == 0 {
		return clientMeta{}, false
	}
	return cm, true
}

var consentTmpl = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Connect — agenttasks</title>
<style>
 body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
   font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f0f14;color:#c0caf5}
 .card{width:min(420px,92vw);background:#1a1b26;border:1px solid #2a2b3c;border-radius:12px;padding:26px 24px;box-shadow:0 18px 60px rgba(0,0,0,.5)}
 h1{font-size:18px;margin:0 0 6px} p{color:#a9b1d6;font-size:13.5px;line-height:1.5}
 .org{color:#7aa2f7;font-weight:600} .row{display:flex;gap:10px;margin-top:18px}
 button{flex:1;padding:11px;border-radius:8px;border:1px solid #2a2b3c;font-weight:600;font-size:14px;cursor:pointer}
 .allow{background:#7aa2f7;color:#0b0b12;border-color:#7aa2f7} .deny{background:transparent;color:#c0caf5}
</style></head><body>
<form class="card" method="POST" action="/oauth/authorize">
 <h1>Connect {{.Client}}</h1>
 <p><strong>{{.Client}}</strong> is requesting access to your <span class="org">agenttasks</span> board
    (tenant <span class="org">{{.Org}}</span>). It will be able to read and manage your tasks.</p>
 <input type="hidden" name="req" value="{{.Req}}"/>
 <div class="row">
   <button class="deny" name="decision" value="deny" type="submit">Deny</button>
   <button class="allow" name="decision" value="allow" type="submit">Allow</button>
 </div>
</form></body></html>`))

func (p *Provider) renderConsent(w http.ResponseWriter, client, org, req string) {
	if client == "" {
		client = "An application"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = consentTmpl.Execute(w, map[string]string{"Client": client, "Org": org, "Req": req})
}

func authQuery(req authReq) string {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", req.ClientID)
	v.Set("redirect_uri", req.RedirectURI)
	v.Set("code_challenge", req.Challenge)
	v.Set("code_challenge_method", "S256")
	if req.State != "" {
		v.Set("state", req.State)
	}
	if req.Resource != "" {
		v.Set("resource", req.Resource)
	}
	return v.Encode()
}

func pkceOK(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return constEq(base64.RawURLEncoding.EncodeToString(sum[:]), challenge)
}

func validRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" {
		return false
	}
	if u.Scheme == "https" {
		return u.Host != ""
	}
	if u.Scheme == "http" {
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1"
	}
	return false
}

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func constEq(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func redirectErr(w http.ResponseWriter, r *http.Request, redirectURI, code, state string) {
	u := redirectURI + "?error=" + url.QueryEscape(code)
	if state != "" {
		u += "&state=" + url.QueryEscape(state)
	}
	http.Redirect(w, r, u, http.StatusFound)
}

func httpError(w http.ResponseWriter, status int, msg string) {
	http.Error(w, msg, status)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}
