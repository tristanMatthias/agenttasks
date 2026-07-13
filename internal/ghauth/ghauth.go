// Package ghauth authenticates humans with GitHub OAuth and a first-party,
// server-signed session cookie. It's deliberately stateless: the callback
// exchanges the code, resolves the GitHub user to a stable canonical subject,
// and sets an HMAC-signed cookie the engine validates on every request — no
// third-party script in the page, no client-side token refresh, no CSP
// carve-outs. The org/workspace model (control.db) is unchanged; the subject is
// derived from the GitHub user id.
package ghauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tristanMatthias/tasks/pkg/httpapi"
)

// CookieName is the first-party session cookie (HttpOnly, server-signed).
const CookieName = "agenttasks_session"

const sessionTTL = 30 * 24 * time.Hour

// GitHubUser is the subset of the GitHub /user response we consume.
type GitHubUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// Config configures the GitHub OAuth authenticator.
type Config struct {
	ClientID     string
	ClientSecret string
	// PublicURL is the site origin (e.g. https://agenttasks.sh); the callback is
	// PublicURL + "/auth/github/callback".
	PublicURL string
	// SessionSecret signs the session cookie AND the OAuth state. Required.
	SessionSecret []byte
	// Scopes requested from GitHub. Default: "read:user user:email".
	Scopes string
	// Resolve maps an authenticated GitHub user to the canonical subject used by
	// the tenant/workspace layer (so an existing board can be preserved). If nil,
	// the subject defaults to "gh_<id>".
	Resolve func(GitHubUser) (string, error)

	// Now/HTTPClient/endpoints are injectable for tests; sensible defaults apply.
	Now         func() time.Time
	HTTPClient  *http.Client
	AuthorizeURL string // default https://github.com/login/oauth/authorize
	TokenURL     string // default https://github.com/login/oauth/access_token
	UserURL      string // default https://api.github.com/user
	Secure       *bool  // cookie Secure flag; default true
}

// Authenticator implements httpapi.Authenticator (+ LoginProvider) over the
// first-party session cookie, and serves the OAuth login/callback routes.
type Authenticator struct {
	cfg    Config
	now    func() time.Time
	hc     *http.Client
	secure bool
}

// New validates cfg and builds an Authenticator.
func New(cfg Config) (*Authenticator, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("ghauth: ClientID and ClientSecret are required")
	}
	if len(cfg.SessionSecret) == 0 {
		return nil, errors.New("ghauth: SessionSecret is required")
	}
	if cfg.Scopes == "" {
		cfg.Scopes = "read:user user:email"
	}
	if cfg.AuthorizeURL == "" {
		cfg.AuthorizeURL = "https://github.com/login/oauth/authorize"
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = "https://github.com/login/oauth/access_token"
	}
	if cfg.UserURL == "" {
		cfg.UserURL = "https://api.github.com/user"
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	secure := true
	if cfg.Secure != nil {
		secure = *cfg.Secure
	}
	return &Authenticator{cfg: cfg, now: now, hc: hc, secure: secure}, nil
}

// ---- httpapi.Authenticator ----

// Authorize reads and verifies the session cookie.
func (a *Authenticator) Authorize(r *http.Request) (httpapi.Identity, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return httpapi.Identity{}, false
	}
	claims, err := a.verify(c.Value)
	if err != nil {
		return httpapi.Identity{}, false
	}
	id := httpapi.Identity{Subject: claims.Sub, Claims: map[string]string{}}
	if claims.Name != "" {
		id.Claims["name"] = claims.Name
	}
	if claims.Login != "" {
		id.Claims["login"] = claims.Login
	}
	return id, true
}

// ---- httpapi.LoginProvider ----

// Login (POST /api/login) just points the browser at the OAuth start; the real
// flow is the GET redirect below.
func (a *Authenticator) Login(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/auth/github/login", http.StatusSeeOther)
}

// Logout (POST /api/logout) clears the session cookie.
func (a *Authenticator) Logout(w http.ResponseWriter, r *http.Request) {
	a.clearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// Register mounts the OAuth routes on mux.
func (a *Authenticator) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/github/login", a.handleLogin)
	mux.HandleFunc("GET /auth/github/callback", a.handleCallback)
	mux.HandleFunc("GET /auth/github/logout", a.handleLogoutRedirect)
}

func (a *Authenticator) callbackURL() string {
	return strings.TrimRight(a.cfg.PublicURL, "/") + "/auth/github/callback"
}

// handleLogin redirects to GitHub's consent screen, carrying a signed state that
// pins the post-login redirect target (same-site only) + a CSRF nonce.
func (a *Authenticator) handleLogin(w http.ResponseWriter, r *http.Request) {
	dest := "/"
	if rp := r.URL.Query().Get("redirect_url"); strings.HasPrefix(rp, "/") && !strings.HasPrefix(rp, "//") {
		dest = rp
	}
	nonce := randToken()
	state := a.signState(stateClaims{Dest: dest, Nonce: nonce, Exp: a.now().Add(10 * time.Minute).Unix()})
	http.SetCookie(w, &http.Cookie{
		Name: "gh_oauth_state", Value: nonce, Path: "/", HttpOnly: true,
		Secure: a.secure, SameSite: http.SameSiteLaxMode, MaxAge: 600,
	})
	q := url.Values{}
	q.Set("client_id", a.cfg.ClientID)
	q.Set("redirect_uri", a.callbackURL())
	q.Set("scope", a.cfg.Scopes)
	q.Set("state", state)
	http.Redirect(w, r, a.cfg.AuthorizeURL+"?"+q.Encode(), http.StatusSeeOther)
}

func (a *Authenticator) handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "missing code/state", http.StatusBadRequest)
		return
	}
	sc, err := a.verifyState(state)
	if err != nil {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	// CSRF: the state's nonce must match the cookie set at login start.
	if c, err := r.Cookie("gh_oauth_state"); err != nil || c.Value != sc.Nonce {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	tok, err := a.exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "oauth exchange failed", http.StatusBadGateway)
		return
	}
	gh, err := a.fetchUser(r.Context(), tok)
	if err != nil || gh.ID == 0 {
		http.Error(w, "failed to load GitHub user", http.StatusBadGateway)
		return
	}
	sub := fmt.Sprintf("gh_%d", gh.ID)
	if a.cfg.Resolve != nil {
		if s, err := a.cfg.Resolve(gh); err == nil && s != "" {
			sub = s
		}
	}
	a.setCookie(w, sub, gh.Login, gh.Name)
	// One-time state cookie is done.
	http.SetCookie(w, &http.Cookie{Name: "gh_oauth_state", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, sc.Dest, http.StatusSeeOther)
}

func (a *Authenticator) handleLogoutRedirect(w http.ResponseWriter, r *http.Request) {
	a.clearCookie(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// exchange trades the OAuth code for an access token.
func (a *Authenticator) exchange(ctx context.Context, code string) (string, error) {
	form := url.Values{}
	form.Set("client_id", a.cfg.ClientID)
	form.Set("client_secret", a.cfg.ClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", a.callbackURL())
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.TokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("no access_token (%s)", out.Error)
	}
	return out.AccessToken, nil
}

func (a *Authenticator) fetchUser(ctx context.Context, token string) (GitHubUser, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.UserURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := a.hc.Do(req)
	if err != nil {
		return GitHubUser{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return GitHubUser{}, fmt.Errorf("user endpoint %d", resp.StatusCode)
	}
	var u GitHubUser
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err := json.Unmarshal(body, &u); err != nil {
		return GitHubUser{}, err
	}
	return u, nil
}

// ---- session cookie (stateless, HMAC-signed) ----

type sessionClaims struct {
	Sub   string `json:"sub"`
	Login string `json:"login,omitempty"`
	Name  string `json:"name,omitempty"`
	Exp   int64  `json:"exp"`
}

func (a *Authenticator) setCookie(w http.ResponseWriter, sub, login, name string) {
	claims := sessionClaims{Sub: sub, Login: login, Name: name, Exp: a.now().Add(sessionTTL).Unix()}
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: a.sign(claims), Path: "/", HttpOnly: true,
		Secure: a.secure, SameSite: http.SameSiteLaxMode, MaxAge: int(sessionTTL.Seconds()),
	})
}

func (a *Authenticator) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: "", Path: "/", HttpOnly: true,
		Secure: a.secure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

func (a *Authenticator) sign(c sessionClaims) string {
	payload, _ := json.Marshal(c)
	return mac(a.cfg.SessionSecret, payload)
}

func (a *Authenticator) verify(tokenStr string) (sessionClaims, error) {
	payload, err := open(a.cfg.SessionSecret, tokenStr)
	if err != nil {
		return sessionClaims{}, err
	}
	var c sessionClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return sessionClaims{}, err
	}
	if c.Sub == "" || a.now().Unix() > c.Exp {
		return sessionClaims{}, errors.New("expired or empty session")
	}
	return c, nil
}

// ---- OAuth state (signed, short-lived) ----

type stateClaims struct {
	Dest  string `json:"d"`
	Nonce string `json:"n"`
	Exp   int64  `json:"e"`
}

func (a *Authenticator) signState(s stateClaims) string {
	b, _ := json.Marshal(s)
	return mac(a.cfg.SessionSecret, b)
}

func (a *Authenticator) verifyState(tokenStr string) (stateClaims, error) {
	b, err := open(a.cfg.SessionSecret, tokenStr)
	if err != nil {
		return stateClaims{}, err
	}
	var s stateClaims
	if err := json.Unmarshal(b, &s); err != nil {
		return stateClaims{}, err
	}
	if a.now().Unix() > s.Exp {
		return stateClaims{}, errors.New("state expired")
	}
	return s, nil
}

// ---- HMAC helpers: base64(payload).base64(hmac-sha256) ----

func mac(secret, payload []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write(payload)
	sig := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func open(secret []byte, tok string) ([]byte, error) {
	i := strings.IndexByte(tok, '.')
	if i < 0 {
		return nil, errors.New("malformed token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(tok[:i])
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(tok[i+1:])
	if err != nil {
		return nil, err
	}
	h := hmac.New(sha256.New, secret)
	h.Write(payload)
	if !hmac.Equal(sig, h.Sum(nil)) {
		return nil, errors.New("bad signature")
	}
	return payload, nil
}

func randToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
