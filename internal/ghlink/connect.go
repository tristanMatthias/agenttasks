package ghlink

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Connector runs the "Connect GitHub" install flow: a workspace clicks connect,
// installs the shared GitHub App on its repos, and GitHub redirects back to the
// setup callback — which binds that installation to the workspace so its repos
// auto-link. This is the per-workspace, repeatable half of the integration; the
// App itself is created once.
type Connector struct {
	AppSlug     string // the App's slug, for github.com/apps/<slug>/installations/new
	StateSecret []byte // signs the short-lived connect state
	// Workspace authenticates the request and returns the caller's active
	// workspace id (false when not signed in).
	Workspace func(*http.Request) (string, bool)
	// Bind records that an installation belongs to a workspace.
	Bind         func(installationID int64, workspaceID string) error
	SettingsPath string // where to send the browser after setup (default "/settings/connect")
	LoginPath    string // where to send an unauthenticated connect (default "/auth/github/login")
	Logger       *slog.Logger
}

func (c *Connector) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /integrations/github/connect", c.connect)
	mux.HandleFunc("GET /integrations/github/setup", c.setup)
}

func (c *Connector) settingsPath() string {
	if c.SettingsPath != "" {
		return c.SettingsPath
	}
	return "/settings/connect"
}

func (c *Connector) connect(w http.ResponseWriter, r *http.Request) {
	ws, ok := c.Workspace(r)
	if !ok {
		login := c.LoginPath
		if login == "" {
			login = "/auth/github/login"
		}
		http.Redirect(w, r, login+"?redirect_url=/integrations/github/connect", http.StatusSeeOther)
		return
	}
	state := c.sign(stateClaims{Dest: ws, Exp: time.Now().Add(15 * time.Minute).Unix()})
	dest := "https://github.com/apps/" + c.AppSlug + "/installations/new?state=" + url.QueryEscape(state)
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (c *Connector) setup(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	sc, err := c.verify(q.Get("state"))
	if err != nil {
		http.Redirect(w, r, c.settingsPath()+"?github=error", http.StatusSeeOther)
		return
	}
	if id, _ := strconv.ParseInt(q.Get("installation_id"), 10, 64); id != 0 && c.Bind != nil {
		if err := c.Bind(id, sc.Dest); err != nil && c.Logger != nil {
			c.Logger.Warn("bind installation", "err", err)
		}
	}
	http.Redirect(w, r, c.settingsPath()+"?github=connected", http.StatusSeeOther)
}

// ---- signed state (workspace id + expiry) ----

type stateClaims struct {
	Dest string `json:"d"` // workspace id
	Exp  int64  `json:"e"`
}

func (c *Connector) sign(s stateClaims) string {
	b, _ := json.Marshal(s)
	mac := hmac.New(sha256.New, c.StateSecret)
	mac.Write(b)
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (c *Connector) verify(tok string) (stateClaims, error) {
	i := strings.IndexByte(tok, '.')
	if i < 0 {
		return stateClaims{}, errors.New("malformed state")
	}
	payload, err := base64.RawURLEncoding.DecodeString(tok[:i])
	if err != nil {
		return stateClaims{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(tok[i+1:])
	if err != nil {
		return stateClaims{}, err
	}
	mac := hmac.New(sha256.New, c.StateSecret)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return stateClaims{}, errors.New("bad state signature")
	}
	var s stateClaims
	if err := json.Unmarshal(payload, &s); err != nil {
		return stateClaims{}, err
	}
	if s.Dest == "" || time.Now().Unix() > s.Exp {
		return stateClaims{}, errors.New("expired state")
	}
	return s, nil
}
