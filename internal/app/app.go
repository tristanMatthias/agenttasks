// Package app wires the control-plane HTTP handler: a JWKS Authenticator + a
// per-org tenant resolver plugged into tasks/pkg/httpapi. tasksd is embedded as
// a library; none of its code knows about tenants or the identity provider.
package app

import (
	"context"
	"crypto/rand"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tristanMatthias/agenttasks/internal/ghauth"
	"github.com/tristanMatthias/agenttasks/internal/oauth"
	"github.com/tristanMatthias/agenttasks/internal/oidc"
	"github.com/tristanMatthias/agenttasks/internal/tenant"
	"github.com/tristanMatthias/agenttasks/internal/workspaces"
	"github.com/tristanMatthias/tasks/pkg/httpapi"
	"github.com/tristanMatthias/tasks/pkg/mcpsrv"
	"github.com/tristanMatthias/tasks/web"
)

// Config configures the control plane.
type Config struct {
	JWKSURL        string
	Issuer         string
	EmailClaim     string // JWT claim holding the user's email (default "email")
	NameClaim      string // JWT claim holding the user's display name (default "name")
	DataDir        string
	Prefix         string
	PublishableKey string // (legacy hosted sign-in page) publishable key
	LoginURL       string // where the UI sends unauthenticated visitors (default /sign-in)
	PublicURL      string // public base URL (e.g. https://agenttasks.sh); enables the OAuth AS
	OAuthSecret    string // HMAC secret for OAuth client_ids/codes; random if empty
	BehindProxy    bool
	RateLimit      float64
	Logger         *slog.Logger

	// GitHub OAuth sign-in. When GitHubClientID is set, the site authenticates
	// humans via GitHub and a first-party session cookie.
	GitHubClientID     string
	GitHubClientSecret string
	SessionSecret      string // HMAC secret for the session cookie (falls back to OAuthSecret)
	// OwnerGitHubLogin/OwnerSubject preserve an existing board across the identity
	// switch: on that GitHub login's first sign-in, map it to OwnerSubject (the
	// board's existing tenant subject) instead of minting a fresh one.
	OwnerGitHubLogin string
	OwnerSubject     string

	// Auth overrides the built authenticator (used by tests). If set, JWKSURL is
	// ignored.
	Auth httpapi.Authenticator
	// OnTenantChange, if set, is invoked (org id + affected task ids) after any
	// mutation in a tenant. WebSocket broadcasting is wired automatically; this is
	// an extra hook (e.g. per-tenant backup/export).
	OnTenantChange func(org string, ids []string)
}

// App is the assembled control plane.
type App struct {
	Handler http.Handler
	Tenants *tenant.Manager
	ws      *workspaces.Store
}

// New builds the control plane.
func New(ctx context.Context, cfg Config) (*App, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	// The control store owns workspaces / members / invites (our self-hosted
	// org model) and the external-identity → subject map. The tenant resolver
	// uses it to route a human to their active workspace after checking
	// membership. Opened first so the authenticator can consult the identity map.
	wsStore, err := workspaces.Open(filepath.Join(cfg.DataDir, "control.db"))
	if err != nil {
		return nil, err
	}

	// registerAuthRoutes mounts any auth-provider routes (set below).
	var registerAuthRoutes func(*http.ServeMux)

	authn := cfg.Auth
	switch {
	case authn != nil:
		// test override
	case cfg.GitHubClientID != "":
		secret := cfg.SessionSecret
		if secret == "" {
			secret = cfg.OAuthSecret
		}
		if secret == "" {
			cfg.Logger.Warn("no SESSION_SECRET set — sessions will not survive a restart")
		}
		gh, err := ghauth.New(ghauth.Config{
			ClientID:      cfg.GitHubClientID,
			ClientSecret:  cfg.GitHubClientSecret,
			PublicURL:     cfg.PublicURL,
			SessionSecret: []byte(secret),
			Resolve:       githubResolver(wsStore, cfg.OwnerGitHubLogin, cfg.OwnerSubject),
		})
		if err != nil {
			return nil, err
		}
		authn = gh
		registerAuthRoutes = gh.Register
	default:
		a, err := oidc.New(ctx, oidc.Config{
			JWKSURL:    cfg.JWKSURL,
			Issuer:     cfg.Issuer,
			EmailClaim: cfg.EmailClaim,
			NameClaim:  cfg.NameClaim,
		})
		if err != nil {
			return nil, err
		}
		authn = a
	}
	jwtAuth := authn // the identity-provider authenticator (reads the user's session)

	mgr := tenant.New(tenant.Options{Dir: cfg.DataDir, Prefix: cfg.Prefix, Workspaces: wsStore})
	// Accept per-workspace API keys (tasks_<workspace>_<secret>) in front of sessions.
	authn = composite{jwt: jwtAuth, tenants: mgr}
	wsAPI := workspaces.NewAPI(wsStore, authn)
	burst := int(cfg.RateLimit) * 2
	if burst < 40 {
		burst = 40
	}
	loginURL := cfg.LoginURL
	if loginURL == "" {
		switch {
		case cfg.GitHubClientID != "":
			loginURL = "/auth/github/login"
		case cfg.PublishableKey != "":
			loginURL = "/sign-in"
		}
	}

	// OAuth authorization server (for browser MCP clients like claude.ai). It
	// authenticates the human via their session and mints a tenant-scoped key as
	// the access token — validated by the same composite authenticator.
	var oauthProv *oauth.Provider
	resourceMeta := ""
	if cfg.PublicURL != "" {
		secret := []byte(cfg.OAuthSecret)
		if len(secret) == 0 {
			secret = make([]byte, 32)
			_, _ = rand.Read(secret)
			cfg.Logger.Warn("AGENTTASKS_OAUTH_SECRET unset — using an ephemeral key; OAuth registrations reset on restart")
		}
		oauthProv = oauth.New(oauth.Config{
			Issuer:    cfg.PublicURL,
			Resource:  cfg.PublicURL + "/mcp",
			SignInURL: loginURL,
			HMACKey:   secret,
			Logger:    cfg.Logger,
			AuthUser: func(r *http.Request) (string, bool) {
				id, ok := jwtAuth.Authorize(r)
				if !ok {
					return "", false
				}
				// Default the picker to the human's ACTIVE workspace.
				wsID, _ := wsStore.Active(id.Subject, r)
				return wsID, true
			},
			Workspaces: func(r *http.Request) []oauth.Workspace {
				id, ok := jwtAuth.Authorize(r)
				if !ok {
					return nil
				}
				out := []oauth.Workspace{{ID: workspaces.PersonalID(id.Subject), Name: "Personal"}}
				mine, _ := wsStore.WorkspacesForUser(id.Subject)
				for _, w := range mine {
					out = append(out, oauth.Workspace{ID: w.ID, Name: w.Name})
				}
				return out
			},
			Mint: func(workspaceID string) (string, error) {
				c, err := mgr.CoreFor(workspaceID)
				if err != nil {
					return "", err
				}
				k, err := c.CreateKey("Claude web (OAuth)", "oauth")
				if err != nil {
					return "", err
				}
				return k.Secret, nil
			},
		})
		resourceMeta = cfg.PublicURL + "/.well-known/oauth-protected-resource"
	}

	// GitHub sign-in needs no in-page script and no CSP carve-out — the session
	// is a plain first-party cookie. The legacy hosted sign-in page (only when
	// GitHub isn't configured) still injects its boot script + matching CSP.
	injectHead, csp := "", ""
	if cfg.GitHubClientID == "" && cfg.PublishableKey != "" {
		frontendAPI := frontendAPIFromPublishableKey(cfg.PublishableKey)
		injectHead = clerkBootHead(cfg.PublishableKey, frontendAPI)
		csp = clerkCSP(frontendAPI)
	}

	srv := httpapi.New(httpapi.Config{
		Auth:                authn,
		Resolve:             mgr.Resolve,
		TopicFor:            mgr.TopicFor, // scope live (WebSocket) updates per workspace
		MCP:                 mcpsrv.HandlerResolved(mgr.Resolve), // per-tenant MCP at /mcp (auth-gated)
		LoginURL:            loginURL,
		ResourceMetadataURL: resourceMeta,
		InjectHead:          injectHead,
		CSP:                 csp,
		Static:              web.Static(),
		Logger:              cfg.Logger,
		BehindProxy:         cfg.BehindProxy,
		RateLimit:           cfg.RateLimit,
		RateBurst:           burst,
		Metrics:             true,
	})

	// Broadcast every tenant mutation to that workspace's WebSocket clients (topic
	// = org id, matching TopicFor). Wired now that srv exists; the manager applies
	// it to already-created Cores too. Compose any external hook the host passed.
	mgr.SetOnChange(func(org string, ids []string) {
		srv.Publish(org, ids)
		if cfg.OnTenantChange != nil {
			cfg.OnTenantChange(org, ids)
		}
	})

	// Front the tasks handler with the control-plane endpoints: the workspace API
	// + invite links (always), the auth-provider routes, and the OAuth AS.
	// Everything else falls through to the tasks handler.
	mux := http.NewServeMux()
	wsAPI.Register(mux)
	if registerAuthRoutes != nil {
		registerAuthRoutes(mux) // GitHub OAuth: /auth/github/{login,callback,logout}
	}
	if cfg.GitHubClientID == "" && cfg.PublishableKey != "" {
		sign := signInHandler(cfg.PublishableKey, frontendAPIFromPublishableKey(cfg.PublishableKey))
		mux.HandleFunc("GET /sign-in", sign)
		mux.HandleFunc("GET /sign-up", sign)
	}
	if oauthProv != nil {
		oauthProv.Register(mux)
	}
	mux.Handle("/", srv.Handler())

	return &App{Handler: mux, Tenants: mgr, ws: wsStore}, nil
}

// githubResolver maps a GitHub user to the canonical subject used by the tenant
// layer. It's stable: the mapping is persisted on first sign-in and reused after.
// If the login matches the configured owner and has no mapping yet, it's bound
// to ownerSubject — preserving that account's existing board across the switch.
func githubResolver(ws *workspaces.Store, ownerLogin, ownerSubject string) func(ghauth.GitHubUser) (string, error) {
	return func(u ghauth.GitHubUser) (string, error) {
		pid := strconv.FormatInt(u.ID, 10)
		if sub, ok := ws.LinkedSubject("github", pid); ok {
			return sub, nil
		}
		sub := "gh_" + pid
		if ownerLogin != "" && ownerSubject != "" && strings.EqualFold(u.Login, ownerLogin) {
			sub = ownerSubject
		}
		_ = ws.LinkIdentity("github", pid, sub, u.Login)
		return sub, nil
	}
}

// Close releases all tenant + control-store resources.
func (a *App) Close() {
	a.Tenants.Close()
	if a.ws != nil {
		a.ws.Close()
	}
}
