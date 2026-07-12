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
	PublishableKey string // Clerk pk_live_/pk_test_ for the sign-in page
	LoginURL       string // where the UI sends unauthenticated visitors (default /sign-in)
	PublicURL      string // public base URL (e.g. https://agenttasks.sh); enables the OAuth AS
	OAuthSecret    string // HMAC secret for OAuth client_ids/codes; random if empty
	BehindProxy    bool
	RateLimit      float64
	Logger         *slog.Logger

	// Auth overrides the built authenticator (used by tests). If set, JWKSURL is
	// ignored.
	Auth httpapi.Authenticator
	// OnTenantChange is invoked (with the org id) after any mutation in a tenant.
	OnTenantChange func(org string)
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
	authn := cfg.Auth
	if authn == nil {
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

	// The control store owns workspaces / members / invites (our self-hosted
	// replacement for Clerk Organizations). The tenant resolver uses it to route
	// a human to their active workspace after checking membership.
	wsStore, err := workspaces.Open(filepath.Join(cfg.DataDir, "control.db"))
	if err != nil {
		return nil, err
	}
	mgr := tenant.New(tenant.Options{Dir: cfg.DataDir, Prefix: cfg.Prefix, OnChange: cfg.OnTenantChange, Workspaces: wsStore})
	// Accept per-workspace API keys (tasks_<workspace>_<secret>) in front of sessions.
	authn = composite{jwt: jwtAuth, tenants: mgr}
	wsAPI := workspaces.NewAPI(wsStore, authn)
	burst := int(cfg.RateLimit) * 2
	if burst < 40 {
		burst = 40
	}
	loginURL := cfg.LoginURL
	if loginURL == "" && cfg.PublishableKey != "" {
		loginURL = "/sign-in"
	}

	// OAuth authorization server (for browser MCP clients like claude.ai). It
	// authenticates the human via their Clerk session and mints a tenant-scoped
	// key as the access token — validated by the same composite authenticator.
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
			SignInURL: "/sign-in",
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

	// Keep Clerk's session alive on the board page (ClerkJS refreshes the
	// short-lived __session cookie), so refreshes don't bounce through /sign-in.
	injectHead := ""
	if cfg.PublishableKey != "" {
		injectHead = clerkBootHead(cfg.PublishableKey, frontendAPIFromPublishableKey(cfg.PublishableKey))
	}

	srv := httpapi.New(httpapi.Config{
		Auth:                authn,
		Resolve:             mgr.Resolve,
		MCP:                 mcpsrv.HandlerResolved(mgr.Resolve), // per-tenant MCP at /mcp (auth-gated)
		LoginURL:            loginURL,
		ResourceMetadataURL: resourceMeta,
		InjectHead:          injectHead,
		Static:              web.Static(),
		Logger:              cfg.Logger,
		BehindProxy:         cfg.BehindProxy,
		RateLimit:           cfg.RateLimit,
		RateBurst:           burst,
		Metrics:             true,
	})

	// Front the tasks handler with the control-plane endpoints: the workspace API
	// + invite links (always), plus the sign-in page and OAuth AS when Clerk is
	// configured. Everything else falls through to the tasks handler.
	mux := http.NewServeMux()
	wsAPI.Register(mux)
	if cfg.PublishableKey != "" {
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

// Close releases all tenant + control-store resources.
func (a *App) Close() {
	a.Tenants.Close()
	if a.ws != nil {
		a.ws.Close()
	}
}
