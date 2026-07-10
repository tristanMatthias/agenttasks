// Package app wires the control-plane HTTP handler: a JWKS Authenticator + a
// per-org tenant resolver plugged into tasks/pkg/httpapi. tasksd is embedded as
// a library; none of its code knows about tenants or the identity provider.
package app

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/tristanMatthias/agenttasks/internal/oidc"
	"github.com/tristanMatthias/agenttasks/internal/tenant"
	"github.com/tristanMatthias/tasks/pkg/httpapi"
	"github.com/tristanMatthias/tasks/web"
)

// Config configures the control plane.
type Config struct {
	JWKSURL        string
	Issuer         string
	OrgClaim       string
	DataDir        string
	Prefix         string
	PublishableKey string // Clerk pk_live_/pk_test_ for the sign-in page
	LoginURL       string // where the UI sends unauthenticated visitors (default /sign-in)
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
}

// New builds the control plane.
func New(ctx context.Context, cfg Config) (*App, error) {
	authn := cfg.Auth
	if authn == nil {
		a, err := oidc.New(ctx, oidc.Config{JWKSURL: cfg.JWKSURL, Issuer: cfg.Issuer, OrgClaim: cfg.OrgClaim})
		if err != nil {
			return nil, err
		}
		authn = a
	}
	mgr := tenant.New(tenant.Options{Dir: cfg.DataDir, Prefix: cfg.Prefix, OnChange: cfg.OnTenantChange})
	burst := int(cfg.RateLimit) * 2
	if burst < 40 {
		burst = 40
	}
	loginURL := cfg.LoginURL
	if loginURL == "" && cfg.PublishableKey != "" {
		loginURL = "/sign-in"
	}
	srv := httpapi.New(httpapi.Config{
		Auth:        authn,
		Resolve:     mgr.Resolve,
		LoginURL:    loginURL,
		Static:      web.Static(),
		Logger:      cfg.Logger,
		BehindProxy: cfg.BehindProxy,
		RateLimit:   cfg.RateLimit,
		RateBurst:   burst,
		Metrics:     true,
	})

	// Front the tasks handler with the hosted sign-in page (ClerkJS).
	handler := http.Handler(srv.Handler())
	if cfg.PublishableKey != "" {
		frontendAPI := frontendAPIFromPublishableKey(cfg.PublishableKey)
		sign := signInHandler(cfg.PublishableKey, frontendAPI)
		mux := http.NewServeMux()
		mux.HandleFunc("GET /sign-in", sign)
		mux.HandleFunc("GET /sign-up", sign)
		mux.Handle("/", srv.Handler())
		handler = mux
	}
	return &App{Handler: handler, Tenants: mgr}, nil
}

// Close releases all tenant resources.
func (a *App) Close() { a.Tenants.Close() }
