// Package oidc provides a JWT-via-JWKS Authenticator that plugs into
// tasks/pkg/httpapi. It verifies a session token (from an Authorization: Bearer
// header or a session cookie) against a JWKS endpoint and extracts the tenant
// (organization) id from a configurable claim. Clerk is just a specific JWKS
// issuer + org claim; nothing here is Clerk-specific.
package oidc

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/tristanMatthias/tasks/pkg/httpapi"
)

// Config configures the authenticator.
type Config struct {
	JWKSURL    string // JWKS endpoint (e.g. Clerk's .well-known/jwks.json)
	Issuer     string // optional expected "iss"
	OrgClaim   string // claim holding the tenant id (default "org_id")
	CookieName string // session cookie to read (default "__session")
	// RequireOrg rejects tokens without an org claim (multi-tenant). When false,
	// a token without an org resolves to a per-user tenant (Subject).
	RequireOrg bool
}

// Authenticator implements httpapi.Authenticator.
type Authenticator struct {
	kf         keyfunc.Keyfunc
	issuer     string
	orgClaim   string
	cookie     string
	requireOrg bool
}

// New builds an Authenticator, fetching the JWKS (cached + auto-refreshed).
func New(ctx context.Context, cfg Config) (*Authenticator, error) {
	if cfg.JWKSURL == "" {
		return nil, fmt.Errorf("oidc: JWKSURL required")
	}
	kf, err := keyfunc.NewDefaultCtx(ctx, []string{cfg.JWKSURL})
	if err != nil {
		return nil, fmt.Errorf("oidc: load jwks: %w", err)
	}
	orgClaim := cfg.OrgClaim
	if orgClaim == "" {
		orgClaim = "org_id"
	}
	cookie := cfg.CookieName
	if cookie == "" {
		cookie = "__session"
	}
	return &Authenticator{kf: kf, issuer: cfg.Issuer, orgClaim: orgClaim, cookie: cookie, requireOrg: cfg.RequireOrg}, nil
}

// Authorize verifies the token and returns the tenant identity. The tenant id
// is placed in Claims["org"] (the org claim, or the subject when no org and
// RequireOrg is false) — that's what the tenant CoreResolver keys on.
func (a *Authenticator) Authorize(r *http.Request) (httpapi.Identity, bool) {
	raw := bearer(r)
	if raw == "" {
		if c, err := r.Cookie(a.cookie); err == nil {
			raw = c.Value
		}
	}
	if raw == "" {
		return httpapi.Identity{}, false
	}
	tok, err := jwt.Parse(raw, a.kf.Keyfunc, jwt.WithValidMethods([]string{"RS256", "ES256"}))
	if err != nil || !tok.Valid {
		return httpapi.Identity{}, false
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return httpapi.Identity{}, false
	}
	if a.issuer != "" {
		if iss, _ := claims["iss"].(string); iss != a.issuer {
			return httpapi.Identity{}, false
		}
	}
	sub, _ := claims["sub"].(string)
	org, _ := claims[a.orgClaim].(string)
	if org == "" {
		if a.requireOrg {
			return httpapi.Identity{}, false
		}
		org = "u_" + sub // fall back to a per-user tenant
	}
	if org == "" {
		return httpapi.Identity{}, false
	}
	return httpapi.Identity{Subject: sub, Claims: map[string]string{"org": org}}, true
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}
