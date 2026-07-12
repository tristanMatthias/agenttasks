// Package oidc provides a JWT-via-JWKS Authenticator that plugs into
// tasks/pkg/httpapi. It verifies a session token (from an Authorization: Bearer
// header or a session cookie) against a JWKS endpoint and extracts the user's
// identity (subject + optional email/name). Clerk is just a specific JWKS
// issuer; nothing here is Clerk-specific.
//
// Workspace/tenant selection is NOT done here — the control plane maps a user to
// their workspaces itself (see internal/workspaces). This authenticator only
// answers "who is this request?".
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
	EmailClaim string // claim holding the user's email (default "email")
	NameClaim  string // claim holding the user's display name (default "name")
	CookieName string // session cookie to read (default "__session")
}

// Authenticator implements httpapi.Authenticator.
type Authenticator struct {
	kf         keyfunc.Keyfunc
	issuer     string
	emailClaim string
	nameClaim  string
	cookie     string
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
	emailClaim := cfg.EmailClaim
	if emailClaim == "" {
		emailClaim = "email"
	}
	nameClaim := cfg.NameClaim
	if nameClaim == "" {
		nameClaim = "name"
	}
	cookie := cfg.CookieName
	if cookie == "" {
		cookie = "__session"
	}
	return &Authenticator{kf: kf, issuer: cfg.Issuer, emailClaim: emailClaim, nameClaim: nameClaim, cookie: cookie}, nil
}

// Authorize verifies the token and returns the user identity: Subject is the
// stable user id (sub); Claims carries optional email/name for the workspace
// layer (member display + email-restricted invites).
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
	if sub == "" {
		return httpapi.Identity{}, false
	}
	out := map[string]string{}
	if email, _ := claims[a.emailClaim].(string); email != "" {
		out["email"] = email
	}
	if name, _ := claims[a.nameClaim].(string); name != "" {
		out["name"] = name
	}
	return httpapi.Identity{Subject: sub, Claims: out}, true
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}
