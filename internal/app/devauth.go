package app

import (
	"net/http"
	"strings"

	"github.com/tristanMatthias/tasks/pkg/httpapi"
)

// DevAuth is a local-development authenticator: a fixed token (as a Bearer
// header or the "agenttasks_dev" cookie) authenticates as one stable user, so
// the whole self-hosted workspace system runs without an identity provider.
// NEVER enable in production — it's gated behind AGENTTASKS_DEV_TOKEN.
type DevAuth struct{ Token string }

// Authorize implements httpapi.Authenticator.
func (d DevAuth) Authorize(r *http.Request) (httpapi.Identity, bool) {
	tok := ""
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		tok = strings.TrimSpace(h[7:])
	}
	if tok == "" {
		if c, err := r.Cookie("agenttasks_dev"); err == nil {
			tok = c.Value
		}
	}
	if tok == "" || tok != d.Token {
		return httpapi.Identity{}, false
	}
	return httpapi.Identity{
		Subject: "dev_user",
		Claims:  map[string]string{"email": "dev@local", "name": "Dev User"},
	}, true
}
