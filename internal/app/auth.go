package app

import (
	"net/http"
	"strings"

	"github.com/tristanMatthias/agenttasks/internal/tenant"
	"github.com/tristanMatthias/tasks/pkg/core"
	"github.com/tristanMatthias/tasks/pkg/httpapi"
)

// composite authorizes a request by either an API key or the identity provider's
// JWT. An "Authorization: Bearer tasks_<org>_<secret>" is routed to the org's
// tenant Core and verified there (bots/agents); anything else falls through to
// the JWT authenticator (browser sessions). Both resolve to Identity.Claims
// ["org"], which the tenant CoreResolver keys on — so the two paths converge.
type composite struct {
	jwt     httpapi.Authenticator
	tenants *tenant.Manager
}

func (a composite) Authorize(r *http.Request) (httpapi.Identity, bool) {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		tok := strings.TrimSpace(h[len("Bearer "):])
		if sel, secret, ok := core.SplitToken(tok); ok {
			// A tasks_ token: it must carry an org selector and verify against that
			// tenant — never fall through to the JWT path for a key attempt.
			if sel == "" {
				return httpapi.Identity{}, false
			}
			c, err := a.tenants.CoreFor(sel)
			if err != nil {
				return httpapi.Identity{}, false
			}
			k, err := c.VerifyKey(secret)
			if err != nil {
				return httpapi.Identity{}, false
			}
			return httpapi.Identity{Subject: "key:" + k.ID, Claims: map[string]string{"org": sel}}, true
		}
	}
	return a.jwt.Authorize(r)
}

// Login/Logout delegate to the identity authenticator when it drives a browser
// login flow (so POST /api/login + /api/logout are mounted and reach it).
func (a composite) Login(w http.ResponseWriter, r *http.Request) {
	if lp, ok := a.jwt.(httpapi.LoginProvider); ok {
		lp.Login(w, r)
		return
	}
	http.Error(w, "login not supported", http.StatusNotFound)
}

func (a composite) Logout(w http.ResponseWriter, r *http.Request) {
	if lp, ok := a.jwt.(httpapi.LoginProvider); ok {
		lp.Logout(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
