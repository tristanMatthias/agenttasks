package workspaces

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/tristanMatthias/tasks/pkg/httpapi"
)

// API serves the control-plane workspace endpoints (list/create/switch, members,
// invites). Authentication reuses the tasks Authenticator: it identifies the
// human by their subject and rejects API keys (which carry an org selector and
// have no business managing workspaces).
type API struct {
	store *Store
	auth  httpapi.Authenticator
}

// NewAPI builds the workspace API.
func NewAPI(store *Store, auth httpapi.Authenticator) *API { return &API{store: store, auth: auth} }

// Register mounts the routes on mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/workspaces", a.list)
	mux.HandleFunc("POST /api/workspaces", a.create)
	mux.HandleFunc("POST /api/workspaces/switch", a.switchWS)
	mux.HandleFunc("GET /api/workspaces/{id}/members", a.members)
	mux.HandleFunc("PATCH /api/workspaces/{id}/members/{userId}", a.updateMember)
	mux.HandleFunc("DELETE /api/workspaces/{id}/members/{userId}", a.removeMember)
	mux.HandleFunc("GET /api/workspaces/{id}/invites", a.listInvites)
	mux.HandleFunc("POST /api/workspaces/{id}/invites", a.createInvite)
	mux.HandleFunc("DELETE /api/workspaces/{id}/invites/{token}", a.revokeInvite)
	mux.HandleFunc("PATCH /api/workspaces/{id}", a.rename)
	mux.HandleFunc("DELETE /api/workspaces/{id}", a.deleteWS)
	mux.HandleFunc("GET /invite/{token}", a.acceptLink)
}

type principal struct{ sub, email, name string }

// who authenticates the request as a human principal (not an API key).
func (a *API) who(r *http.Request) (principal, bool) {
	id, ok := a.auth.Authorize(r)
	if !ok || id.Subject == "" || id.Claims["org"] != "" {
		return principal{}, false
	}
	return principal{sub: id.Subject, email: id.Claims["email"], name: id.Claims["name"]}, true
}

func (a *API) isAdmin(wsID, sub string) bool {
	role, ok := a.store.Role(wsID, sub)
	return ok && role == RoleAdmin
}

// ---- handlers ----

type wsView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Prefix   string `json:"prefix"`
	Role     string `json:"role"`
	Personal bool   `json:"personal"`
}

func (a *API) list(w http.ResponseWriter, r *http.Request) {
	p, ok := a.who(r)
	if !ok {
		unauthorized(w)
		return
	}
	views := []wsView{{ID: PersonalID(p.sub), Name: "Personal", Role: RoleAdmin, Personal: true}}
	mine, err := a.store.WorkspacesForUser(p.sub)
	if err != nil {
		serverErr(w, err)
		return
	}
	for _, m := range mine {
		views = append(views, wsView{ID: m.ID, Name: m.Name, Prefix: m.Prefix, Role: m.Role})
	}
	active, _ := a.store.Active(p.sub, r)
	writeJSON(w, http.StatusOK, map[string]any{"workspaces": views, "active": active, "me": p.sub})
}

func (a *API) create(w http.ResponseWriter, r *http.Request) {
	p, ok := a.who(r)
	if !ok {
		unauthorized(w)
		return
	}
	var body struct{ Name string `json:"name"` }
	if !readJSON(w, r, &body) {
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		writeErr(w, http.StatusBadRequest, "name required")
		return
	}
	ws := Workspace{ID: randID("ws_", 8), Name: name, CreatedBy: p.sub}
	ws.Slug = slugify(name)
	if ws.Slug == "" {
		ws.Slug = "ws"
	}
	ws.Prefix = ws.Slug
	if err := a.store.CreateWorkspace(ws, p.email, p.name); err != nil {
		serverErr(w, err)
		return
	}
	SetActiveCookie(w, ws.ID)
	writeJSON(w, http.StatusCreated, wsView{ID: ws.ID, Name: ws.Name, Prefix: ws.Prefix, Role: RoleAdmin})
}

func (a *API) switchWS(w http.ResponseWriter, r *http.Request) {
	p, ok := a.who(r)
	if !ok {
		unauthorized(w)
		return
	}
	var body struct{ ID string `json:"id"` }
	if !readJSON(w, r, &body) {
		return
	}
	if body.ID != "" && body.ID != PersonalID(p.sub) {
		if _, member := a.store.Role(body.ID, p.sub); !member {
			writeErr(w, http.StatusForbidden, "not a member")
			return
		}
	}
	target := body.ID
	if target == "" {
		target = PersonalID(p.sub)
	}
	SetActiveCookie(w, target)
	writeJSON(w, http.StatusOK, map[string]any{"active": target})
}

func (a *API) members(w http.ResponseWriter, r *http.Request) {
	p, ok := a.who(r)
	if !ok {
		unauthorized(w)
		return
	}
	wsID := r.PathValue("id")
	if _, member := a.store.Role(wsID, p.sub); !member {
		writeErr(w, http.StatusForbidden, "not a member")
		return
	}
	list, err := a.store.Members(wsID)
	if err != nil {
		serverErr(w, err)
		return
	}
	if list == nil {
		list = []Member{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) updateMember(w http.ResponseWriter, r *http.Request) {
	p, ok := a.who(r)
	if !ok {
		unauthorized(w)
		return
	}
	wsID, userID := r.PathValue("id"), r.PathValue("userId")
	if !a.isAdmin(wsID, p.sub) {
		writeErr(w, http.StatusForbidden, "admin only")
		return
	}
	var body struct{ Role string `json:"role"` }
	if !readJSON(w, r, &body) {
		return
	}
	if body.Role != RoleAdmin && body.Role != RoleMember {
		writeErr(w, http.StatusBadRequest, "invalid role")
		return
	}
	// Don't demote the last admin.
	if body.Role == RoleMember {
		if cur, _ := a.store.Role(wsID, userID); cur == RoleAdmin {
			if n, _ := a.store.CountAdmins(wsID); n <= 1 {
				writeErr(w, http.StatusBadRequest, "workspace needs an admin")
				return
			}
		}
	}
	if err := a.store.UpdateMemberRole(wsID, userID, body.Role); err != nil {
		serverErr(w, err)
		return
	}
	ok200(w)
}

func (a *API) removeMember(w http.ResponseWriter, r *http.Request) {
	p, ok := a.who(r)
	if !ok {
		unauthorized(w)
		return
	}
	wsID, userID := r.PathValue("id"), r.PathValue("userId")
	// Admins can remove anyone; anyone can remove themselves (leave).
	if userID != p.sub && !a.isAdmin(wsID, p.sub) {
		writeErr(w, http.StatusForbidden, "admin only")
		return
	}
	if cur, _ := a.store.Role(wsID, userID); cur == RoleAdmin {
		if n, _ := a.store.CountAdmins(wsID); n <= 1 {
			writeErr(w, http.StatusBadRequest, "workspace needs an admin")
			return
		}
	}
	if err := a.store.RemoveMember(wsID, userID); err != nil {
		serverErr(w, err)
		return
	}
	if userID == p.sub {
		SetActiveCookie(w, PersonalID(p.sub)) // left → back to personal
	}
	ok200(w)
}

func (a *API) listInvites(w http.ResponseWriter, r *http.Request) {
	p, ok := a.who(r)
	if !ok {
		unauthorized(w)
		return
	}
	wsID := r.PathValue("id")
	if !a.isAdmin(wsID, p.sub) {
		writeErr(w, http.StatusForbidden, "admin only")
		return
	}
	pend, err := a.store.PendingInvites(wsID)
	if err != nil {
		serverErr(w, err)
		return
	}
	out := make([]map[string]any, 0, len(pend))
	for _, inv := range pend {
		out = append(out, inviteView(r, inv))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) createInvite(w http.ResponseWriter, r *http.Request) {
	p, ok := a.who(r)
	if !ok {
		unauthorized(w)
		return
	}
	wsID := r.PathValue("id")
	if !a.isAdmin(wsID, p.sub) {
		writeErr(w, http.StatusForbidden, "admin only")
		return
	}
	var body struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	role := body.Role
	if role != RoleAdmin {
		role = RoleMember
	}
	inv := Invite{Token: randID("", 16), WorkspaceID: wsID, Role: role, Email: strings.TrimSpace(body.Email), CreatedBy: p.sub}
	if err := a.store.CreateInvite(inv); err != nil {
		serverErr(w, err)
		return
	}
	stored, _ := a.store.Invite(inv.Token)
	writeJSON(w, http.StatusCreated, inviteView(r, stored))
}

func (a *API) revokeInvite(w http.ResponseWriter, r *http.Request) {
	p, ok := a.who(r)
	if !ok {
		unauthorized(w)
		return
	}
	wsID := r.PathValue("id")
	if !a.isAdmin(wsID, p.sub) {
		writeErr(w, http.StatusForbidden, "admin only")
		return
	}
	if err := a.store.RevokeInvite(r.PathValue("token")); err != nil {
		serverErr(w, err)
		return
	}
	ok200(w)
}

func (a *API) rename(w http.ResponseWriter, r *http.Request) {
	p, ok := a.who(r)
	if !ok {
		unauthorized(w)
		return
	}
	wsID := r.PathValue("id")
	if !a.isAdmin(wsID, p.sub) {
		writeErr(w, http.StatusForbidden, "admin only")
		return
	}
	var body struct{ Name string `json:"name"` }
	if !readJSON(w, r, &body) {
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		writeErr(w, http.StatusBadRequest, "name required")
		return
	}
	if err := a.store.Rename(wsID, name); err != nil {
		serverErr(w, err)
		return
	}
	ok200(w)
}

func (a *API) deleteWS(w http.ResponseWriter, r *http.Request) {
	p, ok := a.who(r)
	if !ok {
		unauthorized(w)
		return
	}
	wsID := r.PathValue("id")
	if !a.isAdmin(wsID, p.sub) {
		writeErr(w, http.StatusForbidden, "admin only")
		return
	}
	if err := a.store.DeleteWorkspace(wsID); err != nil {
		serverErr(w, err)
		return
	}
	SetActiveCookie(w, PersonalID(p.sub))
	ok200(w)
}

// acceptLink handles a shared invite link: a logged-in visitor joins the
// workspace and lands on it; a logged-out visitor is sent to sign in first.
func (a *API) acceptLink(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	p, ok := a.who(r)
	if !ok {
		http.Redirect(w, r, "/sign-in?redirect_url="+urlEscape("/invite/"+token), http.StatusFound)
		return
	}
	wsID, err := a.store.AcceptInvite(token, p.sub, p.email, p.name)
	if err != nil {
		http.Redirect(w, r, "/?invite=error", http.StatusFound)
		return
	}
	SetActiveCookie(w, wsID)
	http.Redirect(w, r, "/", http.StatusFound)
}

// ---- helpers ----

func inviteView(r *http.Request, inv Invite) map[string]any {
	return map[string]any{
		"token": inv.Token,
		"role":  inv.Role,
		"email": inv.Email,
		"url":   inviteURL(r, inv.Token),
	}
}

func inviteURL(r *http.Request, token string) string {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/invite/" + token
}

func randID(prefix string, n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// slugify turns a name into a task-id prefix: lowercase [a-z0-9], other runs
// collapsed to a single '-', trimmed, capped, never trailing '-'.
func slugify(s string) string {
	const maxLen = 24
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if b.Len() > 0 && !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > maxLen {
		out = strings.TrimRight(out[:maxLen], "-")
	}
	return out
}

func urlEscape(s string) string {
	// Minimal escape for a same-site path in a query value.
	return strings.NewReplacer("&", "%26", "#", "%23", "?", "%3F", " ", "%20").Replace(s)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Body == nil {
		writeErr(w, http.StatusBadRequest, "empty body")
		return false
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return false
	}
	return true
}

func ok200(w http.ResponseWriter)        { writeJSON(w, http.StatusOK, map[string]any{"ok": true}) }
func unauthorized(w http.ResponseWriter) { writeErr(w, http.StatusUnauthorized, "unauthorized") }
func serverErr(w http.ResponseWriter, err error) {
	writeErr(w, http.StatusInternalServerError, err.Error())
}
