package workspaces

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tristanMatthias/tasks/pkg/httpapi"
)

// inviteTTL is how long a shareable invite link stays valid.
const inviteTTL = 7 * 24 * time.Hour

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
	mux.HandleFunc("GET /invite/{token}", a.inviteLanding)
	mux.HandleFunc("POST /invite/{token}/accept", a.acceptInvite)
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
	SetActiveCookie(w, r, ws.ID)
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
	SetActiveCookie(w, r, target)
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
	if err := a.store.UpdateMemberRole(wsID, userID, body.Role); err != nil {
		if errors.Is(err, ErrLastAdmin) {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
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
	if err := a.store.RemoveMember(wsID, userID); err != nil {
		if errors.Is(err, ErrLastAdmin) {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		serverErr(w, err)
		return
	}
	if userID == p.sub {
		SetActiveCookie(w, r, PersonalID(p.sub)) // left → back to personal
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
	inv := Invite{
		Token: randID("", 16), WorkspaceID: wsID, Role: role,
		Email:     strings.TrimSpace(body.Email),
		CreatedBy: p.sub,
		ExpiresAt: time.Now().UTC().Add(inviteTTL).Format(time.RFC3339Nano),
	}
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
	SetActiveCookie(w, r, PersonalID(p.sub))
	ok200(w)
}

// inviteLanding (GET) shows a confirmation page for a shared invite link. It
// never mutates — joining happens on an explicit same-origin POST — so a
// cross-site request (an <img> or link to the URL) can't silently add the
// victim to a workspace (CSRF). A logged-out visitor is sent to sign in first.
func (a *API) inviteLanding(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if _, ok := a.who(r); !ok {
		http.Redirect(w, r, "/sign-in?redirect_url="+url.QueryEscape("/invite/"+token), http.StatusFound)
		return
	}
	inv, err := a.store.Invite(token)
	if err != nil || inv.AcceptedAt != "" || (inv.ExpiresAt != "" && now() > inv.ExpiresAt) {
		http.Redirect(w, r, "/?invite=invalid", http.StatusFound)
		return
	}
	ws, err := a.store.Workspace(inv.WorkspaceID)
	if err != nil {
		http.Redirect(w, r, "/?invite=invalid", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = inviteConfirmTmpl.Execute(w, map[string]string{"Token": token, "Name": ws.Name})
}

// acceptInvite (POST) performs the join. It's same-origin + cookie-authed; the
// Lax session cookie isn't sent on a cross-site POST, so CSRF can't reach it.
func (a *API) acceptInvite(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	p, ok := a.who(r)
	if !ok {
		unauthorized(w)
		return
	}
	wsID, err := a.store.AcceptInvite(token, p.sub, p.email, p.name)
	if err != nil {
		http.Redirect(w, r, "/?invite=error", http.StatusFound)
		return
	}
	SetActiveCookie(w, r, wsID)
	http.Redirect(w, r, "/", http.StatusFound)
}

// A minimal, dependency-free confirm page (the board's own styling isn't
// available at this layer). {{.Name}} is auto-escaped by html/template.
var inviteConfirmTmpl = template.Must(template.New("invite").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Join workspace</title>
<style>
  :root{color-scheme:light dark}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
       font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f1115;color:#c0caf5}
  .card{max-width:360px;padding:28px;border:1px solid #2a2f3d;border-radius:14px;background:#161922;text-align:center}
  h1{font-size:18px;margin:0 0 6px} p{color:#8b93a7;font-size:14px;margin:0 0 20px}
  .name{color:#c0caf5;font-weight:600}
  button{width:100%;padding:10px;border:0;border-radius:8px;background:#7aa2f7;color:#0f1115;font-weight:600;font-size:14px;cursor:pointer}
  a{display:inline-block;margin-top:12px;color:#8b93a7;font-size:13px;text-decoration:none}
</style></head>
<body><div class="card">
  <h1>Join workspace</h1>
  <p>You've been invited to join <span class="name">{{.Name}}</span>.</p>
  <form method="post" action="/invite/{{.Token}}/accept"><button type="submit">Join workspace</button></form>
  <a href="/">Not now</a>
</div></body></html>`))

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
