package workspaces

import "net/http"

// WorkspaceCookie names the cookie that selects the active workspace. It's only
// a selector: the server re-verifies membership on every request, so a forged
// value can never reach a workspace the caller isn't a member of.
const WorkspaceCookie = "agenttasks_ws"

// PersonalID is the implicit personal workspace id for a user subject.
func PersonalID(sub string) string { return "u_" + sub }

// Active resolves which workspace a request targets for user `sub`: the cookie's
// workspace when `sub` is a member of it, otherwise the personal workspace. It
// also returns that workspace's stored task-id prefix ("" for personal, so the
// tenant layer applies its default).
func (s *Store) Active(sub string, r *http.Request) (id, prefix string) {
	personal := PersonalID(sub)
	c, err := r.Cookie(WorkspaceCookie)
	if err != nil || c.Value == "" || c.Value == personal {
		return personal, ""
	}
	if _, ok := s.Role(c.Value, sub); !ok {
		return personal, "" // cookie points at a workspace they're not in → personal
	}
	ws, err := s.Workspace(c.Value)
	if err != nil {
		return personal, ""
	}
	return ws.ID, ws.Prefix
}

// SetActiveCookie writes the active-workspace selector cookie.
func SetActiveCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name: WorkspaceCookie, Value: id, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: 365 * 24 * 60 * 60,
	})
}
