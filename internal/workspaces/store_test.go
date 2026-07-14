package workspaces

import (
	"path/filepath"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCreateAndListForUser(t *testing.T) {
	s := openTest(t)
	ws := Workspace{ID: "ws_1", Name: "Acme", Slug: "acme", Prefix: "acme", CreatedBy: "user_1"}
	if err := s.CreateWorkspace(ws, "a@x.com", "Alice"); err != nil {
		t.Fatal(err)
	}
	// Creator is an admin member and sees the workspace.
	got, err := s.WorkspacesForUser("user_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "ws_1" || got[0].Role != RoleAdmin {
		t.Fatalf("WorkspacesForUser = %+v, want one admin membership of ws_1", got)
	}
	// A non-member sees nothing.
	if other, _ := s.WorkspacesForUser("user_2"); len(other) != 0 {
		t.Fatalf("non-member sees %d workspaces, want 0", len(other))
	}
	if role, ok := s.Role("ws_1", "user_2"); ok {
		t.Fatalf("non-member has role %q, want none", role)
	}
}

func TestInviteAcceptFlow(t *testing.T) {
	s := openTest(t)
	_ = s.CreateWorkspace(Workspace{ID: "ws_1", Name: "Acme", Slug: "acme", Prefix: "acme", CreatedBy: "user_1"}, "a@x.com", "Alice")

	if err := s.CreateInvite(Invite{Token: "tok1", WorkspaceID: "ws_1", Role: RoleMember}); err != nil {
		t.Fatal(err)
	}
	if pend, _ := s.PendingInvites("ws_1"); len(pend) != 1 {
		t.Fatalf("pending invites = %d, want 1", len(pend))
	}

	wsID, err := s.AcceptInvite("tok1", "user_2", "b@x.com", "Bob")
	if err != nil {
		t.Fatal(err)
	}
	if wsID != "ws_1" {
		t.Fatalf("accepted into %q, want ws_1", wsID)
	}
	if role, ok := s.Role("ws_1", "user_2"); !ok || role != RoleMember {
		t.Fatalf("bob role = %q ok=%v, want member", role, ok)
	}
	// Invite is now used and no longer pending.
	if pend, _ := s.PendingInvites("ws_1"); len(pend) != 0 {
		t.Fatalf("pending after accept = %d, want 0", len(pend))
	}
	// Re-accepting a used invite fails.
	if _, err := s.AcceptInvite("tok1", "user_3", "c@x.com", "Cara"); err == nil {
		t.Fatal("re-accepting a used invite should fail")
	}
}

func TestEmailRestrictedInvite(t *testing.T) {
	s := openTest(t)
	_ = s.CreateWorkspace(Workspace{ID: "ws_1", Name: "Acme", Slug: "acme", Prefix: "acme", CreatedBy: "user_1"}, "a@x.com", "Alice")
	_ = s.CreateInvite(Invite{Token: "tok1", WorkspaceID: "ws_1", Role: RoleMember, Email: "invited@x.com"})

	if _, err := s.AcceptInvite("tok1", "user_2", "someoneelse@x.com", "Eve"); err == nil {
		t.Fatal("accepting an email-restricted invite with the wrong email should fail")
	}
	if _, err := s.AcceptInvite("tok1", "user_2", "invited@x.com", "Bob"); err != nil {
		t.Fatalf("accepting with the matching email should succeed: %v", err)
	}
}

func TestRolesAndRemoval(t *testing.T) {
	s := openTest(t)
	_ = s.CreateWorkspace(Workspace{ID: "ws_1", Name: "Acme", Slug: "acme", Prefix: "acme", CreatedBy: "user_1"}, "a@x.com", "Alice")
	_ = s.CreateInvite(Invite{Token: "t", WorkspaceID: "ws_1", Role: RoleMember})
	_, _ = s.AcceptInvite("t", "user_2", "b@x.com", "Bob")

	if n, _ := s.CountAdmins("ws_1"); n != 1 {
		t.Fatalf("admins = %d, want 1", n)
	}
	if err := s.UpdateMemberRole("ws_1", "user_2", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.CountAdmins("ws_1"); n != 2 {
		t.Fatalf("admins after promote = %d, want 2", n)
	}
	if err := s.RemoveMember("ws_1", "user_2"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Role("ws_1", "user_2"); ok {
		t.Fatal("removed member still has a role")
	}
}

// The only admin can't be demoted or removed (guarded atomically in the store),
// but once a second admin exists the first can go.
func TestLastAdminGuard(t *testing.T) {
	s := openTest(t)
	_ = s.CreateWorkspace(Workspace{ID: "ws_1", Name: "A", Slug: "a", Prefix: "a", CreatedBy: "u1"}, "", "")

	if err := s.UpdateMemberRole("ws_1", "u1", RoleMember); err != ErrLastAdmin {
		t.Fatalf("demote last admin = %v, want ErrLastAdmin", err)
	}
	if err := s.RemoveMember("ws_1", "u1"); err != ErrLastAdmin {
		t.Fatalf("remove last admin = %v, want ErrLastAdmin", err)
	}

	_ = s.CreateInvite(Invite{Token: "t", WorkspaceID: "ws_1", Role: RoleAdmin})
	if _, err := s.AcceptInvite("t", "u2", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveMember("ws_1", "u1"); err != nil {
		t.Fatalf("remove admin with a spare = %v, want nil", err)
	}
	if n, _ := s.CountAdmins("ws_1"); n != 1 {
		t.Fatalf("admins after removal = %d, want 1", n)
	}
}

// An expired invite is rejected and not listed as pending.
func TestExpiredInvite(t *testing.T) {
	s := openTest(t)
	_ = s.CreateWorkspace(Workspace{ID: "ws_1", Name: "A", Slug: "a", Prefix: "a", CreatedBy: "u1"}, "", "")
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	_ = s.CreateInvite(Invite{Token: "t", WorkspaceID: "ws_1", Role: RoleMember, ExpiresAt: past})

	if _, err := s.AcceptInvite("t", "u2", "", ""); err != ErrInviteExpired {
		t.Fatalf("expired accept = %v, want ErrInviteExpired", err)
	}
	if p, _ := s.PendingInvites("ws_1"); len(p) != 0 {
		t.Fatalf("expired invite still pending: %d", len(p))
	}
}

// An email-restricted invite is rejected when the accepter has NO email (can't
// prove they match) — no silent bypass.
func TestRestrictedInviteNoEmailRejected(t *testing.T) {
	s := openTest(t)
	_ = s.CreateWorkspace(Workspace{ID: "ws_1", Name: "A", Slug: "a", Prefix: "a", CreatedBy: "u1"}, "", "")
	_ = s.CreateInvite(Invite{Token: "t", WorkspaceID: "ws_1", Role: RoleMember, Email: "wanted@x.com"})
	if _, err := s.AcceptInvite("t", "u2", "", "Nobody"); err != ErrInviteEmail {
		t.Fatalf("restricted accept with no email = %v, want ErrInviteEmail", err)
	}
}

// Accepting as an already-member keeps the existing (higher) role and burns the invite.
func TestAcceptAsExistingMember(t *testing.T) {
	s := openTest(t)
	_ = s.CreateWorkspace(Workspace{ID: "ws_1", Name: "A", Slug: "a", Prefix: "a", CreatedBy: "u1"}, "", "")
	_ = s.CreateInvite(Invite{Token: "t", WorkspaceID: "ws_1", Role: RoleMember})
	wsID, err := s.AcceptInvite("t", "u1", "", "") // u1 is already admin
	if err != nil || wsID != "ws_1" {
		t.Fatalf("accept as member = %v %q", err, wsID)
	}
	if r, _ := s.Role("ws_1", "u1"); r != RoleAdmin {
		t.Fatalf("existing role changed to %q, want admin", r)
	}
}

func TestDeleteCascades(t *testing.T) {
	s := openTest(t)
	_ = s.CreateWorkspace(Workspace{ID: "ws_1", Name: "Acme", Slug: "acme", Prefix: "acme", CreatedBy: "user_1"}, "a@x.com", "Alice")
	_ = s.CreateInvite(Invite{Token: "t", WorkspaceID: "ws_1", Role: RoleMember})
	if err := s.DeleteWorkspace("ws_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Workspace("ws_1"); err != ErrNotFound {
		t.Fatalf("workspace after delete: err=%v, want ErrNotFound", err)
	}
	if got, _ := s.WorkspacesForUser("user_1"); len(got) != 0 {
		t.Fatalf("memberships after delete = %d, want 0", len(got))
	}
	if pend, _ := s.PendingInvites("ws_1"); len(pend) != 0 {
		t.Fatalf("invites after delete = %d, want 0", len(pend))
	}
}

func TestRepoLinksAndInstallations(t *testing.T) {
	s := openTest(t)

	// Webhook arrives BEFORE the user finishes the connect setup: repos are
	// stashed but not yet linked (no workspace known).
	if err := s.AddInstallRepos(100, []string{"me/a", "me/b"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.RepoWorkspace("me/a"); ok {
		t.Fatal("repo should not be linked before the installation is bound")
	}

	// Setup binds the installation → workspace, which links the stashed repos.
	if err := s.SetInstallation(100, "ws_x", "octo"); err != nil {
		t.Fatal(err)
	}
	if ws, ok := s.RepoWorkspace("me/a"); !ok || ws != "ws_x" {
		t.Fatalf("me/a -> (%q,%v), want ws_x", ws, ok)
	}
	repos, _ := s.ReposForWorkspace("ws_x")
	if len(repos) != 2 {
		t.Fatalf("workspace repos = %v, want 2", repos)
	}

	// A later "repository added" links immediately (workspace already known).
	if err := s.AddInstallRepos(100, []string{"me/c"}); err != nil {
		t.Fatal(err)
	}
	if ws, ok := s.RepoWorkspace("me/c"); !ok || ws != "ws_x" {
		t.Fatalf("me/c -> (%q,%v), want ws_x", ws, ok)
	}

	// Removing a repo unlinks it.
	_ = s.RemoveInstallRepos(100, []string{"me/c"})
	if _, ok := s.RepoWorkspace("me/c"); ok {
		t.Fatal("me/c should be unlinked after removal")
	}

	// Uninstalling drops every repo for the installation.
	if err := s.DeleteInstallation(100); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.RepoWorkspace("me/a"); ok {
		t.Fatal("uninstall should unlink all repos")
	}
	if _, ok := s.InstallationWorkspace(100); ok {
		t.Fatal("installation should be gone")
	}
}
