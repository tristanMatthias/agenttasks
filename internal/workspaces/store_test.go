package workspaces

import (
	"path/filepath"
	"testing"
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
