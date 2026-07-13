package tenant

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/tristanMatthias/agenttasks/internal/workspaces"
	"github.com/tristanMatthias/tasks/pkg/core"
)

// A shared workspace's prefix is authoritative from the control store, so even
// the seed-less path (as an API key / OAuth client hitting a brand-new
// workspace first) mints ids with the right prefix — no cache-order hole.
func TestCoreFor_SharedPrefixAuthoritative(t *testing.T) {
	dir := t.TempDir()
	ws, err := workspaces.Open(filepath.Join(dir, "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if err := ws.CreateWorkspace(workspaces.Workspace{ID: "ws_x", Name: "Acme", Slug: "acme", Prefix: "acme", CreatedBy: "u1"}, "", ""); err != nil {
		t.Fatal(err)
	}
	m := New(Options{Dir: dir, Workspaces: ws})
	defer m.Close()

	// Seed-less CoreFor (the key/OAuth path) still gets the stored prefix.
	c, err := m.CoreFor("ws_x")
	if err != nil {
		t.Fatal(err)
	}
	if c.Prefix() != "acme" {
		t.Fatalf("seed-less shared prefix = %q, want acme", c.Prefix())
	}
	task, err := c.Create(core.CreateParams{Title: "x"})
	if err != nil {
		t.Fatalf("create in shared workspace: %v", err)
	}
	if !strings.HasPrefix(task.ID, "acme-") {
		t.Fatalf("task id = %q, want acme- prefix", task.ID)
	}
}

// A brand-new workspace takes its task-id prefix from the org slug, and minted
// ids actually carry it.
func TestCoreForSeed_NewWorkspaceGetsSlugPrefix(t *testing.T) {
	m := New(Options{Dir: t.TempDir()})
	defer m.Close()

	c, err := m.CoreForSeed("org_2abc", "Acme Platform")
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Prefix(); got != "acme-platform" {
		t.Fatalf("prefix = %q, want acme-platform", got)
	}
	task, err := c.Create(core.CreateParams{Title: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(task.ID, "acme-platform-") {
		t.Fatalf("task id = %q, want acme-platform- prefix", task.ID)
	}
}

// Reopening an existing workspace never overwrites its stored prefix, even if a
// different slug is supplied (e.g. the org was later renamed).
func TestCoreForSeed_ExistingPrefixPreserved(t *testing.T) {
	dir := t.TempDir()

	m1 := New(Options{Dir: dir})
	if _, err := m1.CoreForSeed("org_2abc", "acme"); err != nil {
		t.Fatal(err)
	}
	m1.Close()

	m2 := New(Options{Dir: dir})
	defer m2.Close()
	c, err := m2.CoreForSeed("org_2abc", "totally-different")
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Prefix(); got != "acme" {
		t.Fatalf("prefix = %q, want acme (preserved)", got)
	}
}

// A personal workspace (u_<sub>, no slug) falls back to the configured default.
func TestCoreForSeed_PersonalUsesDefault(t *testing.T) {
	m := New(Options{Dir: t.TempDir(), Prefix: "me"})
	defer m.Close()

	c, err := m.CoreForSeed("u_user_1", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Prefix(); got != "me" {
		t.Fatalf("prefix = %q, want me", got)
	}
}

// The seed-less path (API keys / OAuth) must not stamp a prefix onto a fresh DB,
// so it can never create a usable workspace with a bogus prefix.
func TestCoreFor_SeedlessDoesNotSeed(t *testing.T) {
	m := New(Options{Dir: t.TempDir()})
	defer m.Close()

	c, err := m.CoreFor("org_2abc")
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Prefix(); got != "" {
		t.Fatalf("seed-less new workspace prefix = %q, want empty", got)
	}
}

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"Acme Platform":                   "acme-platform",
		"  Weird__Name!! ":                "weird-name",
		"UPPER":                           "upper",
		"a—b":                        "a-b", // em dash collapses to one dash
		"":                                "",
		"trailing-dashes---":              "trailing-dashes",
		"0123456789012345678901234567890": "012345678901234567890123", // capped at 24
	}
	for in, want := range cases {
		if got := slugify(in); got != want {
			t.Errorf("slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

// A mutation in a tenant fires the per-tenant onChange with that tenant's org id
// and the affected task id(s) — the seam WebSocket broadcasts ride on. The hook
// is installed lazily (via SetOnChange, mirroring how the server wires it after
// construction) yet still reaches an already-created Core.
func TestSetOnChange_FiresPerTenantWithIDs(t *testing.T) {
	m := New(Options{Dir: t.TempDir()})
	defer m.Close()

	// Create the Core BEFORE registering the listener, to prove late binding.
	c, err := m.CoreForSeed("org_live", "Live")
	if err != nil {
		t.Fatal(err)
	}

	var gotOrg string
	var gotIDs []string
	m.SetOnChange(func(org string, ids []string) {
		gotOrg = org
		gotIDs = ids
	})

	task, err := c.Create(core.CreateParams{Title: "ping"})
	if err != nil {
		t.Fatal(err)
	}
	if gotOrg != "org_live" {
		t.Fatalf("onChange org = %q, want org_live", gotOrg)
	}
	if len(gotIDs) != 1 || gotIDs[0] != task.ID {
		t.Fatalf("onChange ids = %v, want [%s]", gotIDs, task.ID)
	}

	// A change in a DIFFERENT tenant reports that tenant's org, never the first.
	c2, err := m.CoreForSeed("org_other", "Other")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Create(core.CreateParams{Title: "pong"}); err != nil {
		t.Fatal(err)
	}
	if gotOrg != "org_other" {
		t.Fatalf("onChange org = %q, want org_other", gotOrg)
	}
}
