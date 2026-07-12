package tenant

import (
	"strings"
	"testing"

	"github.com/tristanMatthias/tasks/pkg/core"
)

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
