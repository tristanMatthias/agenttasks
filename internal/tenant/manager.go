// Package tenant maps an authenticated org id to its own tasks Core (a separate
// SQLite file per tenant: <dir>/<org>.db), created lazily and cached. It exposes
// a Resolve method that satisfies tasks/pkg/httpapi.CoreResolver.
package tenant

import (
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/tristanMatthias/tasks/pkg/core"
	"github.com/tristanMatthias/tasks/pkg/httpapi"
	"github.com/tristanMatthias/tasks/pkg/store"
)

// Manager owns the per-tenant Cores.
type Manager struct {
	dir      string
	prefix   string
	onChange func(org string)

	mu    sync.Mutex
	cores map[string]*core.Core
}

// Options configure a Manager.
type Options struct {
	Dir    string // directory holding <org>.db files
	Prefix string // fallback id prefix when a workspace has no usable slug (default "t")
	// OnChange, if set, is invoked (with the org id) after any mutation in that
	// tenant — used to drive per-tenant backup/export.
	OnChange func(org string)
}

// New builds a Manager.
func New(opts Options) *Manager {
	prefix := opts.Prefix
	if prefix == "" {
		prefix = "t"
	}
	return &Manager{dir: opts.Dir, prefix: prefix, onChange: opts.OnChange, cores: map[string]*core.Core{}}
}

// Resolve is the httpapi.CoreResolver: it reads the org (and its slug) from the
// request's authenticated Identity and returns that tenant's Core. A browser
// (JWT) request carries the slug, so it's the one that provisions a brand-new
// workspace — seeding a prefix derived from that slug.
func (m *Manager) Resolve(r *http.Request) (*core.Core, error) {
	id, ok := httpapi.IdentityFrom(r.Context())
	if !ok {
		return nil, errors.New("no identity")
	}
	org := id.Claims["org"]
	if org == "" {
		return nil, errors.New("no tenant in token")
	}
	return m.CoreForSeed(org, id.Claims["org_slug"])
}

// CoreFor returns (lazily creating + caching) the Core for an org WITHOUT
// seeding a prefix. Used by the API-key and OAuth paths, which only ever reach
// already-provisioned workspaces — so they can't create one with a bad prefix.
func (m *Manager) CoreFor(org string) (*core.Core, error) {
	return m.coreFor(org, "", false)
}

// CoreForSeed is CoreFor plus: if this call provisions a brand-new (empty)
// workspace, its task-id prefix is seeded from slug. An existing workspace keeps
// the prefix already stored in its meta.
func (m *Manager) CoreForSeed(org, slug string) (*core.Core, error) {
	return m.coreFor(org, slug, true)
}

func (m *Manager) coreFor(org, slug string, seed bool) (*core.Core, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.cores[org]; ok {
		return c, nil
	}
	safe := sanitize(org)
	if safe == "" {
		return nil, errors.New("invalid tenant id")
	}
	st, err := store.Open(filepath.Join(m.dir, safe+".db"))
	if err != nil {
		return nil, err
	}
	// Prefix precedence mirrors core.New: an explicit prefix WINS and overwrites
	// the stored one, so only set it when this is a genuinely new, empty
	// workspace. Otherwise pass "" and let core.New keep the meta prefix (or
	// derive it from existing ids). This preserves every existing board.
	prefix := ""
	if seed {
		if existing, _ := st.Meta("prefix"); existing == "" {
			if n, _ := st.Count(); n == 0 {
				prefix = m.prefixFrom(slug, org)
			}
		}
	}
	// KeySelector embeds the org into minted API tokens (tasks_<org>_<secret>) so
	// a bare bot token routes back to this tenant. The cache key is the same raw
	// org, so the key path and the JWT path share one Core per tenant.
	c, err := core.New(st, core.Options{Prefix: prefix, Actor: "user", KeySelector: org})
	if err != nil {
		st.Close()
		return nil, err
	}
	if m.onChange != nil {
		org := org
		c.SetOnChange(func() { m.onChange(org) })
	}
	m.cores[org] = c
	return c, nil
}

// prefixFrom picks a task-id prefix for a new workspace: the org slug if present
// (the common case), else a slug derived from the org id, else the configured
// default. A personal tenant (u_<sub>) has no slug, so it takes the default.
func (m *Manager) prefixFrom(slug, org string) string {
	if p := slugify(slug); p != "" {
		return p
	}
	if strings.HasPrefix(org, "u_") {
		return m.prefix // personal workspace → generic default
	}
	if p := slugify(org); p != "" {
		return p
	}
	return m.prefix
}

// Close closes all open tenant stores.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.cores {
		c.Store().Close()
	}
	m.cores = map[string]*core.Core{}
}

// sanitize makes an org id safe as a filename (keep [A-Za-z0-9_-], drop the rest).
func sanitize(org string) string {
	var b strings.Builder
	for _, r := range org {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// slugify turns a name/slug into a task-id prefix: lowercase, keep [a-z0-9],
// collapse any other run to a single '-', trim leading/trailing '-', and cap the
// length. The result becomes the visible id prefix (e.g. "acme-platform-07po"),
// so it must never end in '-' (core splits ids on the last '-').
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
