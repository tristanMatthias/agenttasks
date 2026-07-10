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
	Prefix string // issue id prefix for new tenants (default "t")
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

// Resolve is the httpapi.CoreResolver: it reads the org from the request's
// authenticated Identity and returns that tenant's Core.
func (m *Manager) Resolve(r *http.Request) (*core.Core, error) {
	id, ok := httpapi.IdentityFrom(r.Context())
	if !ok {
		return nil, errors.New("no identity")
	}
	org := id.Claims["org"]
	if org == "" {
		return nil, errors.New("no tenant in token")
	}
	return m.CoreFor(org)
}

// CoreFor returns (lazily creating + caching) the Core for an org.
func (m *Manager) CoreFor(org string) (*core.Core, error) {
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
	c, err := core.New(st, core.Options{Prefix: m.prefix, Actor: "user"})
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
