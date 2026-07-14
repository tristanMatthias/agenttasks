// Package workspaces is the control-plane store for the self-hosted org layer:
// workspaces, their members, and pending invites. It replaces what we'd
// otherwise pay Clerk Organizations for — Clerk still handles authentication,
// but membership and invitations live here, in a single SQLite control DB.
//
// A "personal" workspace (id "u_<sub>") is implicit — every user always has one
// and it needs no row here; only shared workspaces are stored.
package workspaces

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Roles. Kept deliberately small; admin can manage members/invites/settings.
const (
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// ErrNotFound is returned when a workspace/invite lookup misses.
var ErrNotFound = errors.New("not found")

// ErrLastAdmin blocks demoting/removing a workspace's only admin.
var ErrLastAdmin = errors.New("workspace needs an admin")

// ErrInviteUsed / ErrInviteExpired / ErrInviteEmail reject a bad accept.
var (
	ErrInviteUsed    = errors.New("invite already used")
	ErrInviteExpired = errors.New("invite has expired")
	ErrInviteEmail   = errors.New("invite is for a different email")
)

// Workspace is a shared board with its own tenant DB and task-id prefix.
type Workspace struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	Prefix    string `json:"prefix"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
}

// Member is a user's membership in a workspace (identity denormalized from the
// token at join time, so listing members needs no identity-provider call).
type Member struct {
	WorkspaceID string `json:"workspace_id"`
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	CreatedAt   string `json:"created_at"`
}

// Invite is a pending, link-shareable invitation. Email may be empty (open
// link) or set (restricted to that address).
type Invite struct {
	Token       string `json:"token"`
	WorkspaceID string `json:"workspace_id"`
	Role        string `json:"role"`
	Email       string `json:"email"`
	CreatedBy   string `json:"created_by"`
	CreatedAt   string `json:"created_at"`
	ExpiresAt   string `json:"expires_at"`
	AcceptedAt  string `json:"accepted_at"`
}

const schema = `
CREATE TABLE IF NOT EXISTS workspaces (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  slug       TEXT NOT NULL,
  prefix     TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memberships (
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id      TEXT NOT NULL,
  email        TEXT NOT NULL DEFAULT '',
  name         TEXT NOT NULL DEFAULT '',
  role         TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  PRIMARY KEY (workspace_id, user_id)
);
CREATE TABLE IF NOT EXISTS invites (
  token        TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  role         TEXT NOT NULL,
  email        TEXT NOT NULL DEFAULT '',
  created_by   TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  expires_at   TEXT NOT NULL DEFAULT '',
  accepted_by  TEXT NOT NULL DEFAULT '',
  accepted_at  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_memberships_user ON memberships(user_id);
-- External identities (e.g. GitHub) mapped to a canonical subject, so a login
-- provider swap or a re-auth reuses the same tenant/board.
CREATE TABLE IF NOT EXISTS identities (
  provider    TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  subject     TEXT NOT NULL,
  login       TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL,
  PRIMARY KEY (provider, provider_id)
);
-- Which GitHub repo ("owner/name") feeds which workspace's board (for the
-- Linear-style PR/commit auto-linking).
CREATE TABLE IF NOT EXISTS repo_links (
  repo         TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_invites_ws ON invites(workspace_id);
`

// Store is the control-plane SQLite database.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the control DB at path, in WAL mode.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // serialize writes; WAL keeps reads concurrent
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("workspaces schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// LinkedSubject returns the canonical subject a provider identity maps to, if any.
func (s *Store) LinkedSubject(provider, providerID string) (string, bool) {
	var sub string
	err := s.db.QueryRow(
		`SELECT subject FROM identities WHERE provider=? AND provider_id=?`, provider, providerID,
	).Scan(&sub)
	if err != nil || sub == "" {
		return "", false
	}
	return sub, true
}

// LinkIdentity records (or refreshes) a provider identity → subject mapping.
func (s *Store) LinkIdentity(provider, providerID, subject, login string) error {
	_, err := s.db.Exec(
		`INSERT INTO identities (provider, provider_id, subject, login, created_at)
		 VALUES (?,?,?,?,?)
		 ON CONFLICT(provider, provider_id) DO UPDATE SET login=excluded.login`,
		provider, providerID, subject, login, now())
	return err
}

// RepoWorkspace returns the workspace a GitHub repo ("owner/name") is linked to.
func (s *Store) RepoWorkspace(repo string) (string, bool) {
	var ws string
	if err := s.db.QueryRow(`SELECT workspace_id FROM repo_links WHERE repo=?`, repo).Scan(&ws); err != nil || ws == "" {
		return "", false
	}
	return ws, true
}

// LinkRepo maps a GitHub repo to a workspace (idempotent).
func (s *Store) LinkRepo(repo, workspaceID string) error {
	_, err := s.db.Exec(
		`INSERT INTO repo_links (repo, workspace_id, created_at) VALUES (?,?,?)
		 ON CONFLICT(repo) DO UPDATE SET workspace_id=excluded.workspace_id`,
		repo, workspaceID, now())
	return err
}

// now is RFC3339Nano so list ordering is stable even within the same second.
func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// CreateWorkspace inserts a workspace and its creator as the first admin, atomically.
func (s *Store) CreateWorkspace(ws Workspace, creatorEmail, creatorName string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ts := now()
	if _, err := tx.Exec(
		`INSERT INTO workspaces (id, name, slug, prefix, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		ws.ID, ws.Name, ws.Slug, ws.Prefix, ws.CreatedBy, ts,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO memberships (workspace_id, user_id, email, name, role, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		ws.ID, ws.CreatedBy, creatorEmail, creatorName, RoleAdmin, ts,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// Workspace returns a workspace by id.
func (s *Store) Workspace(id string) (Workspace, error) {
	var ws Workspace
	err := s.db.QueryRow(
		`SELECT id, name, slug, prefix, created_by, created_at FROM workspaces WHERE id = ?`, id,
	).Scan(&ws.ID, &ws.Name, &ws.Slug, &ws.Prefix, &ws.CreatedBy, &ws.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Workspace{}, ErrNotFound
	}
	return ws, err
}

// WorkspacesForUser returns every workspace the user is a member of, with role.
func (s *Store) WorkspacesForUser(userID string) ([]struct {
	Workspace
	Role string
}, error) {
	rows, err := s.db.Query(
		`SELECT w.id, w.name, w.slug, w.prefix, w.created_by, w.created_at, m.role
		 FROM workspaces w JOIN memberships m ON m.workspace_id = w.id
		 WHERE m.user_id = ? ORDER BY w.name COLLATE NOCASE`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []struct {
		Workspace
		Role string
	}
	for rows.Next() {
		var w Workspace
		var role string
		if err := rows.Scan(&w.ID, &w.Name, &w.Slug, &w.Prefix, &w.CreatedBy, &w.CreatedAt, &role); err != nil {
			return nil, err
		}
		out = append(out, struct {
			Workspace
			Role string
		}{w, role})
	}
	return out, rows.Err()
}

// Role returns the user's role in a workspace and whether they're a member.
func (s *Store) Role(workspaceID, userID string) (string, bool) {
	var role string
	err := s.db.QueryRow(
		`SELECT role FROM memberships WHERE workspace_id = ? AND user_id = ?`, workspaceID, userID,
	).Scan(&role)
	if err != nil {
		return "", false
	}
	return role, true
}

// Members lists a workspace's members (newest first).
func (s *Store) Members(workspaceID string) ([]Member, error) {
	rows, err := s.db.Query(
		`SELECT workspace_id, user_id, email, name, role, created_at
		 FROM memberships WHERE workspace_id = ? ORDER BY created_at`, workspaceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.WorkspaceID, &m.UserID, &m.Email, &m.Name, &m.Role, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// CountAdmins returns how many admins a workspace has (to guard the last one).
func (s *Store) CountAdmins(workspaceID string) (int, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM memberships WHERE workspace_id = ? AND role = ?`, workspaceID, RoleAdmin,
	).Scan(&n)
	return n, err
}

// UpdateMemberRole changes a member's role. Demoting the workspace's only admin
// is rejected atomically (the guard + write share one transaction), so two
// concurrent demotions can't both slip through and leave zero admins.
func (s *Store) UpdateMemberRole(workspaceID, userID, role string) error {
	return s.withGuardedAdminChange(workspaceID, userID, role != RoleAdmin, func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE memberships SET role = ? WHERE workspace_id = ? AND user_id = ?`, role, workspaceID, userID)
		return err
	})
}

// RemoveMember removes a user from a workspace (idempotent). Removing the only
// admin is rejected atomically. Used for both admin-removal and self-leave.
func (s *Store) RemoveMember(workspaceID, userID string) error {
	return s.withGuardedAdminChange(workspaceID, userID, true, func(tx *sql.Tx) error {
		_, err := tx.Exec(`DELETE FROM memberships WHERE workspace_id = ? AND user_id = ?`, workspaceID, userID)
		return err
	})
}

// withGuardedAdminChange runs mutate in a transaction that, when demoting is
// true and the target is currently the last admin, returns ErrLastAdmin instead.
func (s *Store) withGuardedAdminChange(workspaceID, userID string, demoting bool, mutate func(*sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var role string
	err = tx.QueryRow(`SELECT role FROM memberships WHERE workspace_id = ? AND user_id = ?`, workspaceID, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // not a member → nothing to do
	}
	if err != nil {
		return err
	}
	if demoting && role == RoleAdmin {
		var admins int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM memberships WHERE workspace_id = ? AND role = ?`, workspaceID, RoleAdmin).Scan(&admins); err != nil {
			return err
		}
		if admins <= 1 {
			return ErrLastAdmin
		}
	}
	if err := mutate(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// Rename updates a workspace's display name.
func (s *Store) Rename(workspaceID, name string) error {
	_, err := s.db.Exec(`UPDATE workspaces SET name = ? WHERE id = ?`, name, workspaceID)
	return err
}

// DeleteWorkspace removes a workspace and its memberships + invites (not its
// task DB — that's left on disk, recoverable).
func (s *Store) DeleteWorkspace(workspaceID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM memberships WHERE workspace_id = ?`,
		`DELETE FROM invites WHERE workspace_id = ?`,
		`DELETE FROM workspaces WHERE id = ?`,
	} {
		if _, err := tx.Exec(q, workspaceID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// CreateInvite stores a pending invite.
func (s *Store) CreateInvite(inv Invite) error {
	_, err := s.db.Exec(
		`INSERT INTO invites (token, workspace_id, role, email, created_by, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		inv.Token, inv.WorkspaceID, inv.Role, inv.Email, inv.CreatedBy, now(), inv.ExpiresAt,
	)
	return err
}

// Invite returns an invite by token.
func (s *Store) Invite(token string) (Invite, error) {
	var inv Invite
	err := s.db.QueryRow(
		`SELECT token, workspace_id, role, email, created_by, created_at, expires_at, accepted_at
		 FROM invites WHERE token = ?`, token,
	).Scan(&inv.Token, &inv.WorkspaceID, &inv.Role, &inv.Email, &inv.CreatedBy, &inv.CreatedAt, &inv.ExpiresAt, &inv.AcceptedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Invite{}, ErrNotFound
	}
	return inv, err
}

// PendingInvites lists a workspace's unaccepted, unexpired invites.
func (s *Store) PendingInvites(workspaceID string) ([]Invite, error) {
	rows, err := s.db.Query(
		`SELECT token, workspace_id, role, email, created_by, created_at, expires_at, accepted_at
		 FROM invites WHERE workspace_id = ? AND accepted_at = ''
		   AND (expires_at = '' OR expires_at > ?)
		 ORDER BY created_at DESC`, workspaceID, now(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invite
	for rows.Next() {
		var inv Invite
		if err := rows.Scan(&inv.Token, &inv.WorkspaceID, &inv.Role, &inv.Email, &inv.CreatedBy, &inv.CreatedAt, &inv.ExpiresAt, &inv.AcceptedAt); err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

// RevokeInvite deletes a pending invite.
func (s *Store) RevokeInvite(token string) error {
	_, err := s.db.Exec(`DELETE FROM invites WHERE token = ?`, token)
	return err
}

// AcceptInvite adds the user to the invite's workspace and marks it accepted,
// atomically. Idempotent for an already-member user. Returns the workspace id.
func (s *Store) AcceptInvite(token, userID, email, name string) (string, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var inv Invite
	err = tx.QueryRow(
		`SELECT workspace_id, role, email, expires_at, accepted_at FROM invites WHERE token = ?`, token,
	).Scan(&inv.WorkspaceID, &inv.Role, &inv.Email, &inv.ExpiresAt, &inv.AcceptedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if inv.AcceptedAt != "" {
		return "", ErrInviteUsed
	}
	ts := now()
	if inv.ExpiresAt != "" && ts > inv.ExpiresAt {
		return "", ErrInviteExpired
	}
	// A restricted invite requires a matching email. If the accepter's session
	// carries no email, they can't satisfy the restriction — reject (no bypass).
	if inv.Email != "" && !strings.EqualFold(inv.Email, email) {
		return "", ErrInviteEmail
	}
	// Claim the invite atomically first — the WHERE guards against a concurrent
	// accept of the same token (only one UPDATE affects a row).
	res, err := tx.Exec(`UPDATE invites SET accepted_by = ?, accepted_at = ? WHERE token = ? AND accepted_at = ''`, userID, ts, token)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return "", ErrInviteUsed
	}
	// Add membership (idempotent — an already-member accepter keeps their role).
	if _, err := tx.Exec(
		`INSERT INTO memberships (workspace_id, user_id, email, name, role, created_at)
		 VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(workspace_id, user_id) DO NOTHING`,
		inv.WorkspaceID, userID, email, name, inv.Role, ts,
	); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return inv.WorkspaceID, nil
}
