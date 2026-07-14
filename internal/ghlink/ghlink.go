// Package ghlink wires GitHub to the boards, Linear-style: a signed webhook
// turns PRs, pushes and branches into ticket actions. "Closes/Fixes/Resolves
// <id>" in a merged PR (or a default-branch commit) closes the ticket; opening a
// PR that references a ticket links it and moves it to In Progress; and every
// link is recorded as a comment on the ticket. A token only counts if it exactly
// resolves to a task id in the mapped board, so references can't false-match.
package ghlink

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/tristanMatthias/tasks/pkg/core"
)

const actor = "github"

// Installs records GitHub App installations and their repos (populated from
// installation webhooks; the workspace binding is set separately by the connect
// flow's setup callback).
type Installs interface {
	AddInstallRepos(installationID int64, repos []string) error
	RemoveInstallRepos(installationID int64, repos []string) error
	DeleteInstallation(installationID int64) error
}

// Config configures the webhook handler.
type Config struct {
	Secret []byte // GitHub App webhook secret (HMAC-SHA256); required
	// Resolve maps a repo full name ("owner/repo") to its board, or (nil,false)
	// if the repo isn't linked.
	Resolve func(repoFullName string) (*core.Core, bool)
	// Installs, if set, receives installation lifecycle events so installing the
	// App auto-links its repos.
	Installs Installs
	Logger   *slog.Logger
}

// Handler serves POST /webhooks/github.
type Handler struct{ cfg Config }

func New(cfg Config) *Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Handler{cfg: cfg}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /webhooks/github", h.handle)
}

func (h *Handler) handle(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if !h.verify(r.Header.Get("X-Hub-Signature-256"), body) {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	switch r.Header.Get("X-GitHub-Event") {
	case "pull_request":
		h.onPullRequest(body)
	case "push":
		h.onPush(body)
	case "create":
		h.onCreate(body)
	case "installation":
		h.onInstallation(body)
	case "installation_repositories":
		h.onInstallationRepos(body)
	}
	// Always 200 so GitHub doesn't retry on our processing choices.
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) verify(sig string, body []byte) bool {
	if len(h.cfg.Secret) == 0 || !strings.HasPrefix(sig, "sha256=") {
		return false
	}
	want, err := hex.DecodeString(strings.TrimPrefix(sig, "sha256="))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, h.cfg.Secret)
	mac.Write(body)
	return hmac.Equal(want, mac.Sum(nil))
}

// ---- payloads (only the fields we use) ----

type repo struct {
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
}
type prPayload struct {
	Action      string `json:"action"`
	PullRequest struct {
		Number  int    `json:"number"`
		Title   string `json:"title"`
		Body    string `json:"body"`
		HTMLURL string `json:"html_url"`
		Merged  bool   `json:"merged"`
		Head    struct {
			Ref string `json:"ref"`
		} `json:"head"`
	} `json:"pull_request"`
	Repository repo `json:"repository"`
}
type pushPayload struct {
	Ref        string `json:"ref"`
	Repository repo   `json:"repository"`
	Commits    []struct {
		Message string `json:"message"`
		URL     string `json:"url"`
		ID      string `json:"id"`
	} `json:"commits"`
}
type createPayload struct {
	Ref        string `json:"ref"`
	RefType    string `json:"ref_type"`
	Repository repo   `json:"repository"`
}

func (h *Handler) boardFor(fullName string) (*core.Core, bool) {
	if h.cfg.Resolve == nil {
		return nil, false
	}
	return h.cfg.Resolve(fullName)
}

func (h *Handler) onPullRequest(body []byte) {
	var p prPayload
	if json.Unmarshal(body, &p) != nil {
		return
	}
	c, ok := h.boardFor(p.Repository.FullName)
	if !ok {
		return
	}
	pr := p.PullRequest
	text := pr.Title + "\n" + pr.Body
	name := prLinkText(pr.Title, pr.Number)
	// Any reference links — a magic word, a #id, the bare ticket id, or the branch
	// name (Linear-style: the reference IS the link; no "Closes" required).
	refs := resolveAll(c, union(closeRefs(text), hashRefs(text), fullRefs(text, c.Prefix()), branchRefs(pr.Head.Ref)))

	switch p.Action {
	case "opened", "reopened", "ready_for_review", "edited":
		for _, id := range refs {
			h.link(c, id, "Linked to [%s](%s)", name, pr.HTMLURL)
			h.inProgress(c, id)
		}
	case "closed":
		if !pr.Merged {
			return
		}
		// Merging a PR completes every ticket it references — like Linear.
		for _, id := range refs {
			h.closeTicket(c, id, "merged PR #"+strconv.Itoa(pr.Number), "Closed by [%s](%s)", name, pr.HTMLURL)
		}
	}
}

// prLinkText is the link copy for a PR: "<title> #<number>", or just "PR #<n>"
// when the title is empty.
func prLinkText(title string, number int) string {
	if strings.TrimSpace(title) != "" {
		return fmt.Sprintf("%s #%d", title, number)
	}
	return "PR #" + strconv.Itoa(number)
}

func (h *Handler) onPush(body []byte) {
	var p pushPayload
	if json.Unmarshal(body, &p) != nil {
		return
	}
	if p.Ref != "refs/heads/"+p.Repository.DefaultBranch {
		return // only the default branch auto-closes
	}
	c, ok := h.boardFor(p.Repository.FullName)
	if !ok {
		return
	}
	for _, cm := range p.Commits {
		for _, id := range resolveAll(c, closeRefs(cm.Message)) {
			short := cm.ID
			if len(short) > 7 {
				short = short[:7]
			}
			h.closeTicket(c, id, "commit "+short, "Closed by commit [%s](%s)", short, cm.URL)
		}
	}
}

type installPayload struct {
	Action       string `json:"action"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
	Repositories []struct {
		FullName string `json:"full_name"`
	} `json:"repositories"`
	RepositoriesAdded []struct {
		FullName string `json:"full_name"`
	} `json:"repositories_added"`
	RepositoriesRemoved []struct {
		FullName string `json:"full_name"`
	} `json:"repositories_removed"`
}

func names(rs []struct {
	FullName string `json:"full_name"`
}) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		if r.FullName != "" {
			out = append(out, r.FullName)
		}
	}
	return out
}

func (h *Handler) onInstallation(body []byte) {
	if h.cfg.Installs == nil {
		return
	}
	var p installPayload
	if json.Unmarshal(body, &p) != nil {
		return
	}
	switch p.Action {
	case "created":
		_ = h.cfg.Installs.AddInstallRepos(p.Installation.ID, names(p.Repositories))
	case "deleted":
		_ = h.cfg.Installs.DeleteInstallation(p.Installation.ID)
	}
}

func (h *Handler) onInstallationRepos(body []byte) {
	if h.cfg.Installs == nil {
		return
	}
	var p installPayload
	if json.Unmarshal(body, &p) != nil {
		return
	}
	if a := names(p.RepositoriesAdded); len(a) > 0 {
		_ = h.cfg.Installs.AddInstallRepos(p.Installation.ID, a)
	}
	if rm := names(p.RepositoriesRemoved); len(rm) > 0 {
		_ = h.cfg.Installs.RemoveInstallRepos(p.Installation.ID, rm)
	}
}

func (h *Handler) onCreate(body []byte) {
	var p createPayload
	if json.Unmarshal(body, &p) != nil || p.RefType != "branch" {
		return
	}
	c, ok := h.boardFor(p.Repository.FullName)
	if !ok {
		return
	}
	for _, id := range resolveAll(c, branchRefs(p.Ref)) {
		h.link(c, id, "Branch `%s` created", p.Ref)
		h.inProgress(c, id)
	}
}

// ---- actions ----

func (h *Handler) link(c *core.Core, id, format string, a ...any) {
	if _, err := c.Comment(id, fmt.Sprintf(format, a...), actor); err != nil {
		h.cfg.Logger.Warn("ghlink comment failed", "id", id, "err", err)
	}
}

func (h *Handler) inProgress(c *core.Core, id string) {
	t, err := c.Show(id)
	if err != nil || t.Status == "closed" || t.Status == "in_progress" {
		return
	}
	s := "in_progress"
	if _, err := c.Update(id, core.UpdateParams{Status: &s, Actor: actor}); err != nil {
		h.cfg.Logger.Warn("ghlink status failed", "id", id, "err", err)
	}
}

func (h *Handler) closeTicket(c *core.Core, id, reason, format string, a ...any) {
	t, err := c.Show(id)
	if err != nil || t.Status == "closed" {
		return // already closed / gone
	}
	if _, err := c.Close(id, core.CloseParams{Reason: reason, Actor: actor}); err != nil {
		h.cfg.Logger.Warn("ghlink close failed", "id", id, "err", err)
		return
	}
	h.link(c, id, format, a...)
}

// ---- reference parsing ----

var closeRe = regexp.MustCompile(`(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\b[:\s]+#?([A-Za-z0-9][\w.\-]*)`)
var hashRe = regexp.MustCompile(`#([A-Za-z][\w.\-]*)`) // #id (letters, so bare PR numbers don't match)

// closeRefs returns tokens explicitly marked to close a ticket.
func closeRefs(text string) []string { return caps(closeRe.FindAllStringSubmatch(text, -1)) }

// hashRefs returns #-prefixed references.
func hashRefs(text string) []string { return caps(hashRe.FindAllStringSubmatch(text, -1)) }

// fullRefs returns bare, board-prefixed ids mentioned anywhere (e.g.
// "acme-nsvk"). Prefix-scoped so it can't false-match ordinary words.
func fullRefs(text, prefix string) []string {
	if prefix == "" {
		return nil
	}
	re := regexp.MustCompile(`\b(` + regexp.QuoteMeta(prefix) + `-[A-Za-z0-9][\w.\-]*)\b`)
	return caps(re.FindAllStringSubmatch(text, -1))
}

// branchRefs pulls candidate ids out of a branch name (split on / - _ .).
func branchRefs(branch string) []string {
	if branch == "" {
		return nil
	}
	return strings.FieldsFunc(branch, func(r rune) bool {
		return r == '/' || r == '-' || r == '_' || r == '.'
	})
}

func caps(m [][]string) []string {
	out := make([]string, 0, len(m))
	for _, g := range m {
		if len(g) > 1 {
			out = append(out, g[1])
		}
	}
	return out
}

func union(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, s := range l {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// resolveAll keeps only tokens that resolve to a real task in c, returning their
// canonical ids (deduped).
func resolveAll(c *core.Core, tokens []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, tok := range tokens {
		t, err := c.Show(tok)
		if err != nil || t == nil {
			continue
		}
		if !seen[t.ID] {
			seen[t.ID] = true
			out = append(out, t.ID)
		}
	}
	return out
}
