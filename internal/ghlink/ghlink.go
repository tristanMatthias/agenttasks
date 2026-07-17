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
	case "issue_comment":
		h.onIssueComment(body)
	case "pull_request_review":
		h.onReview(body)
	case "pull_request_review_comment":
		h.onReviewComment(body)
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

type commentBody struct {
	Body    string `json:"body"`
	HTMLURL string `json:"html_url"`
}

// A conversation comment on a PR (issue_comment with a pull_request block).
type issueCommentPayload struct {
	Action string `json:"action"`
	Issue  struct {
		Number      int             `json:"number"`
		Title       string          `json:"title"`
		PullRequest json.RawMessage `json:"pull_request"` // present iff the issue is a PR
	} `json:"issue"`
	Comment    commentBody `json:"comment"`
	Repository repo        `json:"repository"`
}

// A PR review (the review body) or an inline review comment.
type reviewPayload struct {
	Action      string      `json:"action"`
	Review      commentBody `json:"review"`
	Comment     commentBody `json:"comment"`
	PullRequest struct {
		Number int    `json:"number"`
		Title  string `json:"title"`
	} `json:"pull_request"`
	Repository repo `json:"repository"`
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

	// Two classes of reference, deliberately treated differently (Linear-style):
	//   closes   — an intentional "this PR completes X": a magic word
	//              (Closes/Fixes/Resolves) or the branch the PR is built on.
	//   mentions — a ticket merely referenced in the title/body (#id, the full
	//              board-prefixed id, or a bare hierarchical id like ps3t.6.2).
	// Merging CLOSES the first set and only LINKS the second — otherwise a PR
	// that name-drops sibling/follow-up tickets would wrongly close them.
	closes := resolveAll(c, union(closeRefs(text), branchRefs(pr.Head.Ref)))
	mentions := resolveAll(c, union(hashRefs(text), fullRefs(text, c.Prefix()), bareRefs(text)))

	switch p.Action {
	case "opened", "reopened", "ready_for_review", "edited":
		for _, id := range union(closes, mentions) {
			h.linkOnce(c, id, pr.Number, name, pr.HTMLURL)
		}
	case "closed":
		if !pr.Merged {
			return
		}
		closed := map[string]bool{}
		for _, id := range closes {
			h.closeTicket(c, id, "merged PR #"+strconv.Itoa(pr.Number), "Closed by [%s](%s)", name, pr.HTMLURL)
			closed[id] = true
		}
		// Mentioned-but-not-closed tickets: record the link (in case the mention
		// only landed at merge), without closing them.
		for _, id := range mentions {
			if !closed[id] {
				h.linkOnce(c, id, pr.Number, name, pr.HTMLURL)
			}
		}
	}
}

// linkComment links every ticket a PR comment mentions (never closes — comments
// are mentions, not completion signals). Shared by the three comment event
// types so a reference in any of them counts.
func (h *Handler) linkComment(repoFullName, text string, prNumber int, prTitle, url string) {
	c, ok := h.boardFor(repoFullName)
	if !ok {
		return
	}
	name := prLinkText(prTitle, prNumber)
	for _, id := range resolveAll(c, union(closeRefs(text), hashRefs(text), fullRefs(text, c.Prefix()), bareRefs(text))) {
		h.linkOnce(c, id, prNumber, name, url)
	}
}

func (h *Handler) onIssueComment(body []byte) {
	var p issueCommentPayload
	if json.Unmarshal(body, &p) != nil || len(p.Issue.PullRequest) == 0 {
		return // not a PR comment (or unparsable)
	}
	if p.Action != "created" && p.Action != "edited" {
		return
	}
	h.linkComment(p.Repository.FullName, p.Comment.Body, p.Issue.Number, p.Issue.Title, p.Comment.HTMLURL)
}

func (h *Handler) onReview(body []byte) {
	var p reviewPayload
	if json.Unmarshal(body, &p) != nil || p.Review.Body == "" {
		return
	}
	h.linkComment(p.Repository.FullName, p.Review.Body, p.PullRequest.Number, p.PullRequest.Title, p.Review.HTMLURL)
}

func (h *Handler) onReviewComment(body []byte) {
	var p reviewPayload
	if json.Unmarshal(body, &p) != nil {
		return
	}
	h.linkComment(p.Repository.FullName, p.Comment.Body, p.PullRequest.Number, p.PullRequest.Title, p.Comment.HTMLURL)
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

// linkOnce links a ticket to a PR and moves it to In Progress, but only if it
// isn't already linked to that PR — so repeated events (PR edits, and the many
// review comments a bot posts) don't spam the ticket with duplicate links.
func (h *Handler) linkOnce(c *core.Core, id string, prNumber int, name, url string) {
	if h.alreadyLinkedToPR(c, id, prNumber) {
		h.inProgress(c, id)
		return
	}
	h.link(c, id, "Linked to [%s](%s)", name, url)
	h.inProgress(c, id)
}

// alreadyLinkedToPR reports whether the ticket already carries a github link to
// this PR (matched on the "/pull/<n>" that every PR/comment url shares).
func (h *Handler) alreadyLinkedToPR(c *core.Core, id string, prNumber int) bool {
	t, err := c.Show(id)
	if err != nil {
		return false
	}
	needle := fmt.Sprintf("/pull/%d", prNumber)
	for _, cm := range t.Comments {
		if cm.Author == actor && strings.Contains(cm.Text, needle) {
			return true
		}
	}
	return false
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

var bareRe = regexp.MustCompile(`\b([A-Za-z0-9]+(?:\.\d+)+)\b`)

// bareRefs returns bare hierarchical child ids mentioned anywhere ("ps3t.6.2").
// The dot-then-digits shape is distinctive enough to rarely appear in prose, and
// resolveAll validates every hit against the board — so this can't false-match.
// These are MENTIONS: they link a ticket to a PR, they never close it.
func bareRefs(text string) []string { return caps(bareRe.FindAllStringSubmatch(text, -1)) }

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
//
// Hierarchical child ids contain dots ("ps3t.6.2"), but branch names encode
// those dots as dashes ("claude/ps3t-6-2-implementation"), so a naive split
// would shatter the id into dead tokens (ps3t, 6, 2). We rejoin a segment with
// the run of purely-numeric segments that follow it, reconstructing the dotted
// id ("ps3t.6.2") — hierarchy levels are always numeric. resolveAll then keeps
// only the ones that are real tickets, so the reconstruction can't false-match.
func branchRefs(branch string) []string {
	if branch == "" {
		return nil
	}
	segs := strings.FieldsFunc(branch, func(r rune) bool {
		return r == '/' || r == '-' || r == '_' || r == '.'
	})
	var out []string
	for i := 0; i < len(segs); {
		tok := segs[i]
		j := i + 1
		for j < len(segs) && isAllDigits(segs[j]) {
			tok += "." + segs[j]
			j++
		}
		out = append(out, tok)
		i = j
	}
	return out
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
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
