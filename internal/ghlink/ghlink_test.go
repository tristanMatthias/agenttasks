package ghlink

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tristanMatthias/tasks/pkg/core"
	"github.com/tristanMatthias/tasks/pkg/store"
)

func newCore(t *testing.T) *core.Core {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := core.New(st, core.Options{Prefix: "acme", Actor: "user"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func send(t *testing.T, h *Handler, secret, event, body string) int {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	req := httptest.NewRequest("POST", "/webhooks/github", strings.NewReader(body))
	req.Header.Set("X-GitHub-Event", event)
	req.Header.Set("X-Hub-Signature-256", sig)
	rec := httptest.NewRecorder()
	h.handle(rec, req)
	return rec.Code
}

func handler(c *core.Core, secret string) *Handler {
	return New(Config{
		Secret:  []byte(secret),
		Resolve: func(repo string) (*core.Core, bool) { return c, repo == "me/repo" },
	})
}

func TestParsing(t *testing.T) {
	if got := closeRefs("Closes acme-nsvk and fixes: #foo, resolved BAR"); len(got) != 3 {
		t.Fatalf("closeRefs = %v, want 3", got)
	}
	if got := hashRefs("see #nsvk not #123"); len(got) != 1 || got[0] != "nsvk" {
		t.Fatalf("hashRefs = %v, want [nsvk] (bare numbers ignored)", got)
	}
	if got := fullRefs("touches acme-nsvk here", "acme"); len(got) != 1 || got[0] != "acme-nsvk" {
		t.Fatalf("fullRefs = %v, want [acme-nsvk]", got)
	}
	if got := branchRefs("tristan/nsvk-node-model"); len(got) < 2 {
		t.Fatalf("branchRefs = %v", got)
	}
}

func TestSignatureRequired(t *testing.T) {
	c := newCore(t)
	h := handler(c, "s3cret")
	req := httptest.NewRequest("POST", "/webhooks/github", strings.NewReader("{}"))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-Hub-Signature-256", "sha256=deadbeef")
	rec := httptest.NewRecorder()
	h.handle(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad-sig status = %d, want 401", rec.Code)
	}
}

func TestMergedPRClosesTicket(t *testing.T) {
	c := newCore(t)
	task, _ := c.Create(core.CreateParams{Title: "Fix the thing"})
	h := handler(c, "s")

	body := `{"action":"closed","pull_request":{"number":7,"merged":true,` +
		`"title":"Closes ` + task.ID + `","body":"","html_url":"https://gh/pr/7"},` +
		`"repository":{"full_name":"me/repo","default_branch":"main"}}`
	if code := send(t, h, "s", "pull_request", body); code != 200 {
		t.Fatalf("status %d", code)
	}
	got, _ := c.Show(task.ID)
	if got.Status != "closed" {
		t.Fatalf("ticket status = %q, want closed", got.Status)
	}
	if got.CommentCount == 0 {
		t.Fatal("expected a link comment recording the PR")
	}
}

func TestMergedPRClosesByReference_NoMagicWord(t *testing.T) {
	c := newCore(t)
	task, _ := c.Create(core.CreateParams{Title: "Referenced only"})
	h := handler(c, "s")

	// No "Closes" anywhere — the ticket is only referenced via the branch name.
	body := `{"action":"closed","pull_request":{"number":8,"merged":true,` +
		`"title":"Some work","body":"just a description","html_url":"https://gh/pr/8",` +
		`"head":{"ref":"tristan/` + shortID(task.ID) + `-referenced-only"}},` +
		`"repository":{"full_name":"me/repo","default_branch":"main"}}`
	send(t, h, "s", "pull_request", body)

	got, _ := c.Show(task.ID)
	if got.Status != "closed" {
		t.Fatalf("status = %q, want closed (referenced by branch, merged)", got.Status)
	}
}

// A hierarchical child id ("<base>.6.2") is dash-encoded in the branch
// ("claude/<base>-6-2-impl"). branchRefs must rejoin the numeric segments so the
// dotted child id is reconstructed and closed on merge.
func TestMergedPRClosesDottedChildViaBranch(t *testing.T) {
	c := newCore(t)
	parent, _ := c.Create(core.CreateParams{Title: "Parent"})
	child, _ := c.Create(core.CreateParams{Title: "Child", Parent: parent.ID})
	// Sanity: the child id is hierarchical (has a dot).
	if !strings.Contains(shortID(child.ID), ".") {
		t.Fatalf("expected a dotted child id, got %q", child.ID)
	}
	dashed := strings.ReplaceAll(shortID(child.ID), ".", "-") // ps3t.6.2 -> ps3t-6-2

	h := handler(c, "s")
	body := `{"action":"closed","pull_request":{"number":9,"merged":true,` +
		`"title":"L4 work","body":"no magic word here","html_url":"https://gh/pr/9",` +
		`"head":{"ref":"claude/` + dashed + `-implementation-tz2wqc"}},` +
		`"repository":{"full_name":"me/repo","default_branch":"main"}}`
	send(t, h, "s", "pull_request", body)

	got, _ := c.Show(child.ID)
	if got.Status != "closed" {
		t.Fatalf("child status = %q, want closed (dotted id via dash-encoded branch)", got.Status)
	}
	// The parent must NOT be closed — only the specific child the branch names.
	if p, _ := c.Show(parent.ID); p.Status == "closed" {
		t.Fatal("parent should not be closed")
	}
}

// A merged PR whose branch names one ticket but whose body merely MENTIONS a
// sibling must close only the branch ticket — the mentioned sibling gets linked,
// never closed. (PR #836 mentioned active siblings ps3t.6.6/6.8/6.9.)
func TestMergedPRLinksButDoesNotCloseMentionedSibling(t *testing.T) {
	c := newCore(t)
	parent, _ := c.Create(core.CreateParams{Title: "Parent"})
	target, _ := c.Create(core.CreateParams{Title: "The PR's ticket", Parent: parent.ID})
	sibling, _ := c.Create(core.CreateParams{Title: "A follow-up", Parent: parent.ID})

	dashed := strings.ReplaceAll(shortID(target.ID), ".", "-")
	h := handler(c, "s")
	body := `{"action":"closed","pull_request":{"number":836,"merged":true,` +
		`"title":"L4 engine","body":"Builds on ` + shortID(sibling.ID) + ` — follow-ups tracked separately.",` +
		`"html_url":"https://gh/pull/836","head":{"ref":"claude/` + dashed + `-impl-x"}},` +
		`"repository":{"full_name":"me/repo","default_branch":"main"}}`
	send(t, h, "s", "pull_request", body)

	if got, _ := c.Show(target.ID); got.Status != "closed" {
		t.Fatalf("target status = %q, want closed", got.Status)
	}
	sib, _ := c.Show(sibling.ID)
	if sib.Status == "closed" {
		t.Fatal("a merely-MENTIONED sibling must not be closed")
	}
	if sib.CommentCount == 0 {
		t.Fatal("the mentioned sibling should still be linked to the PR")
	}
}

// A PR comment that references a ticket links it (in progress) but never closes
// it — and repeated comment events don't spam duplicate links.
func TestPRCommentLinksAndDedupes(t *testing.T) {
	c := newCore(t)
	task, _ := c.Create(core.CreateParams{Title: "Referenced in a comment"})
	h := handler(c, "s")

	body := `{"action":"created",` +
		`"issue":{"number":836,"title":"Some PR","pull_request":{"url":"https://gh/pull/836"}},` +
		`"comment":{"body":"this relates to ` + task.ID + `","html_url":"https://gh/pull/836#issuecomment-1"},` +
		`"repository":{"full_name":"me/repo","default_branch":"main"}}`
	send(t, h, "s", "issue_comment", body)

	got, _ := c.Show(task.ID)
	if got.Status != "in_progress" {
		t.Fatalf("status = %q, want in_progress (linked by comment)", got.Status)
	}
	if got.CommentCount != 1 {
		t.Fatalf("comment count = %d, want 1 link", got.CommentCount)
	}
	// A second identical comment event must not add another link.
	send(t, h, "s", "issue_comment", body)
	got, _ = c.Show(task.ID)
	if got.CommentCount != 1 {
		t.Fatalf("comment count after re-event = %d, want still 1 (deduped)", got.CommentCount)
	}
}

// A non-PR issue comment is ignored (no pull_request block).
func TestIssueCommentIgnoredWhenNotPR(t *testing.T) {
	c := newCore(t)
	task, _ := c.Create(core.CreateParams{Title: "x"})
	h := handler(c, "s")
	body := `{"action":"created","issue":{"number":5,"title":"just an issue"},` +
		`"comment":{"body":"mentions ` + task.ID + `","html_url":"https://gh/issues/5"},` +
		`"repository":{"full_name":"me/repo","default_branch":"main"}}`
	send(t, h, "s", "issue_comment", body)
	if got, _ := c.Show(task.ID); got.CommentCount != 0 {
		t.Fatal("a plain issue comment must not link tickets")
	}
}

func TestBareRefsDottedOnly(t *testing.T) {
	got := bareRefs("Implements ps3t.6.2 and ps3t.6.8; not v236, not plain, see §1.5")
	has := func(s string) bool {
		for _, g := range got {
			if g == s {
				return true
			}
		}
		return false
	}
	if !has("ps3t.6.2") || !has("ps3t.6.8") {
		t.Fatalf("bareRefs = %v, want the dotted ids", got)
	}
	if has("v236") || has("plain") {
		t.Fatalf("bareRefs = %v, must not match non-dotted words", got)
	}
}

func TestBranchRefsRejoinsNumericSegments(t *testing.T) {
	got := branchRefs("claude/ps3t-6-2-implementation-tz2wqc")
	want := "ps3t.6.2"
	found := false
	for _, r := range got {
		if r == want {
			found = true
		}
		if r == "ps3t" || r == "6" || r == "2" {
			t.Fatalf("branchRefs leaked a shattered segment %q: %v", r, got)
		}
	}
	if !found {
		t.Fatalf("branchRefs = %v, want it to contain %q", got, want)
	}
}

func TestOpenedPRLinksAndInProgress(t *testing.T) {
	c := newCore(t)
	task, _ := c.Create(core.CreateParams{Title: "Build it"})
	h := handler(c, "s")

	// Reference by short id in the branch name, no explicit close word.
	body := `{"action":"opened","pull_request":{"number":3,"merged":false,` +
		`"title":"WIP","body":"part of the work","html_url":"https://gh/pr/3",` +
		`"head":{"ref":"tristan/` + shortID(task.ID) + `-build-it"}},` +
		`"repository":{"full_name":"me/repo","default_branch":"main"}}`
	send(t, h, "s", "pull_request", body)

	got, _ := c.Show(task.ID)
	if got.Status != "in_progress" {
		t.Fatalf("status = %q, want in_progress", got.Status)
	}
	if got.CommentCount == 0 {
		t.Fatal("expected a link comment")
	}
}

func TestPushToDefaultBranchCloses(t *testing.T) {
	c := newCore(t)
	task, _ := c.Create(core.CreateParams{Title: "Ship it"})
	h := handler(c, "s")

	body := `{"ref":"refs/heads/main","repository":{"full_name":"me/repo","default_branch":"main"},` +
		`"commits":[{"id":"abcdef1234","message":"fix ` + task.ID + `","url":"https://gh/c/abcdef1"}]}`
	send(t, h, "s", "push", body)

	got, _ := c.Show(task.ID)
	if got.Status != "closed" {
		t.Fatalf("status = %q, want closed (commit on default branch)", got.Status)
	}

	// A push to a NON-default branch must NOT close.
	task2, _ := c.Create(core.CreateParams{Title: "Not yet"})
	body2 := `{"ref":"refs/heads/feature","repository":{"full_name":"me/repo","default_branch":"main"},` +
		`"commits":[{"id":"x","message":"fixes ` + task2.ID + `","url":"u"}]}`
	send(t, h, "s", "push", body2)
	if g, _ := c.Show(task2.ID); g.Status == "closed" {
		t.Fatal("non-default-branch commit should not close")
	}
}

func TestUnlinkedRepoIgnored(t *testing.T) {
	c := newCore(t)
	task, _ := c.Create(core.CreateParams{Title: "X"})
	h := handler(c, "s")
	body := `{"action":"closed","pull_request":{"number":1,"merged":true,"title":"closes ` + task.ID +
		`","body":"","html_url":"u"},"repository":{"full_name":"someone/else","default_branch":"main"}}`
	send(t, h, "s", "pull_request", body)
	if g, _ := c.Show(task.ID); g.Status == "closed" {
		t.Fatal("event for an unlinked repo must be ignored")
	}
}

// fakeInstalls records installation calls for the webhook tests.
type fakeInstalls struct {
	added, removed map[int64][]string
	deleted        []int64
}

func (f *fakeInstalls) AddInstallRepos(id int64, r []string) error {
	if f.added == nil {
		f.added = map[int64][]string{}
	}
	f.added[id] = append(f.added[id], r...)
	return nil
}
func (f *fakeInstalls) RemoveInstallRepos(id int64, r []string) error {
	if f.removed == nil {
		f.removed = map[int64][]string{}
	}
	f.removed[id] = append(f.removed[id], r...)
	return nil
}
func (f *fakeInstalls) DeleteInstallation(id int64) error {
	f.deleted = append(f.deleted, id)
	return nil
}

func TestInstallationWebhooksLinkRepos(t *testing.T) {
	c := newCore(t)
	inst := &fakeInstalls{}
	h := New(Config{Secret: []byte("s"), Installs: inst,
		Resolve: func(string) (*core.Core, bool) { return c, true }})

	created := `{"action":"created","installation":{"id":9},"repositories":[{"full_name":"me/repo"}]}`
	send(t, h, "s", "installation", created)
	if got := inst.added[9]; len(got) != 1 || got[0] != "me/repo" {
		t.Fatalf("created added = %v, want [me/repo]", got)
	}

	addRepos := `{"action":"added","installation":{"id":9},"repositories_added":[{"full_name":"me/two"}]}`
	send(t, h, "s", "installation_repositories", addRepos)
	if got := inst.added[9]; len(got) != 2 {
		t.Fatalf("after add, added = %v, want 2", got)
	}

	del := `{"action":"deleted","installation":{"id":9}}`
	send(t, h, "s", "installation", del)
	if len(inst.deleted) != 1 || inst.deleted[0] != 9 {
		t.Fatalf("deleted = %v, want [9]", inst.deleted)
	}
}

func shortID(id string) string {
	if i := strings.LastIndexByte(id, '-'); i >= 0 {
		return id[i+1:]
	}
	return id
}
