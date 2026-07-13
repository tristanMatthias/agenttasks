package app

import "strings"

import "testing"

func TestFrontendAPIFromPublishableKey(t *testing.T) {
	// pk_live_<base64("clerk.agenttasks.sh$")>
	pk := "pk_live_Y2xlcmsuYWdlbnR0YXNrcy5zaCQ"
	if got := frontendAPIFromPublishableKey(pk); got != "clerk.agenttasks.sh" {
		t.Fatalf("frontendAPI = %q, want clerk.agenttasks.sh", got)
	}
	if got := frontendAPIFromPublishableKey("garbage"); got != "" {
		t.Fatalf("malformed key should yield empty, got %q", got)
	}
}

func TestClerkCSPAllowsClerk(t *testing.T) {
	csp := clerkCSP("clerk.agenttasks.sh")
	clerk := "https://clerk.agenttasks.sh"
	// The domain must be reachable for BOTH loading Clerk's script and its XHR,
	// or the session can't establish and every gated API call 401s.
	for _, directive := range []string{"script-src", "connect-src", "frame-src"} {
		seg := directiveOf(csp, directive)
		if !strings.Contains(seg, clerk) {
			t.Fatalf("%s must include %s; got %q", directive, clerk, seg)
		}
	}
	if !strings.Contains(directiveOf(csp, "script-src"), "'unsafe-inline'") {
		t.Fatal("script-src must allow the inline boot script")
	}
	if !strings.Contains(csp, "default-src 'self'") {
		t.Fatal("CSP should still default-src 'self'")
	}
}

// directiveOf returns the CSP segment for a directive (between its name and the
// next ';'), for asserting on individual policies.
func directiveOf(csp, name string) string {
	i := strings.Index(csp, name)
	if i < 0 {
		return ""
	}
	rest := csp[i:]
	if j := strings.Index(rest, ";"); j >= 0 {
		return rest[:j]
	}
	return rest
}

func TestClerkBootHeadWiresRetryAndAuthReady(t *testing.T) {
	head := clerkBootHead("pk_live_x", "clerk.agenttasks.sh")
	for _, want := range []string{"window.__authReady", "window.fetch", "getToken", "clerk.agenttasks.sh"} {
		if !strings.Contains(head, want) {
			t.Fatalf("boot head missing %q", want)
		}
	}
}
