package app

import (
	"encoding/base64"
	"html/template"
	"net/http"
	"strings"
)

// frontendAPIFromPublishableKey decodes a Clerk publishable key
// (pk_(live|test)_<base64("<frontend-api>$")>) into the frontend API host.
func frontendAPIFromPublishableKey(pk string) string {
	i := strings.Index(pk, "_")
	if i < 0 {
		return ""
	}
	rest := pk[i+1:] // "live_<b64>" or "test_<b64>"
	if j := strings.Index(rest, "_"); j >= 0 {
		rest = rest[j+1:]
	}
	dec, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		// try raw (no padding)
		dec, err = base64.RawStdEncoding.DecodeString(rest)
		if err != nil {
			return ""
		}
	}
	return strings.TrimSuffix(string(dec), "$")
}

var signInTmpl = template.Must(template.New("signin").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Sign in — agenttasks</title>
<style>
  :root { color-scheme: light dark; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
         font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
         background:#0f0f14; color:#c0caf5; }
  #app { }
  .booting { color:#a9b1d6; font-size:14px; }
</style>
</head>
<body>
<div id="app"><div class="booting">Loading sign-in…</div></div>
<script
  async crossorigin="anonymous"
  data-clerk-publishable-key="{{.PublishableKey}}"
  src="https://{{.FrontendAPI}}/npm/@clerk/clerk-js@5/dist/clerk.browser.js"
  type="text/javascript"></script>
<script>
window.addEventListener("load", async () => {
  const app = document.getElementById("app");
  // Honor a local redirect target (e.g. the OAuth /authorize flow). Only same-site
  // absolute paths are allowed, to avoid an open redirect.
  let dest = "/";
  try {
    const rp = new URLSearchParams(location.search).get("redirect_url");
    if (rp && rp.startsWith("/") && !rp.startsWith("//")) dest = rp;
  } catch (_) {}
  try {
    await Clerk.load();
    if (Clerk.user) { window.location.replace(dest); return; }
    app.innerHTML = ""; // clear the "Loading…" placeholder before mounting
    Clerk.mountSignIn(app, {
      afterSignInUrl: dest, afterSignUpUrl: dest,
      signUpUrl: "/sign-in",
      appearance: { variables: { colorPrimary: "#7aa2f7" } },
    });
  } catch (e) {
    app.textContent = "Sign-in failed to load: " + e.message;
  }
});
</script>
</body>
</html>`))

// clerkBootHead returns a <head> snippet (for httpapi.Config.InjectHead) that
// loads ClerkJS on the board itself. ClerkJS keeps Clerk's short-lived __session
// cookie refreshed in the background, so authenticated API calls don't 401 after
// the cookie's ~60s TTL. It exposes window.__authReady, a promise the app awaits
// before deciding what to show: it resolves once ClerkJS has loaded and (for a
// signed-in user) refreshed the session cookie. A logged-out visitor is NOT
// bounced — the SPA renders the public landing page, whose Log in button sends
// them to /sign-in (preserving the current path as the redirect target).
// clerkCSP is a Content-Security-Policy that permits ClerkJS to load and run on
// the board. The default 'self'-only policy blocks clerk.browser.js (loaded from
// the Frontend API domain), Clerk's inline scripts, and its XHR/telemetry — so
// ClerkJS can't establish a session and every cookie-authed API call 401s. Same-
// origin 'self' already covers our own WebSocket (wss://<host>/api/ws).
func clerkCSP(frontendAPI string) string {
	c := "https://" + frontendAPI
	return "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline' " + c + " https://challenges.cloudflare.com; " +
		"connect-src 'self' " + c + " https://*.clerk.accounts.dev https://clerk-telemetry.com; " +
		"img-src 'self' data: https://img.clerk.com " + c + "; " +
		"style-src 'self' 'unsafe-inline'; " +
		"worker-src 'self' blob:; " +
		"frame-src 'self' " + c + " https://challenges.cloudflare.com"
}

func clerkBootHead(pk, frontendAPI string) string {
	return `<script async crossorigin data-clerk-publishable-key="` + pk + `" ` +
		`src="https://` + frontendAPI + `/npm/@clerk/clerk-js@5/dist/clerk.browser.js"></script>` +
		`<script>(function(){` +
		// 1) Refresh-and-retry any same-origin API call that 401s because Clerk's
		//    short-lived __session cookie went stale — reads AND writes, at boot or
		//    mid-session. Without this, a stale cookie makes the board silently show
		//    cached data + optimistic edits that never persist or refresh (while the
		//    __client_uat fallback keeps the app visible). Cross-origin calls (incl.
		//    Clerk's own) are left untouched, so there's no retry loop.
		`var of=window.fetch.bind(window);` +
		`window.fetch=function(input,init){return of(input,init).then(function(res){` +
		`if(res.status!==401)return res;` +
		`var u=(typeof input==="string")?input:(input&&input.url)||"";` +
		`if(u.indexOf("/api/")<0&&u.indexOf("/mcp")<0)return res;` +
		`if(!window.Clerk||!window.Clerk.session)return res;` +
		`return window.Clerk.session.getToken({skipCache:true}).then(function(){return of(input,init);}).catch(function(){return res;});` +
		`});};` +
		// 2) __authReady: wait for the session to hydrate, then force-refresh the
		//    cookie, so the very first reads carry a valid session.
		`window.__authReady=new Promise(function(resolve){function boot(){` +
		`if(!window.Clerk){setTimeout(boot,50);return;}` +
		`window.Clerk.load().then(async function(){` +
		`for(var i=0;i<30&&!window.Clerk.session;i++){await new Promise(function(r){setTimeout(r,100);});}` +
		`if(window.Clerk.session){try{await window.Clerk.session.getToken({skipCache:true});}catch(e){}}` +
		`resolve();` +
		`}).catch(function(){resolve();});}boot();});` +
		`})();</script>`
}

func signInHandler(pk, frontendAPI string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = signInTmpl.Execute(w, map[string]string{"PublishableKey": pk, "FrontendAPI": frontendAPI})
	}
}
