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
  try {
    await Clerk.load();
    if (Clerk.user) { window.location.replace("/"); return; }
    Clerk.mountSignIn(document.getElementById("app"), {
      afterSignInUrl: "/", afterSignUpUrl: "/",
      signUpUrl: "/sign-in",
    });
  } catch (e) {
    document.getElementById("app").textContent = "Sign-in failed to load: " + e.message;
  }
});
</script>
</body>
</html>`))

func signInHandler(pk, frontendAPI string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = signInTmpl.Execute(w, map[string]string{"PublishableKey": pk, "FrontendAPI": frontendAPI})
	}
}
