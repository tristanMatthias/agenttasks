# agenttasks — hosted multi-tenant control plane

The managed-hosting layer for [`tasks`](https://github.com/tristanMatthias/tasks),
deployed at the apex domain (`agenttasks.sh`). It **embeds `tasksd` as a library**
and adds the only things a SaaS needs — identity, per-tenant isolation, and
billing — *without any of that leaking into the open-source `tasks` engine*.

`tasksd` stays single-tenant and generic. This module composes it through two
seams it exposes (`pkg/httpapi`):

- **`Authenticator`** — here, a JWT-via-JWKS verifier (`internal/oidc`). Works with
  any OIDC-style provider; Clerk is just a JWKS URL + an `org_id` claim.
- **`CoreResolver`** — here, a per-org tenant manager (`internal/tenant`) that maps
  the authenticated org to its own SQLite file `data/<org>.db`, created lazily and
  cached. **DB-file-per-tenant** isolation.

The same task UI, REST API, and MCP surface are served per tenant — a user only
ever sees their organization's board.

## Status

- ✅ **Multi-tenant engine built + tested.** `internal/app` wires OIDC auth + the
  tenant resolver into `pkg/httpapi`; `TestTenantIsolation` proves two orgs get
  fully separate DBs with no cross-tenant leakage (signed JWTs vs a live JWKS).
- ⬜ Clerk front-end (hosted sign-in page + org switcher) — needs a Clerk app.
- ⬜ Stripe billing gate (subscription required to create/use a tenant) — needs a
  Stripe account.
- ⬜ Deploy to the apex domain.

## Config (env)

| Env | Purpose |
|---|---|
| `AGENTTASKS_JWKS_URL` / `CLERK_JWKS_URL` | JWKS endpoint to verify session JWTs (required) |
| `AGENTTASKS_ORG_CLAIM` | claim holding the tenant id (default `org_id`) |
| `AGENTTASKS_ISSUER` | optional expected `iss` |
| `AGENTTASKS_LOGIN_URL` | hosted sign-in page the UI redirects unauthenticated visitors to |
| `AGENTTASKS_DATA_DIR` | directory for `<org>.db` files (default `data/tenants`) |
| `AGENTTASKS_ADDR` / `PORT` | listen address |
| `AGENTTASKS_BEHIND_PROXY` | trust `X-Forwarded-For` (behind Cloudflare) |

## Run (dev)

```bash
go build ./... && go test ./...
AGENTTASKS_JWKS_URL=https://<your-app>.clerk.accounts.dev/.well-known/jwks.json \
AGENTTASKS_ADDR=127.0.0.1:8080 \
go run ./cmd/agenttasks
```

CLI / MCP against a tenant use the provider's session JWT (or a personal API
token) as the bearer:

```bash
TASKS_URL=http://127.0.0.1:8080 TASKS_TOKEN=<jwt> tasks ready
```

## Go-live checklist

1. **Clerk app** → enable **Organizations**, grab the JWKS URL + publishable key.
   Ensure the session token carries `org_id` (default) — a Clerk JWT template can
   add it if needed.
2. **Stripe** → account + a Price; add the entitlement gate (subscription required)
   and a webhook to sync subscription status.
3. **Front-end** → a landing + Clerk sign-in page (ClerkJS with the publishable
   key); set `AGENTTASKS_LOGIN_URL` to it so the board redirects there.
4. **Deploy** → build the image, deploy to the host, point `agenttasks.sh` DNS at
   it (grey-cloud), persist `AGENTTASKS_DATA_DIR` (volume or Litestream→R2).

The `tasks` module is pulled via a local `replace` during dev; pin it to a tagged
release (or `@main`) for deploys.
