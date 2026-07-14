// Command agenttasks is the multi-tenant control plane for the hosted service.
// It embeds tasksd (tasks/pkg/httpapi) and serves each organization its own
// isolated task board, authorized by JWTs from an OIDC/JWKS provider (e.g.
// Clerk). Config is via AGENTTASKS_* env vars.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tristanMatthias/agenttasks/internal/app"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	jwks := env("AGENTTASKS_JWKS_URL", env("CLERK_JWKS_URL", ""))
	devToken := os.Getenv("AGENTTASKS_DEV_TOKEN") // local dev only: fixed-token auth, no IdP
	ghClientID := os.Getenv("GITHUB_CLIENT_ID")
	if jwks == "" && devToken == "" && ghClientID == "" {
		logger.Error("set GITHUB_CLIENT_ID (GitHub sign-in) or AGENTTASKS_JWKS_URL")
		os.Exit(1)
	}
	addr := env("AGENTTASKS_ADDR", "")
	if addr == "" {
		if p := os.Getenv("PORT"); p != "" {
			addr = "0.0.0.0:" + p
		} else {
			addr = "127.0.0.1:8080"
		}
	}
	dataDir := env("AGENTTASKS_DATA_DIR", "data/tenants")
	os.MkdirAll(dataDir, 0o755)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := app.Config{
		JWKSURL:        jwks,
		Issuer:         os.Getenv("AGENTTASKS_ISSUER"),
		EmailClaim:     os.Getenv("AGENTTASKS_EMAIL_CLAIM"),
		NameClaim:      os.Getenv("AGENTTASKS_NAME_CLAIM"),
		DataDir:        dataDir,
		Prefix:         env("AGENTTASKS_PREFIX", "t"),
		PublishableKey: env("AGENTTASKS_CLERK_PUBLISHABLE_KEY", os.Getenv("CLERK_PUBLISHABLE_KEY")),
		LoginURL:       os.Getenv("AGENTTASKS_LOGIN_URL"),
		PublicURL:      env("AGENTTASKS_PUBLIC_URL", "https://agenttasks.sh"),
		OAuthSecret:    os.Getenv("AGENTTASKS_OAUTH_SECRET"),
		BehindProxy:    os.Getenv("AGENTTASKS_BEHIND_PROXY") == "true",

		GitHubClientID:      ghClientID,
		GitHubClientSecret:  os.Getenv("GITHUB_CLIENT_SECRET"),
		SessionSecret:       os.Getenv("AGENTTASKS_SESSION_SECRET"),
		OwnerGitHubLogin:    os.Getenv("AGENTTASKS_OWNER_GITHUB"),
		OwnerSubject:        os.Getenv("AGENTTASKS_OWNER_SUBJECT"),
		GitHubWebhookSecret: os.Getenv("GITHUB_WEBHOOK_SECRET"),
		GitHubAppSlug:       os.Getenv("GITHUB_APP_SLUG"),
		OwnerRepo:           os.Getenv("AGENTTASKS_OWNER_REPO"),
		RateLimit:      20,
		Logger:         logger,
	}
	if devToken != "" {
		cfg.Auth = app.DevAuth{Token: devToken}
		logger.Warn("AGENTTASKS_DEV_TOKEN set — using fixed-token dev auth (NOT for production)")
	}
	a, err := app.New(ctx, cfg)
	if err != nil {
		logger.Error("startup", "err", err)
		os.Exit(1)
	}
	defer a.Close()

	srv := &http.Server{
		Addr:              addr,
		Handler:           a.Handler,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	logger.Info("agenttasks control plane starting", "addr", addr, "jwks", jwks, "data_dir", dataDir)

	errc := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case err := <-errc:
		logger.Error("listen", "err", err)
		os.Exit(1)
	}
	sc, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(sc)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
