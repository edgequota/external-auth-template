// external-auth-template/http demonstrates how to implement the
// EdgeQuota external auth HTTP protocol.
//
// It exposes a single HTTP server on :8080 with two endpoints:
//   - POST /check  — EdgeQuota auth check (validates JWT, returns tenant ID).
//   - POST /token  — Creates a signed JWT for testing.
//
// Usage:
//
//	go run . [-addr :8080] [-jwt-secret my-secret]
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	addr := flag.String("addr", envOrDefault("ADDR", ":8080"), "HTTP listen address")
	jwtSecret := flag.String("jwt-secret", envOrDefault("JWT_SECRET", "edgequota-demo-secret"), "HMAC secret for signing JWTs")
	flag.Parse()

	if *jwtSecret == "edgequota-demo-secret" {
		fmt.Fprintln(os.Stderr, "WARNING: using default JWT secret — set JWT_SECRET or --jwt-secret for production")
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	svc := NewAuthService(*jwtSecret, logger)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /check", svc.HandleCheck)
	mux.HandleFunc("POST /token", svc.HandleCreateToken)

	server := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	go func() {
		logger.Info("HTTP server listening", "addr", *addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	logger.Info("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)

	logger.Info("stopped")
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
