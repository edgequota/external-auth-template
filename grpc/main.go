// external-auth-template/grpc demonstrates how to implement the
// EdgeQuota external auth gRPC protocol (edgequota.auth.v1.AuthService).
//
// It exposes:
//   - A gRPC server on :50051 implementing AuthService/Check (JWT validation).
//   - An HTTP server on :8081 with POST /token to create JWTs for testing.
//
// Usage:
//
//	go run . [-grpc-addr :50051] [-http-addr :8081] [-jwt-secret my-secret]
package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	authv1 "github.com/edgequota/external-auth-template/grpc/gen/edgequota/auth/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	grpcAddr := flag.String("grpc-addr", envOrDefault("GRPC_ADDR", ":50051"), "gRPC listen address")
	httpAddr := flag.String("http-addr", envOrDefault("HTTP_ADDR", ":8081"), "HTTP listen address (token endpoint)")
	jwtSecret := flag.String("jwt-secret", envOrDefault("JWT_SECRET", "edgequota-demo-secret"), "HMAC secret for signing JWTs")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	svc := NewAuthService(*jwtSecret, logger)

	// --- gRPC server ---
	grpcServer := grpc.NewServer()
	authv1.RegisterAuthServiceServer(grpcServer, svc)
	reflection.Register(grpcServer)

	lis, err := net.Listen("tcp", *grpcAddr)
	if err != nil {
		logger.Error("failed to listen", "addr", *grpcAddr, "error", err)
		os.Exit(1)
	}

	go func() {
		logger.Info("gRPC server listening", "addr", *grpcAddr)
		if err := grpcServer.Serve(lis); err != nil {
			logger.Error("gRPC server error", "error", err)
		}
	}()

	// --- HTTP server (token endpoint) ---
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", svc.HandleCreateToken)

	httpServer := &http.Server{
		Addr:         *httpAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	go func() {
		logger.Info("HTTP server listening", "addr", *httpAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", "error", err)
		}
	}()

	// --- Graceful shutdown ---
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	logger.Info("shutting down...")
	grpcServer.GracefulStop()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)

	logger.Info("stopped")
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
