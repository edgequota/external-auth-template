package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/edgequota/edgequota-go/auth"
	authv1 "github.com/edgequota/edgequota-go/gen/grpc/edgequota/auth/v1"
)

type AuthService struct {
	authv1.UnimplementedAuthServiceServer

	jwt    *auth.JWTValidator
	logger *slog.Logger
}

func NewAuthService(secret string, logger *slog.Logger) *AuthService {
	return &AuthService{
		jwt:    auth.NewJWTValidator(secret),
		logger: logger,
	}
}

func (s *AuthService) Check(_ context.Context, req *authv1.CheckRequest) (*authv1.CheckResponse, error) {
	s.logger.Info("auth check",
		"method", req.GetMethod(),
		"path", req.GetPath(),
		"remote_addr", req.GetRemoteAddr())

	authHeader := req.GetHeaders()["Authorization"]
	if authHeader == "" {
		authHeader = req.GetHeaders()["authorization"]
	}
	if authHeader == "" {
		return denyGRPC(http.StatusUnauthorized, "missing Authorization header"), nil
	}

	if len(authHeader) <= 7 || authHeader[:7] != "Bearer " {
		return denyGRPC(http.StatusUnauthorized, "invalid Authorization scheme, expected Bearer"), nil
	}

	claims, err := s.jwt.ValidateToken(authHeader[7:])
	if err != nil {
		s.logger.Warn("token validation failed", "error", err)
		return denyGRPC(http.StatusUnauthorized, fmt.Sprintf("invalid token: %v", err)), nil
	}

	tenantID, ok := claims["tenant_id"].(string)
	if !ok || tenantID == "" {
		return denyGRPC(http.StatusForbidden, "token missing required tenant_id claim"), nil
	}

	s.logger.Info("auth allowed", "tenant_id", tenantID)
	return &authv1.CheckResponse{
		Allowed:    true,
		StatusCode: http.StatusOK,
		RequestHeaders: map[string]string{
			"X-Tenant-Id": tenantID,
		},
	}, nil
}

func denyGRPC(code int, message string) *authv1.CheckResponse {
	return &authv1.CheckResponse{
		Allowed:    false,
		StatusCode: int32(code),
		DenyBody:   message,
		ResponseHeaders: map[string]string{
			"Content-Type": "application/json",
		},
	}
}

type createTokenRequest struct {
	TenantID string `json:"tenant_id"`
}

type createTokenResponse struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func (s *AuthService) HandleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req createTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON body"})
		return
	}
	if req.TenantID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "tenant_id is required"})
		return
	}

	expiresIn := 3600
	signed, err := s.jwt.CreateToken(map[string]interface{}{
		"tenant_id": req.TenantID,
		"iss":       "edgequota-auth-template",
	}, time.Duration(expiresIn)*time.Second)
	if err != nil {
		s.logger.Error("failed to sign token", "error", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to sign token"})
		return
	}

	s.logger.Info("token created", "tenant_id", req.TenantID, "expires_in", expiresIn)
	writeJSON(w, http.StatusOK, createTokenResponse{Token: signed, ExpiresIn: expiresIn})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
