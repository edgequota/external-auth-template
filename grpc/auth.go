package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	authv1 "github.com/edgequota/external-auth-template/grpc/gen/edgequota/auth/v1"
	"github.com/golang-jwt/jwt/v5"
)

// AuthService implements edgequota.auth.v1.AuthServiceServer.
// It validates Bearer JWTs signed with a shared HMAC secret and returns
// the tenant ID from the token claims as a request header to be injected
// into the upstream request by EdgeQuota.
type AuthService struct {
	authv1.UnimplementedAuthServiceServer

	secret []byte
	logger *slog.Logger
}

// NewAuthService creates a new AuthService with the given HMAC signing secret.
func NewAuthService(secret string, logger *slog.Logger) *AuthService {
	return &AuthService{
		secret: []byte(secret),
		logger: logger,
	}
}

// --------------------------------------------------------------------------
// gRPC: edgequota.auth.v1.AuthService/Check
// --------------------------------------------------------------------------

// Check validates the Authorization header from the incoming request.
// On success, it returns the tenant_id from the JWT claims as a request header
// (X-Tenant-Id) so EdgeQuota injects it into the upstream request.
func (s *AuthService) Check(ctx context.Context, req *authv1.CheckRequest) (*authv1.CheckResponse, error) {
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

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == authHeader {
		return denyGRPC(http.StatusUnauthorized, "invalid Authorization scheme, expected Bearer"), nil
	}

	claims, err := s.validateToken(tokenStr)
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

// --------------------------------------------------------------------------
// HTTP: POST /token
// --------------------------------------------------------------------------

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

// HandleCreateToken creates a signed JWT containing the tenant_id claim.
// This endpoint is for testing and development; in production the token
// issuer would be your identity provider.
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

	now := time.Now()
	expiresIn := 3600 // 1 hour

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"tenant_id": req.TenantID,
		"iat":       now.Unix(),
		"exp":       now.Add(time.Duration(expiresIn) * time.Second).Unix(),
		"iss":       "edgequota-auth-template",
	})

	signed, err := token.SignedString(s.secret)
	if err != nil {
		s.logger.Error("failed to sign token", "error", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to sign token"})
		return
	}

	s.logger.Info("token created", "tenant_id", req.TenantID, "expires_in", expiresIn)
	writeJSON(w, http.StatusOK, createTokenResponse{
		Token:     signed,
		ExpiresIn: expiresIn,
	})
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

func (s *AuthService) validateToken(tokenStr string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.secret, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
