package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AuthService implements the EdgeQuota HTTP auth protocol.
// EdgeQuota sends a POST with a JSON body containing the original request
// metadata. The service responds with a JSON body indicating allow/deny.
type AuthService struct {
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
// EdgeQuota HTTP auth protocol types
// --------------------------------------------------------------------------

// CheckRequest mirrors edgequota.auth.v1.CheckRequest as JSON.
type CheckRequest struct {
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Headers    map[string]string `json:"headers"`
	RemoteAddr string            `json:"remote_addr"`
	Body       []byte            `json:"body,omitempty"`
}

// CheckResponse mirrors edgequota.auth.v1.CheckResponse as JSON.
type CheckResponse struct {
	Allowed         bool              `json:"allowed"`
	StatusCode      int               `json:"status_code"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	DenyBody        string            `json:"deny_body,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
}

// --------------------------------------------------------------------------
// POST /check — EdgeQuota auth check
// --------------------------------------------------------------------------

// HandleCheck implements the EdgeQuota HTTP auth protocol.
// EdgeQuota posts a JSON CheckRequest; we validate the Authorization header
// from the forwarded headers and return a CheckResponse.
//
// On allow: returns 200 with request_headers containing X-Tenant-Id.
// On deny:  returns the appropriate HTTP status (401/403) with an error body.
func (s *AuthService) HandleCheck(w http.ResponseWriter, r *http.Request) {
	var req CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, CheckResponse{
			Allowed:    false,
			StatusCode: http.StatusBadRequest,
			DenyBody:   "invalid request body",
		})
		return
	}

	s.logger.Info("auth check",
		"method", req.Method,
		"path", req.Path,
		"remote_addr", req.RemoteAddr)

	authHeader := req.Headers["Authorization"]
	if authHeader == "" {
		authHeader = req.Headers["authorization"]
	}

	if authHeader == "" {
		writeJSON(w, http.StatusUnauthorized, CheckResponse{
			Allowed:    false,
			StatusCode: http.StatusUnauthorized,
			DenyBody:   "missing Authorization header",
			ResponseHeaders: map[string]string{
				"Content-Type": "application/json",
			},
		})
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == authHeader {
		writeJSON(w, http.StatusUnauthorized, CheckResponse{
			Allowed:    false,
			StatusCode: http.StatusUnauthorized,
			DenyBody:   "invalid Authorization scheme, expected Bearer",
			ResponseHeaders: map[string]string{
				"Content-Type": "application/json",
			},
		})
		return
	}

	claims, err := s.validateToken(tokenStr)
	if err != nil {
		s.logger.Warn("token validation failed", "error", err)
		writeJSON(w, http.StatusUnauthorized, CheckResponse{
			Allowed:    false,
			StatusCode: http.StatusUnauthorized,
			DenyBody:   fmt.Sprintf("invalid token: %v", err),
			ResponseHeaders: map[string]string{
				"Content-Type": "application/json",
			},
		})
		return
	}

	tenantID, ok := claims["tenant_id"].(string)
	if !ok || tenantID == "" {
		writeJSON(w, http.StatusForbidden, CheckResponse{
			Allowed:    false,
			StatusCode: http.StatusForbidden,
			DenyBody:   "token missing required tenant_id claim",
			ResponseHeaders: map[string]string{
				"Content-Type": "application/json",
			},
		})
		return
	}

	s.logger.Info("auth allowed", "tenant_id", tenantID)

	// Return 200 with the tenant ID to inject into the upstream request.
	writeJSON(w, http.StatusOK, CheckResponse{
		Allowed:    true,
		StatusCode: http.StatusOK,
		RequestHeaders: map[string]string{
			"X-Tenant-Id": tenantID,
		},
	})
}

// --------------------------------------------------------------------------
// POST /token — Create JWT
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
