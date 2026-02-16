package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authv1 "github.com/edgequota/external-auth-template/grpc/gen/edgequota/auth/v1"
	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "test-secret"

func testService() *AuthService {
	return NewAuthService(testSecret, slog.Default())
}

func signToken(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// --------------------------------------------------------------------------
// gRPC Check tests
// --------------------------------------------------------------------------

func TestCheck_MissingAuthHeader(t *testing.T) {
	svc := testService()
	resp, err := svc.Check(context.Background(), &authv1.CheckRequest{
		Method:  "GET",
		Path:    "/api/v1/test",
		Headers: map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Allowed {
		t.Error("expected denied")
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestCheck_InvalidScheme(t *testing.T) {
	svc := testService()
	resp, err := svc.Check(context.Background(), &authv1.CheckRequest{
		Method: "GET",
		Path:   "/api/v1/test",
		Headers: map[string]string{
			"Authorization": "Basic dXNlcjpwYXNz",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Allowed {
		t.Error("expected denied")
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestCheck_InvalidToken(t *testing.T) {
	svc := testService()
	resp, err := svc.Check(context.Background(), &authv1.CheckRequest{
		Method: "GET",
		Path:   "/api/v1/test",
		Headers: map[string]string{
			"Authorization": "Bearer invalid-token",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Allowed {
		t.Error("expected denied")
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestCheck_ExpiredToken(t *testing.T) {
	svc := testService()
	token := signToken(t, testSecret, jwt.MapClaims{
		"tenant_id": "tenant-1",
		"exp":       time.Now().Add(-1 * time.Hour).Unix(),
		"iat":       time.Now().Add(-2 * time.Hour).Unix(),
	})
	resp, err := svc.Check(context.Background(), &authv1.CheckRequest{
		Method: "GET",
		Path:   "/api/v1/test",
		Headers: map[string]string{
			"Authorization": "Bearer " + token,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Allowed {
		t.Error("expected denied")
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestCheck_MissingTenantID(t *testing.T) {
	svc := testService()
	token := signToken(t, testSecret, jwt.MapClaims{
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	resp, err := svc.Check(context.Background(), &authv1.CheckRequest{
		Method: "GET",
		Path:   "/api/v1/test",
		Headers: map[string]string{
			"Authorization": "Bearer " + token,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Allowed {
		t.Error("expected denied")
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

func TestCheck_ValidToken(t *testing.T) {
	svc := testService()
	token := signToken(t, testSecret, jwt.MapClaims{
		"tenant_id": "tenant-42",
		"exp":       time.Now().Add(1 * time.Hour).Unix(),
		"iat":       time.Now().Unix(),
	})
	resp, err := svc.Check(context.Background(), &authv1.CheckRequest{
		Method: "GET",
		Path:   "/api/v1/test",
		Headers: map[string]string{
			"Authorization": "Bearer " + token,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Allowed {
		t.Error("expected allowed")
	}
	if resp.RequestHeaders["X-Tenant-Id"] != "tenant-42" {
		t.Errorf("expected X-Tenant-Id=tenant-42, got %q", resp.RequestHeaders["X-Tenant-Id"])
	}
}

func TestCheck_LowercaseAuthHeader(t *testing.T) {
	svc := testService()
	token := signToken(t, testSecret, jwt.MapClaims{
		"tenant_id": "tenant-lc",
		"exp":       time.Now().Add(1 * time.Hour).Unix(),
		"iat":       time.Now().Unix(),
	})
	resp, err := svc.Check(context.Background(), &authv1.CheckRequest{
		Method: "GET",
		Path:   "/api/v1/test",
		Headers: map[string]string{
			"authorization": "Bearer " + token,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Allowed {
		t.Error("expected allowed")
	}
	if resp.RequestHeaders["X-Tenant-Id"] != "tenant-lc" {
		t.Errorf("expected X-Tenant-Id=tenant-lc, got %q", resp.RequestHeaders["X-Tenant-Id"])
	}
}

func TestCheck_WrongSecret(t *testing.T) {
	svc := testService()
	token := signToken(t, "wrong-secret", jwt.MapClaims{
		"tenant_id": "tenant-1",
		"exp":       time.Now().Add(1 * time.Hour).Unix(),
		"iat":       time.Now().Unix(),
	})
	resp, err := svc.Check(context.Background(), &authv1.CheckRequest{
		Method: "GET",
		Path:   "/api/v1/test",
		Headers: map[string]string{
			"Authorization": "Bearer " + token,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Allowed {
		t.Error("expected denied")
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

// --------------------------------------------------------------------------
// HTTP /token tests
// --------------------------------------------------------------------------

func TestCreateToken_Success(t *testing.T) {
	svc := testService()
	body, _ := json.Marshal(createTokenRequest{TenantID: "tenant-1"})
	req := httptest.NewRequest("POST", "/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	svc.HandleCreateToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp createTokenResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Token == "" {
		t.Error("expected non-empty token")
	}
	if resp.ExpiresIn != 3600 {
		t.Errorf("expected expires_in=3600, got %d", resp.ExpiresIn)
	}

	// Verify the token is valid and contains the tenant_id.
	claims, err := svc.validateToken(resp.Token)
	if err != nil {
		t.Fatal(err)
	}
	if claims["tenant_id"] != "tenant-1" {
		t.Errorf("expected tenant_id=tenant-1, got %v", claims["tenant_id"])
	}
}

func TestCreateToken_MissingTenantID(t *testing.T) {
	svc := testService()
	body, _ := json.Marshal(createTokenRequest{})
	req := httptest.NewRequest("POST", "/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	svc.HandleCreateToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCreateToken_InvalidJSON(t *testing.T) {
	svc := testService()
	req := httptest.NewRequest("POST", "/token", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	svc.HandleCreateToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// --------------------------------------------------------------------------
// E2E: create token → validate with Check
// --------------------------------------------------------------------------

func TestE2E_CreateTokenThenCheck(t *testing.T) {
	svc := testService()

	// Step 1: Create a token.
	body, _ := json.Marshal(createTokenRequest{TenantID: "e2e-tenant"})
	tokenReq := httptest.NewRequest("POST", "/token", bytes.NewReader(body))
	tokenReq.Header.Set("Content-Type", "application/json")
	tokenW := httptest.NewRecorder()
	svc.HandleCreateToken(tokenW, tokenReq)

	if tokenW.Code != http.StatusOK {
		t.Fatalf("token creation failed: %d", tokenW.Code)
	}

	var tokenResp createTokenResponse
	if err := json.NewDecoder(tokenW.Body).Decode(&tokenResp); err != nil {
		t.Fatal(err)
	}

	// Step 2: Use the token in a gRPC Check call.
	checkResp, err := svc.Check(context.Background(), &authv1.CheckRequest{
		Method: "POST",
		Path:   "/api/v1/data",
		Headers: map[string]string{
			"Authorization": "Bearer " + tokenResp.Token,
			"Content-Type":  "application/json",
		},
		RemoteAddr: "10.0.0.1:12345",
	})
	if err != nil {
		t.Fatal(err)
	}

	if !checkResp.Allowed {
		t.Error("expected allowed")
	}
	if checkResp.RequestHeaders["X-Tenant-Id"] != "e2e-tenant" {
		t.Errorf("expected X-Tenant-Id=e2e-tenant, got %q", checkResp.RequestHeaders["X-Tenant-Id"])
	}
}
