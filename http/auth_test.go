package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func checkRequest(t *testing.T, svc *AuthService, req CheckRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/check", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	svc.HandleCheck(w, httpReq)
	return w
}

func decodeCheckResponse(t *testing.T, w *httptest.ResponseRecorder) CheckResponse {
	t.Helper()
	var resp CheckResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// --------------------------------------------------------------------------
// POST /check tests
// --------------------------------------------------------------------------

func TestCheck_MissingAuthHeader(t *testing.T) {
	svc := testService()
	w := checkRequest(t, svc, CheckRequest{
		Method:  "GET",
		Path:    "/api/v1/test",
		Headers: map[string]string{},
	})
	resp := decodeCheckResponse(t, w)
	if resp.Allowed {
		t.Error("expected denied")
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestCheck_InvalidScheme(t *testing.T) {
	svc := testService()
	w := checkRequest(t, svc, CheckRequest{
		Method: "GET",
		Path:   "/api/v1/test",
		Headers: map[string]string{
			"Authorization": "Basic dXNlcjpwYXNz",
		},
	})
	resp := decodeCheckResponse(t, w)
	if resp.Allowed {
		t.Error("expected denied")
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestCheck_InvalidToken(t *testing.T) {
	svc := testService()
	w := checkRequest(t, svc, CheckRequest{
		Method: "GET",
		Path:   "/api/v1/test",
		Headers: map[string]string{
			"Authorization": "Bearer garbage-token",
		},
	})
	resp := decodeCheckResponse(t, w)
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
	w := checkRequest(t, svc, CheckRequest{
		Method: "GET",
		Path:   "/api/v1/test",
		Headers: map[string]string{
			"Authorization": "Bearer " + token,
		},
	})
	resp := decodeCheckResponse(t, w)
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
	w := checkRequest(t, svc, CheckRequest{
		Method: "GET",
		Path:   "/api/v1/test",
		Headers: map[string]string{
			"Authorization": "Bearer " + token,
		},
	})
	resp := decodeCheckResponse(t, w)
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
	w := checkRequest(t, svc, CheckRequest{
		Method: "GET",
		Path:   "/api/v1/test",
		Headers: map[string]string{
			"Authorization": "Bearer " + token,
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	resp := decodeCheckResponse(t, w)
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
	w := checkRequest(t, svc, CheckRequest{
		Method: "GET",
		Path:   "/api/v1/test",
		Headers: map[string]string{
			"authorization": "Bearer " + token,
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	resp := decodeCheckResponse(t, w)
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
	w := checkRequest(t, svc, CheckRequest{
		Method: "GET",
		Path:   "/api/v1/test",
		Headers: map[string]string{
			"Authorization": "Bearer " + token,
		},
	})
	resp := decodeCheckResponse(t, w)
	if resp.Allowed {
		t.Error("expected denied")
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

// --------------------------------------------------------------------------
// POST /token tests
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
// E2E: create token → validate with /check
// --------------------------------------------------------------------------

func TestE2E_CreateTokenThenCheck(t *testing.T) {
	svc := testService()

	// Step 1: Create a token.
	tokenBody, _ := json.Marshal(createTokenRequest{TenantID: "e2e-tenant"})
	tokenReq := httptest.NewRequest("POST", "/token", bytes.NewReader(tokenBody))
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

	// Step 2: Use the token in a /check call.
	w := checkRequest(t, svc, CheckRequest{
		Method: "POST",
		Path:   "/api/v1/data",
		Headers: map[string]string{
			"Authorization": "Bearer " + tokenResp.Token,
			"Content-Type":  "application/json",
		},
		RemoteAddr: "10.0.0.1:12345",
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	resp := decodeCheckResponse(t, w)
	if !resp.Allowed {
		t.Error("expected allowed")
	}
	if resp.RequestHeaders["X-Tenant-Id"] != "e2e-tenant" {
		t.Errorf("expected X-Tenant-Id=e2e-tenant, got %q", resp.RequestHeaders["X-Tenant-Id"])
	}
}
