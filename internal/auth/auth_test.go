package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPAuthentication(t *testing.T) {
	sum := sha256.Sum256([]byte("secret"))
	authenticator, err := New([]string{hex.EncodeToString(sum[:])}, 60)
	if err != nil {
		t.Fatal(err)
	}
	handler := authenticator.HTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	tests := []struct {
		name string
		key  string
		want int
	}{
		{name: "valid", key: "secret", want: http.StatusNoContent},
		{name: "invalid", key: "wrong", want: http.StatusUnauthorized},
		{name: "missing", want: http.StatusUnauthorized},
		{name: "oversize", key: strings.Repeat("a", maxAPIKeyBytes+1), want: http.StatusUnauthorized},
	}
	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.RemoteAddr = fmt.Sprintf("192.0.2.%d:12345", i+1)
			request.Header.Set("X-API-Key", test.key)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
}

func TestHTTPFailureBudgetLockout(t *testing.T) {
	sum := sha256.Sum256([]byte("secret"))
	// 60/min → 1/s with burst 10; exhaust burst then expect continued 401.
	authenticator, err := New([]string{hex.EncodeToString(sum[:])}, 60)
	if err != nil {
		t.Fatal(err)
	}
	handler := authenticator.HTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for i := 0; i < authenticator.burst+5; i++ {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.RemoteAddr = "198.51.100.20:443"
		request.Header.Set("X-API-Key", fmt.Sprintf("wrong-%d", i))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want %d", i, response.Code, http.StatusUnauthorized)
		}
	}
}

func TestAuthorizeGlobalFailureLimiter(t *testing.T) {
	sum := sha256.Sum256([]byte("secret"))
	authenticator, err := New([]string{hex.EncodeToString(sum[:])}, 60)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < authenticator.burst; i++ {
		if _, ok := authenticator.authorize(fmt.Sprintf("bad-%d", i), ""); ok {
			t.Fatalf("attempt %d: expected unauthorized", i)
		}
	}
	if authenticator.failureTokensAvailable("") {
		t.Fatal("expected global failure budget exhausted")
	}
	if _, ok := authenticator.authorize("secret", ""); ok {
		t.Fatal("valid key must short-circuit while global failure budget is empty")
	}
}

func TestAuthorizeValidDoesNotConsumeFailureBudget(t *testing.T) {
	sum := sha256.Sum256([]byte("secret"))
	authenticator, err := New([]string{hex.EncodeToString(sum[:])}, 60)
	if err != nil {
		t.Fatal(err)
	}
	peer := "203.0.113.9"
	before := authenticator.failureLimiter(peer).Tokens()
	if _, ok := authenticator.authorize("secret", peer); !ok {
		t.Fatal("valid key rejected")
	}
	after := authenticator.failureLimiter(peer).Tokens()
	if after < before {
		t.Fatalf("valid key consumed failure tokens: before=%v after=%v", before, after)
	}
}
