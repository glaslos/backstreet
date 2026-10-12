package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
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
	for _, test := range []struct {
		name string
		key  string
		want int
	}{
		{name: "valid", key: "secret", want: http.StatusNoContent},
		{name: "invalid", key: "wrong", want: http.StatusUnauthorized},
		{name: "missing", want: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Set("X-API-Key", test.key)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
}
