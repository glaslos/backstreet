package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const maxAPIKeyBytes = 256

type Authenticator struct {
	hashes     [][]byte
	perMin     rate.Limit
	burst      int
	mu         sync.Mutex
	limits     map[string]*rate.Limiter
	failLimits map[string]*rate.Limiter
	globalFail *rate.Limiter
}

func New(hashes []string, requestsPerMinute int) (*Authenticator, error) {
	perMin := rate.Limit(float64(requestsPerMinute) / 60)
	burst := max(1, int(perMin*10))
	a := &Authenticator{
		perMin:     perMin,
		burst:      burst,
		limits:     make(map[string]*rate.Limiter),
		failLimits: make(map[string]*rate.Limiter),
		globalFail: rate.NewLimiter(perMin, burst),
	}
	for _, value := range hashes {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != sha256.Size {
			return nil, status.Error(codes.InvalidArgument, "API key hashes must be SHA-256 hex")
		}
		a.hashes = append(a.hashes, decoded)
	}
	return a, nil
}

func (a *Authenticator) authorize(key, peerAddr string) (string, bool) {
	if len(key) > maxAPIKeyBytes {
		a.consumeFailure(peerAddr)
		return "", false
	}
	if !a.failureTokensAvailable(peerAddr) {
		return "", false
	}
	sum := sha256.Sum256([]byte(key))
	valid := 0
	for _, candidate := range a.hashes {
		valid |= subtle.ConstantTimeCompare(sum[:], candidate)
	}
	if valid != 1 {
		a.consumeFailure(peerAddr)
		return "", false
	}
	id := hex.EncodeToString(sum[:8])
	a.mu.Lock()
	limiter := a.limits[id]
	if limiter == nil {
		limiter = rate.NewLimiter(a.perMin, a.burst)
		a.limits[id] = limiter
	}
	allowed := limiter.Allow()
	a.mu.Unlock()
	return id, allowed
}

func (a *Authenticator) failureLimiter(peerAddr string) *rate.Limiter {
	a.mu.Lock()
	defer a.mu.Unlock()
	if peerAddr == "" {
		return a.globalFail
	}
	limiter := a.failLimits[peerAddr]
	if limiter == nil {
		limiter = rate.NewLimiter(a.perMin, a.burst)
		a.failLimits[peerAddr] = limiter
	}
	return limiter
}

func (a *Authenticator) failureTokensAvailable(peerAddr string) bool {
	return a.failureLimiter(peerAddr).Tokens() >= 1
}

func (a *Authenticator) consumeFailure(peerAddr string) {
	a.failureLimiter(peerAddr).Allow()
}

func (a *Authenticator) HTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			key = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		_, ok := a.authorize(key, clientIP(r.RemoteAddr))
		if !ok {
			http.Error(w, "unauthorized or rate limited", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Authenticator) UnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if err := a.grpcAuthorize(ctx); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func (a *Authenticator) StreamInterceptor(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := a.grpcAuthorize(stream.Context()); err != nil {
		return err
	}
	return handler(srv, stream)
}

func (a *Authenticator) grpcAuthorize(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	key := first(md.Get("x-api-key"))
	if key == "" {
		key = strings.TrimPrefix(first(md.Get("authorization")), "Bearer ")
	}
	if _, ok := a.authorize(key, grpcPeerAddr(ctx)); !ok {
		return status.Error(codes.Unauthenticated, "unauthorized or rate limited")
	}
	return nil
}

func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func grpcPeerAddr(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	return clientIP(p.Addr.String())
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (a *Authenticator) Cleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.mu.Lock()
			a.limits = make(map[string]*rate.Limiter)
			a.failLimits = make(map[string]*rate.Limiter)
			a.globalFail = rate.NewLimiter(a.perMin, a.burst)
			a.mu.Unlock()
		}
	}
}
